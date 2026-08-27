//! Model-facing [`Tool`] wrappers over the pure reversing-triage analyzers. Each
//! tool reads a workspace file's raw bytes (resolved through [`ExecCtx::resolve`]
//! and capped at [`MAX_BIN_BYTES`]) or, for `bin_symbols_report`, a symbol dump,
//! runs an in-process analyzer (no shell, no disassembler), and returns its serde
//! struct as the canonical value — so a UI card and a future Code Mode read the
//! same fact the model saw.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::reversing::{identify, packer, rop, strings, symbols};
use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Cap on the bytes one reversing tool reads from a file into memory. A triage
/// first pass does not need the whole of a huge artifact; the prefix is analyzed
/// and the value carries `"truncated": true` so the model knows.
const MAX_BIN_BYTES: usize = 32 * 1024 * 1024; // 32 MiB

/// Default per-category cap on the strings surfaced by `bin_strings`, so a
/// string-heavy binary does not flood context. The `total` stays exact.
const DEFAULT_MAX_PER_GROUP: usize = 100;

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Stamp the resolved source path (and a truncation flag) onto an analyzer's
/// object value so the record is self-describing.
fn with_source(mut value: Value, path: &Path, truncated: bool) -> Value {
    if let Value::Object(ref mut m) = value {
        m.insert("path".into(), json!(path.display().to_string()));
        if truncated {
            m.insert("truncated".into(), json!(true));
        }
    }
    value
}

/// Resolve the `path` argument against the session workspace and read up to
/// [`MAX_BIN_BYTES`] of it. Returns the resolved path, the bytes, and whether the
/// file exceeded the cap (in which case only the prefix is returned).
async fn read_capped(ctx: &ExecCtx, arguments: &Value) -> Result<(PathBuf, Vec<u8>, bool), ToolError> {
    use tokio::io::AsyncReadExt;
    let path = ctx.resolve(&arg_str(arguments, "path")?);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|e| ToolError::execution(format!("cannot open {}: {e}", path.display())))?;
    // Read one extra byte so a file exactly at the cap is not falsely flagged.
    let mut limited = file.take(MAX_BIN_BYTES as u64 + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .await
        .map_err(|e| ToolError::execution(format!("cannot read {}: {e}", path.display())))?;
    let truncated = buf.len() > MAX_BIN_BYTES;
    if truncated {
        buf.truncate(MAX_BIN_BYTES);
    }
    Ok((path, buf, truncated))
}

/// Format an `Option<bool>` hardening flag as `on` / `off` / `?`.
fn flag(v: Option<&Value>) -> &'static str {
    match v.and_then(Value::as_bool) {
        Some(true) => "on",
        Some(false) => "off",
        None => "?",
    }
}

/// Identify a binary's format, architecture, and hardening flags (offline).
pub struct BinIdentifyTool;

#[async_trait]
impl Tool for BinIdentifyTool {
    fn name(&self) -> &str {
        "bin_identify"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bin_identify".into(),
            description: "Identify a binary from a workspace file by parsing its header bytes: \
                format (ELF/PE/Mach-O/WASM/Java class), architecture, bit-width, endianness, image \
                kind, and entry point, plus the exploit-mitigation flags where they apply — NX, PIE/\
                ASLR, RELRO (ELF), and stack canary. Offline, no external tools. Start reversing here."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary (absolute, or relative to the workspace)." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let (path, bytes, truncated) = read_capped(ctx, &arguments).await?;
        let info = identify::identify(&bytes);
        Ok(with_source(to_value(info)?, &path, truncated))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let format = value.get("format").and_then(Value::as_str).unwrap_or("unknown");
        let arch = value.get("arch").and_then(Value::as_str).unwrap_or("");
        let bits = value.get("bits").and_then(Value::as_u64).unwrap_or(0);
        let endian = value.get("endian").and_then(Value::as_str).unwrap_or("");
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        let entry = value.get("entry").and_then(Value::as_u64).unwrap_or(0);
        let relro = value.get("relro").and_then(Value::as_str).unwrap_or("?");
        let mut out = format!("bin_identify {path}\n  {format} {arch} ({bits}-bit, {endian}) {kind}");
        if entry != 0 {
            out.push_str(&format!("  entry=0x{entry:x}"));
        }
        out.push_str(&format!(
            "\n  NX={} PIE={} RELRO={relro} canary={}",
            flag(value.get("nx")),
            flag(value.get("pie")),
            flag(value.get("canary")),
        ));
        if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n  [read truncated at cap — header analysis is complete, whole-file checks (canary) may under-report]");
        }
        vec![ContentBlock::text(out)]
    }
}

/// Extract and classify printable strings from a binary (offline).
pub struct BinStringsTool;

#[async_trait]
impl Tool for BinStringsTool {
    fn name(&self) -> &str {
        "bin_strings"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bin_strings".into(),
            description: "Extract printable strings (ASCII and UTF-16LE) from a workspace binary and \
                classify each into a triage category: url, ip, email, path, crypto, secret, version, \
                import, other. Offline. Use `category` to keep only one group; `min_len` sets the \
                minimum run length (default 4)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary (absolute, or relative to the workspace)." },
                    "min_len": { "type": "integer", "description": "Minimum printable run length to keep (default 4)." },
                    "category": { "type": "string", "description": "Keep only this category (url|ip|email|path|crypto|secret|version|import|other)." },
                    "max_per_group": { "type": "integer", "description": "Cap on strings surfaced per category (default 100; `total` stays exact)." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let (path, bytes, truncated) = read_capped(ctx, &arguments).await?;
        let min_len = arg_u64_opt(&arguments, "min_len").unwrap_or(4) as usize;
        let category = arg_str_opt(&arguments, "category");
        let max_per_group = arg_u64_opt(&arguments, "max_per_group").unwrap_or(DEFAULT_MAX_PER_GROUP as u64) as usize;

        let mut hits = strings::extract(&bytes, min_len, category.as_deref());
        let mut capped = false;
        for v in hits.groups.values_mut() {
            if v.len() > max_per_group {
                v.truncate(max_per_group);
                capped = true;
            }
        }
        let mut value = with_source(to_value(hits)?, &path, truncated);
        if capped {
            if let Value::Object(ref mut m) = value {
                m.insert("groups_capped".into(), json!(true));
            }
        }
        Ok(value)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let total = value.get("total").and_then(Value::as_u64).unwrap_or(0);
        let mut out = format!("bin_strings {path} — {total} classified string(s)");
        if let Some(groups) = value.get("groups").and_then(Value::as_object) {
            for (cat, arr) in groups {
                let items = arr.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                let sample: Vec<&str> = items.iter().take(3).filter_map(Value::as_str).collect();
                out.push_str(&format!("\n  {cat} ({}): {}", items.len(), sample.join(", ")));
            }
        }
        if value.get("groups_capped").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n  [some categories capped — total count above is exact]");
        }
        vec![ContentBlock::text(out)]
    }
}

/// Detect packing via overall entropy and known packer signatures (offline).
pub struct BinPackerTool;

#[async_trait]
impl Tool for BinPackerTool {
    fn name(&self) -> &str {
        "bin_packer"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bin_packer".into(),
            description: "Decide whether a workspace binary looks packed/obfuscated: computes overall \
                Shannon entropy (bits/byte) and scans for known packer markers (UPX, ASPack, PECompact, \
                FSG, MPRESS, Themida, MEW, Petite, NsPack, Enigma, VMProtect). Packed = a signature hit \
                OR entropy > 7.2. Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary (absolute, or relative to the workspace)." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let (path, bytes, truncated) = read_capped(ctx, &arguments).await?;
        let verdict = packer::detect(&bytes);
        Ok(with_source(to_value(verdict)?, &path, truncated))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let entropy = value.get("entropy").and_then(Value::as_f64).unwrap_or(0.0);
        let packed = value.get("packed").and_then(Value::as_bool).unwrap_or(false);
        let empty = Vec::new();
        let sigs = value.get("signatures").and_then(Value::as_array).unwrap_or(&empty);
        let sig_list: Vec<&str> = sigs.iter().filter_map(Value::as_str).collect();
        let verdict = if packed { "PACKED" } else { "not packed" };
        let mut out = format!("bin_packer {path} — {verdict} (entropy {entropy:.3} bits/byte)");
        if !sig_list.is_empty() {
            out.push_str(&format!("\n  signatures: {}", sig_list.join(", ")));
        }
        if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n  [read truncated at cap — entropy is over the prefix only]");
        }
        vec![ContentBlock::text(out)]
    }
}

/// First-pass ROP-gadget scan: RET-terminated byte windows (offline).
pub struct BinRopTool;

#[async_trait]
impl Tool for BinRopTool {
    fn name(&self) -> &str {
        "bin_rop"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bin_rop".into(),
            description: "Fast first-pass ROP-gadget scan of a workspace binary: finds x86 RET opcodes \
                (C3/CB/C2/CA) and emits the byte window ending at each. NOT a disassembler — a triage \
                that seeds Ropper/ROPgadget. `max_length` bounds each window (default 10, max 32), \
                `limit` caps returned gadgets (default 200; `total` stays exact), `pattern_hex` keeps \
                only gadgets containing that byte sequence (e.g. \"ffd0\"). Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the binary (absolute, or relative to the workspace)." },
                    "max_length": { "type": "integer", "description": "Max bytes per gadget window (default 10, clamped 1..32)." },
                    "limit": { "type": "integer", "description": "Max gadgets returned (default 200; total still counts all)." },
                    "pattern_hex": { "type": "string", "description": "Keep only gadgets whose bytes contain this hex sequence, e.g. \"ffd0\"." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let (path, bytes, truncated) = read_capped(ctx, &arguments).await?;
        let max_length = arg_u64_opt(&arguments, "max_length").unwrap_or(10) as usize;
        let limit = arg_u64_opt(&arguments, "limit").unwrap_or(200) as usize;
        let pattern_hex = arg_str_opt(&arguments, "pattern_hex");
        let scan = rop::scan(&bytes, max_length, limit, pattern_hex.as_deref());
        Ok(with_source(to_value(scan)?, &path, truncated))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let total = value.get("total").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let gadgets = value.get("gadgets").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("bin_rop {path} — {total} RET gadget(s), {} shown", gadgets.len());
        for g in gadgets.iter().take(10) {
            let offset = g.get("offset").and_then(Value::as_u64).unwrap_or(0);
            let hex = g.get("bytes_hex").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("\n  0x{offset:x}: {hex}"));
        }
        if gadgets.len() > 10 {
            out.push_str(&format!("\n  … +{} more shown in value", gadgets.len() - 10));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Classify symbol names into risk buckets (offline).
pub struct BinSymbolsReportTool;

#[async_trait]
impl Tool for BinSymbolsReportTool {
    fn name(&self) -> &str {
        "bin_symbols_report"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bin_symbols_report".into(),
            description: "Triage a symbol dump (from nm/objdump/readelf) into risk buckets — \
                command_exec, unsafe_memory, format_string, crypto, network, privilege, dynamic_load, \
                anti_debug — the analyst's 'where do I look first' map. Pass the dump text inline as \
                `symbols`, OR a `path` to a file containing it (resolved in the workspace). The last \
                token on each line is taken as the symbol name. Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "symbols": { "type": "string", "description": "Symbol dump text (nm/objdump/readelf output)." },
                    "path": { "type": "string", "description": "Path to a file holding the symbol dump (alternative to `symbols`)." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let has_path = arguments.get("path").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        let (text, source_path, truncated) = if has_path {
            let (path, bytes, truncated) = read_capped(ctx, &arguments).await?;
            (String::from_utf8_lossy(&bytes).into_owned(), Some(path), truncated)
        } else if let Some(inline) = arg_str_opt(&arguments, "symbols") {
            (inline, None, false)
        } else {
            return Err(ToolError::invalid_args("provide `symbols` text or a `path` to a symbol-dump file"));
        };

        let report = symbols::report(&text);
        let mut value = to_value(report)?;
        if let Some(path) = source_path {
            value = with_source(value, &path, truncated);
        }
        Ok(value)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let total = value.get("total").and_then(Value::as_u64).unwrap_or(0);
        let mut out = format!("bin_symbols_report — {total} risky symbol(s)");
        if let Some(buckets) = value.get("buckets").and_then(Value::as_object) {
            for (bucket, arr) in buckets {
                let items = arr.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
                let names: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
                out.push_str(&format!("\n  {bucket} ({}): {}", names.len(), names.join(", ")));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;

    async fn run_in(tool: Arc<dyn Tool>, args: Value, ctx: ExecCtx) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(
            decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args },
            &ctx,
        )
        .await
    }

    /// A tiny ELF64 x86_64 DYN (PIE) header, with a UPX signature, a URL string,
    /// and a `pop rax; ret` gadget appended — one fixture that exercises identify,
    /// packer, strings, and rop.
    fn sample_bin() -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // 64-bit
        b[5] = 1; // little-endian
        b[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = DYN → PIE
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86_64
        b[24..32].copy_from_slice(&0x1040u64.to_le_bytes()); // e_entry
        b.extend_from_slice(b"UPX!"); // packer signature
        b.extend_from_slice(b"\x00https://evil.example/c2\x00");
        b.push(0x58); // pop rax
        b.push(0xc3); // ret
        b
    }

    #[tokio::test]
    async fn identify_packer_strings_rop_over_a_workspace_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("bin.dat"), sample_bin()).await.unwrap();
        // Relative path exercises ctx.resolve against the session workspace.
        let ctx = || ExecCtx::new().with_cwd(dir.path());

        let ident = run_in(Arc::new(BinIdentifyTool), json!({ "path": "bin.dat" }), ctx()).await;
        assert!(!ident.is_error);
        let iv = ident.value.unwrap();
        assert_eq!(iv["format"], "ELF");
        assert_eq!(iv["arch"], "x86_64");
        assert_eq!(iv["bits"], 64);
        assert_eq!(iv["pie"], true);
        assert_eq!(iv["entry"], 0x1040);
        assert!(iv["path"].as_str().unwrap().ends_with("bin.dat"));

        let pack = run_in(Arc::new(BinPackerTool), json!({ "path": "bin.dat" }), ctx()).await;
        let pv = pack.value.unwrap();
        assert_eq!(pv["packed"], true);
        assert!(pv["signatures"].as_array().unwrap().iter().any(|s| s == "UPX"));

        let strs = run_in(Arc::new(BinStringsTool), json!({ "path": "bin.dat", "category": "url" }), ctx()).await;
        let sv = strs.value.unwrap();
        assert_eq!(sv["groups"]["url"][0], "https://evil.example/c2");

        let rop = run_in(Arc::new(BinRopTool), json!({ "path": "bin.dat" }), ctx()).await;
        let rv = rop.value.unwrap();
        assert!(rv["total"].as_u64().unwrap() >= 1);
        assert!(rv["gadgets"].as_array().unwrap().iter().any(|g| g["bytes_hex"].as_str().unwrap().ends_with("c3")));
    }

    #[tokio::test]
    async fn symbols_report_inline_and_missing_input() {
        let syms = "0000 T main\n     U system\n     U strcpy\n     U dlopen";
        let r = run_in(Arc::new(BinSymbolsReportTool), json!({ "symbols": syms }), ExecCtx::new()).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert_eq!(v["buckets"]["command_exec"][0], "system");
        assert_eq!(v["buckets"]["unsafe_memory"][0], "strcpy");
        assert!(v["buckets"]["dynamic_load"].as_array().unwrap().iter().any(|s| s == "dlopen"));

        // Neither symbols nor path → INVALID_ARGS.
        let bad = run_in(Arc::new(BinSymbolsReportTool), json!({}), ExecCtx::new()).await;
        assert!(bad.is_error);
        assert_eq!(bad.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[tokio::test]
    async fn missing_path_is_invalid_args() {
        let r = run_in(Arc::new(BinIdentifyTool), json!({}), ExecCtx::new()).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[tokio::test]
    async fn missing_file_is_exec_error() {
        let ctx = ExecCtx::new();
        let r = run_in(Arc::new(BinIdentifyTool), json!({ "path": "/no/such/binary.xyz" }), ctx).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("EXEC_ERROR"));
    }
}
