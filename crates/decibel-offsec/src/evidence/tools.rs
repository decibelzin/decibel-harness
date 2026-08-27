//! Model-facing [`Tool`] wrappers over the pure evidence core. Each tool
//! resolves its file arguments through [`ExecCtx::resolve`] (exactly like the
//! filesystem and reversing tools), does its own offline I/O — reading the
//! artifact, writing the seal sidecar and the append-only custody log, or
//! writing the `.cast` — and returns a canonical serde value so a UI card and a
//! future Code Mode read the same fact the model saw.
//!
//! Three tools: `evidence_seal`, `evidence_verify`, `evidence_asciicast`. All
//! offline (no network), no policy gating.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::evidence::{
    asciicast_from_transcript, build_asciicast, custody_append, custody_verify_chain, seal,
    sha256_hex, verify, CastEvent, CustodyEntry, Seal, GENESIS_PREV,
};
use crate::util::{arg_str, arg_str_opt, arg_u64_opt, truncate_bytes};

/// Default custody log path (resolved against the session workspace).
const DEFAULT_CUSTODY_LOG: &str = "evidence-custody.jsonl";

/// Cap on an inline `.cast` returned to the model when no output path is given.
const MAX_INLINE_CAST_BYTES: usize = 60_000;

/// Unix seconds now — the clock lives in the tool layer so the core stays pure.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The seal sidecar path for an artifact: `<artifact>.seal.json` (append, not
/// replace-extension, so `report.pdf` → `report.pdf.seal.json`).
fn sidecar_path(artifact: &Path) -> PathBuf {
    let mut s = artifact.to_path_buf().into_os_string();
    s.push(".seal.json");
    PathBuf::from(s)
}

/// Read the whole artifact into memory (evidence must cover the entire file, so
/// there is no triage cap — a huge artifact is fully buffered).
async fn read_artifact(path: &Path) -> Result<Vec<u8>, ToolError> {
    tokio::fs::read(path)
        .await
        .map_err(|e| ToolError::execution(format!("cannot read {}: {e}", path.display())))
}

/// Parse a JSONL custody log. A missing file is an empty log; a corrupt line is
/// an execution error (so `evidence_seal` never chains onto an unparseable log).
async fn read_custody_log(path: &Path) -> Result<Vec<CustodyEntry>, ToolError> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ToolError::execution(format!("cannot read custody log {}: {e}", path.display()))),
    };
    let mut entries = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let e: CustodyEntry = serde_json::from_str(line)
            .map_err(|e| ToolError::execution(format!("custody log {} line {}: {e}", path.display(), i + 1)))?;
        entries.push(e);
    }
    Ok(entries)
}

/// Append one JSONL entry to the custody log (creating it and its parent).
async fn append_custody_entry(path: &Path, entry: &CustodyEntry) -> Result<(), ToolError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ToolError::execution(format!("cannot create {}: {e}", parent.display())))?;
        }
    }
    let mut line = serde_json::to_string(entry).map_err(|e| ToolError::execution(e.to_string()))?;
    line.push('\n');
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .map_err(|e| ToolError::execution(format!("cannot open custody log {}: {e}", path.display())))?;
    f.write_all(line.as_bytes())
        .await
        .map_err(|e| ToolError::execution(format!("cannot append to {}: {e}", path.display())))?;
    Ok(())
}

/// Render a `problems` array (kind/detail) into a text summary.
fn render_problems(header: &str, value: &Value) -> String {
    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let empty = Vec::new();
    let problems = value.get("problems").and_then(Value::as_array).unwrap_or(&empty);
    if ok && problems.is_empty() {
        return format!("{header}: OK — chain of custody intact");
    }
    let mut out = format!("{header}: {} problem(s)\n", problems.len());
    for p in problems {
        let kind = p.get("kind").and_then(Value::as_str).unwrap_or("");
        let target = p.get("target").and_then(Value::as_str).unwrap_or("");
        let detail = p.get("detail").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  [{kind}] {target}: {detail}\n"));
    }
    out
}

// ---------------------------------------------------------------------------
// evidence_seal
// ---------------------------------------------------------------------------

/// Seal an artifact (content hash + keyed MAC beside it) and record the event
/// into the append-only, HMAC-chained custody log.
pub struct EvidenceSealTool;

#[async_trait]
impl Tool for EvidenceSealTool {
    fn name(&self) -> &str {
        "evidence_seal"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "evidence_seal".into(),
            description: "Seal an evidence artifact for chain of custody: hash its full contents \
                (SHA-256) and compute an HMAC-SHA256 under the engagement `key`, writing the seal to \
                `<path>.seal.json` beside the artifact, and append the event to an append-only, \
                HMAC-chained custody log so later tampering with, reordering, or deleting records is \
                detectable. Offline. Verify later with evidence_verify."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Artifact to seal (absolute, or relative to the workspace)." },
                    "key": { "type": "string", "description": "Engagement evidence key for the HMAC. Keep it secret and stable across the engagement." },
                    "note": { "type": "string", "description": "Optional note recorded in the seal and custody entry." },
                    "custody_log": { "type": "string", "description": "Custody log path (default evidence-custody.jsonl in the workspace)." }
                },
                "required": ["path", "key"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = ctx.resolve(&arg_str(&arguments, "path")?);
        let key = arg_str(&arguments, "key")?;
        let note = arg_str_opt(&arguments, "note").unwrap_or_default();
        let log_arg = arg_str_opt(&arguments, "custody_log").unwrap_or_else(|| DEFAULT_CUSTODY_LOG.to_string());
        let log_path = ctx.resolve(&log_arg);

        let bytes = read_artifact(&path).await?;
        // Parse the existing chain BEFORE any write, so we fail fast on a corrupt
        // log rather than half-sealing.
        let existing = read_custody_log(&log_path).await?;
        let (prev_mac, seq) = match existing.last() {
            Some(last) => (last.mac.clone(), last.seq + 1),
            None => (GENESIS_PREV.to_string(), 1),
        };

        if ctx.is_cancelled() {
            return Err(ToolError::Aborted);
        }

        let now = now_unix();
        let s = seal(&bytes, key.as_bytes(), &note, now);
        let sidecar = sidecar_path(&path);
        let sidecar_json = serde_json::to_string_pretty(&s).map_err(|e| ToolError::execution(e.to_string()))?;
        tokio::fs::write(&sidecar, &sidecar_json)
            .await
            .map_err(|e| ToolError::execution(format!("cannot write {}: {e}", sidecar.display())))?;

        let artifact_str = path.display().to_string();
        let entry = custody_append(key.as_bytes(), &prev_mac, seq, now, "seal", &artifact_str, &s.sha256, &note);
        append_custody_entry(&log_path, &entry).await?;

        Ok(json!({
            "path": artifact_str,
            "seal_path": sidecar.display().to_string(),
            "custody_log": log_path.display().to_string(),
            "seq": seq,
            "bytes": bytes.len(),
            "seal": s,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let seq = value.get("seq").and_then(Value::as_u64).unwrap_or(0);
        let sha = value.get("seal").and_then(|s| s.get("sha256")).and_then(Value::as_str).unwrap_or("");
        let short = sha.get(0..16).unwrap_or(sha);
        let seal_path = value.get("seal_path").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!(
            "evidence_seal: sealed {path} (sha256 {short}…) as custody #{seq}\n  seal → {seal_path}"
        ))]
    }
}

// ---------------------------------------------------------------------------
// evidence_verify
// ---------------------------------------------------------------------------

/// Verify sealed evidence: re-derive from disk and report drift, missing files,
/// and custody-chain errors.
pub struct EvidenceVerifyTool;

impl EvidenceVerifyTool {
    /// Single-artifact mode: re-derive the seal from disk and compare to the
    /// stored sidecar.
    async fn verify_artifact(ctx: &ExecCtx, arguments: &Value, key: &str) -> Result<Value, ToolError> {
        let path = ctx.resolve(&arg_str(arguments, "path")?);
        let mut problems = Vec::new();
        let target = path.display().to_string();

        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                problems.push(json!({ "kind": "missing", "target": target, "detail": "artifact not found on disk" }));
                None
            }
            Err(e) => return Err(ToolError::execution(format!("cannot read {}: {e}", path.display()))),
        };

        let sidecar = sidecar_path(&path);
        let sidecar_text = match tokio::fs::read_to_string(&sidecar).await {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                problems.push(json!({ "kind": "missing_seal", "target": sidecar.display().to_string(), "detail": "seal sidecar not found" }));
                None
            }
            Err(e) => return Err(ToolError::execution(format!("cannot read {}: {e}", sidecar.display()))),
        };

        if let (Some(bytes), Some(text)) = (bytes.as_ref(), sidecar_text.as_ref()) {
            let s: Seal = serde_json::from_str(text)
                .map_err(|e| ToolError::execution(format!("seal sidecar {}: {e}", sidecar.display())))?;
            if !verify(bytes, key.as_bytes(), &s) {
                // Classify: content changed (drift) vs. hmac/key mismatch.
                if sha256_hex(bytes) != s.sha256 {
                    problems.push(json!({ "kind": "drift", "target": target, "detail": "content hash no longer matches the seal" }));
                } else {
                    problems.push(json!({ "kind": "seal_mismatch", "target": target, "detail": "hmac does not verify (wrong key or tampered seal)" }));
                }
            }
        }

        let ok = problems.is_empty();
        Ok(json!({ "mode": "artifact", "ok": ok, "target": target, "problems": problems }))
    }

    /// Chain mode: verify the custody log's integrity, then re-hash each
    /// artifact's current bytes against its most recent recorded hash.
    async fn verify_chain(ctx: &ExecCtx, arguments: &Value, key: &str) -> Result<Value, ToolError> {
        let log_arg = arg_str_opt(arguments, "custody_log").unwrap_or_else(|| DEFAULT_CUSTODY_LOG.to_string());
        let log_path = ctx.resolve(&log_arg);
        let mut problems = Vec::new();

        if !tokio::fs::try_exists(&log_path).await.unwrap_or(false) {
            problems.push(json!({ "kind": "missing", "target": log_path.display().to_string(), "detail": "custody log not found" }));
            return Ok(json!({ "mode": "chain", "ok": false, "custody_log": log_path.display().to_string(), "entries": 0, "problems": problems }));
        }

        let entries = read_custody_log(&log_path).await?;

        // Structural chain integrity (reorder / delete / edit / wrong key).
        for err in custody_verify_chain(key.as_bytes(), &entries) {
            problems.push(json!({ "kind": "chain", "target": format!("#{}", err.seq), "detail": format!("{}: {}", err.kind, err.detail) }));
        }

        // Disk drift: only the LATEST entry per artifact reflects the current
        // expected state, so re-hash against that (older entries are history).
        let mut latest: std::collections::HashMap<&str, &CustodyEntry> = std::collections::HashMap::new();
        for e in &entries {
            latest.insert(e.artifact.as_str(), e);
        }
        // Deterministic order by seq for stable reporting.
        let mut newest: Vec<&CustodyEntry> = latest.values().copied().collect();
        newest.sort_by_key(|e| e.seq);
        for e in newest {
            let apath = ctx.resolve(&e.artifact);
            match tokio::fs::read(&apath).await {
                Ok(bytes) => {
                    if sha256_hex(&bytes) != e.sha256 {
                        problems.push(json!({ "kind": "drift", "target": e.artifact, "detail": format!("current content hash differs from custody #{}", e.seq) }));
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    problems.push(json!({ "kind": "missing", "target": e.artifact, "detail": format!("artifact from custody #{} not found on disk", e.seq) }));
                }
                Err(err) => return Err(ToolError::execution(format!("cannot read {}: {err}", apath.display()))),
            }
        }

        let ok = problems.is_empty();
        Ok(json!({ "mode": "chain", "ok": ok, "custody_log": log_path.display().to_string(), "entries": entries.len(), "problems": problems }))
    }
}

#[async_trait]
impl Tool for EvidenceVerifyTool {
    fn name(&self) -> &str {
        "evidence_verify"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "evidence_verify".into(),
            description: "Verify sealed evidence under the engagement `key`. Give `path` to check one \
                artifact against its `<path>.seal.json` sidecar (reports drift if the content changed, \
                or a missing artifact/seal). Otherwise verifies the whole append-only custody log: its \
                HMAC chain integrity (insertion, reordering, deletion, or edits) plus disk drift of \
                every referenced artifact. Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "key": { "type": "string", "description": "The engagement evidence key used when sealing." },
                    "path": { "type": "string", "description": "A single artifact to verify against its seal sidecar. Omit to verify the custody log." },
                    "custody_log": { "type": "string", "description": "Custody log path (default evidence-custody.jsonl); used in chain mode." }
                },
                "required": ["key"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let key = arg_str(&arguments, "key")?;
        if arguments.get("path").and_then(Value::as_str).is_some() {
            Self::verify_artifact(ctx, &arguments, &key).await
        } else {
            Self::verify_chain(ctx, &arguments, &key).await
        }
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let mode = value.get("mode").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(render_problems(&format!("evidence_verify ({mode})"), value))]
    }
}

// ---------------------------------------------------------------------------
// evidence_asciicast
// ---------------------------------------------------------------------------

/// Export a session transcript to an asciinema v2 `.cast`.
pub struct EvidenceAsciicastTool;

#[async_trait]
impl Tool for EvidenceAsciicastTool {
    fn name(&self) -> &str {
        "evidence_asciicast"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "evidence_asciicast".into(),
            description: "Export a terminal session transcript to an asciinema v2 `.cast` for replay. \
                Supply `transcript` inline, `transcript_path` to read a file, or `events` \
                ([{time,data}] with per-chunk timing). With `out` the `.cast` is written there; without \
                it the cast text is returned inline. `width`/`height` default to 120x30. Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "transcript": { "type": "string", "description": "The full transcript text (single event at t=0)." },
                    "transcript_path": { "type": "string", "description": "Path to a transcript file to read instead of `transcript`." },
                    "events": {
                        "type": "array",
                        "description": "Timed output events, if per-chunk timing is known.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "time": { "type": "number", "description": "Seconds from the start." },
                                "data": { "type": "string", "description": "Terminal output at that time." }
                            },
                            "required": ["time", "data"]
                        }
                    },
                    "out": { "type": "string", "description": "Output `.cast` path. Omit to return the cast inline." },
                    "title": { "type": "string", "description": "Recording title (default \"session\")." },
                    "width": { "type": "integer", "description": "Terminal columns (default 120)." },
                    "height": { "type": "integer", "description": "Terminal rows (default 30)." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let width = arg_u64_opt(&arguments, "width").unwrap_or(120) as u32;
        let height = arg_u64_opt(&arguments, "height").unwrap_or(30) as u32;
        let title = arg_str_opt(&arguments, "title").unwrap_or_else(|| "session".to_string());
        let created_at = now_unix();

        // Precedence: explicit timed `events` > `transcript_path` > inline `transcript`.
        let events: Option<Vec<CastEvent>> = arguments.get("events").and_then(Value::as_array).map(|arr| {
            arr.iter()
                .map(|e| CastEvent {
                    time: e.get("time").and_then(Value::as_f64).unwrap_or(0.0),
                    data: e.get("data").and_then(Value::as_str).unwrap_or("").to_string(),
                })
                .collect()
        });

        let (cast, event_count) = if let Some(events) = events {
            let n = events.len();
            (build_asciicast(width, height, &title, created_at, &events), n)
        } else {
            let transcript = if let Some(p) = arg_str_opt(&arguments, "transcript_path") {
                let path = ctx.resolve(&p);
                tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| ToolError::execution(format!("cannot read {}: {e}", path.display())))?
            } else if let Some(t) = arguments.get("transcript").and_then(Value::as_str) {
                t.to_string()
            } else {
                return Err(ToolError::invalid_args("provide one of `transcript`, `transcript_path`, or `events`"));
            };
            (asciicast_from_transcript(width, height, &title, created_at, &transcript), 1)
        };

        if let Some(out_arg) = arg_str_opt(&arguments, "out") {
            let out = ctx.resolve(&out_arg);
            if ctx.is_cancelled() {
                return Err(ToolError::Aborted);
            }
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .map_err(|e| ToolError::execution(format!("cannot create {}: {e}", parent.display())))?;
                }
            }
            tokio::fs::write(&out, &cast)
                .await
                .map_err(|e| ToolError::execution(format!("cannot write {}: {e}", out.display())))?;
            Ok(json!({
                "out": out.display().to_string(),
                "bytes": cast.len(),
                "events": event_count,
                "width": width,
                "height": height,
            }))
        } else {
            let (inline, truncated) = truncate_bytes(&cast, MAX_INLINE_CAST_BYTES);
            Ok(json!({
                "cast": inline,
                "bytes": cast.len(),
                "events": event_count,
                "width": width,
                "height": height,
                "truncated": truncated,
            }))
        }
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let events = value.get("events").and_then(Value::as_u64).unwrap_or(0);
        let bytes = value.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        if let Some(out) = value.get("out").and_then(Value::as_str) {
            vec![ContentBlock::text(format!("evidence_asciicast: wrote {bytes} bytes ({events} event(s)) → {out}"))]
        } else {
            let cast = value.get("cast").and_then(Value::as_str).unwrap_or("");
            let mut out = format!("evidence_asciicast ({events} event(s), {bytes} bytes)\n{cast}");
            if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
                out.push_str("\n[truncated]");
            }
            vec![ContentBlock::text(out)]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;

    async fn run(tool: Arc<dyn Tool>, args: Value, ctx: &ExecCtx) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args }, ctx).await
    }

    #[tokio::test]
    async fn seal_then_verify_clean_then_detect_drift() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let artifact = dir.path().join("find-001.txt");
        tokio::fs::write(&artifact, "SQLi on /login (validated)").await.unwrap();

        // seal → sidecar + custody entry #1
        let sealed = run(
            Arc::new(EvidenceSealTool),
            json!({ "path": "find-001.txt", "key": "engagement-secret", "note": "FIND-001" }),
            &ctx,
        )
        .await;
        assert!(!sealed.is_error, "seal ok: {:?}", sealed);
        let sv = sealed.value.unwrap();
        assert_eq!(sv["seq"], 1);
        assert!(dir.path().join("find-001.txt.seal.json").exists(), "seal sidecar written beside artifact");
        assert!(dir.path().join("evidence-custody.jsonl").exists(), "custody log written");

        // verify single artifact → OK
        let v = run(Arc::new(EvidenceVerifyTool), json!({ "path": "find-001.txt", "key": "engagement-secret" }), &ctx).await;
        assert_eq!(v.value.unwrap()["ok"], true);

        // verify chain → OK (intact custody log + no drift)
        let vc = run(Arc::new(EvidenceVerifyTool), json!({ "key": "engagement-secret" }), &ctx).await;
        assert_eq!(vc.value.unwrap()["ok"], true);

        // tamper the artifact on disk → drift is detected in both modes
        tokio::fs::write(&artifact, "SQLi on /login (FAKE)").await.unwrap();
        let v2 = run(Arc::new(EvidenceVerifyTool), json!({ "path": "find-001.txt", "key": "engagement-secret" }), &ctx).await;
        let v2v = v2.value.unwrap();
        assert_eq!(v2v["ok"], false);
        assert!(v2v["problems"].as_array().unwrap().iter().any(|p| p["kind"] == "drift"));

        let vc2 = run(Arc::new(EvidenceVerifyTool), json!({ "key": "engagement-secret" }), &ctx).await;
        let vc2v = vc2.value.unwrap();
        assert_eq!(vc2v["ok"], false);
        assert!(vc2v["problems"].as_array().unwrap().iter().any(|p| p["kind"] == "drift"));
    }

    #[tokio::test]
    async fn wrong_key_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ExecCtx::new().with_cwd(dir.path());
        tokio::fs::write(dir.path().join("a.txt"), "data").await.unwrap();
        run(Arc::new(EvidenceSealTool), json!({ "path": "a.txt", "key": "right" }), &ctx).await;

        let v = run(Arc::new(EvidenceVerifyTool), json!({ "path": "a.txt", "key": "wrong" }), &ctx).await;
        let vv = v.value.unwrap();
        assert_eq!(vv["ok"], false);
        assert!(vv["problems"].as_array().unwrap().iter().any(|p| p["kind"] == "seal_mismatch"));

        // The custody chain also fails to verify under the wrong key.
        let vc = run(Arc::new(EvidenceVerifyTool), json!({ "key": "wrong" }), &ctx).await;
        let vcv = vc.value.unwrap();
        assert_eq!(vcv["ok"], false);
        assert!(vcv["problems"].as_array().unwrap().iter().any(|p| p["kind"] == "chain"));
    }

    #[tokio::test]
    async fn custody_log_tamper_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ExecCtx::new().with_cwd(dir.path());
        for i in 0..3 {
            let name = format!("e{i}.txt");
            tokio::fs::write(dir.path().join(&name), format!("artifact {i}")).await.unwrap();
            run(Arc::new(EvidenceSealTool), json!({ "path": name, "key": "k" }), &ctx).await;
        }
        // Clean chain verifies.
        let vc = run(Arc::new(EvidenceVerifyTool), json!({ "key": "k" }), &ctx).await;
        assert_eq!(vc.value.unwrap()["ok"], true);

        // Delete the middle custody line → chain breaks.
        let log = dir.path().join("evidence-custody.jsonl");
        let text = tokio::fs::read_to_string(&log).await.unwrap();
        let mut lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        lines.remove(1);
        tokio::fs::write(&log, lines.join("\n") + "\n").await.unwrap();

        let vc2 = run(Arc::new(EvidenceVerifyTool), json!({ "key": "k" }), &ctx).await;
        let vc2v = vc2.value.unwrap();
        assert_eq!(vc2v["ok"], false);
        assert!(vc2v["problems"].as_array().unwrap().iter().any(|p| p["kind"] == "chain"));
    }

    #[tokio::test]
    async fn asciicast_inline_and_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ExecCtx::new().with_cwd(dir.path());

        // inline transcript → cast returned in the value
        let inline = run(
            Arc::new(EvidenceAsciicastTool),
            json!({ "transcript": "$ nmap 10.0.0.5\n445/tcp open\n", "title": "recon" }),
            &ctx,
        )
        .await;
        let iv = inline.value.unwrap();
        let cast = iv["cast"].as_str().unwrap();
        let header: Value = serde_json::from_str(cast.lines().next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);

        // transcript_path + out → .cast written to disk
        tokio::fs::write(dir.path().join("t.log"), "line one\nline two\n").await.unwrap();
        let written = run(
            Arc::new(EvidenceAsciicastTool),
            json!({ "transcript_path": "t.log", "out": "rec.cast" }),
            &ctx,
        )
        .await;
        assert!(!written.is_error, "asciicast write ok: {:?}", written);
        let cast_file = tokio::fs::read_to_string(dir.path().join("rec.cast")).await.unwrap();
        let ev: Value = serde_json::from_str(cast_file.lines().nth(1).unwrap()).unwrap();
        assert_eq!(ev[2], "line one\nline two\n");

        // events array → multi-event cast
        let timed = run(
            Arc::new(EvidenceAsciicastTool),
            json!({ "events": [ { "time": 0.0, "data": "a" }, { "time": 1.5, "data": "b" } ], "out": "timed.cast" }),
            &ctx,
        )
        .await;
        assert_eq!(timed.value.unwrap()["events"], 2);
    }

    #[tokio::test]
    async fn missing_key_is_invalid_args() {
        let r = run(Arc::new(EvidenceSealTool), json!({ "path": "x" }), &ExecCtx::new()).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[tokio::test]
    async fn asciicast_requires_a_source() {
        let r = run(Arc::new(EvidenceAsciicastTool), json!({ "title": "empty" }), &ExecCtx::new()).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
