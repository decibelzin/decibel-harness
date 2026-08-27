//! Model-facing [`Tool`] wrappers over the bundled OFFLINE reference corpora.
//! Each tool reads a compiled-in table (no network, no shell) and returns the
//! matched rows as the canonical value, so a UI card and a future Code Mode read
//! the same reference the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::refs::{killchain, payloads};
use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Default row cap when the model omits `limit` — high enough that a class or
/// phase lookup returns its whole set, low enough to never flood context.
const DEFAULT_LIMIT: usize = 50;

/// Serialize a lookup result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Resolve the `limit` argument to a usize, defaulting when absent or zero.
fn arg_limit(args: &Value) -> usize {
    match arg_u64_opt(args, "limit") {
        Some(n) if n > 0 => n as usize,
        _ => DEFAULT_LIMIT,
    }
}

/// Search the bundled payload library by vulnerability class and/or keyword.
pub struct PayloadSearchTool;

#[async_trait]
impl Tool for PayloadSearchTool {
    fn name(&self) -> &str {
        "payload_search"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "payload_search".into(),
            description: "Search a bundled OFFLINE library of canonical, publicly-known pentest \
                payloads grouped by vulnerability class. Filter by `vuln_class` (e.g. sqli, xss, \
                ssti, ssrf, lfi, cmdi, xxe, nosqli, proto-pollution, jwt, open-redirect, crlf, \
                graphql, idor) and/or a free-text `keyword` matched against name/payload/notes. \
                Both optional — omit both to list the library. No network; returns reference \
                payloads for authorized testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "vuln_class": { "type": "string", "description": "Vulnerability class to filter by (case-insensitive), e.g. \"sqli\". Empty/omitted = all classes." },
                    "keyword": { "type": "string", "description": "Free-text match against payload name/value/notes, e.g. \"metadata\". Empty/omitted = no keyword filter." },
                    "limit": { "type": "integer", "description": "Max payloads to return (default 50)." }
                },
                "required": []
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let vuln_class = arg_str_opt(&arguments, "vuln_class").unwrap_or_default();
        let keyword = arg_str_opt(&arguments, "keyword").unwrap_or_default();
        let limit = arg_limit(&arguments);
        let results = payloads::search(&vuln_class, &keyword, limit);
        Ok(json!({
            "vuln_class": vuln_class,
            "keyword": keyword,
            "count": results.len(),
            "payloads": to_value(results)?,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let payloads = value.get("payloads").and_then(Value::as_array).unwrap_or(&empty);
        let class = value.get("vuln_class").and_then(Value::as_str).unwrap_or("");
        let keyword = value.get("keyword").and_then(Value::as_str).unwrap_or("");
        let mut filt = Vec::new();
        if !class.is_empty() {
            filt.push(format!("class={class}"));
        }
        if !keyword.is_empty() {
            filt.push(format!("keyword={keyword}"));
        }
        let scope = if filt.is_empty() { "all".to_string() } else { filt.join(" ") };
        if payloads.is_empty() {
            return vec![ContentBlock::text(format!("payload_search ({scope})\n(no payloads)"))];
        }
        let mut out = format!("payload_search ({scope}) — {} payload(s)\n", payloads.len());
        for p in payloads {
            let cls = p.get("class").and_then(Value::as_str).unwrap_or("");
            let name = p.get("name").and_then(Value::as_str).unwrap_or("");
            let payload = p.get("payload").and_then(Value::as_str).unwrap_or("");
            let notes = p.get("notes").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  [{cls}] {name}: {payload}  ({notes})\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Look up bundled red-team tools mapped to a kill-chain phase.
pub struct KillchainLookupTool;

#[async_trait]
impl Tool for KillchainLookupTool {
    fn name(&self) -> &str {
        "killchain_lookup"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "killchain_lookup".into(),
            description: "Look up the red-team tools bundled for one MITRE ATT&CK tactic phase. \
                Phases (kill-chain order): reconnaissance, resource-development, initial-access, \
                execution, persistence, privilege-escalation, defense-evasion, credential-access, \
                discovery, lateral-movement, collection, command-and-control, exfiltration, impact. \
                Common aliases resolve (recon, weaponization, delivery, exploitation, privesc, \
                lateral, c2, creds). OFFLINE reference map — no network."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "phase": { "type": "string", "description": "Kill-chain / ATT&CK tactic phase (or a known alias), e.g. \"credential-access\" or \"privesc\"." },
                    "limit": { "type": "integer", "description": "Max tools to return (default 50)." }
                },
                "required": ["phase"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let phase = arg_str(&arguments, "phase")?;
        let limit = arg_limit(&arguments);
        let tools = killchain::lookup(&phase, limit);
        Ok(json!({
            "phase": phase,
            "count": tools.len(),
            "tools": to_value(tools)?,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(render_entries("killchain_lookup", value))]
    }
}

/// Suggest bundled tools by keyword-matching a free-text objective.
pub struct KillchainSuggestTool;

#[async_trait]
impl Tool for KillchainSuggestTool {
    fn name(&self) -> &str {
        "killchain_suggest"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "killchain_suggest".into(),
            description: "Suggest bundled red-team tools for a free-text objective by keyword-\
                matching it against the kill-chain tool map's names and descriptions (e.g. \"crack \
                the captured password hashes\" → hashcat; \"map active directory attack paths\" → \
                bloodhound). Each hit carries its ATT&CK phase. OFFLINE reference — no network."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "objective": { "type": "string", "description": "Plain-language goal to match against the tool map, e.g. \"dump domain credentials remotely\"." },
                    "limit": { "type": "integer", "description": "Max suggestions to return (default 50)." }
                },
                "required": ["objective"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let objective = arg_str(&arguments, "objective")?;
        let limit = arg_limit(&arguments);
        let tools = killchain::suggest(&objective, limit);
        Ok(json!({
            "objective": objective,
            "count": tools.len(),
            "tools": to_value(tools)?,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(render_entries("killchain_suggest", value))]
    }
}

/// Render a `tools` array of kill-chain entries (phase/name/description) into a
/// text summary block — shared by lookup and suggest.
fn render_entries(header: &str, value: &Value) -> String {
    let empty = Vec::new();
    let entries = value.get("tools").and_then(Value::as_array).unwrap_or(&empty);
    if entries.is_empty() {
        return format!("{header}\n(no tools)");
    }
    let mut out = format!("{header} — {} tool(s)\n", entries.len());
    for e in entries {
        let phase = e.get("phase").and_then(Value::as_str).unwrap_or("");
        let name = e.get("name").and_then(Value::as_str).unwrap_or("");
        let desc = e.get("description").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  [{phase}] {name}: {desc}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;

    async fn run(tool: Arc<dyn Tool>, args: Value) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(
            decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args },
            &ExecCtx::new(),
        )
        .await
    }

    #[tokio::test]
    async fn payload_search_by_class_and_keyword() {
        // By class → every row is that class.
        let by_class = run(Arc::new(PayloadSearchTool), json!({ "vuln_class": "sqli" })).await;
        assert!(!by_class.is_error);
        let v = by_class.value.unwrap();
        let rows = v["payloads"].as_array().unwrap();
        assert!(rows.len() >= 4);
        assert!(rows.iter().all(|p| p["class"] == "sqli"));

        // By keyword → the SSRF metadata payload.
        let by_kw = run(Arc::new(PayloadSearchTool), json!({ "keyword": "metadata" })).await;
        let kv = by_kw.value.unwrap();
        assert_eq!(kv["count"], 1);
        assert_eq!(kv["payloads"][0]["class"], "ssrf");

        // limit is honored.
        let capped = run(Arc::new(PayloadSearchTool), json!({ "limit": 3 })).await;
        assert_eq!(capped.value.unwrap()["payloads"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn killchain_lookup_resolves_phase_and_alias() {
        let recon = run(Arc::new(KillchainLookupTool), json!({ "phase": "reconnaissance" })).await;
        assert!(!recon.is_error);
        let rv = recon.value.unwrap();
        assert!(rv["tools"].as_array().unwrap().iter().any(|e| e["name"] == "nmap"));

        // Alias "privesc" resolves to privilege-escalation.
        let pe = run(Arc::new(KillchainLookupTool), json!({ "phase": "privesc" })).await;
        let pv = pe.value.unwrap();
        assert!(pv["tools"].as_array().unwrap().iter().any(|e| e["name"] == "linpeas"));
    }

    #[tokio::test]
    async fn killchain_suggest_matches_objective() {
        let hits = run(Arc::new(KillchainSuggestTool), json!({ "objective": "crack the captured password hashes" })).await;
        assert!(!hits.is_error);
        let hv = hits.value.unwrap();
        assert!(hv["tools"].as_array().unwrap().iter().any(|e| e["name"] == "hashcat"));
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let r = run(Arc::new(KillchainLookupTool), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
