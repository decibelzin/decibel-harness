//! Model-facing [`Tool`] wrappers over the CVE-intelligence client. Unlike the
//! `web/`/`cloud/` analyzers these tools **reach the network** (the public NVD /
//! EPSS / OSV APIs), so each body races its work against `ctx.token()` with
//! `tokio::select!` and returns [`ToolError::Aborted`] on cancellation — the
//! `http`/arsenal pattern. Each returns the scored CVE record(s) as its
//! canonical value (no knowledge-graph ingest), so a UI card and a future Code
//! Mode read the same fact the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::cve::{by_package, lookup, Config, CveCache};
use crate::util::arg_str;

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Look up + score a single CVE: NVD CVSS + EPSS + KEV floor → one composite.
pub struct CveLookupTool {
    cache: CveCache,
}

impl CveLookupTool {
    /// Build the tool over a fresh in-process cache (the `AddFindingTool`
    /// pattern). Register as `Arc::new(CveLookupTool::new())`.
    pub fn new() -> Self {
        CveLookupTool { cache: CveCache::new() }
    }
}

impl Default for CveLookupTool {
    fn default() -> Self {
        CveLookupTool::new()
    }
}

#[async_trait]
impl Tool for CveLookupTool {
    fn name(&self) -> &str {
        "cve_lookup"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "cve_lookup".into(),
            description: "Look up a CVE by id and score how EXPLOITABLE it really is: NVD CVSS \
                (severity), EPSS (real-world 30-day exploit probability), and a CISA KEV floor \
                (actively-exploited CVEs are pinned high) combined into one 0-10 composite with a \
                severity rating and the CVE description. Reaches the public NVD + EPSS APIs (no key \
                needed); repeats within the session are served from an in-process cache."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "cve": { "type": "string", "description": "The CVE id, e.g. CVE-2021-44228 (case-insensitive)." }
                },
                "required": ["cve"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let id = arg_str(&arguments, "cve")?;
        let cfg = Config::default();
        let records = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = lookup(std::slice::from_ref(&id), &cfg, &self.cache) => r.map_err(ToolError::execution)?,
        };
        let record = records
            .into_iter()
            .next()
            .ok_or_else(|| ToolError::execution(format!("no CVE record produced for `{id}`")))?;
        to_value(record)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let id = value.get("id").and_then(Value::as_str).unwrap_or("");
        let composite = value.get("composite").and_then(Value::as_f64).unwrap_or(0.0);
        let severity = value.get("severity").and_then(Value::as_str).unwrap_or("");
        let mut out = format!("cve_lookup {id} — composite {composite:.1} ({severity})\n");
        match value.get("cvss").and_then(Value::as_f64) {
            Some(c) => out.push_str(&format!("  CVSS: {c:.1}\n")),
            None => out.push_str("  CVSS: (none)\n"),
        }
        match value.get("epss").and_then(Value::as_f64) {
            Some(e) => out.push_str(&format!("  EPSS: {e:.4}\n")),
            None => out.push_str("  EPSS: (none)\n"),
        }
        if value.get("kev").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("  KEV: actively exploited (CISA)\n");
        }
        if let Some(desc) = value.get("description").and_then(Value::as_str) {
            out.push_str(&format!("  {}\n", desc.chars().take(300).collect::<String>()));
        }
        vec![ContentBlock::text(out)]
    }
}

/// OSV lookup: which vulnerability ids affect a package version.
pub struct CveByPackageTool;

#[async_trait]
impl Tool for CveByPackageTool {
    fn name(&self) -> &str {
        "cve_by_package"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "cve_by_package".into(),
            description: "Look up which known vulnerabilities affect a specific package version, via \
                the OSV.dev database. Give the ecosystem, package name, and exact version; returns the \
                affected vulnerability ids (CVE / GHSA / …) — feed those into cve_lookup for \
                exploitability scoring. Reaches the public OSV API (no key needed)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "ecosystem": { "type": "string", "description": "OSV ecosystem, e.g. PyPI, npm, crates.io, Go, Maven, RubyGems, NuGet." },
                    "package": { "type": "string", "description": "Package name as published in that ecosystem." },
                    "version": { "type": "string", "description": "Exact package version to check, e.g. 2.14.1." }
                },
                "required": ["ecosystem", "package", "version"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let ecosystem = arg_str(&arguments, "ecosystem")?;
        let package = arg_str(&arguments, "package")?;
        let version = arg_str(&arguments, "version")?;
        let cfg = Config::default();
        let ids = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = by_package(&package, &version, &ecosystem, &cfg) => r.map_err(ToolError::execution)?,
        };
        Ok(json!({
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "count": ids.len(),
            "vulns": ids,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let ecosystem = value.get("ecosystem").and_then(Value::as_str).unwrap_or("");
        let package = value.get("package").and_then(Value::as_str).unwrap_or("");
        let version = value.get("version").and_then(Value::as_str).unwrap_or("");
        let empty = Vec::new();
        let vulns = value.get("vulns").and_then(Value::as_array).unwrap_or(&empty);
        if vulns.is_empty() {
            return vec![ContentBlock::text(format!(
                "cve_by_package {ecosystem}:{package}@{version}\n(no known vulnerabilities)"
            ))];
        }
        let mut out = format!(
            "cve_by_package {ecosystem}:{package}@{version} — {} vuln(s)\n",
            vulns.len()
        );
        for v in vulns {
            if let Some(idv) = v.as_str() {
                out.push_str(&format!("  {idv}\n"));
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

    // Offline only: missing-argument validation happens before any network I/O,
    // and `render` is pure. The live end-to-end path is covered in `cve` mod via
    // a local mock server — no test here touches the real NVD/EPSS/OSV APIs.

    #[tokio::test]
    async fn cve_lookup_missing_arg_is_invalid_args() {
        let r = run(Arc::new(CveLookupTool::new()), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[tokio::test]
    async fn cve_by_package_missing_arg_is_invalid_args() {
        // ecosystem + package present, version missing → INVALID_ARGS before any request.
        let r = run(
            Arc::new(CveByPackageTool),
            json!({ "ecosystem": "PyPI", "package": "requests" }),
        )
        .await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[test]
    fn cve_lookup_render_summarizes_the_record() {
        let value = json!({
            "id": "CVE-2021-44228", "cvss": 10.0, "epss": 0.97, "kev": true,
            "composite": 10.0, "severity": "Critical", "description": "Log4Shell RCE"
        });
        let content = CveLookupTool::new().render(&json!({}), &value);
        match &content[0] {
            ContentBlock::Text { text } => {
                assert!(text.contains("CVE-2021-44228"));
                assert!(text.contains("composite 10.0"));
                assert!(text.contains("Critical"));
                assert!(text.contains("KEV"));
                assert!(text.contains("Log4Shell RCE"));
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn cve_by_package_render_lists_vulns() {
        let value = json!({
            "ecosystem": "Maven", "package": "log4j-core", "version": "2.14.1",
            "count": 1, "vulns": ["CVE-2021-44228"]
        });
        let content = CveByPackageTool.render(&json!({}), &value);
        match &content[0] {
            ContentBlock::Text { text } => {
                assert!(text.contains("log4j-core@2.14.1"));
                assert!(text.contains("CVE-2021-44228"));
            }
            _ => panic!("expected text"),
        }
    }
}
