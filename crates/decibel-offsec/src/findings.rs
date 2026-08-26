//! The `add_finding` tool and the engagement's finding store.
//!
//! A finding is a durable security result the agent records as it works: a
//! severity, what and where, optional MITRE ATT&CK technique, and evidence. The
//! store is a shared handle the app reads to build a report; the tool returns
//! the recorded finding as its canonical value.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_str_opt};

/// One recorded security finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Short title of the issue.
    pub title: String,
    /// Severity: info | low | medium | high | critical.
    pub severity: String,
    /// What the issue is and why it matters.
    pub description: String,
    /// Affected target (host, URL, service), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// MITRE ATT&CK technique id (e.g. `T1190`), when it maps to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre: Option<String>,
    /// Supporting evidence (command output, request/response excerpt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// A cloneable handle to the engagement's ordered list of findings.
#[derive(Clone, Default)]
pub struct FindingStore(Arc<Mutex<Vec<Finding>>>);

impl FindingStore {
    /// A fresh empty store.
    pub fn new() -> Self {
        FindingStore::default()
    }

    /// Append one finding.
    pub fn push(&self, finding: Finding) {
        // A poisoned lock only means a prior panic while holding it; recover the
        // guard so recording a finding never itself panics.
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.push(finding);
    }

    /// A snapshot copy of every finding recorded so far.
    pub fn snapshot(&self) -> Vec<Finding> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The number of findings recorded.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether no finding has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Record a security finding into the shared [`FindingStore`].
pub struct AddFindingTool {
    store: FindingStore,
}

impl AddFindingTool {
    /// Build the tool over a shared store handle.
    pub fn new(store: FindingStore) -> Self {
        AddFindingTool { store }
    }
}

const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

#[async_trait]
impl Tool for AddFindingTool {
    fn name(&self) -> &str {
        "add_finding"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "add_finding".into(),
            description: "Record a security finding for the engagement report: a severity, what \
                the issue is, where, an optional MITRE ATT&CK technique id, and evidence. Call it \
                whenever you confirm a vulnerability or notable weakness."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "title": { "type": "string", "description": "Short title of the finding." },
                    "severity": { "type": "string", "enum": SEVERITIES, "description": "Severity level." },
                    "description": { "type": "string", "description": "What the issue is and its impact." },
                    "target": { "type": "string", "description": "Affected host, URL, or service." },
                    "mitre": { "type": "string", "description": "MITRE ATT&CK technique id, e.g. T1190." },
                    "evidence": { "type": "string", "description": "Supporting output or excerpt." }
                },
                "required": ["title", "severity", "description"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let title = arg_str(&arguments, "title")?;
        let severity = arg_str(&arguments, "severity")?.to_ascii_lowercase();
        if !SEVERITIES.contains(&severity.as_str()) {
            return Err(ToolError::invalid_args(format!(
                "`severity` must be one of {SEVERITIES:?}, got `{severity}`"
            )));
        }
        let description = arg_str(&arguments, "description")?;
        let finding = Finding {
            title,
            severity,
            description,
            target: arg_str_opt(&arguments, "target"),
            mitre: arg_str_opt(&arguments, "mitre"),
            evidence: arg_str_opt(&arguments, "evidence"),
        };
        self.store.push(finding.clone());
        let index = self.store.len();

        Ok(json!({
            "recorded": true,
            "index": index,
            "finding": finding,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let finding = value.get("finding");
        let title = finding.and_then(|f| f.get("title")).and_then(Value::as_str).unwrap_or("");
        let severity = finding.and_then(|f| f.get("severity")).and_then(Value::as_str).unwrap_or("");
        let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
        let mitre = finding
            .and_then(|f| f.get("mitre"))
            .and_then(Value::as_str)
            .map(|m| format!(" [{m}]"))
            .unwrap_or_default();
        vec![ContentBlock::text(format!(
            "recorded finding #{index}: [{severity}] {title}{mitre}"
        ))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_a_finding_into_the_shared_store() {
        let store = FindingStore::new();
        let tool = AddFindingTool::new(store.clone());
        let value = tool
            .execute(
                json!({
                    "title": "SQL injection in /login",
                    "severity": "High",
                    "description": "The id parameter is injectable.",
                    "target": "https://t/login",
                    "mitre": "T1190"
                }),
                &ExecCtx::new(),
            )
            .await
            .unwrap();
        assert_eq!(value["recorded"], true);
        assert_eq!(value["index"], 1);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].severity, "high"); // normalized lowercase
        assert_eq!(snap[0].mitre.as_deref(), Some("T1190"));
    }

    #[tokio::test]
    async fn invalid_severity_is_rejected() {
        let tool = AddFindingTool::new(FindingStore::new());
        let err = tool
            .execute(json!({ "title": "x", "severity": "spicy", "description": "d" }), &ExecCtx::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGS");
    }
}
