//! Model-facing [`Tool`] wrappers over the pure cloud analyzers. Each tool runs
//! an in-process analyzer (no network, no shell) and returns its serde struct as
//! the canonical value, so a UI card and a future Code Mode read the same fact
//! the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::cloud::{iam, k8s, metadata, s3, tfstate, userdata};
use crate::util::{arg_str, arg_str_opt};

/// Read an argument that may arrive as a JSON string OR an inline JSON value,
/// returning its text form — so a model can pass either `"{...}"` or `{...}`.
fn arg_json_text(args: &Value, key: &str) -> Option<String> {
    match args.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(v) => Some(v.to_string()),
    }
}

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Render a `findings` array (severity/id/detail) into a text summary block.
fn render_findings(header: &str, value: &Value) -> String {
    let empty = Vec::new();
    let findings = value.get("findings").and_then(Value::as_array).unwrap_or(&empty);
    if findings.is_empty() {
        return format!("{header}\n(no findings)");
    }
    let mut out = format!("{header} — {} finding(s)\n", findings.len());
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let id = f.get("id").and_then(Value::as_str).unwrap_or("");
        let detail = f.get("detail").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  [{sev}] {id}: {detail}\n"));
    }
    out
}

/// Audit an AWS IAM policy document for wildcards + privesc primitives (offline).
pub struct IamPolicyAuditTool;

#[async_trait]
impl Tool for IamPolicyAuditTool {
    fn name(&self) -> &str {
        "iam_policy_audit"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "iam_policy_audit".into(),
            description: "Audit an AWS IAM policy document for full-admin (`Action:*`) and service \
                wildcards, `Resource:*` over-grants, `NotAction` allow-all-except patterns, and the \
                canonical IAM privilege-escalation primitives (Rhino Security Labs — PassRole, \
                CreateAccessKey, AttachUserPolicy, AssumeRole, etc.). Offline JSON analysis — accepts \
                the policy as a JSON object or a JSON string."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "policy": { "description": "The IAM policy document ({Statement:...}) as a JSON object or string." }
                },
                "required": ["policy"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let policy = arg_json_text(&arguments, "policy")
            .ok_or_else(|| ToolError::invalid_args("missing required `policy` (the IAM policy JSON, object or string)"))?;
        let audit = iam::audit(&policy).map_err(ToolError::execution)?;
        to_value(audit)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let statements = value.get("statements").and_then(Value::as_u64).unwrap_or(0);
        vec![ContentBlock::text(render_findings(&format!("iam_policy_audit ({statements} statement(s))"), value))]
    }
}

/// Extract S3 bucket names from arbitrary text (offline).
pub struct S3BucketsFromTextTool;

#[async_trait]
impl Tool for S3BucketsFromTextTool {
    fn name(&self) -> &str {
        "s3_buckets_from_text"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "s3_buckets_from_text".into(),
            description: "Extract distinct AWS S3 bucket names from arbitrary text — `s3://bucket`, \
                virtual-hosted (`bucket.s3[.region].amazonaws.com`), and path-style \
                (`s3[.region].amazonaws.com/bucket`) URLs — validated against AWS bucket-naming rules \
                and returned sorted. Offline. Feed it logs, HTML, JS, or config to enumerate targets."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Any text blob to scan for S3 bucket references." }
                },
                "required": ["text"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let text = arg_str(&arguments, "text")?;
        to_value(s3::extract(&text))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let buckets = value.get("buckets").and_then(Value::as_array).unwrap_or(&empty);
        if buckets.is_empty() {
            return vec![ContentBlock::text("s3_buckets_from_text\n(no buckets found)")];
        }
        let mut out = format!("s3_buckets_from_text — {} bucket(s)\n", buckets.len());
        for b in buckets {
            if let Some(name) = b.as_str() {
                out.push_str(&format!("  {name}\n"));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

/// Scan EC2 user-data / cloud-init (or any text) for embedded secrets (offline).
pub struct UserDataSecretsTool;

#[async_trait]
impl Tool for UserDataSecretsTool {
    fn name(&self) -> &str {
        "user_data_secrets"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "user_data_secrets".into(),
            description: "Scan EC2 user-data / cloud-init scripts (or any text blob) for embedded \
                secrets — AWS access/secret keys, private-key blocks, GitHub PATs, Slack tokens, \
                Google API keys, bearer tokens, and password/secret assignments. Reports the 1-based \
                line and a REDACTED preview (never the full secret). Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The user-data / script / config text to scan." }
                },
                "required": ["text"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let text = arg_str(&arguments, "text")?;
        to_value(userdata::scan(&text))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let hits = value.get("hits").and_then(Value::as_array).unwrap_or(&empty);
        if hits.is_empty() {
            return vec![ContentBlock::text("user_data_secrets\n(no secrets found)")];
        }
        let mut out = format!("user_data_secrets — {} hit(s)\n", hits.len());
        for h in hits {
            let kind = h.get("kind").and_then(Value::as_str).unwrap_or("");
            let line = h.get("line").and_then(Value::as_u64).unwrap_or(0);
            let preview = h.get("preview").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  L{line} {kind}: {preview}\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Audit a Kubernetes manifest for container-escape / privilege primitives (offline).
pub struct K8sAuditTool;

#[async_trait]
impl Tool for K8sAuditTool {
    fn name(&self) -> &str {
        "k8s_audit"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "k8s_audit".into(),
            description: "Audit a Kubernetes manifest (Pod or a workload's pod template — \
                Deployment/DaemonSet/StatefulSet/Job) for container-escape and privilege primitives: \
                hostNetwork/hostPID/hostIPC, sensitive hostPath mounts (docker.sock, /, /etc, \
                /var/run), `privileged`, allowPrivilegeEscalation, running as root, dangerous added \
                capabilities (SYS_ADMIN, NET_ADMIN, …), and plaintext env secrets. Offline — accepts \
                the manifest as a JSON object or string."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "manifest": { "description": "The Kubernetes manifest ({kind, spec:...}) as a JSON object or string." }
                },
                "required": ["manifest"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let manifest = arg_json_text(&arguments, "manifest")
            .ok_or_else(|| ToolError::invalid_args("missing required `manifest` (the k8s manifest JSON, object or string)"))?;
        let audit = k8s::audit(&manifest).map_err(ToolError::execution)?;
        to_value(audit)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(render_findings(&format!("k8s_audit (kind={kind})"), value))]
    }
}

/// Audit a Terraform state file for sensitive outputs + plaintext secrets (offline).
pub struct TfstateAuditTool;

#[async_trait]
impl Tool for TfstateAuditTool {
    fn name(&self) -> &str {
        "tfstate_audit"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "tfstate_audit".into(),
            description: "Audit a `terraform.tfstate` document for secrets Terraform persists in clear \
                text: outputs flagged `sensitive` (their values sit in the state), and plaintext \
                secret-named resource attributes (password/secret/private_key/token/access_key). \
                Offline — accepts the state as a JSON object or string."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "tfstate": { "description": "The terraform.tfstate document as a JSON object or string." }
                },
                "required": ["tfstate"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let tfstate = arg_json_text(&arguments, "tfstate")
            .ok_or_else(|| ToolError::invalid_args("missing required `tfstate` (the terraform state JSON, object or string)"))?;
        let audit = tfstate::audit(&tfstate).map_err(ToolError::execution)?;
        to_value(audit)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(render_findings("tfstate_audit", value))]
    }
}

/// List cloud instance-metadata endpoints — the SSRF target catalogue (offline).
pub struct MetadataEndpointsTool;

#[async_trait]
impl Tool for MetadataEndpointsTool {
    fn name(&self) -> &str {
        "metadata_endpoints"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "metadata_endpoints".into(),
            description: "Return the cloud instance-metadata endpoint catalogue — the SSRF target list \
                for AWS/GCP/Azure/Oracle/Alibaba/DigitalOcean/Kubernetes (IMDSv1/v2, credential and \
                OAuth-token URLs, and the headers each requires). Static reference: `provider` filters \
                (case-insensitive); omit or pass `all` for everything. Offline."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "provider": { "type": "string", "description": "aws|gcp|azure|oracle|alibaba|digitalocean|kubernetes, or `all` (default)." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let provider = arg_str_opt(&arguments, "provider").unwrap_or_else(|| "all".into());
        let endpoints = metadata::endpoints(&provider);
        let count = endpoints.len();
        let endpoints_val = to_value(endpoints)?;
        Ok(json!({
            "provider": provider,
            "count": count,
            "endpoints": endpoints_val,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let provider = value.get("provider").and_then(Value::as_str).unwrap_or("all");
        let empty = Vec::new();
        let endpoints = value.get("endpoints").and_then(Value::as_array).unwrap_or(&empty);
        if endpoints.is_empty() {
            return vec![ContentBlock::text(format!("metadata_endpoints ({provider})\n(no endpoints — unknown provider)"))];
        }
        let mut out = format!("metadata_endpoints ({provider}) — {} endpoint(s)\n", endpoints.len());
        for e in endpoints {
            let p = e.get("provider").and_then(Value::as_str).unwrap_or("");
            let url = e.get("url").and_then(Value::as_str).unwrap_or("");
            let note = e.get("note").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  [{p}] {url}\n      {note}\n"));
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

    #[tokio::test]
    async fn iam_audit_flags_admin_wildcard_from_inline_object() {
        let r = run(
            Arc::new(IamPolicyAuditTool),
            json!({ "policy": { "Statement": { "Effect": "Allow", "Action": "*", "Resource": "*" } } }),
        )
        .await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert_eq!(v["statements"], 1);
        assert!(v["findings"].as_array().unwrap().iter().any(|f| f["id"] == "admin_wildcard"));
    }

    #[tokio::test]
    async fn iam_audit_accepts_a_json_string_too() {
        let r = run(
            Arc::new(IamPolicyAuditTool),
            json!({ "policy": r#"{"Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}}"# }),
        )
        .await;
        let v = r.value.unwrap();
        assert!(v["findings"].as_array().unwrap().iter().any(|f| f["id"] == "privesc_primitive"));
    }

    #[tokio::test]
    async fn s3_and_userdata_extract_and_scan() {
        let s3 = run(
            Arc::new(S3BucketsFromTextTool),
            json!({ "text": "logs at s3://prod-assets/x and https://s3.amazonaws.com/legacy-backups/db.sql" }),
        )
        .await;
        let buckets = s3.value.unwrap()["buckets"].clone();
        assert_eq!(buckets, json!(["legacy-backups", "prod-assets"]));

        let ud = run(
            Arc::new(UserDataSecretsTool),
            json!({ "text": "export AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2primary" }),
        )
        .await;
        let hits = ud.value.unwrap()["hits"].clone();
        let arr = hits.as_array().unwrap();
        assert!(arr.iter().any(|h| h["kind"] == "aws_access_key_id"));
        // Redacted preview never carries the full password.
        assert!(arr.iter().all(|h| !h["preview"].as_str().unwrap().contains("hunter2primary")));
    }

    #[tokio::test]
    async fn k8s_and_tfstate_audits_produce_findings() {
        let k = run(
            Arc::new(K8sAuditTool),
            json!({ "manifest": { "kind": "Pod", "spec": { "hostNetwork": true,
                "containers": [ { "name": "c", "securityContext": { "privileged": true } } ] } } }),
        )
        .await;
        let kv = k.value.unwrap();
        assert_eq!(kv["kind"], "Pod");
        assert!(kv["findings"].as_array().unwrap().iter().any(|f| f["id"] == "privileged"));

        let tf = run(
            Arc::new(TfstateAuditTool),
            json!({ "tfstate": { "outputs": { "db_password": { "value": "s3cr3tPw", "sensitive": true } },
                "resources": [ { "instances": [ { "attributes": { "password": "hunter2primary" } } ] } ] } }),
        )
        .await;
        let tv = tf.value.unwrap();
        assert!(tv["findings"].as_array().unwrap().iter().any(|f| f["id"] == "sensitive_output"));
        assert!(tv["findings"].as_array().unwrap().iter().any(|f| f["id"] == "plaintext_secret"));
    }

    #[tokio::test]
    async fn metadata_endpoints_filters_and_defaults_to_all() {
        let aws = run(Arc::new(MetadataEndpointsTool), json!({ "provider": "AWS" })).await;
        let av = aws.value.unwrap();
        assert_eq!(av["provider"], "AWS");
        let eps = av["endpoints"].as_array().unwrap();
        assert!(!eps.is_empty());
        assert!(eps.iter().all(|e| e["provider"] == "aws"));

        // No provider → the full catalogue.
        let all = run(Arc::new(MetadataEndpointsTool), json!({})).await;
        let allv = all.value.unwrap();
        assert_eq!(allv["provider"], "all");
        assert!(allv["count"].as_u64().unwrap() >= 12);
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let r = run(Arc::new(S3BucketsFromTextTool), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));

        let r2 = run(Arc::new(IamPolicyAuditTool), json!({})).await;
        assert!(r2.is_error);
        assert_eq!(r2.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
