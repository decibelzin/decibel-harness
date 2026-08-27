//! Pure, offline cloud analyzers — ported from Decepticon's `tools/cloud`
//! bucket (crate `decepticon-cloud`) into Decibel with **no executor
//! dependency**: every capability is in-process, deterministic, and unit-tested.
//!
//! Six capabilities, surfaced as model-facing tools in [`tools`]: AWS IAM privesc
//! audit (`iam_policy_audit`), S3 bucket extraction (`s3_buckets_from_text`),
//! EC2 user-data secret scan (`user_data_secrets`), Kubernetes manifest audit
//! (`k8s_audit`), Terraform-state secret scan (`tfstate_audit`), and the cloud
//! metadata SSRF endpoint catalogue (`metadata_endpoints`). Each analyzer returns
//! a serde struct so the tool layer hands it straight to the model (and, later,
//! the knowledge graph) as a canonical value.

pub mod iam;
pub mod k8s;
pub mod metadata;
pub mod s3;
pub mod tfstate;
pub mod tools;
pub mod userdata;

use serde::{Deserialize, Serialize};

/// One analyzer finding. `severity` uses the KG scale (info|low|medium|high|critical).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub id: String,
    pub detail: String,
}

impl Finding {
    pub fn new(severity: &str, id: &str, detail: impl Into<String>) -> Self {
        Finding { severity: severity.into(), id: id.into(), detail: detail.into() }
    }
}

/// Recursively walk a JSON value, yielding every `(json-path, string-value)` leaf.
/// Shared by the secret scanners (tfstate / k8s env).
pub(crate) fn string_leaves(v: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::String(s) => out.push((path.to_string(), s.clone())),
        serde_json::Value::Array(a) => {
            for (i, e) in a.iter().enumerate() {
                string_leaves(e, &format!("{path}[{i}]"), out);
            }
        }
        serde_json::Value::Object(o) => {
            for (k, e) in o {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                string_leaves(e, &p, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finding_new_sets_fields() {
        let f = Finding::new("high", "privesc_primitive", "detail text");
        assert_eq!(f.severity, "high");
        assert_eq!(f.id, "privesc_primitive");
        assert_eq!(f.detail, "detail text");
    }

    #[test]
    fn string_leaves_walks_nested_json() {
        let v = json!({ "a": "x", "b": [ "y", { "c": "z" } ], "n": 5 });
        let mut out = Vec::new();
        string_leaves(&v, "", &mut out);
        // Only string leaves are yielded, each with its json-path.
        assert!(out.contains(&("a".to_string(), "x".to_string())));
        assert!(out.contains(&("b[0]".to_string(), "y".to_string())));
        assert!(out.contains(&("b[1].c".to_string(), "z".to_string())));
        assert_eq!(out.len(), 3); // the numeric leaf `n` is skipped
    }
}
