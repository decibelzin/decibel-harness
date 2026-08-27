//! Terraform state audit: sensitive outputs + plaintext secrets baked into the
//! state file (Terraform persists resource attributes — including passwords — in
//! clear text).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloud::{string_leaves, Finding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfstateAudit {
    pub findings: Vec<Finding>,
}

/// A leaf key (the part after the last `.` / `[`) that names a secret.
fn secret_key(path: &str) -> bool {
    let leaf = path.rsplit(['.', '[']).next().unwrap_or(path).to_ascii_lowercase();
    ["password", "secret", "private_key", "token", "access_key", "secret_key"]
        .iter()
        .any(|k| leaf.contains(k))
}

/// Audit a `terraform.tfstate` document.
pub fn audit(tfstate_json: &str) -> Result<TfstateAudit, String> {
    let doc: Value = serde_json::from_str(tfstate_json).map_err(|e| format!("tfstate json: {e}"))?;
    let mut findings = Vec::new();

    // Sensitive outputs: their values sit in the state in plaintext.
    if let Some(outputs) = doc["outputs"].as_object() {
        for (name, o) in outputs {
            if o["sensitive"].as_bool() == Some(true) {
                findings.push(Finding::new("high", "sensitive_output", format!("Output `{name}` is marked sensitive — its value is stored in plaintext in the state.")));
            }
        }
    }

    // Plaintext secrets in resource attributes.
    let mut leaves = Vec::new();
    string_leaves(&doc["resources"], "resources", &mut leaves);
    for (path, value) in leaves {
        if secret_key(&path) && !value.is_empty() && value.len() >= 4 && !value.starts_with("${") {
            let short = path.rsplit(['.', '[']).next().unwrap_or(&path);
            findings.push(Finding::new("high", "plaintext_secret", format!("Resource attribute `{short}` holds a plaintext secret in the state file.")));
        }
    }

    Ok(TfstateAudit { findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_sensitive_output_and_plaintext_resource_secret() {
        let s = r#"{
            "outputs": { "db_password": { "value": "s3cr3tPw", "sensitive": true },
                          "region": { "value": "us-east-1", "sensitive": false } },
            "resources": [
              { "type": "aws_db_instance", "name": "main",
                "instances": [ { "attributes": { "username": "admin", "password": "hunter2primary" } } ] }
            ]
        }"#;
        let a = audit(s).unwrap();
        assert!(a.findings.iter().any(|f| f.id == "sensitive_output" && f.detail.contains("db_password")));
        assert!(a.findings.iter().any(|f| f.id == "plaintext_secret" && f.detail.contains("password")));
        // A non-sensitive output and a plain username don't trip it.
        assert!(!a.findings.iter().any(|f| f.detail.contains("region")));
        assert!(!a.findings.iter().any(|f| f.detail.contains("username")));
    }

    #[test]
    fn clean_state_is_quiet() {
        let s = r#"{"outputs":{"vpc_id":{"value":"vpc-1","sensitive":false}},"resources":[]}"#;
        assert!(audit(s).unwrap().findings.is_empty());
    }
}
