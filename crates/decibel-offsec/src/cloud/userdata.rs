//! Scan EC2 user-data / cloud-init (or any text blob) for embedded secrets.

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHit {
    pub kind: String,
    pub line: usize,
    /// A redacted preview (first chars + …), never the full secret.
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretScan {
    pub hits: Vec<SecretHit>,
}

fn rules() -> Vec<(&'static str, Regex)> {
    let r = |s: &str| Regex::new(s).expect("static regex");
    vec![
        ("aws_access_key_id", r(r"AKIA[0-9A-Z]{16}")),
        ("aws_secret_access_key", r(r#"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}"#)),
        ("private_key_block", r(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("github_pat", r(r"ghp_[A-Za-z0-9]{36}")),
        ("slack_token", r(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
        ("google_api_key", r(r"AIza[0-9A-Za-z\-_]{35}")),
        ("bearer_token", r(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
        ("password_assignment", r(r#"(?i)(password|passwd|pwd)\s*[=:]\s*\S{4,}"#)),
        ("generic_secret", r(r#"(?i)(secret|api[_-]?key|token)\s*[=:]\s*\S{8,}"#)),
    ]
}

fn redact(s: &str) -> String {
    let head: String = s.chars().take(6).collect();
    format!("{head}…")
}

/// Scan `text` for secrets, reporting the 1-based line and a redacted preview.
pub fn scan(text: &str) -> SecretScan {
    let rules = rules();
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        for (kind, re) in &rules {
            if let Some(m) = re.find(line) {
                hits.push(SecretHit { kind: kind.to_string(), line: i + 1, preview: redact(m.as_str()) });
            }
        }
    }
    SecretScan { hits }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aws_key_and_password_and_redacts() {
        let text = "#!/bin/bash\nexport AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASSWORD=hunter2primary\necho done";
        let s = scan(text);
        assert!(s.hits.iter().any(|h| h.kind == "aws_access_key_id" && h.line == 2));
        assert!(s.hits.iter().any(|h| h.kind == "password_assignment" && h.line == 3));
        // Never leak the full secret.
        assert!(s.hits.iter().all(|h| h.preview.ends_with('…')));
        assert!(!s.hits.iter().any(|h| h.preview.contains("hunter2primary")));
    }

    #[test]
    fn finds_private_key_block_and_github_pat() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\ntoken=ghp_012345678901234567890123456789012345";
        let s = scan(text);
        assert!(s.hits.iter().any(|h| h.kind == "private_key_block"));
        assert!(s.hits.iter().any(|h| h.kind == "github_pat"));
    }

    #[test]
    fn clean_userdata_has_no_hits() {
        assert!(scan("#!/bin/bash\napt-get update\nsystemctl restart nginx").hits.is_empty());
    }
}
