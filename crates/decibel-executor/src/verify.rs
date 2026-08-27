//! PoC verification with a differential negative control (the zero-false-
//! positive gate, port spec §7). A finding validates only when the positive PoC
//! shows a success marker AND a baseline/negative run does NOT — killing the
//! "it printed the string but so does everything" class of false positive.

use serde::{Deserialize, Serialize};

use crate::{ExecRequest, Executor};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocSpec {
    /// The exploit command whose output should contain a success marker.
    pub command: String,
    /// Any of these substrings in the output ⇒ success.
    pub success_patterns: Vec<String>,
    /// A baseline command that should NOT reproduce success (differential control).
    #[serde(default)]
    pub negative_command: Option<String>,
    /// Substrings expected in the baseline output (if any).
    #[serde(default)]
    pub negative_patterns: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub validated: bool,
    pub positive_matched: bool,
    pub negative_ok: bool,
    pub positive_output: String,
    pub negative_output: String,
    pub note: String,
}

fn any_match(haystack: &str, needles: &[String]) -> bool {
    needles.iter().any(|n| !n.is_empty() && haystack.contains(n.as_str()))
}

/// Run the PoC (and optional negative control) through the executor and decide.
pub async fn validate(ex: &Executor, spec: &PocSpec) -> Result<Verdict, String> {
    let pos = ex
        .exec(ExecRequest::new(spec.command.clone()).timeout_ms(spec.timeout_ms))
        .await?;
    let pos_out = format!("{}{}", pos.stdout, pos.stderr);
    let positive_matched = any_match(&pos_out, &spec.success_patterns);

    let (negative_ok, negative_output, note) = match &spec.negative_command {
        Some(cmd) => {
            let neg = ex
                .exec(ExecRequest::new(cmd.clone()).timeout_ms(spec.timeout_ms))
                .await?;
            let neg_out = format!("{}{}", neg.stdout, neg.stderr);
            let baseline_ok = spec.negative_patterns.is_empty() || any_match(&neg_out, &spec.negative_patterns);
            let leaks_success = any_match(&neg_out, &spec.success_patterns);
            let ok = baseline_ok && !leaks_success;
            let note = if leaks_success {
                "baseline also showed success marker → false positive".to_string()
            } else if !baseline_ok {
                "baseline did not match expected negative pattern".to_string()
            } else {
                "differential control passed".to_string()
            };
            (ok, neg_out, note)
        }
        None => (true, String::new(), "no negative control provided (weak validation)".to_string()),
    };

    Ok(Verdict {
        validated: positive_matched && negative_ok,
        positive_matched,
        negative_ok,
        positive_output: pos_out,
        negative_output,
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LocalExecutor;

    fn local() -> Executor {
        Executor::Local(LocalExecutor::new(std::env::temp_dir()))
    }

    #[tokio::test]
    async fn validates_with_passing_negative_control() {
        let spec = PocSpec {
            command: "echo INJECTED-4931".into(),
            success_patterns: vec!["INJECTED-4931".into()],
            negative_command: Some("echo normal-baseline".into()),
            negative_patterns: vec!["baseline".into()],
            timeout_ms: 5000,
        };
        let v = validate(&local(), &spec).await.unwrap();
        assert!(v.positive_matched);
        assert!(v.negative_ok);
        assert!(v.validated, "note: {}", v.note);
    }

    #[tokio::test]
    async fn rejects_false_positive_when_baseline_also_succeeds() {
        // Both positive and negative print the marker → not a real finding.
        let spec = PocSpec {
            command: "echo MARKER".into(),
            success_patterns: vec!["MARKER".into()],
            negative_command: Some("echo MARKER".into()),
            negative_patterns: vec![],
            timeout_ms: 5000,
        };
        let v = validate(&local(), &spec).await.unwrap();
        assert!(v.positive_matched);
        assert!(!v.negative_ok);
        assert!(!v.validated);
        assert!(v.note.contains("false positive"));
    }

    #[tokio::test]
    async fn not_validated_when_success_marker_absent() {
        let spec = PocSpec {
            command: "echo nothing-here".into(),
            success_patterns: vec!["INJECTED".into()],
            negative_command: None,
            negative_patterns: vec![],
            timeout_ms: 5000,
        };
        let v = validate(&local(), &spec).await.unwrap();
        assert!(!v.positive_matched);
        assert!(!v.validated);
    }
}
