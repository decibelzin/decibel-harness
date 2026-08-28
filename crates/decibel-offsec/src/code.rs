//! The `run_code` tool — Code Mode's execution core.
//!
//! Write a whole script (Python / Node / bash) and run it in ONE call, instead of
//! many `shell` round-trips: loops, parsing, multi-step logic become a real program.
//! The code is piped to the interpreter via a quoted heredoc (no temp file), so it
//! runs the same locally or on the configured Remote (SSH) host — write a Python
//! exploit and run it on a Kali box in a single call. There is no sandbox: it runs
//! with the operator's authority, like every other tool.
//!
//! (Follow-up: a "tools as functions" SDK so the code can call the other tools
//! programmatically — that needs an IPC bridge and is out of scope for this slice.)

use std::sync::Arc;

use async_trait::async_trait;
use decibel_executor::Executor;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::shell::run_shell;
use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Default per-run timeout when the model gives none.
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Heredoc delimiter used to pipe the code to the interpreter verbatim.
const HEREDOC_DELIM: &str = "DECIBEL_CODE_EOF";

/// Run a whole script (Python/Node/bash) in one call — locally, or on a Remote
/// (SSH) executor when configured.
#[derive(Default)]
pub struct RunCodeTool {
    remote: Option<Arc<Executor>>,
}

impl RunCodeTool {
    /// A local-execution run_code tool (the default).
    pub fn new() -> Self {
        RunCodeTool { remote: None }
    }

    /// A run_code tool that runs its scripts on a remote executor (SSH).
    pub fn remote(executor: Arc<Executor>) -> Self {
        RunCodeTool { remote: Some(executor) }
    }
}

/// Map a language label to its interpreter binary; `None` = unsupported.
fn interpreter(lang: &str) -> Option<&'static str> {
    match lang.trim().to_lowercase().as_str() {
        "python" | "python3" | "py" => Some("python3"),
        "node" | "js" | "javascript" => Some("node"),
        "bash" | "sh" | "shell" => Some("bash"),
        _ => None,
    }
}

#[async_trait]
impl Tool for RunCodeTool {
    fn name(&self) -> &str {
        "run_code"
    }

    fn schema(&self) -> ToolSchema {
        let host = if self.remote.is_some() {
            "the configured REMOTE host over SSH"
        } else {
            "the local host"
        };
        ToolSchema {
            name: "run_code".into(),
            description: format!(
                "Write a whole script and run it in one call on {host}: pass `language` \
                 (python | node | bash) and `code`. Prefer this over many `shell` round-trips when \
                 you need loops, parsing, or multi-step logic — write a real program that does the \
                 work and prints its result. Returns stdout, stderr, and exit code. The code is piped \
                 to the interpreter (no file is left behind); it runs with full authority."
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "language": { "type": "string", "enum": ["python", "node", "bash"], "description": "Language / interpreter." },
                    "code": { "type": "string", "description": "The full source to run." },
                    "workdir": { "type": "string", "description": "Working directory for the run." },
                    "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds (default 120000)." }
                },
                "required": ["language", "code"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let language = arg_str(&arguments, "language")?;
        let code = arg_str(&arguments, "code")?;
        let workdir = arg_str_opt(&arguments, "workdir");
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS);
        let interp = interpreter(&language).ok_or_else(|| {
            ToolError::invalid_args(format!("unsupported language `{language}` (use python | node | bash)"))
        })?;
        if code.contains(HEREDOC_DELIM) {
            return Err(ToolError::invalid_args(
                "code must not contain the internal heredoc delimiter DECIBEL_CODE_EOF",
            ));
        }
        // Quoted heredoc → the code runs verbatim (no shell expansion) with no temp file.
        let command = format!("{interp} <<'{HEREDOC_DELIM}'\n{code}\n{HEREDOC_DELIM}");
        let mut value = run_shell(&self.remote, &command, workdir.as_deref(), timeout_ms, ctx).await?;
        if let Value::Object(map) = &mut value {
            map.insert("language".into(), Value::String(language));
        }
        Ok(value)
    }

    fn render(&self, arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let lang = arguments.get("language").and_then(Value::as_str).unwrap_or("");
        let stdout = value.get("stdout").and_then(Value::as_str).unwrap_or("");
        let stderr = value.get("stderr").and_then(Value::as_str).unwrap_or("");
        let mut out = String::new();
        if !lang.is_empty() {
            out.push_str(&format!("[{lang}]\n"));
        }
        if stdout.is_empty() && stderr.is_empty() {
            out.push_str("(no output)");
        } else {
            out.push_str(stdout);
        }
        if !stderr.is_empty() {
            out.push_str("\n[stderr]\n");
            out.push_str(stderr);
        }
        // Mirror `shell`'s render so the model is never fed truncated/signalled output
        // as if it were complete.
        if value.get("stdout_truncated").and_then(Value::as_bool).unwrap_or(false)
            || value.get("stderr_truncated").and_then(Value::as_bool).unwrap_or(false)
        {
            out.push_str("\n[output truncated]");
        }
        if value.get("timed_out").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n[timed out]");
        } else if let Some(code) = value.get("exit_code").and_then(Value::as_i64) {
            out.push_str(&format!("\n[exit code: {code}]"));
        } else if let Some(sig) = value.get("signal").and_then(Value::as_str) {
            out.push_str(&format!("\n[killed by signal: {sig}]"));
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_a_bash_script() {
        // bash is available on every platform this runs on (Git Bash on Windows).
        let tool = RunCodeTool::new();
        let value = tool
            .execute(
                json!({ "language": "bash", "code": "for i in 1 2 3; do echo \"n=$i\"; done" }),
                &ExecCtx::new(),
            )
            .await
            .unwrap();
        assert_eq!(value["exit_code"], 0);
        let stdout = value["stdout"].as_str().unwrap();
        assert!(stdout.contains("n=1") && stdout.contains("n=3"), "got: {stdout}");
        assert_eq!(value["language"], "bash");
    }

    #[tokio::test]
    async fn rejects_unknown_language() {
        let tool = RunCodeTool::new();
        let err = tool
            .execute(json!({ "language": "ruby", "code": "puts 1" }), &ExecCtx::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGS");
    }
}
