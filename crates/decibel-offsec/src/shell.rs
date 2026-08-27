//! The `shell` tool: run a command through the OS shell with full authority.
//!
//! No sandbox — this is a red-team tool on the operator's own box. Process
//! spawning, whole-tree kill on timeout/cancel, and secret-env scrubbing live
//! in [`crate::proc`], shared with the `nmap` tool.

use std::time::Duration;

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};
use tokio::process::Command;

use crate::proc::run_command;
use crate::util::{arg_str, arg_str_opt, arg_u64_opt, truncate_bytes};

/// Default per-command timeout when the model gives none.
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Cap on captured output per stream, so a noisy command cannot flood context.
const MAX_STREAM_BYTES: usize = 60_000;

/// Run a shell command and return its captured output and exit status.
pub struct ShellTool;

/// Build the platform shell invocation for one command line. The secret-env
/// scrub is applied later, in [`run_command`].
fn shell_command(command: &str) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "shell".into(),
            description: "Run a command through the OS shell (cmd on Windows, sh on Unix) and \
                return its stdout, stderr, and exit code. Each call runs in a fresh shell — no \
                state persists between calls; pass `workdir` instead of using cd. Use this to run \
                any installed tool (nmap, sqlmap, curl, etc.)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "The command line to execute." },
                    "workdir": { "type": "string", "description": "Working directory for this command." },
                    "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds (default 120000)." }
                },
                "required": ["command"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let command = arg_str(&arguments, "command")?;
        let workdir = arg_str_opt(&arguments, "workdir");
        let timeout = Duration::from_millis(arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS));

        let mut cmd = shell_command(&command);
        // An explicit workdir wins (resolved against the workspace like every other
        // tool path); otherwise fall back to the session workspace itself.
        if let Some(dir) = &workdir {
            cmd.current_dir(ctx.resolve(dir));
        } else if let Some(cwd) = ctx.cwd() {
            cmd.current_dir(cwd);
        }
        let result = run_command(cmd, timeout, ctx).await?;

        let (stdout, out_cut) = truncate_bytes(&result.stdout, MAX_STREAM_BYTES);
        let (stderr, err_cut) = truncate_bytes(&result.stderr, MAX_STREAM_BYTES);

        Ok(json!({
            "exit_code": result.exit_code,
            "signal": result.signal,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": result.timed_out,
            "stdout_truncated": out_cut,
            "stderr_truncated": err_cut,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let stdout = value.get("stdout").and_then(Value::as_str).unwrap_or("");
        let stderr = value.get("stderr").and_then(Value::as_str).unwrap_or("");
        let timed_out = value.get("timed_out").and_then(Value::as_bool).unwrap_or(false);
        let exit_code = value.get("exit_code").and_then(Value::as_i64);

        let mut out = String::new();
        if stdout.is_empty() && stderr.is_empty() {
            out.push_str("(no output)");
        } else {
            out.push_str(stdout);
        }
        if !stderr.is_empty() {
            out.push_str("\n[stderr]\n");
            out.push_str(stderr);
        }
        if value.get("stdout_truncated").and_then(Value::as_bool).unwrap_or(false)
            || value.get("stderr_truncated").and_then(Value::as_bool).unwrap_or(false)
        {
            out.push_str("\n[output truncated]");
        }
        if timed_out {
            out.push_str("\n[timed out]");
        } else if let Some(code) = exit_code {
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
    async fn runs_a_command_and_captures_output() {
        let tool = ShellTool;
        let value = tool
            .execute(json!({ "command": "echo hello" }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["exit_code"], 0);
        assert!(value["stdout"].as_str().unwrap().contains("hello"));
        assert_eq!(value["timed_out"], false);
    }

    #[tokio::test]
    async fn secret_env_is_not_visible_to_the_child() {
        std::env::set_var("DECIBEL_TEST_SECRET_TOKEN", "leak-me");
        let tool = ShellTool;
        let cmd = if cfg!(windows) {
            "echo [%DECIBEL_TEST_SECRET_TOKEN%]"
        } else {
            "echo [$DECIBEL_TEST_SECRET_TOKEN]"
        };
        let value = tool.execute(json!({ "command": cmd }), &ExecCtx::new()).await.unwrap();
        let stdout = value["stdout"].as_str().unwrap();
        assert!(!stdout.contains("leak-me"), "secret leaked into child: {stdout}");
        std::env::remove_var("DECIBEL_TEST_SECRET_TOKEN");
    }

    #[tokio::test]
    async fn times_out_a_long_command() {
        let tool = ShellTool;
        let cmd = if cfg!(windows) {
            "ping -n 4 127.0.0.1 > NUL"
        } else {
            "sleep 3"
        };
        let value = tool
            .execute(json!({ "command": cmd, "timeout_ms": 200 }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["timed_out"], true);
    }
}
