//! The `shell` tool: run a command through the OS shell with full authority.
//!
//! No sandbox — this is a red-team tool on the operator's own box. Process
//! spawning, whole-tree kill on timeout/cancel, and secret-env scrubbing live
//! in [`crate::proc`], shared with the `nmap` tool.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use decibel_executor::{ExecRequest, Executor};
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
///
/// With no `remote` executor the command runs on the local host (Git Bash on
/// Windows, `sh` on Unix), with secret-env scrubbing and whole-tree timeout/cancel.
/// When a **Remote (SSH)** backend is configured, the command runs on that host
/// instead — the operator drives a real box's arsenal without installing anything
/// locally.
#[derive(Default)]
pub struct ShellTool {
    remote: Option<Arc<Executor>>,
}

impl ShellTool {
    /// A local-execution shell tool (the default).
    pub fn new() -> Self {
        ShellTool { remote: None }
    }

    /// A shell tool that runs its commands on a remote executor (SSH).
    pub fn remote(executor: Arc<Executor>) -> Self {
        ShellTool { remote: Some(executor) }
    }
}

/// Locate a POSIX shell to prefer on Windows (Git Bash), so the model's
/// Linux-style command lines (pipes, `;`, `2>/dev/null`, heredocs, inline
/// `python -c` with newlines) run as written instead of being mangled by cmd.
#[cfg(windows)]
fn windows_bash() -> Option<std::path::PathBuf> {
    let candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ];
    for c in candidates {
        let p = std::path::PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("bash.exe");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Build the platform shell invocation for one command line. Prefers Git Bash on
/// Windows (the model writes POSIX shell); falls back to cmd. The secret-env
/// scrub is applied later, in [`run_command`].
fn shell_command(command: &str) -> Command {
    #[cfg(windows)]
    {
        if let Some(bash) = windows_bash() {
            let mut c = Command::new(bash);
            c.arg("-c").arg(command);
            return c;
        }
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    }
}

/// Run a shell `command` on the configured backend — the local host, or a Remote
/// (SSH) executor when `remote` is set — and return the canonical
/// `{exit_code, stdout, stderr, timed_out, …}` value. Shared by the `shell` and
/// `run_code` tools. The remote path races the cancel token so Stop returns promptly.
pub(crate) async fn run_shell(
    remote: &Option<Arc<Executor>>,
    command: &str,
    workdir: Option<&str>,
    timeout_ms: u64,
    ctx: &ExecCtx,
) -> Result<Value, ToolError> {
    if let Some(executor) = remote {
        let mut req = ExecRequest::new(command).timeout_ms(timeout_ms);
        if let Some(dir) = workdir {
            req = req.cwd(dir.to_string());
        }
        let r = tokio::select! {
            biased;
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            out = executor.exec(req) => out.map_err(ToolError::execution)?,
        };
        let (stdout, out_cut) = truncate_bytes(&r.stdout, MAX_STREAM_BYTES);
        let (stderr, err_cut) = truncate_bytes(&r.stderr, MAX_STREAM_BYTES);
        return Ok(json!({
            "exit_code": r.exit_code,
            "signal": Value::Null,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": r.timed_out,
            "stdout_truncated": out_cut || r.truncated,
            "stderr_truncated": err_cut,
            "remote": true,
        }));
    }
    let mut cmd = shell_command(command);
    // An explicit workdir wins (resolved against the workspace like every other tool
    // path); otherwise fall back to the session workspace itself.
    if let Some(dir) = workdir {
        cmd.current_dir(ctx.resolve(dir));
    } else if let Some(cwd) = ctx.cwd() {
        cmd.current_dir(cwd);
    }
    let result = run_command(cmd, Duration::from_millis(timeout_ms), ctx).await?;
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

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> ToolSchema {
        let description = if self.remote.is_some() {
            "Run a command on the configured REMOTE host over SSH and return its stdout, stderr, \
             and exit code. This engagement runs REMOTE: `shell` is your only path to the target \
             box — use it for ALL host work (recon like nmap/curl, and file ops like cat/grep/ls); \
             there are no local filesystem tools. Each call runs in a fresh shell (no state \
             persists); pass `workdir` for the remote working directory."
                .to_string()
        } else {
            "Run a command through the OS shell (Git Bash if present on Windows, else cmd; sh on \
             Unix) and return its stdout, stderr, and exit code. Each call runs in a fresh shell — \
             no state persists between calls; pass `workdir` instead of using cd. Use this to run \
             any installed tool (nmap, sqlmap, curl, etc.)."
                .to_string()
        };
        ToolSchema {
            name: "shell".into(),
            description,
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
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS);
        run_shell(&self.remote, &command, workdir.as_deref(), timeout_ms, ctx).await
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
        let tool = ShellTool::new();
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
        let tool = ShellTool::new();
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
        let tool = ShellTool::new();
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
