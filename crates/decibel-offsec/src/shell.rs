//! The `shell` tool: run a command through the OS shell with full authority.
//!
//! No sandbox — this is a red-team tool on the operator's own box. The one
//! safety measure is not a guard rail but a leak fix: secret-looking env vars
//! (`*KEY*`/`*SECRET*`/`*TOKEN*`/`*PASSWORD*`) are stripped from the child, so
//! the harness's own OpenRouter key can never surface in a command's output and
//! back into model context.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};
use tokio::process::Command;

use crate::util::{arg_str, arg_str_opt, arg_u64_opt, truncate_bytes};

/// Default per-command timeout when the model gives none.
const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Cap on captured output per stream, so a noisy command cannot flood context.
const MAX_STREAM_BYTES: usize = 60_000;

/// Run a shell command and return its captured output and exit status.
pub struct ShellTool;

/// Whether an environment variable name looks like a secret to withhold.
///
/// Substring match on the uppercased name. `PWD` catches MySQL's documented
/// `MYSQL_PWD` (and, harmlessly, `PWD`/`OLDPWD` — cosmetic, since the child's
/// cwd is set via `current_dir`); `AUTH`/`SESSION`/`BEARER` catch bearer and
/// session credentials; `URL` catches connection strings that embed
/// credentials (`postgres://user:pass@host`).
fn is_secret_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "AUTH", "SESSION",
        "BEARER", "PRIVATE", "URL",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

/// Build the platform shell invocation for one command line.
fn shell_command(command: &str) -> Command {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    // Scrub secret-looking vars from the child; keep everything else (PATH, etc).
    cmd.env_clear();
    for (name, value) in std::env::vars() {
        if !is_secret_env(&name) {
            cmd.env(name, value);
        }
    }
    cmd
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
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true); // backstop: dropping the child kills the wrapper
        // Put the shell in its own process group so a whole-tree kill (below)
        // reaches every child it launched — `kill_on_drop` alone kills only the
        // wrapper, orphaning the actual tool (nmap, sqlmap, …).
        #[cfg(unix)]
        cmd.process_group(0);
        if let Some(dir) = &workdir {
            cmd.current_dir(dir);
        }

        let child = cmd.spawn().map_err(|e| ToolError::execution(format!("failed to spawn shell: {e}")))?;
        // Capture the pid before the child is moved into the output future, so
        // a timeout/cancel can kill the whole process tree, not just the wrapper.
        let pid = child.id();
        let output_fut = child.wait_with_output();

        let raced = tokio::select! {
            _ = ctx.token().cancelled() => {
                kill_tree(pid);
                return Err(ToolError::Aborted);
            }
            r = tokio::time::timeout(timeout, output_fut) => r,
        };

        let (mut exit_code, mut signal_text, mut stdout, mut stderr, timed_out) = match raced {
            Ok(Ok(output)) => {
                let code = output.status.code();
                (
                    code,
                    exit_signal(&output.status),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                    false,
                )
            }
            Ok(Err(e)) => return Err(ToolError::execution(format!("shell I/O error: {e}"))),
            Err(_elapsed) => {
                // The wrapper dies via kill_on_drop when `output_fut` is dropped;
                // kill the rest of the tree so no launched tool survives.
                kill_tree(pid);
                (None, None, String::new(), String::new(), true)
            }
        };

        let (out_text, out_cut) = truncate_bytes(&stdout, MAX_STREAM_BYTES);
        let (err_text, err_cut) = truncate_bytes(&stderr, MAX_STREAM_BYTES);
        stdout = out_text;
        stderr = err_text;
        // Normalize an unknown code so the canonical value is always present.
        if timed_out {
            exit_code = None;
            signal_text = None;
        }

        Ok(json!({
            "exit_code": exit_code,
            "signal": signal_text,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
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

/// Kill the process tree rooted at `pid`, not just the shell wrapper.
///
/// On Windows the shell is `cmd /C <tool>`, and `cmd.exe` spawns the tool as a
/// separate child, so `taskkill /T /F` walks the tree. On Unix the shell was
/// spawned in its own process group ([`process_group(0)`]), so `kill(-pid, …)`
/// signals the whole group. Best-effort: a failure to reap one process is not
/// worth failing the tool call over.
#[cfg(windows)]
fn kill_tree(pid: Option<u32>) {
    let Some(pid) = pid else { return };
    let _ = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Unix: signal the shell's whole process group (negative pid).
#[cfg(unix)]
fn kill_tree(pid: Option<u32>) {
    if let Some(pid) = pid {
        // SAFETY: `kill` is async-signal-safe and takes plain integers; a
        // negative pid targets the process group, which the child leads.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// Render a terminating signal name on Unix; `None` on Windows or a clean exit.
#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|s| s.to_string())
}

/// Windows has no POSIX signals.
#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_env_detection() {
        assert!(is_secret_env("OPENROUTER_API_KEY"));
        assert!(is_secret_env("aws_secret_access_key"));
        assert!(is_secret_env("GITHUB_TOKEN"));
        assert!(is_secret_env("DB_PASSWORD"));
        // Names that contain none of the classic needles but still hold secrets.
        assert!(is_secret_env("MYSQL_PWD"));
        assert!(is_secret_env("GITHUB_AUTH"));
        assert!(is_secret_env("DATABASE_URL"));
        assert!(is_secret_env("AWS_SESSION_TOKEN"));
        assert!(!is_secret_env("PATH"));
        assert!(!is_secret_env("HOME"));
        assert!(!is_secret_env("LANG"));
    }

    #[tokio::test]
    async fn runs_a_command_and_captures_output() {
        let tool = ShellTool;
        let cmd = if cfg!(windows) { "echo hello" } else { "echo hello" };
        let value = tool
            .execute(serde_json::json!({ "command": cmd }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["exit_code"], 0);
        assert!(value["stdout"].as_str().unwrap().contains("hello"));
        assert_eq!(value["timed_out"], false);
    }

    #[tokio::test]
    async fn secret_env_is_not_visible_to_the_child() {
        // Set a secret-looking var in this process; the child must not see it.
        std::env::set_var("DECIBEL_TEST_SECRET_TOKEN", "leak-me");
        let tool = ShellTool;
        let cmd = if cfg!(windows) {
            "echo [%DECIBEL_TEST_SECRET_TOKEN%]"
        } else {
            "echo [$DECIBEL_TEST_SECRET_TOKEN]"
        };
        let value = tool
            .execute(serde_json::json!({ "command": cmd }), &ExecCtx::new())
            .await
            .unwrap();
        let stdout = value["stdout"].as_str().unwrap();
        assert!(!stdout.contains("leak-me"), "secret leaked into child: {stdout}");
        std::env::remove_var("DECIBEL_TEST_SECRET_TOKEN");
    }

    #[tokio::test]
    async fn times_out_a_long_command() {
        let tool = ShellTool;
        let cmd = if cfg!(windows) {
            // ping -n 4 sleeps ~3s; a 200ms timeout must trip.
            "ping -n 4 127.0.0.1 > NUL"
        } else {
            "sleep 3"
        };
        let value = tool
            .execute(serde_json::json!({ "command": cmd, "timeout_ms": 200 }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["timed_out"], true);
    }
}
