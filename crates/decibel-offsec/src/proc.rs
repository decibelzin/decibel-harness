//! Shared process execution: spawn a command, race it against a timeout and
//! cancellation, and kill the WHOLE process tree — not just the wrapper — when
//! either fires. Used by both the `shell` and `nmap` tools so the
//! security-critical kill and secret-env scrub live in one place.

use std::process::Stdio;
use std::time::Duration;

use decibel_tools::{ExecCtx, ToolError};
use tokio::process::Command;

/// The captured outcome of one command.
pub struct RunResult {
    /// Process exit code, or `None` on a signal or timeout.
    pub exit_code: Option<i32>,
    /// Terminating signal name (Unix), when the process was signalled.
    pub signal: Option<String>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// Whether the timeout fired.
    pub timed_out: bool,
}

/// Whether an environment variable name looks like a secret to withhold from a
/// spawned child, so a credential never leaks into captured output and back
/// into model context.
///
/// Substring match on the uppercased name. `PWD` catches MySQL's documented
/// `MYSQL_PWD`; `AUTH`/`SESSION`/`BEARER` catch bearer/session credentials;
/// `URL` catches connection strings that embed credentials.
pub fn is_secret_env(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "AUTH", "SESSION",
        "BEARER", "PRIVATE", "URL",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

/// Run `cmd` with the secret-scrubbed environment, capturing stdout/stderr and
/// bounding it by `timeout` and `ctx` cancellation. On timeout or cancel the
/// whole process tree is killed. The caller sets the program, args, and any
/// working directory on `cmd` before calling.
pub async fn run_command(
    mut cmd: Command,
    timeout: Duration,
    ctx: &ExecCtx,
) -> Result<RunResult, ToolError> {
    // Scrub secret-looking env vars from the child; keep everything else.
    cmd.env_clear();
    for (name, value) in std::env::vars() {
        if !is_secret_env(&name) {
            cmd.env(name, value);
        }
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Own process group so a whole-tree kill reaches every launched child.
    #[cfg(unix)]
    cmd.process_group(0);

    let child = cmd
        .spawn()
        .map_err(|e| ToolError::execution(format!("failed to spawn process: {e}")))?;
    let pid = child.id();
    let output_fut = child.wait_with_output();

    let raced = tokio::select! {
        _ = ctx.token().cancelled() => {
            kill_tree(pid);
            return Err(ToolError::Aborted);
        }
        r = tokio::time::timeout(timeout, output_fut) => r,
    };

    match raced {
        Ok(Ok(output)) => Ok(RunResult {
            exit_code: output.status.code(),
            signal: exit_signal(&output.status),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            timed_out: false,
        }),
        Ok(Err(e)) => Err(ToolError::execution(format!("process I/O error: {e}"))),
        Err(_elapsed) => {
            kill_tree(pid);
            Ok(RunResult {
                exit_code: None,
                signal: None,
                stdout: String::new(),
                stderr: String::new(),
                timed_out: true,
            })
        }
    }
}

/// Kill the process tree rooted at `pid`, not just the direct wrapper.
///
/// On Windows a launched tool (nmap.exe, …) is a separate child of the wrapper,
/// so `taskkill /T /F` walks the tree. On Unix the child leads its own process
/// group ([`run_command`] sets `process_group(0)`), so `kill(-pid, …)` signals
/// the whole group. Best-effort.
#[cfg(windows)]
pub fn kill_tree(pid: Option<u32>) {
    let Some(pid) = pid else { return };
    let _ = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Unix: signal the child's whole process group (negative pid).
#[cfg(unix)]
pub fn kill_tree(pid: Option<u32>) {
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
        assert!(is_secret_env("MYSQL_PWD"));
        assert!(is_secret_env("GITHUB_AUTH"));
        assert!(is_secret_env("DATABASE_URL"));
        assert!(is_secret_env("AWS_SESSION_TOKEN"));
        assert!(!is_secret_env("PATH"));
        assert!(!is_secret_env("HOME"));
        assert!(!is_secret_env("LANG"));
    }

    #[tokio::test]
    async fn runs_and_captures() {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.arg("/C").arg("echo hi");
            c
        } else {
            let mut c = Command::new("sh");
            c.arg("-c").arg("echo hi");
            c
        };
        let _ = &mut cmd;
        let out = run_command(cmd, Duration::from_secs(10), &ExecCtx::new()).await.unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.contains("hi"));
        assert!(!out.timed_out);
    }
}
