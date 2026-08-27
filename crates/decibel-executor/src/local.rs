//! Local execution backend: runs commands on the host shell, confined to the
//! engagement workspace. `cwd` may not escape the workspace root.

use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::{strip_ansi, ExecInfo, ExecRequest, ExecResult};

/// Cap captured stdout/stderr so a runaway command can't blow up memory.
const MAX_OUTPUT: usize = 256 * 1024;

pub struct LocalExecutor {
    workspace: PathBuf,
}

impl LocalExecutor {
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        LocalExecutor {
            workspace: workspace.into(),
        }
    }

    pub async fn info(&self) -> ExecInfo {
        ExecInfo {
            kind: "local".into(),
            os: std::env::consts::OS.into(),
            reachable: true,
        }
    }

    pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult, String> {
        let cwd = self.resolve_cwd(req.cwd.as_deref())?;

        let mut cmd = shell_command(&req.command);
        cmd.current_dir(&cwd);
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // If we hit the timeout and drop the child, make sure it dies.
            .kill_on_drop(true);

        let start = Instant::now();
        let child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;

        let dur = Duration::from_millis(req.timeout_ms);
        match timeout(dur, child.wait_with_output()).await {
            Ok(Ok(output)) => {
                let (stdout, t1) = clamp(&strip_ansi(&String::from_utf8_lossy(&output.stdout)));
                let (stderr, t2) = clamp(&strip_ansi(&String::from_utf8_lossy(&output.stderr)));
                Ok(ExecResult {
                    stdout,
                    stderr,
                    exit_code: output.status.code(),
                    timed_out: false,
                    truncated: t1 || t2,
                    duration_ms: start.elapsed().as_millis(),
                })
            }
            Ok(Err(e)) => Err(format!("wait: {e}")),
            Err(_) => Ok(ExecResult {
                stdout: String::new(),
                stderr: format!("timed out after {}ms", req.timeout_ms),
                exit_code: None,
                timed_out: true,
                truncated: false,
                duration_ms: start.elapsed().as_millis(),
            }),
        }
    }

    /// Resolve `rel` against the workspace root and reject any path that escapes
    /// it (the confinement invariant). Uses lexical normalization so it works
    /// even when the target directory does not exist.
    fn resolve_cwd(&self, rel: Option<&str>) -> Result<PathBuf, String> {
        let base = self
            .workspace
            .canonicalize()
            .unwrap_or_else(|_| self.workspace.clone());
        let target = match rel {
            Some(r) => normalize(&base.join(r)),
            None => normalize(&base),
        };
        let base_norm = normalize(&base);
        if !target.starts_with(&base_norm) {
            return Err(format!("cwd escapes workspace: {}", target.display()));
        }
        Ok(target)
    }
}

/// Wrap a command line in the host shell.
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

/// Lexically normalize a path (resolve `.`/`..` without touching the filesystem).
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Truncate to `MAX_OUTPUT`, returning `(text, was_truncated)`.
pub(crate) fn clamp(s: &str) -> (String, bool) {
    if s.len() <= MAX_OUTPUT {
        (s.to_string(), false)
    } else {
        let mut end = MAX_OUTPUT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        (format!("{}\n[...truncated]", &s[..end]), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_workspace() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dcp-exec-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn runs_command_captures_stdout() {
        let ex = LocalExecutor::new(tmp_workspace());
        let r = ex.exec(ExecRequest::new("echo hello-arsenal")).await.unwrap();
        assert!(r.stdout.contains("hello-arsenal"), "stdout: {:?}", r.stdout);
        assert_eq!(r.exit_code, Some(0));
        assert!(!r.timed_out);
    }

    #[tokio::test]
    async fn nonzero_exit_code_is_reported() {
        let ex = LocalExecutor::new(tmp_workspace());
        let cmd = if cfg!(windows) { "exit 3" } else { "exit 3" };
        let r = ex.exec(ExecRequest::new(cmd)).await.unwrap();
        assert_eq!(r.exit_code, Some(3));
    }

    #[tokio::test]
    async fn timeout_kills_and_flags() {
        let ex = LocalExecutor::new(tmp_workspace());
        // ~3s sleep, capped at 400ms.
        let cmd = if cfg!(windows) {
            "ping -n 4 127.0.0.1 >NUL"
        } else {
            "sleep 3"
        };
        let r = ex.exec(ExecRequest::new(cmd).timeout_ms(400)).await.unwrap();
        assert!(r.timed_out, "should have timed out");
        assert!(r.duration_ms < 3000, "killed early: {}ms", r.duration_ms);
    }

    #[tokio::test]
    async fn cwd_confinement_rejects_escape() {
        let ex = LocalExecutor::new(tmp_workspace());
        let err = ex
            .exec(ExecRequest::new("echo x").cwd("../../etc"))
            .await
            .unwrap_err();
        assert!(err.contains("escapes workspace"), "err: {err}");
    }

    #[tokio::test]
    async fn cwd_within_workspace_ok() {
        let ws = tmp_workspace();
        std::fs::create_dir_all(ws.join("sub")).unwrap();
        let ex = LocalExecutor::new(ws);
        let r = ex.exec(ExecRequest::new("echo ok").cwd("sub")).await.unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert!(r.stdout.contains("ok"));
    }

    #[tokio::test]
    async fn info_reports_local() {
        let ex = LocalExecutor::new(tmp_workspace());
        let info = ex.info().await;
        assert_eq!(info.kind, "local");
        assert!(info.reachable);
    }
}
