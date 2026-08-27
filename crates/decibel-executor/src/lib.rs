//! decibel-executor — the execution plane, ported from Decepticon (Fase C).
//!
//! Replaces the upstream Kali sandbox daemon (`SANDBOX_URL` + `POST /execute*`)
//! with a portable Executor abstraction chosen **per engagement**:
//!
//! - **local**     — run on the host shell (dev, or when the host is the box).
//! - **remote**    — SSH into a Kali/VPS the operator controls (heavy arsenal).
//! - **container** — `docker exec` into a Kali image when Docker is present.
//!
//! Wave 1 ships the `local` backend fully (with workspace confinement); the
//! remote/container backends are modelled in `Backend`/`make` so an engagement
//! can already select one, and return a clear "not yet implemented" until their
//! slices land. The one-shot `exec` primitive is the base; persistent named
//! sessions + background jobs (the upstream tmux features) are the next slice.

mod local;
mod remote;
mod session;
mod verify;

pub use local::LocalExecutor;
pub use remote::{RemoteAuth, RemoteExecutor};
pub use session::{SessionManager, SessionOutput, SessionStatus};
pub use verify::{validate, PocSpec, Verdict};

use serde::{Deserialize, Serialize};

/// A command to run. `command` is a shell command line (the upstream `bash`
/// primitive); `cwd` is resolved relative to the executor's workspace and may
/// not escape it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    60_000
}

impl ExecRequest {
    pub fn new(command: impl Into<String>) -> Self {
        ExecRequest {
            command: command.into(),
            cwd: None,
            env: Vec::new(),
            timeout_ms: default_timeout(),
        }
    }

    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

/// The result of an `exec`. `stdout`/`stderr` are ANSI-stripped and capped;
/// `truncated` flags when the cap was hit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub truncated: bool,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecInfo {
    pub kind: String,
    pub os: String,
    pub reachable: bool,
}

/// The execution plane, selected per engagement. `Local` and `Remote` (SSH) are
/// functional; `Container` is modelled but not yet built.
pub enum Executor {
    Local(LocalExecutor),
    Remote(RemoteExecutor),
}

impl Executor {
    pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult, String> {
        match self {
            Executor::Local(l) => l.exec(req).await,
            Executor::Remote(r) => r.exec(req).await,
        }
    }

    pub async fn info(&self) -> ExecInfo {
        match self {
            Executor::Local(l) => l.info().await,
            Executor::Remote(r) => r.info().await,
        }
    }
}

/// Per-engagement executor selection (deserialized from `engagement.executor_json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Backend {
    Local {
        /// Absolute path to the engagement workspace (the confinement root).
        workspace: String,
    },
    Remote {
        host: String,
        #[serde(default)]
        port: Option<u16>,
        user: String,
        #[serde(default)]
        workspace: Option<String>,
        /// Password auth (secret — prefer `key_path`; keep it out of the DB).
        #[serde(default)]
        password: Option<String>,
        /// Path to a private key file (not the secret itself).
        #[serde(default)]
        key_path: Option<String>,
        #[serde(default)]
        passphrase: Option<String>,
    },
    Container {
        image: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        workspace: Option<String>,
    },
}

/// Build an executor for a backend selection. Wave 1 builds `Local`; remote and
/// container return a clear not-yet-implemented error.
pub fn make(backend: Backend) -> Result<Executor, String> {
    match backend {
        Backend::Local { workspace } => Ok(Executor::Local(LocalExecutor::new(workspace))),
        Backend::Remote {
            host,
            port,
            user,
            workspace,
            password,
            key_path,
            passphrase,
        } => {
            let auth = if let Some(path) = key_path {
                RemoteAuth::Key { path, passphrase }
            } else if let Some(pw) = password {
                RemoteAuth::Password(pw)
            } else {
                return Err("remote executor needs key_path or password".into());
            };
            Ok(Executor::Remote(RemoteExecutor::new(
                host,
                port.unwrap_or(22),
                user,
                workspace,
                auth,
            )))
        }
        Backend::Container { .. } => {
            Err("container executor not yet implemented (next slice: docker exec)".into())
        }
    }
}

/// Strip ANSI/VT escape sequences from tool output.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if ('\u{40}'..='\u{7e}').contains(&nc) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m"), "red");
        assert_eq!(strip_ansi("plain"), "plain");
    }

    #[test]
    fn backend_deserializes_from_tagged_json() {
        let b: Backend = serde_json::from_str(r#"{"kind":"local","workspace":"/ws/acme"}"#).unwrap();
        assert!(matches!(b, Backend::Local { .. }));
        let r: Backend =
            serde_json::from_str(r#"{"kind":"remote","host":"1.2.3.4","user":"root"}"#).unwrap();
        assert!(matches!(r, Backend::Remote { .. }));
    }

    #[test]
    fn make_local_ok_and_remote_needs_auth() {
        assert!(make(Backend::Local { workspace: ".".into() }).is_ok());
        // Remote with no password/key is rejected.
        assert!(make(Backend::Remote {
            host: "h".into(),
            port: None,
            user: "u".into(),
            workspace: None,
            password: None,
            key_path: None,
            passphrase: None,
        })
        .is_err());
        // Remote with a password builds.
        assert!(make(Backend::Remote {
            host: "h".into(),
            port: None,
            user: "u".into(),
            workspace: None,
            password: Some("pw".into()),
            key_path: None,
            passphrase: None,
        })
        .is_ok());
    }
}
