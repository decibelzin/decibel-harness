//! Persistent named sessions (the portable equivalent of the upstream tmux
//! sessions). Each session is a long-lived shell whose state (cwd, env vars,
//! background jobs) survives across commands, so interactive/long-running
//! offensive tools are workable:
//!
//! - `run` executes a command in the session and captures its output + exit code
//!   (via a unique completion marker), while the shell keeps running.
//! - `send_input` writes raw input to a running program (the `is_input` path).
//! - `read_new` returns output accumulated since the last read (incremental diff).
//! - `subscribe` streams output chunks live (for the UI terminal card).
//! - `status` / `kill` manage the session lifecycle.
//!
//! Wave: local sessions over piped stdio. A real PTY (for full-screen ncurses
//! TUIs) and SSH-channel sessions are the next enhancements.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use crate::strip_ansi;

/// Output of one `run` in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOutput {
    pub output: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Running,
    Exited { code: Option<i32> },
}

/// One persistent shell session.
struct Session {
    stdin: AsyncMutex<ChildStdin>,
    child: AsyncMutex<Child>,
    /// Full accumulated (ANSI-stripped) output.
    output: Arc<StdMutex<String>>,
    /// Read cursor for `read_new`.
    cursor: StdMutex<usize>,
    /// Live output stream.
    tx: broadcast::Sender<String>,
    seq: AtomicU64,
    /// Whether the session shell is POSIX (bash/sh) vs cmd — decides the
    /// completion-marker script syntax.
    posix: bool,
}

impl Session {
    async fn open(workspace: &PathBuf) -> Result<Self, String> {
        let (mut cmd, posix) = interactive_shell();
        cmd.current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| format!("spawn session shell: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;

        let output = Arc::new(StdMutex::new(String::new()));
        let (tx, _rx) = broadcast::channel(512);
        spawn_reader(stdout, output.clone(), tx.clone());
        spawn_reader(stderr, output.clone(), tx.clone());

        Ok(Session {
            stdin: AsyncMutex::new(stdin),
            child: AsyncMutex::new(child),
            output,
            cursor: StdMutex::new(0),
            tx,
            seq: AtomicU64::new(0),
            posix,
        })
    }

    fn snapshot(&self) -> String {
        self.output.lock().unwrap().clone()
    }

    async fn write_line(&self, line: &str) -> Result<(), String> {
        let mut si = self.stdin.lock().await;
        si.write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        si.flush().await.map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Run a command and capture its output up to a unique completion marker
    /// that also carries the exit code. The shell (and its state) persists.
    async fn run(&self, command: &str, timeout_ms: u64) -> Result<SessionOutput, String> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let marker = format!("__DCP_DONE_{seq}__");
        let start = self.snapshot().len();

        let script = if self.posix {
            format!("{command}\nprintf '%s:%s\\n' {marker} $?\n")
        } else {
            format!("{command}\r\necho {marker}:%errorlevel%\r\n")
        };
        self.write_line(&script).await?;

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let snap = self.snapshot();
            if let Some(rel) = snap[start..].find(&marker) {
                let abs = start + rel;
                let out = snap[start..abs].trim_end().to_string();
                let after = &snap[abs + marker.len()..];
                let code = after
                    .trim_start_matches(':')
                    .lines()
                    .next()
                    .and_then(|s| s.trim().parse::<i32>().ok());
                // Note: `run` does NOT touch the read cursor — that belongs to
                // `read_new`, which tracks streamed/background output separately.
                return Ok(SessionOutput {
                    output: out,
                    exit_code: code,
                    timed_out: false,
                });
            }
            if Instant::now() >= deadline {
                let snap = self.snapshot();
                return Ok(SessionOutput {
                    output: snap[start..].trim_end().to_string(),
                    exit_code: None,
                    timed_out: true,
                });
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Send raw input to a running program (interactive prompt).
    async fn send_input(&self, input: &str) -> Result<(), String> {
        let line = if input.ends_with('\n') {
            input.to_string()
        } else {
            format!("{input}\n")
        };
        self.write_line(&line).await
    }

    /// Output accumulated since the last `read_new`, with our internal
    /// completion markers filtered out (they are noise for the UI terminal).
    fn read_new(&self) -> String {
        let snap = self.snapshot();
        let mut cur = self.cursor.lock().unwrap();
        let start = (*cur).min(snap.len());
        let new = &snap[start..];
        *cur = snap.len();
        new.lines()
            .filter(|l| !l.contains("__DCP_DONE_"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn status(&self) -> SessionStatus {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(status)) => SessionStatus::Exited {
                code: status.code(),
            },
            _ => SessionStatus::Running,
        }
    }

    async fn kill(&self) {
        let mut child = self.child.lock().await;
        let _ = child.start_kill();
    }
}

fn spawn_reader<R>(mut reader: R, output: Arc<StdMutex<String>>, tx: broadcast::Sender<String>)
where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = strip_ansi(&String::from_utf8_lossy(&buf[..n]));
                    output.lock().unwrap().push_str(&chunk);
                    let _ = tx.send(chunk);
                }
            }
        }
    });
}

/// Locate Git Bash on Windows so a session runs POSIX commands (what the model
/// writes) instead of cmd.
#[cfg(windows)]
fn windows_bash() -> Option<PathBuf> {
    let candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ];
    for c in candidates {
        let p = PathBuf::from(c);
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

/// Spawn a shell that reads commands from its (piped) stdin. Returns the command
/// plus whether it is POSIX (bash/sh) — Git Bash is preferred on Windows, else
/// cmd. The bool drives the completion-marker script syntax in `run`.
fn interactive_shell() -> (Command, bool) {
    #[cfg(windows)]
    {
        if let Some(bash) = windows_bash() {
            let mut c = Command::new(bash);
            c.arg("-s"); // read commands from stdin
            return (c, true);
        }
        let mut c = Command::new("cmd");
        c.arg("/Q").arg("/K"); // echo off, stay resident reading stdin
        (c, false)
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-s"); // read commands from stdin
        (c, true)
    }
}

/// Manages persistent named sessions for one executor (confined to a workspace).
pub struct SessionManager {
    workspace: PathBuf,
    sessions: StdMutex<HashMap<String, Arc<Session>>>,
}

impl SessionManager {
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        SessionManager {
            workspace: workspace.into(),
            sessions: StdMutex::new(HashMap::new()),
        }
    }

    async fn get_or_create(&self, id: &str) -> Result<Arc<Session>, String> {
        if let Some(s) = self.sessions.lock().unwrap().get(id) {
            return Ok(s.clone());
        }
        // Open outside the lock (spawning is async), then reconcile any race.
        let created = Arc::new(Session::open(&self.workspace).await?);
        let mut map = self.sessions.lock().unwrap();
        Ok(map.entry(id.to_string()).or_insert(created).clone())
    }

    pub async fn run(&self, id: &str, command: &str, timeout_ms: u64) -> Result<SessionOutput, String> {
        self.get_or_create(id).await?.run(command, timeout_ms).await
    }

    pub async fn send_input(&self, id: &str, input: &str) -> Result<(), String> {
        self.get_or_create(id).await?.send_input(input).await
    }

    pub async fn read_new(&self, id: &str) -> Result<String, String> {
        let s = self
            .sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no such session: {id}"))?;
        Ok(s.read_new())
    }

    pub fn subscribe(&self, id: &str) -> Result<broadcast::Receiver<String>, String> {
        let map = self.sessions.lock().unwrap();
        let s = map.get(id).ok_or_else(|| format!("no such session: {id}"))?;
        Ok(s.tx.subscribe())
    }

    pub async fn status(&self, id: &str) -> Result<SessionStatus, String> {
        let s = self
            .sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no such session: {id}"))?;
        Ok(s.status().await)
    }

    pub async fn kill(&self, id: &str) -> Result<(), String> {
        let s = self.sessions.lock().unwrap().remove(id);
        if let Some(s) = s {
            s.kill().await;
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }

    /// The session's full accumulated (ANSI-stripped) output — the transcript, for
    /// evidence capture (asciicast recording).
    pub fn transcript(&self, id: &str) -> Result<String, String> {
        let s = self
            .sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("no such session: {id}"))?;
        Ok(s.snapshot())
    }
}

/// Whether a new session's shell is POSIX (bash/sh) rather than cmd — so a caller
/// (or a test) can pick command syntax to match the runtime shell.
pub fn shell_is_posix() -> bool {
    interactive_shell().1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dcp-sess-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn state_persists_across_commands() {
        let mgr = SessionManager::new(ws());
        let (set, get) = if shell_is_posix() {
            ("DCPVAR=persisted", "echo $DCPVAR")
        } else {
            ("set DCPVAR=persisted", "echo %DCPVAR%")
        };
        mgr.run("s1", set, 8000).await.unwrap();
        let r = mgr.run("s1", get, 8000).await.unwrap();
        assert!(r.output.contains("persisted"), "output: {:?}", r.output);
        assert_eq!(r.exit_code, Some(0));
    }

    #[tokio::test]
    async fn captures_nonzero_exit_without_killing_session() {
        let mgr = SessionManager::new(ws());
        let fail = if shell_is_posix() { "(exit 4)" } else { "cmd /c exit 4" };
        let r = mgr.run("s2", fail, 8000).await.unwrap();
        assert_eq!(r.exit_code, Some(4), "output: {:?}", r.output);
        // Session still alive: a follow-up command runs.
        let r2 = mgr.run("s2", "echo alive", 8000).await.unwrap();
        assert!(r2.output.contains("alive"));
        assert_eq!(mgr.status("s2").await.unwrap(), SessionStatus::Running);
    }

    #[tokio::test]
    async fn streaming_subscriber_receives_output() {
        let mgr = SessionManager::new(ws());
        // Create the session first so we can subscribe before running.
        mgr.run("s3", "echo warmup", 8000).await.unwrap();
        let mut rx = mgr.subscribe("s3").unwrap();
        mgr.run("s3", "echo streamed-line", 8000).await.unwrap();

        // Drain a few chunks looking for our marker-free content.
        let mut seen = String::new();
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                Ok(Ok(chunk)) => {
                    seen.push_str(&chunk);
                    if seen.contains("streamed-line") {
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(seen.contains("streamed-line"), "streamed: {:?}", seen);
    }

    #[tokio::test]
    async fn read_new_returns_incremental_output() {
        let mgr = SessionManager::new(ws());
        mgr.run("s4", "echo one", 8000).await.unwrap();
        let _ = mgr.read_new("s4").await.unwrap(); // drain
        mgr.run("s4", "echo two", 8000).await.unwrap();
        let diff = mgr.read_new("s4").await.unwrap();
        assert!(diff.contains("two"), "diff: {:?}", diff);
        assert!(!diff.contains("one"), "diff should not repeat old output: {:?}", diff);
    }

    #[tokio::test]
    async fn sessions_are_isolated() {
        let mgr = SessionManager::new(ws());
        let (set_a, set_b, get) = if shell_is_posix() {
            ("K=A", "K=B", "echo $K")
        } else {
            ("set K=A", "set K=B", "echo %K%")
        };
        mgr.run("a", set_a, 8000).await.unwrap();
        mgr.run("b", set_b, 8000).await.unwrap();
        assert!(mgr.run("a", get, 8000).await.unwrap().output.contains("A"));
        assert!(mgr.run("b", get, 8000).await.unwrap().output.contains("B"));
        let mut list = mgr.list();
        list.sort();
        assert_eq!(list, vec!["a".to_string(), "b".to_string()]);
    }

    #[tokio::test]
    async fn kill_removes_session() {
        let mgr = SessionManager::new(ws());
        mgr.run("k", "echo hi", 8000).await.unwrap();
        mgr.kill("k").await.unwrap();
        assert!(mgr.list().is_empty());
        assert!(mgr.read_new("k").await.is_err());
    }
}
