//! Remote execution backend: SSH into a Kali/VPS the operator controls and run
//! the command there. This is the parity path for the heavy arsenal (msf, sliver,
//! evil-winrm…) without Docker on the host — the remote box IS the sandbox.
//!
//! Pure-Rust SSH via `russh` (no OpenSSL / libssh2 C deps). Wave 1 opens a fresh
//! connection per `exec` (stateless); connection pooling + persistent sessions
//! come with the tmux-features slice.

use std::sync::Arc;
use std::time::Instant;

use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::ChannelMsg;
use tokio::time::{timeout, Duration};

use crate::local::clamp;
use crate::{strip_ansi, ExecInfo, ExecRequest, ExecResult};

/// How the client authenticates to the remote host.
#[derive(Debug, Clone)]
pub enum RemoteAuth {
    Password(String),
    Key {
        path: String,
        passphrase: Option<String>,
    },
}

pub struct RemoteExecutor {
    host: String,
    port: u16,
    user: String,
    /// Remote workspace directory the command is `cd`-ed into (soft confinement:
    /// the remote box is itself the sandbox arena).
    workspace: Option<String>,
    auth: RemoteAuth,
}

impl RemoteExecutor {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        workspace: Option<String>,
        auth: RemoteAuth,
    ) -> Self {
        RemoteExecutor {
            host: host.into(),
            port,
            user: user.into(),
            workspace,
            auth,
        }
    }

    pub async fn info(&self) -> ExecInfo {
        // A real connectivity test: resolve the OS via `uname -s`.
        match self.exec(ExecRequest::new("uname -s").timeout_ms(8000)).await {
            Ok(r) if r.exit_code == Some(0) => ExecInfo {
                kind: "remote".into(),
                os: r.stdout.trim().to_lowercase(),
                reachable: true,
            },
            _ => ExecInfo {
                kind: "remote".into(),
                os: String::new(),
                reachable: false,
            },
        }
    }

    pub async fn exec(&self, req: ExecRequest) -> Result<ExecResult, String> {
        let start = Instant::now();
        let command = self.wrap_command(&req);
        let dur = Duration::from_millis(req.timeout_ms);

        match timeout(dur, self.run(&command)).await {
            Ok(Ok((out, err, code))) => {
                let (stdout, t1) = clamp(&strip_ansi(&out));
                let (stderr, t2) = clamp(&strip_ansi(&err));
                Ok(ExecResult {
                    stdout,
                    stderr,
                    exit_code: code,
                    timed_out: false,
                    truncated: t1 || t2,
                    duration_ms: start.elapsed().as_millis(),
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(ExecResult {
                stdout: String::new(),
                stderr: format!("ssh timed out after {}ms", req.timeout_ms),
                exit_code: None,
                timed_out: true,
                truncated: false,
                duration_ms: start.elapsed().as_millis(),
            }),
        }
    }

    /// Prepend a `cd` into the target directory so commands run in the workspace.
    fn wrap_command(&self, req: &ExecRequest) -> String {
        let dir = match (&self.workspace, &req.cwd) {
            (Some(ws), Some(sub)) => Some(format!("{}/{}", ws.trim_end_matches('/'), sub)),
            (Some(ws), None) => Some(ws.clone()),
            (None, Some(sub)) => Some(sub.clone()),
            (None, None) => None,
        };
        match dir {
            Some(d) => format!("cd {} 2>/dev/null; {}", sh_quote(&d), req.command),
            None => req.command.clone(),
        }
    }

    async fn run(&self, command: &str) -> Result<(String, String, Option<i32>), String> {
        let config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect(config, (self.host.as_str(), self.port), ClientHandler)
            .await
            .map_err(|e| format!("ssh connect {}:{}: {e}", self.host, self.port))?;

        let authed = match &self.auth {
            RemoteAuth::Password(p) => handle
                .authenticate_password(&self.user, p.clone())
                .await
                .map_err(|e| format!("ssh auth: {e}"))?
                .success(),
            RemoteAuth::Key { path, passphrase } => {
                let key = load_secret_key(path, passphrase.as_deref())
                    .map_err(|e| format!("load key {path}: {e}"))?;
                let kwa = PrivateKeyWithHashAlg::new(Arc::new(key), None);
                handle
                    .authenticate_publickey(&self.user, kwa)
                    .await
                    .map_err(|e| format!("ssh auth: {e}"))?
                    .success()
            }
        };
        if !authed {
            return Err("ssh authentication failed".into());
        }

        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open session: {e}"))?;
        channel
            .exec(true, command.to_string())
            .await
            .map_err(|e| format!("exec: {e}"))?;

        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext } if ext == 1 => err.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status as i32),
                _ => {}
            }
        }

        Ok((
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
            code,
        ))
    }
}

/// Single-quote a string for POSIX shells (`cd '<dir>'`).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// SSH client handler. Accepts any host key for now.
// TODO(security): pin/verify host keys against a known_hosts store; accept-any
// leaves the connection open to MITM. Tracked for the confinement hardening slice.
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::server::{
        Auth, ChannelOpenHandle, Config as ServerConfig, Handler as ServerHandler, Msg as ServerMsg,
        Server, Session,
    };
    use russh::{Channel, ChannelId};

    // A minimal in-process SSH server: accepts any password, and for an exec
    // request echoes the command back, exiting 7 if the command mentions FAILME.
    #[derive(Clone)]
    struct TestServer;

    impl Server for TestServer {
        type Handler = TestHandler;
        fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> TestHandler {
            TestHandler
        }
    }

    struct TestHandler;

    impl ServerHandler for TestHandler {
        type Error = russh::Error;

        async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
            Ok(Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<ServerMsg>,
            reply: ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let cmd = String::from_utf8_lossy(data).into_owned();
            let code = if cmd.contains("FAILME") { 7 } else { 0 };
            session.data(channel, format!("ran: {cmd}").into_bytes())?;
            session.exit_status_request(channel, code)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        }
    }

    // A throwaway unencrypted ed25519 host key for the in-process test server.
    const TEST_HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACBPpIJDvZTCOcD9PvgR9q5rDuutGjDKjYwIUE9qI4SS4AAAAJhGKbMjRimz\n\
IwAAAAtzc2gtZWQyNTUxOQAAACBPpIJDvZTCOcD9PvgR9q5rDuutGjDKjYwIUE9qI4SS4A\n\
AAAEBL+sBg8KFv5eDIct/bQLMwLyOwOj7uaFZF0naxNnS0TU+kgkO9lMI5wP0++BH2rmsO\n\
660aMMqNjAhQT2ojhJLgAAAAD2RlY2VwdGljb24tdGVzdAECAwQFBg==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    async fn start_test_server() -> u16 {
        let key = russh::keys::PrivateKey::from_openssh(TEST_HOST_KEY).expect("host key");
        let mut config = ServerConfig::default();
        config.keys.push(key);
        let config = Arc::new(config);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut server = TestServer;
        tokio::spawn(async move {
            let _ = server.run_on_socket(config, &listener).await;
        });
        port
    }

    fn password_executor(port: u16) -> RemoteExecutor {
        RemoteExecutor::new(
            "127.0.0.1",
            port,
            "operator",
            Some("/workspace/acme".into()),
            RemoteAuth::Password("hunter2".into()),
        )
    }

    #[tokio::test]
    async fn ssh_exec_roundtrip_and_workspace_cd() {
        let port = start_test_server().await;
        let ex = password_executor(port);
        let r = ex.exec(ExecRequest::new("id").timeout_ms(8000)).await.unwrap();
        assert_eq!(r.exit_code, Some(0), "stderr: {}", r.stderr);
        assert!(!r.timed_out);
        // The server echoes the command it received — proves it ran through SSH
        // AND that we wrapped it with the workspace `cd`.
        assert!(r.stdout.contains("cd '/workspace/acme'"), "stdout: {:?}", r.stdout);
        assert!(r.stdout.contains("; id"), "stdout: {:?}", r.stdout);
    }

    #[tokio::test]
    async fn ssh_nonzero_exit_is_reported() {
        let port = start_test_server().await;
        let ex = password_executor(port);
        let r = ex.exec(ExecRequest::new("FAILME").timeout_ms(8000)).await.unwrap();
        assert_eq!(r.exit_code, Some(7));
    }

    #[tokio::test]
    async fn info_reports_reachable_when_server_up() {
        let port = start_test_server().await;
        let ex = password_executor(port);
        // The test server echoes "ran: ... uname -s" with exit 0, so reachable=true.
        let info = ex.info().await;
        assert_eq!(info.kind, "remote");
        assert!(info.reachable);
    }

    #[tokio::test]
    async fn connect_failure_surfaces_error() {
        // Nothing listening on this port.
        let ex = password_executor(1);
        let err = ex.exec(ExecRequest::new("id").timeout_ms(3000)).await;
        // Either a connect error, or a timeout result — both are non-success.
        match err {
            Ok(r) => assert!(r.timed_out || r.exit_code != Some(0)),
            Err(_) => {}
        }
    }
}
