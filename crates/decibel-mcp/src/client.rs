//! The stdio JSON-RPC 2.0 client.
//!
//! [`McpConnection`] is the protocol core, generic over any byte streams so it
//! can be driven by `tokio::io::duplex()` in tests as well as a subprocess's
//! stdout/stdin in production. [`McpClient`] wraps a connection with the MCP
//! method surface (`initialize`, `tools/list`, `tools/call`) and, when spawned,
//! keeps the child process alive (killed on drop).

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::config::McpServerConfig;

/// Default per-request timeout: a stuck server errors rather than hangs the loop.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A tool as advertised by a remote MCP server's `tools/list`.
#[derive(Clone, Debug, PartialEq)]
pub struct McpToolDef {
    /// The remote tool name (unprefixed, as the server knows it).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// The tool's JSON Schema for arguments (`inputSchema` on the wire).
    pub input_schema: Value,
}

/// Extract and join every `content[].text` string from a `tools/call` result.
pub(crate) fn extract_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// The protocol core: newline-delimited JSON-RPC 2.0 over a reader/writer pair.
///
/// A background task reads response lines and routes each to the pending request
/// with the matching numeric `id`; lines with no `id` (notifications, logs) are
/// ignored. Outbound writes are serialized under an async mutex.
pub struct McpConnection {
    /// Serialized outbound stream (a subprocess stdin or a duplex half).
    writer: AsyncMutex<Box<dyn AsyncWrite + Unpin + Send>>,
    /// In-flight requests keyed by id, each awaiting its response.
    pending: Arc<StdMutex<HashMap<i64, oneshot::Sender<Result<Value, String>>>>>,
    /// Monotonic request id source.
    next_id: AtomicI64,
    /// The background reader task (aborted on drop).
    reader_task: JoinHandle<()>,
    /// Per-request timeout.
    timeout: Duration,
}

impl McpConnection {
    /// Build a connection over any reader/writer, spawning the reader task.
    pub fn new<R, W>(reader: R, writer: W) -> Arc<Self>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let pending: Arc<StdMutex<HashMap<i64, oneshot::Sender<Result<Value, String>>>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let pending_reader = pending.clone();

        let reader_task = tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let msg: Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    // A malformed line can't be routed; skip it rather than die.
                    Err(_) => continue,
                };
                // Only responses (which echo a numeric id) are routable; a line
                // with no id is a notification or log line — ignore it.
                let Some(id) = msg.get("id").and_then(Value::as_i64) else {
                    continue;
                };
                let waiter = pending_reader.lock().unwrap().remove(&id);
                if let Some(tx) = waiter {
                    let outcome = if let Some(err) = msg.get("error") {
                        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                        let message = err
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("JSON-RPC error");
                        Err(format!("JSON-RPC error {code}: {message}"))
                    } else {
                        Ok(msg.get("result").cloned().unwrap_or(Value::Null))
                    };
                    let _ = tx.send(outcome);
                }
            }
            // Stream ended: fail every still-pending request so no caller hangs.
            let mut guard = pending_reader.lock().unwrap();
            for (_, tx) in guard.drain() {
                let _ = tx.send(Err("connection closed".to_string()));
            }
        });

        Arc::new(McpConnection {
            writer: AsyncMutex::new(Box::new(writer)),
            pending,
            next_id: AtomicI64::new(1),
            reader_task,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Write one JSON value as a single `\n`-terminated line, flushed.
    async fn write_line(&self, msg: &Value) -> Result<(), String> {
        let mut line = serde_json::to_string(msg).map_err(|e| format!("serialize failed: {e}"))?;
        line.push('\n');
        let mut guard = self.writer.lock().await;
        let w: &mut (dyn AsyncWrite + Unpin + Send) = &mut **guard;
        w.write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        w.flush().await.map_err(|e| format!("flush failed: {e}"))?;
        Ok(())
    }

    /// Send a request and await its correlated response (or a timeout error).
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        if let Err(e) = self.write_line(&msg).await {
            self.pending.lock().unwrap().remove(&id);
            return Err(e);
        }

        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_canceled)) => Err("response channel closed".to_string()),
            Err(_elapsed) => {
                self.pending.lock().unwrap().remove(&id);
                Err(format!("request `{method}` timed out"))
            }
        }
    }

    /// Send a notification (no id, no response awaited).
    pub async fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        let msg = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.write_line(&msg).await
    }
}

impl Drop for McpConnection {
    fn drop(&mut self) {
        // Stop the background reader; nothing else can reach it once we're gone.
        self.reader_task.abort();
    }
}

/// A connected MCP server: the protocol connection, the server's advertised
/// info, and (when spawned) the owned child process kept alive here.
pub struct McpClient {
    conn: Arc<McpConnection>,
    server_name: String,
    server_info: StdMutex<Option<Value>>,
    // Kept alive so the process is not dropped (and, via kill_on_drop, killed)
    // while the client is in use. `None` for connection-only clients (tests).
    _child: Option<StdMutex<Child>>,
}

impl McpClient {
    /// Build a client over an existing connection (no child process). Used by
    /// tests to pair the client with an in-memory fake server.
    pub fn from_connection(conn: Arc<McpConnection>, server_name: impl Into<String>) -> Arc<Self> {
        Arc::new(McpClient {
            conn,
            server_name: server_name.into(),
            server_info: StdMutex::new(None),
            _child: None,
        })
    }

    /// Spawn the configured server as a subprocess and wire its stdio into a
    /// connection. The child is killed when the returned client is dropped.
    pub async fn spawn(cfg: &McpServerConfig) -> Result<Arc<Self>, String> {
        let mut cmd = Command::new(&cfg.command);
        cmd.args(&cfg.args);
        for (k, v) in &cfg.env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        // Let the server's stderr (its logs) pass through to ours.
        cmd.stderr(Stdio::inherit());
        cmd.kill_on_drop(true);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("failed to spawn `{}`: {e}", cfg.command))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "child process has no stdout".to_string())?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "child process has no stdin".to_string())?;

        let conn = McpConnection::new(stdout, stdin);
        Ok(Arc::new(McpClient {
            conn,
            server_name: cfg.name.clone(),
            server_info: StdMutex::new(None),
            _child: Some(StdMutex::new(child)),
        }))
    }

    /// The logical server name (used to namespace its tools).
    pub fn name(&self) -> &str {
        &self.server_name
    }

    /// The underlying connection, for direct low-level use.
    pub fn connection(&self) -> &Arc<McpConnection> {
        &self.conn
    }

    /// The server's `serverInfo`, populated after [`initialize`](Self::initialize).
    pub fn server_info(&self) -> Option<Value> {
        self.server_info.lock().unwrap().clone()
    }

    /// Perform the MCP handshake: `initialize`, then the `notifications/initialized`
    /// notification. Stores the returned `serverInfo`.
    pub async fn initialize(&self) -> Result<(), String> {
        let params = json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "decibel", "version": env!("CARGO_PKG_VERSION") },
        });
        let result = self.conn.request("initialize", params).await?;
        if let Some(info) = result.get("serverInfo") {
            *self.server_info.lock().unwrap() = Some(info.clone());
        }
        self.conn
            .notify("notifications/initialized", json!({}))
            .await?;
        Ok(())
    }

    /// List the server's tools via `tools/list`.
    pub async fn list_tools(&self) -> Result<Vec<McpToolDef>, String> {
        let result = self.conn.request("tools/list", json!({})).await?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut defs = Vec::with_capacity(tools.len());
        for t in tools {
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if name.is_empty() {
                continue;
            }
            let description = t
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let input_schema = t.get("inputSchema").cloned().unwrap_or_else(|| json!({}));
            defs.push(McpToolDef {
                name,
                description,
                input_schema,
            });
        }
        Ok(defs)
    }

    /// Invoke a remote tool via `tools/call`. On success returns the whole
    /// `result` (with its `content` and `isError`); a JSON-RPC error or an
    /// `isError: true` result maps to `Err`.
    pub async fn call_tool(&self, name: &str, args: Value) -> Result<Value, String> {
        let params = json!({ "name": name, "arguments": args });
        let result = self.conn.request("tools/call", params).await?;
        if result.get("isError").and_then(Value::as_bool).unwrap_or(false) {
            let text = extract_text(&result);
            return Err(if text.is_empty() {
                format!("tool `{name}` reported an error")
            } else {
                text
            });
        }
        Ok(result)
    }
}
