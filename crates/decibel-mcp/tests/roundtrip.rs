//! Hermetic round-trip tests: the client is paired to an in-memory fake MCP
//! server over `tokio::io::duplex()` — no subprocess, no network.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use decibel_llm::{CallId, ContentBlock};
use decibel_mcp::{McpClient, McpConnection, McpTool};
use decibel_tools::{ExecCtx, Tool, ToolCall, ToolRegistry};

/// Serialize a JSON value as one `\n`-terminated line and flush it.
async fn send_line<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Value) {
    let mut s = serde_json::to_string(msg).unwrap();
    s.push('\n');
    writer.write_all(s.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
}

/// A full fake MCP server: initialize / tools/list / tools/call, advertising an
/// `echo` tool (round-trips its text) and a `boom` tool (always JSON-RPC errors).
async fn full_fake_server<R, W>(reader: R, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = serde_json::from_str(line).unwrap();
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let id = msg.get("id").cloned();

        let resp = match method {
            "initialize" => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "fake", "version": "9.9.9" }
                }
            })),
            // A notification has no id and expects no response.
            "notifications/initialized" => None,
            "tools/list" => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [
                    {
                        "name": "echo",
                        "description": "echoes text back",
                        "inputSchema": {
                            "type": "object",
                            "properties": { "text": { "type": "string" } },
                            "required": ["text"]
                        }
                    },
                    {
                        "name": "boom",
                        "description": "always errors",
                        "inputSchema": { "type": "object" }
                    }
                ] }
            })),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("");
                match name {
                    "echo" => {
                        let text = msg["params"]["arguments"]["text"].as_str().unwrap_or("");
                        Some(json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {
                                "content": [{ "type": "text", "text": format!("echo: {text}") }],
                                "isError": false
                            }
                        }))
                    }
                    "boom" => Some(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32000, "message": "boom failed" }
                    })),
                    other => Some(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": format!("unknown tool: {other}") }
                    })),
                }
            }
            "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
            _ => Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("method not found: {method}") }
            })),
        };

        if let Some(resp) = resp {
            send_line(&mut writer, &resp).await;
        }
    }
}

/// A correlation probe: collects the first two requests, then answers them in
/// REVERSE order (echoing each id + its `tag`). Arrival order on the wire thus
/// differs from request order, so a passing test proves id-based routing.
async fn reverse_pair_server<R, W>(reader: R, mut writer: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut lines = BufReader::new(reader).lines();
    let mut collected: Vec<Value> = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = serde_json::from_str(line).unwrap();
        if msg.get("id").is_none() {
            continue; // ignore notifications
        }
        collected.push(msg);
        if collected.len() == 2 {
            for m in collected.iter().rev() {
                let resp = json!({
                    "jsonrpc": "2.0", "id": m["id"].clone(),
                    "result": { "tag": m["params"]["tag"].clone() }
                });
                send_line(&mut writer, &resp).await;
            }
            collected.clear();
        }
    }
}

/// Wire a client to the full fake server; returns the connected client.
fn wire_client(server_name: &str) -> Arc<McpClient> {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(full_fake_server(sr, sw));
    let (cr, cw) = tokio::io::split(client_side);
    let conn = McpConnection::new(cr, cw);
    McpClient::from_connection(conn, server_name)
}

#[tokio::test]
async fn handshake_stores_server_info() {
    let client = wire_client("kali");
    client.initialize().await.expect("handshake succeeds");
    let info = client.server_info().expect("serverInfo stored");
    assert_eq!(info["name"], "fake");
    assert_eq!(info["version"], "9.9.9");
}

#[tokio::test]
async fn list_tools_returns_advertised_tools() {
    let client = wire_client("kali");
    client.initialize().await.unwrap();
    let defs = client.list_tools().await.expect("tools/list succeeds");
    assert_eq!(defs.len(), 2);
    assert_eq!(defs[0].name, "echo");
    assert_eq!(defs[0].description, "echoes text back");
    assert_eq!(defs[0].input_schema["properties"]["text"]["type"], "string");
    assert_eq!(defs[1].name, "boom");
}

#[tokio::test]
async fn call_tool_round_trips_content() {
    let client = wire_client("kali");
    client.initialize().await.unwrap();
    let result = client
        .call_tool("echo", json!({ "text": "hello" }))
        .await
        .expect("call succeeds");
    assert_eq!(result["isError"], false);
    assert_eq!(result["content"][0]["text"], "echo: hello");
}

#[tokio::test]
async fn jsonrpc_error_surfaces_as_err() {
    let client = wire_client("kali");
    client.initialize().await.unwrap();
    let err = client
        .call_tool("boom", json!({}))
        .await
        .expect_err("boom must error");
    assert!(err.contains("boom failed"), "got: {err}");
}

#[tokio::test]
async fn responses_correlate_when_two_requests_are_in_flight() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_side);
    tokio::spawn(reverse_pair_server(sr, sw));
    let (cr, cw) = tokio::io::split(client_side);
    let conn = McpConnection::new(cr, cw);

    // Two concurrent requests; the server answers them in reverse order.
    let c1 = conn.clone();
    let c2 = conn.clone();
    let f1 = tokio::spawn(async move { c1.request("probe", json!({ "tag": "first" })).await });
    let f2 = tokio::spawn(async move { c2.request("probe", json!({ "tag": "second" })).await });

    let r1 = f1.await.unwrap().expect("first resolves");
    let r2 = f2.await.unwrap().expect("second resolves");
    // Each caller gets ITS OWN tag back — routing is by id, not arrival order.
    assert_eq!(r1["tag"], "first");
    assert_eq!(r2["tag"], "second");
}

#[tokio::test]
async fn mcp_tool_executes_through_a_real_registry() {
    let client = wire_client("hexstrike");
    client.initialize().await.unwrap();
    let defs = client.list_tools().await.unwrap();
    let echo_def = defs.iter().find(|d| d.name == "echo").unwrap();

    let tool: Arc<dyn Tool> = Arc::new(McpTool::new(client.clone(), "hexstrike", echo_def));
    assert_eq!(tool.name(), "mcp_hexstrike_echo");
    // The schema carries the prefixed name and the remote input schema.
    let schema = tool.schema();
    assert_eq!(schema.name, "mcp_hexstrike_echo");
    assert_eq!(schema.parameters["properties"]["text"]["type"], "string");

    let mut reg = ToolRegistry::new();
    reg.register(tool);

    let call = ToolCall {
        call_id: CallId::from("c1"),
        name: "mcp_hexstrike_echo".into(),
        arguments: json!({ "text": "pwn" }),
    };
    let result = reg.execute(call, &ExecCtx::new()).await;
    assert!(!result.is_error, "unexpected error: {result:?}");
    assert_eq!(result.content, vec![ContentBlock::text("echo: pwn")]);
}

#[tokio::test]
async fn mcp_tool_error_surfaces_through_the_registry() {
    let client = wire_client("hexstrike");
    client.initialize().await.unwrap();
    let defs = client.list_tools().await.unwrap();
    let boom_def = defs.iter().find(|d| d.name == "boom").unwrap();

    let tool: Arc<dyn Tool> = Arc::new(McpTool::new(client.clone(), "hexstrike", boom_def));
    let mut reg = ToolRegistry::new();
    reg.register(tool);

    let call = ToolCall {
        call_id: CallId::from("c2"),
        name: "mcp_hexstrike_boom".into(),
        arguments: json!({}),
    };
    let result = reg.execute(call, &ExecCtx::new()).await;
    assert!(result.is_error);
    assert_eq!(result.error_code.as_deref(), Some("EXEC_ERROR"));
}
