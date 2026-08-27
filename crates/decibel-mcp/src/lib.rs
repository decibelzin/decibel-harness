//! MCP client for Decibel Harness.
//!
//! Decibel's agent speaks to external MCP tool servers (HexStrike AI, Kali-MCP,
//! ...) so their tools appear as native [`decibel_tools::Tool`]s. The transport
//! is newline-delimited JSON-RPC 2.0 over a subprocess's stdio; the protocol is
//! implemented on a stream-generic [`McpConnection`] so it is testable against
//! an in-memory fake server.
//!
//! ## Usage
//!
//! ```no_run
//! use decibel_mcp::{register_mcp_server, McpServerConfig};
//! use decibel_tools::ToolRegistry;
//!
//! # async fn wire(registry: &mut ToolRegistry) -> Result<(), String> {
//! let cfg = McpServerConfig::new("hexstrike", "hexstrike-mcp");
//! // Keep the returned client alive for as long as its tools are registered:
//! let _client = register_mcp_server(registry, &cfg).await?;
//! // The registry now holds `mcp_hexstrike_<tool>` for every remote tool.
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod config;
pub mod tool;

use std::sync::Arc;

use decibel_tools::{Tool, ToolRegistry};

pub use client::{McpClient, McpConnection, McpToolDef};
pub use config::McpServerConfig;
pub use tool::{sanitize_name, tool_name, McpTool};

/// Connect to an MCP server: spawn it, complete the handshake, list its tools,
/// and build an [`McpTool`] for each. Returns the live client (keep it alive!)
/// and the tools as `Arc<dyn Tool>`.
pub async fn connect(
    cfg: &McpServerConfig,
) -> Result<(Arc<McpClient>, Vec<Arc<dyn Tool>>), String> {
    let client = McpClient::spawn(cfg).await?;
    client.initialize().await?;
    let defs = client.list_tools().await?;
    let tools = defs
        .iter()
        .map(|def| Arc::new(McpTool::new(client.clone(), &cfg.name, def)) as Arc<dyn Tool>)
        .collect();
    Ok((client, tools))
}

/// Connect and register every remote tool into `registry`. Returns the live
/// client so the caller keeps the connection (and its subprocess) alive for as
/// long as the registered tools may be invoked.
pub async fn register_mcp_server(
    registry: &mut ToolRegistry,
    cfg: &McpServerConfig,
) -> Result<Arc<McpClient>, String> {
    let (client, tools) = connect(cfg).await?;
    for tool in tools {
        registry.register(tool);
    }
    Ok(client)
}
