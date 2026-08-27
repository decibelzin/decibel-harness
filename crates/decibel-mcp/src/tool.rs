//! [`McpTool`]: a remote MCP tool exposed as a native `decibel_tools::Tool`.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};

use crate::client::{extract_text, McpClient, McpToolDef};

/// Sanitize a segment to `[a-z0-9_]`: lowercase ASCII alphanumerics kept, every
/// other character becomes `_`.
pub fn sanitize_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// The native tool name for a remote tool: `mcp_<server>_<remote>`, each segment
/// sanitized. Prefixing keeps remote names from clashing with built-in tools.
pub fn tool_name(server: &str, remote: &str) -> String {
    format!("mcp_{}_{}", sanitize_name(server), sanitize_name(remote))
}

/// A single remote MCP tool, callable through the shared [`McpClient`].
pub struct McpTool {
    client: Arc<McpClient>,
    #[allow(dead_code)]
    server: String,
    remote_name: String,
    tool_name: String,
    description: String,
    input_schema: Value,
}

impl McpTool {
    /// Build a tool wrapper for one advertised remote tool on `server`.
    pub fn new(client: Arc<McpClient>, server: impl Into<String>, def: &McpToolDef) -> Self {
        let server = server.into();
        let tool_name = tool_name(&server, &def.name);
        McpTool {
            client,
            server,
            remote_name: def.name.clone(),
            tool_name,
            description: def.description.clone(),
            input_schema: def.input_schema.clone(),
        }
    }

    /// The remote (unprefixed) tool name the server knows this tool by.
    pub fn remote_name(&self) -> &str {
        &self.remote_name
    }
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.tool_name
    }

    fn schema(&self) -> ToolSchema {
        // A tool's `inputSchema` must be a JSON Schema object; fall back to an
        // empty object schema when the server sent something else.
        let parameters = if self.input_schema.is_object() {
            self.input_schema.clone()
        } else {
            json!({ "type": "object", "properties": {} })
        };
        ToolSchema {
            name: self.tool_name.clone(),
            description: self.description.clone(),
            parameters,
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        tokio::select! {
            // Cooperative cancellation: the turn was aborted.
            _ = ctx.token().cancelled() => Err(ToolError::Aborted),
            outcome = self.client.call_tool(&self.remote_name, arguments) => {
                outcome.map_err(ToolError::execution)
            }
        }
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        // Prefer the joined text of the result's content blocks; fall back to
        // the stringified value when there is no textual content.
        let text = extract_text(value);
        let text = if text.is_empty() {
            value.to_string()
        } else {
            text
        };
        vec![ContentBlock::text(text)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_lowercases_and_replaces_non_alnum() {
        assert_eq!(sanitize_name("Hex-Strike AI"), "hex_strike_ai");
        assert_eq!(sanitize_name("port.scan/v2"), "port_scan_v2");
        assert_eq!(sanitize_name("nmap"), "nmap");
    }

    #[test]
    fn tool_name_prefixes_and_sanitizes_both_segments() {
        assert_eq!(tool_name("Kali-MCP", "nmap.scan"), "mcp_kali_mcp_nmap_scan");
        assert_eq!(tool_name("hexstrike", "echo"), "mcp_hexstrike_echo");
    }
}
