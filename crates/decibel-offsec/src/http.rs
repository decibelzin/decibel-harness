//! The `http` tool: send one arbitrary HTTP request and return the raw response.
//!
//! Full control of method, headers, and body, with no SSRF filtering — probing
//! internal hosts and odd ports is the point of a web-pentest tool. Redirects
//! are NOT followed, so the model sees each hop's real status and `Location`.

use std::time::Duration;

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use reqwest::redirect::Policy;
use reqwest::Method;
use serde_json::{json, Map, Value};

use crate::util::{arg_str, arg_str_opt, arg_u64_opt, truncate_bytes};

/// Cap on the response body returned to the model.
const MAX_BODY_BYTES: usize = 60_000;
/// Default request timeout.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Send one HTTP request with explicit method/headers/body.
pub struct HttpTool;

#[async_trait]
impl Tool for HttpTool {
    fn name(&self) -> &str {
        "http"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http".into(),
            description: "Send one HTTP request and return the status, response headers, and body. \
                Full control of method, headers, and body; redirects are not followed and no host \
                is filtered. Use it to probe web services, test endpoints, and send crafted requests."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "The absolute URL to request." },
                    "method": { "type": "string", "description": "HTTP method (default GET)." },
                    "headers": { "type": "object", "description": "Request headers as a name→value map." },
                    "body": { "type": "string", "description": "Raw request body, when applicable." },
                    "timeout_ms": { "type": "integer", "description": "Timeout in milliseconds (default 30000)." }
                },
                "required": ["url"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let url = arg_str(&arguments, "url")?;
        let method_str = arg_str_opt(&arguments, "method").unwrap_or_else(|| "GET".to_string());
        let method = Method::from_bytes(method_str.to_ascii_uppercase().as_bytes())
            .map_err(|_| ToolError::invalid_args(format!("invalid HTTP method `{method_str}`")))?;
        let timeout = Duration::from_millis(arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS));

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // pentesting: self-signed targets are normal
            .build()
            .map_err(|e| ToolError::execution(format!("failed to build HTTP client: {e}")))?;

        let mut request = client.request(method, &url);
        if let Some(headers) = arguments.get("headers").and_then(Value::as_object) {
            for (name, value) in headers {
                if let Some(v) = value.as_str() {
                    request = request.header(name, v);
                }
            }
        }
        if let Some(body) = arg_str_opt(&arguments, "body") {
            request = request.body(body);
        }

        let send = request.send();
        let response = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = send => r.map_err(|e| ToolError::execution(format!("request failed: {e}")))?,
        };

        let status = response.status().as_u16();
        let mut headers = Map::new();
        for (name, value) in response.headers() {
            headers.insert(
                name.to_string(),
                Value::String(value.to_str().unwrap_or("<binary>").to_string()),
            );
        }
        let raw_body = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = response.text() => r.map_err(|e| ToolError::execution(format!("failed to read body: {e}")))?,
        };
        let (body, truncated) = truncate_bytes(&raw_body, MAX_BODY_BYTES);

        Ok(json!({
            "status": status,
            "headers": Value::Object(headers),
            "body": body,
            "body_truncated": truncated,
        }))
    }

    fn render(&self, arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let status = value.get("status").and_then(Value::as_u64).unwrap_or(0);
        let method = arguments.get("method").and_then(Value::as_str).unwrap_or("GET");
        let url = arguments.get("url").and_then(Value::as_str).unwrap_or("");
        let body = value.get("body").and_then(Value::as_str).unwrap_or("");

        let mut out = format!("{} {} → {}\n", method.to_ascii_uppercase(), url, status);
        if let Some(headers) = value.get("headers").and_then(Value::as_object) {
            for (name, v) in headers {
                if let Some(v) = v.as_str() {
                    out.push_str(&format!("{name}: {v}\n"));
                }
            }
        }
        out.push('\n');
        out.push_str(body);
        if value.get("body_truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n[body truncated]");
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn invalid_method_is_rejected() {
        let tool = HttpTool;
        let err = tool
            .execute(json!({ "url": "http://example.com", "method": "BAD METHOD" }), &ExecCtx::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGS");
    }

    #[tokio::test]
    async fn missing_url_is_rejected() {
        let tool = HttpTool;
        let err = tool.execute(json!({}), &ExecCtx::new()).await.unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGS");
    }

    #[test]
    fn render_shows_status_line() {
        let tool = HttpTool;
        let content = tool.render(
            &json!({ "url": "http://t/", "method": "get" }),
            &json!({ "status": 200, "headers": {}, "body": "ok" }),
        );
        match &content[0] {
            ContentBlock::Text { text } => {
                assert!(text.contains("GET http://t/ → 200"));
                assert!(text.contains("ok"));
            }
            _ => panic!("expected text"),
        }
    }
}
