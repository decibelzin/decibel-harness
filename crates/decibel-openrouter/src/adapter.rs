//! The streaming chat-completions adapter.
//!
//! Builds an OpenAI-compatible request from neutral [`GenerateOptions`], streams
//! the SSE response, and maps each delta onto a neutral [`StreamChunk`]. Every
//! outcome — success, HTTP error, transport failure — leaves the stream as a
//! single terminal `Finish` chunk; the stream itself never yields an `Err`.

use async_stream::stream;
use eventsource_stream::Eventsource;
use futures_util::Stream;
use futures_util::StreamExt;
use serde_json::{json, Value};

use decibel_llm::{
    ChunkStream, ContentBlock, FinishReason, GenerateOptions, LlmAdapter, LlmFailure, Message,
    MessageSource, StreamChunk, TokenUsage, ToolSchema,
};

use crate::DEFAULT_BASE_URL;

/// Block index reserved for the assistant's reasoning stream.
const REASONING_INDEX: u32 = 0;
/// Block index reserved for the assistant's visible-text stream.
const TEXT_INDEX: u32 = 1;
/// Base offset for tool-call block indices (provider tool-call index is added).
const TOOL_CALL_BASE: u32 = 2;

/// The OpenRouter adapter. Holds the HTTP client, endpoint, and optional key.
#[derive(Clone)]
pub struct OpenRouterAdapter {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    referer: String,
    title: String,
}

impl OpenRouterAdapter {
    /// Build an adapter with the given API key (or `None` for the public
    /// catalog only) against the default endpoint.
    pub fn new(api_key: Option<String>) -> Self {
        OpenRouterAdapter {
            client: reqwest::Client::new(),
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key,
            referer: "https://github.com/decibelzin/decibel-harness".to_string(),
            title: "Decibel Harness".to_string(),
        }
    }

    /// Point the adapter at a different API root (e.g. a mock server in tests).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// The shared HTTP client, for reusing it in catalog fetches.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Stream one model call. The returned stream is `'static` (it owns its
    /// request), so a caller can drop it to cancel the request.
    pub fn stream(&self, options: GenerateOptions) -> impl Stream<Item = StreamChunk> + 'static {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = build_request_body(&options);
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let referer = self.referer.clone();
        let title = self.title.clone();

        stream! {
            let mut request = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("HTTP-Referer", &referer)
                .header("X-Title", &title)
                .json(&body);
            if let Some(key) = &api_key {
                request = request.bearer_auth(key);
            }

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    yield StreamChunk::Finish { reason: transport_failure(&err) };
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                yield StreamChunk::Finish { reason: http_failure(status.as_u16(), &body) };
                return;
            }

            let mut events = response.bytes_stream().eventsource();
            let mut usage: Option<TokenUsage> = None;
            let mut finish: Option<FinishReason> = None;

            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(err) => {
                        finish = Some(FinishReason::Error {
                            failure: LlmFailure {
                                message: format!("stream read error: {err}"),
                                code: "STREAM_READ".into(),
                                status: None,
                                retry_after_ms: None,
                            },
                        });
                        break;
                    }
                };
                let data = event.data.trim();
                if data.is_empty() {
                    continue;
                }
                if data == "[DONE]" {
                    break;
                }
                let Ok(obj) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                // An error object may arrive mid-stream instead of a choice.
                if let Some(error) = obj.get("error") {
                    finish = Some(FinishReason::Error { failure: parse_error_object(error) });
                    break;
                }
                if let Some(u) = obj.get("usage").and_then(parse_usage) {
                    usage = Some(u);
                }
                let Some(choice) = obj.get("choices").and_then(|c| c.get(0)) else {
                    continue;
                };
                if let Some(delta) = choice.get("delta") {
                    for chunk in map_delta(delta) {
                        yield chunk;
                    }
                }
                if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                    if !reason.is_empty() {
                        finish = Some(map_finish_reason(reason));
                    }
                }
            }

            if let Some(usage) = usage {
                yield StreamChunk::Usage { usage };
            }
            yield StreamChunk::Finish {
                reason: finish.unwrap_or(FinishReason::Stop),
            };
        }
    }
}

impl LlmAdapter for OpenRouterAdapter {
    /// Box the inherent stream behind the neutral seam. `self.stream(options)`
    /// resolves to the inherent method (inherent methods win method-call
    /// resolution), so this does not recurse.
    fn stream(&self, options: GenerateOptions) -> ChunkStream {
        Box::pin(self.stream(options))
    }
}

/// Build the OpenAI-compatible request body.
fn build_request_body(options: &GenerateOptions) -> Value {
    let mut messages = Vec::new();
    if let Some(system) = &options.system {
        if !system.is_empty() {
            messages.push(json!({ "role": "system", "content": system }));
        }
    }
    for message in &options.messages {
        messages.push(convert_message(message));
    }

    let mut body = json!({
        "model": options.model,
        "messages": messages,
        "stream": true,
        "stream_options": { "include_usage": true },
    });
    let map = body.as_object_mut().expect("object literal");
    if !options.tools.is_empty() {
        map.insert("tools".into(), Value::Array(options.tools.iter().map(convert_tool).collect()));
        map.insert("tool_choice".into(), json!("auto"));
    }
    if let Some(temperature) = options.temperature {
        map.insert("temperature".into(), json!(temperature));
    }
    if let Some(max_tokens) = options.max_tokens {
        map.insert("max_tokens".into(), json!(max_tokens));
    }
    body
}

/// Convert one neutral message to an OpenAI wire message.
fn convert_message(message: &Message) -> Value {
    // A tool result is its own OpenAI role.
    if let MessageSource::Tool { call_id } = &message.source {
        return json!({
            "role": "tool",
            "tool_call_id": call_id.as_str(),
            "content": tool_result_text(message),
        });
    }

    let role = match message.role {
        decibel_llm::Role::User => "user",
        decibel_llm::Role::Assistant => "assistant",
    };
    let mut text = String::new();
    let mut tool_calls = Vec::new();
    for block in &message.content {
        match block {
            ContentBlock::Text { text: t } => text.push_str(t),
            ContentBlock::Reasoning { .. } => {}
            ContentBlock::ToolCall { id, name, arguments } => {
                tool_calls.push(json!({
                    "id": id.as_str(),
                    "type": "function",
                    "function": { "name": name, "arguments": arguments },
                }));
            }
            ContentBlock::ToolResult { .. } => {}
        }
    }

    let mut out = json!({ "role": role });
    let map = out.as_object_mut().expect("object literal");
    if tool_calls.is_empty() {
        map.insert("content".into(), json!(text));
    } else {
        // An assistant tool-call message may carry no visible content.
        map.insert(
            "content".into(),
            if text.is_empty() { Value::Null } else { json!(text) },
        );
        map.insert("tool_calls".into(), Value::Array(tool_calls));
    }
    out
}

/// Flatten a tool-result message's nested content to text for the wire.
fn tool_result_text(message: &Message) -> String {
    for block in &message.content {
        if let ContentBlock::ToolResult { content, .. } = block {
            return content
                .iter()
                .filter_map(ContentBlock::as_text)
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    String::new()
}

/// Convert one neutral tool schema to an OpenAI function tool.
fn convert_tool(tool: &ToolSchema) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
        },
    })
}

/// Map one streaming delta object to zero or more neutral chunks.
fn map_delta(delta: &Value) -> Vec<StreamChunk> {
    let mut chunks = Vec::new();
    // Reasoning arrives under `reasoning` (OpenRouter) or `reasoning_content`.
    for key in ["reasoning", "reasoning_content"] {
        if let Some(text) = delta.get(key).and_then(Value::as_str) {
            if !text.is_empty() {
                chunks.push(StreamChunk::ReasoningDelta {
                    index: REASONING_INDEX,
                    text: text.to_string(),
                });
            }
        }
    }
    if let Some(text) = delta.get("content").and_then(Value::as_str) {
        if !text.is_empty() {
            chunks.push(StreamChunk::TextDelta {
                index: TEXT_INDEX,
                text: text.to_string(),
            });
        }
    }
    if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
        for tc in tool_calls {
            let tc_index = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as u32;
            let id = tc.get("id").and_then(Value::as_str).map(str::to_string);
            let function = tc.get("function");
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let arguments_delta = function
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            chunks.push(StreamChunk::ToolCallDelta {
                index: TOOL_CALL_BASE + tc_index,
                id,
                name,
                arguments_delta,
            });
        }
    }
    chunks
}

/// Map an OpenAI finish-reason string to the neutral reason.
fn map_finish_reason(reason: &str) -> FinishReason {
    match reason {
        "stop" | "content_filter" => FinishReason::Stop,
        "length" => FinishReason::MaxTokens,
        "tool_calls" | "function_call" => FinishReason::ToolCalls,
        _ => FinishReason::Stop,
    }
}

/// Parse an OpenAI usage object into neutral token accounting.
fn parse_usage(usage: &Value) -> Option<TokenUsage> {
    let input_tokens = usage.get("prompt_tokens").and_then(Value::as_u64)?;
    let output_tokens = usage.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0);
    let cache_read_tokens = usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64);
    let reasoning_tokens = usage
        .get("completion_tokens_details")
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(Value::as_u64);
    Some(TokenUsage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        reasoning_tokens,
    })
}

/// Turn an HTTP status + body into a neutral failure with a routing code.
fn http_failure(status: u16, body: &str) -> FinishReason {
    let code = match status {
        401 | 403 => "AUTH",
        402 => "QUOTA_EXCEEDED",
        429 => "RATE_LIMIT",
        s if s >= 500 => "PROVIDER_ERROR",
        _ => "HTTP_ERROR",
    };
    // OpenRouter wraps errors as { "error": { "message", "code" } }.
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str().map(str::to_string)))
        .unwrap_or_else(|| body.chars().take(300).collect());
    FinishReason::Error {
        failure: LlmFailure {
            message,
            code: code.into(),
            status: Some(status),
            retry_after_ms: None,
        },
    }
}

/// Parse a mid-stream `{ "error": {...} }` object into a failure.
fn parse_error_object(error: &Value) -> LlmFailure {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("provider stream error")
        .to_string();
    let status = error.get("code").and_then(Value::as_u64).map(|c| c as u16);
    LlmFailure {
        message,
        code: "PROVIDER_ERROR".into(),
        status,
        retry_after_ms: None,
    }
}

/// A transport-level (pre-response) failure.
fn transport_failure(err: &reqwest::Error) -> FinishReason {
    FinishReason::Error {
        failure: LlmFailure {
            message: format!("transport error: {err}"),
            code: "TRANSPORT".into(),
            status: None,
            retry_after_ms: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;

    #[test]
    fn request_body_has_stream_and_tools() {
        let options = GenerateOptions {
            provider: "openrouter".into(),
            model: "x-ai/grok-4-fast:free".into(),
            messages: vec![Message::human("u1", vec![ContentBlock::text("hi")])],
            system: Some("be terse".into()),
            tools: vec![ToolSchema {
                name: "bash".into(),
                description: "run a command".into(),
                parameters: json!({ "type": "object" }),
            }],
            temperature: Some(0.2),
            max_tokens: Some(256),
        };
        let body = build_request_body(&options);
        assert_eq!(body["model"], "x-ai/grok-4-fast:free");
        assert_eq!(body["stream"], true);
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["tools"][0]["function"]["name"], "bash");
        assert_eq!(body["tool_choice"], "auto");
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["max_tokens"], 256);
    }

    #[test]
    fn assistant_tool_call_and_tool_result_round_trip_to_wire() {
        let assistant = Message::assistant(
            "a1",
            vec![ContentBlock::ToolCall {
                id: CallId::from("c1"),
                name: "bash".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            }],
            "openrouter",
            "m",
        );
        let wire = convert_message(&assistant);
        assert_eq!(wire["role"], "assistant");
        assert_eq!(wire["content"], Value::Null);
        assert_eq!(wire["tool_calls"][0]["id"], "c1");
        assert_eq!(wire["tool_calls"][0]["function"]["name"], "bash");

        let result = Message::tool_result("r1", CallId::from("c1"), vec![ContentBlock::text("out")], false);
        let wire = convert_message(&result);
        assert_eq!(wire["role"], "tool");
        assert_eq!(wire["tool_call_id"], "c1");
        assert_eq!(wire["content"], "out");
    }

    #[test]
    fn maps_content_and_tool_call_deltas() {
        let delta = json!({ "content": "Hello" });
        let chunks = map_delta(&delta);
        assert!(matches!(&chunks[0], StreamChunk::TextDelta { text, .. } if text == "Hello"));

        let delta = json!({
            "tool_calls": [{ "index": 0, "id": "c1", "function": { "name": "bash", "arguments": "{}" } }]
        });
        let chunks = map_delta(&delta);
        match &chunks[0] {
            StreamChunk::ToolCallDelta { index, id, name, arguments_delta } => {
                assert_eq!(*index, TOOL_CALL_BASE);
                assert_eq!(id.as_deref(), Some("c1"));
                assert_eq!(name.as_deref(), Some("bash"));
                assert_eq!(arguments_delta, "{}");
            }
            other => panic!("expected tool-call delta, got {other:?}"),
        }
    }

    #[test]
    fn finish_reason_mapping() {
        assert!(matches!(map_finish_reason("stop"), FinishReason::Stop));
        assert!(matches!(map_finish_reason("length"), FinishReason::MaxTokens));
        assert!(matches!(map_finish_reason("tool_calls"), FinishReason::ToolCalls));
    }

    #[test]
    fn http_failure_codes() {
        assert!(matches!(
            http_failure(429, "{\"error\":{\"message\":\"slow down\"}}"),
            FinishReason::Error { failure } if failure.code == "RATE_LIMIT" && failure.message == "slow down"
        ));
        assert!(matches!(
            http_failure(401, "bad key"),
            FinishReason::Error { failure } if failure.code == "AUTH"
        ));
    }
}
