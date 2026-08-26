//! End-to-end loop test with a scripted mock adapter — proves `run_turn` drives
//! a full ReAct turn (model calls a tool, reads its result, then answers)
//! deterministically and offline.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::{json, Value};

use decibel_agent::{run_turn, AgentConfig, StopReason, TurnSignal};
use decibel_core::{EventKind, Session};
use decibel_llm::{
    ChunkStream, ContentBlock, FinishReason, GenerateOptions, LlmAdapter, Message, StreamChunk,
    ToolSchema,
};
use decibel_tools::{ExecCtx, Tool, ToolError, ToolRegistry};

/// An adapter that replays one scripted chunk sequence per `stream()` call.
struct MockAdapter {
    scripts: Mutex<VecDeque<Vec<StreamChunk>>>,
}

impl MockAdapter {
    fn new(scripts: Vec<Vec<StreamChunk>>) -> Self {
        MockAdapter {
            scripts: Mutex::new(scripts.into()),
        }
    }
}

impl LlmAdapter for MockAdapter {
    fn stream(&self, _options: GenerateOptions) -> ChunkStream {
        let script = self.scripts.lock().unwrap().pop_front().unwrap_or_default();
        Box::pin(futures_util::stream::iter(script))
    }
}

/// A tool that echoes its `text` argument back as the canonical value.
struct EchoTool;

#[async_trait]
impl Tool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "echo".into(),
            description: "echo text".into(),
            parameters: json!({ "type": "object", "properties": { "text": { "type": "string" } }, "required": ["text"] }),
        }
    }
    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let text = arguments
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_args("missing `text`"))?;
        Ok(json!({ "echoed": text }))
    }
    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(
            value.get("echoed").and_then(Value::as_str).unwrap_or("").to_string(),
        )]
    }
}

fn tool_call_step(id: &str, name: &str, args: &str) -> Vec<StreamChunk> {
    vec![
        StreamChunk::ToolCallDelta {
            index: 2,
            id: Some(id.into()),
            name: Some(name.into()),
            arguments_delta: args.into(),
        },
        StreamChunk::Finish { reason: FinishReason::ToolCalls },
    ]
}

fn text_step(text: &str) -> Vec<StreamChunk> {
    vec![
        StreamChunk::TextDelta { index: 1, text: text.into() },
        StreamChunk::Finish { reason: FinishReason::Stop },
    ]
}

#[tokio::test]
async fn drives_a_full_react_turn() {
    // Step 1: the model calls `echo`. Step 2: it answers with the result.
    let adapter = MockAdapter::new(vec![
        tool_call_step("c1", "echo", r#"{"text":"pwned"}"#),
        text_step("The echo tool returned pwned. Done."),
    ]);
    let mut registry = ToolRegistry::new();
    registry.register(std::sync::Arc::new(EchoTool));

    let mut session = Session::new("t1");
    let config = AgentConfig::new("mock", "mock-model").with_system("be terse");
    let prompt = Message::human("u1", vec![ContentBlock::text("echo pwned for me")]);

    let outcome = run_turn(&mut session, &adapter, &registry, &config, prompt, TurnSignal::new()).await;

    assert_eq!(outcome.stop_reason, StopReason::Completed);
    assert_eq!(outcome.steps, 2);
    assert!(outcome.final_text.contains("Done"));

    // Transcript: user, assistant(tool-call), tool-result, assistant(final).
    let messages = session.derive_messages();
    assert_eq!(messages.len(), 4, "got: {messages:#?}");
    // The tool result carries the echoed value the model then summarized.
    let tool_result = &messages[2];
    assert!(matches!(tool_result.source, decibel_llm::MessageSource::Tool { .. }));

    // Durable facts: exactly one tool/call and one tool/result were logged.
    let calls = session
        .events()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::ToolCall { .. }))
        .count();
    let results = session
        .events()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::ToolResult { .. }))
        .count();
    assert_eq!((calls, results), (1, 1));

    // The turn opened and closed exactly once, completed.
    let turn_ends: Vec<_> = session
        .events()
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::TurnEnd { reason, .. } => Some(reason.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(turn_ends.len(), 1);
    assert!(matches!(turn_ends[0], decibel_core::TurnEndReason::Completed));
}

#[tokio::test]
async fn answers_without_tools_in_one_step() {
    let adapter = MockAdapter::new(vec![text_step("nmap maps networks.")]);
    let registry = ToolRegistry::new();
    let mut session = Session::new("t2");
    let config = AgentConfig::new("mock", "mock-model");
    let prompt = Message::human("u1", vec![ContentBlock::text("what is nmap?")]);

    let outcome = run_turn(&mut session, &adapter, &registry, &config, prompt, TurnSignal::new()).await;
    assert_eq!(outcome.stop_reason, StopReason::Completed);
    assert_eq!(outcome.steps, 1);
    assert_eq!(outcome.final_text, "nmap maps networks.");
    assert_eq!(session.derive_messages().len(), 2);
}

#[tokio::test]
async fn model_request_error_ends_the_turn() {
    let adapter = MockAdapter::new(vec![vec![StreamChunk::Finish {
        reason: FinishReason::Error {
            failure: decibel_llm::LlmFailure {
                message: "rate limited".into(),
                code: "RATE_LIMIT".into(),
                status: Some(429),
                retry_after_ms: None,
            },
        },
    }]]);
    let registry = ToolRegistry::new();
    let mut session = Session::new("t3");
    let config = AgentConfig::new("mock", "mock-model");
    let prompt = Message::human("u1", vec![ContentBlock::text("hi")]);

    let outcome = run_turn(&mut session, &adapter, &registry, &config, prompt, TurnSignal::new()).await;
    match outcome.stop_reason {
        StopReason::Error(failure) => assert_eq!(failure.code, "RATE_LIMIT"),
        other => panic!("expected error stop, got {other:?}"),
    }
}
