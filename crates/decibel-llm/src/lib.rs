//! Provider-neutral LLM vocabulary for Decibel Harness.
//!
//! This is the leaf crate every other crate speaks: [`Message`] and its
//! [`ContentBlock`]s are the shared immutable values used by delivery, durable
//! session history, and model requests; [`StreamChunk`] is the raw streaming
//! protocol; [`GenerateOptions`] is one assembled request. There is no I/O and
//! no async runtime here — the concrete OpenRouter adapter and the streaming
//! trait live in downstream crates so this vocabulary stays cheap to depend on.
//!
//! The shapes mirror the DeepSeek Harness (`dsh-llm`) vocabulary so the durable
//! JSON is familiar; the code is an independent Rust implementation.

pub mod adapter;
pub mod assembler;
pub mod content;
pub mod ids;
pub mod message;
pub mod options;
pub mod stream;

pub use adapter::{ChunkStream, LlmAdapter};
pub use assembler::BlockAssembler;
pub use content::ContentBlock;
pub use ids::{CallId, MessageId, SessionId};
pub use message::{Message, MessageSource, Role};
pub use options::{GenerateOptions, ToolSchema};
pub use stream::{FinishReason, LlmFailure, StreamChunk, TokenUsage};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_block_wire_shape() {
        let block = ContentBlock::text("hi");
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json, serde_json::json!({ "type": "text", "text": "hi" }));
        let round: ContentBlock = serde_json::from_value(json).unwrap();
        assert_eq!(round, block);
    }

    #[test]
    fn tool_call_block_wire_shape() {
        let block = ContentBlock::ToolCall {
            id: CallId::from("call_1"),
            name: "bash".into(),
            arguments: r#"{"command":"ls"}"#.into(),
        };
        let json = serde_json::to_value(&block).unwrap();
        assert_eq!(json["type"], "tool-call");
        assert_eq!(json["id"], "call_1");
        assert_eq!(json["name"], "bash");
        let round: ContentBlock = serde_json::from_value(json).unwrap();
        assert_eq!(round, block);
    }

    #[test]
    fn assistant_message_carries_model_source() {
        let msg = Message::assistant(
            "m1",
            vec![ContentBlock::text("done")],
            "openrouter",
            "x-ai/grok-4-fast:free",
        );
        assert_eq!(msg.role, Role::Assistant);
        match &msg.source {
            MessageSource::Model { provider, model } => {
                assert_eq!(provider, "openrouter");
                assert_eq!(model, "x-ai/grok-4-fast:free");
            }
            other => panic!("expected model source, got {other:?}"),
        }
    }

    #[test]
    fn empty_and_reasoning_only_messages_are_content_empty() {
        assert!(Message::assistant("a", vec![], "p", "m").is_content_empty());
        assert!(Message::assistant(
            "b",
            vec![ContentBlock::reasoning("thinking")],
            "p",
            "m",
        )
        .is_content_empty());
        assert!(!Message::assistant("c", vec![ContentBlock::text("x")], "p", "m")
            .is_content_empty());
    }

    #[test]
    fn finish_reason_error_wire_shape() {
        let finish = StreamChunk::Finish {
            reason: FinishReason::Error {
                failure: LlmFailure {
                    message: "rate limited".into(),
                    code: "RATE_LIMIT".into(),
                    status: Some(429),
                    retry_after_ms: Some(1000),
                },
            },
        };
        let json = serde_json::to_value(&finish).unwrap();
        assert_eq!(json["type"], "finish");
        assert_eq!(json["reason"]["kind"], "error");
        assert_eq!(json["reason"]["failure"]["code"], "RATE_LIMIT");
        let round: StreamChunk = serde_json::from_value(json).unwrap();
        assert_eq!(round, finish);
    }
}
