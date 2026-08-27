//! Folds the raw [`StreamChunk`] protocol back into complete content blocks and
//! an assistant [`Message`].
//!
//! Adapters emit deltas (and, for OpenAI-compatible providers, usually no
//! explicit `block-end`), so the assembler accumulates by block index and
//! finalizes every open block on demand. A `max-tokens` finish drops tool-call
//! blocks, which may have been truncated mid-arguments.

use std::collections::BTreeMap;

use crate::content::ContentBlock;
use crate::ids::{CallId, MessageId};
use crate::message::Message;
use crate::stream::{FinishReason, StreamChunk, TokenUsage};

/// A block being accumulated across deltas.
#[derive(Clone, Debug)]
enum Pending {
    Text(String),
    Reasoning(String),
    ToolCall {
        id: Option<String>,
        name: Option<String>,
        arguments: String,
    },
}

/// Incrementally assembles raw stream chunks into blocks and a message.
#[derive(Debug, Default)]
pub struct BlockAssembler {
    blocks: BTreeMap<u32, Pending>,
    usage: Option<TokenUsage>,
    finish: Option<FinishReason>,
}

impl BlockAssembler {
    /// A fresh assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one raw chunk.
    pub fn push(&mut self, chunk: StreamChunk) {
        match chunk {
            StreamChunk::BlockStart { index, block_type } => {
                self.blocks.entry(index).or_insert_with(|| match block_type.as_str() {
                    "reasoning" => Pending::Reasoning(String::new()),
                    "tool-call" => Pending::ToolCall {
                        id: None,
                        name: None,
                        arguments: String::new(),
                    },
                    _ => Pending::Text(String::new()),
                });
            }
            StreamChunk::TextDelta { index, text } => {
                match self.blocks.entry(index).or_insert_with(|| Pending::Text(String::new())) {
                    Pending::Text(buf) => buf.push_str(&text),
                    // A delta of the wrong kind for an existing block is ignored;
                    // adapters keep one kind per index.
                    _ => {}
                }
            }
            StreamChunk::ReasoningDelta { index, text } => {
                match self
                    .blocks
                    .entry(index)
                    .or_insert_with(|| Pending::Reasoning(String::new()))
                {
                    Pending::Reasoning(buf) => buf.push_str(&text),
                    _ => {}
                }
            }
            StreamChunk::ToolCallDelta {
                index,
                id,
                name,
                arguments_delta,
            } => {
                let entry = self.blocks.entry(index).or_insert_with(|| Pending::ToolCall {
                    id: None,
                    name: None,
                    arguments: String::new(),
                });
                if let Pending::ToolCall {
                    id: slot_id,
                    name: slot_name,
                    arguments,
                } = entry
                {
                    if id.is_some() {
                        *slot_id = id;
                    }
                    if name.is_some() {
                        *slot_name = name;
                    }
                    arguments.push_str(&arguments_delta);
                }
            }
            StreamChunk::BlockEnd { index, block } => {
                // An explicit block-end replaces the accumulated block outright.
                self.blocks.insert(index, finalized_to_pending(block));
            }
            StreamChunk::Usage { usage } => {
                self.usage = Some(usage);
            }
            StreamChunk::Finish { reason } => {
                self.finish = Some(reason);
            }
        }
    }

    /// The finalized content blocks in index order. Tool calls with no id are
    /// dropped (unaddressable), and every tool call is dropped after a
    /// `max-tokens` finish (they may be truncated).
    pub fn blocks(&self) -> Vec<ContentBlock> {
        let drop_tool_calls = matches!(self.finish, Some(FinishReason::MaxTokens));
        self.blocks
            .values()
            .filter_map(|pending| match pending {
                Pending::Text(text) if !text.is_empty() => Some(ContentBlock::text(text.clone())),
                Pending::Text(_) => None,
                Pending::Reasoning(text) if !text.is_empty() => {
                    Some(ContentBlock::reasoning(text.clone()))
                }
                Pending::Reasoning(_) => None,
                Pending::ToolCall { id, name, arguments } => {
                    if drop_tool_calls {
                        return None;
                    }
                    let id = id.clone()?;
                    let name = name.clone().unwrap_or_default();
                    Some(ContentBlock::ToolCall {
                        id: CallId::from(id),
                        name,
                        arguments: if arguments.is_empty() {
                            "{}".to_string()
                        } else {
                            arguments.clone()
                        },
                    })
                }
            })
            .collect()
    }

    /// The terminal finish reason, once seen.
    pub fn finish(&self) -> Option<&FinishReason> {
        self.finish.as_ref()
    }

    /// The reported token usage, when the provider sent it.
    pub fn usage(&self) -> Option<TokenUsage> {
        self.usage
    }

    /// Whether any assembled block contains a tool call (after finish policy).
    pub fn has_tool_calls(&self) -> bool {
        self.blocks()
            .iter()
            .any(|block| matches!(block, ContentBlock::ToolCall { .. }))
    }

    /// Build the assistant message from the assembled blocks.
    pub fn into_message(
        &self,
        id: impl Into<MessageId>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Message {
        Message::assistant(id, self.blocks(), provider, model)
    }
}

/// Convert an already-finalized block (from `block-end`) into a `Pending`.
fn finalized_to_pending(block: ContentBlock) -> Pending {
    match block {
        ContentBlock::Text { text } => Pending::Text(text),
        ContentBlock::Reasoning { text } => Pending::Reasoning(text),
        ContentBlock::ToolCall { id, name, arguments } => Pending::ToolCall {
            id: Some(id.0),
            name: Some(name),
            arguments,
        },
        // A tool-result or image never arrives on the assistant stream; keep an
        // empty text so nothing is silently lost.
        ContentBlock::ToolResult { .. } | ContentBlock::Image { .. } => Pending::Text(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_interleaved_text_deltas() {
        let mut a = BlockAssembler::new();
        a.push(StreamChunk::TextDelta { index: 0, text: "Hel".into() });
        a.push(StreamChunk::TextDelta { index: 0, text: "lo".into() });
        a.push(StreamChunk::Finish { reason: FinishReason::Stop });
        assert_eq!(a.blocks(), vec![ContentBlock::text("Hello")]);
        assert!(!a.has_tool_calls());
    }

    #[test]
    fn assembles_tool_call_across_deltas() {
        let mut a = BlockAssembler::new();
        a.push(StreamChunk::ToolCallDelta {
            index: 0,
            id: Some("call_1".into()),
            name: Some("bash".into()),
            arguments_delta: r#"{"command":"#.into(),
        });
        a.push(StreamChunk::ToolCallDelta {
            index: 0,
            id: None,
            name: None,
            arguments_delta: r#""ls"}"#.into(),
        });
        a.push(StreamChunk::Finish { reason: FinishReason::ToolCalls });
        assert!(a.has_tool_calls());
        assert_eq!(
            a.blocks(),
            vec![ContentBlock::ToolCall {
                id: CallId::from("call_1"),
                name: "bash".into(),
                arguments: r#"{"command":"ls"}"#.into(),
            }]
        );
    }

    #[test]
    fn max_tokens_drops_possibly_truncated_tool_calls() {
        let mut a = BlockAssembler::new();
        a.push(StreamChunk::TextDelta { index: 0, text: "partial".into() });
        a.push(StreamChunk::ToolCallDelta {
            index: 1,
            id: Some("call_x".into()),
            name: Some("bash".into()),
            arguments_delta: r#"{"command":"#.into(),
        });
        a.push(StreamChunk::Finish { reason: FinishReason::MaxTokens });
        // The text survives; the truncated tool call is dropped.
        assert_eq!(a.blocks(), vec![ContentBlock::text("partial")]);
        assert!(!a.has_tool_calls());
    }

    #[test]
    fn into_message_carries_model_source() {
        let mut a = BlockAssembler::new();
        a.push(StreamChunk::TextDelta { index: 0, text: "hi".into() });
        let msg = a.into_message("m1", "openrouter", "z-ai/glm-4.6:free");
        assert_eq!(msg.content, vec![ContentBlock::text("hi")]);
    }
}
