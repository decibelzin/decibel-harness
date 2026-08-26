//! The shared immutable `Message` value.
//!
//! One message value is used by delivery, durable history, and model requests
//! alike. Every message has an id, a role, content, and a typed source from
//! creation onward — the source is the only channel that tells a direct human
//! prompt, a synthetic injection, and a tool result apart.

use serde::{Deserialize, Serialize};

use crate::content::ContentBlock;
use crate::ids::{CallId, MessageId};

/// Who authored a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The end user, an injected context, or a tool result (all user-role).
    User,
    /// The model.
    Assistant,
}

/// Typed provenance of a message. Content is identical across sources; this is
/// what distinguishes a human prompt from an injected context or a tool result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MessageSource {
    /// A direct prompt typed by the human.
    Human,
    /// Context injected by a plugin (file notices, skill bodies, notices).
    Plugin {
        /// The plugin that produced the injection.
        plugin: String,
    },
    /// An assistant message produced by a model.
    Model {
        /// Provider route that produced it.
        provider: String,
        /// Model id that produced it.
        model: String,
    },
    /// A tool result, coupled to the call it answers.
    Tool {
        /// Id of the answered call.
        call_id: CallId,
    },
}

/// An identified, immutable message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Stable identity, minted at creation.
    pub id: MessageId,
    /// Author role.
    pub role: Role,
    /// Ordered content blocks.
    pub content: Vec<ContentBlock>,
    /// Typed provenance.
    pub source: MessageSource,
}

impl Message {
    /// Build a user-role human prompt with a caller-supplied id.
    pub fn human(id: impl Into<MessageId>, content: Vec<ContentBlock>) -> Self {
        Message {
            id: id.into(),
            role: Role::User,
            content,
            source: MessageSource::Human,
        }
    }

    /// Build an assistant message from a model source.
    pub fn assistant(
        id: impl Into<MessageId>,
        content: Vec<ContentBlock>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Message {
            id: id.into(),
            role: Role::Assistant,
            content,
            source: MessageSource::Model {
                provider: provider.into(),
                model: model.into(),
            },
        }
    }

    /// Build a tool-result message coupled to its call.
    pub fn tool_result(
        id: impl Into<MessageId>,
        call_id: CallId,
        content: Vec<ContentBlock>,
        is_error: bool,
    ) -> Self {
        Message {
            id: id.into(),
            role: Role::User,
            content: vec![ContentBlock::ToolResult {
                tool_call_id: call_id.clone(),
                content,
                is_error,
            }],
            source: MessageSource::Tool { call_id },
        }
    }

    /// Whether every content block is empty of visible substance.
    ///
    /// An assistant message that carried only reasoning or no blocks derives to
    /// nothing in model history (mirrors the DeepSeek Harness rule that an
    /// empty-content assistant message stays out of the transcript).
    pub fn is_content_empty(&self) -> bool {
        self.content.iter().all(|block| match block {
            ContentBlock::Text { text } => text.is_empty(),
            ContentBlock::Reasoning { .. } => true,
            _ => false,
        })
    }
}
