//! Typed content blocks — the units a message's content is made of.
//!
//! The block set is a closed, `type`-tagged union mirroring the JSON wire
//! shape (`{ "type": "text", "text": "..." }`). Adapters map provider content
//! onto these; the loop and session log never see provider-native shapes.

use serde::{Deserialize, Serialize};

use crate::ids::CallId;

/// One typed content block.
///
/// Serialized with an internal `type` tag so the durable form matches the
/// vocabulary the DeepSeek Harness session log uses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ContentBlock {
    /// Plain text visible to the user.
    Text {
        /// The visible text.
        text: String,
    },
    /// Reasoning / thinking content, distinct from visible text.
    Reasoning {
        /// The reasoning text.
        text: String,
    },
    /// A tool invocation requested by the model.
    ToolCall {
        /// Provider-issued call id; correlates with the matching result.
        id: CallId,
        /// The tool name.
        name: String,
        /// Raw JSON argument string exactly as the model produced it.
        arguments: String,
    },
    /// The result of a tool invocation, sent back to the model.
    ToolResult {
        /// Id of the call this result answers.
        tool_call_id: CallId,
        /// Nested model-facing content of the result.
        content: Vec<ContentBlock>,
        /// Whether the call failed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_error: bool,
    },
}

impl ContentBlock {
    /// Construct a plain-text block.
    pub fn text(text: impl Into<String>) -> Self {
        ContentBlock::Text { text: text.into() }
    }

    /// Construct a reasoning block.
    pub fn reasoning(text: impl Into<String>) -> Self {
        ContentBlock::Reasoning { text: text.into() }
    }

    /// The visible text of a `Text` block, or `None` for any other block.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            ContentBlock::Text { text } => Some(text),
            _ => None,
        }
    }
}
