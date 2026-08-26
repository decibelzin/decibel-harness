//! The assembled request an adapter receives, and the tool schema shape.

use serde::{Deserialize, Serialize};

use crate::message::Message;

/// JSON-schema description of a tool, as sent to the model. Declared here (not
/// in the tools crate) because it is part of `GenerateOptions`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Tool name the model calls.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema object for the arguments.
    pub parameters: serde_json::Value,
}

/// One fully assembled model request. A loop-built request assembles `messages`
/// from the derived session history; a one-shot caller may pass any list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenerateOptions {
    /// Registered provider route selecting the adapter.
    pub provider: String,
    /// Adapter-owned model id.
    pub model: String,
    /// Ordered conversation messages, exactly as the provider sees them.
    pub messages: Vec<Message>,
    /// System prompt text (adapters map to the provider's system slot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Tool schemas (adapters map to the provider's `tools` field).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSchema>,
    /// Sampling temperature, when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    /// Maximum output tokens, when capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
}
