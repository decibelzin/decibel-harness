//! The raw streaming protocol emitted by adapters, plus token accounting.
//!
//! Every adapter outcome reaches consumers as a terminal `Finish` chunk;
//! operational failure is a finish reason, never a thrown error across the
//! stream boundary. A `BlockAssembler` (in `decibel-core`/the loop) folds these
//! raw chunks back into complete blocks and an assistant message.

use serde::{Deserialize, Serialize};

use crate::content::ContentBlock;

/// Token accounting for one model call. Counts are disjoint: `input_tokens` is
/// uncached input only; cache hits are reported separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Uncached input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Cache-read (hit) input tokens, when the provider reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,
    /// Reasoning tokens, when the provider reports them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
}

/// Serializable provider/transport failure facts. Policy decides retryability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LlmFailure {
    /// Human-readable failure message.
    pub message: String,
    /// Stable provider-neutral routing code (e.g. `RATE_LIMIT`, `AUTH`).
    pub code: String,
    /// HTTP status, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Provider-requested retry delay in milliseconds, when valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Why a model response stopped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum FinishReason {
    /// The model produced a complete response and stopped.
    Stop,
    /// The model stopped to make tool calls.
    ToolCalls,
    /// The output-token ceiling was reached.
    MaxTokens,
    /// The request was aborted; carries the failure facts.
    Aborted {
        /// Failure facts for the abort.
        failure: LlmFailure,
    },
    /// The request failed; carries the failure facts.
    Error {
        /// Failure facts for the error.
        failure: LlmFailure,
    },
}

/// One raw streaming chunk. Block indexes correlate interleaved deltas;
/// `BlockEnd` carries the assembled block. Usage precedes the terminal finish.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum StreamChunk {
    /// A new content block began at `index`.
    BlockStart {
        /// Block index within the response.
        index: u32,
        /// The block's type tag.
        block_type: String,
    },
    /// Incremental visible text for the block at `index`.
    TextDelta {
        /// Block index.
        index: u32,
        /// Text fragment.
        text: String,
    },
    /// Incremental reasoning text for the block at `index`.
    ReasoningDelta {
        /// Block index.
        index: u32,
        /// Reasoning fragment.
        text: String,
    },
    /// Incremental tool-call arguments for the block at `index`.
    ToolCallDelta {
        /// Block index.
        index: u32,
        /// Provider call id (may arrive across deltas).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// Tool name, when first seen.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Raw argument-string fragment.
        arguments_delta: String,
    },
    /// The block at `index` is complete; carries the assembled block.
    BlockEnd {
        /// Block index.
        index: u32,
        /// The completed block.
        block: ContentBlock,
    },
    /// Token accounting for the call.
    Usage {
        /// The usage record.
        usage: TokenUsage,
    },
    /// Terminal chunk. Every stream ends with exactly one of these.
    Finish {
        /// Why the response stopped.
        reason: FinishReason,
    },
}
