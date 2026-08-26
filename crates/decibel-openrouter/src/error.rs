//! Errors from the OpenRouter adapter's non-streaming calls (catalog fetch).
//!
//! Streaming failures never surface as an `Err` from the stream — they arrive
//! as a terminal `StreamChunk::Finish { reason: Error | Aborted }`, mirroring
//! the DeepSeek Harness rule that a model-request failure is a finish, not a
//! thrown error across the stream boundary.

use thiserror::Error;

/// A failure from a request/response OpenRouter call.
#[derive(Debug, Error)]
pub enum OpenRouterError {
    /// The HTTP transport failed (DNS, TLS, connection, timeout).
    #[error("openrouter transport error: {0}")]
    Transport(#[from] reqwest::Error),
    /// The endpoint returned a non-success status with a body.
    #[error("openrouter returned HTTP {status}: {body}")]
    Http {
        /// The HTTP status code.
        status: u16,
        /// The (possibly truncated) response body.
        body: String,
    },
    /// The response body was not the expected JSON shape.
    #[error("openrouter returned unexpected JSON: {0}")]
    Json(#[from] serde_json::Error),
}
