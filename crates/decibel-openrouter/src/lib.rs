//! The OpenRouter adapter for Decibel Harness.
//!
//! Two capabilities: a live [model catalog](catalog) (`GET /api/v1/models`,
//! public — the data behind the model picker) and a streaming
//! [chat adapter](adapter) that maps OpenAI-compatible SSE onto the neutral
//! [`decibel_llm::StreamChunk`] protocol. This is the only crate that performs
//! network I/O; everything above it stays provider-neutral.

pub mod adapter;
pub mod catalog;
pub mod error;

pub use adapter::OpenRouterAdapter;
pub use catalog::{fetch_default_models, fetch_models, parse_catalog, ModelInfo};
pub use error::OpenRouterError;

/// The default OpenRouter API root.
pub const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";
