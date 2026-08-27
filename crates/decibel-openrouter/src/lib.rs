//! The LLM provider adapter for Decibel Harness (currently the **DeepSeek** API).
//!
//! Two capabilities: the [model catalog](catalog) (the fixed DeepSeek model list
//! behind the picker) and a streaming [chat adapter](adapter) that maps
//! OpenAI-compatible SSE onto the neutral [`decibel_llm::StreamChunk`] protocol.
//! DeepSeek exposes an OpenAI-compatible endpoint, so the adapter is unchanged
//! beyond its base URL. This is the only crate that performs network I/O;
//! everything above it stays provider-neutral. (The crate is still named
//! `decibel-openrouter` for now — an internal label, not shown to the user.)

pub mod adapter;
pub mod catalog;
pub mod error;

pub use adapter::OpenRouterAdapter;
pub use catalog::{
    deepseek_models, fetch_default_models, fetch_full_catalog, fetch_models,
    openrouter_free_deepseek_models, parse_catalog, ModelInfo, PROVIDER_DEEPSEEK, PROVIDER_OPENROUTER,
};
pub use error::OpenRouterError;

/// The DeepSeek API root (OpenAI-compatible; the adapter appends
/// `/chat/completions`). Also the adapter's default when no base URL is set.
pub const DEFAULT_BASE_URL: &str = "https://api.deepseek.com";

/// The DeepSeek API root (paid models). Same as [`DEFAULT_BASE_URL`].
pub const DEEPSEEK_BASE_URL: &str = "https://api.deepseek.com";

/// The OpenRouter API root (free DeepSeek models + public model catalog).
pub const OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";
