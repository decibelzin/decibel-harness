//! The tool registry and guarded execution pipeline for Decibel Harness.
//!
//! A [`Tool`] declares a model-facing schema, runs a body returning a canonical
//! JSON [`serde_json::Value`], and renders that value to model-facing content
//! with a pure function. The value/render split is the load-bearing idea from
//! DeepSeek Harness: the model reads the rendered content, the UI replays a card
//! from the same canonical value in the log, and a future Code Mode dispatches
//! over the value — none of them parse each other's text.
//!
//! [`ToolRegistry::execute`] runs one call through pre-policy → body → render →
//! post-policy and always settles as a [`ToolResult`] (a failure becomes an
//! error result, never a panic or a propagated `Err`).

pub mod error;
pub mod registry;
pub mod tool;

pub use error::ToolError;
pub use registry::{PostPolicy, PreDecision, PrePolicy, ToolRegistry};
pub use tool::{ExecCtx, Tool, ToolCall, ToolResult};
