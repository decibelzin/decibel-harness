//! The adapter seam: the neutral interface the loop calls to stream a model.
//!
//! A concrete adapter (e.g. `decibel-openrouter`) implements [`LlmAdapter`]; the
//! agent loop depends only on this trait, so the provider is swappable. The
//! trait lives in the vocabulary crate and stays runtime-free — it names
//! `futures_core::Stream` but pulls in no async executor.

use std::pin::Pin;

use futures_core::Stream;

use crate::options::GenerateOptions;
use crate::stream::StreamChunk;

/// A boxed, sendable stream of raw chunks — the uniform return of any adapter.
pub type ChunkStream = Pin<Box<dyn Stream<Item = StreamChunk> + Send>>;

/// One model provider the loop can call. Failures are delivered as a terminal
/// [`StreamChunk::Finish`] with an error/aborted reason, never as a stream error.
pub trait LlmAdapter: Send + Sync {
    /// Stream one model call. Dropping the returned stream cancels the request.
    fn stream(&self, options: GenerateOptions) -> ChunkStream;
}
