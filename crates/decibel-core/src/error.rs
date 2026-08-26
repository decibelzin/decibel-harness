//! Errors raised while building or replaying a session.

use thiserror::Error;

/// A failure appending to, or reconstructing, a session.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A surface-eligible event was appended without a surface op.
    #[error("surface event at seq {seq} was appended without a surface op")]
    MissingSurfaceOp {
        /// The offending event seq.
        seq: u64,
    },
    /// A log-only event carried surface metadata it may not have.
    #[error("log-only event at seq {seq} carries a surface op")]
    SurfaceOnLogOnly {
        /// The offending event seq.
        seq: u64,
    },
    /// A replace named a start/end that is not a current surface node.
    #[error("replace names surface node {seq} that is not on the surface")]
    UnknownSurfaceNode {
        /// The missing node seq.
        seq: u64,
    },
    /// A replace's start position is after its end position.
    #[error("replace range start {start} is after end {end}")]
    InvalidReplaceRange {
        /// The start seq.
        start: u64,
        /// The end seq.
        end: u64,
    },
    /// A replace did not cite every surface node it shadows.
    #[error("replace {replacement} does not cite shadowed surface node {missing}")]
    IncompleteReplaceCoverage {
        /// The shadowed node that was not cited.
        missing: u64,
        /// The replacement event seq.
        replacement: u64,
    },
    /// A restored seed had a non-contiguous seq.
    #[error("seed event at index {index} has seq {seq} (expected {index}); seed must be contiguous from 0")]
    NonContiguousSeed {
        /// The seed array index.
        index: usize,
        /// The seq the event actually carried.
        seq: u64,
    },
    /// A JSONL line could not be parsed as a session event.
    #[error("failed to parse session event at line {line}: {source}")]
    Parse {
        /// The 1-based line number.
        line: usize,
        /// The underlying JSON error.
        source: serde_json::Error,
    },
    /// An I/O failure reading or writing persistence.
    #[error("session persistence I/O error: {0}")]
    Io(#[from] std::io::Error),
}
