//! Tool failure taxonomy. A tool body returns `Result<Value, ToolError>`; the
//! registry turns any error into a model-facing error result rather than
//! propagating it, so one failing tool never breaks the loop.

use thiserror::Error;

/// A structured tool failure carrying a stable routing `code` distinct from the
/// human message.
#[derive(Debug, Error)]
pub enum ToolError {
    /// The model arguments did not satisfy the tool's contract.
    #[error("{0}")]
    InvalidArgs(String),
    /// The tool ran but failed (its own domain error).
    #[error("{0}")]
    Execution(String),
    /// Policy denied the call before dispatch.
    #[error("{0}")]
    Denied(String),
    /// The call was cancelled.
    #[error("tool call aborted")]
    Aborted,
}

impl ToolError {
    /// The stable routing code for this failure.
    pub fn code(&self) -> &'static str {
        match self {
            ToolError::InvalidArgs(_) => "INVALID_ARGS",
            ToolError::Execution(_) => "EXEC_ERROR",
            ToolError::Denied(_) => "DENIED",
            ToolError::Aborted => "ABORTED",
        }
    }

    /// Convenience constructor for an execution failure from any message.
    pub fn execution(message: impl Into<String>) -> Self {
        ToolError::Execution(message.into())
    }

    /// Convenience constructor for invalid arguments.
    pub fn invalid_args(message: impl Into<String>) -> Self {
        ToolError::InvalidArgs(message.into())
    }
}
