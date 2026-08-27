//! The `Tool` trait and the values that flow through one execution.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use decibel_llm::{CallId, ContentBlock, ToolSchema};

use crate::error::ToolError;

/// One tool call as the model requested it, after argument parsing.
#[derive(Clone, Debug)]
pub struct ToolCall {
    /// Provider call id, paired with the result.
    pub call_id: CallId,
    /// The tool name.
    pub name: String,
    /// Parsed arguments (the loop parses the model's raw JSON string into this).
    pub arguments: Value,
}

/// Per-execution context handed to a tool body: cooperative cancellation and the
/// session's working directory (which the filesystem/shell tools default to).
#[derive(Clone, Debug)]
pub struct ExecCtx {
    cancel: CancellationToken,
    cwd: Option<PathBuf>,
}

impl ExecCtx {
    /// A context with a fresh, never-cancelled token and no working directory.
    pub fn new() -> Self {
        ExecCtx {
            cancel: CancellationToken::new(),
            cwd: None,
        }
    }

    /// A context wired to an existing cancellation token (the turn's signal).
    pub fn with_token(cancel: CancellationToken) -> Self {
        ExecCtx { cancel, cwd: None }
    }

    /// Set the session working directory the shell/filesystem/search tools use as
    /// their default. Relative paths a tool receives are resolved against it.
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Whether the caller has requested cancellation.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// The underlying token, for `tokio::select!` in async tool bodies.
    pub fn token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// The session working directory, if one was set.
    pub fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    /// Resolve a tool-supplied path: an absolute path is used as-is; a relative
    /// path joins the session cwd (or is returned unchanged when no cwd is set,
    /// preserving the process-cwd behavior for callers that never set one).
    pub fn resolve(&self, path: &str) -> PathBuf {
        let p = Path::new(path);
        if p.is_absolute() {
            return p.to_path_buf();
        }
        match &self.cwd {
            Some(cwd) => cwd.join(p),
            None => p.to_path_buf(),
        }
    }
}

impl Default for ExecCtx {
    fn default() -> Self {
        ExecCtx::new()
    }
}

/// The settled outcome of one tool call — the value/render split made concrete.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolResult {
    /// The call this answers.
    pub call_id: CallId,
    /// Model-facing content (rendered from the canonical value, or an error line).
    pub content: Vec<ContentBlock>,
    /// Whether the call failed.
    pub is_error: bool,
    /// The canonical JSON value on success — execution-local, never sent to the
    /// model directly, but the source of `content` and (later) UI presentation.
    pub value: Option<Value>,
    /// A stable error code when `is_error`.
    pub error_code: Option<String>,
    /// Set when a tool's success should end the current agent turn.
    pub concludes_turn: bool,
}

impl ToolResult {
    /// Build a success result from a canonical value and its rendered content.
    pub fn success(call_id: CallId, value: Value, content: Vec<ContentBlock>) -> Self {
        ToolResult {
            call_id,
            content,
            is_error: false,
            value: Some(value),
            error_code: None,
            concludes_turn: false,
        }
    }

    /// Build an error result whose content is the standard `Error: <message>` line.
    pub fn error(call_id: CallId, code: impl Into<String>, message: impl std::fmt::Display) -> Self {
        ToolResult {
            call_id,
            content: vec![ContentBlock::text(format!("Error: {message}"))],
            is_error: true,
            value: None,
            error_code: Some(code.into()),
            concludes_turn: false,
        }
    }
}

/// A registered tool.
///
/// A tool declares its model-facing schema, runs a body that returns only a
/// canonical JSON value, and renders that value to content with a pure
/// function. `render` must depend only on its arguments — a UI calls it during
/// live streaming and during log replay, so it can hold no state.
#[async_trait]
pub trait Tool: Send + Sync {
    /// The model-facing name (unique in a registry).
    fn name(&self) -> &str;

    /// The schema sent to the model.
    fn schema(&self) -> ToolSchema;

    /// Whether this call may overlap sibling calls. Only an explicit `true`
    /// opts in; the safe default is exclusive.
    fn is_concurrency_safe(&self, _arguments: &Value) -> bool {
        false
    }

    /// Run the accepted call and return only its canonical value. Async bodies
    /// must observe `ctx` for cancellation and settle after their work stops.
    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError>;

    /// Project the canonical value to model-facing content. Pure and total.
    fn render(&self, arguments: &Value, value: &Value) -> Vec<ContentBlock>;
}
