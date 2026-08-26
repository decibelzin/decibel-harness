//! The session-event vocabulary: the append-only facts an interaction is made
//! of. Message history is derived from these; boundary and log-only events add
//! no message.

use serde::{Deserialize, Serialize};

use decibel_llm::{Message, StreamChunk, TokenUsage};

/// Why an active agent driver was cancelled.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum CancelCause {
    /// The human asked to stop.
    User,
    /// A parent agent cancelled its child.
    Parent,
    /// A hook policy stopped the turn.
    Hook {
        /// Human-readable reason.
        reason: String,
    },
    /// The agent is being disposed.
    Disposed,
}

/// Why a turn ended.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TurnEndReason {
    /// The turn completed naturally.
    Completed,
    /// A cancellation request interrupted the live turn.
    Aborted {
        /// The cancellation cause.
        reason: CancelCause,
    },
    /// The proposed step was rejected before any model call.
    Blocked,
    /// The turn failed with a structured error.
    Error {
        /// Human-readable failure message.
        message: String,
        /// Stable routing code.
        code: String,
    },
    /// At least one step reached its output-token ceiling.
    MaxTokens,
    /// A backend closed a crash-orphaned turn on reload.
    Interrupted,
}

/// Lifecycle state of one todo entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    /// Not started.
    Pending,
    /// Being worked now.
    InProgress,
    /// Finished.
    Completed,
}

/// One entry in the agent's todo list. The list is replaced wholesale on every
/// write (last-write-wins), so entries need no stable identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TodoItem {
    /// Short imperative line shown in the UI.
    pub content: String,
    /// Lifecycle state.
    pub status: TodoStatus,
}

/// The typed payload of one session event.
///
/// Serialized with an internal `type` tag using the DeepSeek Harness spellings
/// (`turn/start`, `assistant/message`, …) so the durable log is legible and
/// portable. Surface metadata (see [`SurfaceOp`]) lives on the [`SessionEvent`]
/// envelope, not here, because only three variants may carry it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventKind {
    /// Opens a turn before the loop claims input or runs pre-step.
    #[serde(rename = "turn/start")]
    TurnStart {
        /// The turn number.
        turn: u64,
    },
    /// Closes a turn with the reason it ended.
    #[serde(rename = "turn/end")]
    TurnEnd {
        /// The turn number.
        turn: u64,
        /// Why it ended.
        reason: TurnEndReason,
    },
    /// Opens a step — one model call plus the tools it requests.
    #[serde(rename = "step/start")]
    StepStart {
        /// The turn number.
        turn: u64,
        /// The step number within the turn.
        step: u64,
    },
    /// Closes a step.
    #[serde(rename = "step/end")]
    StepEnd {
        /// The turn number.
        turn: u64,
        /// The step number within the turn.
        step: u64,
    },
    /// A user-role message on the model-visible surface (human prompt, injected
    /// context, or an entered continuation). Surface-eligible.
    #[serde(rename = "user/message")]
    UserMessage(Message),
    /// A raw stream chunk — token-level replay fidelity. Log-only.
    #[serde(rename = "assistant/chunk")]
    AssistantChunk {
        /// The turn number.
        turn: u64,
        /// The step number.
        step: u64,
        /// The raw chunk.
        chunk: StreamChunk,
    },
    /// The assembled assistant message for one step. Surface-eligible.
    #[serde(rename = "assistant/message")]
    AssistantMessage {
        /// The turn number.
        turn: u64,
        /// The step number.
        step: u64,
        /// The assembled message.
        message: Message,
        /// Token usage, when the adapter reported it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        usage: Option<TokenUsage>,
    },
    /// The model requested one tool invocation. Log-only; the call lives inside
    /// its assistant message too, but this event pairs it with a result.
    #[serde(rename = "tool/call")]
    ToolCall {
        /// The turn number.
        turn: u64,
        /// The step number.
        step: u64,
        /// Provider call id.
        call_id: decibel_llm::CallId,
        /// Tool name.
        name: String,
        /// Raw argument JSON string.
        arguments: String,
    },
    /// A completed tool call's model-facing result message. Surface-eligible.
    #[serde(rename = "tool/result")]
    ToolResult {
        /// The turn number.
        turn: u64,
        /// The step number.
        step: u64,
        /// The tool-result message.
        message: Message,
    },
    /// Whole-list todo snapshot; latest write wins on replay. Log-only.
    #[serde(rename = "todo/write")]
    TodoWrite {
        /// The complete list.
        todos: Vec<TodoItem>,
    },
    /// Marks the end of a constructor seed (resume/fork boundary). Log-only.
    #[serde(rename = "session/end-seed")]
    EndSeed,
}

impl EventKind {
    /// Whether this event type may appear on the ordered surface (and therefore
    /// must carry a [`SurfaceOp`] when appended).
    pub fn is_surface_eligible(&self) -> bool {
        matches!(
            self,
            EventKind::UserMessage(_)
                | EventKind::AssistantMessage { .. }
                | EventKind::ToolResult { .. }
        )
    }

    /// Project this event to the model message it contributes, if any. An
    /// empty-content assistant message derives to `None` and stays out of the
    /// transcript.
    pub fn derive_message(&self) -> Option<&Message> {
        match self {
            EventKind::UserMessage(message) => Some(message),
            EventKind::ToolResult { message, .. } => Some(message),
            EventKind::AssistantMessage { message, .. } => {
                if message.is_content_empty() {
                    None
                } else {
                    Some(message)
                }
            }
            _ => None,
        }
    }
}

/// How a surface-eligible event entered the ordered surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum SurfaceOp {
    /// Added to the tail — the normal path for a new message.
    Append,
    /// Replaces surface nodes from `start` through `end` (both inclusive, both
    /// existing surface-node seqs) with this node. Used by compaction.
    Replace {
        /// First shadowed surface-node seq (inclusive).
        start: u64,
        /// Last shadowed surface-node seq (inclusive).
        end: u64,
    },
}

/// One immutable entry in the session log.
///
/// `surface_op` and `source_event_seqs` exist only on surface-eligible events;
/// [`crate::Session::append_surface`] enforces that at the append site.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Monotonic sequence number within the session (equals its log index).
    pub seq: u64,
    /// Unix epoch milliseconds.
    pub time: i64,
    /// The typed payload.
    #[serde(flatten)]
    pub kind: EventKind,
    /// How this event entered the surface; absent for log-only events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_op: Option<SurfaceOp>,
    /// Seq numbers of earlier events this one cites as sources (the chunks
    /// behind a message, or the surface nodes a replace shadows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_seqs: Option<Vec<u64>>,
}
