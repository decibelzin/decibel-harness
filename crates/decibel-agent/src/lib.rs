//! The agent loop for Decibel Harness.
//!
//! [`run_turn`] drives one ReAct turn against a [`Session`]: it opens the turn,
//! records the user prompt, and runs steps — each a model request plus the tool
//! calls it makes — until the model answers without calling a tool (or a bound
//! or failure stops it). Every model chunk, message, tool call, and result is a
//! durable [`decibel_core`] event, so the whole turn replays from the log.
//!
//! The model is behind [`LlmAdapter`] and the tools behind [`ToolRegistry`];
//! this crate depends on neither concretely, matching the DeepSeek Harness rule
//! that new behavior attaches to seams rather than the loop.

use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use decibel_core::{EventKind, Session, SurfaceIntent, TurnEndReason};
use decibel_llm::{
    BlockAssembler, ContentBlock, FinishReason, GenerateOptions, LlmAdapter, LlmFailure, Message,
};
use decibel_tools::{ExecCtx, ToolCall, ToolRegistry};

/// Configuration for one loop run.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Provider route recorded on assistant messages.
    pub provider: String,
    /// Model id the adapter interprets.
    pub model: String,
    /// System prompt text, when any.
    pub system: Option<String>,
    /// Sampling temperature, when any.
    pub temperature: Option<f64>,
    /// Output-token cap per request, when any.
    pub max_tokens: Option<u64>,
    /// Hard bound on steps per turn — the runaway-tool-loop backstop.
    pub max_steps: u64,
}

impl AgentConfig {
    /// A config for `provider`/`model` with sane defaults (16-step bound).
    pub fn new(provider: impl Into<String>, model: impl Into<String>) -> Self {
        AgentConfig {
            provider: provider.into(),
            model: model.into(),
            system: None,
            temperature: None,
            max_tokens: None,
            max_steps: 16,
        }
    }

    /// Set the system prompt.
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Set the output-token cap.
    pub fn with_max_tokens(mut self, max_tokens: u64) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
}

/// Why a turn stopped.
#[derive(Clone, Debug, PartialEq)]
pub enum StopReason {
    /// The model answered without calling a tool, or a tool concluded the turn.
    Completed,
    /// The step bound was hit while tools were still being called.
    MaxSteps,
    /// A model request failed terminally.
    Error(LlmFailure),
}

/// The outcome of one turn.
#[derive(Clone, Debug)]
pub struct TurnOutcome {
    /// Why the turn stopped.
    pub stop_reason: StopReason,
    /// The turn number that ran.
    pub turn: u64,
    /// How many model steps executed.
    pub steps: u64,
    /// The final visible assistant text (concatenated text blocks of the last message).
    pub final_text: String,
}

/// Run one turn: append the prompt, then step until the model stops calling
/// tools. `cancel` aborts an in-flight step cooperatively (tools observe it and
/// the stream is dropped). Every effect is a session event.
pub async fn run_turn(
    session: &mut Session,
    adapter: &dyn LlmAdapter,
    tools: &ToolRegistry,
    config: &AgentConfig,
    prompt: Message,
    cancel: CancellationToken,
) -> TurnOutcome {
    let turn = next_turn(session);
    let _ = session.append_log(EventKind::TurnStart { turn });

    // Record the user prompt as the first surface message.
    let _ = session.append_surface(EventKind::UserMessage(prompt), SurfaceIntent::append_bare());

    let mut step: u64 = 0;
    let mut final_text = String::new();

    loop {
        step += 1;
        let _ = session.append_log(EventKind::StepStart { turn, step });

        // Assemble the request from the derived history plus the visible tools.
        let options = GenerateOptions {
            provider: config.provider.clone(),
            model: config.model.clone(),
            messages: session.derive_messages(),
            system: config.system.clone(),
            tools: tools.schemas(),
            temperature: config.temperature,
            max_tokens: config.max_tokens,
        };

        // Stream, logging every chunk for replay fidelity and folding blocks.
        let mut assembler = BlockAssembler::new();
        let mut chunk_seqs: Vec<u64> = Vec::new();
        let mut stream = adapter.stream(options);
        while let Some(chunk) = stream.next().await {
            if let Ok(event) =
                session.append_log(EventKind::AssistantChunk { turn, step, chunk: chunk.clone() })
            {
                chunk_seqs.push(event.seq);
            }
            assembler.push(chunk);
            if cancel.is_cancelled() {
                break;
            }
        }
        drop(stream);

        // A terminal model-request failure ends the turn.
        if let Some(FinishReason::Error { failure } | FinishReason::Aborted { failure }) =
            assembler.finish().cloned()
        {
            let message = Message::assistant(
                format!("a-{turn}-{step}"),
                assembler.blocks(),
                &config.provider,
                &config.model,
            );
            record_assistant(session, turn, step, message, &chunk_seqs);
            let _ = session.append_log(EventKind::StepEnd { turn, step });
            let _ = session.append_log(EventKind::TurnEnd {
                turn,
                reason: TurnEndReason::Error {
                    message: failure.message.clone(),
                    code: failure.code.clone(),
                },
            });
            return TurnOutcome {
                stop_reason: StopReason::Error(failure),
                turn,
                steps: step,
                final_text,
            };
        }

        // Commit the assistant message for this step.
        let message = Message::assistant(
            format!("a-{turn}-{step}"),
            assembler.blocks(),
            &config.provider,
            &config.model,
        );
        let text = text_of(&message);
        if !text.is_empty() {
            final_text = text;
        }
        record_assistant(session, turn, step, message.clone(), &chunk_seqs);

        // Collect the tool calls the model requested.
        let calls = tool_calls_of(&message);
        if calls.is_empty() {
            let _ = session.append_log(EventKind::StepEnd { turn, step });
            let _ = session.append_log(EventKind::TurnEnd {
                turn,
                reason: TurnEndReason::Completed,
            });
            return TurnOutcome {
                stop_reason: StopReason::Completed,
                turn,
                steps: step,
                final_text,
            };
        }

        // Execute each call in model order, recording call/result pairs.
        let mut concluded = false;
        for (call_id, name, raw_args) in calls {
            let call_seq = session
                .append_log(EventKind::ToolCall {
                    turn,
                    step,
                    call_id: call_id.clone(),
                    name: name.clone(),
                    arguments: raw_args.clone(),
                })
                .map(|e| e.seq)
                .unwrap_or(0);

            let arguments = parse_arguments(&raw_args);
            let ctx = ExecCtx::with_token(cancel.clone());
            let result = tools
                .execute(ToolCall { call_id: call_id.clone(), name, arguments }, &ctx)
                .await;
            concluded = concluded || result.concludes_turn;

            let result_message =
                Message::tool_result(format!("r-{call_id}"), call_id, result.content, result.is_error);
            let _ = session.append_surface(
                EventKind::ToolResult { turn, step, message: result_message },
                SurfaceIntent::append(vec![call_seq]),
            );
        }

        let _ = session.append_log(EventKind::StepEnd { turn, step });

        if concluded {
            let _ = session.append_log(EventKind::TurnEnd { turn, reason: TurnEndReason::Completed });
            return TurnOutcome { stop_reason: StopReason::Completed, turn, steps: step, final_text };
        }

        if step >= config.max_steps {
            let _ = session.append_log(EventKind::TurnEnd { turn, reason: TurnEndReason::Completed });
            return TurnOutcome { stop_reason: StopReason::MaxSteps, turn, steps: step, final_text };
        }
    }
}

/// Commit one assistant message, skipping the surface node when it has no
/// derivable content (an empty message would just be dropped by derivation).
fn record_assistant(session: &mut Session, turn: u64, step: u64, message: Message, chunk_seqs: &[u64]) {
    let _ = session.append_surface(
        EventKind::AssistantMessage { turn, step, message, usage: None },
        SurfaceIntent::append(chunk_seqs.to_vec()),
    );
}

/// The next turn number: one past the last `turn/start` in the log.
fn next_turn(session: &Session) -> u64 {
    session
        .events()
        .iter()
        .rev()
        .find_map(|event| match &event.kind {
            EventKind::TurnStart { turn } => Some(*turn),
            _ => None,
        })
        .unwrap_or(0)
        + 1
}

/// Concatenate the visible text blocks of a message.
fn text_of(message: &Message) -> String {
    message
        .content
        .iter()
        .filter_map(ContentBlock::as_text)
        .collect::<Vec<_>>()
        .join("")
}

/// Extract `(call_id, name, raw_arguments)` for each tool-call block.
fn tool_calls_of(message: &Message) -> Vec<(decibel_llm::CallId, String, String)> {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            ContentBlock::ToolCall { id, name, arguments } => {
                Some((id.clone(), name.clone(), arguments.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Parse the model's raw argument string; invalid JSON is preserved as a string
/// value so the tool reports invalid args rather than the loop guessing.
fn parse_arguments(raw: &str) -> Value {
    if raw.trim().is_empty() {
        return Value::Object(Default::default());
    }
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

/// Re-export the cancellation token type callers wire into a turn.
pub use tokio_util::sync::CancellationToken as TurnSignal;

/// Convenience: register tools shared behind an `Arc` in one call.
pub fn registry_with(tools: impl IntoIterator<Item = Arc<dyn decibel_tools::Tool>>) -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    for tool in tools {
        registry.register(tool);
    }
    registry
}
