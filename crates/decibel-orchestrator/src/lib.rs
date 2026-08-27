//! Multi-agent red-team orchestration.
//!
//! An **orchestrator** agent plans an authorized engagement and delegates each
//! kill-chain phase to a **specialist** subagent through the [`SubagentTool`]
//! (`delegate`). Each delegation runs a complete agent turn in its own fresh
//! session with a restricted toolset and its own persona — so a phase's context
//! stays isolated (the Decepticon idea) — while every specialist and the
//! orchestrator record into one shared [`FindingStore`], the engagement report.
//!
//! This is the lean, one-shot form: a delegation runs, returns a structured
//! result, and ends. Continuable specialists are future work.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use decibel_agent::{run_turn_observed, AgentConfig, Progress, StopReason};
use decibel_core::Session;
use decibel_llm::{ContentBlock, LlmAdapter, Message, ToolSchema};
use decibel_offsec::{register_named, FindingStore};
use decibel_tools::{ExecCtx, Tool, ToolError, ToolRegistry};
use serde_json::{json, Value};

pub mod roster;

/// One kill-chain specialist: a persona plus the exact tools it may use.
#[derive(Clone)]
pub struct Specialist {
    /// The name the orchestrator delegates to (e.g. `recon`).
    pub name: String,
    /// The specialist's system prompt.
    pub system: String,
    /// Tool names this specialist is given (a subset of the offensive toolkit).
    pub tools: Vec<String>,
    /// Step bound for one delegation.
    pub max_steps: u64,
}

/// The standard kill-chain specialist roster (the 17 upstream sub-agents),
/// built from [`roster::specialists()`] in kill-chain order. Each specialist
/// gets its real persona (compiled in) and its scoped `decibel-offsec` toolset.
///
/// The high-risk gates start read-only: `gated_tools(spec, false, false)` strips
/// the active shell/exploit family from the `ics_operator` (`roe_gate`) and
/// `wireless_operator` (`hw_gate`) until an operator authorizes them, so those
/// specialists cannot run active ops out of the box.
pub fn default_specialists() -> Vec<Specialist> {
    roster::specialists()
        .into_iter()
        .map(|spec| Specialist {
            name: spec.name.to_string(),
            system: roster::specialist_prompt(spec.name).unwrap_or("").to_string(),
            tools: roster::gated_tools(spec, false, false).iter().map(|s| s.to_string()).collect(),
            max_steps: 16,
        })
        .collect()
}

/// The orchestrator's system prompt. Lists the full kill-chain roster
/// dynamically so it always matches [`default_specialists()`].
pub fn orchestrator_system() -> String {
    let roster = roster::specialists()
        .iter()
        .map(|s| format!("`{}` ({})", s.name, s.phase))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "You are the ORCHESTRATOR of an authorized red-team engagement, operating with the user's \
permission on systems they own or may test. Break the objective into kill-chain phases and \
delegate each to a specialist with the `delegate` tool. Available specialists, in kill-chain \
order: {roster}. Delegate reconnaissance FIRST (`recon`/`osint_operator`), then pass its concrete \
results into the exploitation and post-exploitation phases; cover detection with `blue_cell` and \
reporting via specialists' `report_executive` / `record_finding`. Give each delegation a specific, \
self-contained task string — the specialist does not see this conversation, but every specialist \
records into the one shared engagement finding store. Keep your own messages brief; the specialists \
do the work. Finish with a short engagement summary."
    )
}

/// The model-facing `delegate` tool: run one specialist subagent turn.
pub struct SubagentTool {
    adapter: Arc<dyn LlmAdapter>,
    model: String,
    findings: FindingStore,
    specialists: Vec<Specialist>,
    max_tokens: u64,
    counter: AtomicU64,
}

impl SubagentTool {
    /// Build the delegation tool over an adapter, the model every specialist
    /// uses, the shared finding store, and the specialist roster.
    pub fn new(
        adapter: Arc<dyn LlmAdapter>,
        model: impl Into<String>,
        findings: FindingStore,
        specialists: Vec<Specialist>,
        max_tokens: u64,
    ) -> Self {
        SubagentTool {
            adapter,
            model: model.into(),
            findings,
            specialists,
            max_tokens,
            counter: AtomicU64::new(0),
        }
    }

    fn specialist(&self, name: &str) -> Option<&Specialist> {
        self.specialists.iter().find(|s| s.name == name)
    }

    fn names(&self) -> String {
        self.specialists.iter().map(|s| s.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

#[async_trait]
impl Tool for SubagentTool {
    fn name(&self) -> &str {
        "delegate"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "delegate".into(),
            description: format!(
                "Delegate one kill-chain phase to a specialist subagent, which runs its own \
isolated turn with a restricted toolset and returns a summary. Specialists: {}. Give a specific, \
self-contained task — the specialist does not see this conversation.",
                self.names()
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "specialist": {
                        "type": "string",
                        "enum": self.specialists.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                        "description": "Which specialist to run."
                    },
                    "task": { "type": "string", "description": "The self-contained task for the specialist." }
                },
                "required": ["specialist", "task"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let name = arguments
            .get("specialist")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_args("missing `specialist`"))?
            .to_string();
        let task = arguments
            .get("task")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ToolError::invalid_args("missing non-empty `task`"))?
            .to_string();
        let specialist = self
            .specialist(&name)
            .ok_or_else(|| ToolError::invalid_args(format!("unknown specialist `{name}`; available: {}", self.names())))?
            .clone();

        // A fresh registry and session give the specialist an isolated context;
        // the shared finding store threads findings back to the engagement.
        let mut registry = ToolRegistry::new();
        register_named(&mut registry, &specialist.tools.iter().map(String::as_str).collect::<Vec<_>>(), &self.findings);

        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut session = Session::new(format!("sub-{name}-{n}"));
        let mut config = AgentConfig::new("openrouter", &self.model).with_system(&specialist.system).with_max_tokens(self.max_tokens);
        config.max_steps = specialist.max_steps;
        let prompt = Message::human(format!("task-{name}-{n}"), vec![ContentBlock::text(task)]);

        let findings_before = self.findings.len();
        // Print the specialist's activity indented, so the orchestrator run does
        // not go silent during a long delegation. Cancellation propagates via
        // the shared token.
        let label = name.clone();
        let outcome = run_turn_observed(
            &mut session,
            self.adapter.as_ref(),
            &registry,
            &config,
            prompt,
            ctx.token().clone(),
            &mut |event| match event {
                Progress::Step(s) => eprintln!("      · {label} step {s}"),
                Progress::Token(_) => {}
                Progress::ToolCall { name, args } => {
                    let preview: String = args.chars().take(120).collect();
                    eprintln!("      · {label} → {name} {preview}");
                }
                Progress::ToolResult { name, is_error, .. } => {
                    eprintln!("      · {label}   {} {name}", if is_error { "[error]" } else { "[ok]" });
                }
            },
        )
        .await;

        let findings_added = self.findings.len().saturating_sub(findings_before);
        let stop = match &outcome.stop_reason {
            StopReason::Completed => "completed".to_string(),
            StopReason::MaxSteps => "max-steps".to_string(),
            StopReason::Error(f) => format!("error: [{}] {}", f.code, f.message),
        };

        Ok(json!({
            "specialist": name,
            "summary": outcome.final_text,
            "steps": outcome.steps,
            "findings_added": findings_added,
            "stop": stop,
        }))
    }

    fn render(&self, arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let specialist = arguments.get("specialist").and_then(Value::as_str).unwrap_or("?");
        let summary = value.get("summary").and_then(Value::as_str).unwrap_or("");
        let steps = value.get("steps").and_then(Value::as_u64).unwrap_or(0);
        let added = value.get("findings_added").and_then(Value::as_u64).unwrap_or(0);
        let stop = value.get("stop").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!(
            "[{specialist}] {stop}, {steps} step(s), {added} finding(s) recorded.\n{summary}"
        ))]
    }
}

/// Build the orchestrator's registry: the `delegate` tool over the default
/// specialists plus a shared `add_finding`, and return the engagement's finding
/// store. Every specialist and the orchestrator record into the same store.
pub fn build_engagement(
    adapter: Arc<dyn LlmAdapter>,
    model: impl Into<String>,
    max_tokens: u64,
) -> (ToolRegistry, FindingStore) {
    let findings = FindingStore::new();
    let specialists = default_specialists();
    let mut registry = ToolRegistry::new();
    registry.register(Arc::new(SubagentTool::new(
        adapter,
        model,
        findings.clone(),
        specialists,
        max_tokens,
    )));
    register_named(&mut registry, &["add_finding"], &findings);
    (registry, findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::{ChunkStream, GenerateOptions};
    use futures_util_stub::stream_of;

    /// A stub adapter that replies with fixed chunks, so a delegation runs
    /// without a network.
    struct StubAdapter;
    impl LlmAdapter for StubAdapter {
        fn stream(&self, _options: GenerateOptions) -> ChunkStream {
            stream_of(vec![
                decibel_llm::StreamChunk::TextDelta { index: 1, text: "done recon".into() },
                decibel_llm::StreamChunk::Finish { reason: decibel_llm::FinishReason::Stop },
            ])
        }
    }

    #[test]
    fn specialists_have_expected_toolsets() {
        let s = default_specialists();
        // The full kill-chain roster (17 standard specialists), not the old trio.
        assert_eq!(s.len(), 17);
        // Kill-chain sorted → recon is first, scoped to its scanners.
        assert_eq!(s[0].name, "recon");
        assert!(s[0].tools.contains(&"port_scan".to_string()));
        // Each specialist carries its real persona (compiled in), not an empty prompt.
        assert!(s.iter().all(|sp| !sp.system.is_empty()), "every specialist has a persona");
        // web_operator gets the native web/auth analyzers.
        let web = s.iter().find(|sp| sp.name == "web_operator").expect("web_operator present");
        assert!(web.tools.contains(&"jwt_parse".to_string()));
        // ics_operator is RoE-gated → starts read-only, so NO active shell.
        let ics = s.iter().find(|sp| sp.name == "ics_operator").expect("ics_operator present");
        assert!(!ics.tools.contains(&"shell".to_string()), "ics_operator is gated read-only: {:?}", ics.tools);
        assert!(ics.tools.contains(&"kg_query".to_string()));
    }

    #[test]
    fn build_engagement_exposes_delegate_tool() {
        let (registry, _findings) = build_engagement(Arc::new(StubAdapter), "m", 500);
        let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
        assert!(names.contains(&"delegate".to_string()));
        assert!(names.contains(&"add_finding".to_string()));
    }

    #[tokio::test]
    async fn delegate_runs_a_specialist_turn() {
        let findings = FindingStore::new();
        let tool = SubagentTool::new(
            Arc::new(StubAdapter),
            "m",
            findings.clone(),
            default_specialists(),
            500,
        );
        let value = tool
            .execute(json!({ "specialist": "recon", "task": "scan it" }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["specialist"], "recon");
        assert_eq!(value["summary"], "done recon");
        assert_eq!(value["stop"], "completed");
    }

    #[tokio::test]
    async fn unknown_specialist_is_rejected() {
        let tool = SubagentTool::new(Arc::new(StubAdapter), "m", FindingStore::new(), default_specialists(), 500);
        let err = tool.execute(json!({ "specialist": "ghost", "task": "x" }), &ExecCtx::new()).await.unwrap_err();
        assert_eq!(err.code(), "INVALID_ARGS");
    }
}

/// Tiny in-crate stream helper for tests (avoids a dev-dep just for one stream).
#[cfg(test)]
mod futures_util_stub {
    use decibel_llm::{ChunkStream, StreamChunk};

    /// A `ChunkStream` yielding the given chunks in order.
    pub fn stream_of(chunks: Vec<StreamChunk>) -> ChunkStream {
        Box::pin(StubStream { chunks: chunks.into_iter() })
    }

    struct StubStream {
        chunks: std::vec::IntoIter<StreamChunk>,
    }

    impl futures_core::Stream for StubStream {
        type Item = StreamChunk;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<StreamChunk>> {
            std::task::Poll::Ready(self.chunks.next())
        }
    }
}
