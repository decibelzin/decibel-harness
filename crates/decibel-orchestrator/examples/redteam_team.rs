//! The multi-agent red-team: an orchestrator delegates kill-chain phases to
//! recon / exploit / report specialists, each with its own isolated context and
//! toolset, all recording into one shared engagement report.
//!
//! Needs an API key (OPENROUTER_API_KEY in a workspace-root .env or the shell):
//!
//!     cargo run -p decibel-orchestrator --example redteam_team "engage 127.0.0.1"
//!     cargo run -p decibel-orchestrator --example redteam_team "engage 127.0.0.1" z-ai/glm-5.2:free
//!
//! Authorized use only. This makes MANY model requests (orchestrator + each
//! specialist's turn), so it uses free-tier quota quickly.

use std::sync::Arc;

use decibel_agent::{run_turn_observed, AgentConfig, Progress, StopReason};
use decibel_core::Session;
use decibel_llm::{ContentBlock, LlmAdapter, Message, MessageSource};
use decibel_openrouter::{fetch_default_models, OpenRouterAdapter};
use decibel_orchestrator::{build_engagement, orchestrator_system};

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let api_key = match std::env::var("OPENROUTER_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("Set OPENROUTER_API_KEY (free at https://openrouter.ai/keys), in a .env or the shell.");
            std::process::exit(1);
        }
    };

    let objective = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Run a red-team engagement against 127.0.0.1 and report findings.".to_string());

    let adapter: Arc<dyn LlmAdapter> = Arc::new(OpenRouterAdapter::new(Some(api_key)));

    let candidates: Vec<String> = match std::env::args().nth(2) {
        Some(m) => vec![m],
        None => {
            eprintln!("Fetching free tool-capable models…");
            let mut models: Vec<_> = fetch_default_models()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|m| m.is_free && m.supports_tools)
                .collect();
            models.sort_by(|a, b| b.context_length.cmp(&a.context_length));
            models.into_iter().map(|m| m.id).collect()
        }
    };
    if candidates.is_empty() {
        eprintln!("No free tool-capable model available; pass a model id explicitly.");
        std::process::exit(1);
    }

    eprintln!("Objective: {objective}\n");
    for (i, model) in candidates.iter().enumerate() {
        eprintln!("──────── orchestrator model: {model} ────────");
        eprintln!("  (streaming — Ctrl+C to stop; specialists run indented)\n");

        // The engagement shares one finding store across the orchestrator and
        // every specialist it delegates to.
        let (registry, findings) = build_engagement(adapter.clone(), model.clone(), 1200);

        let mut session = Session::new(format!("engagement-{i}"));
        let config = AgentConfig::new("openrouter", model).with_system(orchestrator_system()).with_max_tokens(1000);
        let prompt = Message::human("obj", vec![ContentBlock::text(objective.clone())]);

        let outcome = run_turn_observed(
            &mut session,
            adapter.as_ref(),
            &registry,
            &config,
            prompt,
            decibel_agent::TurnSignal::new(),
            &mut |event| match event {
                Progress::Step(n) => println!("\n\n════ orchestrator step {n} ════"),
                Progress::Token(t) => {
                    print!("{t}");
                    use std::io::Write;
                    let _ = std::io::stdout().flush();
                }
                Progress::ToolCall { name, args } => {
                    let preview: String = args.chars().take(160).collect();
                    println!("\n▶ {name} {preview}");
                }
                Progress::ToolResult { name, is_error, .. } => {
                    println!("◀ {} {name}", if is_error { "[error]" } else { "[ok]" });
                }
            },
        )
        .await;

        if let StopReason::Error(failure) = &outcome.stop_reason {
            let daily_capped = failure.message.contains("per-day") || failure.message.contains("free-models-per-day");
            if daily_capped {
                eprintln!(
                    "\n  Free daily quota exhausted: {}\n  → wait for the daily reset, or add ~$10 of credit at https://openrouter.ai/credits.",
                    failure.message
                );
                std::process::exit(1);
            }
            let skippable = matches!(failure.status, Some(403) | Some(429))
                || matches!(failure.code.as_str(), "RATE_LIMIT" | "TIMEOUT" | "PROVIDER_ERROR")
                || failure.message.contains("agentic harnesses");
            if skippable && i + 1 < candidates.len() {
                eprintln!("  ([{}] — next model)\n", failure.code);
                continue;
            }
            eprintln!("  model error: [{}] {}", failure.code, failure.message);
            std::process::exit(1);
        }

        print_transcript(&session);
        eprintln!("\n★ orchestrator: {:?} in {} step(s)", outcome.stop_reason, outcome.steps);

        let recorded = findings.snapshot();
        eprintln!("\n=== ENGAGEMENT REPORT: {} finding(s) ===", recorded.len());
        for (n, f) in recorded.iter().enumerate() {
            let mitre = f.mitre.as_deref().map(|m| format!(" [{m}]")).unwrap_or_default();
            let target = f.target.as_deref().map(|t| format!(" @ {t}")).unwrap_or_default();
            eprintln!("  #{}: [{}] {}{}{}", n + 1, f.severity, f.title, target, mitre);
            eprintln!("      {}", f.description);
        }
        return;
    }

    eprintln!("No free model completed the engagement; pass a model id or try later.");
    std::process::exit(1);
}

/// Print only the orchestrator's own transcript (its delegations and summary).
fn print_transcript(session: &Session) {
    println!("\n=== orchestrator transcript ===");
    for msg in session.derive_messages() {
        match &msg.source {
            MessageSource::Human => println!("\n[objective] {}", join_text(&msg)),
            MessageSource::Model { .. } => {
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text } if !text.is_empty() => println!("\n[orchestrator] {text}"),
                        ContentBlock::ToolCall { name, arguments, .. } => {
                            println!("\n[delegate] {name} {arguments}")
                        }
                        _ => {}
                    }
                }
            }
            MessageSource::Tool { .. } => println!("[result]\n{}", join_text(&msg)),
            MessageSource::Plugin { .. } => println!("[injected] {}", join_text(&msg)),
        }
    }
}

fn join_text(msg: &Message) -> String {
    msg.content
        .iter()
        .map(|b| match b {
            ContentBlock::Text { text } => text.clone(),
            ContentBlock::ToolResult { content, .. } => {
                content.iter().filter_map(ContentBlock::as_text).collect::<Vec<_>>().join("\n")
            }
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join("")
}
