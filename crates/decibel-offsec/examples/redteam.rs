//! The live red-team agent: the full offensive toolkit wired into the agent
//! loop, driven by a free OpenRouter model.
//!
//! Needs an API key (DEEPSEEK_API_KEY in a workspace-root .env or the shell):
//!
//!     cargo run -p decibel-offsec --example redteam "recon localhost: what ports are open?"
//!     cargo run -p decibel-offsec --example redteam "read ./Cargo.toml and summarize it" deepseek-v4-pro
//!
//! Authorized use only: run it against systems you own or may test.

use std::io::Write;

use decibel_agent::{run_turn_observed, AgentConfig, Progress, StopReason, TurnSignal};
use decibel_core::Session;
use decibel_llm::{ContentBlock, Message, MessageSource};
use decibel_openrouter::{fetch_default_models, OpenRouterAdapter};
use decibel_tools::ToolRegistry;
use decibel_offsec::register_all;

const SYSTEM: &str = "You are Decibel, an autonomous offensive-security (red-team) agent operating \
with the user's authorization on systems they own or may test. Work in a recon → analysis → \
exploitation → reporting loop. Use the shell tool to run installed tools (nmap, curl, etc.), the \
http tool for web requests, the filesystem and search tools to inspect the target, and record every \
confirmed weakness with add_finding (include a MITRE ATT&CK technique id when it maps to one). Be \
concise and act; do not ask for permission you already have.";

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();

    let api_key = match std::env::var("DEEPSEEK_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("Set DEEPSEEK_API_KEY (from https://platform.deepseek.com/api_keys), in a .env or the shell.");
            std::process::exit(1);
        }
    };

    let prompt_text = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Recon the local machine: who am I, what OS, and what is listening?".to_string());

    let adapter = OpenRouterAdapter::new(Some(api_key));

    // An explicit second arg pins the model, else cycle free tool-capable ones.
    let candidates: Vec<String> = match std::env::args().nth(2) {
        Some(m) => vec![m],
        None => {
            let mut models: Vec<_> = fetch_default_models()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|m| m.supports_tools)
                .collect();
            models.sort_by(|a, b| b.context_length.cmp(&a.context_length));
            models.into_iter().map(|m| m.id).collect()
        }
    };
    if candidates.is_empty() {
        eprintln!("No DeepSeek model available; pass a model id explicitly.");
        std::process::exit(1);
    }

    eprintln!("Prompt: {prompt_text}\n");
    for (i, model) in candidates.iter().enumerate() {
        eprintln!("──────── model: {model} ────────");

        let mut registry = ToolRegistry::new();
        let findings = register_all(&mut registry);

        let mut session = Session::new(format!("redteam-{i}"));
        let config = AgentConfig::new("deepseek", model).with_system(SYSTEM).with_max_tokens(1200);
        let prompt = Message::human("u1", vec![ContentBlock::text(prompt_text.clone())]);

        // Live progress: tokens, tool calls, and results appear as they happen,
        // so a multi-step recon turn never looks frozen.
        eprintln!("  (streaming — Ctrl+C to stop)\n");
        let outcome = run_turn_observed(
            &mut session,
            &adapter,
            &registry,
            &config,
            prompt,
            TurnSignal::new(),
            &mut |event| match event {
                Progress::Step(n) => println!("\n\n──── step {n} ────"),
                Progress::Token(t) => {
                    print!("{t}");
                    let _ = std::io::stdout().flush();
                }
                Progress::ToolCall { name, args } => println!("\n→ {name} {args}"),
                Progress::ToolResult { name, is_error, .. } => {
                    println!("  {} {name}", if is_error { "[error]" } else { "[ok]" })
                }
            },
        )
        .await;

        if let StopReason::Error(failure) = &outcome.stop_reason {
            // Out of credit affects every DeepSeek model, so cycling is pointless.
            let out_of_credit = failure.status == Some(402)
                || failure.code == "QUOTA_EXCEEDED"
                || failure.message.contains("Insufficient Balance");
            if out_of_credit {
                eprintln!(
                    "\n  DeepSeek: insufficient balance: {}\n  → add credit at https://platform.deepseek.com/top_up.",
                    failure.message
                );
                std::process::exit(1);
            }
            let skippable = matches!(failure.status, Some(429))
                || matches!(failure.code.as_str(), "RATE_LIMIT" | "TIMEOUT" | "PROVIDER_ERROR");
            if skippable && i + 1 < candidates.len() {
                eprintln!("  ([{}] — next model)\n", failure.code);
                continue;
            }
            eprintln!("  model error: [{}] {}", failure.code, failure.message);
            std::process::exit(1);
        }

        print_transcript(&session);
        eprintln!("\n★ stop: {:?} in {} step(s)", outcome.stop_reason, outcome.steps);

        let recorded = findings.snapshot();
        eprintln!("\n=== findings recorded: {} ===", recorded.len());
        for (n, f) in recorded.iter().enumerate() {
            let mitre = f.mitre.as_deref().map(|m| format!(" [{m}]")).unwrap_or_default();
            let target = f.target.as_deref().map(|t| format!(" @ {t}")).unwrap_or_default();
            eprintln!("  #{}: [{}] {}{}{}", n + 1, f.severity, f.title, target, mitre);
        }
        return;
    }

    eprintln!("No DeepSeek model completed the turn; pass a model id or try later.");
    std::process::exit(1);
}

/// Print the derived transcript the way the model built it up.
fn print_transcript(session: &Session) {
    println!("\n=== transcript ({} messages) ===", session.derive_messages().len());
    for msg in session.derive_messages() {
        match &msg.source {
            MessageSource::Human => println!("\n[user] {}", join_text(&msg)),
            MessageSource::Model { .. } => {
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text } if !text.is_empty() => println!("\n[assistant] {text}"),
                        ContentBlock::ToolCall { name, arguments, .. } => {
                            println!("\n[assistant → tool] {name}({arguments})")
                        }
                        _ => {}
                    }
                }
            }
            MessageSource::Tool { .. } => println!("[tool result]\n{}", join_text(&msg)),
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
