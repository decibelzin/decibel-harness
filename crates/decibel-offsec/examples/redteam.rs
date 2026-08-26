//! The live red-team agent: the full offensive toolkit wired into the agent
//! loop, driven by a free OpenRouter model.
//!
//! Needs an API key (OPENROUTER_API_KEY in a workspace-root .env or the shell):
//!
//!     cargo run -p decibel-offsec --example redteam "recon localhost: what ports are open?"
//!     cargo run -p decibel-offsec --example redteam "read ./Cargo.toml and summarize it" z-ai/glm-5.2:free
//!
//! Authorized use only: run it against systems you own or may test.

use decibel_agent::{run_turn, AgentConfig, StopReason, TurnSignal};
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

    let api_key = match std::env::var("OPENROUTER_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("Set OPENROUTER_API_KEY (free at https://openrouter.ai/keys), in a .env or the shell.");
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

    eprintln!("Prompt: {prompt_text}\n");
    for (i, model) in candidates.iter().enumerate() {
        eprintln!("──────── model: {model} ────────");

        let mut registry = ToolRegistry::new();
        let findings = register_all(&mut registry);

        let mut session = Session::new(format!("redteam-{i}"));
        let config = AgentConfig::new("openrouter", model).with_system(SYSTEM).with_max_tokens(1200);
        let prompt = Message::human("u1", vec![ContentBlock::text(prompt_text.clone())]);

        let outcome = run_turn(&mut session, &adapter, &registry, &config, prompt, TurnSignal::new()).await;

        if let StopReason::Error(failure) = &outcome.stop_reason {
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

    eprintln!("No free model completed the turn; pass a model id or try later.");
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
