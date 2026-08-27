//! Stream one real completion from a DeepSeek model — the first time the harness
//! talks to a model.
//!
//! Needs an API key (from https://platform.deepseek.com/api_keys). Put it in a
//! workspace-root `.env` as `DEEPSEEK_API_KEY=sk-...` (auto-loaded), or export it
//! in the shell, then:
//!
//!     cargo run -p decibel-openrouter --example chat_demo
//!     cargo run -p decibel-openrouter --example chat_demo "what is sqlmap?" deepseek-v4-pro
//!
//! With no explicit model, it tries the DeepSeek models in order of context size
//! until one answers.

use std::io::Write;

use decibel_llm::{BlockAssembler, ContentBlock, FinishReason, GenerateOptions, Message, StreamChunk};
use decibel_openrouter::{fetch_default_models, OpenRouterAdapter};
use futures_util::StreamExt;

#[tokio::main]
async fn main() {
    // Load a workspace-root .env if present (dev convenience for the examples).
    let _ = dotenvy::dotenv();

    let api_key = match std::env::var("DEEPSEEK_API_KEY") {
        Ok(key) if !key.trim().is_empty() => key,
        _ => {
            eprintln!("Set DEEPSEEK_API_KEY first (from https://platform.deepseek.com/api_keys).");
            eprintln!("  put it in a workspace-root .env, or:  $env:DEEPSEEK_API_KEY = \"sk-...\"");
            std::process::exit(1);
        }
    };

    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "In one sentence, what does the nmap tool do?".to_string());

    let adapter = OpenRouterAdapter::new(Some(api_key));

    // Explicit model, or the free tool-capable catalog in descending context order.
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
        eprintln!("No DeepSeek model available right now; pass a model id explicitly.");
        std::process::exit(1);
    }

    eprintln!("prompt: {prompt}\n");
    for (i, model) in candidates.iter().enumerate() {
        eprintln!("→ trying model: {model}");
        match stream_once(&adapter, model, &prompt).await {
            Ok(()) => return,
            Err(failure) => {
                let gated = failure.status == Some(403)
                    || failure.message.contains("agentic harnesses")
                    || failure.message.contains("only available");
                if gated && i + 1 < candidates.len() {
                    eprintln!("  (gated / unavailable — trying the next model)\n");
                    continue;
                }
                eprintln!("  failed: [{}] {}", failure.code, failure.message);
                std::process::exit(1);
            }
        }
    }
}

/// Stream one completion and print its text live. Returns `Err(failure)` if the
/// stream ended in an error before producing any text.
async fn stream_once(
    adapter: &OpenRouterAdapter,
    model: &str,
    prompt: &str,
) -> Result<(), decibel_llm::LlmFailure> {
    let options = GenerateOptions {
        provider: "deepseek".into(),
        model: model.to_string(),
        messages: vec![Message::human("u1", vec![ContentBlock::text(prompt)])],
        system: Some("You are Decibel, a concise offensive-security assistant.".into()),
        tools: Vec::new(),
        temperature: Some(0.3),
        max_tokens: Some(400),
    };

    let stream = adapter.stream(options);
    futures_util::pin_mut!(stream);

    let mut assembler = BlockAssembler::new();
    let mut printed_any = false;
    let mut stdout = std::io::stdout();
    let mut result = Ok(());

    while let Some(chunk) = stream.next().await {
        match &chunk {
            StreamChunk::TextDelta { text, .. } => {
                if !printed_any {
                    eprintln!("  --- streaming ---");
                    printed_any = true;
                }
                print!("{text}");
                let _ = stdout.flush();
            }
            StreamChunk::Usage { usage } => {
                eprintln!("\n  usage: {usage:?}");
            }
            StreamChunk::Finish { reason } => {
                if let FinishReason::Error { failure } | FinishReason::Aborted { failure } = reason {
                    // A failure with no text yet is a candidate to skip.
                    if !printed_any {
                        result = Err(failure.clone());
                    } else {
                        eprintln!("\n  finished with error: [{}] {}", failure.code, failure.message);
                    }
                } else {
                    eprintln!("  finish: {reason:?}");
                }
            }
            _ => {}
        }
        assembler.push(chunk);
    }

    if result.is_ok() {
        let _ = assembler.into_message("a1", "deepseek", model);
        println!();
    }
    result
}
