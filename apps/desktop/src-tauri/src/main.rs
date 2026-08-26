// Prevent an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Decibel desktop shell (Tauri v2). It bridges the SolidJS frontend to the
//! Rust harness: a live model catalog, an API key stored in the OS keyring, and
//! a streaming agent run driven by the offensive toolkit.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tauri::ipc::Channel;

use decibel_agent::{run_turn_observed, AgentConfig, Progress, StopReason, TurnSignal};
use decibel_core::Session;
use decibel_llm::{ContentBlock, Message};
use decibel_offsec::register_all;
use decibel_openrouter::OpenRouterAdapter;
use decibel_tools::ToolRegistry;

/// Keyring service/account the OpenRouter key is stored under.
const KEY_SERVICE: &str = "decibel-harness";
const KEY_ACCOUNT: &str = "openrouter";

/// The default offensive-security persona for a single-agent run.
const SYSTEM: &str = "You are Decibel, an autonomous offensive-security (red-team) agent operating \
with the user's authorization on systems they own or may test. Work a recon → analysis → \
exploitation → reporting loop. Use the shell tool to run installed tools (nmap, curl, sqlmap, …), \
the nmap tool for structured scans, the http tool for web requests, and the filesystem/search \
tools to inspect the target. Record confirmed weaknesses with add_finding (include a MITRE ATT&CK \
technique id). Be concise and act; do not ask for permission you already have.";

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// One model as the picker needs it (matches the frontend `ModelInfo`).
#[derive(Serialize, Clone)]
struct ModelDto {
    id: String,
    name: String,
    context_length: u64,
    is_free: bool,
    supports_tools: bool,
    input_modalities: Vec<String>,
}

/// A streamed turn event (matches the frontend `RunEvent` union).
#[derive(Serialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RunEvt {
    Step { n: u64 },
    Token { text: String },
    ToolCall { name: String, args: String },
    ToolResult { name: String, ok: bool },
    Done,
    Error { message: String },
}

/// Resolve the OpenRouter key: OS keyring first, then the `OPENROUTER_API_KEY`
/// environment variable (dev convenience).
fn resolve_key() -> Result<String, String> {
    if let Ok(entry) = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT) {
        if let Ok(pw) = entry.get_password() {
            if !pw.trim().is_empty() {
                return Ok(pw);
            }
        }
    }
    if let Ok(env) = std::env::var("OPENROUTER_API_KEY") {
        if !env.trim().is_empty() {
            return Ok(env);
        }
    }
    Err("No OpenRouter API key set — add it in Settings.".into())
}

/// Fetch the live model catalog (public endpoint; no key required).
#[tauri::command]
async fn list_models() -> Result<Vec<ModelDto>, String> {
    let models = decibel_openrouter::fetch_default_models()
        .await
        .map_err(|e| e.to_string())?;
    Ok(models
        .into_iter()
        .map(|m| ModelDto {
            id: m.id,
            name: m.name,
            context_length: m.context_length,
            is_free: m.is_free,
            supports_tools: m.supports_tools,
            input_modalities: m.input_modalities,
        })
        .collect())
}

/// Whether an OpenRouter key is available (keyring or env).
#[tauri::command]
fn has_api_key() -> bool {
    resolve_key().is_ok()
}

/// Store the OpenRouter key in the OS keyring.
#[tauri::command]
fn save_api_key(key: String) -> Result<(), String> {
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("key is empty".into());
    }
    let entry = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

/// Remove the stored OpenRouter key.
#[tauri::command]
fn delete_api_key() -> Result<(), String> {
    let entry = keyring::Entry::new(KEY_SERVICE, KEY_ACCOUNT).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Run one prompt with the full offensive toolkit, streaming events to the
/// frontend through `on_event`. Errors are delivered as an `error` event.
#[tauri::command]
async fn run_prompt(prompt: String, model: String, on_event: Channel<RunEvt>) -> Result<(), String> {
    let key = match resolve_key() {
        Ok(k) => k,
        Err(e) => {
            let _ = on_event.send(RunEvt::Error { message: e });
            let _ = on_event.send(RunEvt::Done);
            return Ok(());
        }
    };

    let adapter = OpenRouterAdapter::new(Some(key));
    let mut registry = ToolRegistry::new();
    let _findings = register_all(&mut registry);

    let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut session = Session::new(format!("ui-{n}"));
    let config = AgentConfig::new("openrouter", &model).with_system(SYSTEM).with_max_tokens(1200);
    let message = Message::human(format!("u-{n}"), vec![ContentBlock::text(prompt)]);

    let sink = on_event.clone();
    let outcome = run_turn_observed(
        &mut session,
        &adapter,
        &registry,
        &config,
        message,
        TurnSignal::new(),
        &mut |event| {
            let evt = match event {
                Progress::Step(n) => RunEvt::Step { n },
                Progress::Token(t) => RunEvt::Token { text: t.to_string() },
                Progress::ToolCall { name, args } => RunEvt::ToolCall {
                    name: name.to_string(),
                    args: args.to_string(),
                },
                Progress::ToolResult { name, is_error } => RunEvt::ToolResult {
                    name: name.to_string(),
                    ok: !is_error,
                },
            };
            let _ = sink.send(evt);
        },
    )
    .await;

    match outcome.stop_reason {
        StopReason::Error(failure) => {
            let _ = on_event.send(RunEvt::Error {
                message: format!("[{}] {}", failure.code, failure.message),
            });
        }
        _ => {}
    }
    let _ = on_event.send(RunEvt::Done);
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_models,
            has_api_key,
            save_api_key,
            delete_api_key,
            run_prompt
        ])
        .run(tauri::generate_context!())
        .expect("error while running Decibel");
}
