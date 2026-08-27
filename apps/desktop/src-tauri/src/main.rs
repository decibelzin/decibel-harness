// Prevent an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Decibel desktop shell (Tauri v2). It bridges the SolidJS frontend to the
//! Rust harness: a live model catalog, an API key stored in the OS keyring, and
//! a streaming agent run driven by the offensive toolkit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::Serialize;
use serde_json::Value;
use tauri::ipc::Channel;
use tauri::{Manager, State};

use decibel_agent::{run_turn_observed, AgentConfig, Progress, StopReason, TurnSignal};
use decibel_core::Session;
use decibel_llm::{ContentBlock, Message};
use decibel_offsec::register_all;
use decibel_openrouter::OpenRouterAdapter;
use decibel_tools::ToolRegistry;

/// Keyring service the provider keys are stored under (account = provider tag).
const KEY_SERVICE: &str = "decibel-harness";

/// Per-provider (keyring account, env-var, API base URL). The DeepSeek API is
/// the default; `openrouter` serves the free DeepSeek models.
fn provider_config(provider: &str) -> (&'static str, &'static str, &'static str) {
    match provider {
        "openrouter" => (
            "openrouter",
            "OPENROUTER_API_KEY",
            decibel_openrouter::OPENROUTER_BASE_URL,
        ),
        _ => ("deepseek", "DEEPSEEK_API_KEY", decibel_openrouter::DEEPSEEK_BASE_URL),
    }
}

/// Human label for a provider, for messages.
fn provider_label(provider: &str) -> &'static str {
    if provider == "openrouter" {
        "OpenRouter"
    } else {
        "DeepSeek"
    }
}

/// The default offensive-security persona for a single-agent run.
const SYSTEM: &str = "You are Decibel, an autonomous offensive-security (red-team) agent operating \
with the user's authorization on systems they own or may test. Work a recon → analysis → \
exploitation → reporting loop. Use the shell tool to run installed tools (nmap, curl, sqlmap, …), \
the nmap tool for structured scans, the http tool for web requests, and the filesystem/search \
tools to inspect the target. Record confirmed weaknesses with add_finding (include a MITRE ATT&CK \
technique id). Be concise and act; do not ask for permission you already have.";

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// Live cancellation tokens for in-flight runs, keyed by the frontend's run id.
/// A run registers its token here so `cancel_run` can stop it; the browser's
/// AbortSignal alone cannot reach the backend.
#[derive(Default)]
struct RunRegistry(Mutex<HashMap<u64, TurnSignal>>);

/// One model as the picker needs it (matches the frontend `ModelInfo`).
#[derive(Serialize, Clone)]
struct ModelDto {
    id: String,
    name: String,
    provider: String,
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
    /// A tool settled, carrying its rendered `output` and canonical `value` so
    /// the UI can render a rich card (terminal, ports table, diff, …).
    ToolResult { name: String, ok: bool, output: String, value: Option<Value> },
    Done,
    Error { message: String },
}

/// Resolve a provider's key: OS keyring first, then its env var (dev convenience).
fn resolve_key(provider: &str) -> Result<String, String> {
    let (account, env, _) = provider_config(provider);
    if let Ok(entry) = keyring::Entry::new(KEY_SERVICE, account) {
        if let Ok(pw) = entry.get_password() {
            if !pw.trim().is_empty() {
                return Ok(pw);
            }
        }
    }
    if let Ok(value) = std::env::var(env) {
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    Err(format!("No {} API key set — add it in Settings.", provider_label(provider)))
}

/// Fetch the model catalog: the paid DeepSeek models plus the free
/// DeepSeek-on-OpenRouter models (the OpenRouter fetch needs no key).
#[tauri::command]
async fn list_models() -> Result<Vec<ModelDto>, String> {
    let models = decibel_openrouter::fetch_full_catalog()
        .await
        .map_err(|e| e.to_string())?;
    Ok(models
        .into_iter()
        .map(|m| ModelDto {
            id: m.id,
            name: m.name,
            provider: m.provider,
            context_length: m.context_length,
            is_free: m.is_free,
            supports_tools: m.supports_tools,
            input_modalities: m.input_modalities,
        })
        .collect())
}

/// Whether a key for `provider` is available (keyring or env).
#[tauri::command]
fn has_api_key(provider: String) -> bool {
    resolve_key(&provider).is_ok()
}

/// Store a provider's key in the OS keyring (account = provider tag).
#[tauri::command]
fn save_api_key(provider: String, key: String) -> Result<(), String> {
    let key = key.trim().to_string();
    if key.is_empty() {
        return Err("key is empty".into());
    }
    let (account, _, _) = provider_config(&provider);
    let entry = keyring::Entry::new(KEY_SERVICE, account).map_err(|e| e.to_string())?;
    entry.set_password(&key).map_err(|e| e.to_string())
}

/// Remove a provider's stored key.
#[tauri::command]
fn delete_api_key(provider: String) -> Result<(), String> {
    let (account, _, _) = provider_config(&provider);
    let entry = keyring::Entry::new(KEY_SERVICE, account).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Cancel the in-flight run with `run_id`, if it is still live. Called from the
/// frontend when the user hits Stop or starts a new session.
#[tauri::command]
fn cancel_run(run_id: u64, runs: State<'_, RunRegistry>) {
    if let Ok(map) = runs.0.lock() {
        if let Some(token) = map.get(&run_id) {
            token.cancel();
        }
    }
}

/// Run one prompt with the full offensive toolkit against the chosen model,
/// routed to `provider`'s endpoint + key (DeepSeek API, or OpenRouter for the
/// free DeepSeek models). Streams events through `on_event`; a terminal error is
/// delivered as an `error` event. The run registers a cancellation token under
/// `run_id` so `cancel_run` can stop it cooperatively.
#[tauri::command]
async fn run_prompt(
    prompt: String,
    model: String,
    provider: String,
    run_id: u64,
    on_event: Channel<RunEvt>,
    runs: State<'_, RunRegistry>,
) -> Result<(), String> {
    let key = match resolve_key(&provider) {
        Ok(k) => k,
        Err(e) => {
            let _ = on_event.send(RunEvt::Error { message: e });
            let _ = on_event.send(RunEvt::Done);
            return Ok(());
        }
    };

    let (_, _, base_url) = provider_config(&provider);
    let adapter = OpenRouterAdapter::new(Some(key)).with_base_url(base_url);

    // Register this run's cancellation token so cancel_run can reach it.
    let cancel = TurnSignal::new();
    if let Ok(mut map) = runs.0.lock() {
        map.insert(run_id, cancel.clone());
    }

    let mut registry = ToolRegistry::new();
    let _findings = register_all(&mut registry);
    let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut session = Session::new(format!("ui-{n}"));
    let config = AgentConfig::new(&provider, &model).with_system(SYSTEM).with_max_tokens(1200);
    let message = Message::human(format!("u-{n}"), vec![ContentBlock::text(prompt)]);

    let sink = on_event.clone();
    let outcome = run_turn_observed(
        &mut session,
        &adapter,
        &registry,
        &config,
        message,
        cancel.clone(),
        &mut |event| {
            let evt = match event {
                Progress::Step(n) => RunEvt::Step { n },
                Progress::Token(t) => RunEvt::Token { text: t.to_string() },
                Progress::ToolCall { name, args } => RunEvt::ToolCall {
                    name: name.to_string(),
                    args: args.to_string(),
                },
                Progress::ToolResult { name, is_error, output, value } => RunEvt::ToolResult {
                    name: name.to_string(),
                    ok: !is_error,
                    output: output.to_string(),
                    value: value.cloned(),
                },
            };
            let _ = sink.send(evt);
        },
    )
    .await;

    if let Ok(mut map) = runs.0.lock() {
        map.remove(&run_id);
    }

    // A user Stop surfaces as an error mid-stream; don't report that as a failure.
    if let StopReason::Error(failure) = outcome.stop_reason {
        if !cancel.is_cancelled() {
            let daily_capped = failure.message.contains("per-day")
                || failure.message.contains("free-models-per-day");
            let out_of_credit = failure.status == Some(402)
                || failure.code == "QUOTA_EXCEEDED"
                || failure.message.contains("Insufficient Balance");
            let message = if provider == "openrouter" && daily_capped {
                format!(
                    "OpenRouter free daily quota exhausted: {}. Wait for the ~00:00 UTC reset, or \
                     add ~$10 credit at openrouter.ai/credits, or pick a paid DeepSeek model.",
                    failure.message
                )
            } else if provider != "openrouter" && out_of_credit {
                format!(
                    "DeepSeek API: insufficient balance — add credit at platform.deepseek.com/top_up. ({})",
                    failure.message
                )
            } else {
                format!("[{}] {}", failure.code, failure.message)
            };
            let _ = on_event.send(RunEvt::Error { message });
        }
    }
    let _ = on_event.send(RunEvt::Done);
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(RunRegistry::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_models,
            has_api_key,
            save_api_key,
            delete_api_key,
            run_prompt,
            cancel_run
        ])
        .run(tauri::generate_context!())
        .expect("error while running Decibel");
}
