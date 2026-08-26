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

/// Keyring service/account the OpenRouter key is stored under.
const KEY_SERVICE: &str = "decibel-harness";
const KEY_ACCOUNT: &str = "openrouter";

/// How many extra free tool-capable models to line up as fallbacks behind the
/// chosen one, so a gated/overloaded model never dead-ends the run.
const MAX_FALLBACKS: usize = 6;

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
    /// The chosen model failed with a skippable error; the run switched to `to`.
    ModelFallback { to: String, reason: String },
    Done,
    Error { message: String },
}

/// Model id prefixes gated to registered OpenRouter apps (they reject a generic
/// client with an AUTH error), so they make poor fallbacks. Mirrors the frontend.
fn is_gated(id: &str) -> bool {
    id.starts_with("thinkingmachines/")
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

/// Run one prompt with the full offensive toolkit, streaming events to the
/// frontend through `on_event`. When `fallback` is set, a skippable model error
/// (gated / rate-limited / overloaded / timed out) transparently retries with
/// the next free tool-capable model from the live catalog, so the user never
/// sees those errors. A terminal error is delivered as an `error` event. The run
/// registers a cancellation token under `run_id` so `cancel_run` can stop it.
#[tauri::command]
async fn run_prompt(
    prompt: String,
    model: String,
    run_id: u64,
    fallback: bool,
    on_event: Channel<RunEvt>,
    runs: State<'_, RunRegistry>,
) -> Result<(), String> {
    let key = match resolve_key() {
        Ok(k) => k,
        Err(e) => {
            let _ = on_event.send(RunEvt::Error { message: e });
            let _ = on_event.send(RunEvt::Done);
            return Ok(());
        }
    };

    let adapter = OpenRouterAdapter::new(Some(key));

    // Register this run's cancellation token so cancel_run can reach it. It is
    // shared across every fallback attempt so one Stop cancels the whole run.
    let cancel = TurnSignal::new();
    if let Ok(mut map) = runs.0.lock() {
        map.insert(run_id, cancel.clone());
    }

    // The chosen model first; other candidates are appended lazily on the first
    // skippable failure (so a working first model never triggers a catalog fetch).
    let mut candidates = vec![model.clone()];
    let mut expanded = false;
    let mut idx = 0usize;

    loop {
        if cancel.is_cancelled() {
            break;
        }
        let current = candidates[idx].clone();

        // Each attempt gets a fresh registry + session, so a retried model never
        // inherits half a transcript from the model that just failed.
        let mut registry = ToolRegistry::new();
        let _findings = register_all(&mut registry);
        let n = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
        let mut session = Session::new(format!("ui-{n}"));
        let config = AgentConfig::new("openrouter", &current).with_system(SYSTEM).with_max_tokens(1200);
        let message = Message::human(format!("u-{n}"), vec![ContentBlock::text(prompt.clone())]);

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

        match outcome.stop_reason {
            StopReason::Completed | StopReason::MaxSteps => break,
            StopReason::Error(failure) => {
                // A user Stop surfaces as an error mid-stream; don't report it.
                if cancel.is_cancelled() {
                    break;
                }
                // The genuine account-wide free daily cap (a 429 whose message
                // names the per-day limit) is shared by every free model, so
                // cycling is pointless — surface the actionable message and stop.
                // A bare 402 (QUOTA_EXCEEDED) means "out of paid credit" on a
                // paid model — NOT the free cap — so it must fall through to the
                // skippable branch below and let the free fallbacks be tried.
                let daily_capped = failure.message.contains("per-day")
                    || failure.message.contains("free-models-per-day");
                if daily_capped {
                    let _ = on_event.send(RunEvt::Error {
                        message: format!(
                            "Free daily quota exhausted: {}. Wait for the ~00:00 UTC reset, or add \
                             ~$10 credit at openrouter.ai/credits (1000 free requests/day; :free \
                             models still cost $0 each).",
                            failure.message
                        ),
                    });
                    break;
                }
                let skippable = fallback
                    && (matches!(failure.status, Some(402) | Some(403) | Some(429))
                        || matches!(
                            failure.code.as_str(),
                            "AUTH" | "RATE_LIMIT" | "TIMEOUT" | "PROVIDER_ERROR" | "QUOTA_EXCEEDED"
                        )
                        || failure.message.contains("agentic harnesses"));
                if skippable {
                    if !expanded {
                        expanded = true;
                        candidates.extend(fallback_models(&candidates).await);
                    }
                    if idx + 1 < candidates.len() {
                        let next = candidates[idx + 1].clone();
                        let _ = on_event.send(RunEvt::ModelFallback {
                            to: next,
                            reason: failure.code.clone(),
                        });
                        idx += 1;
                        continue;
                    }
                }
                let _ = on_event.send(RunEvt::Error {
                    message: format!("[{}] {}", failure.code, failure.message),
                });
                break;
            }
        }
    }

    if let Ok(mut map) = runs.0.lock() {
        map.remove(&run_id);
    }
    let _ = on_event.send(RunEvt::Done);
    Ok(())
}

/// Free, tool-capable, non-gated model ids from the live catalog (largest
/// context first), excluding any already in `have`, capped at [`MAX_FALLBACKS`].
/// A catalog fetch failure yields no fallbacks (the original error then stands).
async fn fallback_models(have: &[String]) -> Vec<String> {
    let Ok(models) = decibel_openrouter::fetch_default_models().await else {
        return Vec::new();
    };
    let mut usable: Vec<_> = models
        .into_iter()
        .filter(|m| m.is_free && m.supports_tools && !is_gated(&m.id))
        .collect();
    usable.sort_by(|a, b| b.context_length.cmp(&a.context_length));
    usable
        .into_iter()
        .map(|m| m.id)
        .filter(|id| !have.contains(id))
        .take(MAX_FALLBACKS)
        .collect()
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
