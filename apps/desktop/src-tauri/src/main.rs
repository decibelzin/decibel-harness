// Prevent an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Decibel desktop shell (Tauri v2). It bridges the SolidJS frontend to the
//! Rust harness: a live model catalog, an API key stored in the OS keyring, and
//! a streaming agent run driven by the offensive toolkit.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use decibel_agent::{run_turn, run_turn_observed, AgentConfig, Progress, StopReason, TurnSignal};
use decibel_core::{persist, EventKind, Session, SurfaceIntent};
use decibel_llm::{ContentBlock, Message, MessageSource};
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

/// System prompt for a `/compact` summarization turn (no tools).
const COMPACT_SYSTEM: &str = "You are compacting a red-team engagement transcript. Produce a dense, \
factual summary that a fresh agent can continue from with no other context.";
/// The user instruction that drives a `/compact` turn.
const COMPACT_PROMPT: &str = "Summarize the engagement so far as a handoff: the target(s), what was \
enumerated/attempted, confirmed findings (with severity and any MITRE ids), credentials or artifacts \
obtained, and the concrete next steps. Preserve every fact needed to continue. Be concise; omit chatter.";

static SESSION_SEQ: AtomicU64 = AtomicU64::new(0);

/// Next unique message id (`u-1`, `u-2`, …), shared across turns and sessions.
fn next_msg_id(prefix: &str) -> String {
    format!("{prefix}-{}", SESSION_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Live cancellation tokens for in-flight runs, keyed by the frontend's run id.
/// A run registers its token here so `cancel_run` can stop it; the browser's
/// AbortSignal alone cannot reach the backend.
#[derive(Default)]
struct RunRegistry(Mutex<HashMap<u64, TurnSignal>>);

/// The durable conversation sessions, keyed by the frontend's session id, so the
/// model sees prior turns (multi-turn memory). Each session sits behind its own
/// async mutex, held for a whole turn/compaction, so two operations on the same
/// conversation serialize instead of forking a blank session and clobbering each
/// other on write-back.
#[derive(Default)]
struct Sessions(Mutex<HashMap<String, Arc<tokio::sync::Mutex<Session>>>>);

/// The lock handle for a conversation's session (created empty on first use).
/// Cloned out under the (brief) map lock; the caller then awaits the session
/// lock for the duration of its turn.
fn session_handle(sessions: &Sessions, session_id: &str) -> Arc<tokio::sync::Mutex<Session>> {
    let mut map = sessions.0.lock().unwrap_or_else(|e| e.into_inner());
    map.entry(session_id.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(Session::new(session_id.to_string()))))
        .clone()
}

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
    app: AppHandle,
    prompt: String,
    model: String,
    provider: String,
    workspace: Option<String>,
    session_id: String,
    run_id: u64,
    on_event: Channel<RunEvt>,
    runs: State<'_, RunRegistry>,
    sessions: State<'_, Sessions>,
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
    // Lock this conversation's session for the whole turn so the model sees prior
    // turns and a concurrent run/compact on the same conversation serializes
    // behind us instead of forking a blank session.
    let handle = session_handle(&sessions, &session_id);
    let mut session = handle.lock().await;
    let mut config = AgentConfig::new(&provider, &model).with_system(SYSTEM).with_max_tokens(1200);
    // The chosen workspace becomes the tools' working directory for this run.
    if let Some(ws) = workspace.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        config = config.with_cwd(ws);
    }
    let message = Message::human(next_msg_id("u"), vec![ContentBlock::text(prompt)]);

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

    // Save the conversation (including this turn) to disk, then release the lock.
    persist_session(&app, &session_id, &session);
    drop(session);
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

/// Whether `path` is an existing directory — used to validate a chosen workspace
/// before the frontend accepts it.
#[tauri::command]
fn path_is_dir(path: String) -> bool {
    !path.trim().is_empty() && std::path::Path::new(path.trim()).is_dir()
}

/// Drop a conversation's session (a new one starts on the next run). Called by
/// `/clear` and New Session. An in-flight run/compact holds its own `Arc` clone,
/// so it finishes on the now-orphaned session while the next run starts fresh.
#[tauri::command]
fn clear_session(session_id: String, sessions: State<'_, Sessions>) {
    if let Ok(mut map) = sessions.0.lock() {
        map.remove(&session_id);
    }
}

/// Context usage for `/context`: how much of the model's window the conversation
/// is using. `last_input_tokens` is the provider-reported prompt size of the most
/// recent turn (the real context the model saw); `estimated_tokens` is a rough
/// forward estimate of the current derived history (~4 chars/token).
#[derive(Serialize, Clone)]
struct ContextInfo {
    messages: u64,
    estimated_tokens: u64,
    last_input_tokens: Option<u64>,
    last_output_tokens: Option<u64>,
}

/// Report the current conversation's context usage.
#[tauri::command]
fn session_context(session_id: String, sessions: State<'_, Sessions>) -> ContextInfo {
    let empty = ContextInfo { messages: 0, estimated_tokens: 0, last_input_tokens: None, last_output_tokens: None };
    let handle = match sessions.0.lock() {
        Ok(map) => map.get(&session_id).cloned(),
        Err(_) => None,
    };
    let Some(handle) = handle else { return empty };
    // Non-blocking: if a run/compact holds the session, report empty rather than
    // stall the UI (a /context call while idle always gets the lock).
    let Ok(session) = handle.try_lock() else { return empty };

    let messages = session.derive_messages();
    let chars: usize = messages
        .iter()
        .flat_map(|m| m.content.iter())
        .map(|b| match b {
            ContentBlock::Text { text } => text.len(),
            ContentBlock::Reasoning { text } => text.len(),
            ContentBlock::ToolCall { arguments, .. } => arguments.len(),
            ContentBlock::ToolResult { content, .. } => {
                content.iter().filter_map(ContentBlock::as_text).map(str::len).sum()
            }
        })
        .sum();

    // The most recent turn's provider-reported usage, if any.
    let last_usage = session
        .events()
        .iter()
        .rev()
        .find_map(|e| match &e.kind {
            EventKind::AssistantMessage { usage, .. } => usage.as_ref(),
            _ => None,
        });

    ContextInfo {
        messages: messages.len() as u64,
        estimated_tokens: (chars / 4) as u64,
        last_input_tokens: last_usage.map(|u| u.input_tokens),
        last_output_tokens: last_usage.map(|u| u.output_tokens),
    }
}

/// Compact a conversation: summarize the history (a toolless model turn) and
/// replace the session with a fresh one seeded with just that summary. Returns
/// the summary text for the UI to show. A no-op (empty string) if the
/// conversation is empty. The summarization runs on a CLONE, and the real
/// session is replaced only on success, so a failed compaction never corrupts or
/// drops the conversation.
#[tauri::command]
async fn compact_session(
    app: AppHandle,
    session_id: String,
    model: String,
    provider: String,
    sessions: State<'_, Sessions>,
) -> Result<String, String> {
    let key = resolve_key(&provider)?;
    let (_, _, base_url) = provider_config(&provider);
    let adapter = OpenRouterAdapter::new(Some(key)).with_base_url(base_url);

    // Lock the conversation for the whole compaction (serializes with any run).
    let handle = session_handle(&sessions, &session_id);
    let mut guard = handle.lock().await;
    if guard.derive_messages().is_empty() {
        return Ok(String::new());
    }

    // Summarize on a clone so the original is untouched if the turn fails.
    let mut work = guard.clone();
    let registry = ToolRegistry::new();
    let config = AgentConfig::new(&provider, &model).with_system(COMPACT_SYSTEM).with_max_tokens(1200);
    let prompt = Message::human(next_msg_id("compact"), vec![ContentBlock::text(COMPACT_PROMPT)]);
    let outcome = run_turn(&mut work, &adapter, &registry, &config, prompt, TurnSignal::new()).await;

    if let StopReason::Error(failure) = &outcome.stop_reason {
        return Err(format!("[{}] {}", failure.code, failure.message)); // original guard untouched
    }
    let summary = outcome.final_text.trim().to_string();
    if summary.is_empty() {
        return Err("compaction produced no summary".into());
    }

    // Replace the history with a fresh session seeded with the summary as an
    // assistant-role message, so the next user prompt still alternates cleanly.
    let mut fresh = Session::new(session_id.clone());
    let seed = Message::assistant(
        next_msg_id("compact-ctx"),
        vec![ContentBlock::text(format!("[Compacted summary of the engagement so far]\n{summary}"))],
        &provider,
        &model,
    );
    let _ = fresh.append_surface(
        EventKind::AssistantMessage { turn: 0, step: 0, message: seed, usage: None },
        SurfaceIntent::append_bare(),
    );
    *guard = fresh;
    persist_session(&app, &session_id, &guard);
    Ok(summary)
}

// ── session persistence (disk) ───────────────────────────────────────────────

/// The directory saved session logs live in (`{app_data}/sessions`), created if
/// needed.
fn sessions_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("sessions");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Metadata sidecar for a saved session (what the sidebar lists).
#[derive(Serialize, Deserialize, Clone)]
struct SessionMeta {
    id: String,
    title: String,
    updated_ms: u64,
}

/// A short title for a session — its first user message, else "New session".
fn derive_title(session: &Session) -> String {
    for m in session.derive_messages() {
        if matches!(m.source, MessageSource::Human) {
            let text = m.content.iter().filter_map(ContentBlock::as_text).collect::<Vec<_>>().join(" ");
            let t = text.trim();
            if !t.is_empty() {
                return t.chars().take(60).collect();
            }
        }
    }
    "New session".to_string()
}

/// Write a session's log + metadata to disk. Called after each turn/compaction so
/// the conversation survives a restart. A renamed title is preserved.
fn persist_session(app: &AppHandle, id: &str, session: &Session) {
    if session.events().is_empty() {
        return;
    }
    let Ok(dir) = sessions_dir(app) else { return };
    if let Ok(jsonl) = persist::to_jsonl(session) {
        let _ = std::fs::write(dir.join(format!("{id}.jsonl")), jsonl);
    }
    let meta_path = dir.join(format!("{id}.meta.json"));
    let kept_title = std::fs::read_to_string(&meta_path)
        .ok()
        .and_then(|s| serde_json::from_str::<SessionMeta>(&s).ok())
        .map(|m| m.title)
        .filter(|t| !t.trim().is_empty());
    let meta = SessionMeta {
        id: id.to_string(),
        title: kept_title.unwrap_or_else(|| derive_title(session)),
        updated_ms: now_ms(),
    };
    if let Ok(js) = serde_json::to_string(&meta) {
        let _ = std::fs::write(meta_path, js);
    }
}

/// One block of a reconstructed transcript (matches the frontend `Block`).
#[derive(Serialize, Clone)]
struct DisplayBlock {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

/// One message of a reconstructed transcript (matches the frontend `Msg`).
#[derive(Serialize, Clone)]
struct DisplayMsg {
    role: String,
    blocks: Vec<DisplayBlock>,
}

/// Rebuild the frontend display transcript from a session's derived messages, so
/// a reopened session shows its text + tool cards (the tool's rendered output; the
/// structured value for a live card is not stored, so cards show text only).
fn reconstruct_display(session: &Session) -> Vec<DisplayMsg> {
    let mut msgs: Vec<DisplayMsg> = Vec::new();
    let mut tool_at: HashMap<String, (usize, usize)> = HashMap::new();
    for m in session.derive_messages() {
        match &m.source {
            MessageSource::Human => {
                let text = m.content.iter().filter_map(ContentBlock::as_text).collect::<Vec<_>>().join("");
                msgs.push(DisplayMsg {
                    role: "user".into(),
                    blocks: vec![DisplayBlock { kind: "text".into(), text: Some(text), name: None, args: None, state: None, output: None }],
                });
            }
            MessageSource::Model { .. } => {
                let mut blocks = Vec::new();
                for b in &m.content {
                    match b {
                        ContentBlock::Text { text } if !text.is_empty() => blocks.push(DisplayBlock {
                            kind: "text".into(),
                            text: Some(text.clone()),
                            name: None, args: None, state: None, output: None,
                        }),
                        ContentBlock::ToolCall { id, name, arguments } => {
                            tool_at.insert(id.as_str().to_string(), (msgs.len(), blocks.len()));
                            blocks.push(DisplayBlock {
                                kind: "tool".into(),
                                name: Some(name.clone()),
                                args: Some(arguments.clone()),
                                state: Some("ok".into()),
                                text: None, output: None,
                            });
                        }
                        _ => {}
                    }
                }
                if !blocks.is_empty() {
                    msgs.push(DisplayMsg { role: "assistant".into(), blocks });
                }
            }
            MessageSource::Tool { call_id } => {
                if let Some(&(mi, bi)) = tool_at.get(call_id.as_str()) {
                    let (output, is_error) = m
                        .content
                        .iter()
                        .find_map(|b| match b {
                            ContentBlock::ToolResult { content, is_error, .. } => Some((
                                content.iter().filter_map(ContentBlock::as_text).collect::<Vec<_>>().join("\n"),
                                *is_error,
                            )),
                            _ => None,
                        })
                        .unwrap_or_default();
                    if let Some(block) = msgs.get_mut(mi).and_then(|msg| msg.blocks.get_mut(bi)) {
                        block.output = Some(output);
                        block.state = Some(if is_error { "error".into() } else { "ok".into() });
                    }
                }
            }
            _ => {}
        }
    }
    msgs
}

/// List saved sessions (newest first) for the sidebar.
#[tauri::command]
fn list_sessions(app: AppHandle) -> Vec<SessionMeta> {
    let Ok(dir) = sessions_dir(&app) else { return Vec::new() };
    let mut out: Vec<SessionMeta> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.to_string_lossy().ends_with(".meta.json") {
                if let Ok(m) = std::fs::read_to_string(&path).and_then(|s| {
                    serde_json::from_str::<SessionMeta>(&s).map_err(std::io::Error::other)
                }) {
                    out.push(m);
                }
            }
        }
    }
    out.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms));
    out
}

/// Load a saved session: reinstate it as the live session (so the next run
/// continues it) and return its reconstructed display transcript.
#[tauri::command]
fn load_session(
    app: AppHandle,
    id: String,
    sessions: State<'_, Sessions>,
) -> Result<Vec<DisplayMsg>, String> {
    let dir = sessions_dir(&app)?;
    let jsonl = std::fs::read_to_string(dir.join(format!("{id}.jsonl"))).map_err(|e| e.to_string())?;
    let session = persist::from_jsonl(id.clone(), &jsonl).map_err(|e| e.to_string())?;
    let display = reconstruct_display(&session);
    if let Ok(mut map) = sessions.0.lock() {
        map.insert(id, Arc::new(tokio::sync::Mutex::new(session)));
    }
    Ok(display)
}

/// Delete a saved session (files + in-memory entry).
#[tauri::command]
fn delete_session(app: AppHandle, id: String, sessions: State<'_, Sessions>) {
    if let Ok(dir) = sessions_dir(&app) {
        let _ = std::fs::remove_file(dir.join(format!("{id}.jsonl")));
        let _ = std::fs::remove_file(dir.join(format!("{id}.meta.json")));
    }
    if let Ok(mut map) = sessions.0.lock() {
        map.remove(&id);
    }
}

/// Rename a saved session (updates its metadata title).
#[tauri::command]
fn rename_session(app: AppHandle, id: String, title: String) -> Result<(), String> {
    let dir = sessions_dir(&app)?;
    let meta_path = dir.join(format!("{id}.meta.json"));
    let mut meta = std::fs::read_to_string(&meta_path)
        .ok()
        .and_then(|s| serde_json::from_str::<SessionMeta>(&s).ok())
        .unwrap_or(SessionMeta { id: id.clone(), title: String::new(), updated_ms: now_ms() });
    meta.title = title.trim().chars().take(80).collect();
    if meta.title.is_empty() {
        return Err("empty title".into());
    }
    std::fs::write(meta_path, serde_json::to_string(&meta).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(RunRegistry::default());
            app.manage(Sessions::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_models,
            has_api_key,
            save_api_key,
            delete_api_key,
            run_prompt,
            cancel_run,
            clear_session,
            session_context,
            compact_session,
            path_is_dir,
            list_sessions,
            load_session,
            delete_session,
            rename_session
        ])
        .run(tauri::generate_context!())
        .expect("error while running Decibel");
}
