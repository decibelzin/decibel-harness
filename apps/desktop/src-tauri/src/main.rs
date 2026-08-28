// Prevent an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The Decibel desktop shell (Tauri v2). It bridges the SolidJS frontend to the
//! Rust harness: a live model catalog, an API key stored in the OS keyring, and
//! a streaming agent run driven by the offensive toolkit.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};

use decibel_agent::{run_turn, run_turn_observed, AgentConfig, Progress, StopReason, TurnSignal};
use decibel_core::{persist, EventKind, Session, SurfaceIntent};
use decibel_llm::{ContentBlock, LlmAdapter, Message, MessageSource};
use decibel_mcp::{register_mcp_server, McpClient, McpServerConfig};
use decibel_offsec::{
    register_named_with_db, Db, FindingStore, Scope, ScopePolicy, ShieldPolicy, ALL_TOOLS,
};
use decibel_openrouter::OpenRouterAdapter;
use decibel_orchestrator::{build_engagement, orchestrator_system, SpecialistEvent, SpecialistSink};
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

/// Persona for PLAN mode: propose, don't execute (no tools are given either).
const PLAN_SYSTEM: &str = "You are Decibel in PLAN MODE. Do NOT run any tools or take any action. \
Produce a concise, numbered plan of the steps you would take for this engagement — for each step, the \
tool or command you would use and why. The operator will review and approve before you act. End with \
the single most important next step.";

/// The non-destructive subset for READ-ONLY access: passive/active-but-non-
/// destructive recon, offline analyzers, read/search, local knowledge-graph +
/// planning state, and finding/report reads — but NO shell/session execution,
/// no PoC, no file writes/edits, and no weaponization (jwt_forge/crack,
/// foundry_* PoC generators, evidence sealing). New destructive/executing tools
/// must be left OUT of this list to stay act-mode-only.
const READONLY_TOOLS: &[&str] = &[
    // Recon (non-destructive — reads the target, never modifies it).
    "nmap", "http", "http_probe", "port_scan", "dns", "dns_subdomains", "tls_inspect",
    "content_discovery", "web_crawl",
    // Read + search.
    "read_file", "glob", "grep",
    // Offline analyzers (no target I/O).
    "jwt_parse", "cookie_audit", "oauth_audit", "graphql_plan", "iam_policy_audit",
    "s3_buckets_from_text", "user_data_secrets", "k8s_audit", "tfstate_audit", "metadata_endpoints",
    "bin_identify", "bin_strings", "bin_packer", "bin_rop", "bin_symbols_report", "solidity_scan",
    "solidity_scan_file",
    // CVE / reference intelligence.
    "cve_lookup", "cve_by_package", "payload_search", "killchain_lookup", "killchain_suggest",
    "cvss_score",
    // Skills + on-demand injection shield.
    "skills_find", "skills_load", "shield_scan",
    // Knowledge graph (reads + local, non-destructive writes) + findings.
    "kg_node", "kg_edge", "mark_crown_jewel", "kg_query", "kg_stats", "kg_neighbors", "kg_ingest",
    "plan_chains", "promote_chain", "impact_analysis", "unexplored_surface",
    "credential_reachability", "record_finding", "add_finding", "report_executive",
    // OPPLAN objective tree (local planning state).
    "add_objective", "update_objective", "get_objective", "list_objectives", "objective_expand",
    "objective_collapse", "load_opplan",
    // Engagement-plan validation + evidence verification (read-only).
    "validate_plan_doc", "evidence_verify",
];

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

/// Whether `handle` is STILL the current session Arc for `id`. A delete_session
/// or load_session during an in-flight run removes/replaces the map entry; a
/// stale run must then NOT persist (it would resurrect a deleted session or
/// clobber a reloaded one back to its pre-turn state).
fn is_current_session(
    sessions: &Sessions,
    id: &str,
    handle: &Arc<tokio::sync::Mutex<Session>>,
) -> bool {
    sessions
        .0
        .lock()
        .map(|map| map.get(id).is_some_and(|cur| Arc::ptr_eq(cur, handle)))
        .unwrap_or(false)
}

/// One conversation's persistent engagement store: a file-backed knowledge graph
/// (`{app_data}/kg/{id}.sqlite`) plus the in-memory finding store, both kept alive
/// across turns so KG nodes/edges and recorded findings accumulate for a
/// conversation instead of dying with each turn. The `Db` is WAL-backed, so the
/// graph also survives an app restart (re-opened lazily on the next run).
struct Engagement {
    db: Db,
    findings: FindingStore,
}

/// The per-session engagement stores, keyed by the same session id as `Sessions`
/// so a knowledge graph shares its conversation's lifetime.
#[derive(Default)]
struct Engagements(Mutex<HashMap<String, Engagement>>);

/// The KG directory (`{app_data}/kg`), created if needed.
fn kg_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?.join("kg");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// Handles (KG + finding store) for a conversation's persistent engagement,
/// opened once per session and cached. Both handles share their inner `Arc`, so
/// the tools registered for a turn write into the session's durable store. If the
/// file-backed DB can't be opened (e.g. disk error), it degrades to an in-memory
/// graph for the session rather than failing the run.
fn engagement_handles(
    engagements: &Engagements,
    app: &AppHandle,
    session_id: &str,
) -> (Db, FindingStore) {
    let mut map = engagements.0.lock().unwrap_or_else(|e| e.into_inner());
    let entry = map.entry(session_id.to_string()).or_insert_with(|| {
        let db = kg_dir(app)
            .and_then(|d| Db::open(&d.join(format!("{session_id}.sqlite"))))
            .unwrap_or_else(|e| {
                eprintln!("kg: file-backed store unavailable ({e}); using in-memory graph");
                decibel_offsec::ephemeral_db()
            });
        Engagement { db, findings: FindingStore::new() }
    });
    (entry.db.handle(), entry.findings.clone())
}

/// Delete a session's on-disk knowledge graph (the sqlite file + its WAL/SHM
/// sidecars). Best-effort — a still-open handle on Windows may keep the file.
fn remove_kg(app: &AppHandle, id: &str) {
    if let Ok(dir) = kg_dir(app) {
        for suffix in ["sqlite", "sqlite-wal", "sqlite-shm"] {
            let _ = std::fs::remove_file(dir.join(format!("{id}.{suffix}")));
        }
    }
}

/// Live MCP tool servers configured in Settings. `configs` is the operator's
/// server list (persisted alongside the frontend's localStorage copy); `clients`
/// keeps the probe connections from `set_mcp_servers` alive so a warm connection
/// (and its subprocess) survives between turns. Each `run_prompt` still opens its
/// own short-lived clients for the turn (held for that turn's lifetime), so the
/// stored clients are only the validation/keep-warm handles.
#[derive(Default)]
struct McpState {
    configs: Mutex<Vec<McpServerConfig>>,
    clients: tokio::sync::Mutex<Vec<Arc<McpClient>>>,
}

/// One MCP server as the frontend configures it (maps to `McpServerConfig`).
#[derive(Serialize, Deserialize, Clone, Default)]
struct McpServerConfigDto {
    name: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    /// Extra child-process env vars, as `[key, value]` pairs (optional; the UI
    /// leaves this empty, but it round-trips for completeness).
    #[serde(default)]
    env: Vec<(String, String)>,
}

impl From<McpServerConfigDto> for McpServerConfig {
    fn from(d: McpServerConfigDto) -> Self {
        McpServerConfig {
            name: d.name,
            command: d.command,
            args: d.args,
            env: d.env,
        }
    }
}

impl From<&McpServerConfig> for McpServerConfigDto {
    fn from(c: &McpServerConfig) -> Self {
        McpServerConfigDto {
            name: c.name.clone(),
            command: c.command.clone(),
            args: c.args.clone(),
            env: c.env.clone(),
        }
    }
}

/// The result of probing one configured MCP server (returned by `set_mcp_servers`).
#[derive(Serialize, Clone)]
struct McpProbeResult {
    name: String,
    ok: bool,
    tools: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Convert the operator's engagement-scope text (one target per line, or
/// comma-separated) into the `{ "targets": [...] }` JSON that `Scope::parse`
/// consumes. An empty result yields an unenforced (inert) scope.
fn scope_to_json(raw: &str) -> String {
    let targets: Vec<String> = raw
        .split(|c: char| c == '\n' || c == '\r' || c == ',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    serde_json::json!({ "targets": targets }).to_string()
}

/// Remote (SSH) execution config from the frontend (Settings → Remote execution).
/// `key_path` is a path to a private key FILE (not the secret itself); no password
/// or passphrase is accepted, so no plaintext credential lives in the app.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RemoteDto {
    host: String,
    #[serde(default)]
    port: Option<u16>,
    user: String,
    #[serde(default)]
    key_path: String,
    #[serde(default)]
    workspace: Option<String>,
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
    // Nested specialist events (orchestrate mode) — a live sub-agent timeline that
    // nests under the `delegate` card. `delegation` correlates a specialist lane.
    SpecialistStart { delegation: u64, specialist: String, task: String },
    SpecialistStep { delegation: u64, specialist: String, n: u64 },
    SpecialistToken { delegation: u64, specialist: String, text: String },
    SpecialistToolCall { delegation: u64, specialist: String, name: String, args: String },
    SpecialistToolResult {
        delegation: u64,
        specialist: String,
        name: String,
        ok: bool,
        output: String,
        value: Option<Value>,
    },
    SpecialistEnd {
        delegation: u64,
        specialist: String,
        ok: bool,
        stop: String,
        steps: u64,
        findings_added: u64,
        tokens: u64,
        summary: String,
    },
    Done,
    Error { message: String },
}

/// Map an orchestrator [`SpecialistEvent`] to the UI-facing [`RunEvt`].
fn specialist_evt(ev: SpecialistEvent) -> RunEvt {
    match ev {
        SpecialistEvent::Start { delegation, specialist, task } => {
            RunEvt::SpecialistStart { delegation, specialist, task }
        }
        SpecialistEvent::Step { delegation, specialist, n } => {
            RunEvt::SpecialistStep { delegation, specialist, n }
        }
        SpecialistEvent::Token { delegation, specialist, text } => {
            RunEvt::SpecialistToken { delegation, specialist, text }
        }
        SpecialistEvent::ToolCall { delegation, specialist, name, args } => {
            RunEvt::SpecialistToolCall { delegation, specialist, name, args }
        }
        SpecialistEvent::ToolResult { delegation, specialist, name, ok, output, value } => {
            RunEvt::SpecialistToolResult { delegation, specialist, name, ok, output, value }
        }
        SpecialistEvent::End {
            delegation,
            specialist,
            ok,
            stop,
            steps,
            findings_added,
            tokens,
            summary,
        } => RunEvt::SpecialistEnd {
            delegation,
            specialist,
            ok,
            stop,
            steps,
            findings_added: findings_added as u64,
            tokens,
            summary,
        },
    }
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
    mode: String,
    access: String,
    scope: Option<String>,
    image: Option<String>,
    max_steps: Option<u32>,
    remote: Option<RemoteDto>,
    session_id: String,
    run_id: u64,
    on_event: Channel<RunEvt>,
    runs: State<'_, RunRegistry>,
    sessions: State<'_, Sessions>,
    engagements: State<'_, Engagements>,
    mcp: State<'_, McpState>,
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
    // `Arc<dyn LlmAdapter>` so the orchestrate path can hand a shared adapter to
    // the specialist subagents (build_engagement) while the single-agent path
    // still borrows it for run_turn_observed.
    let adapter: Arc<dyn LlmAdapter> = Arc::new(OpenRouterAdapter::new(Some(key)).with_base_url(base_url));

    // Register this run's cancellation token so cancel_run can reach it.
    let cancel = TurnSignal::new();
    if let Ok(mut map) = runs.0.lock() {
        map.insert(run_id, cancel.clone());
    }

    // The toolset + persona depend on mode + access:
    //  - PLAN: no tools (propose only).
    //  - ORCHESTRATE: the multi-agent engagement — the orchestrator delegates each
    //    kill-chain phase to the 17-specialist roster via the `delegate` tool.
    //  - ACT: the single-agent toolkit; READ-ONLY access narrows it to the
    //    non-destructive subset, otherwise the full 79-tool arsenal.
    let plan = mode == "plan";
    let orchestrate = mode == "orchestrate";
    // The conversation's persistent engagement store (file-backed KG + finding
    // store), shared across turns. Held in `Engagements` state, so tools registered
    // for this turn write into a store that outlives the turn — the knowledge graph
    // and recorded findings accumulate instead of resetting each turn.
    let (db, findings) = engagement_handles(&engagements, &app, &session_id);
    // Remote (SSH) execution plane — only for EXECUTING runs (plan runs no tools):
    // when configured, the `shell` tool runs commands on that host instead of
    // locally. A build error (bad/missing key file, unresolvable config) aborts the
    // run rather than silently falling back to local (the target was chosen remote);
    // a bad host still surfaces on the first command (the SSH connect is lazy).
    let abort = |msg: String| {
        if let Ok(mut map) = runs.0.lock() {
            map.remove(&run_id);
        }
        let _ = on_event.send(RunEvt::Error { message: msg });
        let _ = on_event.send(RunEvt::Done);
    };
    let remote_exec: Option<Arc<decibel_offsec::Executor>> =
        match remote.filter(|_| !plan).filter(|r| !r.host.trim().is_empty()) {
            Some(r) => {
                let key_path = Some(r.key_path).filter(|s| !s.trim().is_empty());
                if let Some(p) = &key_path {
                    if !std::path::Path::new(p).is_file() {
                        abort(format!("Remote execution: key file not found: {p}"));
                        return Ok(());
                    }
                }
                let backend = decibel_offsec::Backend::Remote {
                    host: r.host,
                    port: r.port,
                    user: r.user,
                    workspace: r.workspace.filter(|s| !s.trim().is_empty()),
                    password: None,
                    key_path,
                    passphrase: None,
                };
                match decibel_offsec::make_executor(backend) {
                    Ok(e) => Some(Arc::new(e)),
                    Err(e) => {
                        abort(format!("Remote execution: {e}"));
                        return Ok(());
                    }
                }
            }
            None => None,
        };
    let mut registry = ToolRegistry::new();
    if orchestrate {
        // Forward each specialist's live progress to the UI as a nested timeline
        // under its `delegate` card. The channel is Send + Sync, so the sink is too.
        let sink: SpecialistSink = {
            let out = on_event.clone();
            Arc::new(move |ev: SpecialistEvent| {
                let _ = out.send(specialist_evt(ev));
            })
        };
        registry = build_engagement(adapter.clone(), model.clone(), 1200, findings.clone(), db.handle(), remote_exec.clone(), Some(sink));
    } else if !plan {
        let names: &[&str] = if access == "readonly" { READONLY_TOOLS } else { ALL_TOOLS };
        register_named_with_db(&mut registry, names, &findings, &db, remote_exec.clone());
    }

    // Safety envelope for any EXECUTING run (act, read-only, and orchestrate —
    // never plan, which runs no tools):
    //  - the prompt-injection SHIELD (a post-policy) frames every tool result's
    //    model-facing text as untrusted DATA;
    //  - the Rules-of-Engagement SCOPE gate (a pre-policy) refuses out-of-scope
    //    targets. An empty/None scope leaves the gate inert.
    // MCP clients opened for this run are kept alive here for the turn's lifetime
    // (dropping a client kills its subprocess, unregistering its tools mid-run).
    let mut _mcp_clients: Vec<Arc<McpClient>> = Vec::new();
    if !plan {
        registry.add_post_policy(std::sync::Arc::new(ShieldPolicy::default()));
        if let Some(scope_text) = scope.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let parsed = Scope::parse(&scope_to_json(scope_text));
            registry.add_pre_policy(std::sync::Arc::new(ScopePolicy::new(parsed)));
        }
        // Register every configured MCP server's remote tools into this run's
        // registry so the agent can call them. A server that fails to connect is
        // surfaced as a non-fatal notice; the run proceeds with the rest.
        let configs = mcp.configs.lock().map(|c| c.clone()).unwrap_or_default();
        for cfg in &configs {
            match register_mcp_server(&mut registry, cfg).await {
                Ok(client) => _mcp_clients.push(client),
                Err(e) => {
                    let _ = on_event.send(RunEvt::Error {
                        message: format!("MCP server `{}` unavailable: {e}", cfg.name),
                    });
                }
            }
        }
    }

    // Lock this conversation's session for the whole turn so the model sees prior
    // turns and a concurrent run/compact on the same conversation serializes
    // behind us instead of forking a blank session.
    let handle = session_handle(&sessions, &session_id);
    let mut session = handle.lock().await;
    let system: String = if plan {
        PLAN_SYSTEM.to_string()
    } else if orchestrate {
        orchestrator_system()
    } else {
        SYSTEM.to_string()
    };
    let mut config = AgentConfig::new(&provider, &model).with_system(system).with_max_tokens(1200);
    // The chosen workspace becomes the tools' working directory for this run.
    if let Some(ws) = workspace.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        config = config.with_cwd(ws);
    }
    // A real engagement takes many tool steps; the AgentConfig default (16) hits
    // the cap mid-recon. 40 is the default (bounds a runaway loop while leaving
    // room), but the operator can raise/lower it in Settings. Clamp to a sane band.
    config.max_steps = max_steps.unwrap_or(40).clamp(1, 200) as u64;
    let mut blocks = vec![ContentBlock::text(prompt)];
    if let Some(img) = image.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        blocks.push(ContentBlock::image(img)); // a data: URL for a vision model
    }
    let message = Message::human(next_msg_id("u"), blocks);

    let sink = on_event.clone();
    let outcome = run_turn_observed(
        &mut session,
        adapter.as_ref(),
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

    // Save the conversation (including this turn) to disk — but only if this run's
    // session is still the current one (a delete/load mid-run must not be undone).
    if is_current_session(&sessions, &session_id, &handle) {
        persist_session(&app, &session_id, &session);
    }
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

/// (Re)configure the external MCP tool servers. Each server is connected in a
/// throwaway probe registry to validate it and discover its tool names; the
/// configs are stored and the successful connections kept alive (warm) in state.
/// Returns a per-server `{ name, ok, tools, error? }` so the UI can show each
/// server's discovered tool count or its connection error. Later `run_prompt`
/// turns register these servers' tools into the run's own registry.
#[tauri::command]
async fn set_mcp_servers(
    servers: Vec<McpServerConfigDto>,
    mcp: State<'_, McpState>,
) -> Result<Vec<McpProbeResult>, String> {
    let configs: Vec<McpServerConfig> = servers.into_iter().map(Into::into).collect();
    let mut results = Vec::with_capacity(configs.len());
    let mut live_clients = Vec::new();
    for cfg in &configs {
        let mut probe = ToolRegistry::new();
        match register_mcp_server(&mut probe, cfg).await {
            Ok(client) => {
                let tools: Vec<String> = probe.schemas().into_iter().map(|s| s.name).collect();
                live_clients.push(client); // keep the connection (subprocess) alive
                results.push(McpProbeResult { name: cfg.name.clone(), ok: true, tools, error: None });
            }
            Err(e) => {
                results.push(McpProbeResult {
                    name: cfg.name.clone(),
                    ok: false,
                    tools: Vec::new(),
                    error: Some(e),
                });
            }
        }
    }
    // Store the configs (used by run_prompt) and replace the warm-client set.
    if let Ok(mut c) = mcp.configs.lock() {
        *c = configs;
    }
    *mcp.clients.lock().await = live_clients;
    Ok(results)
}

/// The currently-configured MCP servers (for the Settings list on startup).
#[tauri::command]
fn list_mcp_servers(mcp: State<'_, McpState>) -> Vec<McpServerConfigDto> {
    mcp.configs
        .lock()
        .map(|c| c.iter().map(McpServerConfigDto::from).collect())
        .unwrap_or_default()
}

/// Whether `path` is an existing directory — used to validate a chosen workspace
/// before the frontend accepts it.
#[tauri::command]
fn path_is_dir(path: String) -> bool {
    !path.trim().is_empty() && std::path::Path::new(path.trim()).is_dir()
}

/// Write text to a file the user chose in a save dialog — used by the findings
/// report export. The frontend picks the path (@tauri-apps/plugin-dialog `save`),
/// then hands it here to persist the generated markdown/SARIF.
#[tauri::command]
fn write_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| e.to_string())
}

/// One finding for the UI drawer (matches the frontend `Finding`).
#[derive(Serialize, Clone)]
struct FindingDto {
    title: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mitre: Option<String>,
}

/// Every finding recorded for a session, from BOTH sinks: `add_finding` (the
/// in-memory finding store) and `record_finding` (the persistent knowledge graph,
/// which survives reload and app restart). The UI merges these with the live
/// transcript so a reopened session's findings do not vanish.
#[tauri::command]
fn session_findings(
    session_id: String,
    engagements: State<'_, Engagements>,
    app: AppHandle,
) -> Vec<FindingDto> {
    let (db, findings) = engagement_handles(&engagements, &app, &session_id);
    let mut out: Vec<FindingDto> = Vec::new();
    for f in findings.snapshot() {
        out.push(FindingDto {
            title: f.title,
            severity: f.severity,
            description: Some(f.description).filter(|s| !s.is_empty()),
            target: f.target,
            mitre: f.mitre,
        });
    }
    if let Ok(conn) = db.0.lock() {
        if let Ok(list) = decibel_offsec::kg_list_findings(&conn, "default") {
            for f in list {
                let detail: Value = serde_json::from_str(&f.detail_json).unwrap_or(Value::Null);
                let field = |k: &str| {
                    detail.get(k).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
                };
                out.push(FindingDto {
                    title: f.title,
                    severity: f.severity,
                    description: field("description"),
                    target: Some(f.target).filter(|s| !s.is_empty()),
                    mitre: field("mitre"),
                });
            }
        }
    }
    out
}

/// Drop a conversation's session (a new one starts on the next run). Called by
/// `/clear` and New Session. An in-flight run/compact holds its own `Arc` clone,
/// so it finishes on the now-orphaned session while the next run starts fresh.
#[tauri::command]
fn clear_session(
    session_id: String,
    sessions: State<'_, Sessions>,
    engagements: State<'_, Engagements>,
) {
    if let Ok(mut map) = sessions.0.lock() {
        map.remove(&session_id);
    }
    // Release the in-memory KG handle so the next run re-opens it fresh. The file
    // stays on disk — the conversation remains reloadable from the sidebar, and its
    // knowledge graph should come back with it. (delete_session removes the file.)
    if let Ok(mut map) = engagements.0.lock() {
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
            // Images are tokenized by the vision model, not by char count.
            ContentBlock::Image { .. } => 0,
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
    if is_current_session(&sessions, &session_id, &handle) {
        persist_session(&app, &session_id, &guard);
    }
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

/// Write atomically: a sibling temp file + rename over the target, so a crash
/// mid-write cannot leave a truncated/partial file that later fails to parse.
fn atomic_write(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
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
        let _ = atomic_write(&dir.join(format!("{id}.jsonl")), &jsonl);
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
        let _ = atomic_write(&meta_path, &js);
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

/// Delete a saved session (files + in-memory entry + its knowledge graph).
#[tauri::command]
fn delete_session(
    app: AppHandle,
    id: String,
    sessions: State<'_, Sessions>,
    engagements: State<'_, Engagements>,
) {
    if let Ok(dir) = sessions_dir(&app) {
        let _ = std::fs::remove_file(dir.join(format!("{id}.jsonl")));
        let _ = std::fs::remove_file(dir.join(format!("{id}.meta.json")));
    }
    if let Ok(mut map) = sessions.0.lock() {
        map.remove(&id);
    }
    // Drop the KG handle first so the file is unlocked, then delete it.
    if let Ok(mut map) = engagements.0.lock() {
        map.remove(&id);
    }
    remove_kg(&app, &id);
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

/// Point `DECIBEL_SKILLS_DIR` at the shipped SKILL.md corpus so `skills_find` /
/// `skills_load` have playbooks even when the session workspace has none. An
/// operator-set env var wins; otherwise use the bundled resource dir (a real
/// build) or, failing that, the crate's `skills/` dir (dev / `npm run app`).
fn install_skills_corpus(app: &AppHandle) {
    if std::env::var("DECIBEL_SKILLS_DIR").ok().filter(|s| !s.trim().is_empty()).is_some() {
        return; // operator override wins
    }
    let candidates = [
        app.path().resource_dir().ok().map(|r| r.join("skills")),
        Some(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/skills"))),
    ];
    for dir in candidates.into_iter().flatten() {
        if dir.is_dir() {
            std::env::set_var("DECIBEL_SKILLS_DIR", dir);
            return;
        }
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            app.manage(RunRegistry::default());
            app.manage(Sessions::default());
            app.manage(Engagements::default());
            app.manage(McpState::default());
            install_skills_corpus(app.handle());
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
            write_text_file,
            session_findings,
            list_sessions,
            load_session,
            delete_session,
            rename_session,
            set_mcp_servers,
            list_mcp_servers
        ])
        .run(tauri::generate_context!())
        .expect("error while running Decibel");
}
