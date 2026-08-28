//! Docker-free local state store (Fase A of the Decepticon port).
//!
//! Replaces the upstream postgres + neo4j stack with a single SQLite file
//! (`~/.decepticon/decepticon.db`). Holds engagements, chat threads/messages,
//! tool calls, findings, the attack-chain **knowledge graph** (nodes/edges —
//! the store that must not be lost, see docs/decepticon-port/FASE0-PORT-SPEC.md
//! §5), and the OPPLAN objective tree.
//!
//! The graph reproduces the upstream invariants: deterministic ids
//! (`sha1("{Kind}::{key}")[:16]`), an `engagement` partition on every node and
//! edge, and upsert-merge semantics (new props win, `created_at` preserved).
//!
//! Every public function takes a `&Connection` so it is unit-testable without
//! Tauri; the `Db` newtype (an `Arc<Mutex<Connection>>`) is what gets managed as
//! Tauri state and locked by the command layer.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

// Re-export so the Tauri command layer can name the connection type without
// depending on rusqlite directly.
pub use rusqlite::Connection;

/// Recon-output → knowledge-graph ingestion (the `kg_ingest_*` capability).
pub mod ingest;

/// Attack-chain planning over the knowledge graph (APOC-free Dijkstra).
pub mod chain;

/// Named knowledge-graph analyses (impact / unexplored-surface / credential-reach).
pub mod analysis;

/// Recognized KG node/edge vocabulary (incl. AD/ADCS + Solidity).
pub mod vocab;

/// Report renderers (executive markdown, SARIF) + CVSS 3.1 calculator.
pub mod report;

/// OPPLAN — objective tree CRUD + the kill-chain gate (upstream OPPLANMiddleware).
pub mod opplan;

/// Managed Tauri state: one shared SQLite connection behind a mutex.
pub struct Db(pub Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = open_conn(path)?;
        Ok(Db(Arc::new(Mutex::new(conn))))
    }

    /// A second handle to the SAME underlying connection (clones the inner `Arc`).
    /// `Db` is deliberately not `Clone` — this names the shared-handle intent, so a
    /// per-session store can be handed to many turns/tools that all lock one file.
    pub fn handle(&self) -> Self {
        Db(self.0.clone())
    }

    /// Total number of recorded findings across all engagements in this store —
    /// the count `record_finding` grows (the KG's `finding` table). Locks the
    /// connection; returns 0 on any error so a caller using it for a progress
    /// delta never panics.
    pub fn finding_count(&self) -> usize {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row("SELECT COUNT(*) FROM finding", [], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .unwrap_or(0)
    }
}

/// Current unix time in whole seconds.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Process-local monotonic counter for non-graph row ids.
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A collision-resistant id for entity rows (engagements, threads, …). Graph
/// nodes/edges use deterministic content ids instead (see `node_id`/`edge_id`).
fn new_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut h = sha1_smol::Sha1::new();
    h.update(format!("{prefix}:{nanos}:{n}").as_bytes());
    format!("{prefix}_{}", &h.digest().to_string()[..16])
}

/// Deterministic node id: `sha1("{kind}::{key}")[:16]`. `key` falls back to the
/// label when the caller supplies no explicit dedup key.
pub fn node_id(kind: &str, key: &str) -> String {
    let mut h = sha1_smol::Sha1::new();
    h.update(format!("{kind}::{key}").as_bytes());
    h.digest().to_string()[..16].to_string()
}

/// Deterministic edge id: `sha1("{src}->{kind}->{dst}::{key}")[:16]`.
pub fn edge_id(src: &str, kind: &str, dst: &str, key: &str) -> String {
    let mut h = sha1_smol::Sha1::new();
    h.update(format!("{src}->{kind}->{dst}::{key}").as_bytes());
    h.digest().to_string()[..16].to_string()
}

fn open_conn(path: &Path) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| format!("open db: {e}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| format!("wal: {e}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| format!("fk: {e}"))?;
    // If a session is cleared mid-run and reopened, a second connection to this
    // file can briefly coexist with the winding-down run's connection. A busy
    // timeout makes a write wait for the other connection's lock (WAL serializes
    // writers) instead of returning SQLITE_BUSY immediately and losing the write.
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| format!("busy_timeout: {e}"))?;
    migrate(&conn)?;
    Ok(conn)
}

/// Open an in-memory database (used by this crate's tests and by downstream
/// crates' tests, e.g. `decepticon-cve`).
pub fn open_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("open :memory:");
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    migrate(&conn).expect("migrate");
    conn
}

/// Apply schema migrations, tracked via `PRAGMA user_version`.
fn migrate(conn: &Connection) -> Result<(), String> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| format!("read user_version: {e}"))?;

    if version < 1 {
        conn.execute_batch(SCHEMA_V1)
            .map_err(|e| format!("migrate v1: {e}"))?;
        conn.pragma_update(None, "user_version", 1)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    Ok(())
}

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS engagement (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    scope_json  TEXT NOT NULL DEFAULT '{}',
    executor_json TEXT NOT NULL DEFAULT '{}',
    ready       INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS thread (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT REFERENCES engagement(id) ON DELETE CASCADE,
    title         TEXT NOT NULL DEFAULT '',
    backend       TEXT NOT NULL DEFAULT 'dsh',
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_thread_engagement ON thread(engagement_id);

CREATE TABLE IF NOT EXISTS message (
    id         TEXT PRIMARY KEY,
    thread_id  TEXT NOT NULL REFERENCES thread(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    text       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_message_thread ON message(thread_id, created_at);

CREATE TABLE IF NOT EXISTS tool_call (
    id          TEXT PRIMARY KEY,
    thread_id   TEXT NOT NULL REFERENCES thread(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'generic',
    status      TEXT NOT NULL DEFAULT 'pending',
    input_json  TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '',
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_toolcall_thread ON tool_call(thread_id);

CREATE TABLE IF NOT EXISTS finding (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    severity      TEXT NOT NULL DEFAULT 'info',
    title         TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    detail_json   TEXT NOT NULL DEFAULT '{}',
    source_tool   TEXT NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_engagement ON finding(engagement_id);

-- Attack-chain knowledge graph (replaces neo4j). Every node/edge is partitioned
-- by `engagement`; reserved provenance lives in columns, `props_json` carries
-- only agent-supplied fields.
CREATE TABLE IF NOT EXISTS graph_node (
    engagement TEXT NOT NULL,
    id         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    label      TEXT NOT NULL,
    props_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (engagement, id)
);
CREATE INDEX IF NOT EXISTS idx_node_kind ON graph_node(engagement, kind);

CREATE TABLE IF NOT EXISTS graph_edge (
    engagement TEXT NOT NULL,
    id         TEXT NOT NULL,
    src        TEXT NOT NULL,
    dst        TEXT NOT NULL,
    kind       TEXT NOT NULL,
    weight     REAL NOT NULL DEFAULT 1.0,
    props_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (engagement, id)
);
CREATE INDEX IF NOT EXISTS idx_edge_src ON graph_edge(engagement, src);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON graph_edge(engagement, dst);

-- OPPLAN objective tree (kept separate from the KG, as upstream does).
CREATE TABLE IF NOT EXISTS objective (
    engagement_id  TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    id             TEXT NOT NULL,
    phase          TEXT NOT NULL DEFAULT '',
    title          TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    priority       INTEGER NOT NULL DEFAULT 100,
    blocked_by_json TEXT NOT NULL DEFAULT '[]',
    parent_id      TEXT,
    notes          TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (engagement_id, id)
);
"#;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Engagement {
    pub id: String,
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub scope_json: String,
    #[serde(default)]
    pub executor_json: String,
    #[serde(default)]
    pub ready: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: String,
    pub engagement_id: Option<String>,
    pub title: String,
    pub backend: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub thread_id: String,
    pub role: String,
    pub text: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub engagement_id: String,
    pub severity: String,
    pub title: String,
    pub target: String,
    pub detail_json: String,
    pub source_tool: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub engagement: String,
    pub kind: String,
    pub label: String,
    pub props_json: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub engagement: String,
    pub src: String,
    pub dst: String,
    pub kind: String,
    pub weight: f64,
    pub props_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KgStats {
    pub nodes: i64,
    pub edges: i64,
    pub nodes_by_kind: Vec<(String, i64)>,
}

/// The whole knowledge graph for an engagement — every node and edge, for the UI
/// to lay out and render.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KgGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ---------------------------------------------------------------------------
// Engagements
// ---------------------------------------------------------------------------

/// Ensure an engagement row exists for a given id (used by the agent/MCP path,
/// where the engagement is a partition label that may not have been created
/// through the app). Keeps the `finding`/`thread`/`objective` foreign keys valid
/// while letting the agent write against a bare label.
pub fn ensure_engagement(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute(
        "INSERT OR IGNORE INTO engagement (id, slug, name, scope_json, executor_json, ready, created_at)
         VALUES (?1, ?1, ?1, '{}', '{}', 0, ?2)",
        params![id, now()],
    )
    .map_err(|e| format!("ensure engagement: {e}"))?;
    Ok(())
}

pub fn create_engagement(conn: &Connection, slug: &str, name: &str) -> Result<Engagement, String> {
    let e = Engagement {
        // The slug IS the engagement identity: the agent uses it as the KG
        // partition and (via ensure_engagement) the row id, so findings, graph,
        // and this row all key on the same value. Slugs are therefore unique.
        id: slug.to_string(),
        slug: slug.to_string(),
        name: name.to_string(),
        scope_json: "{}".into(),
        executor_json: "{}".into(),
        ready: false,
        created_at: now(),
    };
    conn.execute(
        "INSERT INTO engagement (id, slug, name, scope_json, executor_json, ready, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![e.id, e.slug, e.name, e.scope_json, e.executor_json, e.ready as i64, e.created_at],
    )
    .map_err(|e| format!("create engagement: {e}"))?;
    Ok(e)
}

fn row_to_engagement(r: &rusqlite::Row) -> rusqlite::Result<Engagement> {
    Ok(Engagement {
        id: r.get(0)?,
        slug: r.get(1)?,
        name: r.get(2)?,
        scope_json: r.get(3)?,
        executor_json: r.get(4)?,
        ready: r.get::<_, i64>(5)? != 0,
        created_at: r.get(6)?,
    })
}

pub fn list_engagements(conn: &Connection) -> Result<Vec<Engagement>, String> {
    let mut stmt = conn
        .prepare("SELECT id, slug, name, scope_json, executor_json, ready, created_at FROM engagement ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], row_to_engagement)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

pub fn get_engagement(conn: &Connection, id: &str) -> Result<Option<Engagement>, String> {
    conn.query_row(
        "SELECT id, slug, name, scope_json, executor_json, ready, created_at FROM engagement WHERE id = ?1",
        params![id],
        row_to_engagement,
    )
    .optional()
    .map_err(|e| e.to_string())
}

pub fn set_engagement_ready(conn: &Connection, id: &str, ready: bool) -> Result<(), String> {
    conn.execute(
        "UPDATE engagement SET ready = ?2 WHERE id = ?1",
        params![id, ready as i64],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn set_engagement_executor(conn: &Connection, id: &str, executor_json: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE engagement SET executor_json = ?2 WHERE id = ?1",
        params![id, executor_json],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Set the engagement's scope / rules-of-engagement (`scope_json`).
pub fn set_engagement_scope(conn: &Connection, id: &str, scope_json: &str) -> Result<(), String> {
    conn.execute("UPDATE engagement SET scope_json = ?2 WHERE id = ?1", params![id, scope_json])
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Threads & messages
// ---------------------------------------------------------------------------

pub fn create_thread(
    conn: &Connection,
    engagement_id: Option<&str>,
    title: &str,
    backend: &str,
) -> Result<Thread, String> {
    let t = Thread {
        id: new_id("thr"),
        engagement_id: engagement_id.map(str::to_string),
        title: title.to_string(),
        backend: backend.to_string(),
        created_at: now(),
    };
    conn.execute(
        "INSERT INTO thread (id, engagement_id, title, backend, created_at) VALUES (?1,?2,?3,?4,?5)",
        params![t.id, t.engagement_id, t.title, t.backend, t.created_at],
    )
    .map_err(|e| format!("create thread: {e}"))?;
    Ok(t)
}

pub fn list_threads(conn: &Connection) -> Result<Vec<Thread>, String> {
    let mut stmt = conn
        .prepare("SELECT id, engagement_id, title, backend, created_at FROM thread ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(Thread {
                id: r.get(0)?,
                engagement_id: r.get(1)?,
                title: r.get(2)?,
                backend: r.get(3)?,
                created_at: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

pub fn add_message(conn: &Connection, thread_id: &str, role: &str, text: &str) -> Result<Message, String> {
    let m = Message {
        id: new_id("msg"),
        thread_id: thread_id.to_string(),
        role: role.to_string(),
        text: text.to_string(),
        created_at: now(),
    };
    conn.execute(
        "INSERT INTO message (id, thread_id, role, text, created_at) VALUES (?1,?2,?3,?4,?5)",
        params![m.id, m.thread_id, m.role, m.text, m.created_at],
    )
    .map_err(|e| format!("add message: {e}"))?;
    Ok(m)
}

pub fn list_messages(conn: &Connection, thread_id: &str) -> Result<Vec<Message>, String> {
    let mut stmt = conn
        .prepare("SELECT id, thread_id, role, text, created_at FROM message WHERE thread_id = ?1 ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![thread_id], |r| {
            Ok(Message {
                id: r.get(0)?,
                thread_id: r.get(1)?,
                role: r.get(2)?,
                text: r.get(3)?,
                created_at: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

pub fn add_finding(
    conn: &Connection,
    engagement_id: &str,
    severity: &str,
    title: &str,
    target: &str,
    detail_json: &str,
    source_tool: &str,
) -> Result<Finding, String> {
    let f = Finding {
        id: new_id("find"),
        engagement_id: engagement_id.to_string(),
        severity: severity.to_string(),
        title: title.to_string(),
        target: target.to_string(),
        detail_json: detail_json.to_string(),
        source_tool: source_tool.to_string(),
        created_at: now(),
    };
    conn.execute(
        "INSERT INTO finding (id, engagement_id, severity, title, target, detail_json, source_tool, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![f.id, f.engagement_id, f.severity, f.title, f.target, f.detail_json, f.source_tool, f.created_at],
    )
    .map_err(|e| format!("add finding: {e}"))?;
    Ok(f)
}

pub fn list_findings(conn: &Connection, engagement_id: &str) -> Result<Vec<Finding>, String> {
    let mut stmt = conn
        .prepare("SELECT id, engagement_id, severity, title, target, detail_json, source_tool, created_at FROM finding WHERE engagement_id = ?1 ORDER BY created_at DESC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![engagement_id], |r| {
            Ok(Finding {
                id: r.get(0)?,
                engagement_id: r.get(1)?,
                severity: r.get(2)?,
                title: r.get(3)?,
                target: r.get(4)?,
                detail_json: r.get(5)?,
                source_tool: r.get(6)?,
                created_at: r.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Knowledge graph (the store that must not be lost)
// ---------------------------------------------------------------------------

/// Reserved provenance keys for a **node**: these live in dedicated columns and are
/// the source of truth. If an agent smuggles one into `props_json`, it is stripped
/// on read (KG-6) so it can never shadow the real column value.
pub const RESERVED_NODE_KEYS: &[&str] = &["id", "engagement", "kind", "label", "created_at", "updated_at"];

/// Reserved provenance keys for an **edge** (columns, not props).
pub const RESERVED_EDGE_KEYS: &[&str] = &["id", "engagement", "src", "dst", "kind", "weight", "created_at"];

/// Remove reserved provenance keys from a serialized props object so an agent-set
/// `created_at`/`kind`/… inside `props_json` can never leak back through a read
/// (KG-6). The columns remain the source of truth; this only sanitizes the
/// agent-supplied blob. Non-object / unparseable props pass through untouched.
pub fn strip_reserved(props_json: &str, reserved: &[&str]) -> String {
    match serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(props_json) {
        Ok(mut map) => {
            let mut changed = false;
            for k in reserved {
                if map.remove(*k).is_some() {
                    changed = true;
                }
            }
            if changed {
                serde_json::to_string(&map).unwrap_or_else(|_| props_json.to_string())
            } else {
                props_json.to_string()
            }
        }
        Err(_) => props_json.to_string(),
    }
}

/// Run `f` inside a single SQL transaction so a multi-statement KG write is
/// all-or-nothing (KG-7): on `Err` the whole batch is rolled back, so the graph
/// never holds a half-written ingest. If a transaction is already open on this
/// connection (an ingester wrapping many upserts), `f` simply joins it — the
/// outermost caller owns COMMIT/ROLLBACK, so nested upserts don't clash. The
/// process-wide `Arc<Mutex<Connection>>` is what makes operating on a shared
/// `&Connection` transaction sound here (no other thread can interleave).
pub fn with_tx<T>(conn: &Connection, f: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
    if !conn.is_autocommit() {
        // Already inside a transaction: participate, don't nest (SQLite has no
        // nested BEGIN). The outer scope commits or rolls back the whole unit.
        return f(conn);
    }
    conn.execute_batch("BEGIN").map_err(|e| format!("begin tx: {e}"))?;
    match f(conn) {
        Ok(v) => {
            conn.execute_batch("COMMIT").map_err(|e| format!("commit tx: {e}"))?;
            Ok(v)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// Upsert a node. `key` is the dedup key (falls back to `label`). Existing props
/// are merged with `props_json` (new keys win); `created_at` is preserved.
/// Returns the deterministic node id. The SELECT-then-INSERT/UPDATE runs inside a
/// transaction (KG-7) so it is atomic even standalone.
pub fn kg_upsert_node(
    conn: &Connection,
    engagement: &str,
    kind: &str,
    label: &str,
    key: Option<&str>,
    props_json: &str,
) -> Result<String, String> {
    let dedup = key.unwrap_or(label);
    let id = node_id(kind, dedup);

    with_tx(conn, |conn| {
        let ts = now();
        let existing: Option<(String, i64)> = conn
            .query_row(
                "SELECT props_json, created_at FROM graph_node WHERE engagement = ?1 AND id = ?2",
                params![engagement, id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| e.to_string())?;

        let merged = merge_props(existing.as_ref().map(|(p, _)| p.as_str()), props_json)?;

        match existing {
            Some((_, created_at)) => {
                conn.execute(
                    "UPDATE graph_node SET kind=?3, label=?4, props_json=?5, updated_at=?6 WHERE engagement=?1 AND id=?2",
                    params![engagement, id, kind, label, merged, ts],
                )
                .map_err(|e| e.to_string())?;
                let _ = created_at; // preserved implicitly (not overwritten)
            }
            None => {
                conn.execute(
                    "INSERT INTO graph_node (engagement, id, kind, label, props_json, created_at, updated_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?6)",
                    params![engagement, id, kind, label, merged, ts],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })?;
    Ok(id)
}

/// Upsert an edge between two node ids. `key` lets multiple edges of the same
/// kind between the same pair coexist. Returns the deterministic edge id.
pub fn kg_upsert_edge(
    conn: &Connection,
    engagement: &str,
    src: &str,
    dst: &str,
    kind: &str,
    weight: f64,
    key: Option<&str>,
    props_json: &str,
) -> Result<String, String> {
    let id = edge_id(src, kind, dst, key.unwrap_or(""));
    let ts = now();
    conn.execute(
        "INSERT INTO graph_edge (engagement, id, src, dst, kind, weight, props_json, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)
         ON CONFLICT(engagement, id) DO UPDATE SET
            weight = excluded.weight,
            props_json = excluded.props_json",
        params![engagement, id, src, dst, kind, weight, props_json, ts],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

fn row_to_node(r: &rusqlite::Row) -> rusqlite::Result<GraphNode> {
    Ok(GraphNode {
        id: r.get(0)?,
        engagement: r.get(1)?,
        kind: r.get(2)?,
        label: r.get(3)?,
        // KG-6: reserved provenance keys are the columns' job; strip them from the
        // agent-supplied props on the way out so they can never shadow a column.
        props_json: strip_reserved(&r.get::<_, String>(4)?, RESERVED_NODE_KEYS),
        created_at: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

pub fn kg_by_kind(conn: &Connection, engagement: &str, kind: &str) -> Result<Vec<GraphNode>, String> {
    let mut stmt = conn
        .prepare("SELECT id, engagement, kind, label, props_json, created_at, updated_at FROM graph_node WHERE engagement = ?1 AND kind = ?2 ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![engagement, kind], row_to_node)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())
}

/// One-hop neighbours of a node. `direction` is "out", "in", or "both".
pub fn kg_neighbors(
    conn: &Connection,
    engagement: &str,
    node_id: &str,
    direction: &str,
) -> Result<Vec<GraphNode>, String> {
    let sql = match direction {
        "out" => "SELECT dst FROM graph_edge WHERE engagement=?1 AND src=?2",
        "in" => "SELECT src FROM graph_edge WHERE engagement=?1 AND dst=?2",
        _ => "SELECT dst FROM graph_edge WHERE engagement=?1 AND src=?2 UNION SELECT src FROM graph_edge WHERE engagement=?1 AND dst=?2",
    };
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let ids: Vec<String> = stmt
        .query_map(params![engagement, node_id], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for nid in ids {
        if let Some(n) = conn
            .query_row(
                "SELECT id, engagement, kind, label, props_json, created_at, updated_at FROM graph_node WHERE engagement=?1 AND id=?2",
                params![engagement, nid],
                row_to_node,
            )
            .optional()
            .map_err(|e| e.to_string())?
        {
            out.push(n);
        }
    }
    Ok(out)
}

pub fn kg_stats(conn: &Connection, engagement: &str) -> Result<KgStats, String> {
    let nodes: i64 = conn
        .query_row("SELECT COUNT(*) FROM graph_node WHERE engagement=?1", params![engagement], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let edges: i64 = conn
        .query_row("SELECT COUNT(*) FROM graph_edge WHERE engagement=?1", params![engagement], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    let mut stmt = conn
        .prepare("SELECT kind, COUNT(*) FROM graph_node WHERE engagement=?1 GROUP BY kind ORDER BY kind")
        .map_err(|e| e.to_string())?;
    let by_kind = stmt
        .query_map(params![engagement], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    Ok(KgStats { nodes, edges, nodes_by_kind: by_kind })
}

fn row_to_edge(r: &rusqlite::Row) -> rusqlite::Result<GraphEdge> {
    Ok(GraphEdge {
        id: r.get(0)?,
        engagement: r.get(1)?,
        src: r.get(2)?,
        dst: r.get(3)?,
        kind: r.get(4)?,
        weight: r.get(5)?,
        // KG-6: strip reserved provenance keys from edge props on read.
        props_json: strip_reserved(&r.get::<_, String>(6)?, RESERVED_EDGE_KEYS),
        created_at: r.get(7)?,
    })
}

/// The whole knowledge graph for an engagement (all nodes + all edges), for the
/// UI to lay out and draw.
pub fn kg_graph(conn: &Connection, engagement: &str) -> Result<KgGraph, String> {
    let mut ns = conn
        .prepare("SELECT id, engagement, kind, label, props_json, created_at, updated_at FROM graph_node WHERE engagement=?1 ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;
    let nodes = ns
        .query_map(params![engagement], row_to_node)
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    let mut es = conn
        .prepare("SELECT id, engagement, src, dst, kind, weight, props_json, created_at FROM graph_edge WHERE engagement=?1 ORDER BY created_at ASC")
        .map_err(|e| e.to_string())?;
    let edges = es
        .query_map(params![engagement], row_to_edge)
        .map_err(|e| e.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    Ok(KgGraph { nodes, edges })
}

/// Merge two JSON objects (base ⊕ incoming; incoming keys win). Non-object
/// inputs are treated as empty objects.
fn merge_props(base: Option<&str>, incoming: &str) -> Result<String, String> {
    let mut map = base
        .and_then(|s| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(s).ok())
        .unwrap_or_default();
    if let Ok(inc) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(incoming) {
        for (k, v) in inc {
            map.insert(k, v);
        }
    }
    serde_json::to_string(&map).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests (E2E round-trips over a real SQLite database)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_sets_version() {
        let conn = open_memory();
        let v: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn engagement_thread_message_roundtrip() {
        let conn = open_memory();
        let eng = create_engagement(&conn, "acme-web", "ACME Web App").unwrap();
        assert!(!eng.ready);

        let thr = create_thread(&conn, Some(&eng.id), "First contact", "dsh").unwrap();
        add_message(&conn, &thr.id, "user", "scope the target").unwrap();
        add_message(&conn, &thr.id, "assistant", "starting recon").unwrap();

        let engs = list_engagements(&conn).unwrap();
        assert_eq!(engs.len(), 1);
        assert_eq!(engs[0].slug, "acme-web");

        let msgs = list_messages(&conn, &thr.id).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "user");
        assert_eq!(msgs[1].text, "starting recon");

        set_engagement_ready(&conn, &eng.id, true).unwrap();
        assert!(get_engagement(&conn, &eng.id).unwrap().unwrap().ready);
    }

    #[test]
    fn kg_deterministic_ids_and_upsert_merge() {
        let conn = open_memory();
        let e = "acme";

        // First upsert creates the node.
        let host = kg_upsert_node(&conn, e, "Host", "10.10.10.5", Some("10.10.10.5"), r#"{"os":"linux"}"#).unwrap();
        // Same key -> same deterministic id.
        let again = kg_upsert_node(&conn, e, "Host", "10.10.10.5", Some("10.10.10.5"), r#"{"tags":["web"]}"#).unwrap();
        assert_eq!(host, again);
        assert_eq!(host, node_id("Host", "10.10.10.5"));

        // Props merged (os preserved, tags added).
        let hosts = kg_by_kind(&conn, e, "Host").unwrap();
        assert_eq!(hosts.len(), 1);
        let props: serde_json::Value = serde_json::from_str(&hosts[0].props_json).unwrap();
        assert_eq!(props["os"], "linux");
        assert_eq!(props["tags"][0], "web");

        // A service node + an edge Host->RUNS->Service.
        let svc = kg_upsert_node(&conn, e, "Service", "10.10.10.5:80/http", None, r#"{"port":80}"#).unwrap();
        kg_upsert_edge(&conn, e, &host, &svc, "RUNS", 1.0, None, "{}").unwrap();

        let neigh = kg_neighbors(&conn, e, &host, "out").unwrap();
        assert_eq!(neigh.len(), 1);
        assert_eq!(neigh[0].kind, "Service");

        let stats = kg_stats(&conn, e).unwrap();
        assert_eq!(stats.nodes, 2);
        assert_eq!(stats.edges, 1);
    }

    #[test]
    fn kg_engagement_partition_isolates() {
        let conn = open_memory();
        kg_upsert_node(&conn, "eng-a", "Host", "1.1.1.1", None, "{}").unwrap();
        kg_upsert_node(&conn, "eng-b", "Host", "2.2.2.2", None, "{}").unwrap();

        assert_eq!(kg_stats(&conn, "eng-a").unwrap().nodes, 1);
        assert_eq!(kg_stats(&conn, "eng-b").unwrap().nodes, 1);
        // eng-a cannot see eng-b's host.
        assert_eq!(kg_by_kind(&conn, "eng-a", "Host").unwrap()[0].label, "1.1.1.1");
    }

    #[test]
    fn kg_graph_returns_all_nodes_and_edges() {
        let conn = open_memory();
        let e = "eng-g";
        let host = kg_upsert_node(&conn, e, "Host", "10.0.0.1", Some("10.0.0.1"), "{}").unwrap();
        let svc = kg_upsert_node(&conn, e, "Service", "10.0.0.1:22/ssh", None, r#"{"port":22}"#).unwrap();
        kg_upsert_edge(&conn, e, &host, &svc, "RUNS", 1.0, None, "{}").unwrap();
        // A second engagement's data must not leak in.
        kg_upsert_node(&conn, "other", "Host", "9.9.9.9", None, "{}").unwrap();

        let g = kg_graph(&conn, e).unwrap();
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].kind, "RUNS");
        assert_eq!(g.edges[0].src, host);
        assert_eq!(g.edges[0].dst, svc);
        assert!(g.nodes.iter().all(|n| n.engagement == e));
    }

    #[test]
    fn findings_roundtrip() {
        let conn = open_memory();
        let eng = create_engagement(&conn, "acme", "ACME").unwrap();
        add_finding(&conn, &eng.id, "high", "SQLi in /login", "10.10.10.5", r#"{"param":"user"}"#, "sqlmap").unwrap();
        let fs = list_findings(&conn, &eng.id).unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, "high");
    }

    #[test]
    fn finding_count_totals_across_engagements() {
        // The delegation progress delta relies on this counting every engagement's
        // findings (a specialist may record under any engagement slug).
        let db = Db(Arc::new(Mutex::new(open_memory())));
        assert_eq!(db.finding_count(), 0);
        {
            let conn = db.0.lock().unwrap();
            let a = create_engagement(&conn, "a", "A").unwrap();
            let b = create_engagement(&conn, "b", "B").unwrap();
            add_finding(&conn, &a.id, "high", "x", "t", "{}", "s").unwrap();
            add_finding(&conn, &b.id, "low", "y", "t", "{}", "s").unwrap();
        }
        assert_eq!(db.finding_count(), 2);
    }

    #[test]
    fn same_key_different_engagement_same_node_id() {
        // Node id is content-addressed by (kind,key); the engagement column is
        // what keeps two engagements' identically-keyed nodes distinct rows.
        let a = node_id("Host", "10.0.0.1");
        let b = node_id("Host", "10.0.0.1");
        assert_eq!(a, b);
    }

    #[test]
    fn reserved_props_are_stripped_on_read_but_columns_intact() {
        // KG-6: an agent smuggles reserved provenance keys into props. On read they
        // must be gone from props, while the real column values are untouched.
        let conn = open_memory();
        let e = "acme";
        kg_upsert_node(
            &conn,
            e,
            "Host",
            "10.0.0.1",
            Some("10.0.0.1"),
            r#"{"created_at":1,"updated_at":2,"kind":"Bogus","label":"spoof","id":"x","engagement":"other","os":"linux"}"#,
        )
        .unwrap();

        let hosts = kg_by_kind(&conn, e, "Host").unwrap();
        assert_eq!(hosts.len(), 1);
        let n = &hosts[0];
        let props: serde_json::Value = serde_json::from_str(&n.props_json).unwrap();
        // Every reserved key is stripped from the returned props.
        for k in RESERVED_NODE_KEYS {
            assert!(props.get(*k).is_none(), "reserved key `{k}` leaked through props");
        }
        // The non-reserved prop survives.
        assert_eq!(props["os"], "linux");
        // The columns are the real provenance, not the agent's spoofed values.
        assert_eq!(n.kind, "Host");
        assert_eq!(n.label, "10.0.0.1");
        assert_eq!(n.engagement, e);
        assert!(n.created_at > 1, "created_at column is the real timestamp, not the spoofed 1");
    }

    #[test]
    fn with_tx_rolls_back_a_failed_multi_write() {
        // KG-7: a multi-statement write that fails midway leaves the graph unchanged.
        let conn = open_memory();
        let e = "acme";
        let r: Result<(), String> = with_tx(&conn, |c| {
            kg_upsert_node(c, e, "Host", "10.0.0.1", Some("10.0.0.1"), "{}")?;
            kg_upsert_node(c, e, "Service", "10.0.0.1:80", Some("10.0.0.1:80"), "{}")?;
            Err("boom midway".into())
        });
        assert!(r.is_err());
        // All-or-nothing: neither node persisted.
        assert_eq!(kg_stats(&conn, e).unwrap().nodes, 0);
    }

    #[test]
    fn nested_upserts_participate_in_the_outer_transaction() {
        // The inner kg_upsert_node's own with_tx must NOT open a nested BEGIN when a
        // transaction is already open; a failure still rolls the whole unit back.
        let conn = open_memory();
        let e = "acme";
        let ok: Result<(), String> = with_tx(&conn, |c| {
            kg_upsert_node(c, e, "Host", "h1", Some("h1"), "{}")?;
            kg_upsert_node(c, e, "Host", "h2", Some("h2"), "{}")?;
            Ok(())
        });
        assert!(ok.is_ok());
        assert_eq!(kg_stats(&conn, e).unwrap().nodes, 2, "committed batch persists");
    }
}
