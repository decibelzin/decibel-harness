//! Model-facing [`Tool`] wrappers over `decibel-store`'s knowledge-graph, attack-chain,
//! analysis, and report surface. Every tool holds a shared [`decibel_store::Db`]
//! (an `Arc<Mutex<Connection>>` under the hood) and does synchronous rusqlite work
//! under a tightly-scoped lock — the store fns are sync, so no `.await` is ever held
//! across the guard.
//!
//! All knowledge-graph state is **engagement-scoped**: every tool accepts an
//! optional `engagement` string (default `"default"`) and calls
//! [`decibel_store::ensure_engagement`] at the top of `execute` so the partition row
//! exists before any finding/objective foreign key needs it.
//!
//! The arg names + semantics mirror the upstream Decepticon dispatcher's `call_tool`
//! match arms (its authoritative spec), so the same JSON drives both providers:
//!   - `kg_node` / `kg_edge` / `mark_crown_jewel` — KG authoring (vocab-checked);
//!   - `kg_query` / `kg_stats` / `kg_neighbors` — KG reads;
//!   - `kg_ingest` — the unified recon-output ingester (`decibel_store::ingest::ingest`);
//!   - `plan_chains` / `promote_chain` — attack-chain planning (`decibel_store::chain`);
//!   - `impact_analysis` / `unexplored_surface` / `credential_reachability` — named
//!     analyses (`decibel_store::analysis`);
//!   - `record_finding` — a finding row + a traversable `Finding` KG node;
//!   - `cvss_score` — the standalone CVSS 3.1 calculator (`decibel_store::report::cvss_v31`);
//!   - `report_executive` — the CISO-level markdown summary.
//!
//! `kg_neighbors` has no upstream dispatcher arm; it is ported straight over
//! [`decibel_store::kg_neighbors`], resolving the node id deterministically from
//! `kind`+`key` via [`decibel_store::node_id`] (see the tool's schema).

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_bool, arg_str, arg_str_opt, arg_u64_opt};

/// The engagement partition when the model names none (mirrors upstream `default`).
const DEFAULT_ENGAGEMENT: &str = "default";
/// The upstream planner uses an effectively-unbounded cost ceiling.
const MAX_COST: f64 = 1.0e9;

/// The engagement partition argument, defaulting to `"default"`.
fn engagement_of(args: &Value) -> String {
    arg_str_opt(args, "engagement")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_ENGAGEMENT.to_string())
}

/// Serialize a store struct into the canonical tool value, mapping a serde failure
/// to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Standard "db mutex poisoned" execution error for a failed lock.
fn poisoned() -> ToolError {
    ToolError::execution("db mutex poisoned")
}

/// KG vocab enforcement (KG-9), the decibel counterpart of upstream's
/// `DECEPTICON_KG_STRICT_VOCAB`. In strict mode an out-of-vocabulary kind is
/// rejected; otherwise the write is accepted and a `warning` is surfaced so the
/// agent still learns it went off-vocab.
fn kg_strict_vocab() -> bool {
    matches!(
        std::env::var("DECIBEL_KG_STRICT_VOCAB").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    )
}

/// A non-fatal "off-vocabulary" note for a kind (used when not in strict mode).
fn vocab_warning(kind: &str, is_node: bool) -> Option<String> {
    let known = if is_node {
        decibel_store::vocab::known_node(kind)
    } else {
        decibel_store::vocab::known_edge(kind)
    };
    (!known).then(|| {
        format!("`{kind}` is not in the documented KG vocabulary (accepted; set DECIBEL_KG_STRICT_VOCAB=1 to enforce)")
    })
}

/// Reject an out-of-vocabulary kind only in strict mode; otherwise accept.
fn check_vocab(kind: &str, is_node: bool) -> Result<(), ToolError> {
    let known = if is_node {
        decibel_store::vocab::known_node(kind)
    } else {
        decibel_store::vocab::known_edge(kind)
    };
    if kg_strict_vocab() && !known {
        let (what, hint) = if is_node {
            ("node", "a documented PascalCase kind (Host/Service/Vulnerability/Finding/Candidate/Hypothesis/Patch/…)")
        } else {
            ("edge", "a documented UPPER_SNAKE rel (EXPLOITS/PIVOTS_TO/ADMIN_TO/HAS_FINDING/…)")
        };
        return Err(ToolError::execution(format!(
            "unknown {what} kind `{kind}` (strict KG vocab). Use {hint}, or unset DECIBEL_KG_STRICT_VOCAB."
        )));
    }
    Ok(())
}

// ===========================================================================
// kg_node — upsert a standalone KG node of a vocab-checked kind
// ===========================================================================

/// Upsert a standalone knowledge-graph node.
pub struct KgNodeTool {
    db: decibel_store::Db,
}

impl KgNodeTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgNodeTool { db }
    }
}

#[async_trait]
impl Tool for KgNodeTool {
    fn name(&self) -> &str {
        "kg_node"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_node".into(),
            description: "Upsert a standalone knowledge-graph node of a given `kind` (PascalCase \
                vocabulary: Host/Service/Vulnerability/Finding/Candidate/Hypothesis/Patch/…). The \
                producer path for the vuln-research pipeline kinds — scanner records `Candidate`, \
                detector `Hypothesis`, patcher `Patch`. Vocab-checked (rejected under \
                DECIBEL_KG_STRICT_VOCAB, otherwise a `warning` is returned). Returns the node id."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "description": "Node kind (PascalCase)." },
                    "label": { "type": "string", "description": "Node label." },
                    "key": { "type": "string", "description": "Optional dedup key (defaults to label)." },
                    "props_json": { "type": "string", "description": "Optional JSON props object." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["kind", "label"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let kind = arg_str(&arguments, "kind")?;
        let label = arg_str(&arguments, "label")?;
        let key = arg_str_opt(&arguments, "key");
        let props = arg_str_opt(&arguments, "props_json").unwrap_or_else(|| "{}".into());
        check_vocab(&kind, true)?;

        let id = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::kg_upsert_node(
                &conn,
                &engagement,
                &kind,
                &label,
                key.as_deref().or(Some(label.as_str())),
                &props,
            )
            .map_err(ToolError::execution)?
        };
        Ok(json!({ "id": id, "kind": kind, "label": label, "warning": vocab_warning(&kind, true) }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        let label = value.get("label").and_then(Value::as_str).unwrap_or("");
        let id = value.get("id").and_then(Value::as_str).unwrap_or("");
        let mut out = format!("kg_node: {kind} \"{label}\" → {id}");
        if let Some(w) = value.get("warning").and_then(Value::as_str) {
            out.push_str(&format!("\n  warning: {w}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// kg_edge — record an attack-relevant edge (upserts both endpoints)
// ===========================================================================

/// Record an attack-relevant edge the chain planner can traverse.
pub struct KgEdgeTool {
    db: decibel_store::Db,
}

impl KgEdgeTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgEdgeTool { db }
    }
}

#[async_trait]
impl Tool for KgEdgeTool {
    fn name(&self) -> &str {
        "kg_edge"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_edge".into(),
            description: "Record an attack-relevant edge the chain planner can traverse. `rel` in \
                {EXPLOITS,ENABLES,LEAKS,LEADS_TO,PIVOTS_TO,ESCALATES_TO,HAS_VULN,CAN_ACCESS,ADMIN_TO}. \
                Upserts both endpoints. Set `validated:true` for a proven step (half traversal cost). \
                Kinds are checked against the KG vocabulary (rejected under DECIBEL_KG_STRICT_VOCAB, \
                otherwise a `warning` is returned)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "src_kind": { "type": "string", "description": "Source node kind, e.g. Service." },
                    "src": { "type": "string", "description": "Source label." },
                    "rel": { "type": "string", "description": "Relationship (UPPER_SNAKE)." },
                    "dst_kind": { "type": "string", "description": "Dest node kind, e.g. Host." },
                    "dst": { "type": "string", "description": "Dest label." },
                    "weight": { "type": "number", "description": "Traversal weight (default 1)." },
                    "validated": { "type": "boolean", "description": "A proven step → half cost." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["src_kind", "src", "rel", "dst_kind", "dst"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let rel = arg_str(&arguments, "rel")?;
        let src_kind = arg_str(&arguments, "src_kind")?;
        let src = arg_str(&arguments, "src")?;
        let dst_kind = arg_str(&arguments, "dst_kind")?;
        let dst = arg_str(&arguments, "dst")?;
        check_vocab(&rel, false)?;
        check_vocab(&src_kind, true)?;
        check_vocab(&dst_kind, true)?;
        let weight = arguments.get("weight").and_then(Value::as_f64).unwrap_or(1.0);
        let validated = arg_bool(&arguments, "validated", false);

        {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            let s = decibel_store::kg_upsert_node(&conn, &engagement, &src_kind, &src, Some(&src), "{}")
                .map_err(ToolError::execution)?;
            let d = decibel_store::kg_upsert_node(&conn, &engagement, &dst_kind, &dst, Some(&dst), "{}")
                .map_err(ToolError::execution)?;
            let props = if validated { r#"{"validated":true}"# } else { "{}" };
            decibel_store::kg_upsert_edge(&conn, &engagement, &s, &d, &rel, weight, None, props)
                .map_err(ToolError::execution)?;
        }
        Ok(json!({
            "src": src, "rel": rel, "dst": dst, "weight": weight, "validated": validated,
            "warning": vocab_warning(&rel, false)
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let src = value.get("src").and_then(Value::as_str).unwrap_or("");
        let rel = value.get("rel").and_then(Value::as_str).unwrap_or("");
        let dst = value.get("dst").and_then(Value::as_str).unwrap_or("");
        let validated = value.get("validated").and_then(Value::as_bool).unwrap_or(false);
        let mut out = format!("kg_edge: {src} -{rel}-> {dst}{}", if validated { " (validated)" } else { "" });
        if let Some(w) = value.get("warning").and_then(Value::as_str) {
            out.push_str(&format!("\n  warning: {w}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// mark_crown_jewel — mark an asset as the objective the planner routes toward
// ===========================================================================

/// Mark an asset as a CrownJewel (the objective the chain planner routes toward).
pub struct MarkCrownJewelTool {
    db: decibel_store::Db,
}

impl MarkCrownJewelTool {
    pub fn new(db: decibel_store::Db) -> Self {
        MarkCrownJewelTool { db }
    }
}

#[async_trait]
impl Tool for MarkCrownJewelTool {
    fn name(&self) -> &str {
        "mark_crown_jewel"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "mark_crown_jewel".into(),
            description: "Mark an asset as a CrownJewel (the objective the chain planner routes \
                toward). Optionally link an existing asset to it via `from`+`from_kind`+`rel`."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "label": { "type": "string", "description": "The crown-jewel label, e.g. 'domain-admin'." },
                    "note": { "type": "string", "description": "Why it matters (optional)." },
                    "from_kind": { "type": "string", "description": "Optional linked-asset kind." },
                    "from": { "type": "string", "description": "Optional linked-asset label." },
                    "rel": { "type": "string", "description": "Optional relationship to the jewel." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["label"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let label = arg_str(&arguments, "label")?;
        let note = arg_str_opt(&arguments, "note").unwrap_or_default();
        let from_kind = arg_str_opt(&arguments, "from_kind");
        let from = arg_str_opt(&arguments, "from");
        let rel = arg_str_opt(&arguments, "rel");

        let cj = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            let props = json!({ "note": note }).to_string();
            let cj = decibel_store::kg_upsert_node(&conn, &engagement, "CrownJewel", &label, Some(&label), &props)
                .map_err(ToolError::execution)?;
            // Optionally link an existing asset to the objective (e.g. Host ADMIN_TO CrownJewel).
            if let (Some(fk), Some(fl), Some(rl)) = (&from_kind, &from, &rel) {
                let f = decibel_store::kg_upsert_node(&conn, &engagement, fk, fl, Some(fl), "{}")
                    .map_err(ToolError::execution)?;
                decibel_store::kg_upsert_edge(&conn, &engagement, &f, &cj, rl, 1.0, None, "{}")
                    .map_err(ToolError::execution)?;
            }
            cj
        };
        Ok(json!({ "crown_jewel": label, "id": cj }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let label = value.get("crown_jewel").and_then(Value::as_str).unwrap_or("");
        let id = value.get("id").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("mark_crown_jewel: {label} → {id}"))]
    }
}

// ===========================================================================
// kg_query — query nodes by kind
// ===========================================================================

/// Query knowledge-graph nodes by kind.
pub struct KgQueryTool {
    db: decibel_store::Db,
}

impl KgQueryTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgQueryTool { db }
    }
}

#[async_trait]
impl Tool for KgQueryTool {
    fn name(&self) -> &str {
        "kg_query"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_query".into(),
            description: "Query knowledge-graph nodes by kind (Host/Service/URL/Entrypoint/CVE/\
                Finding/...). Returns the matching nodes for the engagement."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "description": "Node kind to list." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["kind"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let kind = arg_str(&arguments, "kind")?;
        let nodes = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::kg_by_kind(&conn, &engagement, &kind).map_err(ToolError::execution)?
        };
        let count = nodes.len();
        let nodes_val = to_value(&nodes)?;
        Ok(json!({ "kind": kind, "count": count, "nodes": nodes_val }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let kind = value.get("kind").and_then(Value::as_str).unwrap_or("");
        let count = value.get("count").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let nodes = value.get("nodes").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("kg_query {kind}: {count} node(s)");
        for n in nodes.iter().take(25) {
            let label = n.get("label").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("\n  - {label}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// kg_stats — node/edge counts for the engagement
// ===========================================================================

/// Knowledge-graph node/edge counts for the engagement.
pub struct KgStatsTool {
    db: decibel_store::Db,
}

impl KgStatsTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgStatsTool { db }
    }
}

#[async_trait]
impl Tool for KgStatsTool {
    fn name(&self) -> &str {
        "kg_stats"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_stats".into(),
            description: "Knowledge-graph node/edge counts (and a per-kind node tally) for the engagement."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let stats = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::kg_stats(&conn, &engagement).map_err(ToolError::execution)?
        };
        to_value(stats)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let nodes = value.get("nodes").and_then(Value::as_i64).unwrap_or(0);
        let edges = value.get("edges").and_then(Value::as_i64).unwrap_or(0);
        vec![ContentBlock::text(format!("kg_stats: {nodes} node(s), {edges} edge(s)"))]
    }
}

// ===========================================================================
// kg_neighbors — one-hop neighbours of a node (no upstream arm; ported over
// decibel_store::kg_neighbors, resolving the id deterministically)
// ===========================================================================

/// One-hop neighbours of a node, resolving the node id deterministically from
/// `kind`+`key` (`decibel_store::node_id`).
pub struct KgNeighborsTool {
    db: decibel_store::Db,
}

impl KgNeighborsTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgNeighborsTool { db }
    }
}

#[async_trait]
impl Tool for KgNeighborsTool {
    fn name(&self) -> &str {
        "kg_neighbors"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_neighbors".into(),
            description: "One-hop neighbours of a knowledge-graph node. Identify the node by its \
                `kind` + `label` (or an explicit `key`); `direction` is out|in|both (default both). \
                Returns the adjacent nodes."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "kind": { "type": "string", "description": "The node's kind (PascalCase)." },
                    "label": { "type": "string", "description": "The node's label." },
                    "key": { "type": "string", "description": "Explicit dedup key if it differs from label (optional)." },
                    "direction": { "type": "string", "description": "out|in|both (default both)." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["kind", "label"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let kind = arg_str(&arguments, "kind")?;
        let label = arg_str(&arguments, "label")?;
        let key = arg_str_opt(&arguments, "key");
        let direction = arg_str_opt(&arguments, "direction").unwrap_or_else(|| "both".into());
        // The node id is content-addressed by (kind, key|label) — the same rule the
        // upserts use — so we can resolve it without a scan.
        let id = decibel_store::node_id(&kind, key.as_deref().unwrap_or(&label));

        let neighbors = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::kg_neighbors(&conn, &engagement, &id, &direction).map_err(ToolError::execution)?
        };
        let count = neighbors.len();
        let neighbors_val = to_value(&neighbors)?;
        Ok(json!({
            "node": label,
            "direction": direction,
            "count": count,
            "neighbors": neighbors_val
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let node = value.get("node").and_then(Value::as_str).unwrap_or("");
        let dir = value.get("direction").and_then(Value::as_str).unwrap_or("");
        let count = value.get("count").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let ns = value.get("neighbors").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("kg_neighbors {node} ({dir}): {count}");
        for n in ns.iter().take(25) {
            let kind = n.get("kind").and_then(Value::as_str).unwrap_or("");
            let label = n.get("label").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("\n  - [{kind}] {label}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// kg_ingest — the unified recon-output ingester
// ===========================================================================

/// Ingest a recon tool's output into the knowledge graph.
pub struct KgIngestTool {
    db: decibel_store::Db,
}

impl KgIngestTool {
    pub fn new(db: decibel_store::Db) -> Self {
        KgIngestTool { db }
    }
}

#[async_trait]
impl Tool for KgIngestTool {
    fn name(&self) -> &str {
        "kg_ingest"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "kg_ingest".into(),
            description: "Ingest a recon tool's output into the knowledge graph. `tool` in \
                {port-scan,http-probe,dns,content-discovery,tls-inspect,web-crawl} (native) or \
                {nuclei,httpx,masscan,ffuf,dnsx,katana,slither} (third-party JSON/JSONL) or {nmap} \
                (its -oX XML) or {bloodhound} (SharpHound/BloodHound JSON — one collector file per \
                call, builds the AD attack graph) or {testssl} (testssl.sh --jsonfile → TLS vulns) \
                or {sarif} (SARIF v2.1.0 → vulns) or {impacket} (secretsdump TEXT → Credential \
                nodes) or {netexec} (nxc/cme JSON → hosts + admin creds) or the vuln-research \
                pipeline artifacts {candidates}/{hypotheses}/{patches} — each accepts JSON-lines or a \
                {items:[...]} wrapper. Run the scanner via shell/bash, then pipe its output here. The \
                whole ingest is atomic (a parse that fails midway rolls back)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "tool": { "type": "string", "description": "Source tool name." },
                    "json": { "type": "string", "description": "The tool's JSON, JSONL, or XML output." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["tool", "json"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let tool = arg_str(&arguments, "tool")?;
        let data = arg_str(&arguments, "json")?;
        let report = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::ingest::ingest(&conn, &engagement, &tool, &data).map_err(ToolError::execution)?
        };
        Ok(json!({ "tool": tool, "nodes": report.nodes, "edges": report.edges }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let tool = value.get("tool").and_then(Value::as_str).unwrap_or("");
        let nodes = value.get("nodes").and_then(Value::as_u64).unwrap_or(0);
        let edges = value.get("edges").and_then(Value::as_u64).unwrap_or(0);
        vec![ContentBlock::text(format!("kg_ingest[{tool}]: +{nodes} node(s), +{edges} edge(s)"))]
    }
}

// ===========================================================================
// plan_chains — plan attack chains (Entrypoint → CrownJewel)
// ===========================================================================

/// Plan attack chains over the knowledge graph.
pub struct PlanChainsTool {
    db: decibel_store::Db,
}

impl PlanChainsTool {
    pub fn new(db: decibel_store::Db) -> Self {
        PlanChainsTool { db }
    }
}

#[async_trait]
impl Tool for PlanChainsTool {
    fn name(&self) -> &str {
        "plan_chains"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "plan_chains".into(),
            description: "Plan attack chains (Entrypoint → CrownJewel) over the knowledge graph. \
                Cost prefers routes into high-severity nodes and `validated` edges; each chain \
                carries a `score` (critical-path score = inverse cost + worst severity on the path)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "max_depth": { "type": "integer", "description": "Max hops (default 12)." },
                    "top_k": { "type": "integer", "description": "How many chains (default 20)." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let max_depth = arg_u64_opt(&arguments, "max_depth").unwrap_or(12) as usize;
        let top_k = arg_u64_opt(&arguments, "top_k").unwrap_or(20) as usize;
        let chains = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::chain::plan_chains(&conn, &engagement, max_depth, MAX_COST, top_k)
                .map_err(ToolError::execution)?
        };
        let count = chains.len();
        let chains_val = to_value(&chains)?;
        Ok(json!({ "count": count, "chains": chains_val }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let chains = value.get("chains").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("plan_chains: {} chain(s)", chains.len());
        for c in chains.iter().take(10) {
            let cost = c.get("cost").and_then(Value::as_f64).unwrap_or(0.0);
            let hops = c.get("hops").and_then(Value::as_u64).unwrap_or(0);
            let path: Vec<&str> = c.get("path").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).collect()
            }).unwrap_or_default();
            out.push_str(&format!("\n  cost {cost:.1} ({hops} hops): {}", path.join(" → ")));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// promote_chain — materialize the cheapest Entrypoint→CrownJewel path
// ===========================================================================

/// Materialize the cheapest Entrypoint→CrownJewel path as a durable AttackPath node.
pub struct PromoteChainTool {
    db: decibel_store::Db,
}

impl PromoteChainTool {
    pub fn new(db: decibel_store::Db) -> Self {
        PromoteChainTool { db }
    }
}

#[async_trait]
impl Tool for PromoteChainTool {
    fn name(&self) -> &str {
        "promote_chain"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "promote_chain".into(),
            description: "Materialize the cheapest Entrypoint→CrownJewel path as a durable \
                AttackPath node (STARTS_AT/REACHES/STEP edges) for the report. Returns its node id."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "entry": { "type": "string", "description": "The Entrypoint label." },
                    "crown_jewel": { "type": "string", "description": "The CrownJewel label." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["entry", "crown_jewel"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let entry = arg_str(&arguments, "entry")?;
        let crown = arg_str(&arguments, "crown_jewel")?;
        let ap = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::chain::promote_chain(&conn, &engagement, &entry, &crown, MAX_COST)
                .map_err(ToolError::execution)?
        };
        match ap {
            Some(id) => Ok(json!({ "attack_path": id })),
            None => Ok(json!({ "attack_path": null, "note": "no path from that entrypoint to that crown jewel" })),
        }
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        match value.get("attack_path").and_then(Value::as_str) {
            Some(id) => vec![ContentBlock::text(format!("promote_chain: AttackPath {id}"))],
            None => vec![ContentBlock::text("promote_chain: no path found".to_string())],
        }
    }
}

// ===========================================================================
// impact_analysis — blast radius of a node
// ===========================================================================

/// Blast radius of a node over the attack-relationship graph.
pub struct ImpactAnalysisTool {
    db: decibel_store::Db,
}

impl ImpactAnalysisTool {
    pub fn new(db: decibel_store::Db) -> Self {
        ImpactAnalysisTool { db }
    }
}

#[async_trait]
impl Tool for ImpactAnalysisTool {
    fn name(&self) -> &str {
        "impact_analysis"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "impact_analysis".into(),
            description: "Blast radius of a node: everything reachable FROM it over the \
                attack-relationship graph (incl. AD/ADCS + credential edges), with hop distance and \
                any CrownJewels reached. Use to judge what compromising an asset unlocks."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "node": { "type": "string", "description": "The node's label, e.g. 'app01' or 'domain-admin'." },
                    "kind": { "type": "string", "description": "Optional node kind to disambiguate (Host/Service/CrownJewel/…)." },
                    "max_depth": { "type": "integer", "description": "Max hops (default 8)." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["node"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let node = arg_str(&arguments, "node")?;
        let kind = arg_str_opt(&arguments, "kind");
        let max_depth = arg_u64_opt(&arguments, "max_depth").unwrap_or(8) as usize;
        let report = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::analysis::impact_analysis(&conn, &engagement, &node, kind.as_deref(), max_depth)
                .map_err(ToolError::execution)?
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let node = value.get("node").and_then(Value::as_str).unwrap_or("");
        let reached = value.get("reached_count").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let jewels: Vec<&str> = value.get("crown_jewels_reached").and_then(Value::as_array).unwrap_or(&empty)
            .iter().filter_map(Value::as_str).collect();
        let mut out = format!("impact_analysis {node}: reaches {reached} node(s)");
        if !jewels.is_empty() {
            out.push_str(&format!("; crown jewels: {}", jewels.join(", ")));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// unexplored_surface — services with no HAS_VULN edge yet
// ===========================================================================

/// Services / web entrypoints recon found but nobody has analyzed yet.
pub struct UnexploredSurfaceTool {
    db: decibel_store::Db,
}

impl UnexploredSurfaceTool {
    pub fn new(db: decibel_store::Db) -> Self {
        UnexploredSurfaceTool { db }
    }
}

#[async_trait]
impl Tool for UnexploredSurfaceTool {
    fn name(&self) -> &str {
        "unexplored_surface"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "unexplored_surface".into(),
            description: "Services and web entrypoints that recon found but nobody has analyzed yet \
                (no HAS_VULN edge), each mapped to its host. Tells you where to look next."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let report = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::analysis::unexplored_surface(&conn, &engagement).map_err(ToolError::execution)?
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let count = value.get("count").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let services = value.get("services").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("unexplored_surface: {count} service(s)");
        for s in services.iter().take(25) {
            let label = s.get("label").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("\n  - {label}"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// credential_reachability — what a looted secret unlocks
// ===========================================================================

/// For every captured Credential/Secret: what it unlocks.
pub struct CredentialReachabilityTool {
    db: decibel_store::Db,
}

impl CredentialReachabilityTool {
    pub fn new(db: decibel_store::Db) -> Self {
        CredentialReachabilityTool { db }
    }
}

#[async_trait]
impl Tool for CredentialReachabilityTool {
    fn name(&self) -> &str {
        "credential_reachability"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "credential_reachability".into(),
            description: "For every captured Credential/Secret: the Users it AUTHENTICATES_TO and the \
                assets those users CAN_ACCESS / ADMIN_TO / HAS_SESSION. Shows what a looted secret unlocks."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let report = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::analysis::credential_reachability(&conn, &engagement).map_err(ToolError::execution)?
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let count = value.get("count").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let creds = value.get("credentials").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("credential_reachability: {count} credential(s)");
        for c in creds.iter().take(25) {
            let cred = c.get("credential").and_then(Value::as_str).unwrap_or("");
            let reaches = c.get("reaches").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
            out.push_str(&format!("\n  - {cred} → {reaches} node(s)"));
        }
        vec![ContentBlock::text(out)]
    }
}

// ===========================================================================
// record_finding — a finding row + a traversable Finding KG node
// ===========================================================================

/// Record a validated finding + materialize a traversable `Finding` KG node.
pub struct RecordFindingTool {
    db: decibel_store::Db,
}

impl RecordFindingTool {
    pub fn new(db: decibel_store::Db) -> Self {
        RecordFindingTool { db }
    }
}

#[async_trait]
impl Tool for RecordFindingTool {
    fn name(&self) -> &str {
        "record_finding"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "record_finding".into(),
            description: "Record a validated finding for the engagement. Also materializes a \
                `Finding` node in the knowledge graph (linked to the affected target Host via \
                HAS_FINDING) so it is traversable by the analyses + reporting."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "severity": { "type": "string", "description": "info|low|medium|high|critical (default info)." },
                    "title": { "type": "string", "description": "Finding title." },
                    "target": { "type": "string", "description": "Affected target." },
                    "detail_json": { "type": "string", "description": "JSON details." },
                    "source_tool": { "type": "string", "description": "Tool that found it." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["title"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let severity = arg_str_opt(&arguments, "severity").unwrap_or_else(|| "info".into());
        let title = arg_str(&arguments, "title")?;
        let target = arg_str_opt(&arguments, "target").unwrap_or_default();
        let detail_json = arg_str_opt(&arguments, "detail_json").unwrap_or_else(|| "{}".into());
        let source_tool = arg_str_opt(&arguments, "source_tool").unwrap_or_default();

        let finding = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            let finding = decibel_store::add_finding(
                &conn, &engagement, &severity, &title, &target, &detail_json, &source_tool,
            )
            .map_err(ToolError::execution)?;
            // KG-5: also materialize a `Finding` graph node (keyed on the finding id so
            // each finding is its own node), linked to the affected target Host when one
            // is named — so findings are traversable by the analyses + visible in the KG.
            let props = json!({ "severity": severity, "target": target, "finding_id": finding.id }).to_string();
            let fnode = decibel_store::kg_upsert_node(&conn, &engagement, "Finding", &title, Some(&finding.id), &props)
                .map_err(ToolError::execution)?;
            if !target.is_empty() {
                let host = decibel_store::kg_upsert_node(&conn, &engagement, "Host", &target, Some(&target), "{}")
                    .map_err(ToolError::execution)?;
                decibel_store::kg_upsert_edge(&conn, &engagement, &host, &fnode, "HAS_FINDING", 1.0, None, "{}")
                    .map_err(ToolError::execution)?;
            }
            finding
        };
        to_value(finding)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let sev = value.get("severity").and_then(Value::as_str).unwrap_or("");
        let title = value.get("title").and_then(Value::as_str).unwrap_or("");
        let target = value.get("target").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("record_finding [{sev}] {title} @ {target}"))]
    }
}

// ===========================================================================
// cvss_score — standalone CVSS 3.1 base-score calculator
// ===========================================================================

/// Compute a CVSS 3.1 base score from a vector string.
pub struct CvssScoreTool {
    db: decibel_store::Db,
}

impl CvssScoreTool {
    pub fn new(db: decibel_store::Db) -> Self {
        CvssScoreTool { db }
    }
}

#[async_trait]
impl Tool for CvssScoreTool {
    fn name(&self) -> &str {
        "cvss_score"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "cvss_score".into(),
            description: "Compute a CVSS 3.1 base score from a vector string \
                (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "vector": { "type": "string", "description": "CVSS:3.1/AV:N/... vector string." },
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                },
                "required": ["vector"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let vector = arg_str(&arguments, "vector")?;
        // The calculator is pure, but we honor the shared pattern: touch the store to
        // keep the engagement row present (the tool holds a Db like every other).
        {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
        }
        let score = decibel_store::report::cvss_v31(&vector).map_err(ToolError::execution)?;
        to_value(score)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let base = value.get("base_score").and_then(Value::as_f64).unwrap_or(0.0);
        let sev = value.get("severity").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("cvss_score: {base} ({sev})"))]
    }
}

// ===========================================================================
// report_executive — CISO-level markdown summary
// ===========================================================================

/// Render the engagement's executive summary (Markdown).
pub struct ReportExecutiveTool {
    db: decibel_store::Db,
}

impl ReportExecutiveTool {
    pub fn new(db: decibel_store::Db) -> Self {
        ReportExecutiveTool { db }
    }
}

#[async_trait]
impl Tool for ReportExecutiveTool {
    fn name(&self) -> &str {
        "report_executive"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "report_executive".into(),
            description: "Render the engagement's executive summary (Markdown): a severity breakdown, \
                the findings table, and the top attack chains over the knowledge graph."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let md = {
            let conn = self.db.0.lock().map_err(|_| poisoned())?;
            decibel_store::ensure_engagement(&conn, &engagement).map_err(ToolError::execution)?;
            decibel_store::report::report_executive(&conn, &engagement).map_err(ToolError::execution)?
        };
        Ok(json!({ "engagement": engagement, "markdown": md }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let md = value.get("markdown").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(md.to_string())]
    }
}

// ===========================================================================
// Tests — every tool driven through a ToolRegistry over one shared in-memory Db
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{ToolCall, ToolRegistry};
    use std::sync::{Arc, Mutex};

    /// A fresh in-memory shared Db.
    fn shared_db() -> decibel_store::Db {
        decibel_store::Db(Arc::new(Mutex::new(decibel_store::open_memory())))
    }

    /// Share the inner Arc into another `Db` handle (Db is not `Clone`).
    fn handle(db: &decibel_store::Db) -> decibel_store::Db {
        decibel_store::Db(db.0.clone())
    }

    /// A registry with every kg.rs tool, all sharing `db`.
    fn registry(db: &decibel_store::Db) -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(KgNodeTool::new(handle(db))));
        reg.register(Arc::new(KgEdgeTool::new(handle(db))));
        reg.register(Arc::new(MarkCrownJewelTool::new(handle(db))));
        reg.register(Arc::new(KgQueryTool::new(handle(db))));
        reg.register(Arc::new(KgStatsTool::new(handle(db))));
        reg.register(Arc::new(KgNeighborsTool::new(handle(db))));
        reg.register(Arc::new(KgIngestTool::new(handle(db))));
        reg.register(Arc::new(PlanChainsTool::new(handle(db))));
        reg.register(Arc::new(PromoteChainTool::new(handle(db))));
        reg.register(Arc::new(ImpactAnalysisTool::new(handle(db))));
        reg.register(Arc::new(UnexploredSurfaceTool::new(handle(db))));
        reg.register(Arc::new(CredentialReachabilityTool::new(handle(db))));
        reg.register(Arc::new(RecordFindingTool::new(handle(db))));
        reg.register(Arc::new(CvssScoreTool::new(handle(db))));
        reg.register(Arc::new(ReportExecutiveTool::new(handle(db))));
        reg
    }

    async fn call(reg: &ToolRegistry, name: &str, args: Value) -> decibel_tools::ToolResult {
        reg.execute(
            ToolCall { call_id: CallId::from("c1"), name: name.into(), arguments: args },
            &ExecCtx::new(),
        )
        .await
    }

    #[tokio::test]
    async fn kg_node_edge_query_stats_neighbors_roundtrip() {
        let db = shared_db();
        let reg = registry(&db);

        // A node round-trips (id returned, in-vocab → no warning).
        let n = call(&reg, "kg_node", json!({ "kind": "Host", "label": "app01" })).await;
        assert!(!n.is_error, "kg_node failed: {:?}", n.content);
        let nv = n.value.unwrap();
        assert!(nv["id"].as_str().is_some());
        assert!(nv["warning"].is_null(), "in-vocab kind should not warn");

        // An out-of-vocab kind is accepted with a warning (non-strict default).
        let odd = call(&reg, "kg_node", json!({ "kind": "Weirdo", "label": "x" })).await;
        assert!(odd.value.unwrap()["warning"].as_str().is_some());

        // An edge upserts both endpoints and round-trips.
        let e = call(&reg, "kg_edge", json!({
            "src_kind": "Host", "src": "app01", "rel": "RUNS",
            "dst_kind": "Service", "dst": "app01:80/http"
        })).await;
        assert!(!e.is_error, "kg_edge failed: {:?}", e.content);

        // kg_query sees the Host node.
        let q = call(&reg, "kg_query", json!({ "kind": "Host" })).await;
        let qv = q.value.unwrap();
        assert_eq!(qv["count"], 1);
        assert_eq!(qv["nodes"][0]["label"], "app01");

        // kg_stats counts 3 nodes (Host, Weirdo, Service) + 1 edge.
        let s = call(&reg, "kg_stats", json!({})).await;
        let sv = s.value.unwrap();
        assert_eq!(sv["nodes"], 3);
        assert_eq!(sv["edges"], 1);

        // kg_neighbors resolves app01's out-neighbour deterministically.
        let nb = call(&reg, "kg_neighbors", json!({ "kind": "Host", "label": "app01", "direction": "out" })).await;
        let nbv = nb.value.unwrap();
        assert_eq!(nbv["count"], 1);
        assert_eq!(nbv["neighbors"][0]["label"], "app01:80/http");
    }

    #[tokio::test]
    async fn crown_jewel_chains_impact_and_findings() {
        let db = shared_db();
        let reg = registry(&db);

        // Mark a crown jewel and wire an Entrypoint→CrownJewel exploit edge.
        let cj = call(&reg, "mark_crown_jewel", json!({ "label": "domain-admin", "note": "the DC" })).await;
        assert!(cj.value.unwrap()["id"].as_str().is_some());
        call(&reg, "kg_edge", json!({
            "src_kind": "Entrypoint", "src": "http://app01/", "rel": "EXPLOITS",
            "dst_kind": "CrownJewel", "dst": "domain-admin"
        })).await;

        // plan_chains finds the entry→jewel route.
        let pc = call(&reg, "plan_chains", json!({})).await;
        let pcv = pc.value.unwrap();
        assert!(pcv["count"].as_u64().unwrap() >= 1, "expected a chain: {pcv}");
        assert_eq!(pcv["chains"][0]["path"][0], "http://app01/");

        // promote_chain materializes an AttackPath node.
        let pr = call(&reg, "promote_chain", json!({ "entry": "http://app01/", "crown_jewel": "domain-admin" })).await;
        assert!(pr.value.unwrap()["attack_path"].as_str().is_some());

        // impact_analysis from the entrypoint reaches the crown jewel.
        let ia = call(&reg, "impact_analysis", json!({ "node": "http://app01/" })).await;
        let iav = ia.value.unwrap();
        assert!(iav["crown_jewels_reached"].as_array().unwrap().iter().any(|j| j.as_str() == Some("domain-admin")));

        // record_finding writes a row and a traversable Finding node.
        let rf = call(&reg, "record_finding", json!({
            "severity": "high", "title": "SQLi in /login", "target": "app01", "source_tool": "sqlmap"
        })).await;
        assert!(!rf.is_error, "record_finding failed: {:?}", rf.content);
        assert_eq!(rf.value.unwrap()["severity"], "high");
        let fq = call(&reg, "kg_query", json!({ "kind": "Finding" })).await;
        assert_eq!(fq.value.unwrap()["count"], 1);
    }

    #[tokio::test]
    async fn ingest_credentials_unexplored_cvss_and_report() {
        let db = shared_db();
        let reg = registry(&db);

        // kg_ingest a native port-scan payload → Host + Service + Entrypoint.
        let ing = call(&reg, "kg_ingest", json!({
            "tool": "port-scan",
            "json": r#"{"target":"10.0.0.5","open_ports":[{"port":80,"service":"http"}]}"#
        })).await;
        let iv = ing.value.unwrap();
        assert!(iv["nodes"].as_u64().unwrap() >= 3, "ingest nodes: {iv}");
        assert!(iv["edges"].as_u64().unwrap() >= 2, "ingest edges: {iv}");

        // The Service has no HAS_VULN → it surfaces as unexplored.
        let un = call(&reg, "unexplored_surface", json!({})).await;
        assert!(un.value.unwrap()["count"].as_u64().unwrap() >= 1);

        // credential_reachability: cred → user → admin-to a DC.
        call(&reg, "kg_edge", json!({
            "src_kind": "Credential", "src": "svc_sql:hash", "rel": "AUTHENTICATES_TO",
            "dst_kind": "ADUser", "dst": "SVC_SQL"
        })).await;
        call(&reg, "kg_edge", json!({
            "src_kind": "ADUser", "src": "SVC_SQL", "rel": "ADMIN_TO",
            "dst_kind": "ADComputer", "dst": "DC01"
        })).await;
        let cr = call(&reg, "credential_reachability", json!({})).await;
        assert_eq!(cr.value.unwrap()["count"], 1);

        // cvss_score computes the classic full-critical vector = 9.8.
        let cv = call(&reg, "cvss_score", json!({ "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" })).await;
        let cvv = cv.value.unwrap();
        assert_eq!(cvv["base_score"], 9.8);
        assert_eq!(cvv["severity"], "Critical");

        // report_executive renders a markdown summary.
        call(&reg, "record_finding", json!({ "severity": "critical", "title": "RCE", "target": "10.0.0.5" })).await;
        let rep = call(&reg, "report_executive", json!({})).await;
        let md = rep.value.unwrap();
        assert!(md["markdown"].as_str().unwrap().contains("# Executive Summary"));
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let db = shared_db();
        let reg = registry(&db);
        let r = call(&reg, "kg_node", json!({ "kind": "Host" })).await; // no label
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
