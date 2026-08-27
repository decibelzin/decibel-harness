//! Model-facing [`Tool`] wrappers over `decibel_store::opplan` — the OPPLAN
//! objective tree (CRUD) plus the **kill-chain gate** enforced inside
//! `update_objective` (recon-before-exploit, blocked_by, don't-give-up,
//! parent-completion, and the vulnresearch stage-gates).
//!
//! Each tool holds a shared [`decibel_store::Db`] (an `Arc<Mutex<Connection>>`;
//! see [`OpplanTool::new`] callers) and is **engagement-scoped**: every call
//! accepts an optional `engagement` string (default `"default"`) and runs
//! `ensure_engagement` first so the row's foreign keys stay valid before any
//! objective write. The store fns are synchronous rusqlite calls, so each
//! `execute` locks the connection, does its work, and returns — no `.await` is
//! ever held across the lock guard.
//!
//! Arg names and semantics mirror the shared Decepticon dispatcher's
//! `add_objective` / `update_objective` / `get_objective` / `list_objectives` /
//! `objective_expand` / `objective_collapse` / `load_opplan` arms exactly.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_store::{ensure_engagement, opplan, Db};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_str_opt};

/// The engagement partition every objective is scoped to when the model names none.
const DEFAULT_ENGAGEMENT: &str = "default";

/// The `engagement` argument, defaulting to `"default"`.
fn engagement_of(args: &Value) -> String {
    arg_str_opt(args, "engagement").unwrap_or_else(|| DEFAULT_ENGAGEMENT.to_string())
}

/// Read an argument as an array of strings (absent / non-array → empty).
fn arg_str_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Serialize a store value into the canonical tool value, mapping a serde failure
/// to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Map the store's `Err(String)` into a `ToolError::Execution`.
fn store_err(e: String) -> ToolError {
    ToolError::execution(e)
}

/// A short `OBJ-NNN [status] phase · title` line from a serialized `Objective`.
fn objective_line(v: &Value) -> String {
    let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
    let status = v.get("status").and_then(Value::as_str).unwrap_or("");
    let phase = v.get("phase").and_then(Value::as_str).unwrap_or("");
    let title = v.get("title").and_then(Value::as_str).unwrap_or("");
    format!("{id} [{status}] {phase} · {title}")
}

// ---------------------------------------------------------------------------
// add_objective
// ---------------------------------------------------------------------------

/// Add an objective to the engagement's OPPLAN tree.
pub struct AddObjectiveTool {
    db: Db,
}

impl AddObjectiveTool {
    pub fn new(db: Db) -> Self {
        AddObjectiveTool { db }
    }
}

#[async_trait]
impl Tool for AddObjectiveTool {
    fn name(&self) -> &str {
        "add_objective"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "add_objective".into(),
            description: "Add an objective to the engagement's OPPLAN tree. New objectives start \
                'pending'. `blocked_by` names sibling objective ids that must complete before this \
                one may start; `parent_id` nests it under another objective (decomposition). Build \
                recon objectives first — the kill-chain gate refuses to START an exploit/post \
                objective until a recon objective is completed."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." },
                    "phase": { "type": "string", "description": "Kill-chain phase label, free text (e.g. \"Recon\", \"Exploitation\", \"Post-Exploitation\"). Classified for the gate." },
                    "title": { "type": "string", "description": "What the objective is." },
                    "priority": { "type": "integer", "description": "Lower = earlier in the roster (default 100)." },
                    "blocked_by": { "type": "array", "items": { "type": "string" }, "description": "Objective ids that must be 'completed' first." },
                    "parent_id": { "type": "string", "description": "Parent objective id to nest under (optional)." },
                    "notes": { "type": "string", "description": "Free-form notes (optional)." }
                },
                "required": ["title"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let title = arg_str(&arguments, "title")?;
        let phase = arg_str_opt(&arguments, "phase").unwrap_or_default();
        let priority = arguments.get("priority").and_then(Value::as_i64).unwrap_or(100);
        let blocked_by = arg_str_array(&arguments, "blocked_by");
        let parent_id = arg_str_opt(&arguments, "parent_id");
        let notes = arg_str_opt(&arguments, "notes").unwrap_or_default();

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let obj = opplan::add_objective(
            &conn,
            &engagement,
            &phase,
            &title,
            priority,
            &blocked_by,
            parent_id.as_deref(),
            &notes,
        )
        .map_err(store_err)?;
        drop(conn);
        to_value(obj)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(format!("add_objective: {}", objective_line(value)))]
    }
}

// ---------------------------------------------------------------------------
// update_objective
// ---------------------------------------------------------------------------

/// Update an objective's status / notes / priority. Status transitions run the
/// kill-chain gate before the write.
pub struct UpdateObjectiveTool {
    db: Db,
}

impl UpdateObjectiveTool {
    pub fn new(db: Db) -> Self {
        UpdateObjectiveTool { db }
    }
}

#[async_trait]
impl Tool for UpdateObjectiveTool {
    fn name(&self) -> &str {
        "update_objective"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "update_objective".into(),
            description: "Update an objective's status, notes, and/or priority. A status change runs \
                the KILL-CHAIN GATE before writing — a violation returns an error and nothing is \
                written: (1) an exploit/post objective cannot go 'in-progress' until a recon \
                objective is 'completed'; (2) it cannot start while any 'blocked_by' objective is \
                not 'completed'; (3) an exploit/post objective cannot be 'blocked' while the \
                knowledge graph holds observations (re-scope instead); (4) a parent cannot 'complete' \
                while a child is non-terminal; plus vulnresearch stage-gates. Statuses: pending, \
                in-progress, completed, blocked, cancelled. Omitted fields are left unchanged."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." },
                    "id": { "type": "string", "description": "Objective id (e.g. OBJ-001)." },
                    "status": { "type": "string", "description": "New status: pending|in-progress|completed|blocked|cancelled (gate-checked)." },
                    "notes": { "type": "string", "description": "Replace the objective's notes (optional)." },
                    "priority": { "type": "integer", "description": "New priority; lower sorts earlier (optional)." }
                },
                "required": ["id"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let id = arg_str(&arguments, "id")?;
        let status = arg_str_opt(&arguments, "status");
        let notes = arg_str_opt(&arguments, "notes");
        let priority = arguments.get("priority").and_then(Value::as_i64);

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let obj = opplan::update_objective(
            &conn,
            &engagement,
            &id,
            status.as_deref(),
            notes.as_deref(),
            priority,
        )
        .map_err(store_err)?;
        drop(conn);
        to_value(obj)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(format!("update_objective: {}", objective_line(value)))]
    }
}

// ---------------------------------------------------------------------------
// get_objective
// ---------------------------------------------------------------------------

/// Fetch a single objective by id (or `null` when it does not exist).
pub struct GetObjectiveTool {
    db: Db,
}

impl GetObjectiveTool {
    pub fn new(db: Db) -> Self {
        GetObjectiveTool { db }
    }
}

#[async_trait]
impl Tool for GetObjectiveTool {
    fn name(&self) -> &str {
        "get_objective"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "get_objective".into(),
            description: "Fetch one objective by id from the engagement's OPPLAN tree. Returns the \
                objective (id, phase, title, status, priority, blocked_by, parent_id, notes) or null \
                if no objective has that id."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." },
                    "id": { "type": "string", "description": "Objective id (e.g. OBJ-001)." }
                },
                "required": ["id"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let id = arg_str(&arguments, "id")?;

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let obj = opplan::get_objective(&conn, &engagement, &id).map_err(store_err)?;
        drop(conn);
        to_value(obj)
    }

    fn render(&self, arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        if value.is_null() {
            let id = arguments.get("id").and_then(Value::as_str).unwrap_or("?");
            return vec![ContentBlock::text(format!("get_objective: {id} not found"))];
        }
        vec![ContentBlock::text(format!("get_objective: {}", objective_line(value)))]
    }
}

// ---------------------------------------------------------------------------
// list_objectives
// ---------------------------------------------------------------------------

/// List every objective for an engagement, in roster order.
pub struct ListObjectivesTool {
    db: Db,
}

impl ListObjectivesTool {
    pub fn new(db: Db) -> Self {
        ListObjectivesTool { db }
    }
}

#[async_trait]
impl Tool for ListObjectivesTool {
    fn name(&self) -> &str {
        "list_objectives"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "list_objectives".into(),
            description: "List all objectives for the engagement, ordered by (priority, id) — the \
                roster order to walk. Returns { count, objectives: [...] }."
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

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let objs = opplan::list_objectives(&conn, &engagement).map_err(store_err)?;
        drop(conn);
        Ok(json!({ "count": objs.len(), "objectives": objs }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let objs = value.get("objectives").and_then(Value::as_array).unwrap_or(&empty);
        if objs.is_empty() {
            return vec![ContentBlock::text("list_objectives: (empty)".to_string())];
        }
        let mut out = format!("list_objectives: {} objective(s)\n", objs.len());
        for o in objs {
            out.push_str(&format!("  {}\n", objective_line(o)));
        }
        vec![ContentBlock::text(out)]
    }
}

// ---------------------------------------------------------------------------
// objective_expand
// ---------------------------------------------------------------------------

/// Decompose an objective into child objectives (children inherit the parent's phase).
pub struct ObjectiveExpandTool {
    db: Db,
}

impl ObjectiveExpandTool {
    pub fn new(db: Db) -> Self {
        ObjectiveExpandTool { db }
    }
}

#[async_trait]
impl Tool for ObjectiveExpandTool {
    fn name(&self) -> &str {
        "objective_expand"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "objective_expand".into(),
            description: "Decompose a parent objective into child objectives, one per title in \
                `children`. Children inherit the parent's phase and are priced just after it so they \
                sort under it. Returns the created children."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." },
                    "parent_id": { "type": "string", "description": "Objective id to decompose (e.g. OBJ-001)." },
                    "children": { "type": "array", "items": { "type": "string" }, "description": "Child objective titles." }
                },
                "required": ["parent_id"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let parent_id = arg_str(&arguments, "parent_id")?;
        // Mirror the dispatcher: each child title inherits the parent's phase (empty phase → inherit).
        let children: Vec<(String, String)> = arg_str_array(&arguments, "children")
            .into_iter()
            .map(|t| (String::new(), t))
            .collect();

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let kids = opplan::expand_objective(&conn, &engagement, &parent_id, &children).map_err(store_err)?;
        drop(conn);
        Ok(json!({ "parent_id": parent_id, "count": kids.len(), "children": kids }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let parent = value.get("parent_id").and_then(Value::as_str).unwrap_or("?");
        let empty = Vec::new();
        let kids = value.get("children").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("objective_expand: {parent} → {} child(ren)\n", kids.len());
        for k in kids {
            out.push_str(&format!("  {}\n", objective_line(k)));
        }
        vec![ContentBlock::text(out)]
    }
}

// ---------------------------------------------------------------------------
// objective_collapse
// ---------------------------------------------------------------------------

/// Re-collapse an objective: delete its children. Returns how many were removed.
pub struct ObjectiveCollapseTool {
    db: Db,
}

impl ObjectiveCollapseTool {
    pub fn new(db: Db) -> Self {
        ObjectiveCollapseTool { db }
    }
}

#[async_trait]
impl Tool for ObjectiveCollapseTool {
    fn name(&self) -> &str {
        "objective_collapse"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "objective_collapse".into(),
            description: "Re-collapse an objective by deleting its direct children (undo an expand). \
                Returns { removed } — the number of child objectives deleted."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "engagement": { "type": "string", "description": "Engagement partition (default \"default\")." },
                    "parent_id": { "type": "string", "description": "Objective id whose children to remove." }
                },
                "required": ["parent_id"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let engagement = engagement_of(&arguments);
        let parent_id = arg_str(&arguments, "parent_id")?;

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let removed = opplan::collapse_objective(&conn, &engagement, &parent_id).map_err(store_err)?;
        drop(conn);
        Ok(json!({ "parent_id": parent_id, "removed": removed }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let parent = value.get("parent_id").and_then(Value::as_str).unwrap_or("?");
        let removed = value.get("removed").and_then(Value::as_u64).unwrap_or(0);
        vec![ContentBlock::text(format!("objective_collapse: {parent} → removed {removed} child(ren)"))]
    }
}

// ---------------------------------------------------------------------------
// load_opplan
// ---------------------------------------------------------------------------

/// Render the objective tree as a compact catalog for the orchestrator prompt.
pub struct LoadOpplanTool {
    db: Db,
}

impl LoadOpplanTool {
    pub fn new(db: Db) -> Self {
        LoadOpplanTool { db }
    }
}

#[async_trait]
impl Tool for LoadOpplanTool {
    fn name(&self) -> &str {
        "load_opplan"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "load_opplan".into(),
            description: "Render the engagement's OPPLAN objective tree as a compact catalog (roots \
                first, children indented; each line shows id, status, phase, title, and unresolved \
                blocked_by). Returns { catalog } for pasting into the orchestrator's plan block."
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

        let conn = self.db.0.lock().map_err(|_| ToolError::execution("decibel-store mutex poisoned"))?;
        ensure_engagement(&conn, &engagement).map_err(store_err)?;
        let catalog = opplan::render_catalog(&conn, &engagement).map_err(store_err)?;
        drop(conn);
        Ok(json!({ "catalog": catalog }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let catalog = value.get("catalog").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(catalog.to_string())]
    }
}

// ---------------------------------------------------------------------------
// Tests — drive each tool through a ToolRegistry over one shared in-memory Db.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{ToolCall, ToolRegistry};
    use std::sync::{Arc, Mutex};

    /// A fresh in-memory store handle.
    fn mem_db() -> Db {
        Db(Arc::new(Mutex::new(decibel_store::open_memory())))
    }

    /// A registry with every OPPLAN tool, all sharing the one `db` (inner Arc cloned).
    fn registry_with(db: &Db) -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(AddObjectiveTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(UpdateObjectiveTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(GetObjectiveTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(ListObjectivesTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(ObjectiveExpandTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(ObjectiveCollapseTool::new(Db(db.0.clone()))));
        reg.register(Arc::new(LoadOpplanTool::new(Db(db.0.clone()))));
        reg
    }

    async fn call(reg: &ToolRegistry, name: &str, args: Value) -> decibel_tools::ToolResult {
        reg.execute(
            ToolCall { call_id: CallId::from("c1"), name: name.to_string(), arguments: args },
            &ExecCtx::new(),
        )
        .await
    }

    #[tokio::test]
    async fn add_get_list_roundtrip() {
        let db = mem_db();
        let reg = registry_with(&db);

        let added = call(&reg, "add_objective", json!({ "phase": "Recon", "title": "enumerate host" })).await;
        assert!(!added.is_error, "add failed: {:?}", added.content);
        let v = added.value.unwrap();
        assert_eq!(v["id"], "OBJ-001");
        assert_eq!(v["status"], "pending");
        assert_eq!(v["title"], "enumerate host");

        // get round-trips the same objective.
        let got = call(&reg, "get_objective", json!({ "id": "OBJ-001" })).await;
        assert!(!got.is_error);
        assert_eq!(got.value.unwrap()["title"], "enumerate host");

        // A missing objective returns null, not an error.
        let missing = call(&reg, "get_objective", json!({ "id": "OBJ-404" })).await;
        assert!(!missing.is_error);
        assert!(missing.value.unwrap().is_null());

        // list wraps in an object (never a bare array) and counts.
        call(&reg, "add_objective", json!({ "phase": "Exploit", "title": "web SQLi" })).await;
        let listed = call(&reg, "list_objectives", json!({})).await;
        let lv = listed.value.unwrap();
        assert_eq!(lv["count"], 2);
        assert_eq!(lv["objectives"].as_array().unwrap().len(), 2);
        assert_eq!(lv["objectives"][0]["id"], "OBJ-001"); // priority/roster order
    }

    #[tokio::test]
    async fn update_enforces_kill_chain_gate() {
        let db = mem_db();
        let reg = registry_with(&db);

        call(&reg, "add_objective", json!({ "phase": "Recon", "title": "enumerate" })).await;
        let exploit = call(&reg, "add_objective", json!({ "phase": "Exploit", "title": "SQLi" })).await;
        let exploit_id = exploit.value.unwrap()["id"].as_str().unwrap().to_string();

        // The exploit objective cannot start before recon completes — the gate rejects it.
        let blocked = call(&reg, "update_objective", json!({ "id": exploit_id, "status": "in-progress" })).await;
        assert!(blocked.is_error, "gate should have blocked the exploit start");
        assert_eq!(blocked.error_code.as_deref(), Some("EXEC_ERROR"));

        // Recon can start and complete freely.
        let s1 = call(&reg, "update_objective", json!({ "id": "OBJ-001", "status": "in-progress" })).await;
        assert!(!s1.is_error);
        let s2 = call(&reg, "update_objective", json!({ "id": "OBJ-001", "status": "completed" })).await;
        assert!(!s2.is_error);
        assert_eq!(s2.value.unwrap()["status"], "completed");

        // Now the exploit objective may start.
        let ok = call(&reg, "update_objective", json!({ "id": "OBJ-002", "status": "in-progress" })).await;
        assert!(!ok.is_error, "exploit should start after recon completes: {:?}", ok.content);
        assert_eq!(ok.value.unwrap()["status"], "in-progress");
    }

    #[tokio::test]
    async fn expand_collapse_and_load_catalog() {
        let db = mem_db();
        let reg = registry_with(&db);

        let parent = call(&reg, "add_objective", json!({ "phase": "Recon", "title": "parent" })).await;
        let pid = parent.value.unwrap()["id"].as_str().unwrap().to_string();

        let expanded = call(&reg, "objective_expand", json!({ "parent_id": pid, "children": ["sub a", "sub b"] })).await;
        assert!(!expanded.is_error, "expand failed: {:?}", expanded.content);
        let ev = expanded.value.unwrap();
        assert_eq!(ev["count"], 2);
        let kids = ev["children"].as_array().unwrap();
        assert_eq!(kids[0]["parent_id"], "OBJ-001");
        assert_eq!(kids[0]["phase"], "Recon"); // inherited from parent

        // The catalog shows the tree, child indented.
        let cat = call(&reg, "load_opplan", json!({})).await;
        let catalog = cat.value.unwrap()["catalog"].as_str().unwrap().to_string();
        assert!(catalog.contains("OBJ-001"));
        assert!(catalog.contains("  - [pending] OBJ-002"));

        // collapse removes the children.
        let collapsed = call(&reg, "objective_collapse", json!({ "parent_id": "OBJ-001" })).await;
        assert!(!collapsed.is_error);
        assert_eq!(collapsed.value.unwrap()["removed"], 2);
        let after = call(&reg, "list_objectives", json!({})).await;
        assert_eq!(after.value.unwrap()["count"], 1);
    }

    #[tokio::test]
    async fn engagement_scoping_isolates_and_missing_required_arg_is_invalid() {
        let db = mem_db();
        let reg = registry_with(&db);

        // Two engagements keep separate OBJ-NNN sequences.
        call(&reg, "add_objective", json!({ "engagement": "eng-a", "phase": "Recon", "title": "a" })).await;
        call(&reg, "add_objective", json!({ "engagement": "eng-b", "phase": "Recon", "title": "b" })).await;
        let a = call(&reg, "list_objectives", json!({ "engagement": "eng-a" })).await;
        let b = call(&reg, "list_objectives", json!({ "engagement": "eng-b" })).await;
        assert_eq!(a.value.unwrap()["count"], 1);
        assert_eq!(b.value.unwrap()["count"], 1);
        // The default engagement saw neither.
        let def = call(&reg, "list_objectives", json!({})).await;
        assert_eq!(def.value.unwrap()["count"], 0);

        // A missing required arg surfaces as INVALID_ARGS (not degraded/swallowed).
        let bad = call(&reg, "add_objective", json!({ "phase": "Recon" })).await;
        assert!(bad.is_error);
        assert_eq!(bad.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
