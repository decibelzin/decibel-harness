//! Engagement-planning bundle: the 8 documents the interviewer (Soundwave)
//! produces before an engagement goes live, plus the validation that gates the
//! planning → operator handoff, and the two model-facing [`Tool`]s that drive it.
//!
//! The schema knowledge + cross-document invariants are vendored faithfully from
//! Decepticon's `planning` crate (deps `serde_json` only — pure and offline, no
//! filesystem and no network). The tools wrap that logic:
//!   - `validate_plan_doc` — validate a single `plan/*.json` document against its
//!     schema (the per-document check the upstream dispatcher runs inline on every
//!     `write_file` to a plan path, lifted into a standalone tool);
//!   - `complete_engagement_planning` — the terminal handoff signal: gather the 8
//!     documents from the workspace `plan/` directory (via [`ExecCtx::resolve`]),
//!     run every per-document schema check AND the five cross-document invariants,
//!     and report `{ ready, problems }` — plus, when the bundle validates, the
//!     parsed RoE `in_scope`/`out_of_scope` so the app can arm the RoE scope gate.
//!
//! The five cross-validation invariants (all must hold before handoff):
//!   1. ThreatProfile initial-access ⊆ RoE permitted_actions
//!   2. CONOPS kill-chain targets ⊆ RoE in_scope
//!   3. Cleanup lists every persistence mechanism named in CONOPS
//!   4. Abort has ≥1 EMERGENCY trigger
//!   5. DataHandling frameworks cover the RoE frameworks
//!
//! Validation is a guardrail, not a straitjacket: an invariant only fires when the
//! fields it references are actually present, so the agent is caught on real
//! contradictions without being blocked on optional detail.
//!
//! Divergences from the upstream `complete_engagement_planning` dispatcher arm
//! (all in service of "self-contained, no decepticon_store"):
//!   - the upstream arm returns `Err(...)` when the bundle is incomplete; this tool
//!     returns a canonical value `{ ready:false, problems:[...] }` instead, so the
//!     structured problems (and, on success, the parsed scope) live in the tool's
//!     `value` for the app/UI to read — the value/render split's whole point;
//!   - it does NOT write engagement readiness or scope into a store. It only
//!     *reports* the RoE `in_scope`/`out_of_scope`; the app arms the gate from that.

use std::collections::BTreeMap;

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_str_opt};

// =============================================================================
// Vendored planning schema + validators (Decepticon `planning` crate, faithful)
// =============================================================================

/// One of the eight engagement-planning documents, in write order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DocKind {
    Roe,
    ThreatProfile,
    Conops,
    Deconfliction,
    Contact,
    DataHandling,
    Abort,
    Cleanup,
}

/// The bundle in the fixed write order the interviewer must follow. Each entry is
/// `(workspace-relative path, kind)`; all live under `plan/` so the whole bundle is
/// one directory at intake.
pub const PLAN_DOCS: &[(&str, DocKind)] = &[
    ("plan/roe.json", DocKind::Roe),
    ("plan/threat-profile.json", DocKind::ThreatProfile),
    ("plan/conops.json", DocKind::Conops),
    ("plan/deconfliction.json", DocKind::Deconfliction),
    ("plan/contact.json", DocKind::Contact),
    ("plan/data-handling.json", DocKind::DataHandling),
    ("plan/abort.json", DocKind::Abort),
    ("plan/cleanup.json", DocKind::Cleanup),
];

impl DocKind {
    /// The canonical workspace-relative path for this document.
    pub fn path(self) -> &'static str {
        PLAN_DOCS.iter().find(|(_, k)| *k == self).map(|(p, _)| *p).unwrap_or("")
    }

    /// A short human label for summaries.
    pub fn label(self) -> &'static str {
        match self {
            DocKind::Roe => "Rules of Engagement",
            DocKind::ThreatProfile => "Threat Profile",
            DocKind::Conops => "CONOPS",
            DocKind::Deconfliction => "Deconfliction",
            DocKind::Contact => "Contacts",
            DocKind::DataHandling => "Data Handling",
            DocKind::Abort => "Abort Criteria",
            DocKind::Cleanup => "Cleanup",
        }
    }
}

/// Which planning document (if any) a workspace-relative path denotes. Tolerant of
/// a leading `./` and both slash directions so it matches however the agent writes
/// the path.
pub fn doc_for_path(rel: &str) -> Option<DocKind> {
    let norm = rel.trim_start_matches("./").replace('\\', "/").to_lowercase();
    PLAN_DOCS
        .iter()
        .find(|(p, _)| norm == *p || norm.ends_with(&format!("/{p}")))
        .map(|(_, k)| *k)
}

// --- small JSON helpers -------------------------------------------------------

fn arr<'a>(v: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
    v.get(key).and_then(Value::as_array)
}
fn nonempty_arr(v: &Value, key: &str) -> bool {
    arr(v, key).map(|a| !a.is_empty()).unwrap_or(false)
}
fn nonempty_str(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false)
}

/// The comparable label of an array element, whether it is a bare string or an
/// object carrying one of the usual name-ish keys. Lowercased + trimmed.
fn elem_label(v: &Value) -> Option<String> {
    let s = match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(_) => ["name", "target", "action", "technique", "framework", "mechanism", "phase", "value"]
            .iter()
            .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_string)),
        _ => None,
    };
    s.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty())
}

fn labels(v: &Value, key: &str) -> Vec<String> {
    arr(v, key).map(|a| a.iter().filter_map(elem_label).collect()).unwrap_or_default()
}

/// Does `needle` match any of `hay` by loose containment (either direction)? Used
/// for scope/permission checks where "web app" should satisfy in-scope "web".
fn loosely_covered(needle: &str, hay: &[String]) -> bool {
    hay.iter().any(|h| h == needle || h.contains(needle) || needle.contains(h.as_str()))
}

// --- per-document validation --------------------------------------------------

/// Validate a single document against its schema. Returns the list of problems
/// (empty = valid). Run on every plan-doc write so a malformed document is caught
/// the moment it is written, never bounced to the operator.
pub fn validate_doc(kind: DocKind, v: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    if !v.is_object() {
        errs.push(format!("{}: document must be a JSON object", kind.label()));
        return errs;
    }
    // Push a "must be a non-empty array" error for `key` unless it holds one.
    macro_rules! need_arr {
        ($key:expr) => {
            if !nonempty_arr(v, $key) {
                errs.push(format!("{}: `{}` must be a non-empty array", kind.label(), $key));
            }
        };
    }
    match kind {
        DocKind::Roe => {
            need_arr!("in_scope");
            need_arr!("permitted_actions");
        }
        DocKind::ThreatProfile => {
            if !nonempty_str(v, "adversary") {
                errs.push(format!("{}: `adversary` must be a non-empty string", kind.label()));
            }
            if arr(v, "initial_access").is_none() {
                errs.push(format!("{}: `initial_access` must be an array", kind.label()));
            }
        }
        DocKind::Conops => need_arr!("kill_chain"),
        DocKind::Deconfliction => need_arr!("procedures"),
        DocKind::Contact => {
            need_arr!("contacts");
            // Each contact needs a name and at least one reach channel.
            for (i, c) in arr(v, "contacts").into_iter().flatten().enumerate() {
                let has_name = c.get("name").and_then(Value::as_str).map(|s| !s.trim().is_empty()).unwrap_or(false);
                let has_reach = ["channel", "email", "phone", "slack"].iter().any(|k| nonempty_str(c, k));
                if !has_name || !has_reach {
                    errs.push(format!(
                        "{}: contact #{} needs a `name` and a reach channel (channel/email/phone)",
                        kind.label(),
                        i + 1
                    ));
                }
            }
        }
        DocKind::DataHandling => {
            if !nonempty_str(v, "classification") {
                errs.push(format!("{}: `classification` must be a non-empty string", kind.label()));
            }
            need_arr!("frameworks");
        }
        DocKind::Abort => need_arr!("triggers"),
        DocKind::Cleanup => {
            // Persistence may legitimately be empty (a footprint-free engagement),
            // but the key must be present so the cross-check is meaningful; artifacts
            // is where residue to remove is listed.
            if arr(v, "persistence").is_none() {
                errs.push(format!("{}: `persistence` must be an array (may be empty)", kind.label()));
            }
            if arr(v, "artifacts").is_none() {
                errs.push(format!("{}: `artifacts` must be an array (may be empty)", kind.label()));
            }
        }
    }
    errs
}

// --- cross-document invariants ------------------------------------------------

/// Validate the whole bundle: every document present + valid on its own, then the
/// five cross-document invariants. Returns the list of problems (empty = the
/// handoff may proceed). Missing documents are reported by their path so the agent
/// knows exactly what to write next.
pub fn validate_bundle(docs: &BTreeMap<DocKind, Value>) -> Vec<String> {
    let mut errs = Vec::new();

    // 0. Presence + per-doc validity.
    for (path, kind) in PLAN_DOCS {
        match docs.get(kind) {
            None => errs.push(format!("missing document: {path}")),
            Some(v) => errs.extend(validate_doc(*kind, v)),
        }
    }
    // If anything is missing/malformed, cross-checks would be noise — stop here.
    if !errs.is_empty() {
        return errs;
    }

    let roe = &docs[&DocKind::Roe];
    let tp = &docs[&DocKind::ThreatProfile];
    let conops = &docs[&DocKind::Conops];
    let dh = &docs[&DocKind::DataHandling];
    let abort = &docs[&DocKind::Abort];
    let cleanup = &docs[&DocKind::Cleanup];

    // 1. ThreatProfile initial-access ⊆ RoE permitted_actions.
    let permitted = labels(roe, "permitted_actions");
    for ia in labels(tp, "initial_access") {
        if !loosely_covered(&ia, &permitted) {
            errs.push(format!("ThreatProfile initial-access `{ia}` is not in RoE permitted_actions"));
        }
    }

    // 2. CONOPS kill-chain targets ⊆ RoE in_scope. Only kill-chain steps that name
    //    a concrete `target` are checked (a phase label like "Recon" names none).
    let in_scope = labels(roe, "in_scope");
    for step in arr(conops, "kill_chain").into_iter().flatten() {
        if let Some(t) = step.get("target").and_then(Value::as_str) {
            let t = t.trim().to_lowercase();
            if !t.is_empty() && !loosely_covered(&t, &in_scope) {
                errs.push(format!("CONOPS kill-chain target `{t}` is not in RoE in_scope"));
            }
        }
    }

    // 3. Cleanup lists every persistence mechanism named in CONOPS.
    let conops_persist = labels(conops, "persistence");
    if !conops_persist.is_empty() {
        let cleaned = labels(cleanup, "persistence");
        for p in &conops_persist {
            if !loosely_covered(p, &cleaned) {
                errs.push(format!("Cleanup does not account for CONOPS persistence mechanism `{p}`"));
            }
        }
    }

    // 4. Abort has ≥1 EMERGENCY trigger.
    let has_emergency = arr(abort, "triggers").into_iter().flatten().any(|t| {
        t.get("level").and_then(Value::as_str).map(|l| l.eq_ignore_ascii_case("emergency")).unwrap_or(false)
    });
    if !has_emergency {
        errs.push("Abort criteria must include at least one EMERGENCY trigger".to_string());
    }

    // 5. DataHandling frameworks cover the RoE frameworks (only if RoE names any).
    let roe_frameworks = labels(roe, "frameworks");
    if !roe_frameworks.is_empty() {
        let dh_frameworks = labels(dh, "frameworks");
        for f in &roe_frameworks {
            if !loosely_covered(f, &dh_frameworks) {
                errs.push(format!("DataHandling frameworks omit RoE framework `{f}`"));
            }
        }
    }

    errs
}

/// A one-line-per-document summary table (Markdown) for the handoff message.
/// Renders the count of the headline collection in each document so the operator
/// sees the shape of what was produced at a glance.
pub fn bundle_summary(docs: &BTreeMap<DocKind, Value>) -> String {
    let count = |k: DocKind, key: &str| docs.get(&k).and_then(|v| arr(v, key)).map(|a| a.len()).unwrap_or(0);
    let mut out = String::from("| Document | Path | Summary |\n|---|---|---|\n");
    for (path, kind) in PLAN_DOCS {
        let summary = match kind {
            DocKind::Roe => format!(
                "{} in-scope, {} permitted actions",
                count(*kind, "in_scope"),
                count(*kind, "permitted_actions")
            ),
            DocKind::ThreatProfile => format!("{} initial-access vectors", count(*kind, "initial_access")),
            DocKind::Conops => format!("{}-step kill chain", count(*kind, "kill_chain")),
            DocKind::Deconfliction => format!("{} procedures", count(*kind, "procedures")),
            DocKind::Contact => format!("{} contacts", count(*kind, "contacts")),
            DocKind::DataHandling => format!("{} frameworks", count(*kind, "frameworks")),
            DocKind::Abort => format!("{} triggers", count(*kind, "triggers")),
            DocKind::Cleanup => format!(
                "{} persistence, {} artifacts",
                count(*kind, "persistence"),
                count(*kind, "artifacts")
            ),
        };
        out.push_str(&format!("| {} | `{}` | {} |\n", kind.label(), path, summary));
    }
    out
}

// =============================================================================
// validate_plan_doc — per-document schema check for one `plan/*.json`
// =============================================================================

/// Validate a single engagement-planning document against its schema.
pub struct ValidatePlanDocTool;

#[async_trait]
impl Tool for ValidatePlanDocTool {
    fn name(&self) -> &str {
        "validate_plan_doc"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "validate_plan_doc".into(),
            description: "Validate ONE engagement-planning document against its schema (the same \
                per-document check that gates a plan-doc write). `path` selects which of the 8 plan \
                documents to check (plan/roe.json, plan/threat-profile.json, plan/conops.json, \
                plan/deconfliction.json, plan/contact.json, plan/data-handling.json, plan/abort.json, \
                plan/cleanup.json). Pass inline `content` to validate JSON you have not written yet; \
                omit it to read + check the file already in the workspace. Returns `{valid, problems}`."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "One of the 8 plan-doc paths; selects the schema to check against." },
                    "content": { "type": "string", "description": "Optional inline JSON to validate; if omitted the file at `path` is read from the workspace." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = arg_str(&arguments, "path")?;
        // The path names the document, which fixes the schema. A path that is not one
        // of the eight cannot be schema-checked, so reject it as an argument error.
        let kind = doc_for_path(&path).ok_or_else(|| {
            ToolError::invalid_args(format!(
                "`{path}` is not one of the 8 planning documents (plan/roe.json, plan/threat-profile.json, \
                 plan/conops.json, plan/deconfliction.json, plan/contact.json, plan/data-handling.json, \
                 plan/abort.json, plan/cleanup.json)"
            ))
        })?;

        // Validate the caller's inline content, else read the document from the workspace.
        let content = match arg_str_opt(&arguments, "content") {
            Some(c) => c,
            None => {
                let resolved = ctx.resolve(&path);
                tokio::fs::read_to_string(&resolved)
                    .await
                    .map_err(|e| ToolError::execution(format!("cannot read {}: {e}", resolved.display())))?
            }
        };

        let parsed: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            // Invalid JSON is a validation problem the agent must fix, not a tool failure.
            Err(e) => {
                return Ok(json!({
                    "path": path,
                    "document": kind.label(),
                    "valid": false,
                    "problems": [format!("`{path}` is not valid JSON: {e}")],
                }));
            }
        };
        let problems = validate_doc(kind, &parsed);
        Ok(json!({
            "path": path,
            "document": kind.label(),
            "valid": problems.is_empty(),
            "problems": problems,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let doc = value.get("document").and_then(Value::as_str).unwrap_or("");
        let valid = value.get("valid").and_then(Value::as_bool).unwrap_or(false);
        if valid {
            return vec![ContentBlock::text(format!("validate_plan_doc [{doc}]: valid"))];
        }
        let empty = Vec::new();
        let problems = value.get("problems").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("validate_plan_doc [{doc}]: INVALID — {} problem(s)", problems.len());
        for p in problems {
            if let Some(s) = p.as_str() {
                out.push_str(&format!("\n  - {s}"));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

// =============================================================================
// complete_engagement_planning — validate the full bundle + report scope
// =============================================================================

/// Terminal planning signal: validate the 8-document bundle and, on success,
/// report the RoE scope so the app can arm the gate.
pub struct CompleteEngagementPlanningTool;

#[async_trait]
impl Tool for CompleteEngagementPlanningTool {
    fn name(&self) -> &str {
        "complete_engagement_planning"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "complete_engagement_planning".into(),
            description: "Terminal planning signal: validate the full 8-document engagement bundle in \
                the workspace `plan/` directory — each document's schema AND the cross-document \
                invariants (initial-access ⊆ permitted actions, kill-chain targets ⊆ in-scope, cleanup \
                covers persistence, ≥1 EMERGENCY abort trigger, data-handling frameworks cover RoE). \
                Returns `{ready, problems}`; when it validates, also returns the RoE `in_scope`/\
                `out_of_scope` so the engagement's scope gate can be armed, plus a summary table. Call \
                once, after all 8 documents are written."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {}
            }),
        }
    }

    async fn execute(&self, _arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        // Gather the 8 documents from the workspace. A doc that is missing or not
        // valid JSON is simply left out of the map — `validate_bundle` then reports
        // it by path, mirroring the upstream dispatcher's read-then-skip loop.
        let mut docs: BTreeMap<DocKind, Value> = BTreeMap::new();
        for (path, kind) in PLAN_DOCS {
            let resolved = ctx.resolve(path);
            if let Ok(bytes) = tokio::fs::read(&resolved).await {
                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                    docs.insert(*kind, v);
                }
            }
        }

        let problems = validate_bundle(&docs);
        let documents: Vec<&str> = PLAN_DOCS.iter().map(|(p, _)| *p).collect();

        if !problems.is_empty() {
            return Ok(json!({
                "ready": false,
                "problems": problems,
                "documents": documents,
            }));
        }

        // Bundle validates: surface the RoE scope so the app can arm the gate. Only
        // the in_scope / out_of_scope allowlists are reported (self-contained — no
        // store write); the app builds its Scope from these two arrays.
        let list = |key: &str| -> Vec<String> {
            docs.get(&DocKind::Roe)
                .and_then(|roe| roe.get(key))
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        let in_scope = list("in_scope");
        let out_of_scope = list("out_of_scope");
        let summary = bundle_summary(&docs);

        Ok(json!({
            "ready": true,
            "problems": [],
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "documents": documents,
            "summary": summary,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let ready = value.get("ready").and_then(Value::as_bool).unwrap_or(false);
        if ready {
            let in_scope = value.get("in_scope").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
            let out = value.get("out_of_scope").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
            let summary = value.get("summary").and_then(Value::as_str).unwrap_or("");
            return vec![ContentBlock::text(format!(
                "complete_engagement_planning: READY — engagement may hand off ({in_scope} in-scope, \
                 {out} out-of-scope target(s))\n{summary}"
            ))];
        }
        let empty = Vec::new();
        let problems = value.get("problems").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("complete_engagement_planning: NOT READY — {} problem(s)", problems.len());
        for p in problems {
            if let Some(s) = p.as_str() {
                out.push_str(&format!("\n  - {s}"));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

// =============================================================================
// Tests — vendored validator tests (paths fixed) + tool tests via a ToolRegistry
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use decibel_llm::CallId;
    use decibel_tools::{ToolCall, ToolRegistry, ToolResult};
    use std::path::Path;
    use std::sync::Arc;

    // --- vendored planning-validator tests (unchanged logic) -----------------

    fn valid_bundle() -> BTreeMap<DocKind, Value> {
        let mut m = BTreeMap::new();
        m.insert(DocKind::Roe, json!({
            "in_scope": ["10.0.0.0/24", "app.target.test"],
            "permitted_actions": ["recon", "exploitation", "lateral-movement"],
            "frameworks": ["PTES"],
        }));
        m.insert(DocKind::ThreatProfile, json!({
            "adversary": "APT-simulated",
            "initial_access": ["exploitation", "recon"],
        }));
        m.insert(DocKind::Conops, json!({
            "kill_chain": [
                { "phase": "Recon" },
                { "phase": "Exploitation", "target": "app.target.test" },
            ],
            "persistence": ["scheduled-task"],
        }));
        m.insert(DocKind::Deconfliction, json!({ "procedures": ["notify SOC before scanning"] }));
        m.insert(DocKind::Contact, json!({
            "contacts": [{ "name": "Blue Lead", "email": "soc@target.test" }],
        }));
        m.insert(DocKind::DataHandling, json!({
            "classification": "confidential",
            "frameworks": ["PTES", "GDPR"],
        }));
        m.insert(DocKind::Abort, json!({
            "triggers": [
                { "level": "WARNING", "condition": "prod latency spike" },
                { "level": "EMERGENCY", "condition": "unintended outage" },
            ],
        }));
        m.insert(DocKind::Cleanup, json!({
            "persistence": ["scheduled-task"],
            "artifacts": ["/tmp/loot"],
        }));
        m
    }

    #[test]
    fn path_mapping_round_trips_and_is_tolerant() {
        for (path, kind) in PLAN_DOCS {
            assert_eq!(doc_for_path(path), Some(*kind));
            assert_eq!(kind.path(), *path);
        }
        assert_eq!(doc_for_path("./plan/roe.json"), Some(DocKind::Roe));
        assert_eq!(doc_for_path("plan\\abort.json"), Some(DocKind::Abort));
        assert_eq!(doc_for_path("C:/ws/plan/conops.json"), Some(DocKind::Conops));
        assert_eq!(doc_for_path("notes.md"), None);
        assert_eq!(doc_for_path("plan/other.json"), None);
    }

    #[test]
    fn a_complete_faithful_bundle_validates() {
        let errs = validate_bundle(&valid_bundle());
        assert!(errs.is_empty(), "expected clean bundle, got: {errs:?}");
    }

    #[test]
    fn missing_documents_are_reported_by_path() {
        let mut b = valid_bundle();
        b.remove(&DocKind::Cleanup);
        b.remove(&DocKind::Abort);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.contains("plan/cleanup.json")));
        assert!(errs.iter().any(|e| e.contains("plan/abort.json")));
    }

    #[test]
    fn per_doc_validation_catches_shape_errors() {
        assert!(validate_doc(DocKind::Roe, &json!({ "in_scope": [] , "permitted_actions": ["x"]}))
            .iter().any(|e| e.contains("in_scope")));
        assert!(validate_doc(DocKind::Contact, &json!({ "contacts": [{ "name": "x" }] }))
            .iter().any(|e| e.contains("reach channel")));
        assert!(validate_doc(DocKind::Abort, &json!({ "triggers": [] }))
            .iter().any(|e| e.contains("triggers")));
        assert!(validate_doc(DocKind::Cleanup, &json!({ "persistence": [] , "artifacts": []})).is_empty());
    }

    #[test]
    fn invariant_1_initial_access_must_be_permitted() {
        let mut b = valid_bundle();
        b.get_mut(&DocKind::ThreatProfile).unwrap()["initial_access"] = json!(["phishing"]);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.contains("phishing") && e.contains("permitted_actions")), "{errs:?}");
    }

    #[test]
    fn invariant_2_killchain_targets_must_be_in_scope() {
        let mut b = valid_bundle();
        b.get_mut(&DocKind::Conops).unwrap()["kill_chain"] = json!([{ "phase": "Exploit", "target": "evil.example.com" }]);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.contains("evil.example.com") && e.contains("in_scope")), "{errs:?}");
    }

    #[test]
    fn invariant_3_cleanup_must_cover_persistence() {
        let mut b = valid_bundle();
        b.get_mut(&DocKind::Cleanup).unwrap()["persistence"] = json!([]);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.contains("scheduled-task")), "{errs:?}");
    }

    #[test]
    fn invariant_4_abort_needs_emergency_trigger() {
        let mut b = valid_bundle();
        b.get_mut(&DocKind::Abort).unwrap()["triggers"] = json!([{ "level": "WARNING", "condition": "x" }]);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.contains("EMERGENCY")), "{errs:?}");
    }

    #[test]
    fn invariant_5_datahandling_covers_roe_frameworks() {
        let mut b = valid_bundle();
        b.get_mut(&DocKind::DataHandling).unwrap()["frameworks"] = json!(["SOC2"]);
        let errs = validate_bundle(&b);
        assert!(errs.iter().any(|e| e.to_lowercase().contains("ptes")), "{errs:?}");
    }

    #[test]
    fn summary_table_names_every_document() {
        let s = bundle_summary(&valid_bundle());
        for (_, kind) in PLAN_DOCS {
            assert!(s.contains(kind.label()), "summary missing {}", kind.label());
        }
        assert!(s.contains("2-step kill chain"));
    }

    // --- tool tests (driven through a ToolRegistry) --------------------------

    /// A registry with both planning tools.
    fn registry() -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(CompleteEngagementPlanningTool));
        reg.register(Arc::new(ValidatePlanDocTool));
        reg
    }

    async fn call(reg: &ToolRegistry, name: &str, args: Value, ctx: &ExecCtx) -> ToolResult {
        reg.execute(
            ToolCall { call_id: CallId::from("c1"), name: name.into(), arguments: args },
            ctx,
        )
        .await
    }

    /// A full, cross-valid on-disk bundle (mirrors the upstream e2e fixture).
    fn full_docs() -> Vec<(&'static str, Value)> {
        vec![
            ("plan/roe.json", json!({
                "in_scope": ["app.target.test"],
                "out_of_scope": ["prod.bank.test"],
                "permitted_actions": ["recon", "exploitation"],
                "frameworks": ["PTES"]
            })),
            ("plan/threat-profile.json", json!({ "adversary": "sim", "initial_access": ["exploitation"] })),
            ("plan/conops.json", json!({ "kill_chain": [{ "phase": "Exploit", "target": "app.target.test" }], "persistence": ["cron"] })),
            ("plan/deconfliction.json", json!({ "procedures": ["notify SOC"] })),
            ("plan/contact.json", json!({ "contacts": [{ "name": "Blue", "email": "soc@t.test" }] })),
            ("plan/data-handling.json", json!({ "classification": "confidential", "frameworks": ["PTES"] })),
            ("plan/abort.json", json!({ "triggers": [{ "level": "EMERGENCY", "condition": "outage" }] })),
            ("plan/cleanup.json", json!({ "persistence": ["cron"], "artifacts": ["/tmp/x"] })),
        ]
    }

    fn write_bundle(dir: &Path, docs: &[(&str, Value)]) {
        for (rel, v) in docs {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, v.to_string()).unwrap();
        }
    }

    #[tokio::test]
    async fn complete_planning_reports_missing_docs_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let reg = registry();

        // The handoff is refused (ready:false) while the bundle is empty, and the
        // missing documents are reported by path.
        let r = call(&reg, "complete_engagement_planning", json!({}), &ctx).await;
        assert!(!r.is_error, "content: {:?}", r.content);
        let v = r.value.unwrap();
        assert_eq!(v["ready"], false);
        assert!(v["problems"].as_array().unwrap().iter().any(|p| p.as_str().unwrap().contains("plan/roe.json")));
    }

    #[tokio::test]
    async fn complete_planning_arms_scope_on_a_valid_bundle() {
        let dir = tempfile::tempdir().unwrap();
        write_bundle(dir.path(), &full_docs());
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let reg = registry();

        let r = call(&reg, "complete_engagement_planning", json!({}), &ctx).await;
        assert!(!r.is_error, "content: {:?}", r.content);
        let v = r.value.unwrap();
        assert_eq!(v["ready"], true);
        assert!(v["problems"].as_array().unwrap().is_empty());
        // The RoE scope is surfaced so the app can arm the gate.
        assert!(v["in_scope"].as_array().unwrap().iter().any(|t| t == "app.target.test"));
        assert!(v["out_of_scope"].as_array().unwrap().iter().any(|t| t == "prod.bank.test"));
        assert!(v["summary"].as_str().unwrap().contains("Rules of Engagement"));
    }

    #[tokio::test]
    async fn complete_planning_reports_a_cross_invariant_violation() {
        let dir = tempfile::tempdir().unwrap();
        let mut docs = full_docs();
        // initial_access names an action RoE does not permit → invariant 1 fails.
        docs[1] = ("plan/threat-profile.json", json!({ "adversary": "sim", "initial_access": ["phishing"] }));
        write_bundle(dir.path(), &docs);
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let reg = registry();

        let r = call(&reg, "complete_engagement_planning", json!({}), &ctx).await;
        let v = r.value.unwrap();
        assert_eq!(v["ready"], false);
        assert!(v["problems"].as_array().unwrap().iter().any(|p| {
            let s = p.as_str().unwrap();
            s.contains("phishing") && s.contains("permitted_actions")
        }));
    }

    #[tokio::test]
    async fn validate_plan_doc_checks_a_single_document() {
        let dir = tempfile::tempdir().unwrap();
        // A malformed RoE on disk is reported invalid, with the schema problem.
        write_bundle(dir.path(), &[("plan/roe.json", json!({ "in_scope": [], "permitted_actions": ["x"] }))]);
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let reg = registry();

        let bad = call(&reg, "validate_plan_doc", json!({ "path": "plan/roe.json" }), &ctx).await;
        assert!(!bad.is_error, "content: {:?}", bad.content);
        let bv = bad.value.unwrap();
        assert_eq!(bv["valid"], false);
        assert!(bv["problems"].as_array().unwrap().iter().any(|p| p.as_str().unwrap().contains("in_scope")));

        // Inline content is validated without touching the filesystem.
        let good = call(&reg, "validate_plan_doc", json!({
            "path": "plan/abort.json",
            "content": json!({ "triggers": [{ "level": "EMERGENCY", "condition": "x" }] }).to_string()
        }), &ctx).await;
        assert_eq!(good.value.unwrap()["valid"], true);
    }

    #[tokio::test]
    async fn validate_plan_doc_flags_invalid_json() {
        let ctx = ExecCtx::new();
        let reg = registry();
        let r = call(&reg, "validate_plan_doc", json!({ "path": "plan/roe.json", "content": "{ not json" }), &ctx).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert_eq!(v["valid"], false);
        assert!(v["problems"].as_array().unwrap().iter().any(|p| p.as_str().unwrap().contains("not valid JSON")));
    }

    #[tokio::test]
    async fn validate_plan_doc_rejects_a_non_plan_path() {
        let ctx = ExecCtx::new();
        let reg = registry();
        let r = call(&reg, "validate_plan_doc", json!({ "path": "notes.md" }), &ctx).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    #[tokio::test]
    async fn validate_plan_doc_requires_path() {
        let ctx = ExecCtx::new();
        let reg = registry();
        let r = call(&reg, "validate_plan_doc", json!({}), &ctx).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
