//! OPPLAN — the operation plan: an engagement's objective tree, plus the
//! **kill-chain gate** the upstream `OPPLANMiddleware` enforced at runtime.
//!
//! Upstream expressed kill-chain ordering as middleware that intercepted tool
//! calls (an exploit objective cannot go `in-progress` before a recon objective
//! is `completed`; you cannot `block` while recon produced observations; a parent
//! cannot `complete` while children are still open). Here the objective CRUD is a
//! shared tool (MCP + harness), so the gate lives in the **single write path**
//! (`update_objective`) — which means it holds for every provider at once (Claude
//! CLI, Codex, harness), not per-runtime.
//!
//! Objective ids are human-legible `OBJ-NNN` (per engagement), matching the
//! `OBJ-NNN` tokens the Decepticon persona and finding protocol reference.

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::now;

/// The terminal states an objective can rest in (no further work expected).
pub const TERMINAL: &[&str] = &["completed", "blocked", "cancelled"];
/// Every legal objective status.
pub const STATUSES: &[&str] = &["pending", "in-progress", "completed", "blocked", "cancelled"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Objective {
    pub id: String,
    pub engagement_id: String,
    /// Kill-chain phase label (free text; classified by [`phase_order`]).
    pub phase: String,
    pub title: String,
    /// `pending` | `in-progress` | `completed` | `blocked` | `cancelled`.
    pub status: String,
    /// Lower = earlier in the roster (kill-chain order), mirrors sub-agent priority.
    pub priority: i64,
    /// Ids of objectives that must be `completed` before this one may start.
    pub blocked_by: Vec<String>,
    pub parent_id: Option<String>,
    pub notes: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Kill-chain ordinal for a phase label. Recon/discovery = 0, initial-access/
/// exploitation = 1, everything post-compromise = 2, planning/unknown = 0 (so a
/// bare objective never trips the exploit-before-recon gate spuriously). Matching
/// is substring/keyword based so free-text phases ("Web Recon", "AD Exploitation")
/// classify correctly.
pub fn phase_order(phase: &str) -> u8 {
    let p = phase.to_ascii_lowercase();
    let has = |kws: &[&str]| kws.iter().any(|k| p.contains(k));
    if has(&["recon", "discovery", "osint", "enumerat", "footprint", "scan", "plan"]) {
        0
    } else if has(&[
        "post", "privesc", "privilege", "lateral", "c2", "command-and-control",
        "exfil", "impact", "persist", "collection", "escalat", "domain-admin",
    ]) {
        // Check post-compromise BEFORE exploit so "post-exploitation" isn't caught
        // by the "exploit" keyword below.
        2
    } else if has(&[
        "exploit", "initial-access", "initial access", "phish", "access",
        "delivery", "weaponiz", "attack",
    ]) {
        1
    } else {
        0
    }
}

/// True if `phase` is a reconnaissance/discovery phase.
pub fn is_recon_phase(phase: &str) -> bool {
    phase_order(phase) == 0
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

fn row_to_objective(r: &rusqlite::Row) -> rusqlite::Result<Objective> {
    let blocked_by_json: String = r.get(6)?;
    Ok(Objective {
        id: r.get(0)?,
        engagement_id: r.get(1)?,
        phase: r.get(2)?,
        title: r.get(3)?,
        status: r.get(4)?,
        priority: r.get(5)?,
        blocked_by: serde_json::from_str(&blocked_by_json).unwrap_or_default(),
        parent_id: r.get(7)?,
        notes: r.get(8)?,
        created_at: r.get(9)?,
        updated_at: r.get(10)?,
    })
}

const COLS: &str = "id, engagement_id, phase, title, status, priority, blocked_by_json, parent_id, notes, created_at, updated_at";

/// Next `OBJ-NNN` id for an engagement (1-based, zero-padded to 3).
fn next_objective_id(conn: &Connection, engagement: &str) -> Result<String, String> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM objective WHERE engagement_id = ?1",
            params![engagement],
            |r| r.get(0),
        )
        .map_err(|e| format!("count objectives: {e}"))?;
    Ok(format!("OBJ-{:03}", n + 1))
}

/// Add an objective. `blocked_by` names sibling objective ids that must complete
/// first; `parent_id` nests it under another objective (decomposition).
#[allow(clippy::too_many_arguments)]
pub fn add_objective(
    conn: &Connection,
    engagement: &str,
    phase: &str,
    title: &str,
    priority: i64,
    blocked_by: &[String],
    parent_id: Option<&str>,
    notes: &str,
) -> Result<Objective, String> {
    let ts = now();
    let o = Objective {
        id: next_objective_id(conn, engagement)?,
        engagement_id: engagement.to_string(),
        phase: phase.to_string(),
        title: title.to_string(),
        status: "pending".to_string(),
        priority,
        blocked_by: blocked_by.to_vec(),
        parent_id: parent_id.map(str::to_string),
        notes: notes.to_string(),
        created_at: ts,
        updated_at: ts,
    };
    conn.execute(
        "INSERT INTO objective (id, engagement_id, phase, title, status, priority, blocked_by_json, parent_id, notes, created_at, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            o.id, o.engagement_id, o.phase, o.title, o.status, o.priority,
            serde_json::to_string(&o.blocked_by).unwrap_or_else(|_| "[]".into()),
            o.parent_id, o.notes, o.created_at, o.updated_at
        ],
    )
    .map_err(|e| format!("add objective: {e}"))?;
    Ok(o)
}

pub fn get_objective(conn: &Connection, engagement: &str, id: &str) -> Result<Option<Objective>, String> {
    conn.query_row(
        &format!("SELECT {COLS} FROM objective WHERE engagement_id = ?1 AND id = ?2"),
        params![engagement, id],
        row_to_objective,
    )
    .optional()
    .map_err(|e| format!("get objective: {e}"))
}

/// All objectives for an engagement, ordered by `(priority, id)` — the roster
/// order the orchestrator should walk.
pub fn list_objectives(conn: &Connection, engagement: &str) -> Result<Vec<Objective>, String> {
    let mut stmt = conn
        .prepare(&format!("SELECT {COLS} FROM objective WHERE engagement_id = ?1 ORDER BY priority ASC, id ASC"))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![engagement], row_to_objective)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}

/// Direct children of `parent_id`.
pub fn children(conn: &Connection, engagement: &str, parent_id: &str) -> Result<Vec<Objective>, String> {
    let mut stmt = conn
        .prepare(&format!("SELECT {COLS} FROM objective WHERE engagement_id = ?1 AND parent_id = ?2 ORDER BY priority ASC, id ASC"))
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![engagement, parent_id], row_to_objective)
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}

/// Update an objective's mutable fields. `status` transitions run the kill-chain
/// gate ([`check_transition`]) before the write; a violation returns `Err` and
/// nothing is written. `None` fields are left unchanged.
pub fn update_objective(
    conn: &Connection,
    engagement: &str,
    id: &str,
    status: Option<&str>,
    notes: Option<&str>,
    priority: Option<i64>,
) -> Result<Objective, String> {
    let cur = get_objective(conn, engagement, id)?
        .ok_or_else(|| format!("objective {id} not found"))?;

    if let Some(new_status) = status {
        if !STATUSES.contains(&new_status) {
            return Err(format!("invalid status '{new_status}' (want one of {STATUSES:?})"));
        }
        if new_status != cur.status {
            check_transition(conn, engagement, &cur, new_status)?;
        }
    }

    let new_status = status.unwrap_or(&cur.status);
    let new_notes = notes.unwrap_or(&cur.notes);
    let new_priority = priority.unwrap_or(cur.priority);
    let ts = now();
    conn.execute(
        "UPDATE objective SET status = ?1, notes = ?2, priority = ?3, updated_at = ?4
         WHERE engagement_id = ?5 AND id = ?6",
        params![new_status, new_notes, new_priority, ts, engagement, id],
    )
    .map_err(|e| format!("update objective: {e}"))?;
    get_objective(conn, engagement, id)?.ok_or_else(|| "objective vanished after update".into())
}

/// Decompose an objective into child objectives (the `objective_expand` tool).
/// Children inherit the parent's phase unless the caller overrides it, and are
/// priced just after the parent so they sort under it.
pub fn expand_objective(
    conn: &Connection,
    engagement: &str,
    parent_id: &str,
    children_titles: &[(String, String)], // (phase, title); empty phase → inherit
) -> Result<Vec<Objective>, String> {
    let parent = get_objective(conn, engagement, parent_id)?
        .ok_or_else(|| format!("parent objective {parent_id} not found"))?;
    let mut out = Vec::new();
    for (i, (phase, title)) in children_titles.iter().enumerate() {
        let phase = if phase.is_empty() { parent.phase.as_str() } else { phase.as_str() };
        let child = add_objective(
            conn,
            engagement,
            phase,
            title,
            parent.priority + 1 + i as i64,
            &[],
            Some(parent_id),
            "",
        )?;
        out.push(child);
    }
    Ok(out)
}

/// Re-collapse an objective: delete its (non-terminal) children (the
/// `objective_collapse` tool). Returns how many were removed.
pub fn collapse_objective(conn: &Connection, engagement: &str, parent_id: &str) -> Result<u64, String> {
    let n = conn
        .execute(
            "DELETE FROM objective WHERE engagement_id = ?1 AND parent_id = ?2",
            params![engagement, parent_id],
        )
        .map_err(|e| format!("collapse objective: {e}"))?;
    Ok(n as u64)
}

// ---------------------------------------------------------------------------
// The kill-chain gate (upstream OPPLANMiddleware, now at the write path)
// ---------------------------------------------------------------------------

fn has_completed_recon(conn: &Connection, engagement: &str) -> Result<bool, String> {
    let objs = list_objectives(conn, engagement)?;
    Ok(objs
        .iter()
        .any(|o| o.status == "completed" && is_recon_phase(&o.phase)))
}

fn kg_has_observations(conn: &Connection, engagement: &str) -> Result<bool, String> {
    Ok(crate::kg_stats(conn, engagement)?.nodes > 0)
}

/// The knowledge-graph delta a vulnresearch pipeline stage requires from its
/// predecessor before it may start — the #8 "stage-gating by KG delta" moved from
/// persona prose into enforced CODE. `AnyNode` = the KG must hold ≥1 node of one of
/// these kinds; `Finding` = ≥1 finding must be recorded.
enum StageDelta {
    AnyNode(&'static [&'static str]),
    Finding,
}

/// Map a phase/stage label to its required predecessor delta. Matches the stage by
/// keyword so it fires whether the orchestrator labels the objective's phase with
/// the specialist name ("detector") or the phase label ("Detect"). Returns
/// `(delta, predecessor-stage, human-readable requirement)`. `None` for stage 1
/// (scanner) and any non-pipeline phase — so a standard red-team OPPLAN (Recon /
/// Exploitation / Post) is never touched.
fn vulnresearch_stage_delta(phase: &str) -> Option<(StageDelta, &'static str, &'static str)> {
    let p = phase.to_ascii_lowercase();
    if p.contains("detect") {
        Some((StageDelta::AnyNode(&["Candidate", "Vulnerability"]), "scanner", "candidate/vulnerability observations"))
    } else if p.contains("verif") {
        Some((StageDelta::AnyNode(&["Vulnerability", "Hypothesis", "Candidate"]), "detector", "a vulnerability or hypothesis"))
    } else if p.contains("patch") {
        Some((StageDelta::Finding, "verifier", "a validated finding"))
    } else {
        None
    }
}

fn kg_has_any_kind(conn: &Connection, engagement: &str, kinds: &[&str]) -> Result<bool, String> {
    for k in kinds {
        if !crate::kg_by_kind(conn, engagement, k)?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Enforce the kill-chain gates for a status transition. Called by
/// [`update_objective`] before any write.
///
/// 1. **Recon-first** — an exploit-or-later objective cannot go `in-progress`
///    until some recon objective is `completed`.
/// 2. **Blocked-by** — an objective cannot go `in-progress` while any objective
///    it is `blocked_by` is not yet `completed`.
/// 3. **Don't-give-up** — an exploit-or-later objective cannot be marked
///    `blocked` while the KG holds observations (there is material to act on;
///    re-scope or narrow instead).
/// 4. **Parent completion** — a parent cannot go `completed` while a child is
///    still non-terminal.
pub fn check_transition(
    conn: &Connection,
    engagement: &str,
    obj: &Objective,
    new_status: &str,
) -> Result<(), String> {
    let order = phase_order(&obj.phase);

    if new_status == "in-progress" {
        if order >= 1 && !has_completed_recon(conn, engagement)? {
            return Err(format!(
                "kill-chain gate: {} is a phase-{} (exploit/post) objective — recon must complete first. \
                 Dispatch recon and mark a recon objective 'completed' before starting this.",
                obj.id, order
            ));
        }
        for dep in &obj.blocked_by {
            match get_objective(conn, engagement, dep)? {
                Some(d) if d.status == "completed" => {}
                Some(d) => {
                    return Err(format!(
                        "blocked_by gate: {} depends on {} which is '{}', not 'completed'",
                        obj.id, dep, d.status
                    ))
                }
                None => {
                    return Err(format!("blocked_by gate: {} depends on {} which does not exist", obj.id, dep))
                }
            }
        }

        // 5. Vulnresearch stage-gate (#8) — a pipeline stage cannot start until its
        //    predecessor's KG delta exists (detector needs candidates/vulns, verifier
        //    needs a vuln/hypothesis, patcher needs a finding). Enforced as code, not
        //    just persona prose; a no-op for non-pipeline phases.
        if let Some((delta, prev, needed)) = vulnresearch_stage_delta(&obj.phase) {
            let satisfied = match delta {
                StageDelta::AnyNode(kinds) => kg_has_any_kind(conn, engagement, kinds)?,
                StageDelta::Finding => !crate::list_findings(conn, engagement)?.is_empty(),
            };
            if !satisfied {
                return Err(format!(
                    "vulnresearch stage-gate: {} (phase '{}') needs {} in the knowledge graph first — \
                     run the {} stage and ingest its results before starting this stage.",
                    obj.id, obj.phase, needed, prev
                ));
            }
        }
    }

    if new_status == "blocked" && order >= 1 && kg_has_observations(conn, engagement)? {
        return Err(format!(
            "don't-give-up gate: {} cannot be blocked while the knowledge graph holds observations — \
             re-scope to a different vector or run a focused recon turn instead of blocking.",
            obj.id
        ));
    }

    if new_status == "completed" {
        let open: Vec<String> = children(conn, engagement, &obj.id)?
            .into_iter()
            .filter(|c| !TERMINAL.contains(&c.status.as_str()))
            .map(|c| c.id)
            .collect();
        if !open.is_empty() {
            return Err(format!(
                "parent-completion gate: {} has non-terminal children {:?} — finish or cancel them first",
                obj.id, open
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Catalog render (the `load_opplan` tool + the prompt's OPPLAN block)
// ---------------------------------------------------------------------------

/// Render the objective tree as a compact catalog for the orchestrator prompt /
/// `load_opplan`. Roots first, children indented; each line shows id, status,
/// phase, title, and unresolved `blocked_by`.
pub fn render_catalog(conn: &Connection, engagement: &str) -> Result<String, String> {
    let all = list_objectives(conn, engagement)?;
    if all.is_empty() {
        return Ok("OPPLAN is empty — build it with add_objective (recon first).".to_string());
    }
    let mut out = String::from("OPPLAN objectives:\n");
    let roots = all.iter().filter(|o| o.parent_id.is_none());
    for o in roots {
        push_line(&mut out, o, 0);
        for c in all.iter().filter(|c| c.parent_id.as_deref() == Some(o.id.as_str())) {
            push_line(&mut out, c, 1);
        }
    }
    Ok(out)
}

fn push_line(out: &mut String, o: &Objective, depth: usize) {
    let indent = "  ".repeat(depth);
    let dep = if o.blocked_by.is_empty() {
        String::new()
    } else {
        format!(" (blocked_by {})", o.blocked_by.join(","))
    };
    out.push_str(&format!(
        "{indent}- [{}] {} · {} · {}{}\n",
        o.status, o.id, o.phase, o.title, dep
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ensure_engagement, kg_upsert_node, open_memory};

    fn setup() -> (Connection, &'static str) {
        let conn = open_memory();
        ensure_engagement(&conn, "e1").unwrap();
        (conn, "e1")
    }

    #[test]
    fn phase_classification() {
        assert_eq!(phase_order("Web Recon"), 0);
        assert_eq!(phase_order("Reconnaissance"), 0);
        assert_eq!(phase_order("Initial Access"), 1);
        assert_eq!(phase_order("AD Exploitation"), 1);
        assert_eq!(phase_order("Post-Exploitation"), 2); // not caught by "exploit"
        assert_eq!(phase_order("Lateral Movement"), 2);
        assert_eq!(phase_order("Privilege Escalation"), 2);
    }

    #[test]
    fn crud_roundtrip_and_ids() {
        let (c, e) = setup();
        let a = add_objective(&c, e, "Recon", "enumerate host", 10, &[], None, "").unwrap();
        let b = add_objective(&c, e, "Exploit", "web SQLi", 20, &[], None, "").unwrap();
        assert_eq!(a.id, "OBJ-001");
        assert_eq!(b.id, "OBJ-002");
        assert_eq!(a.status, "pending");
        let listed = list_objectives(&c, e).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, "OBJ-001"); // priority order
        assert!(get_objective(&c, e, "OBJ-001").unwrap().is_some());
        assert!(get_objective(&c, e, "OBJ-404").unwrap().is_none());
    }

    #[test]
    fn recon_first_gate_blocks_exploit_start() {
        let (c, e) = setup();
        let _recon = add_objective(&c, e, "Recon", "enumerate", 10, &[], None, "").unwrap();
        let exploit = add_objective(&c, e, "Exploit", "SQLi", 20, &[], None, "").unwrap();
        // exploit can't start before recon completes
        let err = update_objective(&c, e, &exploit.id, Some("in-progress"), None, None).unwrap_err();
        assert!(err.contains("recon must complete"), "got: {err}");
        // recon can start freely, then complete
        update_objective(&c, e, "OBJ-001", Some("in-progress"), None, None).unwrap();
        update_objective(&c, e, "OBJ-001", Some("completed"), None, None).unwrap();
        // now exploit may start
        let ok = update_objective(&c, e, &exploit.id, Some("in-progress"), None, None).unwrap();
        assert_eq!(ok.status, "in-progress");
    }

    #[test]
    fn blocked_by_gate() {
        let (c, e) = setup();
        let a = add_objective(&c, e, "Recon", "a", 10, &[], None, "").unwrap();
        let b = add_objective(&c, e, "Recon", "b", 20, &[a.id.clone()], None, "").unwrap();
        let err = update_objective(&c, e, &b.id, Some("in-progress"), None, None).unwrap_err();
        assert!(err.contains("blocked_by gate"), "got: {err}");
        update_objective(&c, e, &a.id, Some("in-progress"), None, None).unwrap();
        update_objective(&c, e, &a.id, Some("completed"), None, None).unwrap();
        assert!(update_objective(&c, e, &b.id, Some("in-progress"), None, None).is_ok());
    }

    #[test]
    fn dont_give_up_gate_on_observations() {
        let (c, e) = setup();
        let _recon = add_objective(&c, e, "Recon", "r", 10, &[], None, "").unwrap();
        update_objective(&c, e, "OBJ-001", Some("in-progress"), None, None).unwrap();
        update_objective(&c, e, "OBJ-001", Some("completed"), None, None).unwrap();
        let exp = add_objective(&c, e, "Exploit", "x", 20, &[], None, "").unwrap();
        update_objective(&c, e, &exp.id, Some("in-progress"), None, None).unwrap();
        // With no KG observations, blocking is allowed.
        // Add an observation → blocking an exploit objective is now refused.
        kg_upsert_node(&c, e, "Host", "10.0.0.1", None, "{}").unwrap();
        let err = update_objective(&c, e, &exp.id, Some("blocked"), None, None).unwrap_err();
        assert!(err.contains("don't-give-up"), "got: {err}");
    }

    #[test]
    fn parent_completion_gate_and_expand_collapse() {
        let (c, e) = setup();
        let p = add_objective(&c, e, "Recon", "parent", 10, &[], None, "").unwrap();
        let kids = expand_objective(
            &c,
            e,
            &p.id,
            &[("".into(), "sub a".into()), ("".into(), "sub b".into())],
        )
        .unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].parent_id.as_deref(), Some(p.id.as_str()));
        assert_eq!(kids[0].phase, "Recon"); // inherited
        // parent can't complete with open children
        let err = update_objective(&c, e, &p.id, Some("completed"), None, None).unwrap_err();
        assert!(err.contains("parent-completion gate"), "got: {err}");
        // collapse removes them
        assert_eq!(collapse_objective(&c, e, &p.id).unwrap(), 2);
        assert!(update_objective(&c, e, &p.id, Some("completed"), None, None).is_ok());
    }

    #[test]
    fn catalog_renders_tree() {
        let (c, e) = setup();
        let p = add_objective(&c, e, "Recon", "root", 10, &[], None, "").unwrap();
        expand_objective(&c, e, &p.id, &[("".into(), "child".into())]).unwrap();
        let cat = render_catalog(&c, e).unwrap();
        assert!(cat.contains("OBJ-001"));
        assert!(cat.contains("  - [pending] OBJ-002")); // indented child
    }

    #[test]
    fn vulnresearch_stage_gate_needs_predecessor_kg_delta() {
        let (c, e) = setup();
        // A Verify stage can't start on an empty KG (the detector produced nothing).
        let verify = add_objective(&c, e, "Verify", "prove the bug", 30, &[], None, "").unwrap();
        let err = update_objective(&c, e, &verify.id, Some("in-progress"), None, None).unwrap_err();
        assert!(err.contains("stage-gate") && err.contains("vulnerability"), "got: {err}");
        // Once a Vulnerability node exists, the verifier stage may start.
        kg_upsert_node(&c, e, "Vulnerability", "reentrancy in withdraw", None, "{}").unwrap();
        let ok = update_objective(&c, e, &verify.id, Some("in-progress"), None, None).unwrap();
        assert_eq!(ok.status, "in-progress");
    }

    #[test]
    fn vulnresearch_patch_stage_needs_a_finding() {
        let (c, e) = setup();
        let patch = add_objective(&c, e, "Patch", "fix it", 40, &[], None, "").unwrap();
        let err = update_objective(&c, e, &patch.id, Some("in-progress"), None, None).unwrap_err();
        assert!(err.contains("stage-gate") && err.contains("finding"), "got: {err}");
        // A recorded finding (the verifier's output) unlocks the patch stage.
        crate::add_finding(&c, e, "high", "reentrancy", "withdraw", "{}", "verifier").unwrap();
        assert!(update_objective(&c, e, &patch.id, Some("in-progress"), None, None).is_ok());
    }

    #[test]
    fn stage_gate_leaves_standard_redteam_phases_untouched() {
        // A normal red-team OPPLAN (Recon/Exploit/Post) must not trip the pipeline gate.
        let (c, e) = setup();
        let recon = add_objective(&c, e, "Recon", "enumerate", 10, &[], None, "").unwrap();
        // Recon starts freely with an empty KG — no vulnresearch delta required.
        assert!(update_objective(&c, e, &recon.id, Some("in-progress"), None, None).is_ok());
        assert!(vulnresearch_stage_delta("Recon").is_none());
        assert!(vulnresearch_stage_delta("Exploitation").is_none());
        assert!(vulnresearch_stage_delta("Scan").is_none()); // stage 1 has no predecessor
    }
}
