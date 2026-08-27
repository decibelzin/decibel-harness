//! Attack-chain planning over the knowledge graph — the APOC-free reimpl of the
//! upstream chain planner (port spec §5). Finds the cheapest weighted paths from
//! each `Entrypoint` to each `CrownJewel` over the attack-relationship whitelist,
//! using Dijkstra on the engagement-scoped graph loaded from SQLite.
//!
//! Edge cost = `max(weight, 0.05) × severity_multiplier(dst) × validated_factor`
//! (upstream cost model): arriving at a higher-severity node is cheaper (more
//! attractive), and an edge marked `validated` (a proven step) is half-cost.
//! Everything is engagement-scoped and pure, so it is unit-testable with a
//! synthetic graph.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::Connection;

/// Relationship types a real attack path may traverse (upstream whitelist +
/// the AD/ADCS + credential/session vocabulary). Shared by the chain planner and
/// the named analyses (`crate::analysis`) so both reason over the same edges.
pub(crate) const ATTACK_RELS: &[&str] = &[
    // Core attack progression.
    "EXPLOITS", "ENABLES", "LEAKS", "LEADS_TO", "PIVOTS_TO", "ESCALATES_TO",
    "HAS_VULN", "CAN_ACCESS", "ADMIN_TO",
    // Recon structure (so a chain can start from a discovered service).
    "RESOLVES_TO", "RUNS", "EXPOSES",
    // Credential / session (BloodHound-style).
    "AUTHENTICATES_TO", "HAS_SESSION", "MEMBER_OF", "CAN_RDP", "CAN_PSREMOTE",
    // AD object-control primitives.
    "GENERIC_ALL", "GENERIC_WRITE", "WRITE_DACL", "WRITE_OWNER", "OWNS",
    "FORCE_CHANGE_PASSWORD", "ADD_MEMBER", "ADD_KEY_CREDENTIAL_LINK",
    "ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT",
    // AD/DC attacks.
    "DCSYNC", "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD", "GOLDEN_CERT", "SYNC_LAPS",
    // ADCS ESC1–ESC16.
    "ADCS_ESC1", "ADCS_ESC2", "ADCS_ESC3", "ADCS_ESC4", "ADCS_ESC5", "ADCS_ESC6",
    "ADCS_ESC7", "ADCS_ESC8", "ADCS_ESC9", "ADCS_ESC10", "ADCS_ESC11", "ADCS_ESC12",
    "ADCS_ESC13", "ADCS_ESC14", "ADCS_ESC15", "ADCS_ESC16",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Chain {
    /// Node labels from entrypoint to crown jewel, in order.
    pub path: Vec<String>,
    /// Node ids for the same path (lets `promote_chain` materialize it).
    #[serde(default)]
    pub ids: Vec<String>,
    pub cost: f64,
    pub hops: usize,
    /// Critical-path score: `0.6·(1/max(cost,0.1))·10 + 0.4·worst_vuln_severity`
    /// (inverse cost + worst node severity on the path, 0–10ish). Higher = more
    /// critical (cheap route into high-severity assets).
    #[serde(default)]
    pub score: f64,
}

struct Graph {
    /// id -> (kind, label)
    nodes: HashMap<String, (String, String)>,
    /// id -> [(dst, weight)]
    adj: HashMap<String, Vec<(String, f64)>>,
    /// id -> node severity on a 0–10 scale (for critical_path_score).
    sev_score: HashMap<String, f64>,
}

/// A node's severity as a 0–10 score (for `critical_path_score`), from its
/// `props_json.severity`.
fn sev_to_score(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 10.0,
        "high" => 8.0,
        "medium" => 5.0,
        "low" => 3.0,
        "info" => 1.0,
        _ => 0.0,
    }
}

/// Critical-path score for a chain (upstream formula): inverse traversal cost
/// (cheaper = more reachable) blended with the worst vulnerability severity on
/// the path (higher = more impactful).
pub fn critical_path_score(cost: f64, worst_vuln_severity: f64) -> f64 {
    0.6 * (1.0 / cost.max(0.1)) * 10.0 + 0.4 * worst_vuln_severity
}

/// Traversal-cost multiplier by a node's severity (upstream
/// `SEVERITY_COST_MULTIPLIER`): a path INTO a critical node is the cheapest, so
/// the planner prefers routes that reach high-impact assets.
fn sev_mult(severity: &str) -> f64 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0.4,
        "high" => 0.6,
        "medium" => 1.0,
        "low" => 1.5,
        "info" => 2.5,
        _ => 1.0,
    }
}

fn load_graph(conn: &Connection, engagement: &str) -> Result<Graph, String> {
    let mut nodes = HashMap::new();
    // Per-node severity multiplier, read from `props_json.severity` (defaults 1.0
    // for recon nodes that carry no severity).
    let mut sev: HashMap<String, f64> = HashMap::new();
    // Per-node 0–10 severity score for critical_path_score.
    let mut sev_score: HashMap<String, f64> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, kind, label, props_json FROM graph_node WHERE engagement = ?1")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![engagement], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (id, kind, label, props) = row.map_err(|e| e.to_string())?;
            let sev_str = serde_json::from_str::<serde_json::Value>(&props)
                .ok()
                .and_then(|v| v.get("severity").and_then(|s| s.as_str()).map(str::to_string));
            let m = sev_str.as_deref().map(sev_mult).unwrap_or(1.0);
            sev_score.insert(id.clone(), sev_str.as_deref().map(sev_to_score).unwrap_or(0.0));
            sev.insert(id.clone(), m);
            nodes.insert(id, (kind, label));
        }
    }

    let mut adj: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    {
        let placeholders = ATTACK_RELS.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT src, dst, weight, props_json FROM graph_edge WHERE engagement = ? AND kind IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(ATTACK_RELS.len() + 1);
        binds.push(&engagement);
        for rel in ATTACK_RELS {
            binds.push(rel);
        }
        let rows = stmt
            .query_map(binds.as_slice(), |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, f64>(2)?, r.get::<_, String>(3)?))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (src, dst, weight, props) = row.map_err(|e| e.to_string())?;
            let validated = serde_json::from_str::<serde_json::Value>(&props)
                .ok()
                .and_then(|v| v.get("validated").and_then(|b| b.as_bool()))
                .unwrap_or(false);
            let cost = weight.max(0.05) * sev.get(&dst).copied().unwrap_or(1.0) * if validated { 0.5 } else { 1.0 };
            adj.entry(src).or_default().push((dst, cost));
        }
    }

    Ok(Graph { nodes, adj, sev_score })
}

#[derive(PartialEq)]
struct HeapEntry {
    cost: f64,
    node: String,
}
impl Eq for HeapEntry {}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for a min-heap; NaN-safe.
        other
            .cost
            .partial_cmp(&self.cost)
            .unwrap_or(Ordering::Equal)
    }
}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Dijkstra from `start` over the graph; returns (cost, prev-map) for reached nodes.
fn dijkstra(g: &Graph, start: &str, max_cost: f64) -> (HashMap<String, f64>, HashMap<String, String>) {
    let mut dist: HashMap<String, f64> = HashMap::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    let mut heap = BinaryHeap::new();

    dist.insert(start.to_string(), 0.0);
    heap.push(HeapEntry { cost: 0.0, node: start.to_string() });

    while let Some(HeapEntry { cost, node }) = heap.pop() {
        if cost > *dist.get(&node).unwrap_or(&f64::INFINITY) {
            continue;
        }
        if let Some(neighbors) = g.adj.get(&node) {
            for (dst, w) in neighbors {
                let next = cost + w;
                if next > max_cost {
                    continue;
                }
                if next < *dist.get(dst).unwrap_or(&f64::INFINITY) {
                    dist.insert(dst.clone(), next);
                    prev.insert(dst.clone(), node.clone());
                    heap.push(HeapEntry { cost: next, node: dst.clone() });
                }
            }
        }
    }
    (dist, prev)
}

fn reconstruct(prev: &HashMap<String, String>, start: &str, goal: &str) -> Option<Vec<String>> {
    let mut path = vec![goal.to_string()];
    let mut cur = goal.to_string();
    while cur != start {
        cur = prev.get(&cur)?.clone();
        path.push(cur.clone());
    }
    path.reverse();
    Some(path)
}

/// Plan the cheapest attack chains from every Entrypoint to every CrownJewel.
/// Returns up to `top_k` chains sorted by ascending cost (bounded by `max_cost`
/// and `max_depth` hops).
pub fn plan_chains(
    conn: &Connection,
    engagement: &str,
    max_depth: usize,
    max_cost: f64,
    top_k: usize,
) -> Result<Vec<Chain>, String> {
    let g = load_graph(conn, engagement)?;

    let entries: Vec<&String> = g
        .nodes
        .iter()
        .filter(|(_, (kind, _))| kind == "Entrypoint")
        .map(|(id, _)| id)
        .collect();
    let jewels: Vec<&String> = g
        .nodes
        .iter()
        .filter(|(_, (kind, _))| kind == "CrownJewel")
        .map(|(id, _)| id)
        .collect();

    let mut chains = Vec::new();
    for entry in &entries {
        let (dist, prev) = dijkstra(&g, entry, max_cost);
        for jewel in &jewels {
            if let Some(&cost) = dist.get(*jewel) {
                if let Some(ids) = reconstruct(&prev, entry, jewel) {
                    let hops = ids.len().saturating_sub(1);
                    if hops == 0 || hops > max_depth {
                        continue;
                    }
                    let labels = ids
                        .iter()
                        .map(|id| g.nodes.get(id).map(|(_, l)| l.clone()).unwrap_or_else(|| id.clone()))
                        .collect();
                    let worst = ids.iter().map(|id| g.sev_score.get(id).copied().unwrap_or(0.0)).fold(0.0_f64, f64::max);
                    chains.push(Chain { path: labels, ids, cost, hops, score: critical_path_score(cost, worst) });
                }
            }
        }
    }

    chains.sort_by(|a, b| a.cost.partial_cmp(&b.cost).unwrap_or(Ordering::Equal));
    chains.truncate(top_k);
    Ok(chains)
}

/// Materialize the cheapest `entry_label → crown_label` chain as an `AttackPath`
/// node (upstream `promote_chain`): the node links `STARTS_AT`→entry,
/// `REACHES`→crown, and `STEP`(order=i)→each node on the path. Returns the new
/// AttackPath node id, or `None` if no path exists. Idempotent (keyed on the pair).
pub fn promote_chain(
    conn: &Connection,
    engagement: &str,
    entry_label: &str,
    crown_label: &str,
    max_cost: f64,
) -> Result<Option<String>, String> {
    let g = load_graph(conn, engagement)?;
    let find = |want_kind: &str, label: &str| -> Option<String> {
        g.nodes.iter().find_map(|(id, (kind, l))| (kind == want_kind && l == label).then(|| id.clone()))
    };
    let (Some(entry), Some(crown)) = (find("Entrypoint", entry_label), find("CrownJewel", crown_label)) else {
        return Ok(None);
    };
    let (dist, prev) = dijkstra(&g, &entry, max_cost);
    let Some(cost) = dist.get(&crown).copied() else { return Ok(None) };
    let Some(ids) = reconstruct(&prev, &entry, &crown) else { return Ok(None) };
    if ids.len() < 2 {
        return Ok(None);
    }
    let worst = ids.iter().map(|id| g.sev_score.get(id).copied().unwrap_or(0.0)).fold(0.0_f64, f64::max);
    let score = critical_path_score(cost, worst);

    let key = format!("{entry_label}=>{crown_label}");
    let label = format!("{entry_label} → {crown_label}");
    let props = serde_json::json!({ "cost": cost, "hops": ids.len() - 1, "score": score }).to_string();
    let ap = crate::kg_upsert_node(conn, engagement, "AttackPath", &label, Some(&key), &props)?;
    crate::kg_upsert_edge(conn, engagement, &ap, &entry, "STARTS_AT", 1.0, None, "{}")?;
    crate::kg_upsert_edge(conn, engagement, &ap, &crown, "REACHES", 1.0, None, "{}")?;
    for (i, id) in ids.iter().enumerate() {
        let step_props = serde_json::json!({ "order": i }).to_string();
        crate::kg_upsert_edge(conn, engagement, &ap, id, "STEP", 1.0, Some(&i.to_string()), &step_props)?;
    }
    Ok(Some(ap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kg_upsert_edge, kg_upsert_node, open_memory};

    fn node(conn: &Connection, kind: &str, label: &str) -> String {
        kg_upsert_node(conn, "e", kind, label, Some(label), "{}").unwrap()
    }

    #[test]
    fn severity_and_validated_make_a_route_cheaper() {
        let conn = open_memory();
        let entry = node(&conn, "Entrypoint", "e");
        let jewel = node(&conn, "CrownJewel", "dc");
        // Route A: through a CRITICAL vuln with a VALIDATED exploit edge.
        let critv = kg_upsert_node(&conn, "e", "Vulnerability", "critv", Some("critv"), r#"{"severity":"critical"}"#).unwrap();
        kg_upsert_edge(&conn, "e", &entry, &critv, "HAS_VULN", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &critv, &jewel, "EXPLOITS", 1.0, None, r#"{"validated":true}"#).unwrap();
        // Route B: through a plain host, same weights, no severity/validated.
        let plain = node(&conn, "Host", "plain");
        kg_upsert_edge(&conn, "e", &entry, &plain, "PIVOTS_TO", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &plain, &jewel, "ADMIN_TO", 1.0, None, "{}").unwrap();

        let chains = plan_chains(&conn, "e", 12, 1.0e9, 5).unwrap();
        // A = 1·0.4 (into critical) + 1·1·0.5 (validated) = 0.9; B = 1 + 1 = 2.0.
        assert!(chains[0].path.contains(&"critv".to_string()), "cheapest should go via the critical validated route: {:?}", chains[0].path);
        assert!((chains[0].cost - 0.9).abs() < 1e-9, "cost {}", chains[0].cost);
    }

    #[test]
    fn critical_path_score_rewards_cheap_and_severe() {
        // Cheaper path scores higher; higher severity scores higher.
        assert!(critical_path_score(0.5, 10.0) > critical_path_score(5.0, 10.0));
        assert!(critical_path_score(1.0, 10.0) > critical_path_score(1.0, 0.0));
        // Chains carry a score, and a route into a critical node beats a plain one.
        let conn = open_memory();
        let entry = node(&conn, "Entrypoint", "e");
        let jewel = node(&conn, "CrownJewel", "dc");
        let crit = kg_upsert_node(&conn, "e", "Vulnerability", "cv", Some("cv"), r#"{"severity":"critical"}"#).unwrap();
        kg_upsert_edge(&conn, "e", &entry, &crit, "HAS_VULN", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &crit, &jewel, "EXPLOITS", 1.0, None, "{}").unwrap();
        let chains = plan_chains(&conn, "e", 10, 1.0e9, 5).unwrap();
        assert!(chains[0].score > 0.0, "chain carries a critical-path score");
        assert!(!chains[0].ids.is_empty(), "chain carries node ids for promotion");
    }

    #[test]
    fn promote_chain_materializes_an_attackpath() {
        let conn = open_memory();
        let entry = node(&conn, "Entrypoint", "http://t/");
        let web = node(&conn, "Service", "t:80/http");
        let jewel = node(&conn, "CrownJewel", "domain-admin");
        kg_upsert_edge(&conn, "e", &entry, &web, "EXPLOITS", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &web, &jewel, "ADMIN_TO", 1.0, None, "{}").unwrap();

        let ap = promote_chain(&conn, "e", "http://t/", "domain-admin", 1.0e9).unwrap().expect("a path exists");
        // The AttackPath node + its STARTS_AT/REACHES/STEP edges exist.
        let paths = crate::kg_by_kind(&conn, "e", "AttackPath").unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].id, ap);
        let out = crate::kg_neighbors(&conn, "e", &ap, "out").unwrap();
        assert!(out.len() >= 4, "STARTS_AT + REACHES + one STEP per node: {}", out.len());
        // No path for a bad pair → None.
        assert!(promote_chain(&conn, "e", "http://t/", "nonexistent", 1.0e9).unwrap().is_none());
    }

    #[test]
    fn finds_shortest_entry_to_crownjewel() {
        let conn = open_memory();
        // entry -EXPLOITS-> web(1) -PIVOTS_TO-> db(1) -ADMIN_TO-> jewel   cost 3
        // entry -LEADS_TO-> jewel                                          cost 5 (longer weight)
        let entry = node(&conn, "Entrypoint", "http://t/");
        let web = node(&conn, "Service", "t:80/http");
        let db = node(&conn, "Host", "db");
        let jewel = node(&conn, "CrownJewel", "domain-admin");

        kg_upsert_edge(&conn, "e", &entry, &web, "EXPLOITS", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &web, &db, "PIVOTS_TO", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &db, &jewel, "ADMIN_TO", 1.0, None, "{}").unwrap();
        kg_upsert_edge(&conn, "e", &entry, &jewel, "LEADS_TO", 5.0, None, "{}").unwrap();

        let chains = plan_chains(&conn, "e", 10, 100.0, 5).unwrap();
        assert!(!chains.is_empty());
        let best = &chains[0];
        assert_eq!(best.cost, 3.0, "chains: {chains:?}");
        assert_eq!(best.hops, 3);
        assert_eq!(best.path.first().unwrap(), "http://t/");
        assert_eq!(best.path.last().unwrap(), "domain-admin");
    }

    #[test]
    fn respects_max_cost_bound() {
        let conn = open_memory();
        let entry = node(&conn, "Entrypoint", "e1");
        let jewel = node(&conn, "CrownJewel", "j1");
        kg_upsert_edge(&conn, "e", &entry, &jewel, "LEADS_TO", 9.0, None, "{}").unwrap();
        // max_cost below the only path's cost → no chains.
        assert!(plan_chains(&conn, "e", 10, 5.0, 5).unwrap().is_empty());
        // enough budget → one chain.
        assert_eq!(plan_chains(&conn, "e", 10, 20.0, 5).unwrap().len(), 1);
    }

    #[test]
    fn no_jewel_no_chains() {
        let conn = open_memory();
        let entry = node(&conn, "Entrypoint", "e1");
        let host = node(&conn, "Host", "h1");
        kg_upsert_edge(&conn, "e", &entry, &host, "EXPLOITS", 1.0, None, "{}").unwrap();
        assert!(plan_chains(&conn, "e", 10, 100.0, 5).unwrap().is_empty());
    }
}
