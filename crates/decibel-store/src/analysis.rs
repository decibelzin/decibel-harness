//! Named knowledge-graph analyses (parity gate KG-11) — the APOC-free reimpl of
//! upstream's engagement-scoped Cypher analytics:
//!
//! - [`impact_analysis`] — blast radius: what compromising a node reaches, over
//!   the attack-relationship whitelist (upstream `apoc.path.expandConfig`).
//! - [`unexplored_surface`] — Services with no `HAS_VULN` edge yet (where to look
//!   next).
//! - [`credential_reachability`] — Credential → `AUTHENTICATES_TO` → User →
//!   `CAN_ACCESS`/`ADMIN_TO`/`HAS_SESSION` (what a captured secret unlocks).
//!
//! All are engagement-scoped and pure (unit-testable against a synthetic graph).

use std::collections::{HashMap, HashSet, VecDeque};

use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::chain::ATTACK_RELS;
use crate::Connection;

// ---------------------------------------------------------------------------
// Shared loaders
// ---------------------------------------------------------------------------

/// id -> (kind, label) for every node in the engagement.
fn node_map(conn: &Connection, engagement: &str) -> Result<HashMap<String, (String, String)>, String> {
    let mut stmt = conn
        .prepare("SELECT id, kind, label FROM graph_node WHERE engagement = ?1")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![engagement], |r| {
            Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<HashMap<_, _>>>().map_err(|e| e.to_string())
}

/// Directed edges (src, dst) whose kind is in `kinds`, engagement-scoped.
fn edges_of(conn: &Connection, engagement: &str, kinds: &[&str]) -> Result<Vec<(String, String)>, String> {
    if kinds.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = kinds.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!("SELECT src, dst FROM graph_edge WHERE engagement = ? AND kind IN ({placeholders})");
    let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
    let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(kinds.len() + 1);
    binds.push(&engagement);
    for k in kinds {
        binds.push(k);
    }
    let rows = stmt
        .query_map(binds.as_slice(), |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|e| e.to_string())
}

fn adjacency(edges: &[(String, String)]) -> HashMap<String, Vec<String>> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for (s, d) in edges {
        adj.entry(s.clone()).or_default().push(d.clone());
    }
    adj
}

// ---------------------------------------------------------------------------
// impact_analysis
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReachedNode {
    pub label: String,
    pub kind: String,
    pub hops: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    pub node: String,
    pub kind: String,
    pub reached_count: usize,
    pub crown_jewels_reached: Vec<String>,
    pub reachable: Vec<ReachedNode>,
}

/// Resolve a node id from a label (and optional kind) within the engagement.
fn resolve_node(
    nodes: &HashMap<String, (String, String)>,
    label: &str,
    kind: Option<&str>,
) -> Option<(String, String, String)> {
    nodes.iter().find_map(|(id, (k, l))| {
        (l == label && kind.map(|kk| kk == k).unwrap_or(true))
            .then(|| (id.clone(), k.clone(), l.clone()))
    })
}

/// Blast radius: every node reachable FROM `node` over the attack-relationship
/// whitelist, with the minimum hop distance, bounded by `max_depth`.
pub fn impact_analysis(
    conn: &Connection,
    engagement: &str,
    node: &str,
    kind: Option<&str>,
    max_depth: usize,
) -> Result<ImpactReport, String> {
    let nodes = node_map(conn, engagement)?;
    let (start_id, start_kind, start_label) =
        resolve_node(&nodes, node, kind).ok_or_else(|| format!("node '{node}' not found in the graph"))?;

    let adj = adjacency(&edges_of(conn, engagement, ATTACK_RELS)?);

    // BFS for minimum hops.
    let mut seen: HashSet<String> = HashSet::from([start_id.clone()]);
    let mut q: VecDeque<(String, usize)> = VecDeque::from([(start_id.clone(), 0usize)]);
    let mut reached: Vec<ReachedNode> = Vec::new();
    while let Some((id, hops)) = q.pop_front() {
        if hops >= max_depth {
            continue;
        }
        for dst in adj.get(&id).into_iter().flatten() {
            if seen.insert(dst.clone()) {
                let (k, l) = nodes.get(dst).cloned().unwrap_or_else(|| ("Unknown".into(), dst.clone()));
                reached.push(ReachedNode { label: l, kind: k, hops: hops + 1 });
                q.push_back((dst.clone(), hops + 1));
            }
        }
    }

    reached.sort_by(|a, b| a.hops.cmp(&b.hops).then(a.label.cmp(&b.label)));
    let crown_jewels_reached = reached
        .iter()
        .filter(|r| r.kind == "CrownJewel")
        .map(|r| r.label.clone())
        .collect();

    Ok(ImpactReport {
        node: start_label,
        kind: start_kind,
        reached_count: reached.len(),
        crown_jewels_reached,
        reachable: reached,
    })
}

// ---------------------------------------------------------------------------
// unexplored_surface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnexploredService {
    pub label: String,
    pub kind: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnexploredReport {
    pub count: usize,
    pub services: Vec<UnexploredService>,
}

/// Services (and web Entrypoints) with no `HAS_VULN` edge yet — the attack
/// surface recon found but nobody has analyzed. Each is mapped back to its Host
/// (via `RUNS`/`EXPOSES`) when known.
pub fn unexplored_surface(conn: &Connection, engagement: &str) -> Result<UnexploredReport, String> {
    let nodes = node_map(conn, engagement)?;

    // Nodes that already have a vulnerability recorded against them.
    let has_vuln: HashSet<String> = edges_of(conn, engagement, &["HAS_VULN"])?
        .into_iter()
        .map(|(s, _)| s)
        .collect();

    // Host -RUNS/EXPOSES-> Service : map service id -> host label.
    let mut host_of: HashMap<String, String> = HashMap::new();
    for (src, dst) in edges_of(conn, engagement, &["RUNS", "EXPOSES"])? {
        if let Some((k, l)) = nodes.get(&src) {
            if k == "Host" {
                host_of.entry(dst).or_insert_with(|| l.clone());
            }
        }
    }

    let mut services: Vec<UnexploredService> = nodes
        .iter()
        .filter(|(id, (kind, _))| (kind == "Service" || kind == "Entrypoint") && !has_vuln.contains(*id))
        .map(|(id, (kind, label))| UnexploredService {
            label: label.clone(),
            kind: kind.clone(),
            host: host_of.get(id).cloned(),
        })
        .collect();
    services.sort_by(|a, b| a.label.cmp(&b.label));

    Ok(UnexploredReport { count: services.len(), services })
}

// ---------------------------------------------------------------------------
// credential_reachability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredReach {
    pub credential: String,
    pub users: Vec<String>,
    pub reaches: Vec<ReachedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredReport {
    pub count: usize,
    pub credentials: Vec<CredReach>,
}

/// For every `Credential`/`Secret`, what it unlocks: the Users it
/// `AUTHENTICATES_TO`, then the assets those users can `CAN_ACCESS`/`ADMIN_TO`/
/// `HAS_SESSION` (hop distance 1 = the user, 2 = the asset).
pub fn credential_reachability(conn: &Connection, engagement: &str) -> Result<CredReport, String> {
    let nodes = node_map(conn, engagement)?;
    let auth = adjacency(&edges_of(conn, engagement, &["AUTHENTICATES_TO"])?);
    let access = adjacency(&edges_of(conn, engagement, &["CAN_ACCESS", "ADMIN_TO", "HAS_SESSION"])?);

    let label = |id: &str| nodes.get(id).map(|(_, l)| l.clone()).unwrap_or_else(|| id.to_string());
    let kind = |id: &str| nodes.get(id).map(|(k, _)| k.clone()).unwrap_or_else(|| "Unknown".into());

    let mut creds: Vec<CredReach> = Vec::new();
    for (id, (k, l)) in nodes.iter() {
        if k != "Credential" && k != "Secret" {
            continue;
        }
        let user_ids: Vec<String> = auth.get(id).cloned().unwrap_or_default();
        if user_ids.is_empty() {
            continue; // a credential that authenticates to nothing (yet) is not reachable
        }
        let mut reaches: Vec<ReachedNode> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for u in &user_ids {
            if seen.insert(u.clone()) {
                reaches.push(ReachedNode { label: label(u), kind: kind(u), hops: 1 });
            }
            for a in access.get(u).into_iter().flatten() {
                if seen.insert(a.clone()) {
                    reaches.push(ReachedNode { label: label(a), kind: kind(a), hops: 2 });
                }
            }
        }
        reaches.sort_by(|x, y| x.hops.cmp(&y.hops).then(x.label.cmp(&y.label)));
        creds.push(CredReach {
            credential: l.clone(),
            users: user_ids.iter().map(|u| label(u)).collect(),
            reaches,
        });
    }
    creds.sort_by(|a, b| a.credential.cmp(&b.credential));

    Ok(CredReport { count: creds.len(), credentials: creds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kg_upsert_edge, kg_upsert_node, open_memory};

    fn n(conn: &Connection, kind: &str, label: &str) -> String {
        kg_upsert_node(conn, "e", kind, label, Some(label), "{}").unwrap()
    }
    fn e(conn: &Connection, src: &str, dst: &str, kind: &str) {
        kg_upsert_edge(conn, "e", src, dst, kind, 1.0, None, "{}").unwrap();
    }

    #[test]
    fn impact_is_the_blast_radius() {
        let c = open_memory();
        let entry = n(&c, "Entrypoint", "web");
        let host = n(&c, "Host", "app01");
        let dc = n(&c, "CrownJewel", "domain-admin");
        let unrelated = n(&c, "Host", "island");
        e(&c, &entry, &host, "EXPLOITS");
        e(&c, &host, &dc, "ADMIN_TO");
        let _ = unrelated;

        let r = impact_analysis(&c, "e", "web", None, 8).unwrap();
        assert_eq!(r.node, "web");
        assert_eq!(r.reached_count, 2); // app01 (1 hop), domain-admin (2 hops)
        assert_eq!(r.crown_jewels_reached, vec!["domain-admin"]);
        assert_eq!(r.reachable[0], ReachedNode { label: "app01".into(), kind: "Host".into(), hops: 1 });
        // island is not reachable.
        assert!(!r.reachable.iter().any(|x| x.label == "island"));
        // depth bound: only 1 hop → the DC (2 hops) drops out.
        let shallow = impact_analysis(&c, "e", "web", None, 1).unwrap();
        assert_eq!(shallow.reached_count, 1);
        assert!(shallow.crown_jewels_reached.is_empty());
    }

    #[test]
    fn impact_unknown_node_errors() {
        let c = open_memory();
        n(&c, "Host", "h");
        assert!(impact_analysis(&c, "e", "nope", None, 5).is_err());
    }

    #[test]
    fn unexplored_lists_services_without_has_vuln() {
        let c = open_memory();
        let host = n(&c, "Host", "app01");
        let s80 = n(&c, "Service", "app01:80/http");
        let s22 = n(&c, "Service", "app01:22/ssh");
        e(&c, &host, &s80, "RUNS");
        e(&c, &host, &s22, "RUNS");
        // s80 already has a vuln; s22 does not.
        let v = n(&c, "Vulnerability", "CVE-x");
        e(&c, &s80, &v, "HAS_VULN");

        let r = unexplored_surface(&c, "e").unwrap();
        assert_eq!(r.count, 1);
        assert_eq!(r.services[0].label, "app01:22/ssh");
        assert_eq!(r.services[0].host.as_deref(), Some("app01"));
    }

    #[test]
    fn credential_reachability_walks_auth_then_access() {
        let c = open_memory();
        let cred = n(&c, "Credential", "svc_sql:hash");
        let user = n(&c, "ADUser", "SVC_SQL");
        let dc = n(&c, "ADComputer", "DC01");
        e(&c, &cred, &user, "AUTHENTICATES_TO");
        e(&c, &user, &dc, "ADMIN_TO");

        let r = credential_reachability(&c, "e").unwrap();
        assert_eq!(r.count, 1);
        let cr = &r.credentials[0];
        assert_eq!(cr.credential, "svc_sql:hash");
        assert_eq!(cr.users, vec!["SVC_SQL"]);
        // reaches the user (hop 1) and DC01 (hop 2, ADMIN_TO).
        assert!(cr.reaches.iter().any(|x| x.label == "DC01" && x.hops == 2));
        assert!(cr.reaches.iter().any(|x| x.label == "SVC_SQL" && x.hops == 1));
    }

    #[test]
    fn credential_with_no_auth_edge_is_skipped() {
        let c = open_memory();
        n(&c, "Credential", "orphan");
        assert_eq!(credential_reachability(&c, "e").unwrap().count, 0);
    }
}
