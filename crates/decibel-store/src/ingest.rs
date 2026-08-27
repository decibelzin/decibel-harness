//! Recon-output ingestion: parse the native arsenal's JSON output into the
//! knowledge graph (the `kg_ingest_*` capability from the port spec §7).
//!
//! Each parser turns one tool's JSON into engagement-scoped nodes/edges via the
//! KG upsert API, following the upstream node/edge vocabulary
//! (Host/Service/URL/Entrypoint/Technology; RUNS/EXPOSES/RESOLVES_TO/USES) and
//! the "web ports become entrypoints" rule. Pure + deterministic → unit-testable
//! without a live scanner: feed captured JSON, assert the graph.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{kg_upsert_edge, kg_upsert_node, with_tx, Connection};

// Node kinds (PascalCase, matching upstream Neo4j labels).
const HOST: &str = "Host";
const SERVICE: &str = "Service";
const URL: &str = "URL";
const ENTRYPOINT: &str = "Entrypoint";
const TECHNOLOGY: &str = "Technology";
const VULNERABILITY: &str = "Vulnerability";

// Vuln-research pipeline node kinds (auto-produced from the pipeline's workspace
// JSONL artifacts — KG-5).
const CANDIDATE: &str = "Candidate";
const HYPOTHESIS: &str = "Hypothesis";
const PATCH: &str = "Patch";

// Edge kinds (UPPER_SNAKE, matching upstream relationship types).
const RUNS: &str = "RUNS";
const EXPOSES: &str = "EXPOSES";
const RESOLVES_TO: &str = "RESOLVES_TO";
const USES: &str = "USES";
const HAS_VULN: &str = "HAS_VULN";

// Active Directory (BloodHound) node kinds — see `crate::vocab`.
const AD_USER: &str = "ADUser";
const AD_COMPUTER: &str = "ADComputer";
const AD_GROUP: &str = "ADGroup";
const AD_DOMAIN: &str = "ADDomain";
const AD_GPO: &str = "ADGPO";
const AD_OU: &str = "ADOU";
const AD_CERT_TEMPLATE: &str = "ADCertTemplate";
const AD_CERT_AUTHORITY: &str = "ADCertAuthority";
const CREDENTIAL: &str = "Credential";

/// How many nodes/edges an ingest produced.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IngestReport {
    pub nodes: usize,
    pub edges: usize,
}

/// Dispatch to the right parser by tool name. Covers the six native arsenal
/// tools plus common third-party scanners the agent runs through `shell`/`bash`
/// (their JSON/JSONL output → the same KG), so heavy firepower feeds the graph.
///
/// The whole ingest runs inside one SQL transaction (KG-7): a multi-node/edge
/// parser that fails midway rolls back entirely, so the graph never holds a
/// partial ingest.
pub fn ingest(conn: &Connection, engagement: &str, tool: &str, json: &str) -> Result<IngestReport, String> {
    with_tx(conn, |conn| ingest_inner(conn, engagement, tool, json))
}

/// The raw dispatch (no transaction of its own — `ingest` wraps it). Kept separate
/// so tests can compose several ingests inside one caller-owned transaction.
fn ingest_inner(conn: &Connection, engagement: &str, tool: &str, json: &str) -> Result<IngestReport, String> {
    match tool {
        "port-scan" | "port_scan" => ingest_port_scan(conn, engagement, json),
        "http-probe" | "http_probe" => ingest_http_probe(conn, engagement, json),
        "dns" | "dns-sub" => ingest_dns(conn, engagement, json),
        "content-discovery" | "content_discovery" => ingest_content(conn, engagement, json),
        "web-crawl" | "crawl" => ingest_crawl(conn, engagement, json),
        "tls-inspect" | "tls" => ingest_tls(conn, engagement, json),
        // Third-party scanners (JSON/JSONL).
        "nuclei" | "nuclei-jsonl" => ingest_nuclei(conn, engagement, json),
        "httpx" | "httpx-jsonl" => ingest_httpx(conn, engagement, json),
        "masscan" | "masscan-json" => ingest_masscan(conn, engagement, json),
        "ffuf" | "ffuf-json" => ingest_ffuf(conn, engagement, json),
        "dnsx" | "dnsx-jsonl" => ingest_dnsx(conn, engagement, json),
        "katana" | "katana-jsonl" => ingest_katana(conn, engagement, json),
        // Third-party scanner (XML).
        "nmap" | "nmap-xml" => ingest_nmap(conn, engagement, json),
        // Smart-contract static analyzer.
        "slither" | "slither-json" => ingest_slither(conn, engagement, json),
        // Active Directory attack graph (BloodHound / SharpHound JSON).
        "bloodhound" | "sharphound" => ingest_bloodhound(conn, engagement, json),
        // TLS posture (testssl.sh --jsonfile).
        "testssl" | "testssl-json" => ingest_testssl(conn, engagement, json),
        // Static-analysis results (SARIF v2.1.0 — semgrep/codeql/…).
        "sarif" => ingest_sarif(conn, engagement, json),
        // Dumped credentials (impacket secretsdump text output).
        "impacket" | "secretsdump" => ingest_secretsdump(conn, engagement, json),
        // Host/credential recon (netexec/crackmapexec JSON).
        "cme" | "netexec" | "nxc" => ingest_netexec(conn, engagement, json),
        // Vuln-research pipeline artifacts (JSONL or `{items:[...]}`) → pipeline
        // nodes (KG-5): scanner candidates, detector hypotheses, patcher patches.
        "candidates" | "candidate" => ingest_candidates(conn, engagement, json),
        "hypotheses" | "hypothesis" => ingest_hypotheses(conn, engagement, json),
        "patches" | "patch" => ingest_patches(conn, engagement, json),
        other => Err(format!("unknown ingest tool: {other}")),
    }
}

/// True for ports/services that should also surface as web entrypoints.
fn is_web(port: u64, service: Option<&str>) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443 | 8000 | 8888)
        || matches!(service, Some("http") | Some("https") | Some("http-proxy") | Some("https-alt"))
}

/// Ingest `decepticon-arsenal port-scan` JSON:
/// `{ target, open_ports:[{port, service?, banner?}], scanned }`.
pub fn ingest_port_scan(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse port-scan json: {e}"))?;
    let target = v["target"].as_str().ok_or("port-scan: missing target")?;
    let mut rep = IngestReport::default();

    let host = kg_upsert_node(conn, engagement, HOST, target, Some(target), "{}")?;
    rep.nodes += 1;

    if let Some(ports) = v["open_ports"].as_array() {
        for p in ports {
            let port = match p["port"].as_u64() {
                Some(n) => n,
                None => continue,
            };
            let service = p["service"].as_str();
            let key = format!("{target}:{port}");
            let label = match service {
                Some(s) => format!("{target}:{port}/{s}"),
                None => key.clone(),
            };
            let mut props = serde_json::Map::new();
            props.insert("port".into(), Value::from(port));
            if let Some(s) = service {
                props.insert("service".into(), Value::from(s));
            }
            if let Some(b) = p["banner"].as_str() {
                props.insert("banner".into(), Value::from(b));
            }
            let svc = kg_upsert_node(
                conn,
                engagement,
                SERVICE,
                &label,
                Some(&key),
                &Value::Object(props).to_string(),
            )?;
            rep.nodes += 1;
            kg_upsert_edge(conn, engagement, &host, &svc, RUNS, 1.0, None, "{}")?;
            rep.edges += 1;

            if is_web(port, service) {
                let scheme = if port == 443 || service == Some("https") { "https" } else { "http" };
                let url = format!("{scheme}://{target}:{port}");
                let ep = kg_upsert_node(conn, engagement, ENTRYPOINT, &url, Some(&url), "{}")?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &svc, &ep, EXPOSES, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `decepticon-arsenal http-probe` JSON:
/// `{ url, status, title?, server?, technologies:[..] }`.
pub fn ingest_http_probe(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse http-probe json: {e}"))?;
    let url = v["url"].as_str().ok_or("http-probe: missing url")?;
    let mut rep = IngestReport::default();

    let mut props = serde_json::Map::new();
    if let Some(s) = v["status"].as_u64() {
        props.insert("status".into(), Value::from(s));
    }
    if let Some(t) = v["title"].as_str() {
        props.insert("title".into(), Value::from(t));
    }
    if let Some(sv) = v["server"].as_str() {
        props.insert("server".into(), Value::from(sv));
    }
    let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
    rep.nodes += 1;

    // Link to the host it lives on.
    if let Some(host_str) = url_host(url) {
        let host = kg_upsert_node(conn, engagement, HOST, host_str, Some(host_str), "{}")?;
        rep.nodes += 1;
        kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
        rep.edges += 1;
    }

    if let Some(techs) = v["technologies"].as_array() {
        for t in techs {
            if let Some(name) = t.as_str() {
                let tech = kg_upsert_node(conn, engagement, TECHNOLOGY, name, Some(name), "{}")?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &url_node, &tech, USES, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `decepticon-arsenal dns` JSON: `{ name, addrs:[..], resolved }`.
pub fn ingest_dns(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse dns json: {e}"))?;
    let name = v["name"].as_str().ok_or("dns: missing name")?;
    let mut rep = IngestReport::default();

    let host = kg_upsert_node(conn, engagement, HOST, name, Some(name), "{}")?;
    rep.nodes += 1;

    if let Some(addrs) = v["addrs"].as_array() {
        for a in addrs {
            if let Some(addr) = a.as_str() {
                let ip = kg_upsert_node(conn, engagement, HOST, addr, Some(addr), r#"{"kind_hint":"ip"}"#)?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &host, &ip, RESOLVES_TO, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `decepticon-arsenal content-discovery` JSON:
/// `{ base, hits:[{url, status, size}] }`. Each hit becomes a URL node linked to
/// its host.
pub fn ingest_content(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse content json: {e}"))?;
    let mut rep = IngestReport::default();
    if let Some(hits) = v["hits"].as_array() {
        for hit in hits {
            let url = match hit["url"].as_str() {
                Some(u) => u,
                None => continue,
            };
            let mut props = serde_json::Map::new();
            if let Some(s) = hit["status"].as_u64() {
                props.insert("status".into(), Value::from(s));
            }
            if let Some(sz) = hit["size"].as_u64() {
                props.insert("size".into(), Value::from(sz));
            }
            let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
            rep.nodes += 1;
            if let Some(h) = url_host(url) {
                let host = kg_upsert_node(conn, engagement, HOST, h, Some(h), "{}")?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `decepticon-arsenal web-crawl` JSON: `{ pages:[{url, status, title}] }`.
/// Each crawled page becomes a URL node linked to its host.
pub fn ingest_crawl(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse crawl json: {e}"))?;
    let mut rep = IngestReport::default();
    if let Some(pages) = v["pages"].as_array() {
        for page in pages {
            let url = match page["url"].as_str() {
                Some(u) => u,
                None => continue,
            };
            let mut props = serde_json::Map::new();
            if let Some(s) = page["status"].as_u64() {
                props.insert("status".into(), Value::from(s));
            }
            if let Some(t) = page["title"].as_str() {
                props.insert("title".into(), Value::from(t));
            }
            let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
            rep.nodes += 1;
            if let Some(h) = url_host(url) {
                let host = kg_upsert_node(conn, engagement, HOST, h, Some(h), "{}")?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `decepticon-arsenal tls-inspect` JSON: enrich the Host node with the
/// certificate's subject/issuer/validity/SANs.
pub fn ingest_tls(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse tls json: {e}"))?;
    let host = v["host"].as_str().ok_or("tls: missing host")?;

    let mut props = serde_json::Map::new();
    for (src, dst) in [
        ("subject", "tls_subject"),
        ("issuer", "tls_issuer"),
        ("not_before", "tls_not_before"),
        ("not_after", "tls_not_after"),
        ("protocol", "tls_protocol"),
        ("cipher", "tls_cipher"),
    ] {
        if let Some(s) = v[src].as_str() {
            props.insert(dst.into(), Value::from(s));
        }
    }
    if let Some(sans) = v["sans"].as_array() {
        props.insert("tls_sans".into(), Value::Array(sans.clone()));
    }

    kg_upsert_node(conn, engagement, HOST, host, Some(host), &Value::Object(props).to_string())?;
    Ok(IngestReport { nodes: 1, edges: 0 })
}

/// Parse a scanner's output as records: a JSON array `[ {...}, {...} ]` OR
/// newline-delimited JSON (`{...}\n{...}` — nuclei/httpx `-jsonl`). Malformed
/// lines are skipped so a partial capture still ingests what parsed.
fn records(json: &str) -> Vec<Value> {
    let trimmed = json.trim_start();
    if trimmed.starts_with('[') {
        return serde_json::from_str::<Value>(json)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
    }
    json.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// Like [`records`], but also unwraps a `{ "<key>": [...] }` envelope (the pipeline
/// personas may write either bare JSON-lines or a single object wrapping an array).
/// A top-level object that is NOT such an envelope is treated as one record.
fn records_or_items(json: &str, keys: &[&str]) -> Vec<Value> {
    let trimmed = json.trim_start();
    if trimmed.starts_with('{') {
        if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(json) {
            for k in keys {
                if let Some(arr) = o.get(*k).and_then(Value::as_array) {
                    return arr.clone();
                }
            }
            // A lone object that isn't a wrapper → a single record.
            return vec![Value::Object(o)];
        }
    }
    records(json)
}

/// First present string field among `keys`, trimmed, non-empty.
fn first_str<'a>(r: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|k| r[*k].as_str()).map(str::trim).filter(|s| !s.is_empty())
}

/// Ingest the scanner's `recon/candidates.jsonl` (or `{items:[...]}`): one line →
/// one `Candidate` node, props `path`/`line`/`rule` (KG-5). This is the auto-INGEST
/// producer for a pipeline kind that previously existed only via agent authoring.
pub fn ingest_candidates(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records_or_items(json, &["items", "candidates", "results"]) {
        let path = first_str(&r, &["path", "file", "location"]);
        let rule = first_str(&r, &["rule", "rule_id", "check", "category"]);
        let id = first_str(&r, &["id", "uid"]);
        let label = first_str(&r, &["label", "title", "name"]).or(rule).or(path);
        // Skip an empty/degenerate record (nothing to identify it by).
        let (Some(label), true) = (label, path.is_some() || rule.is_some() || id.is_some()) else { continue };
        let line = r["line"].as_u64();
        let key = id
            .map(str::to_string)
            .unwrap_or_else(|| format!("candidate:{}@{}:{}", rule.unwrap_or(""), path.unwrap_or(""), line.unwrap_or(0)));
        let mut props = serde_json::Map::new();
        if let Some(p) = path {
            props.insert("path".into(), Value::from(p));
        }
        if let Some(l) = line {
            props.insert("line".into(), Value::from(l));
        }
        if let Some(ru) = rule {
            props.insert("rule".into(), Value::from(ru));
        }
        kg_upsert_node(conn, engagement, CANDIDATE, label, Some(&key), &Value::Object(props).to_string())?;
        rep.nodes += 1;
    }
    Ok(rep)
}

/// Ingest the detector's `findings/hypotheses.jsonl` (or `{items:[...]}`): one line
/// → one `Hypothesis` node (KG-5). When a record names a vulnerability/CVE, a
/// `Vulnerability` node is upserted and linked `Hypothesis -LEADS_TO-> Vulnerability`
/// so the hypothesis is traversable toward the vuln it concerns.
pub fn ingest_hypotheses(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records_or_items(json, &["items", "hypotheses", "results"]) {
        let id = first_str(&r, &["id", "uid"]);
        let title = first_str(&r, &["title", "hypothesis", "label", "name", "statement"]);
        let (Some(label), true) = (title.or(id), title.is_some() || id.is_some()) else { continue };
        let key = id.map(str::to_string).unwrap_or_else(|| format!("hypothesis:{label}"));
        let mut props = serde_json::Map::new();
        if let Some(p) = first_str(&r, &["path", "file", "location"]) {
            props.insert("path".into(), Value::from(p));
        }
        if let Some(conf) = first_str(&r, &["confidence"]) {
            props.insert("confidence".into(), Value::from(conf));
        }
        let hyp = kg_upsert_node(conn, engagement, HYPOTHESIS, label, Some(&key), &Value::Object(props).to_string())?;
        rep.nodes += 1;
        // Optional link to the vulnerability the hypothesis is about.
        if let Some(vuln) = first_str(&r, &["vulnerability", "vuln", "cve"]) {
            let v = kg_upsert_node(conn, engagement, VULNERABILITY, vuln, Some(vuln), "{}")?;
            rep.nodes += 1;
            kg_upsert_edge(conn, engagement, &hyp, &v, "LEADS_TO", 1.0, None, "{}")?;
            rep.edges += 1;
        }
    }
    Ok(rep)
}

/// Ingest the patcher's `findings/patches.jsonl` (or `{items:[...]}`): one line →
/// one `Patch` node (KG-5), props `path`/`target`/`description`.
pub fn ingest_patches(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records_or_items(json, &["items", "patches", "results"]) {
        let id = first_str(&r, &["id", "uid"]);
        let title = first_str(&r, &["title", "label", "name", "patch"]);
        let path = first_str(&r, &["path", "file", "location"]);
        let label = title.or(path).or(id);
        let (Some(label), true) = (label, title.is_some() || path.is_some() || id.is_some()) else { continue };
        let key = id.map(str::to_string).unwrap_or_else(|| format!("patch:{label}"));
        let mut props = serde_json::Map::new();
        if let Some(p) = path {
            props.insert("path".into(), Value::from(p));
        }
        if let Some(t) = first_str(&r, &["target", "fixes", "vulnerability", "finding"]) {
            props.insert("target".into(), Value::from(t));
        }
        if let Some(d) = first_str(&r, &["description", "detail", "summary"]) {
            props.insert("description".into(), Value::from(d));
        }
        kg_upsert_node(conn, engagement, PATCH, label, Some(&key), &Value::Object(props).to_string())?;
        rep.nodes += 1;
    }
    Ok(rep)
}

/// Ingest `nuclei -jsonl` output: each finding → a `Vulnerability` node linked to
/// the affected Host (`HAS_VULN`). This is the first ingester to emit the
/// Vulnerability vocabulary, so heavy-scanner findings reach the graph + planner.
pub fn ingest_nuclei(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let matched = r["matched-at"].as_str().or_else(|| r["host"].as_str());
        let matched = match matched {
            Some(m) => m,
            None => continue,
        };
        let template = r["template-id"].as_str().or_else(|| r["template"].as_str()).unwrap_or("finding");
        let host_str = url_host(matched).unwrap_or(matched);
        let host = kg_upsert_node(conn, engagement, HOST, host_str, Some(host_str), "{}")?;
        rep.nodes += 1;

        let mut props = serde_json::Map::new();
        props.insert("template".into(), Value::from(template));
        props.insert("matched_at".into(), Value::from(matched));
        if let Some(sev) = r["info"]["severity"].as_str() {
            props.insert("severity".into(), Value::from(sev));
        }
        if let Some(name) = r["info"]["name"].as_str() {
            props.insert("name".into(), Value::from(name));
        }
        let label = r["info"]["name"].as_str().unwrap_or(template);
        let key = format!("{template}@{matched}");
        let vuln = kg_upsert_node(conn, engagement, VULNERABILITY, label, Some(&key), &Value::Object(props).to_string())?;
        rep.nodes += 1;
        kg_upsert_edge(conn, engagement, &host, &vuln, HAS_VULN, 1.0, None, "{}")?;
        rep.edges += 1;
    }
    Ok(rep)
}

/// Ingest `httpx -json` (array or `-jsonl`) output: each probed URL → a `URL`
/// node on its `Host`, with `webserver`/`tech` mapped like the native probe.
pub fn ingest_httpx(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let url = match r["url"].as_str() {
            Some(u) => u,
            None => continue,
        };
        let mut props = serde_json::Map::new();
        if let Some(s) = r["status_code"].as_u64().or_else(|| r["status-code"].as_u64()) {
            props.insert("status".into(), Value::from(s));
        }
        if let Some(t) = r["title"].as_str() {
            props.insert("title".into(), Value::from(t));
        }
        if let Some(sv) = r["webserver"].as_str().or_else(|| r["server"].as_str()) {
            props.insert("server".into(), Value::from(sv));
        }
        let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
        rep.nodes += 1;
        if let Some(h) = url_host(url) {
            let host = kg_upsert_node(conn, engagement, HOST, h, Some(h), "{}")?;
            rep.nodes += 1;
            kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
            rep.edges += 1;
        }
        if let Some(techs) = r["tech"].as_array().or_else(|| r["technologies"].as_array()) {
            for t in techs {
                if let Some(name) = t.as_str() {
                    let tech = kg_upsert_node(conn, engagement, TECHNOLOGY, name, Some(name), "{}")?;
                    rep.nodes += 1;
                    kg_upsert_edge(conn, engagement, &url_node, &tech, USES, 1.0, None, "{}")?;
                    rep.edges += 1;
                }
            }
        }
    }
    Ok(rep)
}

/// Ingest `masscan -oJ` output (`[{ip, ports:[{port, proto, status}]}]`): each
/// open port → a `Service` on its `Host`, web ports promoted to `Entrypoint`
/// (same rule as the native port-scan).
pub fn ingest_masscan(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let ip = match r["ip"].as_str() {
            Some(i) => i,
            None => continue,
        };
        let host = kg_upsert_node(conn, engagement, HOST, ip, Some(ip), "{}")?;
        rep.nodes += 1;
        if let Some(ports) = r["ports"].as_array() {
            for p in ports {
                // masscan reports open ports; a `status` field (if present) must say so.
                if let Some(st) = p["status"].as_str() {
                    if st != "open" {
                        continue;
                    }
                }
                let port = match p["port"].as_u64() {
                    Some(n) => n,
                    None => continue,
                };
                let key = format!("{ip}:{port}");
                let mut props = serde_json::Map::new();
                props.insert("port".into(), Value::from(port));
                if let Some(proto) = p["proto"].as_str() {
                    props.insert("proto".into(), Value::from(proto));
                }
                let svc = kg_upsert_node(conn, engagement, SERVICE, &key, Some(&key), &Value::Object(props).to_string())?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &host, &svc, RUNS, 1.0, None, "{}")?;
                rep.edges += 1;
                if is_web(port, None) {
                    let scheme = if port == 443 { "https" } else { "http" };
                    let url = format!("{scheme}://{ip}:{port}");
                    let ep = kg_upsert_node(conn, engagement, ENTRYPOINT, &url, Some(&url), "{}")?;
                    rep.nodes += 1;
                    kg_upsert_edge(conn, engagement, &svc, &ep, EXPOSES, 1.0, None, "{}")?;
                    rep.edges += 1;
                }
            }
        }
    }
    Ok(rep)
}

/// Ingest `ffuf -o out.json` output (`{results:[{url, status, length}]}`): each
/// hit → a `URL` node on its `Host`.
pub fn ingest_ffuf(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse ffuf json: {e}"))?;
    let mut rep = IngestReport::default();
    if let Some(results) = v["results"].as_array() {
        for hit in results {
            let url = match hit["url"].as_str() {
                Some(u) => u,
                None => continue,
            };
            let mut props = serde_json::Map::new();
            if let Some(s) = hit["status"].as_u64() {
                props.insert("status".into(), Value::from(s));
            }
            if let Some(sz) = hit["length"].as_u64() {
                props.insert("size".into(), Value::from(sz));
            }
            let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
            rep.nodes += 1;
            if let Some(h) = url_host(url) {
                let host = kg_upsert_node(conn, engagement, HOST, h, Some(h), "{}")?;
                rep.nodes += 1;
                kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// Ingest `dnsx -json` (array or `-jsonl`) output: each record's A/AAAA answers →
/// `Host` RESOLVES_TO ip (same shape as the native dns ingester, at scale).
pub fn ingest_dnsx(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let name = match r["host"].as_str().or_else(|| r["name"].as_str()) {
            Some(n) => n,
            None => continue,
        };
        let host = kg_upsert_node(conn, engagement, HOST, name, Some(name), "{}")?;
        rep.nodes += 1;
        for key in ["a", "aaaa"] {
            if let Some(addrs) = r[key].as_array() {
                for a in addrs {
                    if let Some(addr) = a.as_str() {
                        let ip = kg_upsert_node(conn, engagement, HOST, addr, Some(addr), r#"{"kind_hint":"ip"}"#)?;
                        rep.nodes += 1;
                        kg_upsert_edge(conn, engagement, &host, &ip, RESOLVES_TO, 1.0, None, "{}")?;
                        rep.edges += 1;
                    }
                }
            }
        }
    }
    Ok(rep)
}

/// Ingest `katana -jsonl` output: each crawled endpoint → a `URL` node on its
/// `Host`. Accepts both the nested (`request.endpoint`) and flat (`url`) shapes.
pub fn ingest_katana(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let url = match r["request"]["endpoint"].as_str().or_else(|| r["url"].as_str()) {
            Some(u) => u,
            None => continue,
        };
        let mut props = serde_json::Map::new();
        if let Some(s) = r["response"]["status_code"].as_u64() {
            props.insert("status".into(), Value::from(s));
        }
        let url_node = kg_upsert_node(conn, engagement, URL, url, Some(url), &Value::Object(props).to_string())?;
        rep.nodes += 1;
        if let Some(h) = url_host(url) {
            let host = kg_upsert_node(conn, engagement, HOST, h, Some(h), "{}")?;
            rep.nodes += 1;
            kg_upsert_edge(conn, engagement, &host, &url_node, EXPOSES, 1.0, None, "{}")?;
            rep.edges += 1;
        }
    }
    Ok(rep)
}

/// Ingest `slither . --json` output: each detector → a `Vulnerability` node.
/// Slither's `impact` maps to the KG severity scale.
pub fn ingest_slither(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse slither json: {e}"))?;
    let detectors = v["results"]["detectors"].as_array().cloned().unwrap_or_default();
    let mut rep = IngestReport::default();
    for d in &detectors {
        let check = d["check"].as_str().unwrap_or("finding");
        let severity = match d["impact"].as_str().unwrap_or("").to_ascii_lowercase().as_str() {
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            "informational" | "optimization" => "info",
            _ => "medium",
        };
        // Key on check + the first element's name so repeated checks on different
        // functions get distinct nodes (idempotent per (check, location)).
        let loc = d["elements"].as_array().and_then(|a| a.first()).and_then(|e| e["name"].as_str()).unwrap_or("");
        let key = format!("slither:{check}@{loc}");
        let mut props = serde_json::Map::new();
        props.insert("severity".into(), Value::from(severity));
        props.insert("check".into(), Value::from(check));
        if let Some(desc) = d["description"].as_str() {
            props.insert("description".into(), Value::from(desc.trim()));
        }
        if let Some(conf) = d["confidence"].as_str() {
            props.insert("confidence".into(), Value::from(conf));
        }
        let label = if loc.is_empty() { check.to_string() } else { format!("{check} ({loc})") };
        kg_upsert_node(conn, engagement, VULNERABILITY, &label, Some(&key), &Value::Object(props).to_string())?;
        rep.nodes += 1;
    }
    Ok(rep)
}

/// Map a BloodHound object/principal type to a KG node kind.
fn bh_kind(t: &str) -> Option<&'static str> {
    match t.trim().to_ascii_lowercase().as_str() {
        "user" | "users" => Some(AD_USER),
        "computer" | "computers" => Some(AD_COMPUTER),
        "group" | "groups" => Some(AD_GROUP),
        "domain" | "domains" => Some(AD_DOMAIN),
        "gpo" | "gpos" => Some(AD_GPO),
        "ou" | "ous" => Some(AD_OU),
        "certtemplate" | "certtemplates" => Some(AD_CERT_TEMPLATE),
        "enterpriseca" | "enterprisecas" | "rootca" | "rootcas" | "aiaca" | "aiacas" | "ntauthstore"
        | "ntauthstores" => Some(AD_CERT_AUTHORITY),
        _ => None,
    }
}

/// Map a BloodHound ACE `RightName` to an attack-graph edge kind (a subset of the
/// AD/ADCS vocabulary the chain planner + credential/impact analyses traverse).
fn bh_right(right: &str) -> Option<&'static str> {
    match right.trim().to_ascii_lowercase().as_str() {
        "genericall" | "allextendedrights" => Some("GENERIC_ALL"),
        "genericwrite" => Some("GENERIC_WRITE"),
        "writedacl" => Some("WRITE_DACL"),
        "writeowner" => Some("WRITE_OWNER"),
        "owns" => Some("OWNS"),
        "forcechangepassword" => Some("FORCE_CHANGE_PASSWORD"),
        "addmember" | "addmembers" => Some("ADD_MEMBER"),
        "addkeycredentiallink" => Some("ADD_KEY_CREDENTIAL_LINK"),
        "dcsync" | "getchanges" | "getchangesall" => Some("DCSYNC"),
        "readlapspassword" => Some("READ_LAPS_PASSWORD"),
        "readgmsapassword" => Some("READ_GMSA_PASSWORD"),
        "allowedtodelegate" => Some("ALLOWED_TO_DELEGATE"),
        _ => None,
    }
}

/// Extract a `Results`-style array from a BloodHound field that may be either
/// `{ "Results": [...] }` (CE) or a bare `[...]` (legacy).
fn bh_results(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Object(o)) => o.get("Results").and_then(Value::as_array).cloned().unwrap_or_default(),
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    }
}

/// Upsert the node for a `{ObjectIdentifier, ObjectType}` reference (a group member,
/// local admin, …), returning its id. Type falls back to Group when unknown.
fn bh_endpoint(conn: &Connection, engagement: &str, m: &Value) -> Result<Option<String>, String> {
    let sid = m.get("ObjectIdentifier").and_then(Value::as_str).unwrap_or("");
    if sid.is_empty() {
        return Ok(None);
    }
    let kind = m.get("ObjectType").and_then(Value::as_str).and_then(bh_kind).unwrap_or(AD_GROUP);
    Ok(Some(kg_upsert_node(conn, engagement, kind, sid, Some(sid), "{}")?))
}

/// Ingest BloodHound/SharpHound JSON (one collector file: users/computers/groups/
/// domains/gpos/ous/certtemplates/…) into the AD attack graph. Objects become
/// ADUser/ADComputer/ADGroup/… nodes (keyed by SID so cross-file references merge),
/// and relationships become the AD/ADCS edges the chain planner + credential/impact
/// analyses already traverse: group `Members` → `MEMBER_OF`, computer `Sessions` →
/// `HAS_SESSION`, `LocalAdmins` → `ADMIN_TO`, and each `Ace` → its control edge
/// (GENERIC_ALL/WRITE_DACL/DCSYNC/…). Tolerant of the CE and legacy shapes.
pub fn ingest_bloodhound(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse bloodhound json: {e}"))?;
    let file_kind = v.get("meta").and_then(|m| m.get("type")).and_then(Value::as_str).and_then(bh_kind);
    let data = v.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut rep = IngestReport::default();

    for obj in &data {
        let sid = obj.get("ObjectIdentifier").and_then(Value::as_str).unwrap_or("");
        // The object's own kind: the file's meta.type, else a per-object hint.
        let kind = file_kind
            .or_else(|| obj.get("ObjectType").and_then(Value::as_str).and_then(bh_kind));
        let (Some(kind), false) = (kind, sid.is_empty()) else { continue };

        let props = obj.get("Properties");
        let name = props.and_then(|p| p.get("name")).and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(sid);
        let domain = props.and_then(|p| p.get("domain")).and_then(Value::as_str).unwrap_or("");
        let node_props = serde_json::json!({ "sid": sid, "domain": domain }).to_string();
        let this_id = kg_upsert_node(conn, engagement, kind, name, Some(sid), &node_props)?;
        rep.nodes += 1;

        // Group membership: member -MEMBER_OF-> group.
        if kind == AD_GROUP {
            for m in obj.get("Members").and_then(Value::as_array).into_iter().flatten() {
                if let Some(mid) = bh_endpoint(conn, engagement, m)? {
                    kg_upsert_edge(conn, engagement, &mid, &this_id, "MEMBER_OF", 1.0, None, "{}")?;
                    rep.edges += 1;
                }
            }
        }

        // Computer sessions + local admins.
        if kind == AD_COMPUTER {
            for s in bh_results(obj.get("Sessions")) {
                if let Some(user_sid) = s.get("UserSID").and_then(Value::as_str) {
                    let uid = kg_upsert_node(conn, engagement, AD_USER, user_sid, Some(user_sid), "{}")?;
                    kg_upsert_edge(conn, engagement, &this_id, &uid, "HAS_SESSION", 1.0, None, "{}")?;
                    rep.edges += 1;
                }
            }
            for a in bh_results(obj.get("LocalAdmins")) {
                if let Some(aid) = bh_endpoint(conn, engagement, &a)? {
                    kg_upsert_edge(conn, engagement, &aid, &this_id, "ADMIN_TO", 1.0, None, "{}")?;
                    rep.edges += 1;
                }
            }
        }

        // ACLs: principal -RIGHT-> this object.
        for ace in obj.get("Aces").and_then(Value::as_array).into_iter().flatten() {
            let psid = ace.get("PrincipalSID").and_then(Value::as_str).unwrap_or("");
            let right = ace.get("RightName").and_then(Value::as_str).unwrap_or("");
            let (Some(edge), false) = (bh_right(right), psid.is_empty()) else { continue };
            let pkind = ace.get("PrincipalType").and_then(Value::as_str).and_then(bh_kind).unwrap_or(AD_GROUP);
            let pid = kg_upsert_node(conn, engagement, pkind, psid, Some(psid), "{}")?;
            kg_upsert_edge(conn, engagement, &pid, &this_id, edge, 1.0, None, "{}")?;
            rep.edges += 1;
        }
    }
    Ok(rep)
}

/// Normalize a tool's severity word to the KG scale.
fn norm_severity(s: &str) -> Option<&'static str> {
    match s.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" | "error" => Some("high"),
        "medium" | "warning" | "moderate" => Some("medium"),
        "low" | "note" => Some("low"),
        "info" | "informational" | "none" => Some("info"),
        _ => None,
    }
}

/// Ingest `testssl.sh --jsonfile` output (array of `{id, ip, port, severity,
/// finding}`): every LOW+ item → a `Vulnerability` on its `Host` (`HAS_VULN`).
/// OK/INFO/WARN/DEBUG rows are skipped.
pub fn ingest_testssl(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for f in records(json) {
        let Some(sev) = f["severity"].as_str().and_then(norm_severity) else { continue };
        if sev == "info" {
            continue;
        }
        let ip = f["ip"].as_str().unwrap_or("");
        let host_label = ip.split('/').next().unwrap_or(ip).trim();
        if host_label.is_empty() {
            continue;
        }
        let id = f["id"].as_str().unwrap_or("finding");
        let port = f["port"].as_str().unwrap_or("");
        let host = kg_upsert_node(conn, engagement, HOST, host_label, Some(host_label), "{}")?;
        rep.nodes += 1;
        let key = format!("testssl:{host_label}:{port}:{id}");
        let props = serde_json::json!({ "severity": sev, "source": "testssl", "description": f["finding"].as_str().unwrap_or("").trim() }).to_string();
        let v = kg_upsert_node(conn, engagement, VULNERABILITY, id, Some(&key), &props)?;
        rep.nodes += 1;
        kg_upsert_edge(conn, engagement, &host, &v, HAS_VULN, 1.0, None, "{}")?;
        rep.edges += 1;
    }
    Ok(rep)
}

/// Ingest SARIF v2.1.0 (`runs[].results[]` — semgrep/codeql/any SARIF producer):
/// each result → a `Vulnerability` (severity from `level`, keyed by rule+location).
pub fn ingest_sarif(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("parse sarif: {e}"))?;
    let mut rep = IngestReport::default();
    for run in v["runs"].as_array().into_iter().flatten() {
        for res in run["results"].as_array().into_iter().flatten() {
            let rule = res["ruleId"].as_str().unwrap_or("finding");
            let sev = res["level"].as_str().and_then(norm_severity).unwrap_or("medium");
            let msg = res["message"]["text"].as_str().unwrap_or("");
            let loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str().unwrap_or("");
            let key = format!("sarif:{rule}@{loc}");
            let label = if loc.is_empty() { rule.to_string() } else { format!("{rule} ({loc})") };
            let props = serde_json::json!({ "severity": sev, "source": "sarif", "rule": rule, "description": msg.trim() }).to_string();
            kg_upsert_node(conn, engagement, VULNERABILITY, &label, Some(&key), &props)?;
            rep.nodes += 1;
        }
    }
    Ok(rep)
}

/// Ingest impacket `secretsdump.py` output (TEXT, not JSON): NTLM hash lines
/// `DOMAIN\user:rid:lmhash:nthash:::` → a `Credential` node per account (keyed by
/// user+NT hash). Non-hash lines (headers, kerberos keys, cleartext) are skipped.
pub fn ingest_secretsdump(conn: &Connection, engagement: &str, text: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for line in text.lines() {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let (rid, nt) = (parts[1], parts[3]);
        if rid.parse::<u64>().is_err() || nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let user = parts[0].rsplit('\\').next().unwrap_or(parts[0]).trim();
        if user.is_empty() {
            continue;
        }
        let key = format!("cred:{user}:{nt}");
        let props = serde_json::json!({ "nt": nt, "rid": rid, "source": "secretsdump" }).to_string();
        kg_upsert_node(conn, engagement, CREDENTIAL, user, Some(&key), &props)?;
        rep.nodes += 1;
    }
    Ok(rep)
}

/// Ingest netexec/crackmapexec JSON (best-effort, tolerant of the varying shapes):
/// each record → a `Host`/`ADComputer` (label = hostname/ip, props os/domain), and
/// any `user` + `password`/`hash` → a `Credential`, linked `ADMIN_TO` the host when
/// the record marks admin access.
pub fn ingest_netexec(conn: &Connection, engagement: &str, json: &str) -> Result<IngestReport, String> {
    let mut rep = IngestReport::default();
    for r in records(json) {
        let ip = r["host"].as_str().or_else(|| r["ip"].as_str()).unwrap_or("");
        let hostname = r["hostname"].as_str().or_else(|| r["name"].as_str()).filter(|s| !s.is_empty()).unwrap_or(ip);
        if hostname.is_empty() {
            continue;
        }
        let domain = r["domain"].as_str().unwrap_or("");
        let kind = if domain.is_empty() { HOST } else { AD_COMPUTER };
        let props = serde_json::json!({ "ip": ip, "domain": domain, "os": r["os"].as_str().unwrap_or("") }).to_string();
        let host = kg_upsert_node(conn, engagement, kind, hostname, Some(hostname), &props)?;
        rep.nodes += 1;
        if let Some(user) = r["user"].as_str().filter(|s| !s.is_empty()) {
            let secret = r["hash"].as_str().or_else(|| r["password"].as_str()).unwrap_or("");
            let key = format!("cred:{user}:{secret}");
            let cprops = serde_json::json!({ "source": "netexec", "domain": domain }).to_string();
            let cred = kg_upsert_node(conn, engagement, CREDENTIAL, user, Some(&key), &cprops)?;
            rep.nodes += 1;
            if r["admin"].as_bool().unwrap_or(false) {
                kg_upsert_edge(conn, engagement, &cred, &host, "ADMIN_TO", 1.0, None, "{}")?;
                rep.edges += 1;
            }
        }
    }
    Ok(rep)
}

/// One attribute of an XML start/empty tag as an owned string.
fn xml_attr(e: &quick_xml::events::BytesStart, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| String::from_utf8(a.value.into_owned()).ok())
}

/// Ingest `nmap -oX` XML: hosts → `Host`, each open port → a `Service` (`RUNS`)
/// with proto/service/version props, web ports promoted to `Entrypoint`. A small
/// SAX state machine (quick-xml) so a full nmap scan feeds the graph directly.
pub fn ingest_nmap(conn: &Connection, engagement: &str, xml: &str) -> Result<IngestReport, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    let mut rep = IngestReport::default();

    let mut host_addr: Option<String> = None;
    let mut host_node: Option<String> = None;
    // Current <port> being parsed.
    let mut port: Option<u64> = None;
    let mut proto: Option<String> = None;
    let mut state: Option<String> = None;
    let mut service: Option<String> = None;
    let mut product: Option<String> = None;
    let mut version: Option<String> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"address" => {
                    // Take the first ip address of the host; ignore MAC etc.
                    let kind = xml_attr(&e, b"addrtype").unwrap_or_default();
                    if (kind == "ipv4" || kind == "ipv6") && host_addr.is_none() {
                        if let Some(addr) = xml_attr(&e, b"addr") {
                            host_node = Some(kg_upsert_node(conn, engagement, HOST, &addr, Some(&addr), "{}")?);
                            rep.nodes += 1;
                            host_addr = Some(addr);
                        }
                    }
                }
                b"port" => {
                    port = xml_attr(&e, b"portid").and_then(|p| p.parse::<u64>().ok());
                    proto = xml_attr(&e, b"protocol");
                    state = None;
                    service = None;
                    product = None;
                    version = None;
                }
                b"state" => state = xml_attr(&e, b"state"),
                b"service" => {
                    service = xml_attr(&e, b"name");
                    product = xml_attr(&e, b"product");
                    version = xml_attr(&e, b"version");
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"port" => {
                    if state.as_deref() == Some("open") {
                        if let (Some(addr), Some(host), Some(p)) = (host_addr.as_ref(), host_node.as_ref(), port) {
                            let key = format!("{addr}:{p}");
                            let label = match service.as_deref() {
                                Some(s) => format!("{addr}:{p}/{s}"),
                                None => key.clone(),
                            };
                            let mut props = serde_json::Map::new();
                            props.insert("port".into(), Value::from(p));
                            if let Some(pr) = &proto {
                                props.insert("proto".into(), Value::from(pr.clone()));
                            }
                            if let Some(s) = &service {
                                props.insert("service".into(), Value::from(s.clone()));
                            }
                            let banner = [product.as_deref(), version.as_deref()]
                                .into_iter()
                                .flatten()
                                .collect::<Vec<_>>()
                                .join(" ");
                            if !banner.is_empty() {
                                props.insert("banner".into(), Value::from(banner));
                            }
                            let svc = kg_upsert_node(conn, engagement, SERVICE, &label, Some(&key), &Value::Object(props).to_string())?;
                            rep.nodes += 1;
                            kg_upsert_edge(conn, engagement, host, &svc, RUNS, 1.0, None, "{}")?;
                            rep.edges += 1;

                            if is_web(p, service.as_deref()) {
                                let scheme = if p == 443 || service.as_deref() == Some("https") { "https" } else { "http" };
                                let url = format!("{scheme}://{addr}:{p}");
                                let ep = kg_upsert_node(conn, engagement, ENTRYPOINT, &url, Some(&url), "{}")?;
                                rep.nodes += 1;
                                kg_upsert_edge(conn, engagement, &svc, &ep, EXPOSES, 1.0, None, "{}")?;
                                rep.edges += 1;
                            }
                        }
                    }
                    port = None;
                }
                b"host" => {
                    host_addr = None;
                    host_node = None;
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("parse nmap xml: {e}")),
            _ => {}
        }
    }
    Ok(rep)
}

/// Extract the host portion from a URL (`http://host:port/path` → `host`).
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kg_by_kind, kg_neighbors, kg_stats, node_id, open_memory};

    #[test]
    fn ingest_port_scan_builds_host_services_entrypoints() {
        let conn = open_memory();
        let json = r#"{"target":"10.10.10.5","open_ports":[
            {"port":22,"open":true,"service":"ssh","banner":"OpenSSH 8.2"},
            {"port":80,"open":true,"service":"http"}
        ],"scanned":2}"#;
        let rep = ingest_port_scan(&conn, "acme", json).unwrap();

        // 1 host + 2 services + 1 entrypoint (web port 80).
        assert_eq!(rep.nodes, 4);
        // 2 RUNS + 1 EXPOSES.
        assert_eq!(rep.edges, 3);

        let stats = kg_stats(&conn, "acme").unwrap();
        assert_eq!(stats.nodes, 4);
        assert_eq!(stats.edges, 3);

        // The host RUNS two services.
        let host = node_id("Host", "10.10.10.5");
        let neigh = kg_neighbors(&conn, "acme", &host, "out").unwrap();
        assert_eq!(neigh.iter().filter(|n| n.kind == "Service").count(), 2);
        // One entrypoint exists.
        assert_eq!(kg_by_kind(&conn, "acme", "Entrypoint").unwrap().len(), 1);
    }

    #[test]
    fn ingest_http_probe_builds_url_host_and_tech() {
        let conn = open_memory();
        let json = r#"{"url":"http://10.10.10.5:80/","status":200,"title":"ACME","server":"nginx","technologies":["nginx","WordPress"]}"#;
        let rep = ingest_http_probe(&conn, "acme", json).unwrap();

        // url + host + 2 tech = 4 nodes; host->EXPOSES->url + 2 USES = 3 edges.
        assert_eq!(rep.nodes, 4);
        assert_eq!(rep.edges, 3);

        let urls = kg_by_kind(&conn, "acme", "URL").unwrap();
        assert_eq!(urls.len(), 1);
        let props: serde_json::Value = serde_json::from_str(&urls[0].props_json).unwrap();
        assert_eq!(props["server"], "nginx");
        assert_eq!(props["status"], 200);
        assert_eq!(kg_by_kind(&conn, "acme", "Technology").unwrap().len(), 2);
    }

    #[test]
    fn ingest_dns_builds_resolves_edges() {
        let conn = open_memory();
        let json = r#"{"name":"www.acme.tld","addrs":["10.10.10.5","10.10.10.6"],"resolved":true}"#;
        let rep = ingest_dns(&conn, "acme", json).unwrap();
        assert_eq!(rep.nodes, 3); // name + 2 ips
        assert_eq!(rep.edges, 2);

        let name = node_id("Host", "www.acme.tld");
        let neigh = kg_neighbors(&conn, "acme", &name, "out").unwrap();
        assert_eq!(neigh.len(), 2);
    }

    #[test]
    fn reingest_is_idempotent_on_nodes() {
        let conn = open_memory();
        let json = r#"{"target":"1.2.3.4","open_ports":[{"port":443,"open":true,"service":"https"}],"scanned":1}"#;
        ingest_port_scan(&conn, "acme", json).unwrap();
        ingest_port_scan(&conn, "acme", json).unwrap();
        // Deterministic ids → re-ingest doesn't duplicate nodes.
        let stats = kg_stats(&conn, "acme").unwrap();
        assert_eq!(stats.nodes, 3); // host + service + entrypoint
    }

    #[test]
    fn ingest_content_builds_url_nodes_per_hit() {
        let conn = open_memory();
        let json = r#"{"base":"http://10.10.10.5","tested":3,"hits":[
            {"path":"/admin","url":"http://10.10.10.5/admin","status":200,"size":12},
            {"path":"/robots.txt","url":"http://10.10.10.5/robots.txt","status":200,"size":5}
        ]}"#;
        let rep = ingest_content(&conn, "acme", json).unwrap();
        // rep.nodes counts upserts (2 url + 2 host-upserts); the host dedupes to
        // one actual node — assert on the graph for the ground truth.
        assert_eq!(rep.nodes, 4);
        assert_eq!(rep.edges, 2);
        assert_eq!(kg_by_kind(&conn, "acme", "URL").unwrap().len(), 2);
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 1);
    }

    #[test]
    fn ingest_crawl_builds_url_nodes_per_page() {
        let conn = open_memory();
        let json = r#"{"start":"http://10.0.0.5/","pages":[
            {"url":"http://10.0.0.5/","status":200,"title":"Home","depth":0,"links":[]},
            {"url":"http://10.0.0.5/a","status":200,"depth":1,"links":[]}
        ]}"#;
        let rep = ingest_crawl(&conn, "acme", json).unwrap();
        assert_eq!(rep.edges, 2);
        assert_eq!(kg_by_kind(&conn, "acme", "URL").unwrap().len(), 2);
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 1);
    }

    #[test]
    fn ingest_tls_enriches_host_with_cert() {
        let conn = open_memory();
        let json = r#"{"host":"10.10.10.5","port":443,"protocol":"TLSv1_3","cipher":"TLS13_AES_256_GCM_SHA384","subject":"CN=acme","issuer":"CN=acme","not_before":"x","not_after":"y","serial":"01","sans":["acme.tld","www.acme.tld"]}"#;
        let rep = ingest_tls(&conn, "acme", json).unwrap();
        assert_eq!(rep.nodes, 1);
        let hosts = kg_by_kind(&conn, "acme", "Host").unwrap();
        assert_eq!(hosts.len(), 1);
        let props: serde_json::Value = serde_json::from_str(&hosts[0].props_json).unwrap();
        assert_eq!(props["tls_subject"], "CN=acme");
        assert_eq!(props["tls_sans"][1], "www.acme.tld");
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("http://example.com:8080/x"), Some("example.com"));
        assert_eq!(url_host("https://1.2.3.4/"), Some("1.2.3.4"));
        assert_eq!(url_host("example.com"), Some("example.com"));
    }

    #[test]
    fn ingest_nuclei_emits_vulnerabilities_linked_to_hosts() {
        let conn = open_memory();
        // Two JSONL findings (the nuclei -jsonl shape).
        let json = concat!(
            r#"{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"host":"10.0.0.5","matched-at":"http://10.0.0.5:8080/"}"#, "\n",
            r#"{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"host":"10.0.0.5","matched-at":"http://10.0.0.5:8080/"}"#, "\n"
        );
        let rep = ingest_nuclei(&conn, "acme", json).unwrap();
        assert_eq!(rep.edges, 2, "one HAS_VULN per finding");

        let vulns = kg_by_kind(&conn, "acme", "Vulnerability").unwrap();
        assert_eq!(vulns.len(), 2);
        // The host dedupes to one node across both findings.
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 1);
        let crit = vulns.iter().find(|v| v.label == "Log4Shell").unwrap();
        let props: serde_json::Value = serde_json::from_str(&crit.props_json).unwrap();
        assert_eq!(props["severity"], "critical");
        assert_eq!(props["template"], "CVE-2021-44228");
    }

    #[test]
    fn ingest_httpx_maps_url_host_and_tech() {
        let conn = open_memory();
        // httpx uses status_code/webserver/tech; accept a JSON array too.
        let json = r#"[{"url":"https://10.0.0.5","host":"10.0.0.5","status_code":200,"title":"ACME","webserver":"nginx","tech":["nginx","PHP"]}]"#;
        let rep = ingest_httpx(&conn, "acme", json).unwrap();
        assert_eq!(rep.nodes, 4); // url + host + 2 tech
        assert_eq!(rep.edges, 3); // EXPOSES + 2 USES

        let urls = kg_by_kind(&conn, "acme", "URL").unwrap();
        assert_eq!(urls.len(), 1);
        let props: serde_json::Value = serde_json::from_str(&urls[0].props_json).unwrap();
        assert_eq!(props["server"], "nginx");
        assert_eq!(props["status"], 200);
        assert_eq!(kg_by_kind(&conn, "acme", "Technology").unwrap().len(), 2);
    }

    #[test]
    fn ingest_masscan_builds_services_and_web_entrypoints() {
        let conn = open_memory();
        let json = r#"[
            {"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"},{"port":443,"proto":"tcp","status":"open"}]},
            {"ip":"10.0.0.6","ports":[{"port":9999,"proto":"tcp","status":"closed"}]}
        ]"#;
        let rep = ingest_masscan(&conn, "acme", json).unwrap();
        // host5 + svc22 + svc443 + entrypoint(443) + host6 = 5 nodes; 2 RUNS + 1 EXPOSES = 3 edges.
        assert_eq!(rep.nodes, 5);
        assert_eq!(rep.edges, 3);
        assert_eq!(kg_by_kind(&conn, "acme", "Entrypoint").unwrap().len(), 1);
        // The closed port produced no Service.
        assert_eq!(kg_by_kind(&conn, "acme", "Service").unwrap().len(), 2);
    }

    #[test]
    fn ingest_ffuf_builds_url_nodes_per_result() {
        let conn = open_memory();
        let json = r#"{"results":[
            {"url":"http://10.0.0.5/admin","status":200,"length":120,"input":{"FUZZ":"admin"}},
            {"url":"http://10.0.0.5/.git","status":301,"length":0,"input":{"FUZZ":".git"}}
        ]}"#;
        let rep = ingest_ffuf(&conn, "acme", json).unwrap();
        assert_eq!(rep.edges, 2);
        assert_eq!(kg_by_kind(&conn, "acme", "URL").unwrap().len(), 2);
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 1);
    }

    #[test]
    fn records_parses_both_jsonl_and_array_and_skips_junk() {
        // JSONL with a malformed middle line.
        let jsonl = "{\"a\":1}\nnot json\n{\"a\":2}\n";
        assert_eq!(records(jsonl).len(), 2);
        // A JSON array.
        assert_eq!(records(r#"[{"a":1},{"a":2},{"a":3}]"#).len(), 3);
    }

    #[test]
    fn ingest_dispatch_routes_third_party_scanners() {
        let conn = open_memory();
        let r = ingest(&conn, "acme", "nuclei", r#"{"template-id":"x","info":{"severity":"high"},"matched-at":"http://h/"}"#).unwrap();
        assert_eq!(r.edges, 1);
        assert!(ingest(&conn, "acme", "totally-unknown", "{}").is_err());
    }

    #[test]
    fn ingest_nmap_xml_builds_hosts_services_entrypoints() {
        let conn = open_memory();
        // A realistic (trimmed) `nmap -oX` document: one host, ssh + http open,
        // one filtered port that must NOT become a Service, plus a MAC address
        // that must NOT be taken as the host ip.
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames><hostname name="acme.tld" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="3306"><state state="filtered"/><service name="mysql"/></port>
    </ports>
  </host>
</nmaprun>"#;
        let rep = ingest_nmap(&conn, "acme", xml).unwrap();

        // host + ssh + http + entrypoint(80) = 4 nodes; 2 RUNS + 1 EXPOSES = 3 edges.
        assert_eq!(rep.nodes, 4);
        assert_eq!(rep.edges, 3);
        // The host ip, not the MAC, is the node.
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap()[0].label, "10.10.10.5");
        // The filtered port produced no Service.
        assert_eq!(kg_by_kind(&conn, "acme", "Service").unwrap().len(), 2);
        assert_eq!(kg_by_kind(&conn, "acme", "Entrypoint").unwrap().len(), 1);
        // Service banner carries product + version.
        let svcs = kg_by_kind(&conn, "acme", "Service").unwrap();
        let ssh = svcs.iter().find(|s| s.label.contains("/ssh")).unwrap();
        let props: serde_json::Value = serde_json::from_str(&ssh.props_json).unwrap();
        assert_eq!(props["banner"], "OpenSSH 8.2");
    }

    #[test]
    fn ingest_nmap_handles_multiple_hosts() {
        let conn = open_memory();
        let xml = r#"<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
  <host><address addr="10.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host>
</nmaprun>"#;
        let rep = ingest_nmap(&conn, "acme", xml).unwrap();
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 2);
        // host2's 443 promotes to an https entrypoint.
        assert_eq!(kg_by_kind(&conn, "acme", "Entrypoint").unwrap().len(), 1);
        assert!(rep.nodes >= 5);
    }

    #[test]
    fn ingest_slither_emits_vulnerability_nodes_with_severity() {
        let conn = open_memory();
        let json = r#"{"success":true,"results":{"detectors":[
            {"check":"reentrancy-eth","impact":"High","confidence":"Medium","description":"Reentrancy in withdraw()","elements":[{"type":"function","name":"withdraw"}]},
            {"check":"solc-version","impact":"Informational","confidence":"High","description":"Old solc","elements":[]}
        ]}}"#;
        let rep = ingest_slither(&conn, "acme", json).unwrap();
        assert_eq!(rep.nodes, 2);
        let vulns = kg_by_kind(&conn, "acme", "Vulnerability").unwrap();
        assert_eq!(vulns.len(), 2);
        let reent = vulns.iter().find(|v| v.label.contains("reentrancy-eth")).unwrap();
        let props: serde_json::Value = serde_json::from_str(&reent.props_json).unwrap();
        assert_eq!(props["severity"], "high");
        assert!(reent.label.contains("withdraw"));
        // Informational maps to info.
        let info = vulns.iter().find(|v| v.label.contains("solc-version")).unwrap();
        let ip: serde_json::Value = serde_json::from_str(&info.props_json).unwrap();
        assert_eq!(ip["severity"], "info");
    }

    #[test]
    fn ingest_bloodhound_builds_ad_attack_graph() {
        let conn = open_memory();
        // A groups file: DOMAIN ADMINS (G1) has member U1; U2 has GenericAll over it.
        let groups = r#"{"meta":{"type":"groups","count":1},"data":[
            {"ObjectIdentifier":"G1","Properties":{"name":"DOMAIN ADMINS@ACME.LOCAL","domain":"ACME.LOCAL"},
             "Members":[{"ObjectIdentifier":"U1","ObjectType":"User"}],
             "Aces":[{"PrincipalSID":"U2","PrincipalType":"User","RightName":"GenericAll"},
                     {"PrincipalSID":"U2","PrincipalType":"User","RightName":"NothingUseful"}]}
        ]}"#;
        let r1 = ingest(&conn, "ad", "bloodhound", groups).unwrap();
        assert_eq!(r1.nodes, 1); // the group (members/principals are stub-upserted, not counted)
        assert_eq!(r1.edges, 2); // MEMBER_OF (U1) + GENERIC_ALL (U2); the unknown right is skipped

        // A computers file: C1 has a session for U1 and U2 as local admin.
        let computers = r#"{"meta":{"type":"computers","count":1},"data":[
            {"ObjectIdentifier":"C1","Properties":{"name":"WS01.ACME.LOCAL","domain":"ACME.LOCAL"},
             "Sessions":{"Results":[{"UserSID":"U1","ComputerSID":"C1"}]},
             "LocalAdmins":{"Results":[{"ObjectIdentifier":"U2","ObjectType":"User"}]}}
        ]}"#;
        let r2 = ingest(&conn, "ad", "sharphound", computers).unwrap();
        assert_eq!(r2.edges, 2); // HAS_SESSION + ADMIN_TO

        // Nodes: the group carries its real name; ADComputer present.
        let groups_kg = kg_by_kind(&conn, "ad", "ADGroup").unwrap();
        assert!(groups_kg.iter().any(|g| g.label.contains("DOMAIN ADMINS")));
        assert_eq!(kg_by_kind(&conn, "ad", "ADComputer").unwrap().len(), 1);

        // The AD edges are traversable by the named analyses: U2's blast radius
        // reaches the group (GenericAll) and the workstation (AdminTo).
        let imp = crate::analysis::impact_analysis(&conn, "ad", "U2", Some("ADUser"), 5).unwrap();
        let reached: Vec<&str> = imp.reachable.iter().map(|r| r.label.as_str()).collect();
        assert!(reached.iter().any(|l| l.contains("DOMAIN ADMINS")), "U2 GenericAll→group: {reached:?}");
        assert!(reached.iter().any(|l| l.contains("WS01")), "U2 AdminTo→computer: {reached:?}");
    }

    #[test]
    fn ingest_testssl_emits_severity_filtered_vulns() {
        let conn = open_memory();
        let json = r#"[
            {"id":"BEAST","ip":"example.com/93.184.216.34","port":"443","severity":"LOW","finding":"BEAST possible"},
            {"id":"heartbleed","ip":"example.com/93.184.216.34","port":"443","severity":"CRITICAL","finding":"vulnerable"},
            {"id":"cipherlist","ip":"example.com/93.184.216.34","port":"443","severity":"OK","finding":"fine"},
            {"id":"scanTime","ip":"example.com/93.184.216.34","port":"443","severity":"INFO","finding":"12s"}
        ]"#;
        let rep = ingest_testssl(&conn, "acme", json).unwrap();
        // 2 kept (LOW + CRITICAL); OK + INFO skipped. host reused.
        let vulns = kg_by_kind(&conn, "acme", "Vulnerability").unwrap();
        assert_eq!(vulns.len(), 2);
        assert_eq!(rep.edges, 2);
        let hb = vulns.iter().find(|v| v.label == "heartbleed").unwrap();
        let p: serde_json::Value = serde_json::from_str(&hb.props_json).unwrap();
        assert_eq!(p["severity"], "critical");
        // linked to the host (not the host/ip composite).
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap()[0].label, "example.com");
    }

    #[test]
    fn ingest_sarif_maps_levels_to_severity() {
        let conn = open_memory();
        let json = r#"{"version":"2.1.0","runs":[{"results":[
            {"ruleId":"sqli","level":"error","message":{"text":"SQL injection"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"}}}]},
            {"ruleId":"weak-hash","level":"warning","message":{"text":"MD5 used"},"locations":[]}
        ]}]}"#;
        let rep = ingest_sarif(&conn, "acme", json).unwrap();
        assert_eq!(rep.nodes, 2);
        let vulns = kg_by_kind(&conn, "acme", "Vulnerability").unwrap();
        let sqli = vulns.iter().find(|v| v.label.contains("sqli")).unwrap();
        let p: serde_json::Value = serde_json::from_str(&sqli.props_json).unwrap();
        assert_eq!(p["severity"], "high"); // error → high
        assert!(sqli.label.contains("app/db.py"));
    }

    #[test]
    fn ingest_secretsdump_parses_ntlm_lines() {
        let conn = open_memory();
        let text = "Impacket v0.11\n\
            Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n\
            CORP\\svc_sql:1104:aad3b435b51404eeaad3b435b51404ee:5835048ce94ad0564e29a924a03510ef:::\n\
            [*] Kerberos keys grabbed\n\
            krbtgt:aes256-cts-hmac-sha1-96:abcd\n";
        let rep = ingest_secretsdump(&conn, "acme", text).unwrap();
        assert_eq!(rep.nodes, 2); // two NTLM lines; header + kerberos + aes line skipped
        let creds = kg_by_kind(&conn, "acme", "Credential").unwrap();
        assert!(creds.iter().any(|c| c.label == "Administrator"));
        assert!(creds.iter().any(|c| c.label == "svc_sql")); // DOMAIN\ stripped
    }

    #[test]
    fn ingest_netexec_builds_hosts_and_admin_creds() {
        let conn = open_memory();
        let json = r#"[
            {"host":"10.0.0.10","hostname":"DC01","domain":"CORP","os":"Windows Server 2022","user":"administrator","hash":"31d6...","admin":true},
            {"host":"10.0.0.20","hostname":"WS02","os":"Windows 10"}
        ]"#;
        let rep = ingest_netexec(&conn, "acme", json).unwrap();
        // DC01 is domain-joined → ADComputer; WS02 → Host.
        assert_eq!(kg_by_kind(&conn, "acme", "ADComputer").unwrap()[0].label, "DC01");
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap()[0].label, "WS02");
        assert_eq!(kg_by_kind(&conn, "acme", "Credential").unwrap().len(), 1);
        assert_eq!(rep.edges, 1); // admin cred -ADMIN_TO-> DC01
    }

    #[test]
    fn ingest_dnsx_builds_resolves_edges() {
        let conn = open_memory();
        let json = r#"{"host":"www.acme.tld","a":["10.0.0.5"],"aaaa":["::1"]}"#;
        let rep = ingest_dnsx(&conn, "acme", json).unwrap();
        assert_eq!(rep.edges, 2);
        let name = node_id("Host", "www.acme.tld");
        assert_eq!(kg_neighbors(&conn, "acme", &name, "out").unwrap().len(), 2);
    }

    #[test]
    fn ingest_katana_accepts_nested_and_flat_shapes() {
        let conn = open_memory();
        let json = concat!(
            r#"{"request":{"method":"GET","endpoint":"http://10.0.0.5/a"},"response":{"status_code":200}}"#, "\n",
            r#"{"url":"http://10.0.0.5/b"}"#, "\n"
        );
        let rep = ingest_katana(&conn, "acme", json).unwrap();
        assert_eq!(rep.edges, 2);
        assert_eq!(kg_by_kind(&conn, "acme", "URL").unwrap().len(), 2);
        assert_eq!(kg_by_kind(&conn, "acme", "Host").unwrap().len(), 1);
    }

    // --- KG-5: auto-producers for the vuln-research pipeline kinds --------------

    #[test]
    fn ingest_candidates_produces_candidate_nodes_from_jsonl() {
        let conn = open_memory();
        let jsonl = concat!(
            r#"{"path":"src/auth.rs","line":42,"rule":"hardcoded-secret"}"#, "\n",
            r#"{"path":"src/db.rs","line":7,"rule":"sql-string-concat"}"#, "\n",
            "not json\n"
        );
        let rep = ingest(&conn, "vr", "candidates", jsonl).unwrap();
        assert_eq!(rep.nodes, 2, "one Candidate per valid line, junk skipped");
        let cands = kg_by_kind(&conn, "vr", "Candidate").unwrap();
        assert_eq!(cands.len(), 2);
        let auth = cands.iter().find(|c| c.label == "hardcoded-secret").unwrap();
        let props: serde_json::Value = serde_json::from_str(&auth.props_json).unwrap();
        assert_eq!(props["path"], "src/auth.rs");
        assert_eq!(props["line"], 42);
        assert_eq!(props["rule"], "hardcoded-secret");
    }

    #[test]
    fn ingest_candidates_accepts_items_wrapper() {
        let conn = open_memory();
        let wrapped = r#"{"items":[{"path":"a.py","line":1,"rule":"r1"},{"path":"b.py","line":2,"rule":"r2"}]}"#;
        let rep = ingest(&conn, "vr", "candidates", wrapped).unwrap();
        assert_eq!(rep.nodes, 2);
        assert_eq!(kg_by_kind(&conn, "vr", "Candidate").unwrap().len(), 2);
    }

    #[test]
    fn ingest_hypotheses_produces_nodes_and_links_vulnerability() {
        let conn = open_memory();
        let jsonl = concat!(
            r#"{"id":"H1","title":"Auth bypass via type juggling","vulnerability":"CVE-2024-0001","confidence":"high"}"#, "\n",
            r#"{"title":"Reflected XSS in search"}"#, "\n"
        );
        let rep = ingest(&conn, "vr", "hypotheses", jsonl).unwrap();
        // 2 hypotheses + 1 vulnerability node; 1 LEADS_TO edge.
        assert_eq!(rep.nodes, 3);
        assert_eq!(rep.edges, 1);
        let hyps = kg_by_kind(&conn, "vr", "Hypothesis").unwrap();
        assert_eq!(hyps.len(), 2);
        assert_eq!(kg_by_kind(&conn, "vr", "Vulnerability").unwrap().len(), 1);
        // The hypothesis with a vuln reaches it via LEADS_TO.
        let h1 = node_id("Hypothesis", "H1");
        let neigh = kg_neighbors(&conn, "vr", &h1, "out").unwrap();
        assert!(neigh.iter().any(|n| n.kind == "Vulnerability"));
    }

    #[test]
    fn ingest_patches_produces_patch_nodes() {
        let conn = open_memory();
        let jsonl = concat!(
            r#"{"id":"P1","title":"Escape SQL params","path":"src/db.rs","target":"CVE-2024-0002","description":"use bound params"}"#, "\n",
            r#"{"path":"src/auth.rs"}"#, "\n"
        );
        let rep = ingest(&conn, "vr", "patches", jsonl).unwrap();
        assert_eq!(rep.nodes, 2);
        let patches = kg_by_kind(&conn, "vr", "Patch").unwrap();
        assert_eq!(patches.len(), 2);
        let p1 = patches.iter().find(|p| p.label == "Escape SQL params").unwrap();
        let props: serde_json::Value = serde_json::from_str(&p1.props_json).unwrap();
        assert_eq!(props["path"], "src/db.rs");
        assert_eq!(props["target"], "CVE-2024-0002");
        assert_eq!(props["description"], "use bound params");
    }

    // --- KG-7: an ingest that fails midway is all-or-nothing --------------------

    #[test]
    fn a_failed_ingest_batch_rolls_back_completely() {
        // Compose a good ingest and a failing one in ONE caller-owned transaction:
        // the failure must roll the whole unit back, so the earlier writes vanish.
        let conn = open_memory();
        let e = "acme";
        let good = r#"{"target":"10.0.0.1","open_ports":[{"port":80,"open":true,"service":"http"}],"scanned":1}"#;
        let r = with_tx(&conn, |c| {
            ingest_inner(c, e, "port-scan", good)?; // writes host + service + entrypoint
            ingest_inner(c, e, "totally-unknown", "{}") // errors → rollback the batch
        });
        assert!(r.is_err());
        assert_eq!(kg_stats(&conn, e).unwrap().nodes, 0, "partial batch must roll back");
    }
}
