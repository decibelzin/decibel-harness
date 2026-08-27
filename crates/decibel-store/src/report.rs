//! Report renderers over the knowledge graph + findings (port spec §7). Pure
//! functions: read engagement-scoped data and emit an executive markdown report,
//! a SARIF v2.1.0 document, and a standalone CVSS 3.1 base-score calculator.
//!
//! Convention: `engagement` is the shared key used for BOTH the `finding` rows
//! (`engagement_id`) and the KG partition (`graph_node.engagement`), so a report
//! stitches findings, graph stats and attack chains for one engagement.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{chain, kg_stats, list_findings, Connection, Finding};

/// Order severities strongest-first for reporting.
fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// Render a CISO-level executive summary in Markdown.
pub fn report_executive(conn: &Connection, engagement: &str) -> Result<String, String> {
    let mut findings = list_findings(conn, engagement)?;
    findings.sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));
    let stats = kg_stats(conn, engagement)?;
    let chains = chain::plan_chains(conn, engagement, 12, 1.0e9, 5).unwrap_or_default();

    // Severity tally.
    let mut counts: [(&str, usize); 5] = [
        ("critical", 0),
        ("high", 0),
        ("medium", 0),
        ("low", 0),
        ("info", 0),
    ];
    for f in &findings {
        let s = f.severity.to_lowercase();
        if let Some(slot) = counts.iter_mut().find(|(k, _)| *k == s) {
            slot.1 += 1;
        }
    }

    let mut md = String::new();
    let _ = writeln!(md, "# Executive Summary — {engagement}\n");
    let _ = writeln!(
        md,
        "**{}** findings across **{}** assets ({} graph nodes, {} edges).\n",
        findings.len(),
        stats
            .nodes_by_kind
            .iter()
            .filter(|(k, _)| k == "Host")
            .map(|(_, n)| *n)
            .sum::<i64>(),
        stats.nodes,
        stats.edges
    );

    let _ = writeln!(md, "## Severity breakdown\n");
    let _ = writeln!(md, "| Severity | Count |");
    let _ = writeln!(md, "|---|---|");
    for (sev, n) in counts {
        let _ = writeln!(md, "| {} | {} |", cap(sev), n);
    }
    let _ = writeln!(md);

    if !findings.is_empty() {
        let _ = writeln!(md, "## Findings\n");
        let _ = writeln!(md, "| Severity | Title | Target | Source |");
        let _ = writeln!(md, "|---|---|---|---|");
        for f in &findings {
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} |",
                cap(&f.severity),
                md_escape(&f.title),
                md_escape(&f.target),
                md_escape(&f.source_tool)
            );
        }
        let _ = writeln!(md);
    }

    if !chains.is_empty() {
        let _ = writeln!(md, "## Top attack chains\n");
        for c in &chains {
            let _ = writeln!(md, "- **cost {:.1}** ({} hops): {}", c.cost, c.hops, c.path.join(" → "));
        }
        let _ = writeln!(md);
    }

    Ok(md)
}

fn cap(s: &str) -> String {
    let mut ch = s.chars();
    match ch.next() {
        Some(f) => f.to_uppercase().collect::<String>() + ch.as_str(),
        None => String::new(),
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn sarif_level(sev: &str) -> &'static str {
    match sev.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

/// Render the engagement's findings as a SARIF v2.1.0 document (for GitHub code
/// scanning / DefectDojo import).
pub fn report_sarif(conn: &Connection, engagement: &str) -> Result<String, String> {
    let findings = list_findings(conn, engagement)?;

    // Distinct rules keyed by source tool.
    let mut rule_ids: Vec<String> = findings.iter().map(|f| f.source_tool.clone()).collect();
    rule_ids.sort();
    rule_ids.dedup();
    let rules: Vec<_> = rule_ids
        .iter()
        .filter(|id| !id.is_empty())
        .map(|id| json!({ "id": id, "name": id }))
        .collect();

    let results: Vec<_> = findings
        .iter()
        .map(|f: &Finding| {
            json!({
                "ruleId": if f.source_tool.is_empty() { "decibel" } else { &f.source_tool },
                "level": sarif_level(&f.severity),
                "message": { "text": f.title },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": if f.target.is_empty() { "unknown" } else { &f.target } }
                    }
                }],
                "properties": { "severity": f.severity, "id": f.id }
            })
        })
        .collect();

    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "Decibel", "informationUri": "https://github.com/decibelzin/decibel-harness", "rules": rules } },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())
}

// --- CVSS 3.1 base score --------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CvssScore {
    pub base_score: f64,
    pub severity: String,
}

/// Official CVSS 3.1 roundup (FIRST.org spec).
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input as f64 / 10_000.0).floor() + 1.0) / 10.0
    }
}

fn rating(score: f64) -> &'static str {
    if score <= 0.0 {
        "None"
    } else if score < 4.0 {
        "Low"
    } else if score < 7.0 {
        "Medium"
    } else if score < 9.0 {
        "High"
    } else {
        "Critical"
    }
}

/// Compute the CVSS 3.1 **base** score from a vector string like
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.
pub fn cvss_v31(vector: &str) -> Result<CvssScore, String> {
    let mut m = std::collections::HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k.to_uppercase(), v.to_uppercase());
        }
    }
    let get = |k: &str| m.get(k).map(|s| s.as_str()).ok_or_else(|| format!("missing metric {k}"));

    let scope_changed = get("S")? == "C";

    let av: f64 = match get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        x => return Err(format!("bad AV:{x}")),
    };
    let ac: f64 = match get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        x => return Err(format!("bad AC:{x}")),
    };
    let pr: f64 = match get("PR")? {
        "N" => 0.85,
        "L" => if scope_changed { 0.68 } else { 0.62 },
        "H" => if scope_changed { 0.5 } else { 0.27 },
        x => return Err(format!("bad PR:{x}")),
    };
    let ui: f64 = match get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        x => return Err(format!("bad UI:{x}")),
    };
    let cia = |v: &str| -> Result<f64, String> {
        match v {
            "H" => Ok(0.56),
            "L" => Ok(0.22),
            "N" => Ok(0.0),
            x => Err(format!("bad CIA:{x}")),
        }
    };
    let c = cia(get("C")?)?;
    let i = cia(get("I")?)?;
    let a = cia(get("A")?)?;

    let iss: f64 = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact: f64 = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability: f64 = 8.22 * av * ac * pr * ui;

    let base = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    };

    Ok(CvssScore {
        base_score: base,
        severity: rating(base).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{add_finding, create_engagement, kg_upsert_edge, kg_upsert_node, open_memory};

    #[test]
    fn cvss_known_vectors() {
        // Classic full-critical vector = 9.8.
        let s = cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(s.base_score, 9.8);
        assert_eq!(s.severity, "Critical");

        // A medium example (Heartbleed-ish network, low impact confidentiality).
        let s2 = cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N").unwrap();
        assert_eq!(s2.base_score, 5.3);
        assert_eq!(s2.severity, "Medium");

        // Scope-changed, PR:H, all-high impact = 9.1.
        let s3 = cvss_v31("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert_eq!(s3.base_score, 9.1);

        assert!(cvss_v31("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").is_err());
    }

    #[test]
    fn executive_report_has_sections_and_findings() {
        let conn = open_memory();
        let eng = create_engagement(&conn, "acme", "ACME").unwrap();
        let e = &eng.id; // shared key for findings + KG
        add_finding(&conn, e, "critical", "RCE in upload", "10.0.0.5", "{}", "exploit").unwrap();
        add_finding(&conn, e, "low", "Missing header", "10.0.0.5", "{}", "http_probe").unwrap();

        // Build a tiny attack chain in the KG.
        let ep = kg_upsert_node(&conn, e, "Entrypoint", "http://10.0.0.5/", None, "{}").unwrap();
        let jewel = kg_upsert_node(&conn, e, "CrownJewel", "root", None, "{}").unwrap();
        kg_upsert_edge(&conn, e, &ep, &jewel, "EXPLOITS", 1.0, None, "{}").unwrap();

        let md = report_executive(&conn, e).unwrap();
        assert!(md.contains("# Executive Summary"));
        assert!(md.contains("## Severity breakdown"));
        assert!(md.contains("RCE in upload"));
        assert!(md.contains("| Critical | 1 |"));
        assert!(md.contains("## Top attack chains"));
        assert!(md.contains("http://10.0.0.5/ → root"));
    }

    #[test]
    fn sarif_export_is_valid_shape() {
        let conn = open_memory();
        let eng = create_engagement(&conn, "acme", "ACME").unwrap();
        add_finding(&conn, &eng.id, "high", "SQLi", "10.0.0.5/login", "{}", "sqlmap").unwrap();

        let sarif = report_sarif(&conn, &eng.id).unwrap();
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Decibel");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "sqlmap");
        assert_eq!(v["runs"][0]["results"][0]["message"]["text"], "SQLi");
    }
}
