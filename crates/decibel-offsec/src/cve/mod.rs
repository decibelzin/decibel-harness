//! CVE intelligence: composite exploitability scoring (NVD CVSS + EPSS + CISA
//! KEV floor) and OSV package→CVE lookup, over the public APIs
//! (`services.nvd.nist.gov`, `api.first.org/epss`, `api.osv.dev` — no key
//! needed).
//!
//! Ported from Decepticon's `decepticon-cve` crate into Decibel with **no store
//! dependency**: the upstream knowledge-graph ingest is dropped (each tool
//! returns the scored [`CveRecord`](s) as its canonical value), and the upstream
//! file cache is replaced by a lightweight in-process [`CveCache`] the lookup
//! tool struct holds — the `AddFindingTool`/`FindingStore` pattern.
//!
//! HTTP rides the crate's `reqwest` (rustls backend), reading response bodies as
//! text and parsing them with `serde_json` so no `reqwest` `json` feature is
//! required — the same shape the `http` tool uses. Endpoints are configurable
//! ([`Config`]) so the client is unit-tested end-to-end against a local mock
//! without touching the network; the pure [`composite_score`] formula is tested
//! directly.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub mod tools;

/// Endpoints + cache TTL + KEV set. `Default` uses the real public APIs.
#[derive(Debug, Clone)]
pub struct Config {
    /// NVD CVE 2.0 REST base (queried with `?cveId=`).
    pub nvd_base: String,
    /// FIRST EPSS base (queried with `?cve=`).
    pub epss_base: String,
    /// OSV query endpoint (POST).
    pub osv_base: String,
    /// Freshness window for the in-process cache, in seconds.
    pub ttl_secs: u64,
    /// CISA KEV catalogue (CVE ids). Empty by default — no live KEV feed is
    /// wired here; when populated, a listed CVE gets the composite KEV floor.
    pub kev: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            nvd_base: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            epss_base: "https://api.first.org/data/v1/epss".into(),
            osv_base: "https://api.osv.dev/v1/query".into(),
            ttl_secs: 24 * 3600,
            kev: HashSet::new(),
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A scored CVE record — the canonical value the lookup tool returns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CveRecord {
    pub id: String,
    pub cvss: Option<f64>,
    pub epss: Option<f64>,
    pub kev: bool,
    pub composite: f64,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The composite exploitability score (upstream formula):
/// base=CVSS (or 5.0), EPSS adjustment `clamp(3·log10(epss+0.001)+3, -1, +2)`,
/// clamp to 0..10, then a KEV floor of 9.0.
pub fn composite_score(cvss: Option<f64>, epss: Option<f64>, kev: bool) -> f64 {
    let base = cvss.unwrap_or(5.0);
    let e = epss.unwrap_or(0.0);
    let adj = (3.0 * (e + 0.001).log10() + 3.0).clamp(-1.0, 2.0);
    let mut c = (base + adj).clamp(0.0, 10.0);
    if kev {
        c = c.max(9.0);
    }
    (c * 10.0).round() / 10.0
}

/// Map a composite score to a severity rating band.
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

// --- in-process cache ------------------------------------------------------

#[derive(Clone)]
struct CacheEntry {
    record: CveRecord,
    ts: u64,
}

/// A cloneable, in-process CVE cache handle held by the lookup tool — the
/// `FindingStore` pattern (an `Arc<Mutex<HashMap>>`). It replaces the upstream
/// on-disk cache: self-contained, process-lifetime, no store dependency.
#[derive(Clone, Default)]
pub struct CveCache(Arc<Mutex<HashMap<String, CacheEntry>>>);

impl CveCache {
    /// A fresh empty cache.
    pub fn new() -> Self {
        CveCache::default()
    }

    /// Fetch a still-fresh record for `id` (`now - ts < ttl`), if any.
    pub fn get(&self, id: &str, ttl: u64) -> Option<CveRecord> {
        // Recover a poisoned lock so a prior panic never propagates here.
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.get(id).and_then(|e| {
            if now().saturating_sub(e.ts) < ttl {
                Some(e.record.clone())
            } else {
                None
            }
        })
    }

    /// Insert or refresh a record, stamping it with the current time.
    pub fn insert(&self, id: &str, record: CveRecord) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(id.to_string(), CacheEntry { record, ts: now() });
    }
}

// --- HTTP client + fetchers ------------------------------------------------

/// Build the shared HTTP client. No `json` feature is used (bodies are read as
/// text and parsed with `serde_json`), matching the crate's `http` tool.
fn build_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent("decibel-offsec-cve/0.1")
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| format!("http client: {e}"))
}

/// NVD: the highest-available CVSS base score and the English description.
async fn fetch_nvd(client: &reqwest::Client, cfg: &Config, id: &str) -> (Option<f64>, Option<String>) {
    let text = match client.get(&cfg.nvd_base).query(&[("cveId", id)]).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return (None, None),
        },
        Err(_) => return (None, None),
    };
    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let cve = &v["vulnerabilities"][0]["cve"];
    let metrics = &cve["metrics"];
    let cvss = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
        .iter()
        .find_map(|k| metrics[*k][0]["cvssData"]["baseScore"].as_f64());
    let desc = cve["descriptions"]
        .as_array()
        .and_then(|arr| arr.iter().find(|d| d["lang"] == "en"))
        .and_then(|d| d["value"].as_str().map(str::to_string));
    (cvss, desc)
}

/// EPSS: the real-world exploit probability for `id`, if scored.
async fn fetch_epss(client: &reqwest::Client, cfg: &Config, id: &str) -> Option<f64> {
    let text = client
        .get(&cfg.epss_base)
        .query(&[("cve", id)])
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    v["data"][0]["epss"].as_str().and_then(|s| s.parse::<f64>().ok())
}

/// Look up + score a batch of CVE ids (cache-first).
pub async fn lookup(ids: &[String], cfg: &Config, cache: &CveCache) -> Result<Vec<CveRecord>, String> {
    let client = build_client()?;
    let mut out = Vec::with_capacity(ids.len());

    for id in ids {
        let id = id.trim().to_uppercase();
        if id.is_empty() {
            continue;
        }
        if let Some(rec) = cache.get(&id, cfg.ttl_secs) {
            out.push(rec);
            continue;
        }
        let (cvss, description) = fetch_nvd(&client, cfg, &id).await;
        let epss = fetch_epss(&client, cfg, &id).await;
        let kev = cfg.kev.contains(&id);
        let composite = composite_score(cvss, epss, kev);
        let rec = CveRecord {
            id: id.clone(),
            cvss,
            epss,
            kev,
            composite,
            severity: rating(composite).to_string(),
            description,
        };
        cache.insert(&id, rec.clone());
        out.push(rec);
    }
    Ok(out)
}

/// OSV lookup: which vulnerability ids affect `package@version` in `ecosystem`
/// (e.g. `PyPI`, `npm`, `crates.io`, `Go`, `Maven`).
pub async fn by_package(
    package: &str,
    version: &str,
    ecosystem: &str,
    cfg: &Config,
) -> Result<Vec<String>, String> {
    let client = build_client()?;
    let body = json!({
        "version": version,
        "package": { "name": package, "ecosystem": ecosystem }
    })
    .to_string();
    let text = client
        .post(&cfg.osv_base)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("osv request: {e}"))?
        .text()
        .await
        .map_err(|e| format!("osv read: {e}"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("osv json: {e}"))?;
    Ok(v["vulns"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|x| x["id"].as_str().map(str::to_string)).collect())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn composite_formula() {
        // Full CVSS + very high EPSS clamps to 10.
        assert_eq!(composite_score(Some(9.8), Some(0.97), false), 10.0);
        // No data: base 5.0, EPSS adj clamps to -1 → 4.0.
        assert_eq!(composite_score(None, None, false), 4.0);
        // KEV floor forces low-CVSS items up to 9.0.
        assert_eq!(composite_score(Some(3.0), Some(0.0), true), 9.0);
        // Mid: cvss 5.0, epss 0.1 → adj = clamp(3*log10(0.101)+3) ≈ 0.013 → ~5.0
        let m = composite_score(Some(5.0), Some(0.1), false);
        assert!((m - 5.0).abs() < 0.2, "got {m}");
    }

    #[test]
    fn rating_bands() {
        assert_eq!(rating(0.0), "None");
        assert_eq!(rating(3.9), "Low");
        assert_eq!(rating(6.9), "Medium");
        assert_eq!(rating(8.9), "High");
        assert_eq!(rating(9.0), "Critical");
    }

    #[test]
    fn cache_respects_ttl() {
        let cache = CveCache::new();
        let rec = CveRecord {
            id: "CVE-1".into(),
            cvss: Some(9.0),
            epss: Some(0.5),
            kev: false,
            composite: 9.0,
            severity: "Critical".into(),
            description: None,
        };
        cache.insert("CVE-1", rec.clone());
        assert_eq!(cache.get("CVE-1", 3600), Some(rec), "fresh entry hits");
        assert!(cache.get("CVE-1", 0).is_none(), "ttl=0 expires everything");
        assert!(cache.get("CVE-2", 3600).is_none(), "unknown id misses");
    }

    /// A mock API server: routes /nvd, /epss (GET) and /osv (POST) to canned
    /// JSON. Fully local (127.0.0.1, plain HTTP) — no live API is touched.
    async fn mock_api() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");

                    let body = if path.starts_with("/nvd") {
                        r#"{"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","descriptions":[{"lang":"en","value":"Log4Shell RCE"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10.0}}]}}}]}"#
                    } else if path.starts_with("/epss") {
                        r#"{"status":"OK","data":[{"cve":"CVE-2021-44228","epss":"0.97","percentile":"0.99"}]}"#
                    } else if path.starts_with("/osv") {
                        r#"{"vulns":[{"id":"GHSA-jfh8-c2jp-5v3q"},{"id":"CVE-2021-44228"}]}"#
                    } else {
                        "{}"
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    fn mock_cfg(port: u16) -> Config {
        Config {
            nvd_base: format!("http://127.0.0.1:{port}/nvd"),
            epss_base: format!("http://127.0.0.1:{port}/epss"),
            osv_base: format!("http://127.0.0.1:{port}/osv"),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn lookup_end_to_end_over_mock() {
        let port = mock_api().await;
        let cfg = mock_cfg(port);
        let cache = CveCache::new();
        let recs = lookup(&["cve-2021-44228".to_string()], &cfg, &cache).await.unwrap();
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.id, "CVE-2021-44228");
        assert_eq!(r.cvss, Some(10.0));
        assert_eq!(r.epss, Some(0.97));
        assert_eq!(r.composite, 10.0);
        assert_eq!(r.severity, "Critical");
        assert_eq!(r.description.as_deref(), Some("Log4Shell RCE"));

        // Second lookup is served from the in-process cache (id normalized).
        assert!(cache.get("CVE-2021-44228", cfg.ttl_secs).is_some());
    }

    #[tokio::test]
    async fn by_package_end_to_end_over_mock() {
        let port = mock_api().await;
        let cfg = mock_cfg(port);
        let ids = by_package("log4j-core", "2.14.1", "Maven", &cfg).await.unwrap();
        assert!(ids.contains(&"CVE-2021-44228".to_string()));
        assert_eq!(ids.len(), 2);
    }
}
