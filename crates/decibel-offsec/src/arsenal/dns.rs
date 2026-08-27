//! DNS resolution via the system resolver (no external resolver dependency).
//! Forward resolution (A/AAAA) and a wordlist subdomain sweep built on top of it.
//!
//! NOTE: the source's docstring anticipated a trust-dns slice for record-type
//! queries (MX/TXT/NS); that never landed, so this stays on the OS resolver via
//! `std::net::ToSocketAddrs` run on `spawn_blocking` — no external resolver crate.

use std::net::ToSocketAddrs;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    pub name: String,
    pub addrs: Vec<String>,
    pub resolved: bool,
}

/// Resolve a hostname to its IPv4/IPv6 addresses using the OS resolver.
pub async fn resolve(name: &str) -> DnsResult {
    let owned = name.to_string();
    // ToSocketAddrs is blocking; keep it off the async runtime.
    let addrs = tokio::task::spawn_blocking(move || {
        // A port is required by ToSocketAddrs; it does not affect resolution.
        (owned.as_str(), 0u16)
            .to_socket_addrs()
            .map(|it| {
                let mut v: Vec<String> = it.map(|s| s.ip().to_string()).collect();
                v.sort();
                v.dedup();
                v
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();

    DnsResult {
        resolved: !addrs.is_empty(),
        name: name.to_string(),
        addrs,
    }
}

/// Wordlist subdomain sweep: resolve `<word>.<domain>` for each word, returning
/// only the ones that resolve. Bounded concurrency via chunking.
pub async fn subdomains(domain: &str, words: &[String], concurrency: usize) -> Vec<DnsResult> {
    let mut found = Vec::new();
    for chunk in words.chunks(concurrency.max(1)) {
        let mut handles = Vec::with_capacity(chunk.len());
        for w in chunk {
            let fqdn = format!("{}.{}", w.trim(), domain);
            handles.push(tokio::spawn(async move { resolve(&fqdn).await }));
        }
        for h in handles {
            if let Ok(r) = h.await {
                if r.resolved {
                    found.push(r);
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_localhost() {
        let r = resolve("localhost").await;
        assert!(r.resolved, "localhost should resolve");
        assert!(
            r.addrs.iter().any(|a| a == "127.0.0.1" || a == "::1"),
            "got {:?}",
            r.addrs
        );
    }

    #[tokio::test]
    async fn nonexistent_name_does_not_resolve() {
        let r = resolve("nope.invalid.decepticon-arsenal-test.").await;
        assert!(!r.resolved);
        assert!(r.addrs.is_empty());
    }

    #[tokio::test]
    async fn subdomain_sweep_keeps_only_resolving() {
        // Use a controlled case: a nonexistent subdomain under an invalid TLD.
        let words = vec!["nonexistent-sub".to_string()];
        let found = subdomains("invalid.", &words, 4).await;
        assert!(found.is_empty());
    }
}
