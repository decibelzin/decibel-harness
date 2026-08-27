//! Native, cross-platform recon primitives — ported from Decepticon's
//! `decepticon-arsenal` crate (Apache-2.0) into Decibel. Pure-Rust (tokio +
//! rustls, no C, no OpenSSL) so it builds identically on Windows / Linux / macOS,
//! but unlike the `web/` analyzers these capabilities **reach the network**:
//! async TCP port scanning, HTTP probing/crawling, content discovery, TLS
//! certificate inspection, and DNS resolution.
//!
//! Seven capabilities, surfaced as model-facing tools in [`tools`]: `port_scan`,
//! `http_probe`, `web_crawl`, `content_discovery`, `tls_inspect`, `dns`, and
//! `dns_subdomains`. Each analyzer returns a serde struct so the tool layer hands
//! it straight to the model (and, later, the knowledge graph) as a canonical
//! value. Every tool body observes the [`ExecCtx`](decibel_tools::ExecCtx) token
//! so a scan/crawl aborts on cancellation like `nmap`/`shell`.
//!
//! The source shipped a thin `decepticon-arsenal` CLI (`src/main.rs`) that just
//! printed each primitive's JSON for the Executor to shell out to; that wrapper
//! is intentionally dropped — the tool layer is Decibel's driver instead.

pub mod content;
pub mod crawl;
pub mod dns;
pub mod http;
pub mod portscan;
pub mod tls;
pub mod tools;

/// Parse a port specification like `"22,80,443"` or `"1-1024"` (or a mix,
/// `"22,80,8000-8100"`) into a deduplicated, sorted list.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| format!("bad port: {a}"))?;
            let end: u16 = b.trim().parse().map_err(|_| format!("bad port: {b}"))?;
            if start > end {
                return Err(format!("range start > end: {part}"));
            }
            out.extend(start..=end);
        } else {
            out.push(part.parse().map_err(|_| format!("bad port: {part}"))?);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("no ports parsed".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse_ports;

    #[test]
    fn parse_ports_list_and_range() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-3").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_ports("80,1-3,80").unwrap(), vec![1, 2, 3, 80]);
        assert!(parse_ports("").is_err());
        assert!(parse_ports("9-1").is_err());
        assert!(parse_ports("abc").is_err());
    }
}
