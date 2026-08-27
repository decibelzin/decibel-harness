//! Model-facing [`Tool`] wrappers over the native recon primitives. Unlike the
//! `web/` analyzers these tools **reach the network** (async TCP / HTTP / TLS /
//! DNS), so every body races its work against `ctx.token()` with `tokio::select!`
//! and returns [`ToolError::Aborted`] on cancellation — the pattern `nmap`/`http`
//! already use. Each returns its analyzer's serde struct as the canonical value
//! so a UI card and a future Code Mode read the same fact the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::arsenal::{content, crawl, dns, http, parse_ports, portscan, tls};
use crate::util::{arg_bool, arg_str, arg_str_opt, arg_u64_opt};

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Read a word/candidate list that may arrive as a JSON array of strings OR a
/// comma-separated string. Empty entries are dropped.
fn arg_string_list(args: &Value, key: &str) -> Vec<String> {
    match args.get(key) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Read a status-code list (array of ints OR comma-separated string), falling
/// back to `default` when the argument is absent/empty.
fn arg_u16_list(args: &Value, key: &str, default: &[u16]) -> Vec<u16> {
    let parsed: Vec<u16> = match args.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect(),
        Some(Value::String(s)) => s.split(',').filter_map(|x| x.trim().parse().ok()).collect(),
        _ => Vec::new(),
    };
    if parsed.is_empty() {
        default.to_vec()
    } else {
        parsed
    }
}

/// Async TCP-connect port scan with banner grab and service hints.
pub struct PortScanTool;

#[async_trait]
impl Tool for PortScanTool {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "port_scan".into(),
            description: "Async TCP-connect port scan of a host/IP: returns each OPEN port with a \
                service hint and a best-effort banner. Pure-Rust (no nmap needed). `ports` accepts a \
                list and/or ranges like \"22,80,443\" or \"1-1024\" (default \"1-1024\"). Authorized \
                testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Host or IP to scan." },
                    "ports": { "type": "string", "description": "Port spec: list and/or ranges, e.g. \"22,80,8000-8100\" (default \"1-1024\")." },
                    "timeout_ms": { "type": "integer", "description": "Per-connection timeout in ms (default 800)." },
                    "concurrency": { "type": "integer", "description": "Max simultaneous connections (default 512)." }
                },
                "required": ["target"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let target = arg_str(&arguments, "target")?;
        let ports_spec = arg_str_opt(&arguments, "ports").unwrap_or_else(|| "1-1024".into());
        let ports = parse_ports(&ports_spec).map_err(ToolError::invalid_args)?;
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(800);
        let concurrency = arg_u64_opt(&arguments, "concurrency").unwrap_or(512) as usize;

        let report = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = portscan::scan(&target, &ports, timeout_ms, concurrency) => r,
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let target = value.get("target").and_then(Value::as_str).unwrap_or("");
        let scanned = value.get("scanned").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let open = value.get("open_ports").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("port_scan {target} — {} open of {scanned} scanned\n", open.len());
        for p in open {
            let port = p.get("port").and_then(Value::as_u64).unwrap_or(0);
            let service = p.get("service").and_then(Value::as_str).map(|s| format!(" {s}")).unwrap_or_default();
            let banner = p.get("banner").and_then(Value::as_str).map(|b| format!("  {b}")).unwrap_or_default();
            out.push_str(&format!("  {port}/tcp open{service}{banner}\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Probe one URL for status, title, server, redirect, timing, and tech.
pub struct HttpProbeTool;

#[async_trait]
impl Tool for HttpProbeTool {
    fn name(&self) -> &str {
        "http_probe"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_probe".into(),
            description: "Probe a single URL (HTTP or HTTPS) and return its status, page title, \
                Server header, redirect Location, response time, and a light technology fingerprint. \
                HTTPS accepts any certificate (self-signed targets are fine). Redirects are NOT \
                followed — you see each hop's real status."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "URL to probe (scheme optional; defaults to http://)." },
                    "timeout_ms": { "type": "integer", "description": "Connect + read timeout in ms (default 1500)." }
                },
                "required": ["url"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let url = arg_str(&arguments, "url")?;
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(1500);

        let result = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = http::probe(&url, timeout_ms) => r.map_err(ToolError::execution)?,
        };
        to_value(result)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let url = value.get("url").and_then(Value::as_str).unwrap_or("");
        let status = value.get("status").and_then(Value::as_u64).unwrap_or(0);
        let mut out = format!("http_probe {url} → {status}\n");
        if let Some(title) = value.get("title").and_then(Value::as_str) {
            out.push_str(&format!("  title: {title}\n"));
        }
        if let Some(server) = value.get("server").and_then(Value::as_str) {
            out.push_str(&format!("  server: {server}\n"));
        }
        if let Some(location) = value.get("location").and_then(Value::as_str) {
            out.push_str(&format!("  → {location}\n"));
        }
        if let Some(techs) = value.get("technologies").and_then(Value::as_array) {
            if !techs.is_empty() {
                let list: Vec<&str> = techs.iter().filter_map(Value::as_str).collect();
                out.push_str(&format!("  tech: {}\n", list.join(", ")));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

/// Bounded same-host BFS crawl from a start URL.
pub struct WebCrawlTool;

#[async_trait]
impl Tool for WebCrawlTool {
    fn name(&self) -> &str {
        "web_crawl"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "web_crawl".into(),
            description: "Crawl a site breadth-first from a start URL, extracting href/src/action \
                links and following same-host ones up to page and depth budgets. Returns each visited \
                page's URL, status, title, and discovered links. Set `same_host_only` false to follow \
                off-host links too."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Start URL (scheme optional; defaults to http://)." },
                    "max_pages": { "type": "integer", "description": "Max pages to visit (default 50)." },
                    "max_depth": { "type": "integer", "description": "Max link depth from the start (default 2)." },
                    "timeout_ms": { "type": "integer", "description": "Per-request timeout in ms (default 2000)." },
                    "same_host_only": { "type": "boolean", "description": "Only follow same host:port links (default true)." }
                },
                "required": ["url"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let url = arg_str(&arguments, "url")?;
        let max_pages = arg_u64_opt(&arguments, "max_pages").unwrap_or(50) as usize;
        let max_depth = arg_u64_opt(&arguments, "max_depth").unwrap_or(2) as usize;
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(2000);
        let same_host_only = arg_bool(&arguments, "same_host_only", true);

        let report = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = crawl::crawl(&url, max_pages, max_depth, timeout_ms, same_host_only) => r,
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let start = value.get("start").and_then(Value::as_str).unwrap_or("");
        let empty = Vec::new();
        let pages = value.get("pages").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("web_crawl {start} — {} page(s)\n", pages.len());
        for p in pages {
            let url = p.get("url").and_then(Value::as_str).unwrap_or("");
            let status = p.get("status").and_then(Value::as_u64).unwrap_or(0);
            let title = p.get("title").and_then(Value::as_str).map(|t| format!(" ({t})")).unwrap_or_default();
            out.push_str(&format!("  [{status}] {url}{title}\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Wordlist content/path discovery against a base URL.
pub struct ContentDiscoveryTool;

#[async_trait]
impl Tool for ContentDiscoveryTool {
    fn name(&self) -> &str {
        "content_discovery"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "content_discovery".into(),
            description: "Brute-force paths under a base URL from a wordlist (style of ffuf/gobuster): \
                probes `base/<word>` for each word and reports paths whose status is NOT in \
                `ignore_status` (default [404]). Returns each hit's path, status, and body size. \
                Authorized testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "base_url": { "type": "string", "description": "Base URL to bruteforce under, e.g. http://host." },
                    "words": {
                        "type": "array", "items": { "type": "string" },
                        "description": "Candidate paths/words (array, or a comma-separated string)."
                    },
                    "timeout_ms": { "type": "integer", "description": "Per-request timeout in ms (default 1500)." },
                    "concurrency": { "type": "integer", "description": "Max in-flight requests (default 64)." },
                    "ignore_status": {
                        "type": "array", "items": { "type": "integer" },
                        "description": "Statuses treated as misses (default [404])."
                    }
                },
                "required": ["base_url", "words"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let base = arg_str(&arguments, "base_url")?;
        let words = arg_string_list(&arguments, "words");
        if words.is_empty() {
            return Err(ToolError::invalid_args("`words` must be a non-empty list (array or comma-separated string)"));
        }
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(1500);
        let concurrency = arg_u64_opt(&arguments, "concurrency").unwrap_or(64) as usize;
        let ignore = arg_u16_list(&arguments, "ignore_status", &[404]);

        let report = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = content::discover(&base, &words, timeout_ms, concurrency, &ignore) => r,
        };
        to_value(report)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let base = value.get("base").and_then(Value::as_str).unwrap_or("");
        let tested = value.get("tested").and_then(Value::as_u64).unwrap_or(0);
        let empty = Vec::new();
        let hits = value.get("hits").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("content_discovery {base} — {} hit(s) of {tested} tested\n", hits.len());
        for h in hits {
            let path = h.get("path").and_then(Value::as_str).unwrap_or("");
            let status = h.get("status").and_then(Value::as_u64).unwrap_or(0);
            let size = h.get("size").and_then(Value::as_u64).unwrap_or(0);
            out.push_str(&format!("  [{status}] {path} ({size} b)\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Inspect a TLS endpoint's negotiated params and leaf certificate.
pub struct TlsInspectTool;

#[async_trait]
impl Tool for TlsInspectTool {
    fn name(&self) -> &str {
        "tls_inspect"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "tls_inspect".into(),
            description: "Complete a TLS handshake to host:port ACCEPTING ANY certificate (inspecting, \
                not trusting) and report the negotiated protocol and cipher plus the leaf certificate's \
                subject, issuer, validity window, serial, and DNS SANs. Works on self-signed/expired \
                targets. Pure-Rust (rustls + ring)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Hostname or IP." },
                    "port": { "type": "integer", "description": "TLS port (default 443)." },
                    "timeout_ms": { "type": "integer", "description": "Connect + handshake timeout in ms (default 5000)." }
                },
                "required": ["host"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let host = arg_str(&arguments, "host")?;
        let port = arg_u64_opt(&arguments, "port").unwrap_or(443) as u16;
        let timeout_ms = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(5000);

        let info = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = tls::inspect(&host, port, timeout_ms) => r.map_err(ToolError::execution)?,
        };
        to_value(info)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let host = value.get("host").and_then(Value::as_str).unwrap_or("");
        let port = value.get("port").and_then(Value::as_u64).unwrap_or(0);
        let protocol = value.get("protocol").and_then(Value::as_str).unwrap_or("?");
        let cipher = value.get("cipher").and_then(Value::as_str).unwrap_or("?");
        let subject = value.get("subject").and_then(Value::as_str).unwrap_or("");
        let issuer = value.get("issuer").and_then(Value::as_str).unwrap_or("");
        let not_before = value.get("not_before").and_then(Value::as_str).unwrap_or("");
        let not_after = value.get("not_after").and_then(Value::as_str).unwrap_or("");
        let mut out = format!("tls_inspect {host}:{port} — {protocol} / {cipher}\n");
        out.push_str(&format!("  subject: {subject}\n"));
        out.push_str(&format!("  issuer: {issuer}\n"));
        out.push_str(&format!("  valid: {not_before} → {not_after}\n"));
        if let Some(sans) = value.get("sans").and_then(Value::as_array) {
            if !sans.is_empty() {
                let list: Vec<&str> = sans.iter().filter_map(Value::as_str).collect();
                out.push_str(&format!("  SANs: {}\n", list.join(", ")));
            }
        }
        vec![ContentBlock::text(out)]
    }
}

/// Forward-resolve a hostname to its A/AAAA addresses via the OS resolver.
pub struct DnsTool;

#[async_trait]
impl Tool for DnsTool {
    fn name(&self) -> &str {
        "dns"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "dns".into(),
            description: "Resolve a hostname to its IPv4/IPv6 addresses using the system resolver. \
                Returns the sorted, de-duplicated address list and whether the name resolved."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Hostname to resolve." }
                },
                "required": ["name"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let name = arg_str(&arguments, "name")?;
        let result = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = dns::resolve(&name) => r,
        };
        to_value(result)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let name = value.get("name").and_then(Value::as_str).unwrap_or("");
        let empty = Vec::new();
        let addrs = value.get("addrs").and_then(Value::as_array).unwrap_or(&empty);
        if addrs.is_empty() {
            return vec![ContentBlock::text(format!("dns {name} → (did not resolve)"))];
        }
        let list: Vec<&str> = addrs.iter().filter_map(Value::as_str).collect();
        vec![ContentBlock::text(format!("dns {name} → {}", list.join(", ")))]
    }
}

/// Wordlist subdomain sweep: resolve `<word>.<domain>`, keeping the live ones.
pub struct DnsSubdomainsTool;

#[async_trait]
impl Tool for DnsSubdomainsTool {
    fn name(&self) -> &str {
        "dns_subdomains"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "dns_subdomains".into(),
            description: "Wordlist subdomain sweep: resolve `<word>.<domain>` for each word via the \
                system resolver and return only the subdomains that resolve, each with its addresses. \
                Authorized testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "domain": { "type": "string", "description": "Parent domain, e.g. example.com." },
                    "words": {
                        "type": "array", "items": { "type": "string" },
                        "description": "Subdomain labels to try (array, or a comma-separated string)."
                    },
                    "concurrency": { "type": "integer", "description": "Resolutions per batch (default 64)." }
                },
                "required": ["domain", "words"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let domain = arg_str(&arguments, "domain")?;
        let words = arg_string_list(&arguments, "words");
        if words.is_empty() {
            return Err(ToolError::invalid_args("`words` must be a non-empty list (array or comma-separated string)"));
        }
        let concurrency = arg_u64_opt(&arguments, "concurrency").unwrap_or(64) as usize;

        let found = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = dns::subdomains(&domain, &words, concurrency) => r,
        };
        Ok(json!({ "domain": domain, "found": to_value(found)? }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let domain = value.get("domain").and_then(Value::as_str).unwrap_or("");
        let empty = Vec::new();
        let found = value.get("found").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("dns_subdomains {domain} — {} found\n", found.len());
        for r in found {
            let name = r.get("name").and_then(Value::as_str).unwrap_or("");
            let addrs = r.get("addrs").and_then(Value::as_array).unwrap_or(&empty);
            let list: Vec<&str> = addrs.iter().filter_map(Value::as_str).collect();
            out.push_str(&format!("  {name} → {}\n", list.join(", ")));
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn run(tool: Arc<dyn Tool>, args: Value) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(
            decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args },
            &ExecCtx::new(),
        )
        .await
    }

    /// A tiny HTTP server: 200 (with links + a title) for `/` and `/admin`,
    /// 404 otherwise. Returns the bound port.
    async fn serve() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/");
                    let resp = match path {
                        "/" => "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><head><title>Home</title></head><body><a href=\"/admin\">a</a></body></html>".to_string(),
                        "/admin" => "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".to_string(),
                        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn port_scan_finds_open_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let r = run(Arc::new(PortScanTool), json!({ "target": "127.0.0.1", "ports": format!("{open},1"), "timeout_ms": 800 })).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        let open_ports = v["open_ports"].as_array().unwrap();
        assert_eq!(open_ports.len(), 1);
        assert_eq!(open_ports[0]["port"], open);
    }

    #[tokio::test]
    async fn http_probe_reports_status_and_tech() {
        let port = serve().await;
        let r = run(Arc::new(HttpProbeTool), json!({ "url": format!("http://127.0.0.1:{port}/") })).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert_eq!(v["status"], 200);
        assert_eq!(v["title"], "Home");
        assert!(v["technologies"].as_array().unwrap().iter().any(|t| t == "nginx"));
    }

    #[tokio::test]
    async fn web_crawl_follows_same_host_link() {
        let port = serve().await;
        let r = run(Arc::new(WebCrawlTool), json!({ "url": format!("http://127.0.0.1:{port}/"), "max_pages": 10, "max_depth": 2 })).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        let urls: Vec<&str> = v["pages"].as_array().unwrap().iter().filter_map(|p| p["url"].as_str()).collect();
        assert!(urls.iter().any(|u| u.ends_with("/admin")), "should have followed /admin, got {urls:?}");
    }

    #[tokio::test]
    async fn content_discovery_finds_admin_ignores_404() {
        let port = serve().await;
        let r = run(
            Arc::new(ContentDiscoveryTool),
            json!({ "base_url": format!("http://127.0.0.1:{port}"), "words": ["admin", "nope"], "timeout_ms": 1500 }),
        )
        .await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        let hits = v["hits"].as_array().unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["path"], "/admin");
        assert_eq!(hits[0]["status"], 200);
    }

    #[tokio::test]
    async fn tls_inspect_dead_port_is_execution_error() {
        let r = run(Arc::new(TlsInspectTool), json!({ "host": "127.0.0.1", "port": 1, "timeout_ms": 1200 })).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("EXEC_ERROR"));
    }

    #[tokio::test]
    async fn dns_resolves_localhost() {
        let r = run(Arc::new(DnsTool), json!({ "name": "localhost" })).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert_eq!(v["resolved"], true);
        assert!(v["addrs"].as_array().unwrap().iter().any(|a| a == "127.0.0.1" || a == "::1"));
    }

    #[tokio::test]
    async fn dns_subdomains_keeps_only_resolving() {
        let r = run(
            Arc::new(DnsSubdomainsTool),
            json!({ "domain": "invalid.", "words": ["nonexistent-sub"], "concurrency": 4 }),
        )
        .await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert!(v["found"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let r = run(Arc::new(PortScanTool), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));

        let r = run(Arc::new(ContentDiscoveryTool), json!({ "base_url": "http://x" })).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
