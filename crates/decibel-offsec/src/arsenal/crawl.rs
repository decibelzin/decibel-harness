//! Web crawler (spider): BFS from a start URL, extracting links (href/src/
//! action) and following same-host ones up to a page/depth budget. Reuses the
//! HTTP prober's `fetch` for the body.

use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::arsenal::http;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub url: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub depth: usize,
    pub links: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlReport {
    pub start: String,
    pub pages: Vec<Page>,
}

struct Loc {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_loc(url: &str) -> Option<Loc> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some(Loc {
        scheme,
        host,
        port,
        path: if path.is_empty() { "/".into() } else { path.to_string() },
    })
}

fn port_suffix(scheme: &str, port: u16) -> String {
    if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        String::new()
    } else {
        format!(":{port}")
    }
}

/// Resolve a possibly-relative link against a base location into an absolute URL.
fn resolve(base: &Loc, link: &str) -> Option<String> {
    let link = link.split('#').next().unwrap_or("").trim();
    if link.is_empty() {
        return None;
    }
    let low = link.to_ascii_lowercase();
    for bad in ["mailto:", "javascript:", "tel:", "data:"] {
        if low.starts_with(bad) {
            return None;
        }
    }
    if low.starts_with("http://") || low.starts_with("https://") {
        return Some(link.to_string());
    }
    if link.starts_with("//") {
        return Some(format!("{}:{}", base.scheme, link));
    }
    let authority = format!("{}{}", base.host, port_suffix(&base.scheme, base.port));
    if link.starts_with('/') {
        return Some(format!("{}://{}{}", base.scheme, authority, link));
    }
    let dir = match base.path.rfind('/') {
        Some(i) => &base.path[..=i],
        None => "/",
    };
    Some(format!("{}://{}{}{}", base.scheme, authority, dir, link))
}

/// Extract raw `href`/`src`/`action` attribute values from HTML.
fn extract_links(html: &str) -> Vec<String> {
    let low = html.to_ascii_lowercase();
    let mut out = Vec::new();
    for attr in ["href=", "src=", "action="] {
        for (idx, _) in low.match_indices(attr) {
            let after = idx + attr.len();
            let rest = &html[after..];
            let q = match rest.chars().next() {
                Some(c @ ('"' | '\'')) => c,
                _ => continue,
            };
            let val_start = after + q.len_utf8();
            if let Some(end) = html[val_start..].find(q) {
                out.push(html[val_start..val_start + end].to_string());
            }
        }
    }
    out
}

fn same_host(start: &Option<Loc>, url: &str) -> bool {
    match (start, parse_loc(url)) {
        (Some(s), Some(u)) => s.host == u.host && s.port == u.port,
        _ => true,
    }
}

/// Crawl from `start`, visiting at most `max_pages` pages up to `max_depth`.
pub async fn crawl(
    start: &str,
    max_pages: usize,
    max_depth: usize,
    timeout_ms: u64,
    same_host_only: bool,
) -> CrawlReport {
    let start_url = if start.contains("://") {
        start.to_string()
    } else {
        format!("http://{start}")
    };
    let start_loc = parse_loc(&start_url);

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((start_url.clone(), 0));
    let mut pages = Vec::new();

    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= max_pages {
            break;
        }
        if visited.contains(&url) {
            continue;
        }
        visited.insert(url.clone());

        match http::fetch(&url, timeout_ms).await {
            Ok((res, body)) => {
                let base = parse_loc(&url);
                let mut links = Vec::new();
                if let Some(base) = base {
                    for raw in extract_links(&body) {
                        if let Some(abs) = resolve(&base, &raw) {
                            if same_host_only && !same_host(&start_loc, &abs) {
                                continue;
                            }
                            if !links.contains(&abs) {
                                links.push(abs.clone());
                            }
                            if depth < max_depth && !visited.contains(&abs) {
                                queue.push_back((abs, depth + 1));
                            }
                        }
                    }
                }
                pages.push(Page { url, status: res.status, title: res.title, depth, links });
            }
            Err(_) => pages.push(Page { url, status: 0, title: None, depth, links: Vec::new() }),
        }
    }

    CrawlReport { start: start_url, pages }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
                    let html = match path {
                        "/" => r#"<html><body><a href="/a">a</a> <a href="/b">b</a> <a href="http://example.com/x">ext</a></body></html>"#,
                        "/a" => r#"<html><body><a href="/c">c</a></body></html>"#,
                        _ => r#"<html><body>leaf</body></html>"#,
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        html.len(),
                        html
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[test]
    fn extract_and_resolve() {
        let links = extract_links(r#"<a href="/x">x</a><script src='/y.js'></script><form action="z">"#);
        assert_eq!(links, vec!["/x", "/y.js", "z"]);
        let base = parse_loc("http://h.tld:8080/dir/page").unwrap();
        assert_eq!(resolve(&base, "/x").unwrap(), "http://h.tld:8080/x");
        assert_eq!(resolve(&base, "z").unwrap(), "http://h.tld:8080/dir/z");
        assert_eq!(resolve(&base, "https://o.tld/p").unwrap(), "https://o.tld/p");
        assert!(resolve(&base, "mailto:a@b.c").is_none());
    }

    #[tokio::test]
    async fn crawls_same_host_within_depth() {
        let port = serve().await;
        let start = format!("http://127.0.0.1:{port}/");
        let report = crawl(&start, 20, 2, 1500, true).await;

        let urls: HashSet<String> = report.pages.iter().map(|p| p.url.clone()).collect();
        assert!(urls.contains(&format!("http://127.0.0.1:{port}/")));
        assert!(urls.contains(&format!("http://127.0.0.1:{port}/a")));
        assert!(urls.contains(&format!("http://127.0.0.1:{port}/b")));
        assert!(urls.contains(&format!("http://127.0.0.1:{port}/c")), "should follow /a → /c");
        // External host never crawled.
        assert!(!urls.iter().any(|u| u.contains("example.com")));
    }

    #[tokio::test]
    async fn respects_max_pages() {
        let port = serve().await;
        let start = format!("http://127.0.0.1:{port}/");
        let report = crawl(&start, 2, 5, 1500, true).await;
        assert_eq!(report.pages.len(), 2);
    }
}
