//! Wordlist content discovery (style of ffuf/gobuster): probe `base/<word>` for
//! each word and report the paths that don't look like misses. Built on the
//! plain-HTTP prober, bounded-concurrency.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::arsenal::http;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hit {
    pub path: String,
    pub url: String,
    pub status: u16,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub base: String,
    pub tested: usize,
    pub hits: Vec<Hit>,
}

/// Brute-force `base/<word>` over `words`. A path is a hit when its status is
/// not in `ignore_status` (default caller passes `[404]`). `concurrency` caps
/// in-flight requests; `timeout_ms` bounds each request.
pub async fn discover(
    base: &str,
    words: &[String],
    timeout_ms: u64,
    concurrency: usize,
    ignore_status: &[u16],
) -> DiscoveryReport {
    let base_norm = base.trim_end_matches('/').to_string();
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let ignore: Arc<Vec<u16>> = Arc::new(ignore_status.to_vec());
    let mut handles = Vec::with_capacity(words.len());

    for word in words {
        let word = word.trim().trim_start_matches('/').to_string();
        if word.is_empty() {
            continue;
        }
        let url = format!("{base_norm}/{word}");
        let sem = sem.clone();
        let ignore = ignore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            match http::probe(&url, timeout_ms).await {
                Ok(r) if !ignore.contains(&r.status) => Some(Hit {
                    path: format!("/{word}"),
                    url,
                    status: r.status,
                    size: r.content_length,
                }),
                _ => None,
            }
        }));
    }

    let mut hits = Vec::new();
    for h in handles {
        if let Ok(Some(hit)) = h.await {
            hits.push(hit);
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path));

    DiscoveryReport {
        base: base_norm,
        tested: words.len(),
        hits,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A tiny server that returns 200 for `/admin` and `/robots.txt`, 404 else.
    async fn serve() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let resp = if path == "/admin" || path == "/robots.txt" {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    };
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn finds_present_paths_ignores_404() {
        let port = serve().await;
        let base = format!("http://127.0.0.1:{port}");
        let words = ["admin", "secret", "robots.txt", "nope"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let report = discover(&base, &words, 1500, 16, &[404]).await;

        assert_eq!(report.tested, 4);
        let paths: Vec<&str> = report.hits.iter().map(|h| h.path.as_str()).collect();
        assert_eq!(paths, vec!["/admin", "/robots.txt"]);
        assert!(report.hits.iter().all(|h| h.status == 200));
    }

    #[tokio::test]
    async fn empty_words_yield_no_hits() {
        let port = serve().await;
        let base = format!("http://127.0.0.1:{port}");
        let report = discover(&base, &[], 1000, 8, &[404]).await;
        assert!(report.hits.is_empty());
    }
}
