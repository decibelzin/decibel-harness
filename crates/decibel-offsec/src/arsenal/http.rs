//! Minimal HTTP prober (style of httpx): one request, reports status, title,
//! server, redirect location, timing, and a light technology fingerprint.
//!
//! Speaks plain HTTP over raw TCP and HTTPS over the accept-any rustls stack in
//! [`crate::arsenal::tls`]; both are byte streams so the request/response
//! exchange is shared.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    pub url: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub content_length: usize,
    pub elapsed_ms: u128,
    pub technologies: Vec<String>,
}

struct Url {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(raw: &str) -> Result<Url, String> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("http".to_string(), raw),
    };
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        other => return Err(format!("unsupported scheme: {other}")),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| format!("bad port in url: {p}"))?,
        ),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    Ok(Url {
        scheme,
        host,
        port,
        path: if path.is_empty() { "/".into() } else { path.to_string() },
    })
}

/// Probe a single URL. `timeout_ms` bounds connect + read.
pub async fn probe(raw_url: &str, timeout_ms: u64) -> Result<HttpResult, String> {
    fetch(raw_url, timeout_ms).await.map(|(result, _body)| result)
}

/// Like `probe`, but also returns the response body (used by the crawler).
pub async fn fetch(raw_url: &str, timeout_ms: u64) -> Result<(HttpResult, String), String> {
    let url = parse_url(raw_url)?;
    let dur = Duration::from_millis(timeout_ms);
    let start = Instant::now();

    // HTTPS rides the accept-any TLS stack; HTTP goes straight over TCP. Both
    // are byte streams, so the request/response exchange is shared.
    let raw = if url.scheme == "https" {
        let tls = crate::arsenal::tls::connect(&url.host, url.port, timeout_ms).await?;
        exchange(tls, &url, dur).await?
    } else {
        let addr = format!("{}:{}", url.host, url.port);
        let tcp = timeout(dur, TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("connect timeout: {addr}"))?
            .map_err(|e| format!("connect: {e}"))?;
        exchange(tcp, &url, dur).await?
    };

    let elapsed_ms = start.elapsed().as_millis();
    parse_response(raw_url, &raw, elapsed_ms)
}

/// Send the GET and read the response over any byte stream (TCP or TLS).
async fn exchange<S>(mut stream: S, url: &Url, dur: Duration) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: decibel-arsenal/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.path, url.host
    );
    timeout(dur, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    // Read up to 128 KiB of response.
    let mut raw = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    loop {
        match timeout(dur, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > 128 * 1024 {
                    break;
                }
            }
            Ok(Err(e)) => return Err(format!("read: {e}")),
            Err(_) => break, // read timeout — use what we have
        }
    }
    Ok(raw)
}

fn parse_response(url: &str, raw: &[u8], elapsed_ms: u128) -> Result<(HttpResult, String), String> {
    let text = String::from_utf8_lossy(raw);
    let split = text.find("\r\n\r\n").or_else(|| text.find("\n\n"));
    let (head, body) = match split {
        Some(i) => {
            let sep = if text[i..].starts_with("\r\n\r\n") { 4 } else { 2 };
            (&text[..i], &text[i + sep..])
        }
        None => (text.as_ref(), ""),
    };

    let mut lines = head.lines();
    let status_line = lines.next().ok_or("empty response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line: {status_line}"))?;

    let mut server = None;
    let mut location = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match key.as_str() {
                "server" => server = Some(val),
                "location" => location = Some(val),
                _ => {}
            }
        }
    }

    let title = extract_title(body);
    let technologies = fingerprint(server.as_deref(), body);

    Ok((
        HttpResult {
            url: url.to_string(),
            status,
            title,
            server,
            location,
            content_length: body.len(),
            elapsed_ms,
            technologies,
        },
        body.to_string(),
    ))
}

fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let gt = lower[start..].find('>')? + start + 1;
    let end = lower[gt..].find("</title>")? + gt;
    let title = body[gt..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(200).collect())
    }
}

/// Light technology fingerprint from the Server header and obvious body markers.
fn fingerprint(server: Option<&str>, body: &str) -> Vec<String> {
    let mut techs = Vec::new();
    let mut add = |t: &str| {
        let t = t.to_string();
        if !techs.contains(&t) {
            techs.push(t);
        }
    };

    if let Some(s) = server {
        let sl = s.to_ascii_lowercase();
        for (needle, label) in [
            ("nginx", "nginx"),
            ("apache", "Apache"),
            ("caddy", "Caddy"),
            ("cloudflare", "Cloudflare"),
            ("iis", "IIS"),
            ("gunicorn", "Gunicorn"),
            ("werkzeug", "Werkzeug"),
        ] {
            if sl.contains(needle) {
                add(label);
            }
        }
    }

    let bl = body.to_ascii_lowercase();
    for (needle, label) in [
        ("wp-content", "WordPress"),
        ("/_next/", "Next.js"),
        ("__nuxt", "Nuxt"),
        ("ng-version", "Angular"),
        ("react", "React"),
        ("drupal", "Drupal"),
    ] {
        if bl.contains(needle) {
            add(label);
        }
    }

    techs
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request line(s) minimally, then reply.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(response.as_bytes()).await;
            }
        });
        port
    }

    #[test]
    fn parse_url_variants() {
        let u = parse_url("http://example.com/foo").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("example.com", 80, "/foo"));
        let u = parse_url("example.com").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("example.com", 80, "/"));
        let u = parse_url("http://1.2.3.4:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("1.2.3.4", 8080, "/"));
        assert!(parse_url("ftp://x").is_err());
    }

    #[tokio::test]
    async fn probes_status_title_server_and_tech() {
        let resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><head><title>ACME Home</title></head><body>wp-content</body></html>";
        let port = serve_once(resp).await;
        let res = probe(&format!("http://127.0.0.1:{port}/"), 1500).await.unwrap();

        assert_eq!(res.status, 200);
        assert_eq!(res.title.as_deref(), Some("ACME Home"));
        assert_eq!(res.server.as_deref(), Some("nginx/1.18.0"));
        assert!(res.technologies.contains(&"nginx".to_string()));
        assert!(res.technologies.contains(&"WordPress".to_string()));
    }

    #[tokio::test]
    async fn reports_redirect_location() {
        let resp = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nConnection: close\r\n\r\n";
        let port = serve_once(resp).await;
        let res = probe(&format!("http://127.0.0.1:{port}/"), 1500).await.unwrap();
        assert_eq!(res.status, 301);
        assert_eq!(res.location.as_deref(), Some("https://example.com/"));
    }

    #[tokio::test]
    async fn https_to_dead_port_errors() {
        // HTTPS is supported; a closed port fails at connect/handshake.
        assert!(probe("https://127.0.0.1:1", 1500).await.is_err());
    }
}
