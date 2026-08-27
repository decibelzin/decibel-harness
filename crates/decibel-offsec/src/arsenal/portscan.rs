//! Async TCP-connect port scanner with banner grab and bounded concurrency.
//! Style of naabu/rustscan, but dependency-free (pure tokio).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortResult {
    pub port: u16,
    pub open: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub open_ports: Vec<PortResult>,
    pub scanned: usize,
}

/// Guess a service name from a well-known port number.
pub fn service_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => return None,
    })
}

/// Scan `ports` on `target` (a host or IP). Returns only the open ports, each
/// with an optional service hint and a best-effort banner. `concurrency` caps
/// simultaneous connections; `timeout_ms` bounds each connect + banner read.
pub async fn scan(
    target: &str,
    ports: &[u16],
    timeout_ms: u64,
    concurrency: usize,
) -> ScanReport {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let target = target.to_string();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            probe_port(&target, port, timeout_ms).await
        }));
    }

    let mut open_ports = Vec::new();
    for h in handles {
        if let Ok(Some(res)) = h.await {
            open_ports.push(res);
        }
    }
    open_ports.sort_by_key(|r| r.port);

    ScanReport {
        target: target.to_string(),
        open_ports,
        scanned: ports.len(),
    }
}

/// Connect to one port; on success optionally grab a banner. Returns `None` if
/// the port is closed/filtered (so closed ports don't clutter the report).
async fn probe_port(target: &str, port: u16, timeout_ms: u64) -> Option<PortResult> {
    let addr = format!("{target}:{port}");
    let dur = Duration::from_millis(timeout_ms);

    let stream = match timeout(dur, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let banner = grab_banner(stream, dur).await;

    Some(PortResult {
        port,
        open: true,
        service: service_hint(port).map(str::to_string),
        banner,
    })
}

/// Read a short banner some services volunteer on connect (SSH, FTP, SMTP…).
/// Best-effort: a silent service simply yields `None`.
async fn grab_banner(mut stream: TcpStream, dur: Duration) -> Option<String> {
    let mut buf = [0u8; 256];
    match timeout(dur, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let text: String = String::from_utf8_lossy(&buf[..n])
                .chars()
                .map(|c| if c.is_control() && c != ' ' { ' ' } else { c })
                .collect();
            let trimmed = text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn finds_open_port_and_marks_closed_absent() {
        // Bind an ephemeral listener; that port must show open.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
            }
        });

        // A very likely-closed port on loopback for the negative case.
        let closed_port = 1; // privileged, nothing listening on loopback
        let report = scan("127.0.0.1", &[open_port, closed_port], 800, 64).await;

        assert_eq!(report.scanned, 2);
        assert_eq!(report.open_ports.len(), 1, "only the listener port is open");
        assert_eq!(report.open_ports[0].port, open_port);
        assert!(report.open_ports[0].open);
    }

    #[tokio::test]
    async fn grabs_banner_when_service_speaks_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"220 ftp.example.com FTP ready\r\n").await;
            }
        });

        let report = scan("127.0.0.1", &[port], 800, 8).await;
        let banner = report.open_ports[0].banner.as_deref().unwrap_or("");
        assert!(banner.contains("FTP ready"), "got banner: {banner:?}");
    }

    #[test]
    fn service_hints() {
        assert_eq!(service_hint(22), Some("ssh"));
        assert_eq!(service_hint(443), Some("https"));
        assert_eq!(service_hint(65000), None);
    }
}
