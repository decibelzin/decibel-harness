//! The `nmap` tool: run an nmap scan and return STRUCTURED results (hosts,
//! ports, services) rather than raw text, so the model reasons over data.
//!
//! nmap emits XML with `-oX -`; this tool parses that into a canonical value.
//! It shells out to the installed `nmap` binary (via [`crate::proc`], so a scan
//! is killed cleanly on timeout/cancel). If nmap is not installed, the model is
//! told to install it or fall back to the `shell` tool.

use std::time::Duration;

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};
use tokio::process::Command;

use crate::proc::run_command;
use crate::util::{arg_bool, arg_str, arg_str_opt, arg_u64_opt};

/// Default scan timeout (nmap scans can be slow).
const DEFAULT_TIMEOUT_MS: u64 = 180_000;

/// Run an nmap scan and return parsed hosts/ports/services.
pub struct NmapTool;

#[async_trait]
impl Tool for NmapTool {
    fn name(&self) -> &str {
        "nmap"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "nmap".into(),
            description: "Run an nmap scan against a target and return STRUCTURED results: each \
                host with its open ports, protocols, and detected services/versions. Prefer this \
                over calling nmap through the shell when you want to reason over the ports found. \
                Requires nmap installed on PATH."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "Host, IP, CIDR, or range to scan." },
                    "ports": { "type": "string", "description": "Port spec, e.g. \"1-1000\" or \"22,80,443\"." },
                    "service_version": { "type": "boolean", "description": "Detect service/version with -sV (default true)." },
                    "extra_args": { "type": "string", "description": "Additional raw nmap flags, space-separated." },
                    "timeout_ms": { "type": "integer", "description": "Scan timeout in milliseconds (default 180000)." }
                },
                "required": ["target"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let target = arg_str(&arguments, "target")?;
        let timeout = Duration::from_millis(arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS));

        let mut cmd = Command::new("nmap");
        cmd.arg("-oX").arg("-").arg("-Pn"); // XML to stdout; skip host-up probe
        if arg_bool(&arguments, "service_version", true) {
            cmd.arg("-sV");
        }
        if let Some(ports) = arg_str_opt(&arguments, "ports") {
            cmd.arg("-p").arg(ports);
        }
        if let Some(extra) = arg_str_opt(&arguments, "extra_args") {
            for token in extra.split_whitespace() {
                cmd.arg(token);
            }
        }
        cmd.arg(&target);

        let result = run_command(cmd, timeout, ctx).await.map_err(|e| match e {
            ToolError::Aborted => ToolError::Aborted,
            other => ToolError::execution(format!("{other} (is nmap installed and on PATH?)")),
        })?;

        if result.timed_out {
            return Ok(json!({ "target": target, "timed_out": true, "hosts": [] }));
        }
        let xml = result.stdout.trim();
        if !xml.starts_with('<') {
            // nmap failed before producing XML (bad target, permissions, etc.).
            let detail = if result.stderr.trim().is_empty() { xml } else { result.stderr.trim() };
            return Err(ToolError::execution(format!("nmap produced no scan output: {detail}")));
        }
        let hosts = parse_nmap_xml(xml)
            .map_err(|e| ToolError::execution(format!("failed to parse nmap XML: {e}")))?;

        Ok(json!({
            "target": target,
            "timed_out": false,
            "exit_code": result.exit_code,
            "hosts": hosts,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let target = value.get("target").and_then(Value::as_str).unwrap_or("");
        if value.get("timed_out").and_then(Value::as_bool).unwrap_or(false) {
            return vec![ContentBlock::text(format!("nmap {target}: timed out"))];
        }
        let empty = Vec::new();
        let hosts = value.get("hosts").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("nmap {target} — {} host(s)\n", hosts.len());
        for host in hosts {
            let addr = host.get("address").and_then(Value::as_str).unwrap_or("?");
            let name = host
                .get("hostname")
                .and_then(Value::as_str)
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();
            let status = host.get("status").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("\n{addr}{name} [{status}]\n"));
            if let Some(ports) = host.get("ports").and_then(Value::as_array) {
                for p in ports {
                    let port = p.get("port").and_then(Value::as_u64).unwrap_or(0);
                    let proto = p.get("protocol").and_then(Value::as_str).unwrap_or("");
                    let state = p.get("state").and_then(Value::as_str).unwrap_or("");
                    let service = p.get("service").and_then(Value::as_str).unwrap_or("");
                    let product = p.get("product").and_then(Value::as_str).unwrap_or("");
                    let version = p.get("version").and_then(Value::as_str).unwrap_or("");
                    let svc = [service, product, version]
                        .iter()
                        .filter(|s| !s.is_empty())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ");
                    out.push_str(&format!("  {port}/{proto} {state} {svc}\n"));
                }
            }
        }
        vec![ContentBlock::text(out)]
    }
}

/// Parse nmap `-oX -` XML into a JSON array of hosts.
fn parse_nmap_xml(xml: &str) -> Result<Vec<Value>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
    let mut hosts = Vec::new();
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let status = host
            .children()
            .find(|c| c.has_tag_name("status"))
            .and_then(|s| s.attribute("state"))
            .unwrap_or("unknown")
            .to_string();
        // Prefer an IPv4/IPv6 address; fall back to the first address element.
        let address = host
            .children()
            .filter(|c| c.has_tag_name("address"))
            .find_map(|a| {
                let ty = a.attribute("addrtype").unwrap_or("");
                if ty == "ipv4" || ty == "ipv6" {
                    a.attribute("addr").map(str::to_string)
                } else {
                    None
                }
            })
            .or_else(|| {
                host.children()
                    .find(|c| c.has_tag_name("address"))
                    .and_then(|a| a.attribute("addr"))
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let hostname = host
            .descendants()
            .find(|n| n.has_tag_name("hostname"))
            .and_then(|h| h.attribute("name"))
            .map(str::to_string);

        let mut ports = Vec::new();
        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            let portid = port.attribute("portid").and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
            let protocol = port.attribute("protocol").unwrap_or("").to_string();
            let state = port
                .children()
                .find(|c| c.has_tag_name("state"))
                .and_then(|s| s.attribute("state"))
                .unwrap_or("")
                .to_string();
            let service_node = port.children().find(|c| c.has_tag_name("service"));
            let service = service_node.and_then(|s| s.attribute("name")).map(str::to_string);
            let product = service_node.and_then(|s| s.attribute("product")).map(str::to_string);
            let version = service_node.and_then(|s| s.attribute("version")).map(str::to_string);
            ports.push(json!({
                "port": portid,
                "protocol": protocol,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
            }));
        }

        hosts.push(json!({
            "address": address,
            "hostname": hostname,
            "status": status,
            "ports": ports,
        }));
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;

    #[test]
    fn parses_hosts_ports_and_services() {
        let hosts = parse_nmap_xml(SAMPLE).unwrap();
        assert_eq!(hosts.len(), 1);
        let h = &hosts[0];
        assert_eq!(h["address"], "127.0.0.1");
        assert_eq!(h["hostname"], "localhost");
        assert_eq!(h["status"], "up");
        let ports = h["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["port"], 22);
        assert_eq!(ports[0]["protocol"], "tcp");
        assert_eq!(ports[0]["state"], "open");
        assert_eq!(ports[0]["service"], "ssh");
        assert_eq!(ports[0]["product"], "OpenSSH");
        assert_eq!(ports[0]["version"], "8.9p1");
        assert_eq!(ports[1]["service"], "http");
    }

    #[test]
    fn render_shows_ports_table() {
        let hosts = parse_nmap_xml(SAMPLE).unwrap();
        let value = json!({ "target": "127.0.0.1", "timed_out": false, "hosts": hosts });
        let content = NmapTool.render(&json!({}), &value);
        match &content[0] {
            ContentBlock::Text { text } => {
                assert!(text.contains("127.0.0.1 (localhost)"));
                assert!(text.contains("22/tcp open ssh OpenSSH 8.9p1"));
                assert!(text.contains("80/tcp open http nginx"));
            }
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn malformed_xml_is_an_error() {
        assert!(parse_nmap_xml("not xml at all").is_err());
    }
}
