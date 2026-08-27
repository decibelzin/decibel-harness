//! Audit a Kubernetes manifest for container-escape / privilege primitives.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloud::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sAudit {
    pub kind: String,
    pub findings: Vec<Finding>,
}

const DANGEROUS_CAPS: &[&str] = &["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "NET_RAW"];

/// Locate the PodSpec: for a bare Pod it is `spec`; for a workload
/// (Deployment/DaemonSet/StatefulSet/Job) it is `spec.template.spec`.
fn pod_spec(doc: &Value) -> &Value {
    let s = &doc["spec"];
    if s.get("template").is_some() {
        &s["template"]["spec"]
    } else {
        s
    }
}

fn looks_secret(name: &str, value: &str) -> bool {
    let n = name.to_ascii_lowercase();
    (n.contains("password") || n.contains("secret") || n.contains("token") || n.contains("apikey") || n.contains("api_key"))
        && value.len() >= 4
}

/// Audit a manifest (`{kind, spec:{...}}`).
pub fn audit(manifest_json: &str) -> Result<K8sAudit, String> {
    let doc: Value = serde_json::from_str(manifest_json).map_err(|e| format!("manifest json: {e}"))?;
    let kind = doc["kind"].as_str().unwrap_or("").to_string();
    let ps = pod_spec(&doc);
    let mut findings = Vec::new();

    for (field, id) in [("hostNetwork", "host_network"), ("hostPID", "host_pid"), ("hostIPC", "host_ipc")] {
        if ps[field].as_bool() == Some(true) {
            findings.push(Finding::new("high", id, format!("`{field}: true` shares the host namespace — a strong escape/observation primitive.")));
        }
    }

    // hostPath volumes to sensitive locations.
    if let Some(vols) = ps["volumes"].as_array() {
        for v in vols {
            if let Some(path) = v["hostPath"]["path"].as_str() {
                let sev = if path == "/" || path.contains("docker.sock") || path.starts_with("/var/run") || path == "/etc" {
                    "critical"
                } else {
                    "medium"
                };
                findings.push(Finding::new(sev, "host_path", format!("hostPath volume mounts `{path}` from the node — a container-escape vector.")));
            }
        }
    }

    // Per-container security context + env.
    let mut containers: Vec<&Value> = Vec::new();
    for key in ["containers", "initContainers"] {
        if let Some(cs) = ps[key].as_array() {
            containers.extend(cs.iter());
        }
    }
    for c in containers {
        let sc = &c["securityContext"];
        if sc["privileged"].as_bool() == Some(true) {
            findings.push(Finding::new("critical", "privileged", "A container runs `privileged: true` — effectively root on the node."));
        }
        if sc["allowPrivilegeEscalation"].as_bool() == Some(true) {
            findings.push(Finding::new("medium", "allow_privesc", "`allowPrivilegeEscalation: true` lets a process gain more privileges than its parent."));
        }
        if sc["runAsUser"].as_i64() == Some(0) || sc["runAsNonRoot"].as_bool() == Some(false) {
            findings.push(Finding::new("medium", "runs_as_root", "Container runs as root (runAsUser 0 / runAsNonRoot false)."));
        }
        if let Some(add) = sc["capabilities"]["add"].as_array() {
            for cap in add {
                if let Some(name) = cap.as_str() {
                    if DANGEROUS_CAPS.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                        findings.push(Finding::new("high", "dangerous_cap", format!("Container adds the dangerous capability `{name}`.")));
                    }
                }
            }
        }
        if let Some(env) = c["env"].as_array() {
            for e in env {
                if let (Some(name), Some(val)) = (e["name"].as_str(), e["value"].as_str()) {
                    if looks_secret(name, val) {
                        findings.push(Finding::new("medium", "plaintext_env_secret", format!("Env var `{name}` holds a plaintext secret — use a Secret, not `value`.")));
                    }
                }
            }
        }
    }

    Ok(K8sAudit { kind, findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_privileged_hostpath_and_caps_on_a_pod() {
        let m = r#"{"kind":"Pod","spec":{"hostNetwork":true,"volumes":[{"hostPath":{"path":"/var/run/docker.sock"}}],
            "containers":[{"name":"c","securityContext":{"privileged":true,"capabilities":{"add":["SYS_ADMIN"]}},
            "env":[{"name":"DB_PASSWORD","value":"hunter2xyz"}]}]}}"#;
        let a = audit(m).unwrap();
        assert_eq!(a.kind, "Pod");
        for id in ["host_network", "host_path", "privileged", "dangerous_cap", "plaintext_env_secret"] {
            assert!(a.findings.iter().any(|f| f.id == id), "missing {id}: {:?}", a.findings);
        }
        assert!(a.findings.iter().any(|f| f.id == "host_path" && f.severity == "critical"));
    }

    #[test]
    fn digs_into_a_deployment_pod_template() {
        let m = r#"{"kind":"Deployment","spec":{"template":{"spec":{"containers":[
            {"name":"c","securityContext":{"privileged":true}}]}}}}"#;
        let a = audit(m).unwrap();
        assert_eq!(a.kind, "Deployment");
        assert!(a.findings.iter().any(|f| f.id == "privileged"));
    }

    #[test]
    fn a_hardened_pod_is_quiet() {
        let m = r#"{"kind":"Pod","spec":{"containers":[{"name":"c","securityContext":{"privileged":false,"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}}"#;
        assert!(audit(m).unwrap().findings.is_empty());
    }
}
