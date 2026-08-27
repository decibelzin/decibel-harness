//! Kill-chain reference (port spec §3, the committed `killchain.yaml`): a flat
//! map of red-team tools to the 14 MITRE ATT&CK tactic phases, with lookup by
//! phase and keyword-based suggestion from an objective. Bundled, no network.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub phase: String,
    pub name: String,
    pub description: String,
}

/// The 14 canonical MITRE ATT&CK tactic phases, in kill-chain order.
pub const PHASES: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

/// (phase, tool, description)
const TOOLS: &[(&str, &str, &str)] = &[
    ("reconnaissance", "nmap", "port/service/version scanning"),
    ("reconnaissance", "subfinder", "passive subdomain enumeration"),
    ("reconnaissance", "amass", "attack-surface mapping"),
    ("reconnaissance", "httpx", "http probing + tech fingerprint"),
    ("reconnaissance", "shodan", "internet-wide host intel"),
    ("resource-development", "msfvenom", "payload generation"),
    ("resource-development", "sliver", "implant/beacon generation"),
    ("initial-access", "gophish", "phishing campaign framework"),
    ("initial-access", "evilginx2", "MITM phishing / MFA bypass"),
    ("execution", "metasploit", "exploit + payload delivery"),
    ("execution", "sqlmap", "automated SQL injection"),
    ("execution", "commix", "command injection exploitation"),
    ("persistence", "sliver", "beacon persistence"),
    ("persistence", "scheduled-task", "cron / schtasks persistence"),
    ("privilege-escalation", "linpeas", "Linux privesc enumeration"),
    ("privilege-escalation", "winpeas", "Windows privesc enumeration"),
    ("privilege-escalation", "GTFOBins", "abusing binaries for privesc"),
    ("defense-evasion", "amsi-bypass", "in-memory AMSI patching"),
    ("credential-access", "mimikatz", "credential/secret extraction"),
    ("credential-access", "hashcat", "password/hash cracking"),
    ("credential-access", "impacket-secretsdump", "remote secret dumping"),
    ("credential-access", "responder", "LLMNR/NBT-NS poisoning"),
    ("discovery", "bloodhound", "AD attack-path mapping"),
    ("discovery", "netexec", "network/AD enumeration"),
    ("discovery", "enum4linux", "SMB/RPC enumeration"),
    ("lateral-movement", "evil-winrm", "WinRM remote shell"),
    ("lateral-movement", "impacket-psexec", "remote command execution"),
    ("lateral-movement", "impacket-wmiexec", "WMI remote execution"),
    ("collection", "powerview", "AD data collection"),
    ("command-and-control", "sliver", "C2 framework"),
    ("command-and-control", "havoc", "C2 framework"),
    ("exfiltration", "rclone", "bulk data exfiltration"),
    ("exfiltration", "curl", "ad-hoc data exfil over http"),
    ("impact", "note", "impact actions require explicit RoE authorization"),
];

fn to_entry(t: &(&str, &str, &str)) -> Entry {
    Entry {
        phase: t.0.to_string(),
        name: t.1.to_string(),
        description: t.2.to_string(),
    }
}

/// Normalize common phase aliases to the canonical slug.
fn canonical_phase(p: &str) -> String {
    let p = p.to_lowercase().replace([' ', '_'], "-");
    match p.as_str() {
        "recon" => "reconnaissance",
        "weaponization" => "resource-development",
        "delivery" => "initial-access",
        "exploitation" => "execution",
        "privesc" => "privilege-escalation",
        "lateral" | "lateral-movement" => "lateral-movement",
        "c2" | "command-control" => "command-and-control",
        "creds" | "credentials" => "credential-access",
        other => other,
    }
    .to_string()
}

/// Tools mapped to a kill-chain phase.
pub fn lookup(phase: &str, limit: usize) -> Vec<Entry> {
    let want = canonical_phase(phase);
    TOOLS
        .iter()
        .filter(|t| t.0 == want)
        .take(limit)
        .map(to_entry)
        .collect()
}

/// Suggest tools by keyword-matching an objective against tool names/descriptions.
pub fn suggest(objective: &str, limit: usize) -> Vec<Entry> {
    let q = objective.to_lowercase();
    TOOLS
        .iter()
        .filter(|t| {
            q.split_whitespace()
                .any(|w| w.len() > 2 && (t.1.to_lowercase().contains(w) || t.2.to_lowercase().contains(w)))
        })
        .take(limit)
        .map(to_entry)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_phase_and_alias() {
        let recon = lookup("reconnaissance", 100);
        assert!(recon.iter().any(|e| e.name == "nmap"));
        // Alias resolves.
        let recon2 = lookup("recon", 100);
        assert_eq!(recon.len(), recon2.len());
        assert!(lookup("exploitation", 100).iter().any(|e| e.name == "metasploit"));
    }

    #[test]
    fn suggest_by_objective() {
        let hits = suggest("crack the captured password hashes", 100);
        assert!(hits.iter().any(|e| e.name == "hashcat"), "got {hits:?}");
        let ad = suggest("map active directory attack paths", 100);
        assert!(ad.iter().any(|e| e.name == "bloodhound"));
    }

    #[test]
    fn all_phases_covered() {
        for p in PHASES {
            assert!(!lookup(p, 100).is_empty(), "phase {p} has no tools");
        }
    }
}
