//! The kill-chain specialist roster (ported from Decepticon's sub-agent catalog).
//!
//! This is **pure data + selection logic**: the 17 standard specialists, the
//! 5-stage vulnresearch pipeline, each one's persona (compiled in via
//! `include_str!`), its scoped tool surface, and the high-risk authorization
//! gates ([`gated_tools`]) and override-locked safety tools ([`is_locked`]).
//!
//! The tool names here are the exact `decibel-offsec` tool names — they map 1:1
//! into [`decibel_offsec::register_named`], so a specialist's `tools` slice is
//! the literal set of tools it is handed when delegated. The Claude-Code /
//! Codex / MCP provider plumbing from upstream is intentionally omitted: this
//! crate is the in-process harness path.

use serde::Serialize;

// ---------------------------------------------------------------------------
// Specialist catalog (the 17 upstream sub-agents; the high-value roster ported)
// ---------------------------------------------------------------------------

/// A specialist sub-agent: a scoped persona the orchestrator delegates to. Ports
/// upstream's `SubAgentSpec` — the kill-chain sequence is priority-encoded
/// (`priority`, lower = earlier), the tool surface is scoped per role, and each
/// carries its own persona.
#[derive(Debug, Clone, Serialize)]
pub struct SpecialistSpec {
    /// Id exposed to the orchestrator (matches the `subagent_type` it dispatches).
    pub name: &'static str,
    /// Kill-chain phase label (informational for the roster).
    pub phase: &'static str,
    /// Roster order (lower = earlier). Mirrors upstream sub-agent `priority`.
    pub priority: u32,
    /// One line shown to the orchestrator so it can pick the right specialist.
    pub description: &'static str,
    /// Bare tool names this specialist is scoped to.
    pub tools: &'static [&'static str],
    /// Hard RoE authorization gate before any active interaction (ics_operator).
    pub roe_gate: bool,
    /// Hardware-mode check before operating (wireless_operator).
    pub hw_gate: bool,
}

/// The high-value specialist roster (of upstream's 17). Each scopes to real
/// native tools so delegation gives genuine, restricted firepower.
pub const SPECIALISTS: &[SpecialistSpec] = &[
    SpecialistSpec {
        name: "recon", phase: "Reconnaissance", priority: 10,
        description: "Target investigator. Enumerates hosts/services/paths/certs into raw OBSERVATIONS and the knowledge graph. Observes; does NOT classify or exploit.",
        tools: &["port_scan", "http_probe", "dns", "content_discovery", "tls_inspect", "web_crawl",
                 "kg_ingest", "kg_query", "kg_stats", "unexplored_surface", "killchain_lookup", "killchain_suggest",
                 "payload_search", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "exploit", phase: "Exploitation", priority: 20,
        description: "Turns recon observations into initial access: SQLi/SSTI/deserialization/cred attacks. Verifies with a PoC + negative control before recording a finding.",
        tools: &["cve_lookup", "cve_by_package", "payload_search", "killchain_lookup",
                 "skills_find", "skills_load", "poc_validate", "record_finding",
                 "kg_query", "kg_stats", "kg_edge", "mark_crown_jewel",
                 "impact_analysis", "unexplored_surface",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "web_operator", phase: "Web Exploitation", priority: 22,
        description: "Web-app specialist: JWT/cookie/OAuth/GraphQL attacks, auth bypass, IDOR. Uses the native web analyzers plus a shell for tooling.",
        tools: &["jwt_parse", "jwt_forge", "jwt_crack", "cookie_audit", "oauth_audit", "graphql_plan",
                 "http_probe", "content_discovery", "web_crawl", "payload_search", "cve_lookup",
                 "poc_validate", "record_finding", "kg_query", "kg_stats", "kg_edge",
                 "skills_find", "skills_load", "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "reverser", phase: "Binary Reversing", priority: 40,
        description: "Binary triage: identify/strings/packer/ROP/symbols on workspace files; hands deep decompilation to a shell (radare2/Ghidra).",
        tools: &["bin_identify", "bin_strings", "bin_packer", "bin_rop", "bin_symbols_report",
                 "kg_query", "kg_stats", "record_finding", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "contract_auditor", phase: "Smart-Contract Audit", priority: 50,
        description: "Solidity/EVM audit: reentrancy, access control, oracle/flash-loan abuse. Scans source, generates Foundry PoCs, ingests Slither.",
        tools: &["solidity_scan", "solidity_scan_file", "foundry_reentrancy_test",
                 "foundry_access_test", "foundry_flashloan_test", "kg_ingest", "kg_query", "kg_stats",
                 "record_finding", "cve_lookup", "cvss_score", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "cloud_hunter", phase: "Cloud Exploitation", priority: 60,
        description: "AWS/Azure/GCP/k8s: IAM privesc, S3 exposure, k8s escapes, tfstate secrets, metadata SSRF pivoting.",
        tools: &["iam_policy_audit", "s3_buckets_from_text", "user_data_secrets", "k8s_audit",
                 "tfstate_audit", "metadata_endpoints", "cve_lookup", "poc_validate", "record_finding",
                 "kg_query", "kg_stats", "kg_edge", "mark_crown_jewel", "impact_analysis",
                 "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "ad_operator", phase: "Active Directory Exploitation", priority: 70,
        description: "Active Directory: BloodHound ingest, Kerberoast/AS-REP, ADCS ESC, DCSync, multi-hop path planning (tooling reached via shell).",
        tools: &["killchain_lookup", "payload_search", "cve_lookup", "kg_ingest", "kg_query", "kg_stats",
                 "kg_edge", "mark_crown_jewel", "record_finding", "plan_chains", "promote_chain", "skills_find", "skills_load",
                 "impact_analysis", "unexplored_surface", "credential_reachability",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "postexploit", phase: "Post-Exploitation", priority: 80,
        description: "From a foothold: credential access, privilege escalation, lateral movement, C2 (Sliver) management.",
        tools: &["killchain_lookup", "payload_search", "kg_query", "kg_stats", "kg_edge",
                 "mark_crown_jewel", "record_finding", "plan_chains", "promote_chain", "skills_find", "skills_load",
                 "impact_analysis", "credential_reachability",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "osint_operator", phase: "OSINT", priority: 12,
        description: "Passive OSINT before active work: domain/email/subdomain harvest, breach data, Shodan/Censys, exposed assets. Read-only — collects, does not touch the target.",
        tools: &["dns", "http_probe", "web_crawl", "kg_ingest", "kg_query", "kg_stats",
                 "cve_lookup", "payload_search", "killchain_lookup", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "phisher", phase: "Initial Access", priority: 15,
        description: "Phishing / social-engineering initial access (T1566): email phishing, evilginx2, M365 device-code, lookalike domains. Deconflicts lures before sending.",
        tools: &["http_probe", "web_crawl", "payload_search", "killchain_lookup", "skills_find", "skills_load",
                 "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "supply_chain_operator", phase: "Supply Chain", priority: 25,
        description: "Supply-chain attacks (T1195/T1199): dependency confusion, typosquatting, malicious packages, CI/CD & build compromise, SBOM abuse.",
        tools: &["cve_lookup", "cve_by_package", "payload_search", "skills_find", "skills_load",
                 "kg_ingest", "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "mobile_operator", phase: "Mobile", priority: 55,
        description: "Android/iOS app assessment: static (apktool/jadx/MobSF), dynamic (frida/objection), SSL-pinning & root/JB bypass, WebView bridge, backend APIs.",
        tools: &["bin_identify", "bin_strings", "http_probe", "cve_lookup", "payload_search",
                 "skills_find", "skills_load", "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "iot_operator", phase: "IoT", priority: 58,
        description: "IoT/embedded: firmware acquisition + binwalk triage, hardcoded creds, U-Boot/dev-mem, radios (BLE/Zigbee/Z-Wave/sub-GHz/LoRaWAN).",
        tools: &["bin_identify", "bin_strings", "bin_packer", "cve_lookup", "payload_search",
                 "skills_find", "skills_load", "kg_ingest", "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "wireless_operator", phase: "Wireless", priority: 85,
        description: "Wi-Fi (WPA2/3, PMKID, evil-twin/KARMA, deauth, WPS Pixie), BLE GATT, Zigbee Touchlink, sub-GHz replay. Requires authorized hardware mode.",
        tools: &["killchain_lookup", "payload_search", "skills_find", "skills_load",
                 "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: true,
    },
    SpecialistSpec {
        name: "blue_cell", phase: "Detection Coverage", priority: 90,
        description: "Purple-team, read-only: replays engagement activity against detection expectations, surfaces coverage gaps + MTTD, writes a Defense Brief. No shell.",
        tools: &["kg_query", "kg_stats", "plan_chains", "report_executive", "skills_find", "skills_load", "shield_scan"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "ics_operator", phase: "ICS/OT", priority: 92,
        description: "ICS/OT/SCADA (Modbus/DNP3/S7comm/BACnet/OPC-UA). Highest-risk: a hard RoE gate + read-only enumeration first before ANY active interaction.",
        tools: &["cve_lookup", "payload_search", "killchain_lookup", "skills_find", "skills_load",
                 "kg_ingest", "kg_query", "kg_stats", "record_finding",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: true, hw_gate: false,
    },
    SpecialistSpec {
        name: "forensicator", phase: "DFIR", priority: 95,
        description: "DFIR / purple validation: disk/memory/log/network timeline, IOC extraction, Volatility/registry/PCAP triage. Analysis-only.",
        tools: &["cve_lookup", "payload_search", "skills_find", "skills_load",
                 "kg_ingest", "kg_query", "kg_stats", "record_finding",
                 "evidence_seal", "evidence_verify", "evidence_asciicast", "shield_scan",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
];

/// The vulnresearch pipeline — 5 ordered stages under the `vulnresearch`
/// orchestrator. Stage ordering is enforced by the orchestrator; inter-stage
/// state passes via workspace files (candidates/hypotheses/findings).
pub const VULNRESEARCH_PIPELINE: &[SpecialistSpec] = &[
    SpecialistSpec {
        name: "scanner", phase: "Scan", priority: 10,
        description: "Stage 1: broad, cheap sweep of a large codebase → CANDIDATES (no findings). grep/semgrep + native analyzers; writes recon/candidates.jsonl.",
        tools: &["solidity_scan", "solidity_scan_file", "bin_identify", "bin_strings",
                 "kg_ingest", "kg_node", "kg_query", "kg_stats", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "detector", phase: "Detect", priority: 20,
        description: "Stage 2: read source around each candidate → promote to VULNERABILITY+HYPOTHESIS or reject as false positive. Read-only, no PoCs.",
        tools: &["cve_lookup", "cve_by_package", "kg_ingest", "kg_node", "kg_query", "kg_stats",
                 "skills_find", "skills_load", "shell"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "verifier", phase: "Verify", priority: 30,
        description: "Stage 3: zero-false-positive gate — minimal PoC + mandatory negative control → FINDING with CVSS.",
        tools: &["poc_validate", "record_finding", "cvss_score", "evidence_seal", "kg_query", "kg_stats", "kg_edge",
                 "skills_find", "skills_load", "shield_scan", "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "patcher", phase: "Patch", priority: 40,
        description: "Stage 4: minimal diff for a validated finding, proven by re-running the PoC (expect failure).",
        tools: &["poc_validate", "kg_node", "kg_query", "kg_stats", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
    SpecialistSpec {
        name: "exploiter", phase: "Exploitation", priority: 50,
        description: "Stage 5 (optional): chain validated primitives into a weaponized path to a CROWN_JEWEL. Composes proven bugs; discovers none.",
        tools: &["payload_search", "cve_lookup", "cve_by_package", "poc_validate", "record_finding",
                 "kg_query", "kg_stats", "kg_edge", "mark_crown_jewel", "impact_analysis", "skills_find", "skills_load",
                 "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill"],
        roe_gate: false, hw_gate: false,
    },
];

/// The specialist roster for an orchestrator, in kill-chain/stage order.
/// `decepticon` → the standard specialists; `vulnresearch` → the 5 pipeline stages.
pub fn roster_for(parent: &str) -> &'static [SpecialistSpec] {
    if parent.eq_ignore_ascii_case("vulnresearch") {
        VULNRESEARCH_PIPELINE
    } else {
        SPECIALISTS
    }
}

/// The standard (Decepticon) specialist roster, in kill-chain order.
pub fn specialists() -> Vec<&'static SpecialistSpec> {
    sorted(SPECIALISTS)
}

pub(crate) fn sorted(roster: &'static [SpecialistSpec]) -> Vec<&'static SpecialistSpec> {
    let mut v: Vec<&SpecialistSpec> = roster.iter().collect();
    v.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.name.cmp(b.name)));
    v
}

/// Look up a specialist by name (case-insensitive) across BOTH rosters.
pub fn specialist(name: &str) -> Option<&'static SpecialistSpec> {
    SPECIALISTS
        .iter()
        .chain(VULNRESEARCH_PIPELINE.iter())
        .find(|s| s.name.eq_ignore_ascii_case(name))
}

/// True if `assistant` is an orchestrator that dispatches to a specialist roster
/// (Decepticon or Vulnresearch) — i.e. not Soundwave and not a specialist itself.
pub fn is_orchestrator(assistant: &str) -> bool {
    !assistant.eq_ignore_ascii_case("soundwave") && specialist(assistant).is_none()
}

/// A specialist's system prompt (its persona), compiled into the binary so there
/// is no file-resolution fragility when the app is moved/installed.
pub fn specialist_prompt(name: &str) -> Option<&'static str> {
    Some(match name {
        "recon" => include_str!("../specialists/recon.md"),
        "exploit" => include_str!("../specialists/exploit.md"),
        "web_operator" => include_str!("../specialists/web_operator.md"),
        "reverser" => include_str!("../specialists/reverser.md"),
        "contract_auditor" => include_str!("../specialists/contract_auditor.md"),
        "cloud_hunter" => include_str!("../specialists/cloud_hunter.md"),
        "ad_operator" => include_str!("../specialists/ad_operator.md"),
        "postexploit" => include_str!("../specialists/postexploit.md"),
        "osint_operator" => include_str!("../specialists/osint_operator.md"),
        "phisher" => include_str!("../specialists/phisher.md"),
        "supply_chain_operator" => include_str!("../specialists/supply_chain_operator.md"),
        "mobile_operator" => include_str!("../specialists/mobile_operator.md"),
        "iot_operator" => include_str!("../specialists/iot_operator.md"),
        "wireless_operator" => include_str!("../specialists/wireless_operator.md"),
        "blue_cell" => include_str!("../specialists/blue_cell.md"),
        "ics_operator" => include_str!("../specialists/ics_operator.md"),
        "forensicator" => include_str!("../specialists/forensicator.md"),
        "scanner" => include_str!("../specialists/scanner.md"),
        "detector" => include_str!("../specialists/detector.md"),
        "verifier" => include_str!("../specialists/verifier.md"),
        "patcher" => include_str!("../specialists/patcher.md"),
        "exploiter" => include_str!("../specialists/exploiter.md"),
        _ => return None,
    })
}

/// The "active" tool family — anything that runs a command or does I/O against a
/// target. Stripped from a gated specialist until it is authorized (SEC gate for
/// ics/wireless), leaving only read-only reference/KG tools.
const ACTIVE_TOOLS: &[&str] = &[
    "shell", "bash", "bash_input", "bash_output", "bash_status", "bash_kill", "poc_validate",
];

/// A specialist's EFFECTIVE bare-tool scope under the high-risk authorization
/// gates. `ics_operator` (`roe_gate`) stays read-only until `ics_authorized`;
/// `wireless_operator` (`hw_gate`) until `wireless_enabled`. When gated and
/// unauthorized, the active tool family ([`ACTIVE_TOOLS`]) is removed — so the
/// specialist literally cannot run active shell/exploit ops without authorization,
/// enforced in code (not just persona doctrine).
pub fn gated_tools(spec: &SpecialistSpec, ics_authorized: bool, wireless_enabled: bool) -> Vec<&'static str> {
    let blocked = (spec.roe_gate && !ics_authorized) || (spec.hw_gate && !wireless_enabled);
    if !blocked {
        return spec.tools.to_vec();
    }
    spec.tools.iter().copied().filter(|t| !ACTIVE_TOOLS.contains(t)).collect()
}

// ---------------------------------------------------------------------------
// SEC-7 — safety-slots override-locked
// ---------------------------------------------------------------------------

/// The **override-locked safety-critical tools**. Even if an operator disable-list
/// names one of these, it is NEVER stripped from the arsenal — an operator
/// misconfiguration cannot remove a safety control. Upstream's `SAFETY_CRITICAL_SLOTS`.
///   - `shield_scan` — the prompt-injection shield, on demand (SEC-5);
///   - `record_finding` — findings/evidence integrity (the audit trail);
///   - `complete_engagement_planning` — the terminal planning handoff signal.
pub const LOCKED_SAFETY_TOOLS: &[&str] = &["shield_scan", "record_finding", "complete_engagement_planning"];

/// Whether `tool` (bare or `mcp__decepticon__`-prefixed) is override-locked (SEC-7)
/// — i.e. a safety-critical tool an operator's disable-list must never strip.
pub fn is_locked(tool: &str) -> bool {
    let bare = tool.strip_prefix("mcp__decepticon__").unwrap_or(tool);
    LOCKED_SAFETY_TOOLS.iter().any(|t| t.eq_ignore_ascii_case(bare))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_specialist_has_a_prompt() {
        for roster in [SPECIALISTS, VULNRESEARCH_PIPELINE] {
            for s in roster {
                let p = specialist_prompt(s.name).unwrap_or_else(|| panic!("no prompt for {}", s.name));
                assert!(p.len() > 100, "{}: persona too short", s.name);
            }
        }
    }

    #[test]
    fn standard_roster_is_kill_chain_sorted_and_complete() {
        let names: Vec<&str> = specialists().iter().map(|s| s.name).collect();
        assert_eq!(names.len(), 17, "the full standard roster");
        // recon/osint come before exploitation; blue/ics/forensics are last.
        assert_eq!(names[0], "recon");
        let recon_i = names.iter().position(|n| *n == "recon").unwrap();
        let exploit_i = names.iter().position(|n| *n == "exploit").unwrap();
        assert!(recon_i < exploit_i, "recon precedes exploit: {names:?}");
        assert!(names.contains(&"web_operator") && names.contains(&"ics_operator"));
    }

    #[test]
    fn roe_and_hw_gates_strip_the_active_family() {
        // ics_operator (roe_gate) is read-only until authorized: no shell/bash/poc_validate.
        let ics = specialist("ics_operator").unwrap();
        let gated = gated_tools(ics, false, false);
        assert!(!gated.contains(&"shell"), "ics must be read-only when unauthorized: {gated:?}");
        assert!(!gated.contains(&"bash"));
        assert!(!gated.contains(&"poc_validate"));
        // it keeps its read-only reference/KG tools.
        assert!(gated.contains(&"cve_lookup") && gated.contains(&"kg_query"));
        // once authorized, the active family is restored.
        let auth = gated_tools(ics, true, false);
        assert!(auth.contains(&"shell") && auth.contains(&"bash"));

        // wireless_operator (hw_gate) is stripped until hardware is enabled.
        let wl = specialist("wireless_operator").unwrap();
        assert!(!gated_tools(wl, false, false).contains(&"shell"));
        assert!(gated_tools(wl, false, true).contains(&"shell"));

        // an ungated specialist keeps its full surface.
        let recon = specialist("recon").unwrap();
        assert_eq!(gated_tools(recon, false, false).len(), recon.tools.len());
        assert!(gated_tools(recon, false, false).contains(&"port_scan"));
    }

    #[test]
    fn locked_safety_tools_are_recognized() {
        // SEC-7: the safety-critical tools are locked (case-insensitive, prefix-aware).
        assert!(is_locked("shield_scan"));
        assert!(is_locked("mcp__decepticon__record_finding"));
        assert!(is_locked("Complete_Engagement_Planning"));
        assert!(!is_locked("web_crawl"));
        assert!(!is_locked("shell"));
        assert_eq!(LOCKED_SAFETY_TOOLS.len(), 3);
    }

    #[test]
    fn vulnresearch_pipeline_and_orchestrator() {
        // The pipeline roster is discovered under the vulnresearch parent, in stage order.
        let roster = sorted(roster_for("vulnresearch"));
        let names: Vec<&str> = roster.iter().map(|s| s.name).collect();
        assert_eq!(names, ["scanner", "detector", "verifier", "patcher", "exploiter"]);
        // vulnresearch is an orchestrator (gets a roster); a decepticon specialist is not.
        assert!(is_orchestrator("vulnresearch"));
        assert!(is_orchestrator("decepticon"));
        assert!(!is_orchestrator("recon"));
        assert!(!is_orchestrator("soundwave"));
        // a pipeline stage resolves via specialist() across both rosters.
        assert!(specialist("verifier").is_some());
        assert!(specialist("recon").is_some());
        assert!(specialist("ghost").is_none());
    }
}
