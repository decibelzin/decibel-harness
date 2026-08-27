//! Rules-of-Engagement (RoE) scope enforcement.
//!
//! Ported faithfully from Decepticon's `decepticon-roe` crate (Apache-2.0),
//! whose only dependency was `serde_json` — so the whole thing is pure, offline,
//! and self-contained (no `decepticon_store`, no knowledge-graph ingest to omit).
//!
//! An engagement stores `scope_json` = `{ "targets": [...], "notes": "..." }`,
//! where `targets` is the operator's authorized-target allowlist. This module
//! parses that list and answers one question: **is this target in scope?** — so
//! the tool layer can refuse to touch anything the operator did not authorize.
//!
//! Policy: if the operator defined NO targets, RoE is *not configured* and every
//! target is allowed (non-breaking for the default engagement). The moment ANY
//! target is listed, enforcement is strict — anything not matching is denied.
//!
//! A rule matches a target by, in order: exact IP, IPv4 CIDR membership, or
//! domain suffix (`example.com` matches `example.com` and `*.example.com`).
//! Pure + offline (no network, no DNS resolution — a hostname is matched as text,
//! never resolved, so a scope of `example.com` never silently authorizes an IP).
//!
//! Beyond the ported [`Scope`], this module adds [`ScopePolicy`] — a
//! [`decibel_tools::PrePolicy`] that gates every tool call against the scope. It
//! is inert while the scope is unenforced (empty), so it can be installed
//! unconditionally and only bites once the operator lists an authorized target.

use std::net::{IpAddr, Ipv4Addr};

use decibel_tools::{PreDecision, PrePolicy, ToolCall};

/// A parsed authorized-target allowlist.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
enum Rule {
    /// An exact IP (v4 or v6).
    Ip(IpAddr),
    /// An IPv4 network: `(network, mask)` both as big-endian u32.
    V4Cidr { net: u32, mask: u32 },
    /// A domain; matches itself and any subdomain.
    Domain(String),
}

impl Scope {
    /// Parse an engagement's `scope_json`. Malformed JSON or a missing `targets`
    /// array yields an empty (unenforced) scope rather than an error.
    pub fn parse(scope_json: &str) -> Scope {
        let mut rules = Vec::new();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(scope_json) {
            if let Some(arr) = v.get("targets").and_then(|t| t.as_array()) {
                for t in arr {
                    if let Some(rule) = t.as_str().and_then(parse_rule) {
                        rules.push(rule);
                    }
                }
            }
        }
        Scope { rules }
    }

    /// True once the operator has listed at least one authorized target.
    pub fn is_enforced(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Is `target` (a host, IP, `host:port`, or URL) authorized? Always true when
    /// the scope is unenforced.
    pub fn allows(&self, target: &str) -> bool {
        if self.rules.is_empty() {
            return true;
        }
        let host = target_host(target).to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            let v4 = match ip {
                IpAddr::V4(a) => Some(u32::from(a)),
                IpAddr::V6(_) => None,
            };
            return self.rules.iter().any(|r| match r {
                Rule::Ip(rip) => *rip == ip,
                Rule::V4Cidr { net, mask } => v4.map(|a| a & mask == *net).unwrap_or(false),
                Rule::Domain(_) => false,
            });
        }
        self.rules.iter().any(|r| match r {
            Rule::Domain(d) => host == *d || host.ends_with(&format!(".{d}")),
            _ => false,
        })
    }

    /// `Ok(())` if in scope, else a clear denial error naming the target.
    pub fn check(&self, target: &str) -> Result<(), String> {
        if self.allows(target) {
            Ok(())
        } else {
            Err(format!(
                "out of RoE scope: `{}` is not in the engagement's authorized targets — add it in the engagement's Scope & RoE, or point at an authorized target",
                target_host(target)
            ))
        }
    }

    /// **Egress allowlist for `shell`/`bash`** (SEC-2). A shell command can reach
    /// any network target a shell can; the recon tools are scope-gated but a raw
    /// command was not. This extracts the network targets a command *appears* to
    /// contact ([`extract_targets`]) and denies the whole command if any one is
    /// out of scope — closing the last un-gated egress vector.
    ///
    /// Heuristic by nature (it reads a command string, not packets), so it is a
    /// guardrail, not a firewall: no-op when the scope is unenforced, loopback is
    /// always allowed, and version-string/edge false positives are the operator's
    /// cue to widen scope or set `DECEPTICON_EGRESS_DISABLE` (handled by the
    /// caller). Returns the first out-of-scope target as a clear denial.
    pub fn check_command(&self, command: &str) -> Result<(), String> {
        if !self.is_enforced() {
            return Ok(());
        }
        for target in extract_targets(command) {
            if !self.allows(&target) {
                return Err(format!(
                    "egress blocked: command targets `{target}`, which is not in the engagement's authorized scope. \
                     Point it at an authorized target, add it in Scope & RoE, or set DECEPTICON_EGRESS_DISABLE=1 to override."
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Egress target extraction (SEC-2) — pure, heuristic, dependency-free
// ---------------------------------------------------------------------------

/// Common file-name extensions that must NOT be mistaken for a domain's TLD.
const FILE_EXTS: &[&str] = &[
    "sh", "bash", "zsh", "py", "rb", "pl", "php", "js", "ts", "jsx", "tsx", "go", "rs",
    "c", "h", "cpp", "hpp", "java", "class", "jar", "txt", "md", "rst", "json", "xml",
    "csv", "tsv", "yaml", "yml", "toml", "ini", "conf", "cfg", "log", "html", "htm",
    "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "pdf", "zip", "gz", "tgz", "tar",
    "bz2", "xz", "7z", "rar", "exe", "dll", "so", "o", "obj", "bin", "img", "iso", "db",
    "sqlite", "bak", "old", "tmp", "swp", "lock", "sum", "mod", "pem", "key", "crt",
    "cer", "pfx", "p12", "sol", "abi", "wasm", "deb", "rpm", "apk", "ipa", "dmg", "pcap",
];

fn is_local(host: &str) -> bool {
    host.is_empty()
        || host == "localhost"
        || host == "0.0.0.0"
        || host == "::1"
        || host == "::"
        || host.starts_with("127.")
}

fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

/// Common public + internal TLDs. A dotted name is only treated as a network
/// target when its last label is one of these — this keeps `http.server`,
/// `os.path`, `foo.bar` (module/attr access) from being mistaken for domains.
/// Includes internal suffixes (`local`/`corp`/`lan`/…) so AD hostnames match.
/// Exotic real TLDs are the operator's cue to widen scope; IP targets are always
/// caught regardless.
const COMMON_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "edu", "gov", "mil", "info", "biz",
    "me", "ai", "cloud", "tech", "xyz", "online", "site", "shop", "test", "example",
    // internal / lab suffixes.
    "local", "corp", "internal", "intranet", "intra", "lan", "home", "arpa", "domain",
    // common ccTLDs.
    "us", "uk", "de", "fr", "br", "ca", "au", "jp", "cn", "ru", "in", "nl", "es", "it",
    "se", "no", "fi", "pl", "ch", "at", "be", "dk", "ie", "nz", "za", "mx", "kr", "sg",
    "hk", "tw", "pt", "gr", "cz", "ro", "ua", "tr", "il",
];

/// A `label.label(.tld)` name whose last label is a recognized TLD and whose
/// labels are all DNS-legal.
fn looks_like_domain(host: &str) -> bool {
    if !host.contains('.') {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    let tld = labels.last().copied().unwrap_or("").to_ascii_lowercase();
    if FILE_EXTS.contains(&tld.as_str()) || !COMMON_TLDS.contains(&tld.as_str()) {
        return false;
    }
    labels
        .iter()
        .all(|l| l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !l.starts_with('-'))
}

/// The single network target a shell token appears to reference, if any.
fn target_in_token(tok: &str) -> Option<String> {
    let tok = tok.trim_matches(|c: char| matches!(c, '\'' | '"' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'));
    if tok.is_empty() || tok.starts_with('-') {
        return None;
    }
    let had_scheme = tok.contains("://");
    let host = target_host(tok).to_ascii_lowercase();
    if host.is_empty() || is_local(&host) {
        return None;
    }
    if is_ipv4(&host) {
        return Some(host);
    }
    if looks_like_domain(&host) {
        return Some(host);
    }
    // A scheme (`ssh://`, `http://`) means it IS a network target even if the host
    // is a bare name (e.g. an internal hostname without a dot).
    if had_scheme && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.')) {
        return Some(host);
    }
    None
}

/// Extract the distinct network targets a shell command appears to contact:
/// IPv4 literals, `host:port`, URLs, and dotted domain names (loopback and
/// file-like tokens excluded). Pure text — never resolves DNS. Heuristic: it can
/// miss an obfuscated target and can over-match a bare IP-shaped literal.
pub fn extract_targets(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in command.split(|c: char| c.is_whitespace() || matches!(c, '|' | '&' | ';' | '<' | '>' | '"' | '\'' | '`')) {
        if let Some(t) = target_in_token(raw) {
            if seen.insert(t.clone()) {
                out.push(t);
            }
        }
    }
    out
}

fn parse_rule(s: &str) -> Option<Rule> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // CIDR (IPv4 only for now).
    if let Some((ip, prefix)) = s.split_once('/') {
        if let (Ok(v4), Ok(p)) = (ip.trim().parse::<Ipv4Addr>(), prefix.trim().parse::<u32>()) {
            if p <= 32 {
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                return Some(Rule::V4Cidr { net: u32::from(v4) & mask, mask });
            }
        }
        return None;
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(Rule::Ip(ip));
    }
    // Otherwise a domain — tolerate a pasted URL or a leading wildcard.
    let host = target_host(s).to_ascii_lowercase();
    let host = host.trim_start_matches("*.").trim_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(Rule::Domain(host.to_string()))
    }
}

/// Extract the bare host from a host / `host:port` / URL / `user@host` string.
/// Never resolves DNS — pure text.
pub fn target_host(s: &str) -> String {
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    // Strip a trailing :port (but leave bare IPv6 — which has multiple colons — alone).
    let host = if authority.matches(':').count() == 1 {
        authority.split_once(':').map(|(h, _)| h).unwrap_or(authority)
    } else {
        authority
    };
    host.trim().trim_matches('.').to_string()
}

// ---------------------------------------------------------------------------
// ScopePolicy — the RoE gate wired as a decibel_tools::PrePolicy
// ---------------------------------------------------------------------------

/// The tool-call argument keys that name a single network target. Each is checked
/// with [`Scope::check`]; `shell`/`bash`'s raw command is handled separately with
/// [`Scope::check_command`] (egress extraction), since it is a whole command line
/// rather than a single host.
const TARGET_ARG_KEYS: &[&str] = &[
    "target",
    "host",
    "url",
    "base_url",
    "name",
    "callback_url",
    "initial_request_url",
];

/// A pre-execution Rules-of-Engagement gate.
///
/// Holds the engagement's parsed [`Scope`] and, on every tool call, denies the
/// call when a target-bearing argument points out of scope. For `shell`/`bash`
/// the raw `command`/`cmd` string is scanned for out-of-scope egress; for every
/// other tool the common single-target argument keys ([`TARGET_ARG_KEYS`]) are
/// checked.
///
/// **Unenforced until the operator lists a target.** An empty scope allows
/// everything, so this policy is inert by default and can be installed
/// unconditionally — it only starts denying once the operator sets a scope.
pub struct ScopePolicy {
    scope: Scope,
}

impl ScopePolicy {
    /// Gate against an already-parsed `scope`.
    pub fn new(scope: Scope) -> Self {
        ScopePolicy { scope }
    }

    /// Convenience: parse an engagement's `scope_json` and gate against it.
    pub fn parse(scope_json: &str) -> Self {
        ScopePolicy { scope: Scope::parse(scope_json) }
    }

    /// The scope this policy enforces.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl PrePolicy for ScopePolicy {
    fn check(&self, call: &ToolCall) -> PreDecision {
        // Inert until the operator lists at least one authorized target: an empty
        // scope allows everything (mirrors `Scope`'s own unenforced semantics).
        if !self.scope.is_enforced() {
            return PreDecision::Allow;
        }

        // A raw shell/bash command can reach any target: scan the whole command
        // line for out-of-scope egress rather than treating it as one host.
        if matches!(call.name.as_str(), "shell" | "bash") {
            for key in ["command", "cmd"] {
                if let Some(cmd) = call.arguments.get(key).and_then(|v| v.as_str()) {
                    if let Err(reason) = self.scope.check_command(cmd) {
                        return PreDecision::Deny(reason);
                    }
                }
            }
        }

        // Common single-target argument keys on the recon/http/analysis tools.
        for key in TARGET_ARG_KEYS {
            if let Some(target) = call.arguments.get(*key).and_then(|v| v.as_str()) {
                if target.is_empty() {
                    continue;
                }
                if let Err(reason) = self.scope.check(target) {
                    return PreDecision::Deny(reason);
                }
            }
        }

        PreDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_allows_everything() {
        let s = Scope::parse("{}");
        assert!(!s.is_enforced());
        assert!(s.allows("10.0.0.5"));
        assert!(s.allows("anything.example.com"));
    }

    #[test]
    fn exact_ip_scope() {
        let s = Scope::parse(r#"{"targets":["10.0.0.5"]}"#);
        assert!(s.is_enforced());
        assert!(s.allows("10.0.0.5"));
        assert!(s.allows("10.0.0.5:8080"));
        assert!(s.allows("http://10.0.0.5/admin"));
        assert!(!s.allows("10.0.0.6"));
    }

    #[test]
    fn ipv4_cidr_membership() {
        let s = Scope::parse(r#"{"targets":["10.0.0.0/24"]}"#);
        assert!(s.allows("10.0.0.1"));
        assert!(s.allows("10.0.0.254"));
        assert!(!s.allows("10.0.1.1"));
        assert!(!s.allows("192.168.0.1"));
    }

    #[test]
    fn domain_suffix_matching() {
        let s = Scope::parse(r#"{"targets":["example.com"]}"#);
        assert!(s.allows("example.com"));
        assert!(s.allows("api.example.com"));
        assert!(s.allows("https://api.example.com/v1/users"));
        assert!(!s.allows("evil.com"));
        assert!(!s.allows("notexample.com"));
        // A domain scope must NOT authorize an arbitrary IP (no resolution).
        assert!(!s.allows("10.0.0.5"));
    }

    #[test]
    fn mixed_scope_and_check_error() {
        let s = Scope::parse(r#"{"targets":["10.0.0.0/24","acme.test","192.168.1.10"]}"#);
        assert!(s.allows("10.0.0.99"));
        assert!(s.allows("shop.acme.test"));
        assert!(s.allows("192.168.1.10"));
        let err = s.check("8.8.8.8").unwrap_err();
        assert!(err.contains("out of RoE scope"));
        assert!(err.contains("8.8.8.8"));
    }

    #[test]
    fn host_extraction() {
        assert_eq!(target_host("http://example.com:8080/x"), "example.com");
        assert_eq!(target_host("user@10.0.0.5:22"), "10.0.0.5");
        assert_eq!(target_host("example.com"), "example.com");
        assert_eq!(target_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn malformed_scope_is_unenforced() {
        assert!(!Scope::parse("not json").is_enforced());
        assert!(!Scope::parse(r#"{"notes":"hi"}"#).is_enforced());
        assert!(Scope::parse("not json").allows("anything"));
    }

    // --- egress extraction + command gate (SEC-2) -------------------------

    #[test]
    fn extract_finds_ips_urls_domains_not_files_or_flags() {
        let t = extract_targets("nmap -sV -oN out.txt 10.0.0.5 && curl https://api.evil.com/x");
        assert!(t.contains(&"10.0.0.5".to_string()), "{t:?}");
        assert!(t.contains(&"api.evil.com".to_string()), "{t:?}");
        // file names, flags, and the tool name are not targets.
        assert!(!t.iter().any(|x| x == "out.txt" || x == "-on" || x == "nmap"), "{t:?}");
    }

    #[test]
    fn extract_ignores_loopback_and_bare_words() {
        let t = extract_targets("python3 -m http.server 8000 --bind 127.0.0.1");
        // 127.0.0.1 is loopback (allowed), http.server is a file-ish/module token.
        assert!(t.is_empty(), "{t:?}");
    }

    #[test]
    fn extract_pulls_host_from_userat_and_port() {
        let t = extract_targets("ssh root@192.168.1.10 -p 2222");
        assert_eq!(t, vec!["192.168.1.10".to_string()]);
        let t2 = extract_targets("evil-winrm -i dc01.corp.local -u admin");
        assert!(t2.contains(&"dc01.corp.local".to_string()), "{t2:?}");
    }

    #[test]
    fn check_command_blocks_out_of_scope_egress() {
        let s = Scope::parse(r#"{"targets":["10.0.0.0/24"]}"#);
        // in-scope command passes
        assert!(s.check_command("nmap 10.0.0.5").is_ok());
        // out-of-scope target is blocked, naming it
        let err = s.check_command("curl https://8.8.8.8/exfil").unwrap_err();
        assert!(err.contains("egress blocked") && err.contains("8.8.8.8"), "{err}");
        // a mixed command is blocked on the first out-of-scope target
        assert!(s.check_command("nmap 10.0.0.5; curl http://exfil.evil.com").is_err());
        // a command with no network target passes
        assert!(s.check_command("cat /etc/passwd | grep root").is_ok());
    }

    #[test]
    fn check_command_noop_when_unenforced() {
        let s = Scope::parse("{}");
        assert!(!s.is_enforced());
        assert!(s.check_command("curl https://anywhere.example.com").is_ok());
    }

    #[test]
    fn version_string_glued_to_pkg_is_not_flagged() {
        let s = Scope::parse(r#"{"targets":["10.0.0.0/24"]}"#);
        // a pinned dependency version is not a bare target token
        assert!(s.check_command("pip install requests==1.2.3.4").is_ok());
    }

    // --- ScopePolicy (the decibel_tools::PrePolicy gate) -------------------

    use decibel_llm::CallId;
    use serde_json::json;

    fn call(name: &str, arguments: serde_json::Value) -> ToolCall {
        ToolCall {
            call_id: CallId::from("roe-test"),
            name: name.into(),
            arguments,
        }
    }

    #[test]
    fn policy_empty_scope_allows_all() {
        // Inert by default: an empty scope authorizes every call, including a
        // shell command reaching an arbitrary public host.
        let p = ScopePolicy::parse("{}");
        assert_eq!(
            p.check(&call("http_probe", json!({ "url": "https://anywhere.example.com" }))),
            PreDecision::Allow
        );
        assert_eq!(
            p.check(&call("port_scan", json!({ "target": "8.8.8.8" }))),
            PreDecision::Allow
        );
        assert_eq!(
            p.check(&call("shell", json!({ "command": "curl https://8.8.8.8/exfil" }))),
            PreDecision::Allow
        );
    }

    #[test]
    fn policy_in_scope_allows() {
        let p = ScopePolicy::new(Scope::parse(r#"{"targets":["10.0.0.0/24","example.com"]}"#));
        assert_eq!(
            p.check(&call("port_scan", json!({ "target": "10.0.0.5" }))),
            PreDecision::Allow
        );
        assert_eq!(
            p.check(&call("http_probe", json!({ "url": "https://api.example.com/x" }))),
            PreDecision::Allow
        );
        assert_eq!(
            p.check(&call("dns", json!({ "name": "sub.example.com" }))),
            PreDecision::Allow
        );
        // an in-scope shell command is allowed
        assert_eq!(
            p.check(&call("shell", json!({ "command": "nmap -sV 10.0.0.5" }))),
            PreDecision::Allow
        );
        // a call with no target-bearing argument is allowed
        assert_eq!(
            p.check(&call("add_finding", json!({ "detail": "note", "severity": "low" }))),
            PreDecision::Allow
        );
    }

    #[test]
    fn policy_out_of_scope_arg_denies() {
        let p = ScopePolicy::new(Scope::parse(r#"{"targets":["10.0.0.0/24"]}"#));
        match p.check(&call("http_probe", json!({ "url": "https://8.8.8.8/x" }))) {
            PreDecision::Deny(reason) => {
                assert!(reason.contains("out of RoE scope"), "{reason}");
                assert!(reason.contains("8.8.8.8"), "{reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
        // an out-of-scope `target` arg is denied too
        assert!(matches!(
            p.check(&call("port_scan", json!({ "target": "192.168.1.1" }))),
            PreDecision::Deny(_)
        ));
    }

    #[test]
    fn policy_denies_out_of_scope_shell_egress() {
        let p = ScopePolicy::new(Scope::parse(r#"{"targets":["10.0.0.0/24"]}"#));
        match p.check(&call("shell", json!({ "command": "curl https://exfil.evil.com/x" }))) {
            PreDecision::Deny(reason) => {
                assert!(reason.contains("egress blocked"), "{reason}");
                assert!(reason.contains("exfil.evil.com"), "{reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
        // the `cmd` alias is scanned as well
        assert!(matches!(
            p.check(&call("bash", json!({ "cmd": "wget http://8.8.8.8/x" }))),
            PreDecision::Deny(_)
        ));
    }
}
