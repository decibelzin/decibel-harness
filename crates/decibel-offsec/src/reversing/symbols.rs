//! Classify symbol names (from `nm`/`objdump`/`readelf` output) into risk
//! buckets — the analyst's "where do I look first" map.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolReport {
    pub total: usize,
    /// risk bucket -> symbols that landed in it (deduped, sorted).
    pub buckets: BTreeMap<String, Vec<String>>,
}

/// (bucket, substrings that place a symbol in it). Checked in order; first match wins.
const RULES: &[(&str, &[&str])] = &[
    ("command_exec", &["system", "popen", "execve", "execl", "execvp", "winexec", "shellexecute", "createprocess"]),
    ("unsafe_memory", &["strcpy", "strcat", "sprintf", "gets", "memcpy", "alloca", "realpath", "scanf"]),
    ("format_string", &["printf", "fprintf", "snprintf", "vprintf", "syslog"]),
    ("crypto", &["aes", "des", "rsa", "sha", "md5", "hmac", "evp_", "crypt", "rc4"]),
    ("network", &["socket", "connect", "bind", "listen", "recv", "send", "gethostby", "inet_", "wsastartup", "curl_"]),
    ("privilege", &["setuid", "seteuid", "setgid", "adjusttokenprivileges", "impersonate"]),
    ("dynamic_load", &["dlopen", "dlsym", "loadlibrary", "getprocaddress"]),
    ("anti_debug", &["ptrace", "isdebuggerpresent", "checkremotedebugger"]),
];

fn bucket_for(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    for (bucket, keys) in RULES {
        if keys.iter().any(|k| n.contains(k)) {
            return Some(bucket);
        }
    }
    None
}

/// Classify whitespace/newline-separated symbol names. Tolerates `nm` lines like
/// `0000 T symbol` — the last token on each line is taken as the name.
pub fn report(symbols: &str) -> SymbolReport {
    let mut buckets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0;
    for line in symbols.lines() {
        let name = line.split_whitespace().last().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if let Some(b) = bucket_for(name) {
            let v = buckets.entry(b.to_string()).or_default();
            if !v.contains(&name.to_string()) {
                v.push(name.to_string());
                total += 1;
            }
        }
    }
    for v in buckets.values_mut() {
        v.sort();
    }
    SymbolReport { total, buckets }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_nm_style_symbols_into_buckets() {
        let syms = "\
0000000000001139 T main
                 U system
                 U strcpy
                 U printf
                 U SHA256_Init
                 U connect
                 U dlopen
                 U ptrace
                 U some_harmless_helper";
        let r = report(syms);
        assert_eq!(r.buckets["command_exec"], vec!["system"]);
        assert_eq!(r.buckets["unsafe_memory"], vec!["strcpy"]);
        assert!(r.buckets["crypto"].iter().any(|s| s == "SHA256_Init"));
        assert!(r.buckets["network"].iter().any(|s| s == "connect"));
        assert!(r.buckets.contains_key("dynamic_load"));
        assert!(r.buckets.contains_key("anti_debug"));
        // main / helper are not risky → not counted.
        assert!(!r.buckets.values().flatten().any(|s| s == "main"));
    }

    #[test]
    fn dedupes_repeated_symbols() {
        let r = report("U system\nU system\nU system");
        assert_eq!(r.buckets["command_exec"], vec!["system"]);
        assert_eq!(r.total, 1);
    }

    #[test]
    fn empty_input_is_empty() {
        assert_eq!(report("").total, 0);
    }
}
