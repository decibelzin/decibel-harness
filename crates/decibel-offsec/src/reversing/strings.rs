//! Extract printable strings (ASCII + UTF-16LE) and classify them into the
//! triage categories (url/ip/email/path/crypto/version/secret/import/other).

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringHits {
    pub total: usize,
    /// category -> the matched strings (deduped, sorted).
    pub groups: BTreeMap<String, Vec<String>>,
}

fn printable(byte: u8) -> bool {
    (0x20..=0x7e).contains(&byte)
}

/// Extract ASCII runs of length >= `min_len` from bytes.
fn ascii_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in bytes {
        if printable(b) {
            cur.push(b as char);
        } else {
            if cur.len() >= min_len {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

/// Extract UTF-16LE runs (printable ASCII code points stored as `xx 00`).
fn utf16le_runs(bytes: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if printable(bytes[i]) && bytes[i + 1] == 0 {
            cur.push(bytes[i] as char);
            i += 2;
        } else {
            if cur.len() >= min_len {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
            i += 1;
        }
    }
    if cur.len() >= min_len {
        out.push(cur);
    }
    out
}

fn classify(s: &str) -> &'static str {
    let url = Regex::new(r"^[a-z][a-z0-9+.\-]*://").unwrap();
    let ip = Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let email = Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap();
    let version = Regex::new(r"\d+\.\d+\.\d+").unwrap();
    let lower = s.to_lowercase();

    if url.is_match(&lower) {
        "url"
    } else if email.is_match(s) {
        "email"
    } else if ip.is_match(s) {
        "ip"
    } else if s.starts_with('/') || Regex::new(r"^[A-Za-z]:\\").unwrap().is_match(s) || s.contains("/etc/") || s.contains("\\Windows\\") {
        "path"
    } else if ["aes", "rsa", "sha256", "sha1", "md5", "hmac", "-----begin", "private key", "encrypt"].iter().any(|k| lower.contains(k)) {
        "crypto"
    } else if ["password", "passwd", "secret", "api_key", "apikey", "token", "credential"].iter().any(|k| lower.contains(k)) {
        "secret"
    } else if version.is_match(s) {
        "version"
    } else if ["system", "exec", "popen", "loadlibrary", "getprocaddress", "dlopen", "socket", "winexec", "shellexecute"].iter().any(|k| lower.contains(k)) {
        "import"
    } else {
        "other"
    }
}

/// Extract + classify strings. `category_filter` (if set) keeps only that group.
pub fn extract(bytes: &[u8], min_len: usize, category_filter: Option<&str>) -> StringHits {
    let min = min_len.max(1);
    let mut all = ascii_runs(bytes, min);
    all.extend(utf16le_runs(bytes, min));

    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total = 0;
    for s in all {
        let cat = classify(&s);
        if let Some(f) = category_filter {
            if !f.eq_ignore_ascii_case(cat) {
                continue;
            }
        }
        let bucket = groups.entry(cat.to_string()).or_default();
        if !bucket.contains(&s) {
            bucket.push(s);
            total += 1;
        }
    }
    for v in groups.values_mut() {
        v.sort();
    }
    StringHits { total, groups }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_classifies() {
        let blob = b"\x00\x01https://evil.example/c2\x00admin@corp.com\x00/etc/passwd\x00password=hunter2\x00v1.2.3\x00\x02";
        let h = extract(blob, 4, None);
        assert_eq!(h.groups["url"], vec!["https://evil.example/c2"]);
        assert_eq!(h.groups["email"], vec!["admin@corp.com"]);
        assert_eq!(h.groups["path"], vec!["/etc/passwd"]);
        assert!(h.groups["secret"].iter().any(|s| s.contains("password")));
        assert_eq!(h.groups["version"], vec!["v1.2.3"]);
    }

    #[test]
    fn category_filter_restricts_output() {
        let blob = b"https://a.b/x\x00just some text here\x00";
        let h = extract(blob, 4, Some("url"));
        assert_eq!(h.groups.len(), 1);
        assert!(h.groups.contains_key("url"));
    }

    #[test]
    fn reads_utf16le_strings() {
        // "HELLO" as UTF-16LE.
        let blob = b"H\x00E\x00L\x00L\x00O\x00\xff\xff";
        let h = extract(blob, 4, None);
        assert!(h.groups.values().flatten().any(|s| s == "HELLO"));
    }

    #[test]
    fn min_length_is_respected() {
        let h = extract(b"ab\x00abcdef\x00", 4, None);
        // "ab" is dropped; "abcdef" kept.
        assert!(h.groups.values().flatten().any(|s| s == "abcdef"));
        assert!(!h.groups.values().flatten().any(|s| s == "ab"));
    }
}
