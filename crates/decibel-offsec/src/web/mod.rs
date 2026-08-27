//! Pure, offline web/auth analyzers — ported from Decepticon's `tools/web`
//! bucket (crate `decepticon-web`, Apache-2.0) into Decibel with **no executor
//! dependency**: every capability is in-process, deterministic, and unit-tested.
//!
//! Six capabilities, surfaced as model-facing tools in [`tools`]: `jwt_parse` /
//! `jwt_forge` / `jwt_crack`, `cookie_audit`, `oauth_audit`, `graphql_plan`.
//! Each analyzer returns a serde struct so the tool layer hands it straight to
//! the model (and, later, the knowledge graph) as a canonical value.

pub mod cookie;
pub mod graphql;
pub mod jwt;
pub mod oauth;
pub mod tools;

use base64::Engine;
use serde::{Deserialize, Serialize};

/// One analyzer finding. `severity` uses the KG scale (info|low|medium|high|critical).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub id: String,
    pub detail: String,
}

impl Finding {
    pub fn new(severity: &str, id: &str, detail: impl Into<String>) -> Self {
        Finding { severity: severity.into(), id: id.into(), detail: detail.into() }
    }
}

/// Decode base64url (tolerant of missing padding — JWT segments carry none).
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| format!("base64url decode: {e}"))
}

/// Encode bytes as base64url without padding (JWT segment form).
pub(crate) fn b64url_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Total Shannon entropy of a string in bits (per-char entropy × length) — a
/// cheap predictability signal for session tokens / OAuth state.
pub(crate) fn entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    let len = s.chars().count() as f64;
    let per_char: f64 = -counts
        .values()
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>();
    per_char * len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip_without_padding() {
        let bytes = b"{\"alg\":\"none\"}";
        let enc = b64url_encode(bytes);
        assert!(!enc.contains('='), "url-safe no-pad");
        assert_eq!(b64url_decode(&enc).unwrap(), bytes);
    }

    #[test]
    fn entropy_grows_with_variety() {
        assert_eq!(entropy_bits(""), 0.0);
        assert_eq!(entropy_bits("aaaa"), 0.0); // one symbol → 0 entropy
        assert!(entropy_bits("abcd") > entropy_bits("aaba"));
    }
}
