//! Cookie / session-token audit: transport flags, framework fingerprint,
//! entropy, and JWT-in-cookie detection.

use serde::{Deserialize, Serialize};

use crate::web::{entropy_bits, Finding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieAudit {
    pub name: String,
    pub framework: Option<String>,
    pub entropy_bits: f64,
    pub looks_like_jwt: bool,
    pub findings: Vec<Finding>,
}

/// Fingerprint the session framework from a well-known cookie name.
fn fingerprint(name: &str) -> Option<&'static str> {
    match name {
        "PHPSESSID" => Some("PHP"),
        "JSESSIONID" => Some("Java/JSP"),
        "ASP.NET_SessionId" | "ASPSESSIONID" => Some("ASP.NET"),
        "connect.sid" => Some("Express/Node"),
        "laravel_session" | "XSRF-TOKEN" => Some("Laravel"),
        "sessionid" | "csrftoken" => Some("Django"),
        "_rails_session" => Some("Rails"),
        "CFID" | "CFTOKEN" => Some("ColdFusion"),
        _ => None,
    }
}

/// A value is a plausible JWT if it has three base64url segments whose header
/// decodes to a JSON object carrying `alg`.
fn looks_like_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    crate::web::b64url_decode(parts[0])
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .map(|v| v.get("alg").is_some())
        .unwrap_or(false)
}

/// Audit one cookie. Transport flags come from the Set-Cookie attributes the
/// caller observed (`secure`, `http_only`, `same_site`).
pub fn audit(name: &str, value: &str, secure: bool, http_only: bool, same_site: Option<&str>) -> CookieAudit {
    let mut findings = Vec::new();

    if !secure {
        findings.push(Finding::new("medium", "no_secure", "Missing `Secure`: the cookie is sent over plaintext HTTP and can be sniffed."));
    }
    if !http_only {
        findings.push(Finding::new("medium", "no_httponly", "Missing `HttpOnly`: the cookie is readable from JavaScript (XSS → session theft)."));
    }
    match same_site.map(|s| s.to_ascii_lowercase()) {
        None => findings.push(Finding::new("low", "no_samesite", "No `SameSite` attribute: defaults vary; set Lax/Strict to blunt CSRF.")),
        Some(s) if s == "none" && !secure => {
            findings.push(Finding::new("high", "samesite_none_insecure", "`SameSite=None` without `Secure` is rejected by browsers and exposes the cookie cross-site."))
        }
        _ => {}
    }

    let bits = entropy_bits(value);
    // A session identifier under ~48 bits of entropy is guessable/brute-forceable.
    let name_l = name.to_ascii_lowercase();
    let session_like = name_l.contains("sess") || name_l.contains("sid") || name_l.contains("token") || name_l.contains("auth");
    if session_like && !value.is_empty() && bits < 48.0 {
        findings.push(Finding::new("medium", "low_entropy", format!("Session token has only ~{bits:.0} bits of entropy — may be predictable/brute-forceable.")));
    }

    let jwt = looks_like_jwt(value);
    if jwt {
        findings.push(Finding::new("info", "jwt_cookie", "The cookie value is a JWT — analyze it with jwt_parse (and try jwt_crack if HS*)."));
    }

    CookieAudit {
        name: name.to_string(),
        framework: fingerprint(name).map(str::to_string),
        entropy_bits: bits,
        looks_like_jwt: jwt,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_missing_transport_protections() {
        let a = audit("PHPSESSID", "abc123", false, false, None);
        assert_eq!(a.framework.as_deref(), Some("PHP"));
        assert!(a.findings.iter().any(|f| f.id == "no_secure"));
        assert!(a.findings.iter().any(|f| f.id == "no_httponly"));
        assert!(a.findings.iter().any(|f| f.id == "no_samesite"));
    }

    #[test]
    fn clean_cookie_has_no_transport_findings() {
        let a = audit("sessionid", "x9Q2v8Kd1mZ0pL7wB3nR6tY4uH5jC1aS2dF3gH4jK5l", true, true, Some("Strict"));
        assert!(!a.findings.iter().any(|f| f.id == "no_secure"));
        assert!(!a.findings.iter().any(|f| f.id == "no_httponly"));
        assert!(!a.findings.iter().any(|f| f.id == "no_samesite"));
        assert_eq!(a.framework.as_deref(), Some("Django"));
    }

    #[test]
    fn samesite_none_without_secure_is_high() {
        let a = audit("id", "v", false, true, Some("None"));
        assert!(a.findings.iter().any(|f| f.id == "samesite_none_insecure" && f.severity == "high"));
    }

    #[test]
    fn detects_a_jwt_valued_cookie() {
        let jwt = format!(
            "{}.{}.sig",
            crate::web::b64url_encode(br#"{"alg":"HS256"}"#),
            crate::web::b64url_encode(br#"{"u":1}"#)
        );
        let a = audit("auth", &jwt, true, true, Some("Lax"));
        assert!(a.looks_like_jwt);
        assert!(a.findings.iter().any(|f| f.id == "jwt_cookie"));
    }

    #[test]
    fn low_entropy_session_token_is_flagged() {
        let a = audit("sessionid", "12345", true, true, Some("Lax"));
        assert!(a.findings.iter().any(|f| f.id == "low_entropy"));
    }
}
