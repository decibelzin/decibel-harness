//! OAuth 2.0 / OIDC callback audit — static analysis of the authorization
//! request + callback URLs for the well-known misconfigurations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::web::{entropy_bits, Finding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAudit {
    pub findings: Vec<Finding>,
}

/// Parse the query string of a URL into a map (last value wins). Values are left
/// percent-encoded — we only inspect presence/shape, not decode payloads.
fn query_params(url: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(k.to_string(), v.to_string());
    }
    out
}

/// Audit an OAuth/OIDC flow from its callback URL (and, when available, the
/// initial authorization-request URL). `public_client` = an SPA/native client
/// with no client secret, where PKCE is mandatory.
pub fn audit(callback_url: &str, initial_request_url: Option<&str>, public_client: bool) -> OAuthAudit {
    let cb = query_params(callback_url);
    let init = initial_request_url.map(query_params).unwrap_or_default();
    let mut findings = Vec::new();

    // CSRF: an authorization-code callback must carry a state parameter.
    if cb.contains_key("code") {
        match cb.get("state") {
            None => findings.push(Finding::new("high", "missing_state", "Callback returns `code` with no `state` — the flow is open to CSRF / login-CSRF.")),
            Some(state) if entropy_bits(state) < 48.0 => {
                findings.push(Finding::new("medium", "predictable_state", format!("`state` has only ~{:.0} bits of entropy — must be unguessable to stop CSRF.", entropy_bits(state))))
            }
            _ => {}
        }
    }
    if let Some(err) = cb.get("error") {
        findings.push(Finding::new("info", "callback_error", format!("Callback carried an error `{err}` — inspect the failure path.")));
    }

    // Implicit flow: tokens in the URL fragment/response are deprecated & leaky.
    if let Some(rt) = init.get("response_type") {
        if rt.contains("token") {
            findings.push(Finding::new("high", "implicit_flow", "`response_type=token` (implicit flow) leaks the access token in the URL — use authorization code + PKCE."));
        }
    }

    // PKCE: mandatory for public clients.
    if public_client && initial_request_url.is_some() && !init.contains_key("code_challenge") {
        findings.push(Finding::new("high", "no_pkce", "Public client with no `code_challenge` — PKCE is required to stop authorization-code interception."));
    }

    // Redirect URI transport.
    if let Some(ru) = init.get("redirect_uri") {
        if ru.starts_with("http%3A") || ru.starts_with("http:") {
            findings.push(Finding::new("medium", "insecure_redirect_uri", "`redirect_uri` uses plaintext http:// — the code/token can be intercepted."));
        }
    }

    // Scope over-request.
    if let Some(scope) = init.get("scope") {
        let count = scope.split(['+', ' ', ',']).filter(|s| !s.is_empty()).count();
        if scope.contains('*') || count > 5 {
            findings.push(Finding::new("info", "scope_broad", format!("Authorization requests {count} scopes — check for over-privileged consent.")));
        }
    }

    OAuthAudit { findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_on_code_callback_is_high() {
        let a = audit("https://app/cb?code=abc123", None, false);
        assert!(a.findings.iter().any(|f| f.id == "missing_state" && f.severity == "high"));
    }

    #[test]
    fn predictable_state_is_flagged() {
        let a = audit("https://app/cb?code=abc&state=1", None, false);
        assert!(a.findings.iter().any(|f| f.id == "predictable_state"));
    }

    #[test]
    fn strong_state_passes() {
        let a = audit("https://app/cb?code=abc&state=Zk9dP2wQ7vX1mB4nR6tY8uH0jC3aS5dF", None, false);
        assert!(!a.findings.iter().any(|f| f.id == "missing_state" || f.id == "predictable_state"));
    }

    #[test]
    fn implicit_flow_and_missing_pkce_flagged_from_initial_request() {
        let a = audit(
            "https://app/cb?code=abc&state=Zk9dP2wQ7vX1mB4nR6tY8uH0jC3aS5dF",
            Some("https://idp/authorize?response_type=token&scope=openid+profile+email+admin+billing+users&redirect_uri=http://app/cb"),
            true,
        );
        assert!(a.findings.iter().any(|f| f.id == "implicit_flow"));
        assert!(a.findings.iter().any(|f| f.id == "no_pkce"));
        assert!(a.findings.iter().any(|f| f.id == "insecure_redirect_uri"));
        assert!(a.findings.iter().any(|f| f.id == "scope_broad"));
    }

    #[test]
    fn public_client_with_pkce_has_no_pkce_finding() {
        let a = audit(
            "https://app/cb?code=abc&state=Zk9dP2wQ7vX1mB4nR6tY8uH0jC3aS5dF",
            Some("https://idp/authorize?response_type=code&code_challenge=xyz&redirect_uri=https://app/cb"),
            true,
        );
        assert!(!a.findings.iter().any(|f| f.id == "no_pkce"));
        assert!(!a.findings.iter().any(|f| f.id == "insecure_redirect_uri"));
    }
}
