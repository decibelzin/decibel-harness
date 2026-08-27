//! Model-facing [`Tool`] wrappers over the pure web/auth analyzers. Each tool
//! runs an in-process analyzer (no network, no shell) and returns its serde
//! struct as the canonical value, so a UI card and a future Code Mode read the
//! same fact the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_bool, arg_str, arg_str_opt};
use crate::web::{cookie, graphql, jwt, oauth};

/// Read an argument that may arrive as a JSON string OR an inline JSON value,
/// returning its text form — so a model can pass either `"{...}"` or `{...}`.
fn arg_json_text(args: &Value, key: &str) -> Option<String> {
    match args.get(key) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Null) | None => None,
        Some(v) => Some(v.to_string()),
    }
}

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Render a `findings` array (severity/id/detail) into a text summary block.
fn render_findings(header: &str, value: &Value) -> String {
    let empty = Vec::new();
    let findings = value.get("findings").and_then(Value::as_array).unwrap_or(&empty);
    if findings.is_empty() {
        return format!("{header}\n(no findings)");
    }
    let mut out = format!("{header} — {} finding(s)\n", findings.len());
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let id = f.get("id").and_then(Value::as_str).unwrap_or("");
        let detail = f.get("detail").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  [{sev}] {id}: {detail}\n"));
    }
    out
}

/// Decode a JWT and flag its weaknesses (offline).
pub struct JwtParseTool;

#[async_trait]
impl Tool for JwtParseTool {
    fn name(&self) -> &str {
        "jwt_parse"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "jwt_parse".into(),
            description: "Decode a JWT's header and claims and flag classic weaknesses (alg=none, \
                missing exp, jku/x5u/kid header injection, HS* crackability). Offline — does NOT \
                verify the signature. Use before jwt_forge/jwt_crack."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "token": { "type": "string", "description": "The JWT (header.claims[.signature])." }
                },
                "required": ["token"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let token = arg_str(&arguments, "token")?;
        let parsed = jwt::parse(&token).map_err(ToolError::execution)?;
        to_value(parsed)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let alg = value.get("alg").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(render_findings(&format!("jwt_parse (alg={alg})"), value))]
    }
}

/// Forge a JWT with arbitrary claims (none/HS256/HS384/HS512).
pub struct JwtForgeTool;

#[async_trait]
impl Tool for JwtForgeTool {
    fn name(&self) -> &str {
        "jwt_forge"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "jwt_forge".into(),
            description: "Forge a JWT with arbitrary claims and algorithm. `alg` in \
                {none, HS256, HS384, HS512}; `secret` signs HS* (ignored for none). Optional \
                `header` merges over the default header so you can inject kid/jku/x5u. \
                Authorized testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "claims": { "description": "Claims as a JSON object (or a JSON string)." },
                    "alg": { "type": "string", "description": "none|HS256|HS384|HS512 (default HS256)." },
                    "secret": { "type": "string", "description": "HMAC secret for HS* (default empty)." },
                    "header": { "description": "Extra header fields to merge (JSON object or string), e.g. {\"kid\":\"...\"}." }
                },
                "required": ["claims"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let claims = arg_json_text(&arguments, "claims")
            .ok_or_else(|| ToolError::invalid_args("missing required `claims` (JSON object or string)"))?;
        let alg = arg_str_opt(&arguments, "alg").unwrap_or_else(|| "HS256".into());
        let secret = arg_str_opt(&arguments, "secret").unwrap_or_default();
        let header = arg_json_text(&arguments, "header");
        let token = jwt::forge(&claims, &alg, &secret, header.as_deref()).map_err(ToolError::execution)?;
        Ok(json!({ "token": token, "alg": alg }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let token = value.get("token").and_then(Value::as_str).unwrap_or("");
        let alg = value.get("alg").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("jwt_forge (alg={alg})\n{token}"))]
    }
}

/// Dictionary-crack an HS* JWT signing secret (offline).
pub struct JwtCrackTool;

#[async_trait]
impl Tool for JwtCrackTool {
    fn name(&self) -> &str {
        "jwt_crack"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "jwt_crack".into(),
            description: "Dictionary-attack an HS* JWT's HMAC signing secret. Offline. Empty/omitted \
                `wordlist` uses a small bundled weak-secret list. Recovers the secret so tokens can \
                be forged. Authorized testing only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "token": { "type": "string", "description": "A full 3-part HS* JWT." },
                    "wordlist": { "type": "array", "items": { "type": "string" }, "description": "Candidate secrets (optional)." }
                },
                "required": ["token"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let token = arg_str(&arguments, "token")?;
        let wordlist: Vec<String> = arguments
            .get("wordlist")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let result = jwt::crack(&token, &wordlist).map_err(ToolError::execution)?;
        to_value(result)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let cracked = value.get("cracked").and_then(Value::as_bool).unwrap_or(false);
        let tried = value.get("tried").and_then(Value::as_u64).unwrap_or(0);
        let text = if cracked {
            let secret = value.get("secret").and_then(Value::as_str).unwrap_or("");
            format!("jwt_crack: CRACKED after {tried} candidate(s) — secret = {secret:?}")
        } else {
            format!("jwt_crack: not cracked ({tried} candidate(s) tried)")
        };
        vec![ContentBlock::text(text)]
    }
}

/// Audit a cookie's transport flags, framework, entropy, and JWT-ness (offline).
pub struct CookieAuditTool;

#[async_trait]
impl Tool for CookieAuditTool {
    fn name(&self) -> &str {
        "cookie_audit"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "cookie_audit".into(),
            description: "Audit one cookie: fingerprint the framework from its name, score value \
                entropy, detect a JWT value, and flag weak transport flags (missing Secure/HttpOnly/\
                SameSite). Offline — pass the Set-Cookie attributes you observed."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Cookie name (e.g. PHPSESSID)." },
                    "value": { "type": "string", "description": "Cookie value." },
                    "secure": { "type": "boolean", "description": "Secure attribute present (default false)." },
                    "http_only": { "type": "boolean", "description": "HttpOnly attribute present (default false)." },
                    "same_site": { "type": "string", "description": "SameSite value (Strict|Lax|None), if any." }
                },
                "required": ["name"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let name = arg_str(&arguments, "name")?;
        let value = arg_str_opt(&arguments, "value").unwrap_or_default();
        let secure = arg_bool(&arguments, "secure", false);
        let http_only = arg_bool(&arguments, "http_only", false);
        let same_site = arg_str_opt(&arguments, "same_site");
        let audit = cookie::audit(&name, &value, secure, http_only, same_site.as_deref());
        to_value(audit)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let name = value.get("name").and_then(Value::as_str).unwrap_or("");
        let framework = value.get("framework").and_then(Value::as_str);
        let fw = framework.map(|f| format!(" [{f}]")).unwrap_or_default();
        vec![ContentBlock::text(render_findings(&format!("cookie_audit {name}{fw}"), value))]
    }
}

/// Audit an OAuth 2.0 / OIDC callback flow for the classic flaws (offline).
pub struct OAuthAuditTool;

#[async_trait]
impl Tool for OAuthAuditTool {
    fn name(&self) -> &str {
        "oauth_audit"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "oauth_audit".into(),
            description: "Audit an OAuth/OIDC flow from its callback URL (and optionally the initial \
                authorization-request URL) for missing/predictable state, implicit flow, missing PKCE \
                on a public client, insecure redirect_uri, and scope over-request. Offline URL analysis."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "callback_url": { "type": "string", "description": "The redirect/callback URL (with its query)." },
                    "initial_request_url": { "type": "string", "description": "The /authorize request URL, if known." },
                    "public_client": { "type": "boolean", "description": "SPA/native client with no secret — PKCE required (default false)." }
                },
                "required": ["callback_url"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let callback = arg_str(&arguments, "callback_url")?;
        let initial = arg_str_opt(&arguments, "initial_request_url");
        let public_client = arg_bool(&arguments, "public_client", false);
        let audit = oauth::audit(&callback, initial.as_deref(), public_client);
        to_value(audit)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(render_findings("oauth_audit", value))]
    }
}

/// Turn a GraphQL introspection response into IDOR candidates + baseline queries.
pub struct GraphqlPlanTool;

#[async_trait]
impl Tool for GraphqlPlanTool {
    fn name(&self) -> &str {
        "graphql_plan"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "graphql_plan".into(),
            description: "Parse a GraphQL `__schema` introspection response into IDOR candidates \
                (object-fetch fields keyed by an id argument) plus baseline queries to start manual \
                testing. Offline — accepts `{data:{__schema}}` or a bare `{__schema}`."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "introspection": { "description": "The introspection JSON (object or string)." }
                },
                "required": ["introspection"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let introspection = arg_json_text(&arguments, "introspection")
            .ok_or_else(|| ToolError::invalid_args("missing required `introspection` (the __schema JSON)"))?;
        let plan = graphql::plan(&introspection).map_err(ToolError::execution)?;
        to_value(plan)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let query_type = value.get("query_type").and_then(Value::as_str).unwrap_or("");
        let empty = Vec::new();
        let idor = value.get("idor_candidates").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = format!("graphql_plan (query type {query_type}) — {} IDOR candidate(s)\n", idor.len());
        for c in idor {
            let field = c.get("field").and_then(Value::as_str).unwrap_or("");
            let arg = c.get("arg").and_then(Value::as_str).unwrap_or("");
            let query = c.get("query").and_then(Value::as_str).unwrap_or("");
            out.push_str(&format!("  {field}({arg}): {query}\n"));
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;

    async fn run(tool: Arc<dyn Tool>, args: Value) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(
            decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args },
            &ExecCtx::new(),
        )
        .await
    }

    #[tokio::test]
    async fn jwt_forge_then_parse_and_crack_end_to_end() {
        // forge → token
        let forged = run(Arc::new(JwtForgeTool), json!({ "claims": { "role": "admin" }, "alg": "HS256", "secret": "changeme" })).await;
        assert!(!forged.is_error);
        let token = forged.value.unwrap()["token"].as_str().unwrap().to_string();

        // parse flags HS*
        let parsed = run(Arc::new(JwtParseTool), json!({ "token": token })).await;
        assert!(!parsed.is_error);
        let v = parsed.value.unwrap();
        assert_eq!(v["alg"], "HS256");

        // crack recovers the weak secret from the bundled list
        let cracked = run(Arc::new(JwtCrackTool), json!({ "token": token })).await;
        let cv = cracked.value.unwrap();
        assert_eq!(cv["cracked"], true);
        assert_eq!(cv["secret"], "changeme");
    }

    #[tokio::test]
    async fn cookie_and_oauth_and_graphql_produce_findings() {
        let cookie = run(Arc::new(CookieAuditTool), json!({ "name": "PHPSESSID", "value": "abc" })).await;
        assert_eq!(cookie.value.unwrap()["framework"], "PHP");

        let oauth = run(Arc::new(OAuthAuditTool), json!({ "callback_url": "https://app/cb?code=x" })).await;
        let ov = oauth.value.unwrap();
        assert!(ov["findings"].as_array().unwrap().iter().any(|f| f["id"] == "missing_state"));

        let intro = json!({ "__schema": { "queryType": { "name": "Query" }, "types": [
            { "name": "Query", "fields": [ { "name": "user", "args": [ { "name": "id", "type": { "name": "ID" } } ] } ] }
        ] } });
        let gql = run(Arc::new(GraphqlPlanTool), json!({ "introspection": intro })).await;
        let gv = gql.value.unwrap();
        assert_eq!(gv["idor_candidates"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let r = run(Arc::new(JwtParseTool), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
