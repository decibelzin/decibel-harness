//! GraphQL introspection planner: parse a `__schema` introspection response into
//! IDOR candidates (object-fetch fields keyed by an id argument) + baseline
//! queries to kick off manual testing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdorCandidate {
    pub field: String,
    pub arg: String,
    pub arg_type: String,
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlPlan {
    pub query_type: String,
    pub query_fields: Vec<String>,
    pub mutations: Vec<String>,
    pub idor_candidates: Vec<IdorCandidate>,
    pub baseline_queries: Vec<String>,
}

/// Unwrap a possibly-wrapped GraphQL type (`NON_NULL`/`LIST` → `ofType`) to its
/// underlying named type.
fn type_name(t: &Value) -> Option<String> {
    if let Some(name) = t.get("name").and_then(Value::as_str) {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    t.get("ofType").and_then(|inner| type_name(inner))
}

/// An argument is an object-identity key if it is named like an id, or typed
/// `ID`/`Int` — the classic IDOR surface.
fn is_id_arg(name: &str, ty: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "id" || n.ends_with("id") || ty == "ID" || (name == "id" && ty == "Int")
}

/// Find the named type object in the schema's `types` array.
fn find_type<'a>(types: &'a [Value], name: &str) -> Option<&'a Value> {
    types.iter().find(|t| t.get("name").and_then(Value::as_str) == Some(name))
}

fn field_names(ty: &Value) -> Vec<String> {
    ty.get("fields")
        .and_then(Value::as_array)
        .map(|fs| fs.iter().filter_map(|f| f.get("name").and_then(Value::as_str).map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Plan from an introspection response (accepts `{data:{__schema}}` or a bare
/// `{__schema}`).
pub fn plan(introspection_json: &str) -> Result<GraphqlPlan, String> {
    let root: Value = serde_json::from_str(introspection_json).map_err(|e| format!("introspection json: {e}"))?;
    let schema = root.get("data").and_then(|d| d.get("__schema")).or_else(|| root.get("__schema")).ok_or("no __schema in introspection response")?;

    let types = schema.get("types").and_then(Value::as_array).cloned().unwrap_or_default();
    let query_type = schema.get("queryType").and_then(|q| q.get("name")).and_then(Value::as_str).unwrap_or("Query").to_string();
    let mutation_type = schema.get("mutationType").and_then(|m| m.get("name")).and_then(Value::as_str).map(str::to_string);

    let query_obj = find_type(&types, &query_type);
    let query_fields = query_obj.map(field_names).unwrap_or_default();
    let mutations = mutation_type.as_deref().and_then(|m| find_type(&types, m)).map(field_names).unwrap_or_default();

    let mut idor_candidates = Vec::new();
    if let Some(qo) = query_obj {
        if let Some(fields) = qo.get("fields").and_then(Value::as_array) {
            for f in fields {
                let fname = match f.get("name").and_then(Value::as_str) {
                    Some(n) => n,
                    None => continue,
                };
                if let Some(args) = f.get("args").and_then(Value::as_array) {
                    for a in args {
                        let aname = a.get("name").and_then(Value::as_str).unwrap_or("");
                        let atype = a.get("type").and_then(type_name).unwrap_or_default();
                        if is_id_arg(aname, &atype) {
                            idor_candidates.push(IdorCandidate {
                                field: fname.to_string(),
                                arg: aname.to_string(),
                                arg_type: atype.clone(),
                                query: format!("query {{ {fname}({aname}: 1) {{ __typename }} }}"),
                            });
                        }
                    }
                }
            }
        }
    }

    let mut baseline_queries = vec!["query { __typename }".to_string()];
    for f in query_fields.iter().take(3) {
        baseline_queries.push(format!("query {{ {f} {{ __typename }} }}"));
    }

    Ok(GraphqlPlan { query_type, query_fields, mutations, idor_candidates, baseline_queries })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTROSPECTION: &str = r#"{
      "data": { "__schema": {
        "queryType": { "name": "Query" },
        "mutationType": { "name": "Mutation" },
        "types": [
          { "name": "Query", "kind": "OBJECT", "fields": [
            { "name": "user", "args": [ { "name": "id", "type": { "kind": "NON_NULL", "ofType": { "kind": "SCALAR", "name": "ID" } } } ] },
            { "name": "invoice", "args": [ { "name": "invoiceId", "type": { "kind": "SCALAR", "name": "Int" } } ] },
            { "name": "me", "args": [] }
          ] },
          { "name": "Mutation", "kind": "OBJECT", "fields": [
            { "name": "deleteUser", "args": [ { "name": "id", "type": { "name": "ID" } } ] }
          ] }
        ]
      } }
    }"#;

    #[test]
    fn plans_idor_candidates_from_id_args() {
        let p = plan(INTROSPECTION).unwrap();
        assert_eq!(p.query_type, "Query");
        assert!(p.query_fields.contains(&"user".to_string()));
        assert!(p.mutations.contains(&"deleteUser".to_string()));

        // user(id: ID!) and invoice(invoiceId: Int) are IDOR candidates; me() is not.
        assert_eq!(p.idor_candidates.len(), 2);
        let user = p.idor_candidates.iter().find(|c| c.field == "user").unwrap();
        assert_eq!(user.arg, "id");
        assert_eq!(user.arg_type, "ID");
        assert!(user.query.contains("user(id: 1)"));
        assert!(p.idor_candidates.iter().any(|c| c.field == "invoice" && c.arg == "invoiceId"));
    }

    #[test]
    fn accepts_bare_schema_and_emits_baseline_queries() {
        let bare = r#"{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query","fields":[{"name":"ping","args":[]}]}]}}"#;
        let p = plan(bare).unwrap();
        assert!(p.baseline_queries.contains(&"query { __typename }".to_string()));
        assert!(p.baseline_queries.iter().any(|q| q.contains("ping")));
        assert!(p.idor_candidates.is_empty());
    }

    #[test]
    fn errors_without_a_schema() {
        assert!(plan(r#"{"data":{}}"#).is_err());
    }
}
