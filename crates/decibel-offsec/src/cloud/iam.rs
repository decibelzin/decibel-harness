//! AWS IAM policy audit: wildcard grants + the canonical privilege-escalation
//! primitives (Rhino Security Labs' list).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloud::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamAudit {
    pub statements: usize,
    pub findings: Vec<Finding>,
}

/// IAM actions that grant a path to privilege escalation on their own or in
/// small combos (Rhino Security Labs canonical set, trimmed to the high-signal
/// primitives).
const PRIVESC_ACTIONS: &[&str] = &[
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:PassRole",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
    "ec2:RunInstances",
];

fn as_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => vec![],
    }
}

/// Audit an IAM policy document (`{Statement: {...}|[...]}`).
pub fn audit(policy_json: &str) -> Result<IamAudit, String> {
    let doc: Value = serde_json::from_str(policy_json).map_err(|e| format!("policy json: {e}"))?;
    let statements = match &doc["Statement"] {
        Value::Array(a) => a.clone(),
        obj @ Value::Object(_) => vec![obj.clone()],
        _ => return Err("policy has no Statement".into()),
    };

    let mut findings = Vec::new();
    for st in &statements {
        if st["Effect"].as_str() != Some("Allow") {
            continue;
        }
        let actions = as_list(&st["Action"]);
        let resources = as_list(&st["Resource"]);
        let res_wild = resources.iter().any(|r| r == "*");

        for a in &actions {
            if a == "*" {
                findings.push(Finding::new("critical", "admin_wildcard", "Action `*` on an Allow statement grants full administrator access."));
                continue;
            }
            if a.ends_with(":*") {
                let sev = if res_wild { "high" } else { "medium" };
                findings.push(Finding::new(sev, "service_wildcard", format!("Wildcard action `{a}` grants every action in that service{}.", if res_wild { " on all resources" } else { "" })));
            }
            if PRIVESC_ACTIONS.iter().any(|p| p.eq_ignore_ascii_case(a)) {
                findings.push(Finding::new("high", "privesc_primitive", format!("`{a}` is a known IAM privilege-escalation primitive (Rhino Security Labs).")));
            }
        }
        if !actions.is_empty() && res_wild && !actions.iter().any(|a| a == "*") {
            findings.push(Finding::new("low", "resource_wildcard", "Statement grants its actions on `Resource: *` — scope to specific ARNs."));
        }
        if st.get("NotAction").is_some() {
            findings.push(Finding::new("medium", "not_action", "`NotAction` with Allow is an allow-all-except pattern — easy to over-grant."));
        }
    }

    Ok(IamAudit { statements: statements.len(), findings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_full_admin_wildcard() {
        let a = audit(r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#).unwrap();
        assert_eq!(a.statements, 1);
        assert!(a.findings.iter().any(|f| f.id == "admin_wildcard" && f.severity == "critical"));
    }

    #[test]
    fn flags_privesc_and_service_wildcard() {
        let a = audit(r#"{"Statement":[
            {"Effect":"Allow","Action":["iam:PassRole","s3:*"],"Resource":"*"},
            {"Effect":"Deny","Action":"*","Resource":"*"}
        ]}"#).unwrap();
        assert!(a.findings.iter().any(|f| f.id == "privesc_primitive" && f.detail.contains("PassRole")));
        assert!(a.findings.iter().any(|f| f.id == "service_wildcard" && f.detail.contains("s3:*")));
        // The Deny statement is ignored (no admin_wildcard from it).
        assert!(!a.findings.iter().any(|f| f.id == "admin_wildcard"));
    }

    #[test]
    fn clean_scoped_policy_is_quiet() {
        let a = audit(r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}"#).unwrap();
        assert!(a.findings.is_empty(), "{:?}", a.findings);
    }

    #[test]
    fn errors_on_missing_statement() {
        assert!(audit(r#"{"Version":"2012-10-17"}"#).is_err());
    }
}
