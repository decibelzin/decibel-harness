//! The tool registry and its execution pipeline.
//!
//! `execute` runs one call through: unknown-tool check → pre-policy
//! (allow/deny) → the tool body → `render` → post-policy → a settled
//! [`ToolResult`]. Policy hooks are the extension points; with none registered
//! every visible call runs (Decibel ships no approval gate by default).

use std::collections::BTreeMap;
use std::sync::Arc;

use decibel_llm::ToolSchema;

use crate::error::ToolError;
use crate::tool::{ExecCtx, Tool, ToolCall, ToolResult};

/// A pre-execution policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreDecision {
    /// Let the call run.
    Allow,
    /// Reject the call with a reason (becomes an error result).
    Deny(String),
}

/// A synchronous pre-execution policy hook. All registered hooks run in order;
/// the first `Deny` wins and no hook can turn a denial back into an allow.
pub trait PrePolicy: Send + Sync {
    /// Inspect a pending call and allow or deny it.
    fn check(&self, call: &ToolCall) -> PreDecision;
}

/// A post-execution hook that may inspect or replace a settled result.
pub trait PostPolicy: Send + Sync {
    /// Inspect the result and optionally return a replacement.
    fn review(&self, call: &ToolCall, result: ToolResult) -> ToolResult;
}

/// The tool registry: named tools plus ordered policy hooks.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    pre: Vec<Arc<dyn PrePolicy>>,
    post: Vec<Arc<dyn PostPolicy>>,
}

impl ToolRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        ToolRegistry::default()
    }

    /// Register a tool. A duplicate name replaces the prior tool and returns it.
    pub fn register(&mut self, tool: Arc<dyn Tool>) -> Option<Arc<dyn Tool>> {
        self.tools.insert(tool.name().to_string(), tool)
    }

    /// Register a pre-execution policy hook.
    pub fn add_pre_policy(&mut self, policy: Arc<dyn PrePolicy>) {
        self.pre.push(policy);
    }

    /// Register a post-execution policy hook.
    pub fn add_post_policy(&mut self, policy: Arc<dyn PostPolicy>) {
        self.post.push(policy);
    }

    /// Look up a tool by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }

    /// Every visible tool's schema, in name order.
    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools.values().map(|tool| tool.schema()).collect()
    }

    /// The scheduling mode of a call: `true` when the tool classifies it
    /// concurrency-safe, else exclusive (the fail-closed default).
    pub fn is_concurrency_safe(&self, call: &ToolCall) -> bool {
        self.get(&call.name)
            .map(|tool| tool.is_concurrency_safe(&call.arguments))
            .unwrap_or(false)
    }

    /// Run one call through the complete pipeline. This never returns an `Err`:
    /// unknown tools, denials, invalid arguments, and body failures all settle
    /// as an error [`ToolResult`], mirroring how the loop records outcomes.
    pub async fn execute(&self, call: ToolCall, ctx: &ExecCtx) -> ToolResult {
        let Some(tool) = self.get(&call.name) else {
            return self.finish(
                &call,
                ToolResult::error(call.call_id.clone(), "UNKNOWN_TOOL", format!("unknown tool \"{}\"", call.name)),
            );
        };

        // Pre-policy: first Deny wins.
        for policy in &self.pre {
            if let PreDecision::Deny(reason) = policy.check(&call) {
                return self.finish(
                    &call,
                    ToolResult::error(call.call_id.clone(), "DENIED", reason),
                );
            }
        }

        if ctx.is_cancelled() {
            return self.finish(
                &call,
                ToolResult::error(call.call_id.clone(), "ABORTED_BEFORE_DISPATCH", "tool call aborted before dispatch"),
            );
        }

        let result = match tool.execute(call.arguments.clone(), ctx).await {
            Ok(value) => {
                let content = tool.render(&call.arguments, &value);
                ToolResult::success(call.call_id.clone(), value, content)
            }
            Err(err) => ToolResult::error(call.call_id.clone(), err.code(), err),
        };

        // A cancellation that landed during the body supersedes a success.
        let result = if ctx.is_cancelled() && !result.is_error {
            ToolResult::error(call.call_id.clone(), ToolError::Aborted.code(), ToolError::Aborted)
        } else {
            result
        };

        self.finish(&call, result)
    }

    /// Apply post-policy hooks in order to a settled result.
    fn finish(&self, call: &ToolCall, mut result: ToolResult) -> ToolResult {
        for policy in &self.post {
            result = policy.review(call, result);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use decibel_llm::{CallId, ContentBlock};
    use serde_json::{json, Value};

    /// A tool that echoes its `text` argument back as the canonical value.
    struct Echo;

    #[async_trait]
    impl Tool for Echo {
        fn name(&self) -> &str {
            "echo"
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema {
                name: "echo".into(),
                description: "echo the text back".into(),
                parameters: json!({
                    "type": "object",
                    "properties": { "text": { "type": "string" } },
                    "required": ["text"],
                }),
            }
        }
        fn is_concurrency_safe(&self, _arguments: &Value) -> bool {
            true
        }
        async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
            let text = arguments
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| ToolError::invalid_args("missing string `text`"))?;
            Ok(json!({ "echoed": text }))
        }
        fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
            let echoed = value.get("echoed").and_then(Value::as_str).unwrap_or("");
            vec![ContentBlock::text(echoed.to_string())]
        }
    }

    fn call(name: &str, arguments: Value) -> ToolCall {
        ToolCall {
            call_id: CallId::from("c1"),
            name: name.into(),
            arguments,
        }
    }

    #[tokio::test]
    async fn executes_and_renders_canonical_value() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Echo));
        let result = reg.execute(call("echo", json!({ "text": "pwned" })), &ExecCtx::new()).await;
        assert!(!result.is_error);
        assert_eq!(result.value, Some(json!({ "echoed": "pwned" })));
        assert_eq!(result.content, vec![ContentBlock::text("pwned")]);
    }

    #[tokio::test]
    async fn unknown_tool_is_an_error_result() {
        let reg = ToolRegistry::new();
        let result = reg.execute(call("nope", json!({})), &ExecCtx::new()).await;
        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("UNKNOWN_TOOL"));
    }

    #[tokio::test]
    async fn invalid_args_becomes_error_result() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Echo));
        let result = reg.execute(call("echo", json!({})), &ExecCtx::new()).await;
        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("INVALID_ARGS"));
    }

    struct DenyEcho;
    impl PrePolicy for DenyEcho {
        fn check(&self, call: &ToolCall) -> PreDecision {
            if call.name == "echo" {
                PreDecision::Deny("echo is off in this test".into())
            } else {
                PreDecision::Allow
            }
        }
    }

    #[tokio::test]
    async fn pre_policy_can_deny() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Echo));
        reg.add_pre_policy(Arc::new(DenyEcho));
        let result = reg.execute(call("echo", json!({ "text": "x" })), &ExecCtx::new()).await;
        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("DENIED"));
    }

    #[tokio::test]
    async fn cancellation_before_dispatch_is_reported() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Echo));
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let ctx = ExecCtx::with_token(token);
        let result = reg.execute(call("echo", json!({ "text": "x" })), &ctx).await;
        assert!(result.is_error);
        assert_eq!(result.error_code.as_deref(), Some("ABORTED_BEFORE_DISPATCH"));
    }

    #[tokio::test]
    async fn schemas_are_listed_in_name_order() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(Echo));
        let schemas = reg.schemas();
        assert_eq!(schemas.len(), 1);
        assert_eq!(schemas[0].name, "echo");
        assert!(reg.is_concurrency_safe(&call("echo", json!({ "text": "x" }))));
    }
}
