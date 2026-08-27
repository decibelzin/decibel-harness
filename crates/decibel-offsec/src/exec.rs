//! Model-facing tools for the execution plane ([`decibel_executor`]): a family of
//! **persistent shell session** tools — `bash` / `bash_input` / `bash_output` /
//! `bash_status` / `bash_kill` — that share one [`SessionManager`] so a session's
//! state (cwd, env, background jobs) survives across calls, plus `poc_validate`
//! (differential, zero-false-positive PoC verification).
//!
//! These RUN commands on the host with full authority, so they belong to act mode
//! behind the RoE scope gate — never the read-only subset. The shared
//! `SessionManager` is created in [`crate::register_named`] and handed to each
//! `bash*` tool; `poc_validate` builds a local executor per call from the session
//! workspace (`ExecCtx::cwd`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use decibel_executor::{validate, Executor, LocalExecutor, PocSpec, SessionManager};
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Default session id when the model names none.
const DEFAULT_SESSION: &str = "main";
/// Default per-command wait before a session `run` reports a timeout.
const DEFAULT_TIMEOUT_MS: u64 = 60_000;
/// Default PoC command timeout.
const DEFAULT_POC_TIMEOUT_MS: u64 = 30_000;

/// The session id argument, defaulting to `"main"`.
fn session_of(args: &Value) -> String {
    arg_str_opt(args, "session").unwrap_or_else(|| DEFAULT_SESSION.to_string())
}

/// Read an argument as an array of strings (absent → empty).
fn arg_str_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Run a command in a persistent named shell session.
pub struct BashTool {
    sessions: Arc<SessionManager>,
}

impl BashTool {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        BashTool { sessions }
    }
}

#[async_trait]
impl Tool for BashTool {
    fn name(&self) -> &str {
        "bash"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bash".into(),
            description: "Run a shell command in a PERSISTENT named session whose state (cwd, env \
                vars, background jobs) survives across calls — the way to drive interactive or \
                long-running offensive tools (msfconsole, sqlmap, nc, evil-winrm). Returns the \
                command's output and exit code; the shell keeps running. Full host authority — \
                authorized engagements only. Use bash_input to feed a prompt, bash_output to drain \
                streamed/background output."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "Shell command line to run in the session." },
                    "session": { "type": "string", "description": "Session id (default \"main\"); distinct ids are isolated shells." },
                    "timeout_ms": { "type": "integer", "description": "Max wait for completion in ms (default 60000)." }
                },
                "required": ["command"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let command = arg_str(&arguments, "command")?;
        let session = session_of(&arguments);
        let timeout = arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_TIMEOUT_MS);
        let out = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = self.sessions.run(&session, &command, timeout) => r.map_err(ToolError::execution)?,
        };
        Ok(json!({
            "session": session,
            "output": out.output,
            "exit_code": out.exit_code,
            "timed_out": out.timed_out,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let session = value.get("session").and_then(Value::as_str).unwrap_or("");
        let output = value.get("output").and_then(Value::as_str).unwrap_or("");
        let mut head = format!("bash[{session}]");
        if value.get("timed_out").and_then(Value::as_bool).unwrap_or(false) {
            head.push_str(" (timed out)");
        } else if let Some(code) = value.get("exit_code").and_then(Value::as_i64) {
            head.push_str(&format!(" (exit {code})"));
        }
        vec![ContentBlock::text(format!("{head}\n{output}"))]
    }
}

/// Send raw input to a running program in a session (interactive prompt).
pub struct BashInputTool {
    sessions: Arc<SessionManager>,
}

impl BashInputTool {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        BashInputTool { sessions }
    }
}

#[async_trait]
impl Tool for BashInputTool {
    fn name(&self) -> &str {
        "bash_input"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bash_input".into(),
            description: "Send a line of raw input to a running interactive program in a session \
                (e.g. answer a prompt, type a command into an msf/sliver console). Returns any \
                output that arrived shortly after. Pair with bash to launch the interactive tool first."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "input": { "type": "string", "description": "The line to send (a trailing newline is added)." },
                    "session": { "type": "string", "description": "Session id (default \"main\")." }
                },
                "required": ["input"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let input = arg_str(&arguments, "input")?;
        let session = session_of(&arguments);
        self.sessions.send_input(&session, &input).await.map_err(ToolError::execution)?;
        // Give the program a moment to react, then drain what it emitted.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let output = self.sessions.read_new(&session).await.unwrap_or_default();
        Ok(json!({ "session": session, "sent": true, "output": output }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let session = value.get("session").and_then(Value::as_str).unwrap_or("");
        let output = value.get("output").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("bash_input[{session}] sent\n{output}"))]
    }
}

/// Drain output accumulated in a session since the last read (incremental).
pub struct BashOutputTool {
    sessions: Arc<SessionManager>,
}

impl BashOutputTool {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        BashOutputTool { sessions }
    }
}

#[async_trait]
impl Tool for BashOutputTool {
    fn name(&self) -> &str {
        "bash_output"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bash_output".into(),
            description: "Return the output a session produced since the last read — the way to reap \
                a long-running or backgrounded command (a slow scan, a brute-force) without blocking. \
                Call repeatedly to follow progress."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id (default \"main\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let session = session_of(&arguments);
        let output = self.sessions.read_new(&session).await.map_err(ToolError::execution)?;
        Ok(json!({ "session": session, "output": output }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let session = value.get("session").and_then(Value::as_str).unwrap_or("");
        let output = value.get("output").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("bash_output[{session}]\n{output}"))]
    }
}

/// List tracked sessions and one session's liveness.
pub struct BashStatusTool {
    sessions: Arc<SessionManager>,
}

impl BashStatusTool {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        BashStatusTool { sessions }
    }
}

#[async_trait]
impl Tool for BashStatusTool {
    fn name(&self) -> &str {
        "bash_status"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bash_status".into(),
            description: "List all tracked shell sessions and report whether a given session is still \
                running or has exited. A live inventory of concurrent operations."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id to report on (default \"main\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let session = session_of(&arguments);
        let sessions = self.sessions.list();
        // A missing session is not an error here — report it as absent.
        let status = match self.sessions.status(&session).await {
            Ok(s) => serde_json::to_value(s).unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        Ok(json!({ "sessions": sessions, "session": session, "status": status }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let list = value.get("sessions").and_then(Value::as_array).unwrap_or(&empty);
        let names: Vec<&str> = list.iter().filter_map(Value::as_str).collect();
        let session = value.get("session").and_then(Value::as_str).unwrap_or("");
        let status = &value["status"];
        vec![ContentBlock::text(format!(
            "bash_status: {} session(s): [{}]\n  {session}: {}",
            names.len(),
            names.join(", "),
            if status.is_null() { "absent".to_string() } else { status.to_string() }
        ))]
    }
}

/// Kill a session (Ctrl-C its shell) and forget it.
pub struct BashKillTool {
    sessions: Arc<SessionManager>,
}

impl BashKillTool {
    pub fn new(sessions: Arc<SessionManager>) -> Self {
        BashKillTool { sessions }
    }
}

#[async_trait]
impl Tool for BashKillTool {
    fn name(&self) -> &str {
        "bash_kill"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "bash_kill".into(),
            description: "Terminate a shell session and drop it — the way to abort a runaway or stuck \
                interactive tool."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "Session id (default \"main\")." }
                }
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let session = session_of(&arguments);
        self.sessions.kill(&session).await.map_err(ToolError::execution)?;
        Ok(json!({ "session": session, "killed": true }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let session = value.get("session").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("bash_kill[{session}] terminated"))]
    }
}

/// Differential PoC verification (zero-false-positive gate): a finding validates
/// only when the exploit command shows a success marker AND a baseline command
/// does not. Runs commands locally in the session workspace.
pub struct PocValidateTool;

#[async_trait]
impl Tool for PocValidateTool {
    fn name(&self) -> &str {
        "poc_validate"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "poc_validate".into(),
            description: "Prove an exploit with a DIFFERENTIAL negative control. Runs `command` and \
                checks its output for any `success_patterns`; if `negative_command` is given, runs it \
                too and requires it NOT to show success — killing the 'it printed the string but so \
                does everything' false positive. Returns a verdict. Authorized engagements only."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "The exploit/PoC command." },
                    "success_patterns": { "type": "array", "items": { "type": "string" }, "description": "Any of these substrings in the output means success." },
                    "negative_command": { "type": "string", "description": "A baseline/control command that should NOT reproduce success." },
                    "negative_patterns": { "type": "array", "items": { "type": "string" }, "description": "Substrings expected in the baseline output (optional)." },
                    "timeout_ms": { "type": "integer", "description": "Per-command timeout in ms (default 30000)." }
                },
                "required": ["command", "success_patterns"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let command = arg_str(&arguments, "command")?;
        let success_patterns = arg_str_array(&arguments, "success_patterns");
        if success_patterns.is_empty() {
            return Err(ToolError::invalid_args("`success_patterns` must be a non-empty array of strings"));
        }
        let spec = PocSpec {
            command,
            success_patterns,
            negative_command: arg_str_opt(&arguments, "negative_command"),
            negative_patterns: arg_str_array(&arguments, "negative_patterns"),
            timeout_ms: arg_u64_opt(&arguments, "timeout_ms").unwrap_or(DEFAULT_POC_TIMEOUT_MS),
        };
        let workspace = ctx
            .cwd()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let executor = Executor::Local(LocalExecutor::new(workspace));
        let verdict = tokio::select! {
            _ = ctx.token().cancelled() => return Err(ToolError::Aborted),
            r = validate(&executor, &spec) => r.map_err(ToolError::execution)?,
        };
        serde_json::to_value(verdict).map_err(|e| ToolError::execution(e.to_string()))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let validated = value.get("validated").and_then(Value::as_bool).unwrap_or(false);
        let note = value.get("note").and_then(Value::as_str).unwrap_or("");
        let verdict = if validated { "VALIDATED" } else { "NOT validated" };
        vec![ContentBlock::text(format!("poc_validate: {verdict} — {note}"))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{ToolCall, ToolRegistry};

    async fn run(tool: Arc<dyn Tool>, args: Value) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(ToolCall { call_id: CallId::from("c1"), name, arguments: args }, &ExecCtx::new()).await
    }

    #[tokio::test]
    async fn bash_session_persists_state_across_tools() {
        let sessions = Arc::new(SessionManager::new("."));
        let (set, get) = if cfg!(windows) {
            ("set DBVAR=persisted", "echo %DBVAR%")
        } else {
            ("DBVAR=persisted", "echo $DBVAR")
        };
        let r1 = run(Arc::new(BashTool::new(sessions.clone())), json!({ "command": set, "session": "t", "timeout_ms": 8000 })).await;
        assert!(!r1.is_error, "bash set failed: {:?}", r1.content);
        let r2 = run(Arc::new(BashTool::new(sessions.clone())), json!({ "command": get, "session": "t", "timeout_ms": 8000 })).await;
        let v = r2.value.unwrap();
        assert!(v["output"].as_str().unwrap().contains("persisted"), "output: {}", v["output"]);

        // status lists the session; kill drops it.
        let st = run(Arc::new(BashStatusTool::new(sessions.clone())), json!({ "session": "t" })).await;
        assert!(st.value.unwrap()["sessions"].as_array().unwrap().iter().any(|s| s == "t"));
        let _ = run(Arc::new(BashKillTool::new(sessions.clone())), json!({ "session": "t" })).await;
        assert!(sessions.list().is_empty());
    }

    #[tokio::test]
    async fn poc_validate_confirms_with_negative_control() {
        let ok = run(Arc::new(PocValidateTool), json!({
            "command": "echo INJECTED-4931",
            "success_patterns": ["INJECTED-4931"],
            "negative_command": "echo normal-baseline",
            "timeout_ms": 8000
        })).await;
        assert_eq!(ok.value.unwrap()["validated"], true);

        // A baseline that also prints the marker is a false positive.
        let fp = run(Arc::new(PocValidateTool), json!({
            "command": "echo MARKER",
            "success_patterns": ["MARKER"],
            "negative_command": "echo MARKER",
            "timeout_ms": 8000
        })).await;
        assert_eq!(fp.value.unwrap()["validated"], false);
    }

    #[tokio::test]
    async fn poc_validate_requires_success_patterns() {
        let r = run(Arc::new(PocValidateTool), json!({ "command": "echo x", "success_patterns": [] })).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
