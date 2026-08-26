//! The first autonomous turn: a real model, a real shell tool, and the loop
//! that lets the model *act* — run a command, read the result, then answer.
//!
//! Needs OPENROUTER_API_KEY (a workspace-root .env is auto-loaded):
//!
//!     cargo run -p decibel-agent --example agent_demo
//!     cargo run -p decibel-agent --example agent_demo "what OS am I on and who am I?"
//!
//! The `shell` tool runs commands directly on this machine with no sandbox —
//! that is the point of an offensive-security harness. Run it only where you
//! intend the agent to have that access.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use decibel_agent::{run_turn, AgentConfig, StopReason, TurnSignal};
use decibel_core::Session;
use decibel_llm::{ContentBlock, Message, MessageSource, ToolSchema};
use decibel_openrouter::{fetch_default_models, OpenRouterAdapter};
use decibel_tools::{ExecCtx, Tool, ToolError, ToolRegistry};

/// A shell tool with no guard rails: it runs the command on this host and
/// returns stdout/stderr/exit code as a canonical value.
struct ShellTool;

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "shell".into(),
            description: "Run a shell command on this machine and return its stdout, stderr, and exit code. \
                          Use it to inspect the host, run recon tools, or execute any command."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "The command line to run." }
                },
                "required": ["command"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let command = arguments
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_args("missing string `command`"))?;

        // Use the host's native shell — cmd on Windows, sh elsewhere.
        let output = if cfg!(windows) {
            tokio::process::Command::new("cmd").arg("/C").arg(command).output().await
        } else {
            tokio::process::Command::new("sh").arg("-c").arg(command).output().await
        }
        .map_err(|e| ToolError::execution(format!("failed to spawn shell: {e}")))?;

        Ok(json!({
            "command": command,
            "stdout": String::from_utf8_lossy(&output.stdout).trim_end().to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).trim_end().to_string(),
            "exit_code": output.status.code(),
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let stdout = value.get("stdout").and_then(Value::as_str).unwrap_or("");
        let stderr = value.get("stderr").and_then(Value::as_str).unwrap_or("");
        let code = value.get("exit_code").and_then(Value::as_i64);
        let mut text = if stdout.is_empty() { String::new() } else { format!("{stdout}\n") };
        if !stderr.is_empty() {
            text.push_str(&format!("[stderr]\n{stderr}\n"));
        }
        text.push_str(&format!("[exit code: {}]", code.map(|c| c.to_string()).unwrap_or_else(|| "killed".into())));
        vec![ContentBlock::text(text)]
    }
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    let api_key = match std::env::var("OPENROUTER_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            eprintln!("Set OPENROUTER_API_KEY (free at https://openrouter.ai/keys), e.g. in a .env file.");
            std::process::exit(1);
        }
    };

    let prompt_text = std::env::args().nth(1).unwrap_or_else(|| {
        "Run a shell command to print the current user and the operating system, \
         then tell me in one sentence what you found."
            .to_string()
    });

    let adapter = OpenRouterAdapter::new(Some(api_key));

    // An explicit second arg pins the model; otherwise use the free +
    // tool-capable catalog, largest context first.
    let candidates: Vec<String> = match std::env::args().nth(2) {
        Some(model) => vec![model],
        None => {
            eprintln!("Fetching free tool-capable models…");
            let mut models: Vec<_> = fetch_default_models()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|m| m.is_free && m.supports_tools)
                .collect();
            models.sort_by(|a, b| b.context_length.cmp(&a.context_length));
            models.into_iter().map(|m| m.id).collect()
        }
    };

    eprintln!("Prompt: {prompt_text}\n");

    for (i, model) in candidates.iter().enumerate() {
        eprintln!("──────── trying model: {model} ────────");
        let mut session = Session::new(format!("agent-demo-{i}"));
        let config = AgentConfig::new("openrouter", model)
            .with_system(
                "You are Decibel, a concise offensive-security agent. You can run shell \
                 commands with the `shell` tool. Use it to gather facts before answering, \
                 then give a short final answer.",
            )
            .with_max_tokens(600);

        let mut registry = ToolRegistry::new();
        registry.register(Arc::new(ShellTool));

        let prompt = Message::human("u1", vec![ContentBlock::text(prompt_text.clone())]);
        let outcome =
            run_turn(&mut session, &adapter, &registry, &config, prompt, TurnSignal::new()).await;

        // A gated or rate-limited free model can't serve this turn — the free
        // tier shares a quota, so skip to the next candidate.
        if let StopReason::Error(failure) = &outcome.stop_reason {
            let skippable = matches!(failure.status, Some(403) | Some(429))
                || matches!(failure.code.as_str(), "RATE_LIMIT" | "TIMEOUT" | "PROVIDER_ERROR")
                || failure.message.contains("agentic harnesses");
            if skippable && i + 1 < candidates.len() {
                eprintln!("  ([{}] — next model)\n", failure.code);
                continue;
            }
            eprintln!("  model error: [{}] {}", failure.code, failure.message);
            std::process::exit(1);
        }

        print_transcript(&session);
        eprintln!("\n★ stop: {:?} in {} step(s)", outcome.stop_reason, outcome.steps);
        eprintln!("★ final answer: {}", outcome.final_text.trim());
        return;
    }

    eprintln!("No free tool-capable model completed the turn; pass a model id or try later.");
    std::process::exit(1);
}

/// Print the derived transcript the way the model saw it build up.
fn print_transcript(session: &Session) {
    println!("\n=== transcript ({} messages) ===", session.derive_messages().len());
    for msg in session.derive_messages() {
        match &msg.source {
            MessageSource::Human => println!("\n[user] {}", join_text(&msg)),
            MessageSource::Model { .. } => {
                for block in &msg.content {
                    match block {
                        ContentBlock::Text { text } if !text.is_empty() => {
                            println!("\n[assistant] {text}")
                        }
                        ContentBlock::ToolCall { name, arguments, .. } => {
                            println!("\n[assistant → tool] {name}({arguments})")
                        }
                        _ => {}
                    }
                }
            }
            MessageSource::Tool { .. } => println!("[tool result]\n{}", join_text(&msg)),
            MessageSource::Plugin { .. } => println!("[injected] {}", join_text(&msg)),
        }
    }
}

fn join_text(msg: &Message) -> String {
    msg.content
        .iter()
        .map(|b| match b {
            ContentBlock::Text { text } => text.clone(),
            ContentBlock::ToolResult { content, .. } => {
                content.iter().filter_map(ContentBlock::as_text).collect::<Vec<_>>().join("\n")
            }
            _ => String::new(),
        })
        .collect::<Vec<_>>()
        .join("")
}
