//! Runnable demo of the session core: build one turn by hand, derive the model
//! history, serialize to JSONL, then reconstruct and confirm it round-trips.
//!
//! Run it with:
//!     cargo run -p decibel-core --example session_demo

use decibel_core::{persist, EventKind, Session, SurfaceIntent, TurnEndReason};
use decibel_llm::{CallId, ContentBlock, Message, MessageSource, Role};

fn main() {
    let mut session = Session::new("demo-session");

    // --- one turn: the human asks, the model calls a tool, then answers ---
    session.append_log(EventKind::TurnStart { turn: 1 }).unwrap();
    session.append_log(EventKind::StepStart { turn: 1, step: 1 }).unwrap();

    // The human prompt.
    session
        .append_surface(
            EventKind::UserMessage(Message::human(
                "u1",
                vec![ContentBlock::text("scan 10.0.0.5 for open ports")],
            )),
            SurfaceIntent::append_bare(),
        )
        .unwrap();

    // The model responds with a tool call.
    let call_id = CallId::from("call_nmap_1");
    session
        .append_surface(
            EventKind::AssistantMessage {
                turn: 1,
                step: 1,
                message: Message::assistant(
                    "a1",
                    vec![ContentBlock::ToolCall {
                        id: call_id.clone(),
                        name: "bash".into(),
                        arguments: r#"{"command":"nmap -T4 10.0.0.5"}"#.into(),
                    }],
                    "openrouter",
                    "x-ai/grok-4-fast:free",
                ),
                usage: None,
            },
            SurfaceIntent::append_bare(),
        )
        .unwrap();

    // The tool runs; its call and result are logged.
    session
        .append_log(EventKind::ToolCall {
            turn: 1,
            step: 1,
            call_id: call_id.clone(),
            name: "bash".into(),
            arguments: r#"{"command":"nmap -T4 10.0.0.5"}"#.into(),
        })
        .unwrap();
    session
        .append_surface(
            EventKind::ToolResult {
                turn: 1,
                step: 1,
                message: Message::tool_result(
                    "r1",
                    call_id.clone(),
                    vec![ContentBlock::text("22/tcp open ssh\n80/tcp open http")],
                    false,
                ),
            },
            SurfaceIntent::append(vec![4]), // cites the tool/call event seq (seq 4)
        )
        .unwrap();
    session.append_log(EventKind::StepEnd { turn: 1, step: 1 }).unwrap();

    // The model's final answer in a second step.
    session.append_log(EventKind::StepStart { turn: 1, step: 2 }).unwrap();
    session
        .append_surface(
            EventKind::AssistantMessage {
                turn: 1,
                step: 2,
                message: Message::assistant(
                    "a2",
                    vec![ContentBlock::text(
                        "Host 10.0.0.5 has SSH (22) and HTTP (80) open. Next: probe the web service.",
                    )],
                    "openrouter",
                    "x-ai/grok-4-fast:free",
                ),
                usage: None,
            },
            SurfaceIntent::append_bare(),
        )
        .unwrap();
    session.append_log(EventKind::StepEnd { turn: 1, step: 2 }).unwrap();
    session
        .append_log(EventKind::TurnEnd {
            turn: 1,
            reason: TurnEndReason::Completed,
        })
        .unwrap();

    // --- what the model would see next: the derived history ---
    println!("=== derived model history ({} messages) ===", session.derive_messages().len());
    for (i, msg) in session.derive_messages().iter().enumerate() {
        println!("  [{i}] {} :: {}", role_label(msg.role), summarize(msg));
    }

    // --- the durable log ---
    let jsonl = persist::to_jsonl(&session).unwrap();
    println!("\n=== durable JSONL ({} events) ===", session.events().len());
    print!("{jsonl}");

    // --- reconstruct from disk and confirm it is byte-for-byte the same ---
    let restored = persist::from_jsonl("demo-session", &jsonl).unwrap();
    let ok = restored.events() == session.events()
        && restored.derive_messages() == session.derive_messages();
    println!("\n=== round-trip from JSONL: {} ===", if ok { "OK ✓" } else { "MISMATCH ✗" });
    assert!(ok, "round-trip must be lossless");
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

/// One-line summary of a message for the demo output.
fn summarize(msg: &Message) -> String {
    let kind = match &msg.source {
        MessageSource::Human => "human",
        MessageSource::Plugin { .. } => "injected",
        MessageSource::Model { model, .. } => model.as_str(),
        MessageSource::Tool { .. } => "tool-result",
    };
    let body: Vec<String> = msg
        .content
        .iter()
        .map(|block| match block {
            ContentBlock::Text { text } => text.replace('\n', " / "),
            ContentBlock::Reasoning { .. } => "<reasoning>".into(),
            ContentBlock::Image { .. } => "<image>".into(),
            ContentBlock::ToolCall { name, arguments, .. } => format!("call {name}({arguments})"),
            ContentBlock::ToolResult { .. } => "<tool-result>".into(),
        })
        .collect();
    format!("[{kind}] {}", body.join(" | "))
}
