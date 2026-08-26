//! The event-sourced session core of Decibel Harness.
//!
//! A [`Session`] is an append-only log of [`SessionEvent`]s and is the single
//! source of truth for an interaction. The model's message history is *derived*
//! from it by projecting an ordered [`Surface`] of the message-producing
//! events; compaction shadows a run of surface nodes with a single replacement
//! rather than deleting anything. Persistence ([`persist`]) is a plain JSONL
//! codec over the same events.
//!
//! This is a Rust implementation of the design proven in DeepSeek Harness
//! (`dsh-session`, MIT); the event-type spellings (`turn/start`, …) are kept so
//! the durable log reads the same, but the code is our own.

pub mod error;
pub mod event;
pub mod persist;
pub mod session;
pub mod surface;

pub use error::SessionError;
pub use event::{
    CancelCause, EventKind, SessionEvent, SurfaceOp, TodoItem, TodoStatus, TurnEndReason,
};
pub use session::{Session, SurfaceIntent};
pub use surface::Surface;

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::{CallId, ContentBlock, Message};

    fn user(id: &str, text: &str) -> EventKind {
        EventKind::UserMessage(Message::human(id, vec![ContentBlock::text(text)]))
    }

    fn assistant(turn: u64, step: u64, id: &str, text: &str) -> EventKind {
        EventKind::AssistantMessage {
            turn,
            step,
            message: Message::assistant(id, vec![ContentBlock::text(text)], "openrouter", "m"),
            usage: None,
        }
    }

    #[test]
    fn seqs_are_contiguous_from_zero() {
        let mut s = Session::new("s1");
        s.append_log(EventKind::TurnStart { turn: 1 }).unwrap();
        s.append_surface(user("u1", "hello"), SurfaceIntent::append_bare())
            .unwrap();
        assert_eq!(s.events()[0].seq, 0);
        assert_eq!(s.events()[1].seq, 1);
        assert_eq!(s.seq(), 2);
    }

    #[test]
    fn append_log_rejects_surface_kind_and_vice_versa() {
        let mut s = Session::new("s1");
        assert!(matches!(
            s.append_log(user("u1", "x")),
            Err(SessionError::MissingSurfaceOp { .. })
        ));
        assert!(matches!(
            s.append_surface(EventKind::TurnStart { turn: 1 }, SurfaceIntent::append_bare()),
            Err(SessionError::SurfaceOnLogOnly { .. })
        ));
    }

    #[test]
    fn derive_projects_surface_and_skips_empty_assistant() {
        let mut s = Session::new("s1");
        s.append_surface(user("u1", "hi"), SurfaceIntent::append_bare())
            .unwrap();
        // An empty-content assistant message is a surface node but derives to nothing.
        s.append_surface(
            EventKind::AssistantMessage {
                turn: 1,
                step: 1,
                message: Message::assistant("empty", vec![], "openrouter", "m"),
                usage: None,
            },
            SurfaceIntent::append_bare(),
        )
        .unwrap();
        s.append_surface(assistant(1, 2, "a2", "done"), SurfaceIntent::append_bare())
            .unwrap();

        // All three are surface nodes (seqs 0,1,2); the empty one just derives to nothing.
        assert_eq!(s.surface().nodes(), &[0, 1, 2]);
        let msgs = s.derive_messages();
        // Only the human prompt and the non-empty assistant survive derivation.
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, vec![ContentBlock::text("hi")]);
        assert_eq!(msgs[1].content, vec![ContentBlock::text("done")]);
    }

    #[test]
    fn tool_result_surfaces_and_derives() {
        let mut s = Session::new("s1");
        s.append_log(EventKind::ToolCall {
            turn: 1,
            step: 1,
            call_id: CallId::from("c1"),
            name: "bash".into(),
            arguments: "{}".into(),
        })
        .unwrap();
        s.append_surface(
            EventKind::ToolResult {
                turn: 1,
                step: 1,
                message: Message::tool_result(
                    "r1",
                    CallId::from("c1"),
                    vec![ContentBlock::text("output")],
                    false,
                ),
            },
            SurfaceIntent::append(vec![0]),
        )
        .unwrap();
        let msgs = s.derive_messages();
        assert_eq!(msgs.len(), 1);
        assert!(matches!(msgs[0].source, decibel_llm::MessageSource::Tool { .. }));
    }

    #[test]
    fn compaction_replace_shadows_prior_nodes() {
        let mut s = Session::new("s1");
        s.append_surface(user("u1", "a"), SurfaceIntent::append_bare()).unwrap(); // seq0
        s.append_surface(assistant(1, 1, "a1", "b"), SurfaceIntent::append_bare()).unwrap(); // seq1
        s.append_surface(user("u2", "c"), SurfaceIntent::append_bare()).unwrap(); // seq2
        assert_eq!(s.surface().nodes(), &[0, 1, 2]);
        assert_eq!(s.surface().replace_generation(), 0);

        // Compaction summary replacing all three nodes with one.
        s.append_surface(
            EventKind::UserMessage(Message {
                id: "sum".into(),
                role: decibel_llm::Role::User,
                content: vec![ContentBlock::text("summary")],
                source: decibel_llm::MessageSource::Plugin {
                    plugin: "compaction".into(),
                },
            }),
            SurfaceIntent {
                op: SurfaceOp::Replace { start: 0, end: 2 },
                source_event_seqs: Some(vec![0, 1, 2]),
            },
        )
        .unwrap();

        assert_eq!(s.surface().nodes(), &[3]);
        assert_eq!(s.surface().replace_generation(), 1);
        let msgs = s.derive_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].content, vec![ContentBlock::text("summary")]);
        // The raw log still holds every shadowed event.
        assert_eq!(s.events().len(), 4);
    }

    #[test]
    fn replace_requires_full_coverage() {
        let mut s = Session::new("s1");
        s.append_surface(user("u1", "a"), SurfaceIntent::append_bare()).unwrap();
        s.append_surface(user("u2", "b"), SurfaceIntent::append_bare()).unwrap();
        s.append_surface(user("u3", "c"), SurfaceIntent::append_bare()).unwrap();
        let err = s
            .append_surface(
                user("sum", "s"),
                SurfaceIntent {
                    op: SurfaceOp::Replace { start: 0, end: 2 },
                    source_event_seqs: Some(vec![0, 1]), // omits node 2
                },
            )
            .unwrap_err();
        assert!(matches!(err, SessionError::IncompleteReplaceCoverage { missing: 2, .. }));
        // A rejected replace leaves the surface untouched.
        assert_eq!(s.surface().nodes(), &[0, 1, 2]);
    }

    #[test]
    fn jsonl_round_trip_preserves_log_and_surface() {
        let mut s = Session::new("s1");
        s.append_log(EventKind::TurnStart { turn: 1 }).unwrap();
        s.append_surface(user("u1", "hi"), SurfaceIntent::append_bare()).unwrap();
        s.append_surface(assistant(1, 1, "a1", "there"), SurfaceIntent::append(vec![])).unwrap();
        s.append_log(EventKind::TurnEnd {
            turn: 1,
            reason: TurnEndReason::Completed,
        })
        .unwrap();

        let jsonl = persist::to_jsonl(&s).unwrap();
        let restored = persist::from_jsonl("s1", &jsonl).unwrap();
        assert_eq!(restored.events(), s.events());
        assert_eq!(restored.surface().nodes(), s.surface().nodes());
        assert_eq!(restored.derive_messages(), s.derive_messages());
        // Everything before the restore boundary counts as reconstructed.
        assert_eq!(restored.first_live_seq(), 4);
    }

    #[test]
    fn event_envelope_json_shape() {
        let mut s = Session::new("s1");
        s.append_log(EventKind::TurnStart { turn: 7 }).unwrap();
        let json = serde_json::to_value(&s.events()[0]).unwrap();
        assert_eq!(json["type"], "turn/start");
        assert_eq!(json["seq"], 0);
        assert_eq!(json["data"]["turn"], 7);
        assert!(json.get("surface_op").is_none());
    }
}
