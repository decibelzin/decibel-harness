//! The event-sourced session: an append-only log whose derived projection is
//! the model's message history.

use std::time::{SystemTime, UNIX_EPOCH};

use decibel_llm::{Message, SessionId};

use crate::error::SessionError;
use crate::event::{EventKind, SessionEvent, SurfaceOp};
use crate::surface::Surface;

/// Surface placement for a surface-eligible append.
#[derive(Clone, Debug)]
pub struct SurfaceIntent {
    /// How the event joins the surface.
    pub op: SurfaceOp,
    /// Cited source-event seqs (chunks behind a message, nodes a replace shadows).
    pub source_event_seqs: Option<Vec<u64>>,
}

impl SurfaceIntent {
    /// A plain tail append citing the given source seqs (e.g. the chunk seqs).
    pub fn append(source_event_seqs: Vec<u64>) -> Self {
        SurfaceIntent {
            op: SurfaceOp::Append,
            source_event_seqs: Some(source_event_seqs),
        }
    }

    /// A tail append citing no sources (a directly-created message).
    pub fn append_bare() -> Self {
        SurfaceIntent {
            op: SurfaceOp::Append,
            source_event_seqs: None,
        }
    }
}

/// Current Unix epoch milliseconds (saturating at 0 before the epoch).
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// An event-sourced session log plus its ordered surface.
#[derive(Clone, Debug)]
pub struct Session {
    id: SessionId,
    log: Vec<SessionEvent>,
    surface: Surface,
    first_live_seq: u64,
}

impl Session {
    /// Create an empty session.
    pub fn new(id: impl Into<SessionId>) -> Self {
        Session {
            id: id.into(),
            log: Vec::new(),
            surface: Surface::default(),
            first_live_seq: 0,
        }
    }

    /// Reconstruct a session from a seed log (resume/fork/replay). The seed must
    /// be contiguous from seq 0 and each surface event must fold cleanly; the
    /// surface is rebuilt from the same transitions a live append enforces.
    pub fn from_seed(
        id: impl Into<SessionId>,
        seed: Vec<SessionEvent>,
    ) -> Result<Self, SessionError> {
        let mut session = Session::new(id);
        for (index, event) in seed.into_iter().enumerate() {
            if event.seq != index as u64 {
                return Err(SessionError::NonContiguousSeed {
                    index,
                    seq: event.seq,
                });
            }
            session.surface.accept(&event)?;
            session.log.push(event);
        }
        session.first_live_seq = session.log.len() as u64;
        Ok(session)
    }

    /// The session identity.
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The next event's seq — always the current log length.
    pub fn seq(&self) -> u64 {
        self.log.len() as u64
    }

    /// The complete append-only log.
    pub fn events(&self) -> &[SessionEvent] {
        &self.log
    }

    /// The ordered surface over the log.
    pub fn surface(&self) -> &Surface {
        &self.surface
    }

    /// The first seq appended in THIS process (0 without a seed) — events below
    /// it entered through reconstruction.
    pub fn first_live_seq(&self) -> u64 {
        self.first_live_seq
    }

    /// Append a log-only (non-surface) event. Passing a surface-eligible kind is
    /// a misuse and is rejected.
    pub fn append_log(&mut self, kind: EventKind) -> Result<&SessionEvent, SessionError> {
        if kind.is_surface_eligible() {
            return Err(SessionError::MissingSurfaceOp { seq: self.seq() });
        }
        self.commit(kind, None, None)
    }

    /// Append a surface-eligible event with its surface placement. Passing a
    /// log-only kind is a misuse and is rejected.
    pub fn append_surface(
        &mut self,
        kind: EventKind,
        intent: SurfaceIntent,
    ) -> Result<&SessionEvent, SessionError> {
        if !kind.is_surface_eligible() {
            return Err(SessionError::SurfaceOnLogOnly { seq: self.seq() });
        }
        self.commit(kind, Some(intent.op), intent.source_event_seqs)
    }

    /// Validate the candidate against the surface, then commit it to the log.
    /// The surface is validated (and mutated) before the log push, so a
    /// rejected event leaves both unchanged.
    fn commit(
        &mut self,
        kind: EventKind,
        surface_op: Option<SurfaceOp>,
        source_event_seqs: Option<Vec<u64>>,
    ) -> Result<&SessionEvent, SessionError> {
        let event = SessionEvent {
            seq: self.log.len() as u64,
            time: now_ms(),
            kind,
            surface_op,
            source_event_seqs,
        };
        self.surface.accept(&event)?;
        self.log.push(event);
        // The non-empty check is guaranteed by the push above.
        Ok(self.log.last().expect("just pushed"))
    }

    /// Derive the model message history by projecting each surface node once, in
    /// order. Empty-content assistant messages project to nothing. The returned
    /// vector is a fresh clone the caller owns.
    pub fn derive_messages(&self) -> Vec<Message> {
        self.surface
            .nodes()
            .iter()
            .filter_map(|&seq| self.log.get(seq as usize))
            .filter_map(|event| event.kind.derive_message())
            .cloned()
            .collect()
    }
}
