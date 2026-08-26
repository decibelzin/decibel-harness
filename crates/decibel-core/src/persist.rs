//! JSONL persistence: one session event per line.
//!
//! This is the plain durable codec — a swappable backend later. The log is the
//! source of truth, so a session round-trips through JSONL with no loss.

use std::io::{BufRead, Write};

use decibel_llm::SessionId;

use crate::error::SessionError;
use crate::event::SessionEvent;
use crate::session::Session;

/// Serialize a session's complete log as newline-delimited JSON.
pub fn to_jsonl(session: &Session) -> Result<String, SessionError> {
    let mut out = String::new();
    for event in session.events() {
        let line = serde_json::to_string(event).map_err(|source| SessionError::Parse {
            line: event.seq as usize + 1,
            source,
        })?;
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// Reconstruct a session by reading newline-delimited JSON events. Blank lines
/// are skipped; every non-blank line must parse, and the seed must fold as a
/// valid surface.
pub fn from_jsonl(id: impl Into<SessionId>, jsonl: &str) -> Result<Session, SessionError> {
    let mut seed = Vec::new();
    for (index, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: SessionEvent =
            serde_json::from_str(line).map_err(|source| SessionError::Parse {
                line: index + 1,
                source,
            })?;
        seed.push(event);
    }
    Session::from_seed(id, seed)
}

/// Write a session's log to a writer as JSONL.
pub fn write_jsonl<W: Write>(session: &Session, mut writer: W) -> Result<(), SessionError> {
    writer.write_all(to_jsonl(session)?.as_bytes())?;
    Ok(())
}

/// Read a session's log from a buffered reader of JSONL.
pub fn read_jsonl<R: BufRead>(
    id: impl Into<SessionId>,
    reader: R,
) -> Result<Session, SessionError> {
    let mut seed = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let event: SessionEvent =
            serde_json::from_str(&line).map_err(|source| SessionError::Parse {
                line: index + 1,
                source,
            })?;
        seed.push(event);
    }
    Session::from_seed(id, seed)
}
