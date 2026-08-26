//! The ordered surface: the projection of message-producing events from which
//! model history is derived.
//!
//! An `append` adds a node to the tail; a `replace` shadows a contiguous run of
//! existing nodes with one new node (compaction), bumping the generation so
//! derived-history caches rebuild. The raw event log stays append-only
//! underneath — a replace never deletes a record.

use crate::error::SessionError;
use crate::event::{SessionEvent, SurfaceOp};

/// The ordered set of surface-node seqs plus a generation counter that changes
/// on every replace.
#[derive(Clone, Debug, Default)]
pub struct Surface {
    nodes: Vec<u64>,
    replace_generation: u64,
}

impl Surface {
    /// The current surface nodes, in order (each is an event seq).
    pub fn nodes(&self) -> &[u64] {
        &self.nodes
    }

    /// Increments on every committed replace; a derived-history cache keyed by
    /// this value knows when it must rebuild.
    pub fn replace_generation(&self) -> u64 {
        self.replace_generation
    }

    /// Validate and apply one appended event to the surface. Non-surface events
    /// are a no-op. The candidate is fully validated before any mutation, so a
    /// rejected event never leaves the surface half-changed.
    pub fn accept(&mut self, event: &SessionEvent) -> Result<(), SessionError> {
        if !event.kind.is_surface_eligible() {
            if event.surface_op.is_some() {
                return Err(SessionError::SurfaceOnLogOnly { seq: event.seq });
            }
            return Ok(());
        }
        let op = event
            .surface_op
            .as_ref()
            .ok_or(SessionError::MissingSurfaceOp { seq: event.seq })?;
        match op {
            SurfaceOp::Append => {
                self.nodes.push(event.seq);
                Ok(())
            }
            SurfaceOp::Replace { start, end } => {
                let start_pos = self.position_of(*start).ok_or(SessionError::UnknownSurfaceNode {
                    seq: *start,
                })?;
                let end_pos = self.position_of(*end).ok_or(SessionError::UnknownSurfaceNode {
                    seq: *end,
                })?;
                if start_pos > end_pos {
                    return Err(SessionError::InvalidReplaceRange {
                        start: *start,
                        end: *end,
                    });
                }
                let shadowed = &self.nodes[start_pos..=end_pos];
                let sources = event.source_event_seqs.as_deref().unwrap_or(&[]);
                for node in shadowed {
                    if !sources.contains(node) {
                        return Err(SessionError::IncompleteReplaceCoverage {
                            missing: *node,
                            replacement: event.seq,
                        });
                    }
                }
                // Splice the shadowed run out and insert the replacement in place.
                self.nodes.splice(start_pos..=end_pos, [event.seq]);
                self.replace_generation += 1;
                Ok(())
            }
        }
    }

    fn position_of(&self, seq: u64) -> Option<usize> {
        self.nodes.iter().position(|&node| node == seq)
    }
}
