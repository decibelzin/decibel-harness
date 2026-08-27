//! Bundled OFFLINE reference corpora — ported from Decepticon's `decepticon-refs`
//! crate (spec §3) into Decibel with **no executor and no network dependency**:
//! everything ships compiled into the binary, so these are the always-available
//! baseline the agent's reference tools read.
//!
//! Two corpora, surfaced as model-facing tools in [`tools`]:
//!  - [`payloads`] — a payload library grouped by vulnerability class, searchable
//!    by class and/or keyword (`payload_search`).
//!  - [`killchain`] — a flat map of red-team tools to the 14 MITRE ATT&CK tactic
//!    phases, with lookup by phase (`killchain_lookup`) and keyword-based
//!    suggestion from an objective (`killchain_suggest`).
//!
//! Each lookup returns a serde struct (`Payload` / `Entry`), so the tool layer
//! hands the model the same canonical fact a UI card (and a future knowledge
//! graph) reads. The upstream crate depended on nothing but `serde` and carried
//! no knowledge-graph ingest, so this port is a faithful, verbatim vendoring of
//! the two data tables and their pure query logic.

pub mod killchain;
pub mod payloads;
pub mod tools;
