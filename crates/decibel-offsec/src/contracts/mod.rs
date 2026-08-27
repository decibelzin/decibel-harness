//! Pure, offline smart-contract analyzers — ported from Decepticon's
//! `tools/contracts` bucket (crate `decepticon-contracts`) into Decibel with
//! **no executor dependency**: every capability is in-process, deterministic,
//! and unit-tested. No `solc`/`forge` is invoked — the Foundry generators only
//! emit `.sol` source strings that the agent writes and runs via the shell later.
//!
//! Two analysis capabilities plus three generators, surfaced as model-facing
//! tools in [`tools`]: a Solidity vulnerability **pattern scanner** ([`scan`])
//! over an inline source string (`solidity_scan`) or a workspace file
//! (`solidity_scan_file`), and **Foundry PoC-test generators** ([`foundry`]) for
//! reentrancy / access-control / flash-loan (`foundry_reentrancy_test`,
//! `foundry_access_test`, `foundry_flashloan_test`). Each analyzer returns a
//! serde struct so the tool layer hands it straight to the model (and, later,
//! the knowledge graph) as a canonical value.

pub mod foundry;
pub mod scan;
pub mod tools;

use serde::{Deserialize, Serialize};

/// One scanner finding. `severity` uses the KG scale (info|low|medium|high|critical).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub id: String,
    pub line: usize,
    pub detail: String,
}
