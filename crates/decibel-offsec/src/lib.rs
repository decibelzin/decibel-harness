//! The Decibel offensive toolkit: the model-facing tools that make the harness
//! a red-team agent.
//!
//! Every tool implements [`decibel_tools::Tool`] (a canonical JSON value plus a
//! pure `render`), so the same facts drive the model, a replayed UI card, and a
//! future Code Mode. There is no sandbox — the shell and filesystem tools run
//! with the operator's full authority; the only withholding is secret-looking
//! env vars, kept out of spawned processes so a key never leaks into context.
//!
//! [`register_all`] installs the whole toolkit into a [`ToolRegistry`] and
//! returns the shared [`FindingStore`] the app reads to build a report.

pub mod findings;
pub mod fs;
pub mod http;
pub mod nmap;
pub mod proc;
pub mod search;
pub mod shell;
pub mod util;

use std::sync::Arc;

use decibel_tools::ToolRegistry;

pub use findings::{AddFindingTool, Finding, FindingStore};
pub use fs::{ReadFileTool, StrReplaceTool, WriteFileTool};
pub use http::HttpTool;
pub use nmap::NmapTool;
pub use search::{GlobTool, GrepTool};
pub use shell::ShellTool;

/// Every tool name the toolkit provides, in registration order.
pub const ALL_TOOLS: &[&str] = &[
    "shell", "nmap", "http", "read_file", "write_file", "str_replace", "glob", "grep", "add_finding",
];

/// Register the named subset of the toolkit into `registry`, sharing `findings`
/// as the store `add_finding` records into. Unknown names are ignored, so a
/// specialist can name exactly the tools it should have. `add_finding` is only
/// installed when named.
pub fn register_named(registry: &mut ToolRegistry, names: &[&str], findings: &FindingStore) {
    for name in names {
        match *name {
            "shell" => registry.register(Arc::new(ShellTool)),
            "nmap" => registry.register(Arc::new(NmapTool)),
            "http" => registry.register(Arc::new(HttpTool)),
            "read_file" => registry.register(Arc::new(ReadFileTool)),
            "write_file" => registry.register(Arc::new(WriteFileTool)),
            "str_replace" => registry.register(Arc::new(StrReplaceTool)),
            "glob" => registry.register(Arc::new(GlobTool)),
            "grep" => registry.register(Arc::new(GrepTool)),
            "add_finding" => registry.register(Arc::new(AddFindingTool::new(findings.clone()))),
            _ => None,
        };
    }
}

/// Register the complete offensive toolkit into `registry` and return the
/// shared finding store the tools record into.
///
/// Tools installed: `shell`, `nmap`, `http`, `read_file`, `write_file`,
/// `str_replace`, `glob`, `grep`, `add_finding`.
pub fn register_all(registry: &mut ToolRegistry) -> FindingStore {
    let findings = FindingStore::new();
    register_named(registry, ALL_TOOLS, &findings);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_installs_every_tool() {
        let mut registry = ToolRegistry::new();
        let _findings = register_all(&mut registry);
        let names: Vec<String> = registry.schemas().into_iter().map(|s| s.name).collect();
        for expected in [
            "shell", "nmap", "http", "read_file", "write_file", "str_replace", "glob", "grep",
            "add_finding",
        ] {
            assert!(names.contains(&expected.to_string()), "missing tool {expected}");
        }
        assert_eq!(names.len(), 9);
    }
}
