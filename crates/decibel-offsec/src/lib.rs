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
pub mod search;
pub mod shell;
pub mod util;

use std::sync::Arc;

use decibel_tools::ToolRegistry;

pub use findings::{AddFindingTool, Finding, FindingStore};
pub use fs::{ReadFileTool, StrReplaceTool, WriteFileTool};
pub use http::HttpTool;
pub use search::{GlobTool, GrepTool};
pub use shell::ShellTool;

/// Register the complete offensive toolkit into `registry` and return the
/// shared finding store the tools record into.
///
/// Tools installed: `shell`, `http`, `read_file`, `write_file`, `str_replace`,
/// `glob`, `grep`, `add_finding`.
pub fn register_all(registry: &mut ToolRegistry) -> FindingStore {
    let findings = FindingStore::new();
    registry.register(Arc::new(ShellTool));
    registry.register(Arc::new(HttpTool));
    registry.register(Arc::new(ReadFileTool));
    registry.register(Arc::new(WriteFileTool));
    registry.register(Arc::new(StrReplaceTool));
    registry.register(Arc::new(GlobTool));
    registry.register(Arc::new(GrepTool));
    registry.register(Arc::new(AddFindingTool::new(findings.clone())));
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
            "shell", "http", "read_file", "write_file", "str_replace", "glob", "grep", "add_finding",
        ] {
            assert!(names.contains(&expected.to_string()), "missing tool {expected}");
        }
        assert_eq!(names.len(), 8);
    }
}
