//! Discovery tools: `glob` (find files by name pattern) and `grep` (search file
//! contents by regex). Both walk the tree with `walkdir`; `grep` reads each file
//! and matches per line. Results are capped so a broad search never floods the
//! model.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use globset::Glob;
use regex::Regex;
use serde_json::{json, Value};
use walkdir::WalkDir;

use crate::util::{arg_str, arg_str_opt, arg_u64_opt};

/// Cap on returned paths / matches.
const MAX_RESULTS: usize = 400;
/// Skip files larger than this when grepping (likely binaries/blobs).
const MAX_GREP_FILE_BYTES: u64 = 5_000_000;

/// Find files whose path matches a glob pattern.
pub struct GlobTool;

#[async_trait]
impl Tool for GlobTool {
    fn name(&self) -> &str {
        "glob"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "glob".into(),
            description: "List files whose path matches a glob pattern (e.g. `**/*.conf`), under \
                an optional root directory (default the current directory)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Glob pattern, e.g. **/*.rs" },
                    "root": { "type": "string", "description": "Directory to search under (default '.')." }
                },
                "required": ["pattern"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let pattern = arg_str(&arguments, "pattern")?;
        let root = arg_str_opt(&arguments, "root").unwrap_or_else(|| ".".to_string());
        let glob = Glob::new(&pattern)
            .map_err(|e| ToolError::invalid_args(format!("invalid glob `{pattern}`: {e}")))?
            .compile_matcher();

        let mut paths = Vec::new();
        let mut truncated = false;
        for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            if ctx.is_cancelled() {
                return Err(ToolError::Aborted);
            }
            if !entry.file_type().is_file() {
                continue;
            }
            // Match against the path relative to the search root when possible.
            let rel = entry.path().strip_prefix(&root).unwrap_or(entry.path());
            if glob.is_match(rel) || glob.is_match(entry.path()) {
                if paths.len() >= MAX_RESULTS {
                    truncated = true;
                    break;
                }
                paths.push(entry.path().to_string_lossy().into_owned());
            }
        }

        Ok(json!({ "paths": paths, "total": paths.len(), "truncated": truncated }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let paths = value.get("paths").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = String::new();
        for p in paths {
            if let Some(p) = p.as_str() {
                out.push_str(p);
                out.push('\n');
            }
        }
        if out.is_empty() {
            out.push_str("(no matches)");
        }
        if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str(&format!("[capped at {MAX_RESULTS} results]"));
        }
        vec![ContentBlock::text(out)]
    }
}

/// Search file contents by regular expression.
pub struct GrepTool;

#[async_trait]
impl Tool for GrepTool {
    fn name(&self) -> &str {
        "grep"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "grep".into(),
            description: "Search file contents by regular expression under a root directory, \
                returning matching lines grouped by file (path, line number, and line text)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regular expression to match per line." },
                    "root": { "type": "string", "description": "Directory to search under (default '.')." },
                    "glob": { "type": "string", "description": "Optional glob to restrict which files are searched." },
                    "max_results": { "type": "integer", "description": "Cap on total matches (default 400)." }
                },
                "required": ["pattern"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let pattern = arg_str(&arguments, "pattern")?;
        let root = arg_str_opt(&arguments, "root").unwrap_or_else(|| ".".to_string());
        let cap = arg_u64_opt(&arguments, "max_results").unwrap_or(MAX_RESULTS as u64) as usize;
        let re = Regex::new(&pattern)
            .map_err(|e| ToolError::invalid_args(format!("invalid regex `{pattern}`: {e}")))?;
        let file_filter = match arg_str_opt(&arguments, "glob") {
            Some(g) => Some(
                Glob::new(&g)
                    .map_err(|e| ToolError::invalid_args(format!("invalid glob `{g}`: {e}")))?
                    .compile_matcher(),
            ),
            None => None,
        };

        // Grouped by file: path -> Vec<{ line, text }>.
        let mut groups: Vec<Value> = Vec::new();
        let mut total = 0usize;
        let mut truncated = false;

        'walk: for entry in WalkDir::new(&root).into_iter().filter_map(Result::ok) {
            if ctx.is_cancelled() {
                return Err(ToolError::Aborted);
            }
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.metadata().map(|m| m.len()).unwrap_or(0) > MAX_GREP_FILE_BYTES {
                continue;
            }
            if let Some(filter) = &file_filter {
                let rel = entry.path().strip_prefix(&root).unwrap_or(entry.path());
                if !filter.is_match(rel) && !filter.is_match(entry.path()) {
                    continue;
                }
            }
            let Ok(content) = std::fs::read_to_string(entry.path()) else {
                continue; // skip binary / unreadable files
            };
            let mut lines = Vec::new();
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    if total >= cap {
                        truncated = true;
                        // Flush the matches already found in THIS file before
                        // breaking, so they are not lost and `total` stays
                        // consistent with the returned groups.
                        if !lines.is_empty() {
                            groups.push(json!({
                                "path": entry.path().to_string_lossy(),
                                "matches": std::mem::take(&mut lines),
                            }));
                        }
                        break 'walk;
                    }
                    lines.push(json!({ "line": i + 1, "text": line }));
                    total += 1;
                }
            }
            if !lines.is_empty() {
                groups.push(json!({ "path": entry.path().to_string_lossy(), "matches": lines }));
            }
        }

        Ok(json!({ "files": groups, "total": total, "truncated": truncated }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let empty = Vec::new();
        let files = value.get("files").and_then(Value::as_array).unwrap_or(&empty);
        let mut out = String::new();
        for file in files {
            let path = file.get("path").and_then(Value::as_str).unwrap_or("");
            if let Some(matches) = file.get("matches").and_then(Value::as_array) {
                for m in matches {
                    let line = m.get("line").and_then(Value::as_u64).unwrap_or(0);
                    let text = m.get("text").and_then(Value::as_str).unwrap_or("");
                    out.push_str(&format!("{path}:{line}: {text}\n"));
                }
            }
        }
        if out.is_empty() {
            out.push_str("(no matches)");
        }
        if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("[results capped]");
        }
        vec![ContentBlock::text(out)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("a.txt"), "alpha\npassword=secret\n").await.unwrap();
        tokio::fs::write(dir.path().join("b.rs"), "fn main() { let key = 1; }\n").await.unwrap();
        dir
    }

    #[tokio::test]
    async fn glob_finds_by_pattern() {
        let dir = fixture().await;
        let value = GlobTool
            .execute(json!({ "pattern": "**/*.rs", "root": dir.path().to_str().unwrap() }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["total"], 1);
        assert!(value["paths"][0].as_str().unwrap().ends_with("b.rs"));
    }

    #[tokio::test]
    async fn grep_finds_matching_lines() {
        let dir = fixture().await;
        let value = GrepTool
            .execute(json!({ "pattern": "password|key", "root": dir.path().to_str().unwrap() }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(value["total"], 2);
    }

    #[tokio::test]
    async fn grep_flushes_in_progress_file_when_cap_hits_mid_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("m.txt"), "hit one\nhit two\n").await.unwrap();
        let value = GrepTool
            .execute(
                json!({ "pattern": "hit", "root": dir.path().to_str().unwrap(), "max_results": 1 }),
                &ExecCtx::new(),
            )
            .await
            .unwrap();
        assert_eq!(value["total"], 1);
        assert_eq!(value["truncated"], true);
        // The one within-cap match must survive, not be dropped when the cap trips.
        assert_eq!(value["files"].as_array().unwrap().len(), 1);
        assert_eq!(value["files"][0]["matches"][0]["text"], "hit one");
    }

    #[tokio::test]
    async fn grep_respects_glob_filter() {
        let dir = fixture().await;
        let value = GrepTool
            .execute(
                json!({ "pattern": ".", "root": dir.path().to_str().unwrap(), "glob": "**/*.txt" }),
                &ExecCtx::new(),
            )
            .await
            .unwrap();
        // Only a.txt (2 lines) should be searched.
        assert_eq!(value["total"], 2);
    }
}
