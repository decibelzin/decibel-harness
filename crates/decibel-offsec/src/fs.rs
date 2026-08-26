//! Filesystem tools: `read_file`, `write_file`, and `str_replace` (edit).
//!
//! No path sandbox — the agent reads and writes anywhere the process can. Reads
//! are line-addressable and capped; edits require the old text to match exactly
//! once so the model cannot blindly clobber a file.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::util::{arg_str, arg_u64_opt, truncate_bytes};

/// Cap on the bytes one read returns to the model.
const MAX_READ_BYTES: usize = 60_000;

/// Read a UTF-8 text file, optionally a line window.
pub struct ReadFileTool;

#[async_trait]
impl Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "read_file".into(),
            description: "Read a text file and return its contents, optionally a line window \
                (`offset` is the 1-based first line, `limit` the number of lines)."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute or relative file path." },
                    "offset": { "type": "integer", "description": "1-based first line to return." },
                    "limit": { "type": "integer", "description": "Maximum number of lines to return." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = arg_str(&arguments, "path")?;
        let raw = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| ToolError::execution(format!("cannot read {path}: {e}")))?;

        let total_lines = raw.lines().count() as u64;
        let offset = arg_u64_opt(&arguments, "offset").unwrap_or(1).max(1);
        let selected: String = if arguments.get("offset").is_some() || arguments.get("limit").is_some() {
            let limit = arg_u64_opt(&arguments, "limit").unwrap_or(u64::MAX);
            raw.lines()
                .skip((offset - 1) as usize)
                .take(limit as usize)
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            raw.clone()
        };
        let (content, truncated) = truncate_bytes(&selected, MAX_READ_BYTES);

        Ok(json!({
            "path": path,
            "content": content,
            "offset": offset,
            "total_lines": total_lines,
            "truncated": truncated,
        }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let content = value.get("content").and_then(Value::as_str).unwrap_or("");
        let mut out = content.to_string();
        if value.get("truncated").and_then(Value::as_bool).unwrap_or(false) {
            out.push_str("\n[truncated]");
        }
        vec![ContentBlock::text(out)]
    }
}

/// Create or overwrite a file with exact content.
pub struct WriteFileTool;

#[async_trait]
impl Tool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "write_file".into(),
            description: "Create or overwrite a file with the given content. Parent directories \
                are created as needed."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path to write." },
                    "content": { "type": "string", "description": "Full file content." }
                },
                "required": ["path", "content"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = arg_str(&arguments, "path")?;
        // content may legitimately be empty, so read it directly rather than via arg_str.
        let content = arguments
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_args("missing required string `content`"))?;

        // Observe cancellation before the irreversible write, so a cancelled
        // turn does not leave a modified file while the result reports Aborted.
        if ctx.is_cancelled() {
            return Err(ToolError::Aborted);
        }
        if let Some(parent) = std::path::Path::new(&path).parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| ToolError::execution(format!("cannot create {}: {e}", parent.display())))?;
            }
        }
        tokio::fs::write(&path, content)
            .await
            .map_err(|e| ToolError::execution(format!("cannot write {path}: {e}")))?;

        Ok(json!({ "path": path, "bytes_written": content.len() }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        let bytes = value.get("bytes_written").and_then(Value::as_u64).unwrap_or(0);
        vec![ContentBlock::text(format!("wrote {bytes} bytes to {path}"))]
    }
}

/// Replace one exact occurrence of a string in a file.
pub struct StrReplaceTool;

#[async_trait]
impl Tool for StrReplaceTool {
    fn name(&self) -> &str {
        "str_replace"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "str_replace".into(),
            description: "Replace one exact occurrence of `old_str` with `new_str` in a file. \
                The old text must appear exactly once, or the edit is rejected."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File to edit." },
                    "old_str": { "type": "string", "description": "Exact text to replace (must be unique)." },
                    "new_str": { "type": "string", "description": "Replacement text." }
                },
                "required": ["path", "old_str", "new_str"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = arg_str(&arguments, "path")?;
        let old_str = arg_str(&arguments, "old_str")?;
        let new_str = arguments
            .get("new_str")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::invalid_args("missing required string `new_str`"))?;

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| ToolError::execution(format!("cannot read {path}: {e}")))?;
        let matches = content.matches(&old_str).count();
        if matches == 0 {
            return Err(ToolError::execution(format!("`old_str` not found in {path}")));
        }
        if matches > 1 {
            return Err(ToolError::execution(format!(
                "`old_str` appears {matches} times in {path}; it must be unique — include more context"
            )));
        }
        // Observe cancellation before the irreversible write (same reason as write_file).
        if ctx.is_cancelled() {
            return Err(ToolError::Aborted);
        }
        let updated = content.replacen(&old_str, new_str, 1);
        tokio::fs::write(&path, &updated)
            .await
            .map_err(|e| ToolError::execution(format!("cannot write {path}: {e}")))?;

        Ok(json!({ "path": path, "replaced": true }))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(format!("edited {path}"))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_read_edit_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("f.txt");
        let path_str = path.to_str().unwrap();

        // write (creates parent dir)
        let w = WriteFileTool
            .execute(json!({ "path": path_str, "content": "line one\nline two\n" }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(w["bytes_written"], 18); // "line one\nline two\n" = 18 bytes

        // read
        let r = ReadFileTool
            .execute(json!({ "path": path_str }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(r["content"], "line one\nline two\n");
        assert_eq!(r["total_lines"], 2);

        // read a window
        let r2 = ReadFileTool
            .execute(json!({ "path": path_str, "offset": 2, "limit": 1 }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(r2["content"], "line two");

        // edit
        StrReplaceTool
            .execute(json!({ "path": path_str, "old_str": "line one", "new_str": "LINE 1" }), &ExecCtx::new())
            .await
            .unwrap();
        let r3 = ReadFileTool
            .execute(json!({ "path": path_str }), &ExecCtx::new())
            .await
            .unwrap();
        assert_eq!(r3["content"], "LINE 1\nline two\n");
    }

    #[tokio::test]
    async fn cancelled_write_does_not_touch_disk() {
        use tokio_util::sync::CancellationToken;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard.txt");
        let path_str = path.to_str().unwrap();
        let token = CancellationToken::new();
        token.cancel();
        let ctx = ExecCtx::with_token(token);

        let err = WriteFileTool
            .execute(json!({ "path": path_str, "content": "should not land" }), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code(), "ABORTED");
        assert!(!path.exists(), "a cancelled write must not create the file");
    }

    #[tokio::test]
    async fn non_unique_edit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.txt");
        let path_str = path.to_str().unwrap();
        tokio::fs::write(&path, "x\nx\n").await.unwrap();
        let err = StrReplaceTool
            .execute(json!({ "path": path_str, "old_str": "x", "new_str": "y" }), &ExecCtx::new())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "EXEC_ERROR");
    }
}
