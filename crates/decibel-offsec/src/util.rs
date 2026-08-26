//! Shared argument-parsing helpers so every tool validates model input the same
//! way and produces a uniform `INVALID_ARGS` failure.

use decibel_tools::ToolError;
use serde_json::Value;

/// Read a required non-empty string argument.
pub fn arg_str(args: &Value, key: &str) -> Result<String, ToolError> {
    match args.get(key).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        Some(_) => Err(ToolError::invalid_args(format!("`{key}` must be a non-empty string"))),
        None => Err(ToolError::invalid_args(format!("missing required string `{key}`"))),
    }
}

/// Read an optional string argument (absent or `null` → `None`).
pub fn arg_str_opt(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Read an optional positive integer argument.
pub fn arg_u64_opt(args: &Value, key: &str) -> Option<u64> {
    args.get(key).and_then(Value::as_u64)
}

/// Read an optional boolean argument, defaulting when absent.
pub fn arg_bool(args: &Value, key: &str, default: bool) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Truncate a string to a byte budget, appending a marker when it was cut. Used
/// so a huge tool output does not flood the model context.
pub fn truncate_bytes(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_string(), false);
    }
    // Cut on a UTF-8 boundary at or before `max`.
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn required_string_validation() {
        let args = json!({ "a": "x", "b": "", "c": 5 });
        assert_eq!(arg_str(&args, "a").unwrap(), "x");
        assert!(arg_str(&args, "b").is_err()); // empty
        assert!(arg_str(&args, "c").is_err()); // wrong type
        assert!(arg_str(&args, "missing").is_err());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let (out, cut) = truncate_bytes("hello", 100);
        assert_eq!(out, "hello");
        assert!(!cut);
        let (out, cut) = truncate_bytes("héllo", 2); // 'é' is 2 bytes at index 1..3
        assert!(cut);
        assert_eq!(out, "h"); // cannot include the partial 'é'
    }
}
