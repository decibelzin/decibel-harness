//! Model-facing [`Tool`] wrappers over the pure smart-contract analyzers. The
//! two scanners run an in-process pattern engine (no `solc`, no network) over an
//! inline Solidity string or a workspace file resolved through
//! [`ExecCtx::resolve`]; the three Foundry generators are pure string builders
//! that emit a ready-to-drop `.sol` forge test (they run nothing). Each tool
//! returns its serde struct as the canonical value, so a UI card and a future
//! Code Mode read the same fact the model saw.

use async_trait::async_trait;
use decibel_llm::{ContentBlock, ToolSchema};
use decibel_tools::{ExecCtx, Tool, ToolError};
use serde_json::{json, Value};

use crate::contracts::{foundry, scan};
use crate::util::arg_str;

/// Serialize an analyzer result into the canonical tool value, mapping a serde
/// failure to an execution error.
fn to_value<T: serde::Serialize>(v: T) -> Result<Value, ToolError> {
    serde_json::to_value(v).map_err(|e| ToolError::execution(e.to_string()))
}

/// Render a scanner `findings` array (severity/id/line/detail) into a summary.
fn render_scan(header: &str, value: &Value) -> String {
    let empty = Vec::new();
    let findings = value.get("findings").and_then(Value::as_array).unwrap_or(&empty);
    if findings.is_empty() {
        return format!("{header}\n(no findings)");
    }
    let mut out = format!("{header} — {} finding(s)\n", findings.len());
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        let id = f.get("id").and_then(Value::as_str).unwrap_or("");
        let line = f.get("line").and_then(Value::as_u64).unwrap_or(0);
        let detail = f.get("detail").and_then(Value::as_str).unwrap_or("");
        out.push_str(&format!("  L{line} [{sev}] {id}: {detail}\n"));
    }
    out
}

/// Render a generated PoC test (path + full source) so the model can write it.
fn render_poc(header: &str, value: &Value) -> Vec<ContentBlock> {
    let path = value.get("path").and_then(Value::as_str).unwrap_or("");
    let source = value.get("source").and_then(Value::as_str).unwrap_or("");
    vec![ContentBlock::text(format!("{header} → {path}\n\n{source}"))]
}

/// Scan an inline Solidity source string for vulnerability patterns (offline).
pub struct SolidityScanTool;

#[async_trait]
impl Tool for SolidityScanTool {
    fn name(&self) -> &str {
        "solidity_scan"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "solidity_scan".into(),
            description: "Scan Solidity source (passed inline) for the classic vulnerability classes, \
                line-anchored: reentrancy (`.call{value:}`), `tx.origin` auth, `delegatecall`, weak \
                on-chain randomness, `selfdestruct`, unchecked `.send()`, flash-loan callbacks, \
                manipulable spot-price oracles (`getReserves()`), inline assembly, floating pragma, and \
                unchecked `ecrecover`. A high-signal pattern engine (comments are stripped so \
                commented-out code doesn't false-flag) — NOT a compiler. Offline, no solc. Use \
                `solidity_scan_file` to scan a file on disk instead."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "The Solidity source code to scan." }
                },
                "required": ["source"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let source = arg_str(&arguments, "source")?;
        to_value(scan::scan(&source))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        vec![ContentBlock::text(render_scan("solidity_scan", value))]
    }
}

/// Scan a Solidity file resolved in the workspace for vulnerability patterns (offline).
pub struct SolidityScanFileTool;

#[async_trait]
impl Tool for SolidityScanFileTool {
    fn name(&self) -> &str {
        "solidity_scan_file"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "solidity_scan_file".into(),
            description: "Scan a Solidity `.sol` file (read from the workspace) for the classic \
                vulnerability classes — same line-anchored pattern engine as `solidity_scan`: \
                reentrancy, `tx.origin` auth, `delegatecall`, weak randomness, `selfdestruct`, \
                unchecked `.send()`, flash-loan callbacks, spot-price oracles, inline assembly, \
                floating pragma, and unchecked `ecrecover`. Offline, no solc. The value carries the \
                resolved `path` alongside the findings."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to the Solidity file (absolute, or relative to the workspace)." }
                },
                "required": ["path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, ctx: &ExecCtx) -> Result<Value, ToolError> {
        let path = ctx.resolve(&arg_str(&arguments, "path")?);
        let source = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| ToolError::execution(format!("cannot read {}: {e}", path.display())))?;
        let mut value = to_value(scan::scan(&source))?;
        if let Value::Object(ref mut m) = value {
            m.insert("path".into(), json!(path.display().to_string()));
        }
        Ok(value)
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        let path = value.get("path").and_then(Value::as_str).unwrap_or("");
        vec![ContentBlock::text(render_scan(&format!("solidity_scan_file {path}"), value))]
    }
}

/// Generate a Foundry reentrancy PoC test (`.sol` source only — offline).
pub struct FoundryReentrancyTestTool;

#[async_trait]
impl Tool for FoundryReentrancyTestTool {
    fn name(&self) -> &str {
        "foundry_reentrancy_test"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "foundry_reentrancy_test".into(),
            description: "Generate a Foundry (forge-std) reentrancy PoC test targeting `function` on \
                contract `target`. The test re-enters the target through the attacker's `receive()` \
                while the first call is in flight and asserts the target loses at most one withdrawal. \
                Returns the file `path` and the `.sol` `source` only — it compiles/runs nothing. Write \
                the file and run `forge test` yourself."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "The target contract's name (e.g. Vault)." },
                    "function": { "type": "string", "description": "The withdrawal/entry function to re-enter (e.g. withdraw)." },
                    "target_path": { "type": "string", "description": "Solidity import path to the target contract (e.g. ../src/Vault.sol)." }
                },
                "required": ["target", "function", "target_path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let target = arg_str(&arguments, "target")?;
        let function = arg_str(&arguments, "function")?;
        let target_path = arg_str(&arguments, "target_path")?;
        to_value(foundry::reentrancy_test(&target, &function, &target_path))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        render_poc("foundry_reentrancy_test", value)
    }
}

/// Generate a Foundry access-control PoC test (`.sol` source only — offline).
pub struct FoundryAccessTestTool;

#[async_trait]
impl Tool for FoundryAccessTestTool {
    fn name(&self) -> &str {
        "foundry_access_test"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "foundry_access_test".into(),
            description: "Generate a Foundry (forge-std) access-control PoC test that calls `function` \
                on contract `target` as a non-owner (via `vm.prank`) and asserts it reverts \
                (`vm.expectRevert`). Returns the file `path` and the `.sol` `source` only — it \
                compiles/runs nothing. Write the file and run `forge test` yourself."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "The target contract's name (e.g. Token)." },
                    "function": { "type": "string", "description": "The privileged function that should reject non-owners (e.g. mint)." },
                    "target_path": { "type": "string", "description": "Solidity import path to the target contract (e.g. ../src/Token.sol)." }
                },
                "required": ["target", "function", "target_path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let target = arg_str(&arguments, "target")?;
        let function = arg_str(&arguments, "function")?;
        let target_path = arg_str(&arguments, "target_path")?;
        to_value(foundry::access_test(&target, &function, &target_path))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        render_poc("foundry_access_test", value)
    }
}

/// Generate a Foundry flash-loan callback PoC test (`.sol` source only — offline).
pub struct FoundryFlashloanTestTool;

#[async_trait]
impl Tool for FoundryFlashloanTestTool {
    fn name(&self) -> &str {
        "foundry_flashloan_test"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "foundry_flashloan_test".into(),
            description: "Generate a Foundry (forge-std) flash-loan PoC test that invokes contract \
                `target`'s `onFlashLoan` callback from an unexpected caller (via `vm.prank`) and \
                asserts it reverts — the callback must authenticate the pool and initiator. Returns the \
                file `path` and the `.sol` `source` only — it compiles/runs nothing; adjust the \
                selector/args to the target's actual callback signature. Write the file and run \
                `forge test` yourself."
                .into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "target": { "type": "string", "description": "The target contract's name (e.g. Pool)." },
                    "target_path": { "type": "string", "description": "Solidity import path to the target contract (e.g. ../src/Pool.sol)." }
                },
                "required": ["target", "target_path"]
            }),
        }
    }

    async fn execute(&self, arguments: Value, _ctx: &ExecCtx) -> Result<Value, ToolError> {
        let target = arg_str(&arguments, "target")?;
        let target_path = arg_str(&arguments, "target_path")?;
        to_value(foundry::flashloan_test(&target, &target_path))
    }

    fn render(&self, _arguments: &Value, value: &Value) -> Vec<ContentBlock> {
        render_poc("foundry_flashloan_test", value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decibel_llm::CallId;
    use decibel_tools::{Tool, ToolRegistry};
    use std::sync::Arc;

    async fn run(tool: Arc<dyn Tool>, args: Value) -> decibel_tools::ToolResult {
        run_in(tool, args, ExecCtx::new()).await
    }

    async fn run_in(tool: Arc<dyn Tool>, args: Value, ctx: ExecCtx) -> decibel_tools::ToolResult {
        let mut reg = ToolRegistry::new();
        let name = tool.name().to_string();
        reg.register(tool);
        reg.execute(
            decibel_tools::ToolCall { call_id: CallId::from("c1"), name, arguments: args },
            &ctx,
        )
        .await
    }

    const VULN_SRC: &str = r#"
        pragma solidity ^0.8.0;
        contract Vault {
            function withdraw() public {
                require(tx.origin == owner);
                (bool ok,) = msg.sender.call{value: bal}("");
                bal = 0;
            }
        }
    "#;

    #[tokio::test]
    async fn solidity_scan_flags_the_classic_classes() {
        let r = run(Arc::new(SolidityScanTool), json!({ "source": VULN_SRC })).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        let ids: Vec<&str> = v["findings"].as_array().unwrap().iter().map(|f| f["id"].as_str().unwrap()).collect();
        for want in ["reentrancy", "tx_origin_auth", "floating_pragma"] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
        // Line numbers are 1-based and reported.
        assert!(v["findings"].as_array().unwrap().iter().all(|f| f["line"].as_u64().unwrap() >= 1));
    }

    #[tokio::test]
    async fn solidity_scan_file_reads_a_workspace_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Vault.sol"), VULN_SRC).await.unwrap();
        // Relative path exercises ctx.resolve against the session workspace.
        let ctx = ExecCtx::new().with_cwd(dir.path());
        let r = run_in(Arc::new(SolidityScanFileTool), json!({ "path": "Vault.sol" }), ctx).await;
        assert!(!r.is_error);
        let v = r.value.unwrap();
        assert!(v["path"].as_str().unwrap().ends_with("Vault.sol"));
        assert!(v["findings"].as_array().unwrap().iter().any(|f| f["id"] == "reentrancy"));
    }

    #[tokio::test]
    async fn solidity_scan_file_missing_file_is_execution_error() {
        let r = run(Arc::new(SolidityScanFileTool), json!({ "path": "/no/such/Contract.sol" })).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("EXEC_ERROR"));
    }

    #[tokio::test]
    async fn foundry_generators_emit_wellformed_sol() {
        let re = run(
            Arc::new(FoundryReentrancyTestTool),
            json!({ "target": "Vault", "function": "withdraw", "target_path": "../src/Vault.sol" }),
        )
        .await;
        let rv = re.value.unwrap();
        assert_eq!(rv["path"], "test/Vault_Reentrancy.t.sol");
        assert!(rv["source"].as_str().unwrap().contains("contract VaultReentrancyTest is Test"));
        assert!(rv["source"].as_str().unwrap().contains("target.withdraw();"));

        let ac = run(
            Arc::new(FoundryAccessTestTool),
            json!({ "target": "Token", "function": "mint", "target_path": "../src/Token.sol" }),
        )
        .await;
        let av = ac.value.unwrap();
        assert_eq!(av["path"], "test/Token_Access.t.sol");
        assert!(av["source"].as_str().unwrap().contains("vm.expectRevert();"));
        assert!(av["source"].as_str().unwrap().contains("target.mint();"));

        let fl = run(
            Arc::new(FoundryFlashloanTestTool),
            json!({ "target": "Pool", "target_path": "../src/Pool.sol" }),
        )
        .await;
        let fv = fl.value.unwrap();
        assert_eq!(fv["path"], "test/Pool_FlashLoan.t.sol");
        assert!(fv["source"].as_str().unwrap().contains("onFlashLoan"));
        assert!(fv["source"].as_str().unwrap().contains("vm.prank(address(0xBAD));"));
    }

    #[tokio::test]
    async fn missing_required_arg_is_invalid_args() {
        let r = run(Arc::new(SolidityScanTool), json!({})).await;
        assert!(r.is_error);
        assert_eq!(r.error_code.as_deref(), Some("INVALID_ARGS"));

        let r2 = run(Arc::new(FoundryReentrancyTestTool), json!({ "target": "Vault" })).await;
        assert!(r2.is_error);
        assert_eq!(r2.error_code.as_deref(), Some("INVALID_ARGS"));
    }
}
