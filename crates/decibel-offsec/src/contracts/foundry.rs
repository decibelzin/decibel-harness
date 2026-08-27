//! Foundry PoC-test generators. Each returns a ready-to-drop `.sol` forge test
//! (path + source); the agent writes it and runs `forge test` via the shell.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PocTest {
    pub path: String,
    pub source: String,
}

const HEADER: &str = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.13;\n\nimport \"forge-std/Test.sol\";\n";

/// Reentrancy PoC: re-enters `function` through the attacker's `receive()` and
/// asserts the target didn't leak more than a single withdrawal.
pub fn reentrancy_test(target: &str, function: &str, target_path: &str) -> PocTest {
    let source = format!(
        "{HEADER}import \"{target_path}\";\n\n\
contract {target}ReentrancyTest is Test {{\n\
\x20   {target} internal target;\n\
\x20   uint256 internal reenterCount;\n\n\
\x20   function setUp() public {{\n\
\x20       target = new {target}();\n\
\x20       vm.deal(address(target), 10 ether);\n\
\x20       vm.deal(address(this), 1 ether);\n\
\x20   }}\n\n\
\x20   // Re-enter the target while the first call is still in flight.\n\
\x20   receive() external payable {{\n\
\x20       if (reenterCount < 5 && address(target).balance >= 1 ether) {{\n\
\x20           reenterCount++;\n\
\x20           target.{function}();\n\
\x20       }}\n\
\x20   }}\n\n\
\x20   function testReentrancy() public {{\n\
\x20       uint256 balBefore = address(target).balance;\n\
\x20       target.{function}();\n\
\x20       // A reentrancy-safe target loses at most one withdrawal.\n\
\x20       assertGe(address(target).balance, balBefore - 1 ether, \"reentrancy drained more than one call\");\n\
\x20   }}\n\
}}\n"
    );
    PocTest { path: format!("test/{target}_Reentrancy.t.sol"), source }
}

/// Access-control PoC: calls `function` as a non-owner and asserts it reverts.
pub fn access_test(target: &str, function: &str, target_path: &str) -> PocTest {
    let source = format!(
        "{HEADER}import \"{target_path}\";\n\n\
contract {target}AccessTest is Test {{\n\
\x20   {target} internal target;\n\
\x20   address internal attacker = address(0xBEEF);\n\n\
\x20   function setUp() public {{ target = new {target}(); }}\n\n\
\x20   function testUnauthorizedCallReverts() public {{\n\
\x20       vm.prank(attacker);\n\
\x20       // A privileged function called by a non-owner MUST revert.\n\
\x20       vm.expectRevert();\n\
\x20       target.{function}();\n\
\x20   }}\n\
}}\n"
    );
    PocTest { path: format!("test/{target}_Access.t.sol"), source }
}

/// Flash-loan PoC: invokes the callback from an unexpected caller and asserts it
/// rejects (the callback must authenticate the pool + initiator).
pub fn flashloan_test(target: &str, target_path: &str) -> PocTest {
    let source = format!(
        "{HEADER}import \"{target_path}\";\n\n\
contract {target}FlashLoanTest is Test {{\n\
\x20   {target} internal target;\n\n\
\x20   function setUp() public {{ target = new {target}(); }}\n\n\
\x20   function testFlashLoanCallbackRejectsUnknownCaller() public {{\n\
\x20       vm.prank(address(0xBAD));\n\
\x20       // The callback must reject a caller that is not the expected pool.\n\
\x20       // Adjust the selector/args to the target's actual callback signature.\n\
\x20       vm.expectRevert();\n\
\x20       target.onFlashLoan(address(this), address(0), 0, 0, \"\");\n\
\x20   }}\n\
}}\n"
    );
    PocTest { path: format!("test/{target}_FlashLoan.t.sol"), source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentrancy_template_interpolates_and_is_well_formed() {
        let t = reentrancy_test("Vault", "withdraw", "../src/Vault.sol");
        assert_eq!(t.path, "test/Vault_Reentrancy.t.sol");
        assert!(t.source.contains("import \"forge-std/Test.sol\";"));
        assert!(t.source.contains("import \"../src/Vault.sol\";"));
        assert!(t.source.contains("contract VaultReentrancyTest is Test"));
        assert!(t.source.contains("target.withdraw();"));
        // Braces must balance (a crude but useful well-formedness check).
        assert_eq!(t.source.matches('{').count(), t.source.matches('}').count());
    }

    #[test]
    fn access_template_targets_the_function_as_attacker() {
        let t = access_test("Token", "mint", "../src/Token.sol");
        assert_eq!(t.path, "test/Token_Access.t.sol");
        assert!(t.source.contains("vm.prank(attacker);"));
        assert!(t.source.contains("vm.expectRevert();"));
        assert!(t.source.contains("target.mint();"));
        assert_eq!(t.source.matches('{').count(), t.source.matches('}').count());
    }

    #[test]
    fn flashloan_template_calls_the_callback_from_a_bad_caller() {
        let t = flashloan_test("Pool", "../src/Pool.sol");
        assert_eq!(t.path, "test/Pool_FlashLoan.t.sol");
        assert!(t.source.contains("onFlashLoan"));
        assert!(t.source.contains("vm.prank(address(0xBAD));"));
        assert_eq!(t.source.matches('{').count(), t.source.matches('}').count());
    }
}
