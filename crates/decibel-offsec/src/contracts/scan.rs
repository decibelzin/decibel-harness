//! Offline Solidity vulnerability pattern scanner — the classic issue classes,
//! line-anchored. A pattern engine (not a compiler): high-signal, low-noise
//! heuristics that point an auditor at the lines worth a closer look.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::contracts::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
}

struct Rule {
    id: &'static str,
    severity: &'static str,
    re: Regex,
    detail: &'static str,
}

fn rules() -> Vec<Rule> {
    let r = |id, severity, pat: &str, detail| Rule { id, severity, re: Regex::new(pat).expect("static regex"), detail };
    vec![
        r("reentrancy", "high", r"\.call\s*\{\s*value\s*:|\.call\.value\s*\(", "Low-level `.call{value:}` sends ETH and hands control to the callee — guard state changes before it (checks-effects-interactions / nonReentrant)."),
        r("tx_origin_auth", "high", r"tx\.origin\s*==|==\s*tx\.origin", "`tx.origin` used for authorization — phishable; use `msg.sender`."),
        r("delegatecall", "high", r"\.delegatecall\s*\(", "`delegatecall` executes callee code in this contract's context — a user-controlled target is full compromise."),
        r("weak_randomness", "medium", r"block\.(timestamp|number|difficulty|prevrandao)|blockhash\s*\(", "On-chain value used as randomness — miners/validators can influence it. Use a VRF."),
        r("selfdestruct", "high", r"\bselfdestruct\s*\(|\bsuicide\s*\(", "`selfdestruct` present — ensure it is access-controlled; it can brick or drain the contract."),
        r("unchecked_send", "medium", r"\.send\s*\(", "`.send()` returns a bool that is easy to ignore — check it or use a pull-payment pattern."),
        r("flashloan_callback", "medium", r"function\s+(onFlashLoan|executeOperation|uniswapV2Call|receiveFlashLoan|pancakeCall)\s*\(", "Flash-loan callback — it MUST verify the caller is the expected pool and the initiator is this contract."),
        r("oracle_spot_price", "medium", r"getReserves\s*\(\s*\)", "`getReserves()` reads a manipulable spot price — a flash-loan can skew it. Use a TWAP / robust oracle."),
        r("assembly", "low", r"\bassembly\s*\{", "Inline assembly bypasses Solidity's safety checks — audit it carefully."),
        r("floating_pragma", "low", r"pragma\s+solidity\s+\^", "Floating pragma (`^`) — pin an exact compiler version for reproducible, audited builds."),
    ]
}

/// Scan Solidity `source` for vulnerability patterns, reporting 1-based lines.
/// Line and block comments are stripped so commented-out code doesn't false-flag.
pub fn scan(source: &str) -> ScanResult {
    let cleaned = strip_comments(source);
    let rules = rules();
    let mut findings = Vec::new();

    for (i, line) in cleaned.lines().enumerate() {
        for rule in &rules {
            if rule.re.is_match(line) {
                findings.push(Finding {
                    severity: rule.severity.into(),
                    id: rule.id.into(),
                    line: i + 1,
                    detail: rule.detail.into(),
                });
            }
        }
    }

    // Whole-source check: ecrecover whose result isn't compared against address(0).
    if Regex::new(r"ecrecover\s*\(").unwrap().is_match(&cleaned) && !Regex::new(r"==\s*address\(0\)|!=\s*address\(0\)|address\(0\)\s*==|address\(0\)\s*!=").unwrap().is_match(&cleaned) {
        let line = cleaned.lines().position(|l| l.contains("ecrecover")).map(|n| n + 1).unwrap_or(0);
        findings.push(Finding {
            severity: "high".into(),
            id: "unchecked_ecrecover".into(),
            line,
            detail: "`ecrecover` result is not checked against `address(0)` — a malformed signature returns zero and can bypass the check.".into(),
        });
    }

    ScanResult { findings }
}

/// Remove `// line` and `/* block */` comments (keeps line count stable by
/// blanking rather than deleting).
fn strip_comments(src: &str) -> String {
    let no_block = Regex::new(r"(?s)/\*.*?\*/").unwrap().replace_all(src, |m: &regex::Captures| {
        // preserve newlines inside the block so line numbers don't shift
        m[0].chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect::<String>()
    });
    no_block
        .lines()
        .map(|l| match l.find("//") {
            Some(i) => l[..i].to_string(),
            None => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(src: &str) -> Vec<String> {
        scan(src).findings.into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn flags_reentrancy_txorigin_delegatecall() {
        let src = r#"
            pragma solidity ^0.8.0;
            contract Bad {
                function withdraw() public {
                    require(tx.origin == owner);
                    (bool ok,) = msg.sender.call{value: bal}("");
                    bal = 0;
                }
                function admin(address t) public { t.delegatecall(msg.data); }
            }
        "#;
        let ids = ids(src);
        for want in ["reentrancy", "tx_origin_auth", "delegatecall", "floating_pragma"] {
            assert!(ids.iter().any(|s| s == want), "missing {want}: {ids:?}");
        }
    }

    #[test]
    fn flags_weak_randomness_and_unchecked_ecrecover() {
        let src = r#"
            uint r = uint(blockhash(block.number - 1)) % 100;
            address signer = ecrecover(h, v, rs, ss);
        "#;
        let ids = ids(src);
        assert!(ids.iter().any(|s| s == "weak_randomness"));
        assert!(ids.iter().any(|s| s == "unchecked_ecrecover"));
    }

    #[test]
    fn ecrecover_checked_against_zero_is_not_flagged() {
        let src = r#"
            address signer = ecrecover(h, v, rs, ss);
            require(signer != address(0), "bad sig");
        "#;
        assert!(!ids(src).iter().any(|s| s == "unchecked_ecrecover"));
    }

    #[test]
    fn commented_out_code_does_not_false_flag() {
        let src = "// (bool ok,) = msg.sender.call{value: x}(\"\");\nuint a = 1;";
        assert!(scan(src).findings.is_empty(), "{:?}", scan(src).findings);
    }

    #[test]
    fn reports_line_numbers() {
        let src = "line1\nline2 selfdestruct(payable(msg.sender));\nline3";
        let f = scan(src).findings.iter().find(|f| f.id == "selfdestruct").cloned().unwrap();
        assert_eq!(f.line, 2);
    }
}
