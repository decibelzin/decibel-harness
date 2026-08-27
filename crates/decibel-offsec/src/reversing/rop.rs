//! ROP-gadget first pass: scan for x86 RET opcodes and emit the byte window
//! ending at each. NOT a disassembler — a fast triage that feeds Ropper/ROPgadget
//! (matching the upstream `bin_rop`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gadget {
    pub offset: usize,
    pub length: usize,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RopScan {
    pub total: usize,
    pub gadgets: Vec<Gadget>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

/// Parse a hex pattern like "ff d0" / "ffd0" into bytes (None if malformed).
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() || clean.len() % 2 != 0 {
        return None;
    }
    (0..clean.len()).step_by(2).map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok()).collect()
}

/// Scan `bytes` for RET-terminated gadgets. Each gadget is the window of up to
/// `max_length` bytes ending at a RET opcode. `pattern_hex` (if set) keeps only
/// gadgets whose bytes contain that sequence. At most `limit` gadgets returned.
pub fn scan(bytes: &[u8], max_length: usize, limit: usize, pattern_hex: Option<&str>) -> RopScan {
    let max_len = max_length.clamp(1, 32);
    let want = pattern_hex.and_then(parse_hex);
    let mut gadgets = Vec::new();
    let mut total = 0;

    for (i, &b) in bytes.iter().enumerate() {
        // RET opcodes: C3 (ret), CB (retf); C2/CA take a 2-byte immediate that
        // follows, so the opcode terminates the gadget at i (the imm is trailing).
        let is_ret = matches!(b, 0xC3 | 0xCB | 0xC2 | 0xCA);
        if !is_ret {
            continue;
        }
        let start = i.saturating_sub(max_len - 1);
        let window = &bytes[start..=i];
        if let Some(p) = &want {
            if !window.windows(p.len()).any(|w| w == p.as_slice()) {
                continue;
            }
        }
        total += 1;
        if gadgets.len() < limit {
            gadgets.push(Gadget { offset: start, length: window.len(), bytes_hex: hex(window) });
        }
    }
    RopScan { total, gadgets }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ret_terminated_windows() {
        // pop rax ; ret  = 58 c3   |   xor eax,eax ; ret = 31 c0 c3
        let code = [0x58, 0xc3, 0x31, 0xc0, 0xc3];
        let s = scan(&code, 4, 10, None);
        assert_eq!(s.total, 2);
        assert!(s.gadgets.iter().any(|g| g.bytes_hex == "58c3"));
        assert!(s.gadgets.iter().any(|g| g.bytes_hex.ends_with("c3") && g.bytes_hex.contains("31c0")));
    }

    #[test]
    fn pattern_filter_keeps_only_matching_gadgets() {
        let code = [0x58, 0xc3, 0xff, 0xd0, 0xc3]; // second gadget contains ff d0 (call rax)
        let s = scan(&code, 6, 10, Some("ffd0"));
        assert_eq!(s.gadgets.len(), 1);
        assert!(s.gadgets[0].bytes_hex.contains("ffd0"));
    }

    #[test]
    fn limit_caps_returned_but_counts_all() {
        let code = vec![0xc3; 50];
        let s = scan(&code, 2, 5, None);
        assert_eq!(s.total, 50);
        assert_eq!(s.gadgets.len(), 5);
    }

    #[test]
    fn malformed_pattern_is_ignored() {
        // odd-length hex → treated as no filter.
        let code = [0x58, 0xc3];
        assert_eq!(scan(&code, 4, 10, Some("abc")).total, 1);
    }
}
