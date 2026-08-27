//! Pure, offline binary reversing-triage — ported from Decepticon's
//! `tools/reversing` triage bucket (crate `decepticon-reversing`) into Decibel
//! with **no executor dependency**: the fast, in-process first pass that feeds
//! heavier tools like Ghidra/Ropper. Five capabilities, all operating on raw
//! bytes so they are deterministic and unit-testable with crafted fixtures:
//! `identify`, `strings`, `packer`, `rop`, `symbols`.
//!
//! Surfaced as model-facing tools in [`tools`]: `bin_identify`, `bin_strings`,
//! `bin_packer`, `bin_rop`, `bin_symbols_report`. Each analyzer returns a serde
//! struct so the tool layer hands it straight to the model (and, later, the
//! knowledge graph) as a canonical value.

pub mod identify;
pub mod packer;
pub mod rop;
pub mod strings;
pub mod symbols;
pub mod tools;

/// Shannon entropy in bits/byte (0..8) of a byte slice — the packer signal.
pub(crate) fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7, 7, 7, 7]), 0.0); // one symbol → 0 bits
        // All 256 byte values once each → 8 bits (maximum).
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
