//! Packer detection: overall Shannon entropy + known packer byte-signatures.

use serde::{Deserialize, Serialize};

use crate::reversing::entropy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackerVerdict {
    pub entropy: f64,
    pub packed: bool,
    pub signatures: Vec<String>,
}

/// (human name, signature bytes) — the common packers' section names / markers.
const SIGNATURES: &[(&str, &[u8])] = &[
    ("UPX", b"UPX!"),
    ("UPX", b"UPX0"),
    ("UPX", b"UPX1"),
    ("ASPack", b".aspack"),
    ("ASPack", b"ASPack"),
    ("PECompact", b"PECompact"),
    ("FSG", b"FSG!"),
    ("MPRESS", b".MPRESS"),
    ("Themida", b"Themida"),
    ("MEW", b"MEW"),
    ("Petite", b".petite"),
    ("NsPack", b".nsp0"),
    ("Enigma", b".enigma"),
    ("VMProtect", b".vmp0"),
    ("UPX (macho)", b"__XHDR"),
];

/// Detect packing: high entropy (> 7.2 bits/byte) OR a known signature.
pub fn detect(bytes: &[u8]) -> PackerVerdict {
    let ent = entropy(bytes);
    let mut sigs: Vec<String> = Vec::new();
    for (name, sig) in SIGNATURES {
        if bytes.windows(sig.len()).any(|w| w == *sig) && !sigs.iter().any(|s| s == name) {
            sigs.push(name.to_string());
        }
    }
    PackerVerdict {
        entropy: (ent * 1000.0).round() / 1000.0,
        packed: !sigs.is_empty() || ent > 7.2,
        signatures: sigs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_upx_signature() {
        let mut b = vec![0u8; 200];
        b[10..14].copy_from_slice(b"UPX!");
        let v = detect(&b);
        assert!(v.packed);
        assert!(v.signatures.contains(&"UPX".to_string()));
    }

    #[test]
    fn flags_high_entropy_even_without_a_signature() {
        // 256 distinct bytes repeated → entropy 8.0, no signature.
        let b: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let v = detect(&b);
        assert!(v.entropy > 7.2);
        assert!(v.packed);
        assert!(v.signatures.is_empty());
    }

    #[test]
    fn low_entropy_unsigned_binary_is_clean() {
        let b = vec![0u8; 1000]; // all zeros → entropy 0
        let v = detect(&b);
        assert!(!v.packed);
        assert_eq!(v.entropy, 0.0);
    }
}
