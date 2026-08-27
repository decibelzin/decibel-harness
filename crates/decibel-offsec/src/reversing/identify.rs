//! Binary format identification from raw header bytes — ELF / PE / Mach-O / WASM
//! / Java class — with the hardening flags (NX / PIE / RELRO / canary) for the
//! two formats where they matter most (ELF, PE). A hand-rolled struct parser, no
//! object-file crate (matching the upstream "custom struct parser").

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: String,
    pub arch: String,
    pub bits: u8,
    pub endian: String,
    pub kind: String,
    pub entry: u64,
    pub nx: Option<bool>,
    pub pie: Option<bool>,
    pub relro: Option<String>,
    pub canary: Option<bool>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}
fn u16be(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]])).unwrap_or(0)
}
fn u32le(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).unwrap_or(0)
}
fn u16e(b: &[u8], o: usize, le: bool) -> u16 {
    if le { u16le(b, o) } else { u16be(b, o) }
}

/// Identify a binary from its header bytes.
pub fn identify(bytes: &[u8]) -> BinaryInfo {
    if bytes.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return elf(bytes);
    }
    if bytes.starts_with(b"MZ") {
        return pe(bytes);
    }
    if bytes.starts_with(&[0x00, 0x61, 0x73, 0x6d]) {
        return BinaryInfo { format: "WASM".into(), arch: "wasm".into(), bits: 32, endian: "little".into(), kind: "module".into(), ..Default::default() };
    }
    // Mach-O magics (LE-stored thin binaries + BE variants).
    match bytes.get(0..4) {
        Some([0xce, 0xfa, 0xed, 0xfe]) | Some([0xfe, 0xed, 0xfa, 0xce]) => return macho(bytes, 32),
        Some([0xcf, 0xfa, 0xed, 0xfe]) | Some([0xfe, 0xed, 0xfa, 0xcf]) => return macho(bytes, 64),
        Some([0xca, 0xfe, 0xba, 0xbe]) => {
            // CAFEBABE is BOTH a Java class and a Mach-O fat binary. The Java major
            // version (bytes 6..8, big-endian) is >= 45 (Java 1.1); a fat binary's
            // nfat_arch there is tiny.
            if u16be(bytes, 6) >= 45 {
                let major = u16be(bytes, 6);
                return BinaryInfo { format: "Java class".into(), arch: "jvm".into(), bits: 0, endian: "big".into(), kind: format!("classfile v{major}"), ..Default::default() };
            }
            return BinaryInfo { format: "Mach-O".into(), arch: "fat/universal".into(), bits: 0, endian: "big".into(), kind: "fat".into(), ..Default::default() };
        }
        _ => {}
    }
    BinaryInfo { format: "unknown".into(), ..Default::default() }
}

fn elf(b: &[u8]) -> BinaryInfo {
    let bits = if b.get(4) == Some(&2) { 64 } else { 32 };
    let le = b.get(5) != Some(&2);
    let e_type = u16e(b, 16, le);
    let machine = u16e(b, 18, le);
    let arch = match machine {
        3 => "x86",
        62 => "x86_64",
        40 => "arm",
        183 => "aarch64",
        243 => "riscv",
        _ => "other",
    }
    .to_string();
    let entry = if bits == 64 {
        b.get(24..32).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
    } else {
        u32le(b, 24) as u64
    };
    let kind = match e_type {
        1 => "rel",
        2 => "exec",
        3 => "dyn",
        4 => "core",
        _ => "other",
    }
    .to_string();

    // Program headers for NX (PT_GNU_STACK) + RELRO (PT_GNU_RELRO).
    let (phoff, phentsize, phnum) = if bits == 64 {
        (b.get(32..40).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0) as usize, u16e(b, 54, le) as usize, u16e(b, 56, le) as usize)
    } else {
        (u32le(b, 28) as usize, u16e(b, 42, le) as usize, u16e(b, 44, le) as usize)
    };
    let mut nx = None;
    let mut relro = Some("none".to_string());
    for i in 0..phnum.min(128) {
        let off = phoff + i * phentsize.max(1);
        let p_type = u32le(b, off);
        match p_type {
            0x6474e551 => {
                // GNU_STACK: p_flags at +4 (64) / +24 (32); PF_X = 1 → executable stack (NX off).
                let flags = if bits == 64 { u32le(b, off + 4) } else { u32le(b, off + 24) };
                nx = Some(flags & 1 == 0);
            }
            0x6474e552 => relro = Some("partial".to_string()),
            _ => {}
        }
    }

    BinaryInfo {
        format: "ELF".into(),
        arch,
        bits,
        endian: if le { "little" } else { "big" }.into(),
        kind,
        entry,
        nx,
        pie: Some(e_type == 3),
        relro,
        canary: Some(contains(b, b"__stack_chk_fail")),
    }
}

fn pe(b: &[u8]) -> BinaryInfo {
    let pe_off = u32le(b, 0x3c) as usize;
    if b.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return BinaryInfo { format: "PE (MZ, no PE header)".into(), ..Default::default() };
    }
    let coff = pe_off + 4;
    let machine = u16le(b, coff);
    let (arch, _) = match machine {
        0x14c => ("x86", 32),
        0x8664 => ("x86_64", 64),
        0x1c0 | 0x1c4 => ("arm", 32),
        0xaa64 => ("aarch64", 64),
        _ => ("other", 0),
    };
    let characteristics = u16le(b, coff + 18);
    let opt = coff + 20;
    let opt_magic = u16le(b, opt);
    let bits = if opt_magic == 0x20b { 64 } else { 32 };
    let entry = u32le(b, opt + 16) as u64;
    let dll_chars = u16le(b, opt + 0x46);

    BinaryInfo {
        format: "PE".into(),
        arch: arch.into(),
        bits,
        endian: "little".into(),
        kind: if characteristics & 0x2000 != 0 { "dll" } else { "exe" }.into(),
        entry,
        nx: Some(dll_chars & 0x0100 != 0),  // NX_COMPAT
        pie: Some(dll_chars & 0x0040 != 0), // DYNAMIC_BASE (ASLR)
        relro: None,
        canary: Some(contains(b, b"__security_cookie") || contains(b, b"__security_check_cookie")),
    }
}

fn macho(b: &[u8], bits: u8) -> BinaryInfo {
    // cputype at offset 4 (little-endian for the LE-stored magics).
    let cputype = u32le(b, 4);
    let arch = match cputype {
        7 => "x86",
        0x0100_0007 => "x86_64",
        12 => "arm",
        0x0100_000c => "aarch64",
        _ => "other",
    }
    .to_string();
    // Header flags: 32-bit at 24, 64-bit at 24 too; MH_PIE = 0x200000.
    let flags = u32le(b, 24);
    BinaryInfo {
        format: "Mach-O".into(),
        arch,
        bits,
        endian: "little".into(),
        kind: "macho".into(),
        pie: Some(flags & 0x0020_0000 != 0),
        ..Default::default()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal but valid-enough ELF64 x86_64 DYN (PIE) header with a GNU_STACK
    /// program header (NX on) and the canary symbol string appended.
    fn elf64_pie() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[4] = 2; // 64-bit
        b[5] = 1; // little-endian
        b[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = DYN
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = x86_64
        b[24..32].copy_from_slice(&0x1040u64.to_le_bytes()); // e_entry
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        // one program header at offset 64: PT_GNU_STACK, flags = RW (no X → NX on)
        b[64..68].copy_from_slice(&0x6474e551u32.to_le_bytes());
        b[68..72].copy_from_slice(&6u32.to_le_bytes()); // p_flags = R|W
        b.extend_from_slice(b"__stack_chk_fail");
        b
    }

    #[test]
    fn identifies_elf64_pie_nx_canary() {
        let info = identify(&elf64_pie());
        assert_eq!(info.format, "ELF");
        assert_eq!(info.arch, "x86_64");
        assert_eq!(info.bits, 64);
        assert_eq!(info.kind, "dyn");
        assert_eq!(info.pie, Some(true));
        assert_eq!(info.nx, Some(true));
        assert_eq!(info.canary, Some(true));
        assert_eq!(info.entry, 0x1040);
    }

    #[test]
    fn identifies_other_formats_by_magic() {
        assert_eq!(identify(&[0x00, 0x61, 0x73, 0x6d, 1, 0, 0, 0]).format, "WASM");
        // Java class: CAFEBABE + minor(0) + major(52 = Java 8).
        let java = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
        assert_eq!(identify(&java).format, "Java class");
        // Mach-O 64 thin (cffaedfe) with x86_64 cputype.
        let mut macho = vec![0xcf, 0xfa, 0xed, 0xfe];
        macho.extend_from_slice(&0x0100_0007u32.to_le_bytes());
        macho.resize(64, 0);
        let m = identify(&macho);
        assert_eq!(m.format, "Mach-O");
        assert_eq!(m.arch, "x86_64");
        assert_eq!(m.bits, 64);
    }

    #[test]
    fn unknown_is_reported() {
        assert_eq!(identify(b"not a binary").format, "unknown");
        assert_eq!(identify(&[]).format, "unknown");
    }
}
