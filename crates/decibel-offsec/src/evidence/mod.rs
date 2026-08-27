//! Evidence — chain-of-custody sealing and asciicast recording, ported from
//! Decepticon's `evidence` crate (Apache-2.0) into Decibel.
//!
//! Two capabilities, surfaced as model-facing tools in [`tools`]:
//!
//! * **Chain-of-custody sealing.** [`seal`] produces a tamper-evident [`Seal`]
//!   over an artifact — its SHA-256 content hash plus an HMAC-SHA256 of the
//!   content under the engagement's evidence key. [`verify`] re-derives both.
//!   On top of the per-artifact seal, an **append-only HMAC-chained custody
//!   log** ([`CustodyEntry`] / [`custody_append`] / [`custody_verify_chain`])
//!   links every sealing event into a hash chain, so any insertion, reordering,
//!   deletion, or field edit of the log breaks under the key.
//! * **Asciicast recording.** [`build_asciicast`] / [`asciicast_from_transcript`]
//!   render a session transcript to an asciinema v2 `.cast` for replay.
//!
//! The core here is pure and offline (no clock, no fs) — callers pass timestamps,
//! so it is fully unit-testable. The clock and the filesystem live in the
//! [`tools`] layer, which resolves paths through [`decibel_tools::ExecCtx`] and
//! reads/writes the artifact, its seal sidecar, the custody log, and the `.cast`.
//!
//! Faithful port of the source's self-contained logic; the source carried no
//! knowledge-graph ingest to omit.

pub mod tools;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// SHA-256 of `data` as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

// ---------------------------------------------------------------------------
// Chain-of-custody sealing
// ---------------------------------------------------------------------------

/// A tamper-evident seal over an artifact: its content hash plus an HMAC of the
/// content under the engagement's evidence key. Verifying re-derives both.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Seal {
    pub algo: String,
    /// SHA-256 of the sealed content (hex).
    pub sha256: String,
    /// HMAC-SHA256 of the content under the evidence key (hex).
    pub hmac: String,
    /// Unix seconds when sealed.
    pub created_at: i64,
    #[serde(default)]
    pub note: String,
}

/// Seal `data` with `key`. `now` is unix seconds (caller-supplied for testability).
pub fn seal(data: &[u8], key: &[u8], note: &str, now: i64) -> Seal {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    Seal {
        algo: "HMAC-SHA256".into(),
        sha256: sha256_hex(data),
        hmac: hex(&mac.finalize().into_bytes()),
        created_at: now,
        note: note.to_string(),
    }
}

/// Verify `data` against a `Seal` and `key`: the content hash AND the HMAC must
/// both match (HMAC checked in constant time). Any tampering with the artifact or
/// the seal fails.
pub fn verify(data: &[u8], key: &[u8], s: &Seal) -> bool {
    if sha256_hex(data) != s.sha256 {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    match hex_decode(&s.hmac) {
        Some(expected) => mac.verify_slice(&expected).is_ok(),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Append-only, HMAC-chained custody log
// ---------------------------------------------------------------------------

/// The genesis `prev` link for the first custody entry — 32 zero bytes (hex).
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One entry in an append-only custody log. Entries form a hash chain: each
/// entry's `prev` is the previous entry's `mac` (or [`GENESIS_PREV`] for the
/// first), and its own `mac` is HMAC-SHA256 over its canonical fields — which
/// include `prev`. So any insertion, reordering, deletion, or field edit of the
/// log breaks the chain when re-derived under the evidence key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyEntry {
    /// 1-based position in the chain.
    pub seq: u64,
    /// Unix seconds when the event was recorded.
    pub created_at: i64,
    /// What happened (e.g. `seal`).
    pub action: String,
    /// The artifact this event concerns.
    pub artifact: String,
    /// SHA-256 of the artifact at the time (hex).
    pub sha256: String,
    /// Free-form note.
    #[serde(default)]
    pub note: String,
    /// The previous entry's `mac` (or [`GENESIS_PREV`]).
    pub prev: String,
    /// HMAC-SHA256 over this entry's canonical fields, under the evidence key.
    pub mac: String,
}

/// Deterministic, unambiguous byte encoding of an entry's signed fields.
/// Length-prefixing every field prevents boundary-ambiguity collisions (so
/// `"a" + "bc"` cannot hash the same as `"ab" + "c"`).
fn custody_mac_input(
    seq: u64,
    created_at: i64,
    action: &str,
    artifact: &str,
    sha256: &str,
    note: &str,
    prev: &str,
) -> Vec<u8> {
    let seq = seq.to_string();
    let ts = created_at.to_string();
    let fields: [&str; 7] = [&seq, &ts, action, artifact, sha256, note, prev];
    let mut buf = Vec::new();
    for f in fields {
        buf.extend_from_slice(&(f.len() as u64).to_le_bytes());
        buf.extend_from_slice(f.as_bytes());
    }
    buf
}

/// The chained MAC for an entry's fields, as lowercase hex.
#[allow(clippy::too_many_arguments)]
fn custody_mac(
    key: &[u8],
    seq: u64,
    created_at: i64,
    action: &str,
    artifact: &str,
    sha256: &str,
    note: &str,
    prev: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&custody_mac_input(seq, created_at, action, artifact, sha256, note, prev));
    hex(&mac.finalize().into_bytes())
}

/// Build the next custody entry chained onto `prev_mac` (pass [`GENESIS_PREV`]
/// for the first entry). `seq` should be `previous seq + 1` (1 for the first).
#[allow(clippy::too_many_arguments)]
pub fn custody_append(
    key: &[u8],
    prev_mac: &str,
    seq: u64,
    created_at: i64,
    action: &str,
    artifact: &str,
    sha256: &str,
    note: &str,
) -> CustodyEntry {
    let mac = custody_mac(key, seq, created_at, action, artifact, sha256, note, prev_mac);
    CustodyEntry {
        seq,
        created_at,
        action: action.to_string(),
        artifact: artifact.to_string(),
        sha256: sha256.to_string(),
        note: note.to_string(),
        prev: prev_mac.to_string(),
        mac,
    }
}

/// A structural problem found verifying a custody chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainError {
    /// The seq of the offending entry.
    pub seq: u64,
    /// One of `bad_seq` | `bad_genesis` | `broken_link` | `mac_mismatch`.
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Verify an ordered custody chain under `key`. Returns every structural problem
/// found — an empty vec means the chain is intact and unbroken from genesis.
///
/// Checks, per entry: `seq` increments from 1; the `prev` link matches genesis
/// (first) or the previous entry's recorded `mac`; and the entry's own `mac`
/// re-derives correctly. A tampered `mac` therefore surfaces both directly
/// (`mac_mismatch`) and as a `broken_link` on the following entry — the expected
/// signature of a hash chain.
pub fn custody_verify_chain(key: &[u8], entries: &[CustodyEntry]) -> Vec<ChainError> {
    let mut errors = Vec::new();
    let mut expected_prev = GENESIS_PREV.to_string();
    for (i, e) in entries.iter().enumerate() {
        let want_seq = i as u64 + 1;
        if e.seq != want_seq {
            errors.push(ChainError {
                seq: e.seq,
                kind: "bad_seq".into(),
                detail: format!("expected seq {want_seq}, found {}", e.seq),
            });
        }
        if e.prev != expected_prev {
            if i == 0 {
                errors.push(ChainError {
                    seq: e.seq,
                    kind: "bad_genesis".into(),
                    detail: "first entry's prev is not the genesis link".into(),
                });
            } else {
                errors.push(ChainError {
                    seq: e.seq,
                    kind: "broken_link".into(),
                    detail: "prev does not match the previous entry's mac".into(),
                });
            }
        }
        // Re-derive this entry's MAC from its own fields and chain the NEXT
        // entry against THAT (not the stored `mac`). This is what makes a content
        // edit anywhere propagate as a `broken_link` on the following entry — the
        // hash-chain property this function documents — since an edit changes the
        // re-derived MAC while the stored `mac`/`prev` fields stay put.
        let recomputed = custody_mac(key, e.seq, e.created_at, &e.action, &e.artifact, &e.sha256, &e.note, &e.prev);
        if recomputed != e.mac {
            errors.push(ChainError {
                seq: e.seq,
                kind: "mac_mismatch".into(),
                detail: "entry mac does not verify (content tampered or wrong key)".into(),
            });
        }
        expected_prev = recomputed;
    }
    errors
}

// ---------------------------------------------------------------------------
// Asciicast recording (asciinema v2)
// ---------------------------------------------------------------------------

/// One terminal output event at `time` seconds from the start.
#[derive(Debug, Clone)]
pub struct CastEvent {
    pub time: f64,
    pub data: String,
}

/// Build an asciinema v2 `.cast`: a JSON header line followed by one
/// `[time, "o", data]` line per output event. JSON-escaping is handled by
/// serde_json, so arbitrary terminal bytes are safe.
pub fn build_asciicast(width: u32, height: u32, title: &str, created_at: i64, events: &[CastEvent]) -> String {
    let header = serde_json::json!({
        "version": 2,
        "width": width,
        "height": height,
        "timestamp": created_at,
        "title": title,
        "env": { "TERM": "xterm-256color" }
    });
    let mut out = header.to_string();
    out.push('\n');
    for e in events {
        out.push_str(&serde_json::json!([e.time, "o", e.data]).to_string());
        out.push('\n');
    }
    out
}

/// Convenience: a `.cast` for a whole captured transcript as a single output
/// event at t=0 (when per-chunk timing wasn't recorded).
pub fn asciicast_from_transcript(width: u32, height: u32, title: &str, created_at: i64, transcript: &str) -> String {
    build_asciicast(width, height, title, created_at, &[CastEvent { time: 0.0, data: transcript.to_string() }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_verify_roundtrip_and_tamper_detection() {
        let data = b"FIND-001: SQLi on /login (validated)";
        let key = b"engagement-secret";
        let s = seal(data, key, "finding FIND-001", 1_700_000_000);
        assert_eq!(s.algo, "HMAC-SHA256");
        assert_eq!(s.sha256, sha256_hex(data));
        assert!(verify(data, key, &s), "a clean artifact verifies");

        // Tampered content → fails.
        assert!(!verify(b"FIND-001: SQLi on /login (FAKE)", key, &s));
        // Wrong key → fails.
        assert!(!verify(data, b"other-key", &s));
        // Tampered seal (flipped hmac) → fails.
        let mut bad = s.clone();
        bad.hmac.replace_range(0..1, if bad.hmac.starts_with('a') { "b" } else { "a" });
        assert!(!verify(data, key, &bad));
        // Tampered hash → fails (hash check first).
        let mut bad2 = s.clone();
        bad2.sha256 = sha256_hex(b"different");
        assert!(!verify(data, key, &bad2));
    }

    #[test]
    fn seal_serializes_to_json() {
        let s = seal(b"x", b"k", "", 42);
        let json = serde_json::to_string(&s).unwrap();
        let back: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn asciicast_is_valid_v2() {
        let events = [
            CastEvent { time: 0.0, data: "$ nmap 10.0.0.5\n".into() },
            CastEvent { time: 1.5, data: "PORT   STATE\n445/tcp open\n".into() },
        ];
        let cast = build_asciicast(120, 30, "recon session", 1_700_000_000, &events);
        let mut lines = cast.lines();
        // header parses with version 2 + dimensions.
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(header["version"], 2);
        assert_eq!(header["width"], 120);
        // each event line parses as [time, "o", data].
        let e1: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(e1[0], 0.0);
        assert_eq!(e1[1], "o");
        assert!(e1[2].as_str().unwrap().contains("nmap"));
        let e2: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        assert_eq!(e2[0], 1.5);
    }

    #[test]
    fn asciicast_from_transcript_single_event() {
        let cast = asciicast_from_transcript(80, 24, "s", 1, "hello\nworld\n");
        let lines: Vec<&str> = cast.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 event
        let ev: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(ev[2], "hello\nworld\n");
    }

    // --- custody chain (new) ---------------------------------------------

    /// Build a small valid chain of `n` seal entries over `key`.
    fn build_chain(key: &[u8], n: u64) -> Vec<CustodyEntry> {
        let mut entries = Vec::new();
        let mut prev = GENESIS_PREV.to_string();
        for seq in 1..=n {
            let artifact = format!("evidence/find-{seq:03}.txt");
            let sha = sha256_hex(artifact.as_bytes());
            let e = custody_append(key, &prev, seq, 1_700_000_000 + seq as i64, "seal", &artifact, &sha, "");
            prev = e.mac.clone();
            entries.push(e);
        }
        entries
    }

    #[test]
    fn custody_chain_verifies_clean() {
        let key = b"engagement-secret";
        let chain = build_chain(key, 3);
        assert_eq!(chain[0].prev, GENESIS_PREV);
        assert_eq!(chain[1].prev, chain[0].mac);
        assert_eq!(chain[2].prev, chain[1].mac);
        assert!(custody_verify_chain(key, &chain).is_empty(), "a clean chain has no errors");
        // Wrong key → every entry's mac fails to re-derive.
        let bad = custody_verify_chain(b"other", &chain);
        assert_eq!(bad.iter().filter(|e| e.kind == "mac_mismatch").count(), 3);
    }

    #[test]
    fn custody_chain_detects_edit_deletion_and_reorder() {
        let key = b"engagement-secret";

        // 1) Editing a sealed hash breaks that entry's mac AND the next link.
        let mut edited = build_chain(key, 3);
        edited[1].sha256 = sha256_hex(b"swapped artifact");
        let errs = custody_verify_chain(key, &edited);
        assert!(errs.iter().any(|e| e.seq == 2 && e.kind == "mac_mismatch"));
        assert!(errs.iter().any(|e| e.seq == 3 && e.kind == "broken_link"));

        // 2) Deleting the middle entry leaves a seq gap and a broken link.
        let mut deleted = build_chain(key, 3);
        deleted.remove(1); // drop seq 2; seq 3 now sits at index 1
        let errs = custody_verify_chain(key, &deleted);
        assert!(errs.iter().any(|e| e.kind == "bad_seq"));
        assert!(errs.iter().any(|e| e.kind == "broken_link"));

        // 3) Reordering the first two entries breaks genesis + seq.
        let mut reordered = build_chain(key, 3);
        reordered.swap(0, 1);
        let errs = custody_verify_chain(key, &reordered);
        assert!(errs.iter().any(|e| e.kind == "bad_genesis"));
        assert!(errs.iter().any(|e| e.kind == "bad_seq"));
    }
}
