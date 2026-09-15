//! Shared parity-harness support (Phase 0, review finding #6).
//!
//! Provides hermetic, repository-relative corpus/fixture resolution and
//! *explicit, named* skips for genuinely-external oracles, so a parity run can
//! never silently "pass" by doing no work:
//!
//! - Committed fixtures (golden JSON captured from Python) must exist and match
//!   their recorded sha256 — a missing/tampered committed fixture is a hard fail.
//! - External raw-binary corpus and Python-generated vector fixtures are
//!   documented external blockers; when absent, tests emit a `[PARITY-SKIP …]`
//!   line naming the blocker instead of returning silently.
//!
//! Override the raw-binary corpus location with `VIVISECT_CORPUS_DIR`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Directory holding external raw-binary corpus samples.
pub fn corpus_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VIVISECT_CORPUS_DIR") {
        return PathBuf::from(d);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("corpus")
}

/// Directory holding committed + generated fixture JSON.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Resolve an external raw-binary corpus sample by name.
///
/// Returns `None` with an explicit named skip when absent — the raw malware
/// corpus is a documented external blocker (see `PARITY.md`).
pub fn external_sample(name: &str) -> Option<PathBuf> {
    let p = corpus_dir().join(name);
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "[PARITY-SKIP external-corpus] sample '{}' not found under {} \
             (set VIVISECT_CORPUS_DIR). Documented external blocker.",
            name,
            corpus_dir().display()
        );
        None
    }
}

/// Resolve a Python-generated parity fixture (`vectors_*.json`).
///
/// Returns `None` with an explicit named skip when absent — generating these
/// requires an installed Python `vivisect`, a documented external blocker.
pub fn generated_fixture(name: &str) -> Option<PathBuf> {
    let p = fixtures_dir().join(name);
    if p.exists() {
        Some(p)
    } else {
        eprintln!(
            "[PARITY-SKIP python-oracle] generated fixture '{}' not present \
             (run fixtures/generate_*.py under Python vivisect). \
             Documented external blocker.",
            name
        );
        None
    }
}

/// Require a committed fixture; hard-fail if it is missing from the repo.
pub fn required_fixture(name: &str) -> PathBuf {
    let p = fixtures_dir().join(name);
    assert!(
        p.exists(),
        "Committed fixture missing: {} — this file must be tracked in the repo \
         (see fixtures/CORPUS_MANIFEST.json).",
        p.display()
    );
    p
}

// ---------------------------------------------------------------------------
// Corpus manifest (provenance + hash for every committed fixture).
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct CorpusManifest {
    pub version: u32,
    pub description: String,
    pub fixtures: Vec<ManifestEntry>,
}

#[derive(serde::Deserialize)]
pub struct ManifestEntry {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
    pub provenance: String,
}

pub fn load_manifest() -> CorpusManifest {
    let p = fixtures_dir().join("CORPUS_MANIFEST.json");
    let data =
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("cannot parse {}: {e}", p.display()))
}

// ---------------------------------------------------------------------------
// Self-contained SHA-256 (avoids adding an external dev-dependency).
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *wi = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for (hi, vi) in h.iter_mut().zip(v.iter()) {
            *hi = hi.wrapping_add(*vi);
        }
    }

    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{:08x}", word));
    }
    out
}

#[cfg(test)]
mod selftest {
    use super::sha256_hex;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
