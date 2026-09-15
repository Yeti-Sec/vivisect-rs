//! Crypto constant detection module.
//!
//! Scans binary data sections for known cryptographic constants
//! (AES S-box, SHA-256 round constants, RC4 state, etc.).
//! Identifying these helps analysts understand what crypto algorithms
//! a binary uses.

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Known crypto constants and their patterns.
struct CryptoSignature {
    name: &'static str,
    pattern: &'static [u8],
    min_match: usize,
}

/// AES S-box first 16 bytes.
const AES_SBOX: &[u8] = &[
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
];

/// AES inverse S-box first 16 bytes.
const AES_INV_SBOX: &[u8] = &[
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
];

/// SHA-256 round constants (first 4 as LE u32).
const SHA256_K: &[u8] = &[
    0x98, 0x2F, 0x8A, 0x42, 0x91, 0x44, 0x37, 0x71, 0xCF, 0xFB, 0xC0, 0xB5, 0xA5, 0xDB, 0xB5, 0xE9,
];

/// SHA-256 initial hash values (first 8 bytes).
const SHA256_H: &[u8] = &[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb];

/// MD5 T table first 16 bytes.
const MD5_T: &[u8] = &[
    0x78, 0xA4, 0x6A, 0xD7, 0x56, 0xB7, 0xC7, 0xE8, 0xDB, 0x70, 0x20, 0x24, 0xEE, 0xCE, 0xBD, 0xC1,
];

/// CRC32 table first 16 bytes.
const CRC32_TABLE: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99,
];

/// Blowfish P-array first 16 bytes.
const BLOWFISH_P: &[u8] = &[
    0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
];

const SIGNATURES: &[CryptoSignature] = &[
    CryptoSignature {
        name: "AES_SBOX",
        pattern: AES_SBOX,
        min_match: 16,
    },
    CryptoSignature {
        name: "AES_INV_SBOX",
        pattern: AES_INV_SBOX,
        min_match: 16,
    },
    CryptoSignature {
        name: "SHA256_K",
        pattern: SHA256_K,
        min_match: 16,
    },
    CryptoSignature {
        name: "SHA256_H",
        pattern: SHA256_H,
        min_match: 8,
    },
    CryptoSignature {
        name: "MD5_T",
        pattern: MD5_T,
        min_match: 16,
    },
    CryptoSignature {
        name: "CRC32_TABLE",
        pattern: CRC32_TABLE,
        min_match: 16,
    },
    CryptoSignature {
        name: "BLOWFISH_P",
        pattern: BLOWFISH_P,
        min_match: 16,
    },
];

/// Run crypto constant detection.
#[must_use]
pub fn analyze_crypto(workspace: &mut VivWorkspace) -> VivResult<CryptoStats> {
    let mut stats = CryptoStats::default();

    let segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .map(|seg| (seg.va, seg.size))
        .collect();

    for (seg_va, seg_size) in &segments {
        let data = match workspace.read_memory(*seg_va, *seg_size) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for sig in SIGNATURES {
            if sig.pattern.len() > data.len() {
                continue;
            }

            for offset in 0..=(data.len() - sig.min_match) {
                let window = &data[offset..offset + sig.min_match];
                if window == &sig.pattern[..sig.min_match] {
                    let va = *seg_va + offset as u64;
                    if workspace.get_location(va).is_none() {
                        workspace.add_location(
                            va,
                            sig.pattern.len(),
                            LocationType::Struct,
                            Some(sig.name.to_string()),
                        );
                        workspace.set_name(va, sig.name);
                        stats.constants_found += 1;
                        tracing::debug!("[crypto] found {} at 0x{:x}", sig.name, va);
                    }
                }
            }
        }
    }

    tracing::debug!("[crypto] found {} crypto constants", stats.constants_found);
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct CryptoStats {
    pub constants_found: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // AES S-box Constant Tests
    // =========================================================================

    #[test]
    fn test_aes_sbox_first_bytes() {
        // Well-known AES S-box starts with 0x63, 0x7C, 0x77, 0x7B
        assert_eq!(AES_SBOX[0], 0x63);
        assert_eq!(AES_SBOX[1], 0x7C);
        assert_eq!(AES_SBOX[2], 0x77);
        assert_eq!(AES_SBOX[3], 0x7B);
    }

    #[test]
    fn test_aes_sbox_length() {
        assert_eq!(AES_SBOX.len(), 16);
    }

    #[test]
    fn test_aes_sbox_last_byte() {
        assert_eq!(AES_SBOX[15], 0x76);
    }

    #[test]
    fn test_aes_inv_sbox_first_bytes() {
        assert_eq!(AES_INV_SBOX[0], 0x52);
        assert_eq!(AES_INV_SBOX[1], 0x09);
        assert_eq!(AES_INV_SBOX[2], 0x6A);
        assert_eq!(AES_INV_SBOX[3], 0xD5);
    }

    #[test]
    fn test_aes_inv_sbox_length() {
        assert_eq!(AES_INV_SBOX.len(), 16);
    }

    #[test]
    fn test_aes_sbox_and_inv_sbox_differ() {
        // Forward and inverse S-boxes must be different
        assert_ne!(AES_SBOX, AES_INV_SBOX);
    }

    // =========================================================================
    // SHA-256 Constant Tests
    // =========================================================================

    #[test]
    fn test_sha256_k_first_bytes() {
        assert_eq!(SHA256_K[0], 0x98);
        assert_eq!(SHA256_K[1], 0x2F);
        assert_eq!(SHA256_K.len(), 16);
    }

    #[test]
    fn test_sha256_h_first_bytes() {
        assert_eq!(SHA256_H[0], 0x67);
        assert_eq!(SHA256_H[1], 0xe6);
        assert_eq!(SHA256_H.len(), 8);
    }

    // =========================================================================
    // MD5 Constant Tests
    // =========================================================================

    #[test]
    fn test_md5_t_first_bytes() {
        assert_eq!(MD5_T[0], 0x78);
        assert_eq!(MD5_T[1], 0xA4);
        assert_eq!(MD5_T[2], 0x6A);
        assert_eq!(MD5_T[3], 0xD7);
        assert_eq!(MD5_T.len(), 16);
    }

    // =========================================================================
    // CRC32 Constant Tests
    // =========================================================================

    #[test]
    fn test_crc32_table_starts_with_zeros() {
        // CRC32 table always starts with 0x00000000
        assert_eq!(CRC32_TABLE[0], 0x00);
        assert_eq!(CRC32_TABLE[1], 0x00);
        assert_eq!(CRC32_TABLE[2], 0x00);
        assert_eq!(CRC32_TABLE[3], 0x00);
        assert_eq!(CRC32_TABLE.len(), 16);
    }

    // =========================================================================
    // Blowfish Constant Tests
    // =========================================================================

    #[test]
    fn test_blowfish_p_first_bytes() {
        assert_eq!(BLOWFISH_P[0], 0x24);
        assert_eq!(BLOWFISH_P[1], 0x3F);
        assert_eq!(BLOWFISH_P[2], 0x6A);
        assert_eq!(BLOWFISH_P[3], 0x88);
        assert_eq!(BLOWFISH_P.len(), 16);
    }

    // =========================================================================
    // Signature Table Tests
    // =========================================================================

    #[test]
    fn test_signatures_have_valid_names() {
        for sig in SIGNATURES {
            assert!(!sig.name.is_empty(), "Signature has empty name");
        }
    }

    #[test]
    fn test_signatures_min_match_not_larger_than_pattern() {
        for sig in SIGNATURES {
            assert!(
                sig.min_match <= sig.pattern.len(),
                "Signature {} has min_match ({}) > pattern.len() ({})",
                sig.name,
                sig.min_match,
                sig.pattern.len()
            );
        }
    }

    #[test]
    fn test_signatures_min_match_at_least_8() {
        for sig in SIGNATURES {
            assert!(
                sig.min_match >= 8,
                "Signature {} has min_match {} (should be >= 8 to avoid false positives)",
                sig.name,
                sig.min_match
            );
        }
    }

    #[test]
    fn test_signature_count() {
        assert_eq!(SIGNATURES.len(), 7, "Expected 7 crypto signatures");
    }

    #[test]
    fn test_signature_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for sig in SIGNATURES {
            assert!(
                seen.insert(sig.name),
                "Duplicate signature name: {}",
                sig.name
            );
        }
    }

    // =========================================================================
    // AES S-box Pattern Match Simulation
    // =========================================================================

    #[test]
    fn test_aes_sbox_matches_known_bytes() {
        // Simulate the pattern matching logic inline
        let aes_sig = &SIGNATURES[0];
        assert_eq!(aes_sig.name, "AES_SBOX");

        // Create test data with AES S-box embedded at offset 32
        let mut data = [0x00u8; 128];
        data[32..32 + AES_SBOX.len()].copy_from_slice(AES_SBOX);

        // Run the matching logic
        let min_match = aes_sig.min_match;
        let mut found = false;
        for offset in 0..=(data.len() - min_match) {
            let window = &data[offset..offset + min_match];
            if window == &aes_sig.pattern[..min_match] {
                assert_eq!(offset, 32, "Match should be at offset 32");
                found = true;
                break;
            }
        }
        assert!(found, "AES S-box pattern should match");
    }

    #[test]
    fn test_aes_sbox_does_not_match_partial() {
        let aes_sig = &SIGNATURES[0];
        assert_eq!(aes_sig.name, "AES_SBOX");

        // Only embed 15 of 16 required bytes, with last byte wrong
        let mut data = [0x00u8; 64];
        data[0..15].copy_from_slice(&AES_SBOX[..15]);
        // data[15] = 0x00, not 0x76

        let min_match = aes_sig.min_match;
        let mut found = false;
        for offset in 0..=(data.len() - min_match) {
            let window = &data[offset..offset + min_match];
            if window == &aes_sig.pattern[..min_match] {
                found = true;
                break;
            }
        }
        assert!(!found, "Partial AES S-box should not match");
    }

    #[test]
    fn test_no_match_on_zero_data() {
        let data = vec![0x00u8; 256];
        let mut any_match = false;
        for sig in SIGNATURES {
            if sig.pattern.len() > data.len() {
                continue;
            }
            for offset in 0..=(data.len() - sig.min_match) {
                let window = &data[offset..offset + sig.min_match];
                if window == &sig.pattern[..sig.min_match] {
                    // CRC32 table starts with 4 zero bytes, but the rest differs.
                    // We still check if the full min_match matches.
                    if sig.name != "CRC32_TABLE" {
                        any_match = true;
                    }
                }
            }
        }
        // Only CRC32 might match on zero data (first 4 bytes are zero)
        // but the remaining bytes (0x96, 0x30...) won't match zeros
        assert!(!any_match, "Zero data should not match non-CRC32 patterns");
    }

    // =========================================================================
    // CryptoStats Tests
    // =========================================================================

    #[test]
    fn test_crypto_stats_default() {
        let stats = CryptoStats::default();
        assert_eq!(stats.constants_found, 0);
    }

    // =========================================================================
    // analyze_crypto on Empty Workspace
    // =========================================================================

    #[test]
    fn test_crypto_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_crypto(&mut ws).unwrap();
        assert_eq!(result.constants_found, 0);
    }
}
