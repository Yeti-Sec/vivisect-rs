//! MSVC analysis: VAMP signature matching and security cookie function discovery.
//!
//! Two components:
//!
//! - **VAMP signatures** (per-function): Identifies MSVC runtime functions by byte
//!   patterns (security_check_cookie, SEH prolog/epilog, GS prolog, alloca_probe)
//!   and renames them. Port of `vivisect/analysis/ms/msvc.py` + `vivisect/vamp/msvc/`.
//!
//! - **Security cookie discovery** (workspace module): Finds the global security
//!   cookie address from security_check_cookie functions, then scans code for
//!   instructions referencing the cookie to discover functions at code block
//!   starts not yet recognized as function entries.
//!   Port of `vivisect/analysis/ms/msvcfunc.py`.

use crate::constants::Architecture;
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// VAMP signature definition: (bytes_hex, mask_hex_or_empty, name).
/// Empty mask means all bytes must match exactly.
const MSVC_SIGS: &[(&str, &str, &str)] = &[
    // 32-bit security_check_cookie (VS 2005-2013)
    (
        "3b0d000000007502f3c3e9",
        "ffff00000000ffffffffff",
        "ntdll.security_check_cookie",
    ),
    // 32-bit security_check_cookie (VS 2015-2017, BND prefix)
    (
        "3b0d00000000f27502f2c3f2e9",
        "ffff00000000ffffffffffffff",
        "ntdll.security_check_cookie",
    ),
    // 64-bit security_check_cookie (VS 2005-2013)
    (
        "483b0d00000000751148c1c11066f7c1ffff7502f3c348c1c910e9",
        "ffffff00000000ffffffffffffffffffffffffffffffffffffffff",
        "ntdll.security_check_cookie_64",
    ),
    // 64-bit security_check_cookie (VS 2015)
    (
        "483b0d00000000f2751148c1c11066f7c1fffff27502f2c348c1c910e9",
        "ffffff00000000ffffffffffffffffffffffffffffffffffffffffffff",
        "ntdll.security_check_cookie_64",
    ),
    // 64-bit security_check_cookie (VS 2019)
    (
        "483b0d00000000f2751248c1c11066f7c1fffff27502f2c348c1c910e9",
        "ffffff00000000ffffffffffffffffffffffffffffffffffffffffffff",
        "ntdll.security_check_cookie_64",
    ),
    // GS prolog (32-bit): mov eax,[cookie]; xor eax,ebp; mov [ebp-4],eax
    (
        "a10000000033c58945fc",
        "ff00000000ffffffffff",
        "ntdll.gs_prolog",
    ),
    // SEH3 prolog
    (
        "680000000064a10000000050",
        "ff00000000ffffffffffffff",
        "ntdll.seh3_prolog",
    ),
    // SEH4 prolog
    (
        "680000000064ff35000000008b442410",
        "ff00000000ffffffffffffffffffffff",
        "ntdll.seh4_prolog",
    ),
    // EH prolog
    (
        "6aff5064a100000000508b44240c64892500000000896c240c8d6c240c50c3",
        "",
        "ntdll.eh_prolog",
    ),
    // SEH3 epilog
    (
        "8b4df064890d00000000595f5e5bc951c3",
        "",
        "ntdll.seh3_epilog",
    ),
    // SEH4 epilog (VS 2005-2013)
    (
        "8b4df064890d00000000595f5f5e5b8be55d51c3",
        "",
        "ntdll.seh4_epilog",
    ),
    // SEH4 epilog (VS 2015-2017, BND)
    (
        "8b4df064890d00000000595f5f5e5b8be55d51f2c3",
        "",
        "ntdll.seh4_epilog",
    ),
];

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("MSVC signature constants are valid hex"))
        .collect()
}

/// Try to match function bytes against MSVC VAMP signatures.
/// Returns the signature name of the longest match, or None.
#[must_use]
pub fn match_vamp_signature(func_bytes: &[u8]) -> Option<&'static str> {
    let mut best: Option<(&str, usize)> = None;

    for &(sig_hex, mask_hex, name) in MSVC_SIGS {
        let sig = hex_decode(sig_hex);
        if sig.len() > func_bytes.len() {
            continue;
        }

        let has_mask = !mask_hex.is_empty();
        let mask = if has_mask {
            hex_decode(mask_hex)
        } else {
            vec![0xff; sig.len()]
        };

        let matched = sig
            .iter()
            .zip(mask.iter())
            .enumerate()
            .all(|(i, (&s, &m))| (func_bytes[i] & m) == s);

        if matched && best.map_or(true, |(_, len)| sig.len() > len) {
            best = Some((name, sig.len()));
        }
    }

    best.map(|(name, _)| name)
}

/// Extract the global security cookie address from a security_check_cookie function.
///
/// 32-bit: `cmp ecx, [abs32]` — cookie addr at bytes\[2..6\]
/// 64-bit: `cmp rcx, [rip+disp32]` — cookie addr = func_va + 7 + disp32
#[must_use]
pub fn extract_cookie_address(func_bytes: &[u8], func_va: u64, is_64bit: bool) -> Option<u64> {
    if is_64bit {
        // 48 3b 0d XX XX XX XX
        if func_bytes.len() >= 7
            && func_bytes[0] == 0x48
            && func_bytes[1] == 0x3b
            && func_bytes[2] == 0x0d
        {
            let disp =
                i32::from_le_bytes([func_bytes[3], func_bytes[4], func_bytes[5], func_bytes[6]]);
            let rip = func_va + 7; // RIP points past the 7-byte instruction
            Some((rip as i64 + disp as i64) as u64)
        } else {
            None
        }
    } else {
        // 3b 0d XX XX XX XX
        if func_bytes.len() >= 6 && func_bytes[0] == 0x3b && func_bytes[1] == 0x0d {
            let addr =
                u32::from_le_bytes([func_bytes[2], func_bytes[3], func_bytes[4], func_bytes[5]]);
            Some(addr as u64)
        } else {
            None
        }
    }
}

/// Per-function: rename function if it matches a VAMP signature.
/// Returns true if a signature was matched.
pub fn analyze_msvc_function(workspace: &mut VivWorkspace, func_va: u64) -> bool {
    let bytes = match workspace.read_memory(func_va, 80) {
        Ok(b) => b,
        Err(_) => return false,
    };

    if let Some(sig_name) = match_vamp_signature(&bytes) {
        let short_name = sig_name.split('.').last().unwrap_or(sig_name);
        let full_name = format!("{}_{:08x}", short_name, func_va);
        workspace.set_name(func_va, &full_name);

        // Mark as thunk to the signature (matches Python makeFunctionThunk)
        if let Some(meta) = workspace.get_function_mut(func_va) {
            meta.meta
                .insert("Thunk".to_string(), sig_name.to_string());
        }

        true
    } else {
        false
    }
}

/// Discover functions by tracing security cookie references.
///
/// Algorithm (port of Python `ms/msvcfunc.py`):
/// 1. Find security_check_cookie function via VAMP pattern match
/// 2. Extract the global security cookie address from its first instruction
/// 3. Scan executable code for instructions referencing the cookie address
/// 4. For each `mov`-class reference inside a code block, create a function
///    at the block's start if it isn't already a function
#[must_use]
pub fn discover_msvc_functions(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();
    let is_64bit = matches!(arch, Architecture::Amd64);

    if !matches!(arch, Architecture::I386 | Architecture::Amd64) {
        return Ok(vec![]);
    }

    // Step 1: Find security_check_cookie and extract cookie address
    let mut cookie_addr: Option<u64> = None;
    let mut cookie_func_va: Option<u64> = None;

    for func_va in workspace.get_functions() {
        let bytes = match workspace.read_memory(func_va, 20) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Some(name) = match_vamp_signature(&bytes) {
            if name.contains("security_check_cookie") {
                if let Some(addr) = extract_cookie_address(&bytes, func_va, is_64bit) {
                    tracing::debug!(
                        "[msvcfunc] security_check_cookie at {:#x}, cookie at {:#x}",
                        func_va,
                        addr
                    );
                    cookie_addr = Some(addr);
                    cookie_func_va = Some(func_va);
                    break;
                }
            }
        }
    }

    let cookie_addr = match cookie_addr {
        Some(addr) => addr,
        None => {
            tracing::debug!("[msvcfunc] no security_check_cookie found");
            return Ok(vec![]);
        }
    };

    // Name the security_check_cookie function if not already named
    if let Some(fva) = cookie_func_va {
        let suffix = if is_64bit { "_64" } else { "" };
        let name = format!("security_check_cookie{}_{:08x}", suffix, fva);
        workspace.set_name(fva, &name);
    }

    // Step 2: Scan for cookie references in executable code
    let mut discovered = Vec::new();

    if is_64bit {
        // 64-bit: RIP-relative addressing — need to check each instruction
        // individually since the displacement depends on instruction position.
        // Scan code blocks for instructions that reference cookie_addr.
        discover_cookie_refs_x64(workspace, cookie_addr, &mut discovered)?;
    } else {
        // 32-bit: absolute addressing — cookie bytes appear directly in code
        discover_cookie_refs_x86(workspace, cookie_addr, &mut discovered)?;
    }

    Ok(discovered)
}

/// Scan 32-bit code for absolute references to the cookie address.
fn discover_cookie_refs_x86(
    workspace: &mut VivWorkspace,
    cookie_addr: u64,
    discovered: &mut Vec<u64>,
) -> VivResult<()> {
    let cookie_bytes = (cookie_addr as u32).to_le_bytes();

    // Collect executable segments
    let segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|s| workspace.is_executable(s.va))
        .map(|s| (s.va, s.size))
        .collect();

    // Collect code blocks for containing-block lookups
    let blocks: Vec<(u64, usize)> = workspace
        .codeblocks_iter()
        .map(|(&va, b)| (va, b.size))
        .collect();

    for (seg_va, seg_size) in segments {
        let seg_bytes = match workspace.read_memory(seg_va, seg_size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Search for cookie_bytes in the segment
        let mut pos = 1; // start at 1 to allow checking preceding opcode byte
        while pos + 4 <= seg_bytes.len() {
            if seg_bytes[pos..pos + 4] != cookie_bytes {
                pos += 1;
                continue;
            }

            // Found cookie bytes at offset `pos`. Check if preceded by a mov opcode.
            let is_mov = if seg_bytes[pos - 1] == 0xa1 {
                // a1 [addr32] — mov eax, [abs32] (1-byte opcode)
                true
            } else if pos >= 2 {
                let opcode = seg_bytes[pos - 2];
                let modrm = seg_bytes[pos - 1];
                // ModRM with mod=00, r/m=101 = absolute 32-bit addressing
                let is_abs32 = (modrm & 0xC7) == 0x05;
                // mov r/m,reg (89) or mov reg,r/m (8b)
                is_abs32 && (opcode == 0x8b || opcode == 0x89)
            } else {
                false
            };

            if is_mov {
                let ref_va = seg_va + pos as u64;

                // Find the code block containing this reference
                if let Some(block_va) = find_block_containing(&blocks, ref_va) {
                    if !workspace.is_function(block_va) {
                        tracing::debug!(
                            "[msvcfunc] function at {:#x} (cookie ref at {:#x})",
                            block_va,
                            ref_va
                        );
                        workspace.add_function(
                            block_va,
                            FunctionMeta {
                                name: Some(format!("sub_{:x}", block_va)),
                                ..Default::default()
                            },
                        )?;
                        discovered.push(block_va);
                    }
                }
            }

            pos += 1;
        }
    }

    Ok(())
}

/// Scan 64-bit code for RIP-relative references to the cookie address.
fn discover_cookie_refs_x64(
    workspace: &mut VivWorkspace,
    cookie_addr: u64,
    discovered: &mut Vec<u64>,
) -> VivResult<()> {
    // For x64, memory references use RIP-relative addressing.
    // The displacement depends on the instruction's own address, so we can't
    // do a simple byte search. Instead, scan code blocks and check if any
    // instruction could reference cookie_addr.
    //
    // Common patterns:
    //   48 8b 05 disp32  — mov rax, [rip+disp]
    //   8b 05 disp32     — mov eax, [rip+disp]
    //   48 8b 0d disp32  — mov rcx, [rip+disp]
    //
    // For each candidate: check if instruction_va + instruction_size + disp == cookie_addr

    let segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|s| workspace.is_executable(s.va))
        .map(|s| (s.va, s.size))
        .collect();

    let blocks: Vec<(u64, usize)> = workspace
        .codeblocks_iter()
        .map(|(&va, b)| (va, b.size))
        .collect();

    for (seg_va, seg_size) in segments {
        let seg_bytes = match workspace.read_memory(seg_va, seg_size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let mut pos = 0;
        while pos + 7 <= seg_bytes.len() {
            // Check for REX.W + mov reg, [rip+disp32]: 48 8b ModRM disp32
            // or mov reg, [rip+disp32]: 8b ModRM disp32
            let (insn_len, disp_offset) = if seg_bytes[pos] == 0x48
                && (seg_bytes[pos + 1] == 0x8b || seg_bytes[pos + 1] == 0x89)
                && (seg_bytes[pos + 2] & 0xC7) == 0x05
            {
                // REX.W prefix: 48 8b/89 ModRM disp32 — 7 bytes total
                (7usize, pos + 3)
            } else if (seg_bytes[pos] == 0x8b || seg_bytes[pos] == 0x89)
                && (seg_bytes[pos + 1] & 0xC7) == 0x05
            {
                // No REX: 8b/89 ModRM disp32 — 6 bytes total
                (6usize, pos + 2)
            } else {
                pos += 1;
                continue;
            };

            if disp_offset + 4 > seg_bytes.len() {
                break;
            }

            let disp = i32::from_le_bytes([
                seg_bytes[disp_offset],
                seg_bytes[disp_offset + 1],
                seg_bytes[disp_offset + 2],
                seg_bytes[disp_offset + 3],
            ]);

            let insn_va = seg_va + pos as u64;
            let rip_after = insn_va + insn_len as u64;
            let target = (rip_after as i64 + disp as i64) as u64;

            if target == cookie_addr {
                if let Some(block_va) = find_block_containing(&blocks, insn_va) {
                    if !workspace.is_function(block_va) {
                        tracing::debug!(
                            "[msvcfunc] function at {:#x} (cookie ref at {:#x})",
                            block_va,
                            insn_va
                        );
                        workspace.add_function(
                            block_va,
                            FunctionMeta {
                                name: Some(format!("sub_{:x}", block_va)),
                                ..Default::default()
                            },
                        )?;
                        discovered.push(block_va);
                    }
                }
            }

            pos += 1;
        }
    }

    Ok(())
}

/// Find the code block containing an address (linear scan).
fn find_block_containing(blocks: &[(u64, usize)], va: u64) -> Option<u64> {
    for &(block_va, block_size) in blocks {
        if va >= block_va && va < block_va + block_size as u64 {
            return Some(block_va);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vamp_security_check_cookie_32() {
        // cmp ecx, [0x0040c01c]; jnz +2; rep ret; jmp ...
        let bytes = hex_decode("3b0d1cc040007502f3c3e90b160000");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, Some("ntdll.security_check_cookie"));
    }

    #[test]
    fn test_vamp_security_check_cookie_32_bnd() {
        // VS 2015+ with BND prefix
        let bytes = hex_decode("3b0d1cc04000f27502f2c3f2e90b160000");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, Some("ntdll.security_check_cookie"));
    }

    #[test]
    fn test_vamp_security_check_cookie_64() {
        // 48 3b 0d XX XX XX XX 75 11 48 c1 c1 10 66 f7 c1 ff ff 75 02 f3 c3 48 c1 c9 10 e9
        let bytes = hex_decode("483b0d12345678751148c1c11066f7c1ffff7502f3c348c1c910e9aabbccdd");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, Some("ntdll.security_check_cookie_64"));
    }

    #[test]
    fn test_vamp_gs_prolog() {
        // mov eax, [0x0040c01c]; xor eax, ebp; mov [ebp-4], eax
        let bytes = hex_decode("a11cc0400033c58945fc");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, Some("ntdll.gs_prolog"));
    }

    #[test]
    fn test_vamp_seh3_prolog() {
        let bytes = hex_decode("68c09a837c64a10000000050");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, Some("ntdll.seh3_prolog"));
    }

    #[test]
    fn test_vamp_no_match() {
        let bytes = hex_decode("558bec83ec1053565789");
        let name = match_vamp_signature(&bytes);
        assert_eq!(name, None);
    }

    #[test]
    fn test_extract_cookie_32() {
        let bytes = hex_decode("3b0d1cc040007502f3c3e9");
        let addr = extract_cookie_address(&bytes, 0x421f44, false);
        assert_eq!(addr, Some(0x40c01c));
    }

    #[test]
    fn test_extract_cookie_64() {
        // RIP-relative: func_va=0x140019bb0, instruction is 7 bytes
        // rip_after = 0x140019bb7
        // disp = 0x00026a49 (little-endian)
        let bytes = hex_decode("483b0d496a0200751148c1c11066f7c1ffff7502f3c348c1c910e9");
        let addr = extract_cookie_address(&bytes, 0x140019bb0, true);
        // cookie = 0x140019bb7 + 0x26a49 = 0x140040600
        assert_eq!(addr, Some(0x140040600));
    }

    #[test]
    fn test_find_block_containing() {
        let blocks = vec![
            (0x401000, 20),
            (0x401014, 10),
            (0x401100, 50),
        ];
        assert_eq!(find_block_containing(&blocks, 0x401005), Some(0x401000));
        assert_eq!(find_block_containing(&blocks, 0x401014), Some(0x401014));
        assert_eq!(find_block_containing(&blocks, 0x40101d), Some(0x401014));
        assert_eq!(find_block_containing(&blocks, 0x40101e), None);
        assert_eq!(find_block_containing(&blocks, 0x401120), Some(0x401100));
        assert_eq!(find_block_containing(&blocks, 0x400000), None);
    }
}
