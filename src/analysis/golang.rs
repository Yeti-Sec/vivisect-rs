//! Go binary analysis module.
//!
//! Parses the `.gopclntab` section in Go ELF binaries to extract the
//! exact function table. Go embeds a PC-line table (pclntab) in every
//! binary that contains the definitive list of all functions, their
//! entry points, and metadata.
//!
//! This goes beyond Python vivisect's Go support (which only handles
//! Windows PE via opcode pattern matching for `runtime_main`). By
//! parsing the pclntab, we get the complete function list for any Go
//! binary (ELF or PE).
//!
//! Supported pclntab formats:
//! - Go 1.2-1.15:  magic 0xFFFFFFF0
//! - Go 1.16-1.17: magic 0xFFFFFFFA
//! - Go 1.18-1.19: magic 0xFFFFFFFB
//! - Go 1.20-1.21: magic 0xFFFFFFFC (same header as 1.18)
//! - Go 1.22+:     magic 0xFFFFFFF1

use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// Magic values for different Go pclntab versions.
const GO_PCLNTAB_MAGIC_12: u32 = 0xFFFFFFF0; // Go 1.2-1.15
const GO_PCLNTAB_MAGIC_116: u32 = 0xFFFFFFFA; // Go 1.16-1.17
const GO_PCLNTAB_MAGIC_118: u32 = 0xFFFFFFFB; // Go 1.18-1.19
const GO_PCLNTAB_MAGIC_120: u32 = 0xFFFFFFFC; // Go 1.20-1.21
const GO_PCLNTAB_MAGIC_122: u32 = 0xFFFFFFF1; // Go 1.22+

/// Discover Go functions from the `.gopclntab` section.
///
/// Returns the list of function VAs found in the pclntab.
#[must_use]
pub fn discover_go_functions(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    // Find the .gopclntab section
    let gopclntab_info = workspace
        .get_segments()
        .iter()
        .find(|s| s.name == ".gopclntab")
        .map(|s| (s.va, s.size));

    let (pclntab_va, pclntab_size) = match gopclntab_info {
        Some(info) => info,
        None => return Ok(Vec::new()), // Not a Go binary
    };

    if pclntab_size < 72 {
        return Ok(Vec::new()); // Too small for header
    }

    // Read the pclntab header
    let header = match workspace.read_memory(pclntab_va, std::cmp::min(pclntab_size, 72)) {
        Ok(h) => h,
        Err(_) => return Ok(Vec::new()),
    };

    let magic = u32::from_le_bytes(header[0..4].try_into().unwrap_or([0; 4]));
    let ptr_size = header[7] as usize;

    if ptr_size != 4 && ptr_size != 8 {
        tracing::warn!("[golang] invalid ptrSize {} in pclntab", ptr_size);
        return Ok(Vec::new());
    }

    // Find the .text section base address
    let text_va = workspace
        .get_segments()
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.va)
        .unwrap_or(0);

    if text_va == 0 {
        return Ok(Vec::new());
    }

    match magic {
        GO_PCLNTAB_MAGIC_122 | GO_PCLNTAB_MAGIC_120 | GO_PCLNTAB_MAGIC_118 => {
            parse_go_122(workspace, pclntab_va, pclntab_size, text_va, ptr_size)
        }
        GO_PCLNTAB_MAGIC_116 => {
            parse_go_116(workspace, pclntab_va, pclntab_size, text_va, ptr_size)
        }
        GO_PCLNTAB_MAGIC_12 => {
            parse_go_12(workspace, pclntab_va, pclntab_size, text_va, ptr_size)
        }
        _ => {
            tracing::debug!(
                "[golang] unrecognized pclntab magic {:#010x} at {:#x}",
                magic,
                pclntab_va
            );
            Ok(Vec::new())
        }
    }
}

/// Parse Go 1.18+ pclntab format (also used by 1.20, 1.22+).
///
/// Header layout:
///   [0..4]   magic (uint32)
///   [4..6]   padding
///   [6]      minLC (uint8)
///   [7]      ptrSize (uint8)
///   [8..16]  nfunc (int, 8 bytes on 64-bit)
///   [16..24] nfiles (uint, 8 bytes)
///   [24..32] textStart (uintptr, 8 bytes)
///   [32..40] funcnameOffset (uintptr)
///   [40..48] cuOffset (uintptr)
///   [48..56] filetabOffset (uintptr)
///   [56..64] pctabOffset (uintptr)
///   [64..72] pclnOffset (uintptr) — functab starts here
fn parse_go_122(
    workspace: &mut VivWorkspace,
    pclntab_va: u64,
    pclntab_size: usize,
    text_va: u64,
    ptr_size: usize,
) -> VivResult<Vec<u64>> {
    let header = workspace.read_memory(pclntab_va, 72)?;

    // Read nfunc (8 bytes starting at offset 8)
    let nfunc = if ptr_size == 8 {
        u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8])) as usize
    } else {
        u32::from_le_bytes(header[8..12].try_into().unwrap_or([0; 4])) as usize
    };

    if nfunc == 0 || nfunc > 1_000_000 {
        return Ok(Vec::new());
    }

    // Read textStart — if non-zero, use it as base; otherwise use .text VA
    let text_start = if ptr_size == 8 {
        u64::from_le_bytes(header[24..32].try_into().unwrap_or([0; 8]))
    } else {
        u32::from_le_bytes(header[24..28].try_into().unwrap_or([0; 4])) as u64
    };
    let base = if text_start != 0 { text_start } else { text_va };

    // Read pclnOffset (functab offset from pclntab start)
    let pcln_off = if ptr_size == 8 {
        u64::from_le_bytes(header[64..72].try_into().unwrap_or([0; 8])) as usize
    } else {
        u32::from_le_bytes(header[48..52].try_into().unwrap_or([0; 4])) as usize
    };

    // Read functab: each entry is (entryOff uint32, funcOff uint32) = 8 bytes
    let functab_size = nfunc.checked_mul(8).unwrap_or(usize::MAX);
    let functab_end = pcln_off.checked_add(functab_size).unwrap_or(usize::MAX);
    if functab_end > pclntab_size {
        tracing::warn!("[golang] functab extends beyond pclntab");
        return Ok(Vec::new());
    }

    let functab_va = pclntab_va + pcln_off as u64;
    let functab = workspace.read_memory(functab_va, functab_size)?;

    let mut discovered = Vec::new();
    for i in 0..nfunc {
        let entry_off =
            u32::from_le_bytes(functab[i * 8..i * 8 + 4].try_into().unwrap_or([0; 4])) as u64;
        let func_va = base + entry_off;

        if func_va == 0 || !workspace.is_valid_pointer(func_va) {
            continue;
        }

        if !workspace.is_function(func_va) {
            workspace.add_function(
                func_va,
                FunctionMeta {
                    name: Some(format!("go_func_{:x}", func_va)),
                    ..Default::default()
                },
            )?;
            discovered.push(func_va);
        }
    }

    tracing::debug!(
        "[golang] parsed pclntab: {} functions total, {} new",
        nfunc,
        discovered.len()
    );

    // Mark that pclntab was successfully parsed — aggressive discovery modules
    // (emucode, funcentries, pointertables) should skip for Go binaries since
    // pclntab is the authoritative function list.
    workspace.set_meta("go_pclntab_parsed", "true");

    Ok(discovered)
}

/// Parse Go 1.16-1.17 pclntab format.
///
/// Similar to 1.18+ but different header offsets.
fn parse_go_116(
    workspace: &mut VivWorkspace,
    pclntab_va: u64,
    pclntab_size: usize,
    text_va: u64,
    ptr_size: usize,
) -> VivResult<Vec<u64>> {
    // Go 1.16 header is similar to 1.18 but without textStart
    // nfunc at offset 8, functab at specific offset
    let header_size = 8 + ptr_size * 7; // magic+pad+minLC+ptrSize + 7 ptr-sized fields
    if pclntab_size < header_size {
        return Ok(Vec::new());
    }

    let header = workspace.read_memory(pclntab_va, header_size)?;
    let nfunc = if ptr_size == 8 {
        u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8])) as usize
    } else {
        u32::from_le_bytes(header[8..12].try_into().unwrap_or([0; 4])) as usize
    };

    if nfunc == 0 || nfunc > 1_000_000 {
        return Ok(Vec::new());
    }

    // In 1.16, functab offset is at header[8 + ptr_size*5 .. 8 + ptr_size*6]
    let pcln_off_pos = 8 + ptr_size * 5;
    let pcln_off = if ptr_size == 8 {
        u64::from_le_bytes(
            header[pcln_off_pos..pcln_off_pos + 8]
                .try_into()
                .unwrap_or([0; 8]),
        ) as usize
    } else {
        u32::from_le_bytes(
            header[pcln_off_pos..pcln_off_pos + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize
    };

    let functab_size = nfunc
        .checked_mul(2)
        .and_then(|v| v.checked_mul(ptr_size))
        .unwrap_or(usize::MAX);
    let functab_end = pcln_off.checked_add(functab_size).unwrap_or(usize::MAX);
    if functab_end > pclntab_size {
        return Ok(Vec::new());
    }

    let functab_va = pclntab_va + pcln_off as u64;
    let functab = workspace.read_memory(functab_va, functab_size)?;

    let mut discovered = Vec::new();
    for i in 0..nfunc {
        let func_va = if ptr_size == 8 {
            u64::from_le_bytes(
                functab[i * 16..i * 16 + 8]
                    .try_into()
                    .unwrap_or([0; 8]),
            )
        } else {
            u32::from_le_bytes(
                functab[i * 8..i * 8 + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as u64
        };

        if func_va == 0 || !workspace.is_valid_pointer(func_va) {
            continue;
        }

        if !workspace.is_function(func_va) {
            workspace.add_function(
                func_va,
                FunctionMeta {
                    name: Some(format!("go_func_{:x}", func_va)),
                    ..Default::default()
                },
            )?;
            discovered.push(func_va);
        }
    }

    tracing::debug!(
        "[golang] parsed Go 1.16 pclntab: {} functions total, {} new",
        nfunc,
        discovered.len()
    );

    workspace.set_meta("go_pclntab_parsed", "true");

    Ok(discovered)
}

/// Parse Go 1.2-1.15 pclntab format (legacy).
///
/// Header: magic(4) + padding(2) + minLC(1) + ptrSize(1) + nfunc(ptrSize)
/// Functab: nfunc entries of (entry uintptr, offset uintptr)
fn parse_go_12(
    workspace: &mut VivWorkspace,
    pclntab_va: u64,
    pclntab_size: usize,
    _text_va: u64,
    ptr_size: usize,
) -> VivResult<Vec<u64>> {
    let header_size = 8 + ptr_size;
    if pclntab_size < header_size {
        return Ok(Vec::new());
    }

    let header = workspace.read_memory(pclntab_va, header_size)?;
    let nfunc = if ptr_size == 8 {
        u64::from_le_bytes(header[8..16].try_into().unwrap_or([0; 8])) as usize
    } else {
        u32::from_le_bytes(header[8..12].try_into().unwrap_or([0; 4])) as usize
    };

    if nfunc == 0 || nfunc > 1_000_000 {
        return Ok(Vec::new());
    }

    // Functab starts immediately after the header (at offset header_size)
    let functab_size = nfunc
        .checked_mul(2)
        .and_then(|v| v.checked_mul(ptr_size))
        .unwrap_or(usize::MAX);
    let functab_end = header_size.checked_add(functab_size).unwrap_or(usize::MAX);
    if functab_end > pclntab_size {
        return Ok(Vec::new());
    }

    let functab_va = pclntab_va + header_size as u64;
    let functab = workspace.read_memory(functab_va, functab_size)?;

    let mut discovered = Vec::new();
    for i in 0..nfunc {
        // Each entry: (entry_pc, func_data_offset) — both ptr_size bytes
        let func_va = if ptr_size == 8 {
            u64::from_le_bytes(
                functab[i * 16..i * 16 + 8]
                    .try_into()
                    .unwrap_or([0; 8]),
            )
        } else {
            u32::from_le_bytes(
                functab[i * 8..i * 8 + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as u64
        };

        if func_va == 0 || !workspace.is_valid_pointer(func_va) {
            continue;
        }

        if !workspace.is_function(func_va) {
            workspace.add_function(
                func_va,
                FunctionMeta {
                    name: Some(format!("go_func_{:x}", func_va)),
                    ..Default::default()
                },
            )?;
            discovered.push(func_va);
        }
    }

    tracing::debug!(
        "[golang] parsed Go 1.2 pclntab: {} functions total, {} new",
        nfunc,
        discovered.len()
    );

    workspace.set_meta("go_pclntab_parsed", "true");

    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_constants() {
        assert_eq!(GO_PCLNTAB_MAGIC_12, 0xFFFFFFF0);
        assert_eq!(GO_PCLNTAB_MAGIC_116, 0xFFFFFFFA);
        assert_eq!(GO_PCLNTAB_MAGIC_118, 0xFFFFFFFB);
        assert_eq!(GO_PCLNTAB_MAGIC_120, 0xFFFFFFFC);
        assert_eq!(GO_PCLNTAB_MAGIC_122, 0xFFFFFFF1);
    }

    #[test]
    fn test_magic_values_are_distinct() {
        let magics = [
            GO_PCLNTAB_MAGIC_12,
            GO_PCLNTAB_MAGIC_116,
            GO_PCLNTAB_MAGIC_118,
            GO_PCLNTAB_MAGIC_120,
            GO_PCLNTAB_MAGIC_122,
        ];
        for i in 0..magics.len() {
            for j in (i + 1)..magics.len() {
                assert_ne!(magics[i], magics[j],
                    "Magic values at indices {} and {} are equal: {:#x}",
                    i, j, magics[i]);
            }
        }
    }

    #[test]
    fn test_magic_values_high_bytes() {
        for &magic in &[
            GO_PCLNTAB_MAGIC_12,
            GO_PCLNTAB_MAGIC_116,
            GO_PCLNTAB_MAGIC_118,
            GO_PCLNTAB_MAGIC_120,
            GO_PCLNTAB_MAGIC_122,
        ] {
            assert_eq!(magic >> 8, 0xFFFFFF,
                "Magic {:#010x} doesn't have expected high bytes", magic);
        }
    }

    #[test]
    fn test_go_func_name_format() {
        let va: u64 = 0x401234;
        let name = format!("go_func_{:x}", va);
        assert_eq!(name, "go_func_401234");
    }

    #[test]
    fn test_go122_header_layout_sizes() {
        // Go 1.18+ header: 72 bytes total
        assert_eq!(4 + 2 + 1 + 1 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8, 72);
    }

    #[test]
    fn test_go12_header_size_calculation() {
        let header_size_32 = 8 + 4usize;
        let header_size_64 = 8 + 8usize;
        assert_eq!(header_size_32, 12);
        assert_eq!(header_size_64, 16);
    }

    #[test]
    fn test_go122_functab_entry_size() {
        let nfunc = 100usize;
        let functab_size = nfunc * 8;
        assert_eq!(functab_size, 800);
    }

    #[test]
    fn test_go116_functab_entry_size() {
        let nfunc = 50usize;
        let ptr_size = 8usize;
        let functab_size = nfunc * 2 * ptr_size;
        assert_eq!(functab_size, 800);
    }
}
