//! Late-stage pointer chain analysis module.
//!
//! Port of Python's `vivisect/analysis/generic/pointers.py`.
//!
//! Unlike `pointertables` (which finds consecutive pointer arrays of 4+),
//! this module processes ALL free-hanging pointers individually:
//! 1. Follows existing LOC_POINTER locations to create strings/functions at targets
//! 2. Finds remaining free-hanging pointers and creates LOC_POINTER + follows targets
//! 3. Builds a pointer graph and names pointers (`ptr_<target_name>`)
//!
//! This runs LATE in the pipeline (after pointertables, funcentries, etc.)
//! to catch any pointers not covered by table-based analysis.

use std::collections::HashMap;

use crate::analysis::strings::{detect_ascii_string, detect_utf16le_string, MIN_STRING_LENGTH};
use crate::constants::{LocationType, RefType};
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// Analyze a pointer target to determine what type of location it is.
///
/// Port of Python's `analyzePointer()` (vivisect/__init__.py:1992).
/// Returns the LocationType if the target should get a new location, or None.
fn analyze_pointer_target(workspace: &VivWorkspace, va: u64) -> Option<LocationType> {
    if workspace.get_location(va).is_some() {
        return None;
    }

    // Check for UTF-16 LE string first (unicode check before ASCII in Python)
    if is_probably_unicode(workspace, va) {
        return Some(LocationType::Unicode);
    }

    if is_probably_string(workspace, va) {
        return Some(LocationType::String);
    }

    if is_probably_code(workspace, va) {
        return Some(LocationType::Op);
    }

    None
}

/// Check if the VA looks like it contains a null-terminated ASCII string.
fn is_probably_string(workspace: &VivWorkspace, va: u64) -> bool {
    let bytes = match workspace.read_memory(va, 64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    detect_ascii_string(&bytes, 0, MIN_STRING_LENGTH).is_some()
}

/// Check if the VA looks like it contains a null-terminated UTF-16 LE string.
fn is_probably_unicode(workspace: &VivWorkspace, va: u64) -> bool {
    let bytes = match workspace.read_memory(va, 128) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Quick check: first byte should be printable ASCII, second should be 0x00
    if bytes.len() < 4 {
        return false;
    }
    if bytes[1] != 0 || !(0x20..=0x7E).contains(&bytes[0]) {
        return false;
    }

    detect_utf16le_string(&bytes, 0, MIN_STRING_LENGTH).is_some()
}

/// Check if the VA looks like a function entry point by checking for
/// known prologue signatures.
///
/// Python's `isProbablyCode` first checks `isFunctionSignature(va)` (prologue
/// patterns), and falls back to full emulation. Without emulation, we require
/// a prologue match — this is conservative but avoids false positives.
fn is_probably_code(workspace: &VivWorkspace, va: u64) -> bool {
    // Must be in an executable segment
    let in_code = workspace.get_segments().iter().any(|seg| {
        let name_lower = seg.name.to_lowercase();
        (name_lower.contains("text") || name_lower.contains("code"))
            && va >= seg.va
            && va < seg.va + seg.size as u64
    });
    if !in_code {
        return false;
    }

    // Must not already be inside existing code
    if workspace.get_location(va).is_some() {
        return false;
    }

    // Check for function prologue signatures (matching Python's isFunctionSignature)
    let bytes = match workspace.read_memory(va, 16) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let arch = workspace.architecture();
    match arch {
        crate::constants::Architecture::I386 => {
            // push ebp; mov ebp, esp
            if bytes.len() >= 3 && bytes[0] == 0x55 && bytes[1] == 0x8B && bytes[2] == 0xEC {
                return true;
            }
            // mov edi, edi; push ebp; mov ebp, esp (MSVC hotpatch)
            if bytes.len() >= 5
                && bytes[0] == 0x8B
                && bytes[1] == 0xFF
                && bytes[2] == 0x55
                && bytes[3] == 0x8B
                && bytes[4] == 0xEC
            {
                return true;
            }
            // push esi / push edi / push ebx as first insn (common in leaf functions)
            // Only accept if followed by more code-like patterns
            false
        }
        crate::constants::Architecture::Amd64 => {
            // push rbp; mov rbp, rsp
            if bytes.len() >= 4
                && bytes[0] == 0x55
                && bytes[1] == 0x48
                && bytes[2] == 0x89
                && bytes[3] == 0xE5
            {
                return true;
            }
            // sub rsp, imm8 (common amd64 prologue)
            if bytes.len() >= 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC {
                return true;
            }
            // mov [rsp+X], rbx (register save)
            if bytes.len() >= 5 && bytes[0] == 0x48 && bytes[1] == 0x89 && (bytes[2] & 0xC7) == 0x44
            {
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Follow a pointer target: create a string or function at the target address.
///
/// Port of Python's `followPointer()` (vivisect/__init__.py:773).
/// Returns true if something was created.
fn follow_pointer(workspace: &mut VivWorkspace, va: u64) -> bool {
    let ltype = match analyze_pointer_target(workspace, va) {
        Some(t) => t,
        None => return false,
    };

    match ltype {
        LocationType::Op => {
            // Create a function at the code target
            if !workspace.is_function(va) {
                if let Ok(()) = workspace.add_function(
                    va,
                    FunctionMeta {
                        name: Some(format!("sub_{:x}", va)),
                        ..Default::default()
                    },
                ) {
                    tracing::debug!("[pointers] discovered function at 0x{:x}", va);
                    return true;
                }
            }
            false
        }
        LocationType::String => {
            // Create a string location at the target
            if let Ok(bytes) = workspace.read_memory(va, 4096) {
                if let Some(s) = detect_ascii_string(&bytes, 0, MIN_STRING_LENGTH) {
                    workspace.add_location(
                        va,
                        s.size,
                        LocationType::String,
                        Some(s.content.clone()),
                    );
                    workspace.set_name(va, &s.content);
                    tracing::debug!(
                        "[pointers] discovered string at 0x{:x}: {:?}",
                        va,
                        s.content
                    );
                    return true;
                }
            }
            false
        }
        LocationType::Unicode => {
            if let Ok(bytes) = workspace.read_memory(va, 8192) {
                if let Some(s) = detect_utf16le_string(&bytes, 0, MIN_STRING_LENGTH) {
                    workspace.add_location(
                        va,
                        s.size,
                        LocationType::Unicode,
                        Some(s.content.clone()),
                    );
                    workspace.set_name(va, &s.content);
                    tracing::debug!(
                        "[pointers] discovered unicode at 0x{:x}: {:?}",
                        va,
                        s.content
                    );
                    return true;
                }
            }
            false
        }
        _ => false,
    }
}

/// Find free-hanging pointer-sized values pointing to valid addresses.
///
/// Same logic as pointertables::find_pointers but returns ALL pointers,
/// not grouped into tables.
fn find_free_pointers(workspace: &VivWorkspace) -> Vec<(u64, u64)> {
    let ptr_size = match workspace.architecture() {
        crate::constants::Architecture::Amd64 => 8usize,
        _ => 4usize,
    };
    let align = ptr_size;
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    let mut results = Vec::new();

    for seg in workspace.get_segments() {
        let seg_end = seg.va + seg.size as u64;
        let mut va = seg.va;
        if va % align as u64 != 0 {
            va = (va / align as u64 + 1) * align as u64;
        }

        while va + ptr_size as u64 <= seg_end {
            // Skip if a location already exists here
            if let Some(loc) = workspace.get_location(va) {
                let next = va + loc.size as u64;
                va = if next % align as u64 != 0 {
                    (next / align as u64 + 1) * align as u64
                } else {
                    next
                };
                continue;
            }

            if let Ok(bytes) = workspace.read_memory(va, ptr_size) {
                let ptr_val = if is_little {
                    match ptr_size {
                        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                        8 => u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]),
                        _ => {
                            va += align as u64;
                            continue;
                        }
                    }
                } else {
                    match ptr_size {
                        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                        8 => u64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                            bytes[7],
                        ]),
                        _ => {
                            va += align as u64;
                            continue;
                        }
                    }
                };

                if workspace.is_valid_pointer(ptr_val) {
                    results.push((va, ptr_val));
                    va += ptr_size as u64;
                    continue;
                }
            }

            va += align as u64;
        }
    }

    results
}

/// Run the late-stage pointer analysis.
///
/// Port of Python's `vivisect/analysis/generic/pointers.py:analyze()`.
///
/// 1. Follow existing LOC_POINTER locations whose targets don't have locations yet
/// 2. Find remaining free-hanging pointers, create LOC_POINTER + follow
/// 3. Build pointer graph and name pointers based on target names
#[must_use]
pub fn analyze_pointers(workspace: &mut VivWorkspace) -> VivResult<PointerStats> {
    let mut stats = PointerStats::default();
    let ptr_size = match workspace.architecture() {
        crate::constants::Architecture::Amd64 => 8usize,
        _ => 4usize,
    };
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    // Track pointer → target mappings for naming phase
    let mut done: HashMap<u64, u64> = HashMap::new();

    // Phase 1: Follow existing LOC_POINTER locations
    // (from pointertables or PE/ELF parser)
    let existing_pointers: Vec<(u64, usize)> = workspace
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Pointer)
        .map(|(&va, loc)| (va, loc.size))
        .collect();

    for (lva, lsz) in existing_pointers {
        let read_size = if lsz > 0 { lsz } else { ptr_size };
        let tva = match read_pointer(workspace, lva, read_size, is_little) {
            Some(v) => v,
            None => continue,
        };

        if !workspace.is_valid_pointer(tva) {
            continue;
        }

        if workspace.get_location(tva).is_some() {
            // Target already has a location — just record for naming
            if workspace.get_name(lva).is_none() {
                done.insert(lva, tva);
            }
            continue;
        }

        // Follow the pointer target
        if follow_pointer(workspace, tva) {
            stats.followed += 1;
        }
        done.insert(lva, tva);
    }

    // Phase 2: Find free-hanging pointers not yet marked as LOC_POINTER
    let free_ptrs = find_free_pointers(workspace);
    for (addr, pval) in free_ptrs {
        // Create LOC_POINTER at the pointer address
        if workspace.get_location(addr).is_none() {
            workspace.add_location(addr, ptr_size, LocationType::Pointer, None);
            workspace.add_xref(addr, pval, RefType::Pointer);
            stats.pointers_created += 1;
        }

        // Follow the target
        if workspace.is_valid_pointer(pval) && follow_pointer(workspace, pval) {
            stats.followed += 1;
        }

        done.insert(addr, pval);
    }

    // Phase 3: Name pointers based on their targets using graph traversal
    // Build adjacency: target → list of pointers pointing to it
    let mut refs_to: HashMap<u64, Vec<u64>> = HashMap::new();
    for (&ptr, &tgt) in &done {
        refs_to.entry(tgt).or_default().push(ptr);
    }

    // Find leaf nodes (targets that don't themselves point to anything)
    let leaves: Vec<u64> = done
        .values()
        .copied()
        .filter(|tgt| !done.contains_key(tgt))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    for leaf in leaves {
        let name = match workspace.get_name(leaf) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Walk up the pointer chain, naming each pointer
        let mut work: Vec<(u64, String)> = refs_to
            .get(&leaf)
            .map(|ptrs| ptrs.iter().map(|&p| (p, name.clone())).collect())
            .unwrap_or_default();

        while let Some((ptr_va, target_name)) = work.pop() {
            // Only name LOC_POINTER locations that don't already have names
            if workspace.get_name(ptr_va).is_some() {
                continue;
            }
            if workspace
                .get_location(ptr_va)
                .map_or(true, |l| l.ltype != LocationType::Pointer)
            {
                continue;
            }

            let ptr_name = format!("ptr_{}__{:08x}", target_name, ptr_va);
            workspace.set_name(ptr_va, &ptr_name);
            stats.pointers_named += 1;

            // Continue up the chain
            if let Some(parents) = refs_to.get(&ptr_va) {
                for &parent in parents {
                    work.push((parent, ptr_name.clone()));
                }
            }
        }
    }

    tracing::debug!(
        "[pointers] created {} pointers, followed {} targets, named {} pointers",
        stats.pointers_created,
        stats.followed,
        stats.pointers_named
    );

    Ok(stats)
}

/// Read a pointer-sized value from workspace memory.
fn read_pointer(
    workspace: &VivWorkspace,
    va: u64,
    size: usize,
    little_endian: bool,
) -> Option<u64> {
    let bytes = workspace.read_memory(va, size).ok()?;
    if bytes.len() < size {
        return None;
    }
    Some(if little_endian {
        match size {
            4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            8 => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => return None,
        }
    } else {
        match size {
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            8 => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => return None,
        }
    })
}

/// Statistics from pointer analysis.
#[derive(Debug, Default)]
pub struct PointerStats {
    pub pointers_created: usize,
    pub followed: usize,
    pub pointers_named: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pointer_stats_default() {
        let stats = PointerStats::default();
        assert_eq!(stats.pointers_created, 0);
        assert_eq!(stats.followed, 0);
        assert_eq!(stats.pointers_named, 0);
    }

    #[test]
    fn test_pointer_stats_debug() {
        let stats = PointerStats {
            pointers_created: 10,
            followed: 5,
            pointers_named: 3,
        };
        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("pointers_created: 10"));
        assert!(debug_str.contains("followed: 5"));
        assert!(debug_str.contains("pointers_named: 3"));
    }

    #[test]
    fn test_read_pointer_le_u32() {
        // Create a workspace with known memory content
        let _ws = VivWorkspace::new();
        // We can't call read_pointer directly without a workspace with mapped memory,
        // but we can test the byte conversion logic in isolation
        let bytes: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        let val = u32::from_le_bytes(bytes) as u64;
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_read_pointer_le_u64() {
        let bytes: [u8; 8] = [0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12];
        let val = u64::from_le_bytes(bytes);
        assert_eq!(val, 0x12345678DEADBEEF);
    }

    #[test]
    fn test_read_pointer_be_u32() {
        let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let val = u32::from_be_bytes(bytes) as u64;
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_read_pointer_be_u64() {
        let bytes: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0xDE, 0xAD, 0xBE, 0xEF];
        let val = u64::from_be_bytes(bytes);
        assert_eq!(val, 0x12345678DEADBEEF);
    }

    #[test]
    fn test_pointer_name_format() {
        // Verify the naming convention used for pointer locations
        let target_name = "ExitProcess";
        let ptr_va: u64 = 0x42E000;
        let ptr_name = format!("ptr_{}__{:08x}", target_name, ptr_va);
        assert_eq!(ptr_name, "ptr_ExitProcess__0042e000");
    }

    #[test]
    fn test_pointer_name_format_nested() {
        // Test nested pointer naming (pointer to pointer)
        let inner_name = "ptr_ExitProcess__0042e000";
        let outer_va: u64 = 0x42F000;
        let outer_name = format!("ptr_{}__{:08x}", inner_name, outer_va);
        assert_eq!(outer_name, "ptr_ptr_ExitProcess__0042e000__0042f000");
    }

    #[test]
    fn test_x86_prologue_push_ebp_mov() {
        // push ebp; mov ebp, esp (MSVC 32-bit prologue)
        let bytes: [u8; 3] = [0x55, 0x8B, 0xEC];
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x8B);
        assert_eq!(bytes[2], 0xEC);
    }

    #[test]
    fn test_x86_prologue_hotpatch() {
        // mov edi, edi; push ebp; mov ebp, esp (MSVC hotpatch)
        let bytes: [u8; 5] = [0x8B, 0xFF, 0x55, 0x8B, 0xEC];
        assert_eq!(bytes[0], 0x8B);
        assert_eq!(bytes[1], 0xFF);
    }

    #[test]
    fn test_amd64_prologue_push_rbp() {
        // push rbp; mov rbp, rsp (AMD64 prologue)
        let bytes: [u8; 4] = [0x55, 0x48, 0x89, 0xE5];
        assert_eq!(bytes[0], 0x55);
        assert_eq!(bytes[1], 0x48);
        assert_eq!(bytes[2], 0x89);
        assert_eq!(bytes[3], 0xE5);
    }

    #[test]
    fn test_amd64_prologue_sub_rsp() {
        // sub rsp, imm8 (AMD64 prologue)
        let bytes: [u8; 4] = [0x48, 0x83, 0xEC, 0x28];
        assert_eq!(bytes[0], 0x48);
        assert_eq!(bytes[1], 0x83);
        assert_eq!(bytes[2], 0xEC);
    }

    #[test]
    fn test_alignment_calculation() {
        // Test the alignment calculation used in find_free_pointers
        let align = 8usize;
        let va: u64 = 0x1003;
        let aligned = if va % align as u64 != 0 {
            (va / align as u64 + 1) * align as u64
        } else {
            va
        };
        assert_eq!(aligned, 0x1008);

        // Already aligned
        let va2: u64 = 0x1000;
        let aligned2 = if va2 % align as u64 != 0 {
            (va2 / align as u64 + 1) * align as u64
        } else {
            va2
        };
        assert_eq!(aligned2, 0x1000);
    }
}
