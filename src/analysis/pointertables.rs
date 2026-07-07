//! Pointer table discovery module.
//!
//! Port of Python's `vivisect/analysis/generic/pointertables.py`.
//!
//! Scans all memory for pointer-aligned values pointing to valid addresses.
//! Groups consecutive aligned pointers into arrays and creates LOC_POINTER
//! locations. For pointers that target code sections, creates functions at
//! the target address (matching Python's `makePointer` → `followPointer`
//! → `makeFunction` chain).
//!
//! This is a key function discovery module — vtables, callback arrays,
//! and similar data structures contain pointers to functions that aren't
//! reachable via call-following analysis.

use crate::constants::LocationType;
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Minimum number of consecutive aligned pointers to qualify as a table.
/// Python default: `vw.config.viv.analysis.pointertables.table_min_len` = 4
/// (from vivisect/defconfig.py).
const TABLE_MIN_LEN: usize = 4;

/// Scan memory for aligned pointer-sized values that point to valid addresses,
/// skipping addresses that already have locations defined.
///
/// Port of Python's `vw.findPointers()` (vivisect/__init__.py:957).
///
/// Returns `(pointer_va, target_va)` pairs.
fn find_pointers(workspace: &VivWorkspace) -> Vec<(u64, u64)> {
    let ptr_size = match workspace.architecture() {
        crate::constants::Architecture::Amd64 => 8usize,
        _ => 4usize,
    };
    let align = ptr_size;
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    let mut results = Vec::new();

    for seg in workspace.get_segments() {
        let seg_end = seg.va + seg.size as u64;
        // Align start to pointer boundary
        let mut va = seg.va;
        if va % align as u64 != 0 {
            va = (va / align as u64 + 1) * align as u64;
        }

        while va + ptr_size as u64 <= seg_end {
            // Skip if a location already exists here
            if workspace.get_location(va).is_some() {
                // Advance past the existing location
                if let Some(loc) = workspace.get_location(va) {
                    let next = va + loc.size as u64;
                    va = if next % align as u64 != 0 {
                        (next / align as u64 + 1) * align as u64
                    } else {
                        next
                    };
                } else {
                    va += align as u64;
                }
                continue;
            }

            // Read pointer-sized value
            if let Ok(bytes) = workspace.read_memory(va, ptr_size) {
                let ptr_val = if is_little {
                    match ptr_size {
                        4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                        8 => u64::from_le_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3],
                            bytes[4], bytes[5], bytes[6], bytes[7],
                        ]),
                        _ => { va += align as u64; continue; }
                    }
                } else {
                    match ptr_size {
                        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                        8 => u64::from_be_bytes([
                            bytes[0], bytes[1], bytes[2], bytes[3],
                            bytes[4], bytes[5], bytes[6], bytes[7],
                        ]),
                        _ => { va += align as u64; continue; }
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

/// Check if a target VA is inside an executable code segment.
fn is_code_target(workspace: &VivWorkspace, target: u64) -> bool {
    for seg in workspace.get_segments() {
        let name_lower = seg.name.to_lowercase();
        if name_lower.contains("text") || name_lower.contains("code") {
            if target >= seg.va && target < seg.va + seg.size as u64 {
                return true;
            }
        }
    }
    false
}

/// Validate that a target address looks like real code by disassembling
/// at least 3 instructions successfully.
fn validate_code_target(workspace: &VivWorkspace, target: u64, disasm: &X86Disassembler) -> bool {
    let bytes = match workspace.read_memory(target, 32) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let mut valid_insns = 0;
    let mut offset = 0u64;
    while offset < bytes.len() as u64 && valid_insns < 3 {
        let remaining = &bytes[offset as usize..];
        match disasm.disassemble(remaining, target + offset) {
            Ok(op) => {
                if op.size == 0 {
                    break;
                }
                offset += op.size as u64;
                valid_insns += 1;
            }
            Err(_) => break,
        }
    }

    valid_insns >= 3
}

/// Run pointer table analysis.
///
/// 1. Find all pointer-aligned values in memory that point to valid addresses
/// 2. Group consecutive aligned pointers into arrays (minimum TABLE_MIN_LEN)
/// 3. For each pointer in a qualifying table:
///    - Create a LOC_POINTER location at the pointer's VA
///    - If the target is in a code section, create a function there
///
/// Returns the list of newly discovered function VAs.
#[must_use]
pub fn analyze_pointertables(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();
    let ptr_size = match arch {
        crate::constants::Architecture::Amd64 => 8usize,
        _ => 4usize,
    };

    let disasm = match arch {
        crate::constants::Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        crate::constants::Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(Vec::new()),
    };

    let pointers = find_pointers(workspace);
    if pointers.is_empty() {
        return Ok(Vec::new());
    }

    // Group consecutive aligned pointers into arrays
    let mut tables: Vec<Vec<(u64, u64)>> = Vec::new();
    let mut current: Vec<(u64, u64)> = Vec::new();

    for (va, target) in &pointers {
        if let Some(&(last_va, _)) = current.last() {
            if *va == last_va + ptr_size as u64 {
                // Consecutive — extend current table
                current.push((*va, *target));
            } else {
                // Gap — save current table if big enough, start new one
                if current.len() >= TABLE_MIN_LEN {
                    tables.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                current.push((*va, *target));
            }
        } else {
            current.push((*va, *target));
        }
    }
    // Don't forget the last group
    if current.len() >= TABLE_MIN_LEN {
        tables.push(current);
    }

    let mut discovered_functions = Vec::new();

    for table in &tables {
        for &(ptr_va, target_va) in table {
            // Create LOC_POINTER at the pointer's address (if not already defined)
            if workspace.get_location(ptr_va).is_none() {
                workspace.add_location(ptr_va, ptr_size, LocationType::Pointer, None);
            }

            // Add ptr xref
            workspace.add_xref(ptr_va, target_va, crate::constants::RefType::Data);

            // If target is in a code section and not already a function, create one
            // This matches Python's followPointer → makeFunction chain
            if is_code_target(workspace, target_va) && !workspace.is_function(target_va) {
                // Skip targets that are inside existing code (mid-instruction/block)
                if workspace.get_location(target_va).is_some() {
                    continue;
                }

                // Validate by disassembling at least 3 instructions
                if validate_code_target(workspace, target_va, &disasm) {
                    workspace.add_function(
                        target_va,
                        FunctionMeta {
                            name: Some(format!("sub_{:x}", target_va)),
                            ..Default::default()
                        },
                    )?;
                    discovered_functions.push(target_va);
                }
            }
        }
    }

    tracing::debug!(
        "[pointertables] found {} tables with {} total pointers, {} new functions",
        tables.len(),
        tables.iter().map(|t| t.len()).sum::<usize>(),
        discovered_functions.len()
    );

    Ok(discovered_functions)
}
