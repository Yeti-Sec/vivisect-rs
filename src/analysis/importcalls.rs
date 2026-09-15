//! Import call discovery module (i386-specific).
//!
//! Port of Python's `vivisect/analysis/i386/importcalls.py`.
//!
//! Scans undefined memory for pointer-sized values pointing to LOC_IMPORT
//! locations. Checks if the 2 bytes preceding the pointer encode a `call`
//! instruction opcode (`\xff\x15` = call dword ptr [imm32]). If so, the
//! surrounding code hasn't been analyzed yet, so we run code flow analysis
//! starting from the call instruction to discover new functions.
//!
//! This catches "orphaned" code — functions that aren't reachable through
//! normal call-following from entry points but contain import calls.

use crate::analysis::codeflow::CodeFlowAnalyzer;
use crate::constants::{Architecture, LocationType};
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// Scan for import calls in undefined code regions.
///
/// Algorithm (matching Python's importcalls.analyze):
/// 1. Scan undefined memory for 4-byte-aligned values pointing to LOC_IMPORT
/// 2. Check if the 2 bytes before form `\xff\x15` (call [dword ptr imm32])
/// 3. Run code flow analysis from the call instruction (va - 2)
/// 4. Create functions discovered by code flow
///
/// Returns the list of newly discovered function VAs.
#[must_use]
pub fn analyze_importcalls(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();
    if arch != Architecture::I386 {
        return Ok(Vec::new());
    }

    let ptr_size = 4usize;
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    // Collect candidate call sites: addresses where a call [import] instruction
    // exists in undefined code.
    let mut call_sites: Vec<u64> = Vec::new();

    for seg in workspace.get_segments().to_vec() {
        let seg_end = seg.va + seg.size as u64;
        let mut va = seg.va;
        // Align to 4-byte boundary
        if va % ptr_size as u64 != 0 {
            va = (va / ptr_size as u64 + 1) * ptr_size as u64;
        }

        while va + ptr_size as u64 <= seg_end {
            // Skip if a location already exists here
            if let Some(loc) = workspace.get_location(va) {
                let next = va + loc.size as u64;
                va = if next % ptr_size as u64 != 0 {
                    (next / ptr_size as u64 + 1) * ptr_size as u64
                } else {
                    next
                };
                continue;
            }

            // Read 4-byte value
            let bytes = match workspace.read_memory(va, ptr_size) {
                Ok(b) => b,
                Err(_) => {
                    va += ptr_size as u64;
                    continue;
                }
            };

            let ptr_val = if is_little {
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            } else {
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            };

            // Check if target is a LOC_IMPORT
            if let Some(loc) = workspace.get_location(ptr_val) {
                if loc.ltype == LocationType::Import {
                    // Check if 2 bytes before this are \xff\x15 (call [dword ptr imm32])
                    if va >= 2 {
                        if let Ok(prefix) = workspace.read_memory(va - 2, 2) {
                            if prefix[0] == 0xff && prefix[1] == 0x15 {
                                // Also verify no location exists at the call instruction
                                if workspace.get_location(va - 2).is_none() {
                                    call_sites.push(va - 2);
                                }
                            }
                        }
                    }
                }
            }

            va += ptr_size as u64;
        }
    }

    if call_sites.is_empty() {
        return Ok(Vec::new());
    }

    tracing::debug!(
        "[importcalls] found {} candidate import call sites in undefined code",
        call_sites.len()
    );

    // Run code flow analysis from each call site
    let mut analyzer = CodeFlowAnalyzer::new().with_max_instructions(500_000);
    for &site in &call_sites {
        analyzer.add_entry_point(site);
    }

    let mut discovered = Vec::new();

    if let Ok(result) = analyzer.analyze(workspace) {
        for func_va in result.functions_discovered {
            if !workspace.is_function(func_va) {
                workspace.add_function(
                    func_va,
                    FunctionMeta {
                        name: Some(format!("sub_{:x}", func_va)),
                        ..Default::default()
                    },
                )?;
                discovered.push(func_va);
            }
        }
    }

    // Also create functions at the call sites themselves if they're
    // inside a function prologue (they might be mid-function, so check
    // if any call site is also a function entry)
    for &site in &call_sites {
        // Find the function that contains this call site by walking back
        // to find a function entry. The code flow analysis should have
        // already handled this, so we just log.
        if workspace.is_function(site) {
            tracing::trace!("[importcalls] call site {:#x} is already a function", site);
        }
    }

    tracing::debug!(
        "[importcalls] discovered {} new functions from import call sites",
        discovered.len()
    );

    Ok(discovered)
}
