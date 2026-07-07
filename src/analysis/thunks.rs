//! Thunk identification module.
//!
//! Identifies functions that are simple wrappers/forwarders:
//! - **Import thunks**: single-block functions whose only instruction is an
//!   indirect jump through an IAT entry (LOC_IMPORT)
//! - **Internal thunks**: single-block functions whose last instruction is an
//!   unconditional branch/call to another known function
//!
//! Port of Python's `vivisect/analysis/generic/thunks.py`.

use crate::constants::{Architecture, BranchFlags, LocationType};
use crate::core::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Identify import thunks for a single function.
///
/// Decodes the first instruction and checks if it's an indirect jump/call
/// through a LOC_IMPORT location (IAT entry). If so, marks the function
/// as a thunk to that import.
///
/// Corresponds to Python's `thunks.analyzeFunction()`.
pub fn analyze_import_thunk(workspace: &mut VivWorkspace, func_va: u64) {
    let disasm = match workspace.architecture() {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return,
    };

    // Read enough bytes for the first instruction
    let bytes = match workspace.read_memory(func_va, 16) {
        Ok(b) => b,
        Err(_) => return,
    };

    let op = match disasm.disassemble(&bytes, func_va) {
        Ok(op) => op,
        Err(_) => return,
    };

    // Must be a branch or call
    if !op.is_branch() && !op.is_call() {
        return;
    }

    // Check each operand for an indirect reference to an import
    for oper in &op.opers {
        if !oper.is_deref() {
            continue;
        }

        // Get the memory address being dereferenced (e.g., [0x42e000])
        let addr = match oper.get_address(&op) {
            Some(a) => a,
            None => continue,
        };

        // Check if that address is a LOC_IMPORT
        let loc = match workspace.get_location(addr) {
            Some(loc) => loc,
            None => continue,
        };

        if loc.ltype != LocationType::Import {
            continue;
        }

        // This function jumps through an import — mark it as an import thunk
        let import_name = loc.tinfo.clone().unwrap_or_default();
        if let Some(meta) = workspace.get_function_mut(func_va) {
            meta.meta
                .insert("Thunk".to_string(), import_name.clone());
        }

        // Rename the function
        if !import_name.is_empty() {
            let basename = import_name.rsplit('.').next().unwrap_or(&import_name);
            let thunk_name = format!("thunk_{}", basename);
            workspace.set_function_name(func_va, &thunk_name);
        }

        return;
    }
}

/// Scan all functions for non-import thunks.
///
/// A non-import thunk is a single-block function whose last instruction is an
/// unconditional branch or call to another known function. These are typically
/// trampolines, wrappers, or PLT-style stubs.
///
/// Also handles indirect branches by resolving memory operand addresses
/// and reading the target pointer from workspace memory.
///
/// Corresponds to Python's `thunks.analyze()`.
#[must_use]
pub fn scan_thunks(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let disasm = match workspace.architecture() {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(Vec::new()),
    };
    let ptr_size = workspace.architecture().pointer_size();

    let functions: Vec<u64> = workspace.get_functions();
    let mut thunks_found = Vec::new();

    for fva in functions {
        // Skip already-identified thunks
        if workspace.is_function_thunk(fva) {
            continue;
        }

        // Must be a single-block function
        let blocks = workspace.get_function_blocks(fva);
        if blocks.len() != 1 {
            continue;
        }

        let block = &blocks[0];
        if block.size == 0 {
            continue;
        }

        // Find the last instruction in the block by walking forward
        let last_op = {
            let bytes = match workspace.read_memory(block.va, block.size) {
                Ok(b) => b,
                Err(_) => continue,
            };

            let mut last = None;
            let mut offset = 0u64;
            while offset < block.size as u64 {
                let remaining = &bytes[offset as usize..];
                match disasm.disassemble(remaining, block.va + offset) {
                    Ok(op) => {
                        offset += op.size as u64;
                        last = Some(op);
                    }
                    Err(_) => break,
                }
            }
            match last {
                Some(op) => op,
                None => continue,
            }
        };

        // Last instruction must be a branch or call
        if !last_op.is_branch() && !last_op.is_call() {
            continue;
        }

        // First check: is this an indirect branch to an import? (jmp [IAT_addr])
        if let Some((import_name, _import_va)) = check_import_branch(&last_op, workspace) {
            if let Some(meta) = workspace.get_function_mut(fva) {
                meta.meta
                    .insert("Thunk".to_string(), import_name.clone());
            }
            let basename = import_name.rsplit('.').next().unwrap_or(&import_name);
            let thunk_name = format!("thunk_{}", basename);
            workspace.set_function_name(fva, &thunk_name);
            thunks_found.push(fva);
            continue;
        }

        // Second check: is this a direct branch to another known function?
        let target_va = resolve_branch_target(&last_op, workspace, ptr_size);
        let target_va = match target_va {
            Some(va) => va,
            None => continue,
        };

        // Target must be a known function
        if !workspace.is_function(target_va) {
            continue;
        }

        // Don't thunk to yourself
        if target_va == fva {
            continue;
        }

        // This is a thunk — get the target's name
        let target_name = workspace
            .get_name(target_va)
            .or_else(|| {
                workspace
                    .get_function(target_va)
                    .and_then(|m| m.name.as_deref())
            })
            .unwrap_or("unknown")
            .to_string();

        // Check if the current function has a generic name
        let current_name = workspace
            .get_function(fva)
            .and_then(|m| m.name.as_deref())
            .unwrap_or("")
            .to_string();

        let is_generic = current_name.starts_with("sub_")
            || current_name.starts_with("entry_")
            || current_name.is_empty();

        // Mark as thunk
        if let Some(meta) = workspace.get_function_mut(fva) {
            meta.meta
                .insert("Thunk".to_string(), target_name.clone());
        }

        // Only rename if the current name is generic
        if is_generic && !target_name.is_empty() && target_name != "unknown" {
            let basename = target_name.rsplit('.').next().unwrap_or(&target_name);
            let thunk_name = format!("thunk_{}", basename);
            workspace.set_function_name(fva, &thunk_name);
        }

        thunks_found.push(fva);
    }

    Ok(thunks_found)
}

/// Check if an instruction is an indirect branch/call through a LOC_IMPORT location.
///
/// Returns `Some((import_name, import_va))` if the instruction dereferences
/// an import entry (e.g., `jmp [0x42e000]` where 0x42e000 is LOC_IMPORT).
fn check_import_branch(
    op: &crate::envi::Opcode,
    workspace: &VivWorkspace,
) -> Option<(String, u64)> {
    for oper in &op.opers {
        if !oper.is_deref() {
            continue;
        }
        let addr = oper.get_address(op)?;
        let loc = workspace.get_location(addr)?;
        if loc.ltype == LocationType::Import {
            let name = loc.tinfo.clone().unwrap_or_default();
            return Some((name, addr));
        }
    }
    None
}

/// Resolve the target address of a branch/call instruction.
///
/// Handles both direct branches (target in immediate/pc-relative operand)
/// and indirect branches (target read from memory via deref operand).
fn resolve_branch_target(
    op: &crate::envi::Opcode,
    workspace: &VivWorkspace,
    ptr_size: usize,
) -> Option<u64> {
    // First try direct resolution via get_targets()
    let targets = op.get_targets();
    if targets.len() == 1 && !targets[0].1.contains(BranchFlags::FALL) {
        return Some(targets[0].0);
    }

    // For indirect branches (jmp [addr]), resolve via memory read
    for oper in &op.opers {
        if !oper.is_deref() {
            continue;
        }

        let addr = match oper.get_address(op) {
            Some(a) => a,
            None => continue,
        };

        // Read the pointer at that address
        let bytes = match workspace.read_memory(addr, ptr_size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let target = if ptr_size == 4 {
            u32::from_le_bytes(bytes[..4].try_into().ok()?) as u64
        } else {
            u64::from_le_bytes(bytes[..8].try_into().ok()?)
        };

        if workspace.is_valid_pointer(target) {
            return Some(target);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thunk_name_format_simple() {
        let import_name = "ExitProcess";
        let basename = import_name.rsplit('.').next().unwrap_or(import_name);
        let thunk_name = format!("thunk_{}", basename);
        assert_eq!(thunk_name, "thunk_ExitProcess");
    }

    #[test]
    fn test_thunk_name_format_with_library() {
        let import_name = "kernel32.ExitProcess";
        let basename = import_name.rsplit('.').next().unwrap_or(import_name);
        let thunk_name = format!("thunk_{}", basename);
        assert_eq!(thunk_name, "thunk_ExitProcess");
    }

    #[test]
    fn test_thunk_name_format_no_dot() {
        let import_name = "printf";
        let basename = import_name.rsplit('.').next().unwrap_or(import_name);
        let thunk_name = format!("thunk_{}", basename);
        assert_eq!(thunk_name, "thunk_printf");
    }

    #[test]
    fn test_thunk_name_format_multiple_dots() {
        let import_name = "api-ms-win-core-console.WriteConsoleW";
        let basename = import_name.rsplit('.').next().unwrap_or(import_name);
        let thunk_name = format!("thunk_{}", basename);
        assert_eq!(thunk_name, "thunk_WriteConsoleW");
    }

    #[test]
    fn test_generic_name_detection() {
        // Test the logic for identifying generic function names
        let generic_names = vec!["sub_401000", "sub_0", "entry_1", "entry_main", ""];
        let non_generic_names = vec!["main", "ExitProcess", "thunk_printf", "my_func"];

        for name in generic_names {
            let is_generic = name.starts_with("sub_")
                || name.starts_with("entry_")
                || name.is_empty();
            assert!(is_generic, "Expected '{}' to be generic", name);
        }

        for name in non_generic_names {
            let is_generic = name.starts_with("sub_")
                || name.starts_with("entry_")
                || name.is_empty();
            assert!(!is_generic, "Expected '{}' to NOT be generic", name);
        }
    }

    #[test]
    fn test_ptr_size_from_architecture() {
        // Architecture::pointer_size() is used in resolve_branch_target
        assert_eq!(Architecture::I386.pointer_size(), 4);
        assert_eq!(Architecture::Amd64.pointer_size(), 8);
    }

    #[test]
    fn test_pointer_read_u32_le() {
        let bytes = [0x78u8, 0x56, 0x34, 0x12];
        let target = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
        assert_eq!(target, 0x12345678);
    }

    #[test]
    fn test_pointer_read_u64_le() {
        let bytes = [0xEFu8, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12];
        let target = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(target, 0x12345678DEADBEEF);
    }

    #[test]
    fn test_location_type_import() {
        // Verify the LocationType::Import constant used in thunk detection
        assert_ne!(LocationType::Import, LocationType::Op);
        assert_ne!(LocationType::Import, LocationType::Pointer);
    }
}
