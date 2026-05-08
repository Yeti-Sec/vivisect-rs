//! Instruction hook analysis module (i386).
//!
//! Port of Python's `vivisect/analysis/i386/instrhook.py` (59 LOC).
//!
//! Detects STOS (store string) instructions and identifies their EDI/RDI
//! targets as potential pointers. STOS writes to the address in EDI/RDI,
//! so if that register points to a valid address, we should track it.
//!
//! Without full emulation, this module uses a simplified heuristic:
//! scan function blocks for STOS instructions and check for preceding
//! register setup that loads a pointer into EDI/RDI.

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// STOS family mnemonics.
const STOS_MNEMONICS: &[&str] = &["stosb", "stosd", "stosq", "stosw", "stos"];

/// Run instruction hook analysis.
///
/// Scans functions for STOS instructions and checks for pointer
/// targets loaded into EDI/RDI via preceding MOV/LEA instructions.
#[must_use]
pub fn analyze_instrhook(workspace: &mut VivWorkspace) -> VivResult<InstrHookStats> {
    let mut stats = InstrHookStats::default();
    let arch = workspace.architecture();

    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(stats),
    };

    let target_reg = match arch {
        Architecture::I386 => "edi",
        Architecture::Amd64 => "rdi",
        _ => return Ok(stats),
    };

    let funcs: Vec<u64> = workspace.get_functions();

    for func_va in funcs {
        let blocks: Vec<(u64, usize)> = workspace
            .get_function_blocks(func_va)
            .iter()
            .map(|b| (b.va, b.size))
            .collect();

        for &(block_va, block_size) in &blocks {
            let mut va = block_va;
            let block_end = block_va + block_size as u64;
            let mut last_lea_target: Option<u64> = None;

            while va < block_end {
                let bytes = match workspace.read_memory(va, 16) {
                    Ok(b) => b,
                    Err(_) => break,
                };

                let op = match disasm.disassemble(&bytes, va) {
                    Ok(op) if op.size > 0 => op,
                    _ => break,
                };

                // Track LEA/MOV into EDI/RDI
                if (op.mnem == "lea" || op.mnem == "mov") && !op.opers.is_empty() {
                    let dst_name = format!("{:?}", op.opers[0]);
                    if dst_name.to_lowercase().contains(target_reg) && op.opers.len() >= 2 {
                        if let Some(target) = op.opers[1].get_value(&op) {
                            if workspace.is_valid_pointer(target) {
                                last_lea_target = Some(target);
                            }
                        }
                    }
                }

                // Check for STOS instruction
                let mnem_lower = op.mnem.to_lowercase();
                if STOS_MNEMONICS.iter().any(|&s| mnem_lower.starts_with(s)) {
                    if let Some(target) = last_lea_target {
                        // EDI/RDI was loaded with a pointer before STOS
                        if workspace.get_location(target).is_none() {
                            workspace.add_location(
                                target,
                                arch.pointer_size(),
                                crate::constants::LocationType::Pointer,
                                None,
                            );
                            stats.pointers_found += 1;
                        }
                    }
                }

                va += op.size as u64;
            }
        }
    }

    tracing::debug!("[instrhook] found {} STOS-targeted pointers", stats.pointers_found);
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct InstrHookStats {
    pub pointers_found: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stos_mnemonics() {
        assert!(STOS_MNEMONICS.contains(&"stosb"));
        assert!(STOS_MNEMONICS.contains(&"stosd"));
        assert!(STOS_MNEMONICS.contains(&"stosq"));
    }

    #[test]
    fn test_instrhook_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_instrhook(&mut ws).unwrap();
        assert_eq!(result.pointers_found, 0);
    }
}
