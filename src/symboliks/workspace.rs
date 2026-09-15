//! Workspace-integrated symbolic analysis.
//!
//! Bridges the symboliks subsystem to VivWorkspace, enabling symbolic
//! execution of real functions from analyzed binaries.
//!
//! Key functions:
//! - `build_function_graph()` — translate a workspace function into a SymbolikGraph
//! - `analyze_function()` — run symbolic analysis on a workspace function
//! - `resolve_indirect_jump()` — use symbolic state to resolve switch/jump table targets

use std::collections::HashSet;

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::envi::opcode::Opcode;

use super::analysis::{PathResult, SymbolikAnalysisContext, SymbolikGraph};
use super::value::SymbolicValue;

/// Build a SymbolikGraph from a workspace function.
///
/// This is the workspace integration bridge — it reads a function's code blocks
/// from the workspace, disassembles them, and feeds them into the
/// SymbolikAnalysisContext to produce a symbolic graph.
///
/// Port of Python's `SymbolikAnalysisContext.getSymbolikGraph(fva)`.
#[must_use]
pub fn build_function_graph(workspace: &VivWorkspace, func_va: u64) -> Option<SymbolikGraph> {
    let arch = workspace.architecture();
    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return None,
    };

    let ptr_size = arch.pointer_size() as u8;
    let ctx = SymbolikAnalysisContext::new(ptr_size);

    let blocks = workspace.get_function_blocks(func_va);
    if blocks.is_empty() {
        return None;
    }

    // Build block data: (va, opcodes, successor_vas)
    let mut block_data: Vec<(u64, Vec<Opcode>, Vec<u64>)> = Vec::new();

    for block in &blocks {
        let mut opcodes = Vec::new();
        let mut va = block.va;
        let block_end = block.va + block.size as u64;

        while va < block_end {
            let bytes = match workspace.read_memory(va, 16) {
                Ok(b) => b,
                Err(_) => break,
            };

            match disasm.disassemble(&bytes, va) {
                Ok(op) if op.size > 0 => {
                    let op_size = op.size as u64;
                    opcodes.push(op);
                    va += op_size;
                }
                _ => break,
            }
        }

        // Get successor blocks from workspace CFG
        let successors: Vec<u64> = workspace
            .get_block_successors(block.va)
            .into_iter()
            // Only include successors that are blocks in this function
            .filter(|&succ| blocks.iter().any(|b| b.va == succ))
            .collect();

        block_data.push((block.va, opcodes, successors));
    }

    Some(ctx.build_symbolik_graph(func_va, block_data))
}

/// Run symbolic analysis on a workspace function.
///
/// Returns all path results from symbolic execution.
pub fn analyze_function(
    workspace: &VivWorkspace,
    func_va: u64,
    max_paths: usize,
) -> Vec<PathResult> {
    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size() as u8;

    let graph = match build_function_graph(workspace, func_va) {
        Some(g) => g,
        None => return Vec::new(),
    };

    let mut ctx = SymbolikAnalysisContext::new(ptr_size);
    ctx.set_max_paths(max_paths);

    ctx.walk_symbolik_paths(&graph)
}

/// Information about a resolved indirect jump target.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// The computed target address.
    pub target_va: u64,
    /// The symbolic value that was evaluated.
    pub symbolic_target: SymbolicValue,
    /// Path constraints that led to this target.
    pub constraints: Vec<SymbolicValue>,
}

/// Resolve indirect jump targets at a specific VA within a function.
///
/// Walks symbolic paths through the function, and at the specified jump VA,
/// evaluates the symbolic target expression to determine possible concrete
/// target addresses.
///
/// This is the core of switch case resolution — it determines what values
/// the jump target can take by evaluating the symbolic expression for each
/// path that reaches the jump instruction.
pub fn resolve_indirect_jump(
    workspace: &VivWorkspace,
    func_va: u64,
    jump_va: u64,
    max_paths: usize,
) -> Vec<ResolvedTarget> {
    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size() as u8;

    let graph = match build_function_graph(workspace, func_va) {
        Some(g) => g,
        None => return Vec::new(),
    };

    let mut ctx = SymbolikAnalysisContext::new(ptr_size);
    ctx.set_max_paths(max_paths);

    let path_results = ctx.walk_symbolik_paths(&graph);
    let mut resolved = Vec::new();
    let mut seen_targets = HashSet::new();

    for pr in &path_results {
        // Check if this path visits the block containing the jump
        let jump_block = graph
            .blocks
            .values()
            .find(|b| b.opcodes.iter().any(|op| op.va == jump_va));

        // Find the jump instruction and get the target operand's symbolic value
        let jump_block = match jump_block {
            Some(b) => b,
            None => continue,
        };
        if !pr.path.contains(&jump_block.va) {
            continue;
        }

        // The target of an indirect jump is typically in a register or memory operand.
        // Check what value the jump target register holds at the end of this path.
        // For `jmp [table + idx*scale]`, the last effect before the jump should set
        // a temporary or the target register.

        // Look at the block's effects for the jump instruction
        for effect in &jump_block.effects {
            if let super::effect::SymbolicEffect::SetVariable { va, name: _, value } = effect {
                if *va == jump_va {
                    // This effect is from the jump instruction
                    // Try to evaluate the target
                    if let Some(target) = value.as_const() {
                        if workspace.is_valid_pointer(target) && !seen_targets.contains(&target) {
                            seen_targets.insert(target);
                            resolved.push(ResolvedTarget {
                                target_va: target,
                                symbolic_target: value.clone(),
                                constraints: pr.constraints.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Also check the emulator's register state for common jump target registers
        for reg_name in &["rax", "rbx", "rcx", "rdx", "eax", "ebx", "ecx", "edx"] {
            let val = pr.emulator.get_register(reg_name);
            if let Some(target) = val.as_const() {
                if workspace.is_valid_pointer(target) && !seen_targets.contains(&target) {
                    seen_targets.insert(target);
                    resolved.push(ResolvedTarget {
                        target_va: target,
                        symbolic_target: val.clone(),
                        constraints: pr.constraints.clone(),
                    });
                }
            }
        }
    }

    resolved
}

/// Find indirect jumps (potential switch statements) in a function.
///
/// Returns VAs of indirect jump instructions that aren't call instructions.
pub fn find_indirect_jumps(workspace: &VivWorkspace, func_va: u64) -> Vec<u64> {
    let arch = workspace.architecture();
    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Vec::new(),
    };

    let blocks = workspace.get_function_blocks(func_va);
    let mut indirect_jumps = Vec::new();

    for block in &blocks {
        let mut va = block.va;
        let block_end = block.va + block.size as u64;

        while va < block_end {
            let bytes = match workspace.read_memory(va, 16) {
                Ok(b) => b,
                Err(_) => break,
            };

            match disasm.disassemble(&bytes, va) {
                Ok(op) if op.size > 0 => {
                    // Indirect jump: branch + not call + not conditional + has deref operand
                    if op.is_branch() && !op.is_call() && !op.is_conditional() && !op.is_return() {
                        // Check if the target is not a constant (indirect)
                        if !op.opers.is_empty() {
                            let target = op.opers[0].get_value(&op);
                            // If target can't be resolved to a constant, it's indirect
                            if target.is_none() || !workspace.is_valid_pointer(target.unwrap_or(0))
                            {
                                indirect_jumps.push(va);
                            }
                        }
                    }
                    va += op.size as u64;
                }
                _ => break,
            }
        }
    }

    indirect_jumps
}

/// Bounded enumeration of switch case targets.
///
/// For a jump table pattern `jmp [table_base + index * scale]`, reads
/// consecutive entries from the table until hitting an invalid pointer
/// or exceeding max_cases.
///
/// This is a simpler alternative to full symbolic execution for resolving
/// switch cases when the table base address is known.
pub fn enumerate_jump_table(
    workspace: &VivWorkspace,
    table_base: u64,
    max_cases: usize,
) -> Vec<u64> {
    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size();
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    for i in 0..max_cases {
        let entry_va = table_base + (i * ptr_size) as u64;
        let bytes = match workspace.read_memory(entry_va, ptr_size) {
            Ok(b) => b,
            Err(_) => break,
        };

        let target = if is_little {
            match ptr_size {
                4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => break,
            }
        } else {
            match ptr_size {
                4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => break,
            }
        };

        // Validate target is within code sections
        let in_code = workspace.get_segments().iter().any(|seg| {
            let name = seg.name.to_lowercase();
            (name.contains("text") || name.contains("code"))
                && target >= seg.va
                && target < seg.va + seg.size as u64
        });

        if !in_code {
            break;
        }

        if seen.insert(target) {
            targets.push(target);
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enumerate_jump_table_empty() {
        // Without a workspace we can't test much, but we can verify the function signature
        // More thorough testing happens in integration tests
        let targets = enumerate_jump_table(&VivWorkspace::new(), 0x0, 10);
        assert!(targets.is_empty());
    }
}
