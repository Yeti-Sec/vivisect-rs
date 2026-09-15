//! Symbolic switch case analysis module.
//!
//! Port of Python's `vivisect/analysis/generic/symswitchcase.py`.
//!
//! Two-phase approach:
//! 1. **Discovery** — identify switch index range via symbolic path analysis
//! 2. **Wiring** — read jump table entries, create code flow and xrefs
//!
//! Phase 1 uses symbolic emulation to walk paths to the indirect jump,
//! collecting constraints on the index variable. A bounds-based solver then
//! enumerates all satisfying values to determine how many cases the switch handles.
//!
//! Phase 2 reads the jump table for each valid index and creates functions,
//! xrefs, and names for the case handlers.

use crate::constants::{Architecture, RefType};
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;
use crate::symboliks::solver::SymbolicSolver;
use crate::symboliks::workspace::{enumerate_jump_table, find_indirect_jumps};

/// Maximum number of switch cases to resolve per jump.
const MAX_SWITCH_CASES: usize = 256;

/// Resolve a jump table base address from an indirect jump instruction.
///
/// Patterns recognized:
/// - x86: `jmp dword ptr [disp + reg*scale]` → disp is table base
/// - x64: lea-based patterns with RIP-relative addressing
fn resolve_table_base(workspace: &VivWorkspace, jump_va: u64, arch: Architecture) -> Option<u64> {
    let bytes = workspace.read_memory(jump_va, 16).ok()?;

    match arch {
        Architecture::I386 => {
            // jmp [disp32 + reg*scale]: FF 24 XX XX XX XX XX
            if bytes.len() >= 7 && bytes[0] == 0xFF && bytes[1] == 0x24 {
                let sib = bytes[2];
                let base = sib & 0x07;

                // mod=00, base=5: [disp32 + index*scale]
                if base == 0x05 {
                    let disp = u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                    if workspace.is_valid_pointer(disp as u64) {
                        return Some(disp as u64);
                    }
                }
            }
            None
        }
        Architecture::Amd64 => {
            // Scan backwards for lea with table address
            let scan_start = jump_va.saturating_sub(32);
            let scan_bytes = workspace.read_memory(scan_start, 48).ok()?;

            let disasm = X86Disassembler::new(X86Mode::Mode64);
            let mut va = scan_start;
            let mut last_lea_target = None;

            while va < jump_va {
                let offset = (va - scan_start) as usize;
                if offset >= scan_bytes.len() {
                    break;
                }
                match disasm.disassemble(&scan_bytes[offset..], va) {
                    Ok(op) if op.size > 0 => {
                        if op.mnem == "lea" && op.opers.len() >= 2 {
                            if let Some(target) = op.opers[1].get_value(&op) {
                                if workspace.is_valid_pointer(target) {
                                    last_lea_target = Some(target);
                                }
                            }
                        }
                        va += op.size as u64;
                    }
                    _ => {
                        va += 1;
                    }
                }
            }

            last_lea_target
        }
        _ => None,
    }
}

/// Use symbolic path analysis to determine the valid index range for a switch.
///
/// Walks symbolic paths through the function to the indirect jump, collects
/// constraints on the index variable, then uses bounds-based solving to enumerate valid values.
fn resolve_switch_range_symbolic(
    workspace: &VivWorkspace,
    func_va: u64,
    jump_va: u64,
) -> Option<Vec<u64>> {
    use crate::symboliks::analysis::SymbolikAnalysisContext;
    use crate::symboliks::workspace::build_function_graph;

    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size() as u8;

    let graph = build_function_graph(workspace, func_va)?;

    // Find the block containing the indirect jump
    let jump_block_va = graph
        .blocks
        .values()
        .find(|b| b.opcodes.iter().any(|op| op.va == jump_va))
        .map(|b| b.va)?;

    // Walk symbolic paths, collecting constraints from paths that reach the jump block
    let mut ctx = SymbolikAnalysisContext::new(ptr_size);
    ctx.set_max_paths(500);
    ctx.set_max_loop_count(1);

    let path_results = ctx.walk_symbolik_paths(&graph);

    // Collect constraints from paths that visit the jump block
    let mut all_constraints = Vec::new();
    for pr in &path_results {
        if pr.path.contains(&jump_block_va) {
            all_constraints.push(pr.constraints.clone());
        }
    }

    if all_constraints.is_empty() {
        return None;
    }

    // Use bounds solver to find the range of valid index values
    let solver = SymbolicSolver::new();

    // The index variable is typically in a register like eax, ecx, edx
    // Try each common index register and see which one has a bounded range
    let index_candidates = if ptr_size == 4 {
        vec!["eax", "ecx", "edx", "ebx"]
    } else {
        vec!["rax", "rcx", "rdx", "rbx", "rdi", "rsi"]
    };

    for idx_var in &index_candidates {
        for constraints in &all_constraints {
            if constraints.is_empty() {
                continue;
            }

            // Check if this variable has a bounded range under these constraints
            let range = solver.find_range(idx_var, ptr_size, constraints);
            if let Some((min, max)) = range {
                // Sanity check: range shouldn't be too large
                if max >= min && (max - min) < MAX_SWITCH_CASES as u64 {
                    let values =
                        solver.enumerate_values(idx_var, ptr_size, constraints, MAX_SWITCH_CASES);
                    if !values.is_empty() {
                        tracing::debug!(
                            "[symswitchcase] solver found {} values for {} at switch 0x{:x} (range {}-{})",
                            values.len(), idx_var, jump_va, min, max
                        );
                        return Some(values);
                    }
                }
            }
        }
    }

    None
}

/// Run symbolic switch case analysis on a workspace.
///
/// For each function with indirect jumps:
/// 1. Try symbolic path resolution (most accurate)
/// 2. Fall back to jump table enumeration (simpler)
/// 3. Create xrefs and code flow for resolved cases
#[must_use]
pub fn analyze_symswitchcase(workspace: &mut VivWorkspace) -> VivResult<SwitchCaseStats> {
    let arch = workspace.architecture();
    let mut stats = SwitchCaseStats::default();

    let funcs: Vec<u64> = workspace.get_functions();

    for func_va in funcs {
        let indirect_jumps = find_indirect_jumps(workspace, func_va);
        if indirect_jumps.is_empty() {
            continue;
        }

        for jump_va in &indirect_jumps {
            // Phase 1: Try symbolic path resolution
            let symbolic_targets = resolve_switch_range_symbolic(workspace, func_va, *jump_va);

            // Phase 2: Try jump table enumeration
            let table_base = resolve_table_base(workspace, *jump_va, arch);

            let targets = if let Some(sym_targets) = symbolic_targets {
                // Use symbolic results — these are index values, need to read table
                if let Some(base) = table_base {
                    let ptr_size = arch.pointer_size();
                    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

                    sym_targets
                        .iter()
                        .filter_map(|&idx| {
                            let entry_va = base + idx * ptr_size as u64;
                            let bytes = workspace.read_memory(entry_va, ptr_size).ok()?;
                            let target =
                                if is_little {
                                    match ptr_size {
                                        4 => u32::from_le_bytes([
                                            bytes[0], bytes[1], bytes[2], bytes[3],
                                        ]) as u64,
                                        8 => u64::from_le_bytes([
                                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                                            bytes[5], bytes[6], bytes[7],
                                        ]),
                                        _ => return None,
                                    }
                                } else {
                                    match ptr_size {
                                        4 => u32::from_be_bytes([
                                            bytes[0], bytes[1], bytes[2], bytes[3],
                                        ]) as u64,
                                        8 => u64::from_be_bytes([
                                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                                            bytes[5], bytes[6], bytes[7],
                                        ]),
                                        _ => return None,
                                    }
                                };

                            // Validate target is in code
                            let in_code = workspace.get_segments().iter().any(|seg| {
                                let name = seg.name.to_lowercase();
                                (name.contains("text") || name.contains("code"))
                                    && target >= seg.va
                                    && target < seg.va + seg.size as u64
                            });

                            if in_code {
                                Some(target)
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            } else if let Some(base) = table_base {
                // Fall back to bounded table enumeration
                enumerate_jump_table(workspace, base, MAX_SWITCH_CASES)
            } else {
                continue;
            };

            if targets.is_empty() {
                continue;
            }

            stats.switches_found += 1;
            stats.total_cases += targets.len();

            tracing::debug!(
                "[symswitchcase] switch at 0x{:x} in func 0x{:x}: {} cases",
                jump_va,
                func_va,
                targets.len()
            );

            // Wire up the switch cases.
            // Case targets are code blocks WITHIN the parent function, not new
            // functions. Python uses `vw.makeCode(addr)` which creates code within
            // the existing function. Using `add_function()` here would fragment the
            // parent function into multiple smaller functions — incorrect behavior.
            for (i, &target) in targets.iter().enumerate() {
                workspace.add_xref(*jump_va, target, RefType::Code);

                // If the target isn't already defined as a function or code location,
                // add it as a codeblock within the parent function and set a name.
                if !workspace.is_function(target) && workspace.get_location(target).is_none() {
                    // Add as a codeblock belonging to the parent function.
                    // Size 0 is a placeholder — the code flow analyzer will determine
                    // actual block boundaries when it re-analyzes the function.
                    workspace.add_codeblock(target, 0, func_va);
                    workspace.set_name(target, &format!("case_{:x}_{}", func_va, i));
                    stats.cases_wired += 1;
                }
            }
        }
    }

    tracing::debug!(
        "[symswitchcase] found {} switches with {} total cases, {} cases wired",
        stats.switches_found,
        stats.total_cases,
        stats.cases_wired
    );

    Ok(stats)
}

#[derive(Debug, Default)]
pub struct SwitchCaseStats {
    pub switches_found: usize,
    pub total_cases: usize,
    pub cases_wired: usize,
}
