//! Late ELF PLT gap-filling analysis module.
//!
//! Port of Python's `vivisect/analysis/elf/elfplt_late.py` (395 LOC).
//!
//! After code flow analysis has discovered most PLT entries organically,
//! this module fills in the gaps using two heuristics:
//! 1. PLT-Function-Distance: measure gaps between known PLT functions,
//!    then fill gaps at the same interval
//! 2. First-entry: ensure the PLT section start is a function

use crate::constants::Architecture;
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Run late PLT analysis.
#[must_use]
pub fn analyze_elfplt_late(workspace: &mut VivWorkspace) -> VivResult<ElfPltLateStats> {
    let mut stats = ElfPltLateStats::default();

    // Find .plt sections
    let plt_sections: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| seg.name.to_lowercase().starts_with(".plt"))
        .map(|seg| (seg.va, seg.size))
        .collect();

    if plt_sections.is_empty() {
        return Ok(stats);
    }

    for (plt_va, plt_size) in &plt_sections {
        analyze_plt_section(workspace, *plt_va, *plt_size, &mut stats)?;
    }

    tracing::debug!(
        "[elfplt_late] filled {} PLT gaps",
        stats.functions_created
    );

    Ok(stats)
}

fn analyze_plt_section(
    workspace: &mut VivWorkspace,
    plt_va: u64,
    plt_size: usize,
    stats: &mut ElfPltLateStats,
) -> VivResult<()> {
    let plt_end = plt_va + plt_size as u64;

    // Ensure the PLT start is a function (covers lazy loader / PLT0)
    if !workspace.is_function(plt_va) {
        workspace.add_function(
            plt_va,
            FunctionMeta {
                name: Some(format!("plt_stub_{:x}", plt_va)),
                ..Default::default()
            },
        )?;
        stats.functions_created += 1;
    }

    // Find existing functions in this PLT section
    let mut plt_funcs: Vec<u64> = workspace
        .get_functions()
        .into_iter()
        .filter(|&fva| fva >= plt_va && fva < plt_end)
        .collect();
    plt_funcs.sort();

    if plt_funcs.len() < 2 {
        return Ok(());
    }

    // Compute distances between consecutive PLT functions
    let mut dist_counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for pair in plt_funcs.windows(2) {
        let delta = pair[1] - pair[0];
        if delta > 0 && delta <= 64 {
            *dist_counts.entry(delta).or_insert(0) += 1;
        }
    }

    if dist_counts.is_empty() {
        return Ok(());
    }

    // Find the most common distance (= PLT entry size)
    let (&func_dist, _) = dist_counts.iter().max_by_key(|(_, &count)| count).expect("dist_counts is non-empty (checked above)");
    if func_dist == 0 {
        return Ok(());
    }

    // Validate: get the first instruction mnemonic of a known PLT function
    let arch = workspace.architecture();
    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(()),
    };

    // Find a reference PLT entry (second one, since first may be PLT0)
    let ref_fva = if plt_funcs.len() > 1 { plt_funcs[1] } else { plt_funcs[0] };
    let ref_mnem = match workspace.read_memory(ref_fva, 16) {
        Ok(bytes) => match disasm.disassemble(&bytes, ref_fva) {
            Ok(op) if op.size > 0 => Some(op.mnem.clone()),
            _ => None,
        },
        Err(_) => None,
    };

    // Fill backwards from the first known function
    if let Some(ref_mnem) = &ref_mnem {
        let mut va = plt_funcs[0].saturating_sub(func_dist);
        while va >= plt_va {
            if workspace.is_function(va) || is_in_plt_function(workspace, va, &plt_funcs) {
                va = va.saturating_sub(func_dist);
                if va < plt_va { break; }
                continue;
            }

            // Validate mnemonic matches
            if let Ok(bytes) = workspace.read_memory(va, 16) {
                if let Ok(op) = disasm.disassemble(&bytes, va) {
                    if op.size > 0 && op.mnem == *ref_mnem {
                        workspace.add_function(
                            va,
                            FunctionMeta {
                                name: Some(format!("plt_entry_{:x}", va)),
                                ..Default::default()
                            },
                        )?;
                        stats.functions_created += 1;
                    }
                }
            }

            if va < func_dist { break; }
            va -= func_dist;
        }

        // Fill forwards from the last known function
        let last_known = *plt_funcs.last().expect("plt_funcs is non-empty at this point in the analysis");
        let mut va = last_known + func_dist;
        while va < plt_end {
            if workspace.is_function(va) || is_in_plt_function(workspace, va, &plt_funcs) {
                va += func_dist;
                continue;
            }

            if let Ok(bytes) = workspace.read_memory(va, 16) {
                if let Ok(op) = disasm.disassemble(&bytes, va) {
                    if op.size > 0 && op.mnem == *ref_mnem {
                        workspace.add_function(
                            va,
                            FunctionMeta {
                                name: Some(format!("plt_entry_{:x}", va)),
                                ..Default::default()
                            },
                        )?;
                        stats.functions_created += 1;
                    }
                }
            }

            va += func_dist;
        }
    }

    Ok(())
}

/// Check if a VA belongs to an existing PLT function.
fn is_in_plt_function(workspace: &VivWorkspace, va: u64, plt_funcs: &[u64]) -> bool {
    for &fva in plt_funcs {
        if va >= fva {
            // Check if va is within the function's blocks
            let blocks = workspace.get_function_blocks(fva);
            for block in &blocks {
                if va >= block.va && va < block.va + block.size as u64 {
                    return true;
                }
            }
        }
    }
    false
}

#[derive(Debug, Default)]
pub struct ElfPltLateStats {
    pub functions_created: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elfplt_late_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_elfplt_late(&mut ws).unwrap();
        assert_eq!(result.functions_created, 0);
    }
}
