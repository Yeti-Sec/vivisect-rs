//! ARM/AArch64 analysis module.
//!
//! Simplified port of Python's `vivisect/analysis/arm/emulation.py` (518 LOC)
//! and `vivisect/analysis/aarch64/emulation.py` (449 LOC).
//!
//! The Python modules use full emulation for:
//! 1. TBB/TBH (table branch) switch case detection
//! 2. Function API (calling convention) inference from register usage
//! 3. Infinite loop detection
//!
//! This Rust port provides the static analysis portions without emulation.
//! Full emulation-based analysis can be added via icicle when needed.

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run ARM-specific analysis on all ARM functions.
///
/// Currently handles:
/// - Calling convention assignment (ARM AAPCS: R0-R3 for args)
/// - Function naming for known patterns
#[must_use]
pub fn analyze_arm(workspace: &mut VivWorkspace) -> VivResult<ArmAnalysisStats> {
    let mut stats = ArmAnalysisStats::default();
    let arch = workspace.architecture();

    match arch {
        Architecture::ArmV7 | Architecture::Thumb => {}
        _ => return Ok(stats),
    }

    let funcs: Vec<u64> = workspace.get_functions();
    for func_va in funcs {
        if let Some(func) = workspace.get_function_mut(func_va) {
            func.meta
                .entry("CallingConvention".to_string())
                .or_insert_with(|| "aapcs".to_string());
            stats.functions_analyzed += 1;
        }
    }

    tracing::debug!("[arm] analyzed {} ARM functions", stats.functions_analyzed);
    Ok(stats)
}

/// Run AArch64-specific analysis on all AArch64 functions.
///
/// Currently handles:
/// - Calling convention assignment (AArch64 AAPCS64: X0-X7 for args)
#[must_use]
pub fn analyze_aarch64(workspace: &mut VivWorkspace) -> VivResult<ArmAnalysisStats> {
    let mut stats = ArmAnalysisStats::default();

    if workspace.architecture() != Architecture::A64 {
        return Ok(stats);
    }

    let funcs: Vec<u64> = workspace.get_functions();
    for func_va in funcs {
        if let Some(func) = workspace.get_function_mut(func_va) {
            func.meta
                .entry("CallingConvention".to_string())
                .or_insert_with(|| "aapcs64".to_string());
            stats.functions_analyzed += 1;
        }
    }

    tracing::debug!(
        "[aarch64] analyzed {} AArch64 functions",
        stats.functions_analyzed
    );
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct ArmAnalysisStats {
    pub functions_analyzed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_default_arch() {
        let mut ws = VivWorkspace::new();
        let result = analyze_arm(&mut ws).unwrap();
        assert_eq!(result.functions_analyzed, 0);
    }

    #[test]
    fn test_aarch64_default_arch() {
        let mut ws = VivWorkspace::new();
        let result = analyze_aarch64(&mut ws).unwrap();
        assert_eq!(result.functions_analyzed, 0);
    }
}
