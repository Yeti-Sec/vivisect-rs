//! Microsoft hotpatch pad detection module.
//!
//! Port of Python's `vivisect/analysis/ms/hotpatch.py` (25 LOC).
//!
//! Per-function analysis: detects NOP (0x90) or INT3 (0xCC) padding
//! bytes before function entry points, marking them as pad locations.

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run hotpatch pad detection for a single function.
///
/// Checks bytes immediately before the function for NOP/INT3 padding.
/// If 5+ consecutive identical pad bytes are found, creates a pad location.
pub fn analyze_hotpatch_function(workspace: &mut VivWorkspace, func_va: u64) -> bool {
    if func_va == 0 {
        return false;
    }

    // Read byte before function
    let pre_va = func_va - 1;
    let bytes = match workspace.read_memory(pre_va, 1) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let pad_byte = bytes[0];
    if pad_byte != 0x90 && pad_byte != 0xCC {
        return false;
    }

    // Count consecutive identical pad bytes backwards
    let mut count = 1usize;
    let max_scan = 16usize;
    for i in 2..=max_scan {
        let scan_va = func_va.saturating_sub(i as u64);
        if scan_va == 0 {
            break;
        }
        match workspace.read_memory(scan_va, 1) {
            Ok(b) if b[0] == pad_byte => count += 1,
            _ => break,
        }
    }

    if count >= 5 {
        let pad_va = func_va - count as u64;
        if workspace.get_location(pad_va).is_none() {
            workspace.add_location(pad_va, count, LocationType::Pad, None);
            return true;
        }
    }

    false
}

/// Run hotpatch analysis on all functions.
#[must_use]
pub fn analyze_hotpatch(workspace: &mut VivWorkspace) -> VivResult<HotpatchStats> {
    let mut stats = HotpatchStats::default();

    let funcs: Vec<u64> = workspace.get_functions();
    for func_va in funcs {
        if analyze_hotpatch_function(workspace, func_va) {
            stats.pads_found += 1;
        }
    }

    tracing::debug!("[hotpatch] found {} hotpatch pads", stats.pads_found);
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct HotpatchStats {
    pub pads_found: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotpatch_no_function() {
        let mut ws = VivWorkspace::new();
        assert!(!analyze_hotpatch_function(&mut ws, 0));
    }

    #[test]
    fn test_hotpatch_zero_va() {
        let mut ws = VivWorkspace::new();
        assert!(!analyze_hotpatch_function(&mut ws, 0));
    }

    #[test]
    fn test_analyze_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_hotpatch(&mut ws).unwrap();
        assert_eq!(result.pads_found, 0);
    }
}
