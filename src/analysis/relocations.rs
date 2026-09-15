//! Relocation target analysis module.
//!
//! Port of Python's `vivisect/analysis/generic/relocations.py` (19 LOC).
//!
//! Ensures all relocation targets point to valid locations by creating
//! pointer locations at unresolved relocation targets.

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run relocation target analysis.
///
/// Scans all LOC_POINTER locations that might be relocation targets
/// and ensures their targets are valid locations.
#[must_use]
pub fn analyze_relocations(workspace: &mut VivWorkspace) -> VivResult<RelocationStats> {
    let mut stats = RelocationStats::default();
    let ptr_size = workspace.architecture().pointer_size();
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    // Collect existing pointer locations
    let pointers: Vec<(u64, usize)> = workspace
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Pointer)
        .map(|(&va, loc)| (va, loc.size))
        .collect();

    for (ptr_va, ptr_sz) in pointers {
        let read_size = if ptr_sz > 0 { ptr_sz } else { ptr_size };
        let bytes = match workspace.read_memory(ptr_va, read_size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let target = if is_little {
            match read_size {
                4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => continue,
            }
        } else {
            match read_size {
                4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                8 => u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]),
                _ => continue,
            }
        };

        if !workspace.is_valid_pointer(target) {
            continue;
        }

        // If target doesn't have a location, create a pointer
        if workspace.get_location(target).is_none() {
            workspace.add_location(target, ptr_size, LocationType::Pointer, None);
            workspace.add_xref(ptr_va, target, crate::constants::RefType::Pointer);
            stats.targets_resolved += 1;
        }
    }

    tracing::debug!(
        "[relocations] resolved {} relocation targets",
        stats.targets_resolved
    );
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct RelocationStats {
    pub targets_resolved: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocations_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_relocations(&mut ws).unwrap();
        assert_eq!(result.targets_resolved, 0);
    }
}
