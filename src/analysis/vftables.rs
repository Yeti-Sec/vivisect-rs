//! Virtual function table detection module.
//!
//! Port of Python's `vivisect/analysis/ms/vftables.py` (44 LOC).
//!
//! Finds sequences of 4+ consecutive function pointers in memory,
//! which are likely vtable arrays from C++ classes.

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run vtable detection analysis.
///
/// Scans pointer locations for consecutive function pointer sequences.
/// Logs detected vtables (marking as LOC_VFTABLE is deferred to
/// avoid disrupting code flow analysis).
#[must_use]
pub fn analyze_vftables(workspace: &mut VivWorkspace) -> VivResult<VfTableStats> {
    let mut stats = VfTableStats::default();
    let ptr_size = workspace.architecture().pointer_size();
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    // Collect all pointer locations sorted by address
    let mut pointers: Vec<u64> = workspace
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Pointer)
        .map(|(&va, _)| va)
        .collect();
    pointers.sort();

    let mut i = 0;
    while i < pointers.len() {
        let start_va = pointers[i];

        // Check if this pointer targets a function
        let target = match read_pointer(workspace, start_va, ptr_size, is_little) {
            Some(t) => t,
            None => {
                i += 1;
                continue;
            }
        };

        if !workspace.is_function(target) {
            i += 1;
            continue;
        }

        // Count consecutive function pointers
        let mut count = 1usize;
        let mut va = start_va + ptr_size as u64;

        loop {
            if workspace.get_location(va).is_some() {
                // Check if it's a pointer location
                let is_ptr = workspace
                    .get_location(va)
                    .is_some_and(|l| l.ltype == LocationType::Pointer);
                if !is_ptr {
                    break;
                }
            }

            let ptr_val = match read_pointer(workspace, va, ptr_size, is_little) {
                Some(t) => t,
                None => break,
            };

            if !workspace.is_function(ptr_val) {
                break;
            }

            count += 1;
            va += ptr_size as u64;
        }

        if count >= 4 {
            stats.vftables_found += 1;
            stats.total_entries += count;

            // Mark the vtable start
            workspace.add_location(
                start_va,
                count * ptr_size,
                LocationType::VfTable,
                Some(format!("vtable_{:x}", start_va)),
            );
            workspace.set_name(start_va, &format!("vtable_{:x}", start_va));

            tracing::debug!("[vftables] vtable at 0x{:x}: {} entries", start_va, count);
        }

        i += count.max(1);
    }

    tracing::debug!(
        "[vftables] found {} vtables with {} total entries",
        stats.vftables_found,
        stats.total_entries
    );

    Ok(stats)
}

fn read_pointer(
    workspace: &VivWorkspace,
    va: u64,
    size: usize,
    little_endian: bool,
) -> Option<u64> {
    let bytes = workspace.read_memory(va, size).ok()?;
    if bytes.len() < size {
        return None;
    }
    Some(if little_endian {
        match size {
            4 => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            8 => u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => return None,
        }
    } else {
        match size {
            4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            8 => u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            _ => return None,
        }
    })
}

#[derive(Debug, Default)]
pub struct VfTableStats {
    pub vftables_found: usize,
    pub total_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vftables_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_vftables(&mut ws).unwrap();
        assert_eq!(result.vftables_found, 0);
        assert_eq!(result.total_entries, 0);
    }
}
