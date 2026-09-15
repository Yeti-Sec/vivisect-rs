//! ELF constructor/destructor analysis module.
//!
//! Parses `.ctors`, `.dtors`, `.init_array`, and `.fini_array` sections
//! to discover constructor and destructor functions.
//!
//! Port of Python's `vivisect/analysis/elf/__init__.py`.
//!
//! `.ctors`/`.dtors`: 0xFFFFFFFF-terminated pointer arrays (legacy GCC)
//! `.init_array`/`.fini_array`: fixed-size pointer arrays (modern ELF)

use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// Discover functions from ELF constructor/destructor sections.
///
/// Returns the list of function VAs found.
#[must_use]
pub fn discover_elf_ctors(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let ptr_size = workspace.pointer_size();
    if ptr_size != 4 && ptr_size != 8 {
        return Ok(Vec::new());
    }

    let terminator: u64 = if ptr_size == 4 {
        0xFFFFFFFF
    } else {
        0xFFFFFFFFFFFFFFFF
    };

    // Collect segment info to avoid borrow issues
    let segments: Vec<(u64, usize, String)> = workspace
        .get_segments()
        .iter()
        .filter(|s| {
            matches!(
                s.name.as_str(),
                ".ctors" | ".dtors" | ".init_array" | ".fini_array"
            )
        })
        .map(|s| (s.va, s.size, s.name.clone()))
        .collect();

    let mut discovered = Vec::new();

    for (seg_va, seg_size, seg_name) in &segments {
        let is_terminated = seg_name == ".ctors" || seg_name == ".dtors";
        let prefix = match seg_name.as_str() {
            ".ctors" | ".init_array" => "ctor",
            ".dtors" | ".fini_array" => "dtor",
            _ => "init",
        };

        let max_entries = seg_size / ptr_size;
        if max_entries == 0 {
            continue;
        }

        let data = match workspace.read_memory(*seg_va, *seg_size) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for i in 0..max_entries {
            let offset = i * ptr_size;
            if offset + ptr_size > data.len() {
                break;
            }

            let val = if ptr_size == 8 {
                u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as u64
            };

            // Check for terminator (0xFFFFFFFF / 0xFFFFFFFFFFFFFFFF)
            if is_terminated && val == terminator {
                break;
            }

            // Skip null entries
            if val == 0 {
                continue;
            }

            // Validate pointer
            if !workspace.is_valid_pointer(val) {
                continue;
            }

            if !workspace.is_function(val) {
                workspace.add_function(
                    val,
                    FunctionMeta {
                        name: Some(format!("{}_{:x}", prefix, val)),
                        ..Default::default()
                    },
                )?;
                discovered.push(val);
            }
        }
    }

    if !discovered.is_empty() {
        tracing::debug!(
            "[elfctors] discovered {} functions from ctor/dtor/init/fini sections",
            discovered.len()
        );
    }

    Ok(discovered)
}
