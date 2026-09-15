//! Import-Export linker module.
//!
//! Port of Python's `vivisect/analysis/generic/linker.py`.
//!
//! Connects imported symbols in one file to exported symbols in another file
//! within the same workspace. Most useful for multi-file workspaces where
//! multiple DLLs/SOs are loaded together.
//!
//! Algorithm:
//! 1. For each LOC_IMPORT, extract the symbol name
//! 2. Check if any export matches the symbol name
//! 3. If match found: write export VA at import address, convert to LOC_POINTER
//! 4. Create code xrefs from callers to the resolved export

use crate::constants::{LocationType, RefType};
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run the import-export linker analysis.
///
/// Scans all LOC_IMPORT locations and tries to resolve them against exports
/// in the workspace. For single-file workspaces this is typically a no-op.
#[must_use]
pub fn analyze_linker(workspace: &mut VivWorkspace) -> VivResult<LinkerStats> {
    let mut stats = LinkerStats::default();

    // Collect all import locations
    let imports: Vec<(u64, usize, Option<String>)> = workspace
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Import)
        .map(|(&va, loc)| (va, loc.size, loc.tinfo.clone()))
        .collect();

    if imports.is_empty() {
        return Ok(stats);
    }

    // Collect all symbol names and addresses for export lookup
    let symbols: Vec<(u64, String)> = workspace
        .symbols()
        .iter()
        .map(|(va, name)| (va, name.to_string()))
        .collect();

    let ptr_size = match workspace.architecture() {
        crate::constants::Architecture::Amd64 => 8usize,
        _ => 4usize,
    };

    for (iva, _isz, isym_opt) in &imports {
        let isym = match isym_opt {
            Some(s) => s.clone(),
            None => {
                // Try to get from workspace name
                match workspace.get_name(*iva) {
                    Some(n) => n.to_string(),
                    None => continue,
                }
            }
        };

        // Extract the function name from "file.symbol" format
        let import_func = match isym.rsplit_once('.') {
            Some((_file, func)) => func,
            None => &isym,
        };

        // Look for matching export
        for (eva, esym) in &symbols {
            if *eva == *iva {
                continue; // Don't resolve to self
            }

            let export_func = match esym.rsplit_once('.') {
                Some((_file, func)) => func,
                None => esym.as_str(),
            };

            if import_func != export_func {
                continue;
            }

            // Skip if the export is itself a thunk
            if workspace.is_function_thunk(*eva) {
                continue;
            }

            // Convert from LOC_IMPORT to LOC_POINTER
            workspace.add_location(*iva, ptr_size, LocationType::Pointer, None);
            workspace.add_xref(*iva, *eva, RefType::Pointer);

            // Create code xrefs from callers to the resolved export
            let xrefs_to: Vec<u64> = workspace
                .get_xrefs_to(*iva)
                .iter()
                .map(|&(from_va, _ref_type)| from_va)
                .collect();

            for xfr in xrefs_to {
                if let Some(loc) = workspace.get_location(xfr) {
                    if loc.ltype == LocationType::Op {
                        workspace.add_xref(xfr, *eva, RefType::Code);
                    }
                }
            }

            stats.resolved += 1;
            tracing::debug!(
                "[linker] resolved import 0x{:x} -> export 0x{:x} ({:?})",
                iva,
                eva,
                import_func
            );

            break; // Only resolve first match
        }
    }

    tracing::debug!("[linker] resolved {} imports", stats.resolved);
    Ok(stats)
}

/// Statistics from linker analysis.
#[derive(Debug, Default)]
pub struct LinkerStats {
    pub resolved: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linker_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_linker(&mut ws).unwrap();
        assert_eq!(result.resolved, 0);
    }
}
