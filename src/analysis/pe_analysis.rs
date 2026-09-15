//! PE-specific analysis module.
//!
//! Port of Python's `vivisect/analysis/pe.py` (47 LOC).
//!
//! Processes PE relocation sections (.reloc) by creating number locations
//! for each relocation entry.

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Run PE-specific analysis.
///
/// Parses PE relocation chunks in .reloc sections and marks each
/// relocation entry as a 2-byte number location.
#[must_use]
pub fn analyze_pe(workspace: &mut VivWorkspace) -> VivResult<PeAnalysisStats> {
    let mut stats = PeAnalysisStats::default();

    // Find reloc sections
    let reloc_segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| seg.name.to_lowercase().contains("reloc"))
        .map(|seg| (seg.va, seg.size))
        .collect();

    if reloc_segments.is_empty() {
        return Ok(stats);
    }

    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    for (seg_va, seg_size) in &reloc_segments {
        let data = match workspace.read_memory(*seg_va, *seg_size) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Parse relocation chunks: each chunk has a 4-byte page RVA + 4-byte size,
        // followed by 2-byte relocation entries
        let mut offset = 0usize;
        while offset + 8 <= data.len() {
            let _page_rva = if is_little {
                u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ])
            } else {
                u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ])
            };

            let chunk_size = if is_little {
                u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ])
            } else {
                u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ])
            } as usize;

            if chunk_size < 8 || chunk_size > data.len() - offset {
                break;
            }

            // Name the chunk
            let chunk_va = *seg_va + offset as u64;
            workspace.set_name(chunk_va, &format!("reloc_chunk_{:x}", chunk_va));

            // Mark each 2-byte entry
            let entries_start = offset + 8;
            let entries_end = offset + chunk_size;
            let mut entry_offset = entries_start;
            while entry_offset + 2 <= entries_end {
                let entry_va = *seg_va + entry_offset as u64;
                if workspace.get_location(entry_va).is_none() {
                    workspace.add_location(entry_va, 2, LocationType::Number, None);
                    stats.reloc_entries += 1;
                }
                entry_offset += 2;
            }

            offset += chunk_size;
            stats.reloc_chunks += 1;
        }
    }

    tracing::debug!(
        "[pe] processed {} reloc chunks, {} entries",
        stats.reloc_chunks,
        stats.reloc_entries
    );

    Ok(stats)
}

#[derive(Debug, Default)]
pub struct PeAnalysisStats {
    pub reloc_chunks: usize,
    pub reloc_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_analysis_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_pe(&mut ws).unwrap();
        assert_eq!(result.reloc_chunks, 0);
        assert_eq!(result.reloc_entries, 0);
    }
}
