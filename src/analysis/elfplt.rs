//! ELF PLT (Procedure Linkage Table) analysis module.
//!
//! Simplified port of Python's `vivisect/analysis/elf/elfplt.py`.
//!
//! Identifies PLT stubs in ELF binaries and names them based on their
//! GOT targets. PLT entries are small trampolines that jump through the
//! GOT to reach dynamically linked functions.
//!
//! Algorithm:
//! 1. Find .plt and .plt.got sections
//! 2. Find .got.plt or .got sections
//! 3. For each PLT entry: follow the indirect jump to the GOT
//! 4. Look up the import name from the GOT entry
//! 5. Create functions and name them `plt_<import_name>`

use crate::constants::{Architecture, LocationType};
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Find PLT sections in the workspace.
fn find_plt_sections(workspace: &VivWorkspace) -> Vec<(u64, usize)> {
    workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            let name = seg.name.to_lowercase();
            name.starts_with(".plt")
        })
        .map(|seg| (seg.va, seg.size))
        .collect()
}

/// Find GOT sections in the workspace.
fn find_got_sections(workspace: &VivWorkspace) -> Vec<(u64, usize)> {
    workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            let name = seg.name.to_lowercase();
            name.starts_with(".got")
        })
        .map(|seg| (seg.va, seg.size))
        .collect()
}

/// Check if a VA is within any GOT section.
fn is_in_got(va: u64, got_sections: &[(u64, usize)]) -> bool {
    got_sections
        .iter()
        .any(|(base, size)| va >= *base && va < *base + *size as u64)
}

/// Analyze PLT sections for x86/x86-64 ELF binaries.
///
/// Scans PLT sections for indirect jump patterns that target the GOT,
/// then resolves the import names from GOT entries.
#[must_use]
pub fn analyze_elfplt(workspace: &mut VivWorkspace) -> VivResult<ElfPltStats> {
    let mut stats = ElfPltStats::default();
    let arch = workspace.architecture();

    let plt_sections = find_plt_sections(workspace);
    let got_sections = find_got_sections(workspace);

    if plt_sections.is_empty() || got_sections.is_empty() {
        return Ok(stats);
    }

    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(stats),
    };

    let ptr_size = arch.pointer_size();
    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);

    // Build a map of GOT entry VA → import name
    let mut got_names: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
    for (got_va, got_size) in &got_sections {
        let mut offset = 0u64;
        while offset < *got_size as u64 {
            let entry_va = got_va + offset;
            // Check if this GOT entry has a name (from import resolution)
            if let Some(name) = workspace.get_name(entry_va) {
                got_names.insert(entry_va, name.to_string());
            }
            // Check if it's a LOC_IMPORT
            if let Some(loc) = workspace.get_location(entry_va) {
                if loc.ltype == LocationType::Import {
                    if let Some(ref tinfo) = loc.tinfo {
                        got_names.insert(entry_va, tinfo.clone());
                    }
                }
            }
            offset += ptr_size as u64;
        }
    }

    // For each PLT section, try to identify PLT entry boundaries and resolve names
    for (plt_va, plt_size) in &plt_sections {
        let plt_end = plt_va + *plt_size as u64;

        // Heuristic: determine PLT entry size by looking at the first few entries
        // Common sizes: 16 bytes (x86/x64), 8 bytes (.plt.got on some systems)
        let entry_size = detect_plt_entry_size(workspace, &disasm, *plt_va, *plt_size, arch);
        if entry_size == 0 {
            continue;
        }

        // Skip the first entry (PLT0 — lazy resolver stub)
        let mut entry_va = plt_va + entry_size as u64;

        while entry_va + entry_size as u64 <= plt_end {
            // Try to resolve this PLT entry
            if let Some((got_target, import_name)) =
                resolve_plt_entry(workspace, &disasm, entry_va, arch, &got_names, &got_sections, is_little, ptr_size)
            {
                // Create function at PLT entry if not already one
                if !workspace.is_function(entry_va) {
                    let plt_name = format!("plt_{}", clean_import_name(&import_name));
                    workspace.add_function(
                        entry_va,
                        FunctionMeta {
                            name: Some(plt_name.clone()),
                            meta: {
                                let mut m = std::collections::HashMap::new();
                                m.insert("Thunk".to_string(), import_name.clone());
                                m
                            },
                            ..Default::default()
                        },
                    )?;
                    stats.plt_entries += 1;
                    tracing::debug!(
                        "[elfplt] PLT entry at 0x{:x} → GOT 0x{:x} → {}",
                        entry_va, got_target, import_name
                    );
                }
            }

            entry_va += entry_size as u64;
        }
    }

    tracing::debug!("[elfplt] resolved {} PLT entries", stats.plt_entries);
    Ok(stats)
}

/// Detect PLT entry size by analyzing the first few entries.
fn detect_plt_entry_size(
    workspace: &VivWorkspace,
    disasm: &X86Disassembler,
    plt_va: u64,
    plt_size: usize,
    arch: Architecture,
) -> usize {
    // Read the PLT section
    let bytes = match workspace.read_memory(plt_va, plt_size.min(256)) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    // Find the first two unconditional indirect jumps (jmp [GOT])
    // The distance between them is the PLT entry size
    let mut jump_vas = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() && jump_vas.len() < 4 {
        let remaining = &bytes[offset..];
        match disasm.disassemble(remaining, plt_va + offset as u64) {
            Ok(op) if op.size > 0 => {
                // Look for indirect jumps (jmp [mem])
                if op.is_branch() && !op.is_call() && !op.is_conditional() {
                    jump_vas.push(plt_va + offset as u64);
                }
                offset += op.size as usize;
            }
            _ => {
                offset += 1;
            }
        }
    }

    if jump_vas.len() >= 3 {
        // Distance between 2nd and 3rd jumps (skip PLT0 → first real entry)
        let dist = jump_vas[2] - jump_vas[1];
        if dist >= 8 && dist <= 32 {
            return dist as usize;
        }
    }

    if jump_vas.len() >= 2 {
        let dist = jump_vas[1] - jump_vas[0];
        if dist >= 8 && dist <= 32 {
            return dist as usize;
        }
    }

    // Default PLT entry sizes
    match arch {
        Architecture::Amd64 => 16,
        Architecture::I386 => 16,
        _ => 0,
    }
}

/// Resolve a single PLT entry: find where it jumps to via the GOT.
fn resolve_plt_entry(
    workspace: &VivWorkspace,
    disasm: &X86Disassembler,
    entry_va: u64,
    arch: Architecture,
    got_names: &std::collections::HashMap<u64, String>,
    got_sections: &[(u64, usize)],
    is_little: bool,
    ptr_size: usize,
) -> Option<(u64, String)> {
    // Read a few instructions from the PLT entry
    let bytes = workspace.read_memory(entry_va, 16).ok()?;

    // Disassemble first instruction — should be an indirect jump
    let op = disasm.disassemble(&bytes, entry_va).ok()?;

    if !op.is_branch() || op.is_call() || op.is_conditional() {
        return None;
    }

    // Extract the GOT target address from the jump operand
    let got_va = match arch {
        Architecture::Amd64 => {
            // jmp [rip+disp32]: FF 25 XX XX XX XX
            if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
                let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
                let rip_after = entry_va + 6; // RIP points to next instruction
                (rip_after as i64 + disp as i64) as u64
            } else {
                return None;
            }
        }
        Architecture::I386 => {
            // jmp [addr]: FF 25 XX XX XX XX
            if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25 {
                u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as u64
            } else {
                return None;
            }
        }
        _ => return None,
    };

    // Verify the target is in a GOT section
    if !is_in_got(got_va, got_sections) {
        return None;
    }

    // Look up the import name from the GOT entry
    if let Some(name) = got_names.get(&got_va) {
        return Some((got_va, name.clone()));
    }

    // Try reading the GOT entry and looking up the target's name
    if let Ok(got_bytes) = workspace.read_memory(got_va, ptr_size) {
        let target = if is_little {
            match ptr_size {
                4 => u32::from_le_bytes([got_bytes[0], got_bytes[1], got_bytes[2], got_bytes[3]]) as u64,
                8 => u64::from_le_bytes([
                    got_bytes[0], got_bytes[1], got_bytes[2], got_bytes[3],
                    got_bytes[4], got_bytes[5], got_bytes[6], got_bytes[7],
                ]),
                _ => return None,
            }
        } else {
            match ptr_size {
                4 => u32::from_be_bytes([got_bytes[0], got_bytes[1], got_bytes[2], got_bytes[3]]) as u64,
                8 => u64::from_be_bytes([
                    got_bytes[0], got_bytes[1], got_bytes[2], got_bytes[3],
                    got_bytes[4], got_bytes[5], got_bytes[6], got_bytes[7],
                ]),
                _ => return None,
            }
        };

        if let Some(name) = workspace.get_name(target) {
            return Some((got_va, name.to_string()));
        }
    }

    None
}

/// Clean an import name for use in PLT function naming.
fn clean_import_name(name: &str) -> String {
    // Strip "*.prefix" if present
    let name = name.strip_prefix("*.").unwrap_or(name);
    // Strip filename prefix (e.g., "libc.printf" → "printf")
    let name = match name.rsplit_once('.') {
        Some((_file, func)) => func,
        None => name,
    };
    // Strip address suffix if present (e.g., "func_00401000" stays as-is)
    name.to_string()
}

#[derive(Debug, Default)]
pub struct ElfPltStats {
    pub plt_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elfplt_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_elfplt(&mut ws).unwrap();
        assert_eq!(result.plt_entries, 0);
    }

    #[test]
    fn test_clean_import_name() {
        assert_eq!(clean_import_name("libc.printf"), "printf");
        assert_eq!(clean_import_name("*.printf"), "printf");
        assert_eq!(clean_import_name("printf"), "printf");
        assert_eq!(clean_import_name("*.libc.printf"), "printf");
    }
}
