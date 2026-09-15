//! x86 PIC register thunk detection module.
//!
//! Port of Python's `vivisect/analysis/i386/thunk_reg.py` (62 LOC).
//!
//! Detects `__x86.get_pc_thunk.<reg>` functions used in position-independent
//! code (PIC) on i386. These are tiny functions that load the return address
//! (current PC) into a register for PIC addressing.
//!
//! Pattern: `mov reg, [esp]; ret` (8b 04 24 c3 for eax)

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::error::VivResult;

/// Known thunk patterns: (bytes, register_name)
const THUNK_PATTERNS: &[(&[u8], &str)] = &[
    (&[0x8B, 0x04, 0x24, 0xC3], "eax"), // mov eax, [esp]; ret
    (&[0x8B, 0x0C, 0x24, 0xC3], "ecx"), // mov ecx, [esp]; ret
    (&[0x8B, 0x14, 0x24, 0xC3], "edx"), // mov edx, [esp]; ret
    (&[0x8B, 0x1C, 0x24, 0xC3], "ebx"), // mov ebx, [esp]; ret
    (&[0x8B, 0x34, 0x24, 0xC3], "esi"), // mov esi, [esp]; ret
    (&[0x8B, 0x3C, 0x24, 0xC3], "edi"), // mov edi, [esp]; ret
];

/// Run PIC thunk register detection.
///
/// Scans all i386 functions for the `mov reg, [esp]; ret` pattern.
/// Names matched functions as `thunk_<reg>_<va>`.
#[must_use]
pub fn analyze_thunk_reg(workspace: &mut VivWorkspace) -> VivResult<ThunkRegStats> {
    let mut stats = ThunkRegStats::default();

    if workspace.architecture() != Architecture::I386 {
        return Ok(stats);
    }

    let funcs: Vec<u64> = workspace.get_functions();

    for func_va in funcs {
        let bytes = match workspace.read_memory(func_va, 4) {
            Ok(b) => b,
            Err(_) => continue,
        };

        for (pattern, reg_name) in THUNK_PATTERNS {
            if bytes.len() >= pattern.len() && &bytes[..pattern.len()] == *pattern {
                let thunk_name = format!("thunk_{}_{:x}", reg_name, func_va);
                workspace.set_name(func_va, &thunk_name);

                if let Some(func) = workspace.get_function_mut(func_va) {
                    func.meta
                        .insert("ThunkReg".to_string(), reg_name.to_string());
                    func.meta.insert("Thunk".to_string(), thunk_name.clone());
                }

                stats.thunks_found += 1;
                tracing::debug!(
                    "[thunk_reg] PIC thunk at 0x{:x}: {} = [esp]",
                    func_va,
                    reg_name
                );
                break;
            }
        }
    }

    tracing::debug!("[thunk_reg] found {} PIC thunks", stats.thunks_found);
    Ok(stats)
}

#[derive(Debug, Default)]
pub struct ThunkRegStats {
    pub thunks_found: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thunk_patterns_valid() {
        // Each pattern should be exactly 4 bytes
        for (pattern, reg) in THUNK_PATTERNS {
            assert_eq!(pattern.len(), 4, "Pattern for {} should be 4 bytes", reg);
            assert_eq!(
                pattern[0], 0x8B,
                "Pattern for {} should start with MOV opcode",
                reg
            );
            assert_eq!(
                pattern[2], 0x24,
                "Pattern for {} should have [esp] encoding",
                reg
            );
            assert_eq!(pattern[3], 0xC3, "Pattern for {} should end with RET", reg);
        }
    }

    #[test]
    fn test_thunk_patterns_unique_registers() {
        let regs: Vec<&str> = THUNK_PATTERNS.iter().map(|(_, r)| *r).collect();
        let unique: std::collections::HashSet<&&str> = regs.iter().collect();
        assert_eq!(
            regs.len(),
            unique.len(),
            "All register names should be unique"
        );
    }

    #[test]
    fn test_thunk_patterns_cover_all_regs() {
        let regs: Vec<&str> = THUNK_PATTERNS.iter().map(|(_, r)| *r).collect();
        assert!(regs.contains(&"eax"));
        assert!(regs.contains(&"ecx"));
        assert!(regs.contains(&"edx"));
        assert!(regs.contains(&"ebx"));
        assert!(regs.contains(&"esi"));
        assert!(regs.contains(&"edi"));
    }

    #[test]
    fn test_analyze_on_non_i386() {
        let mut ws = VivWorkspace::new();
        // Default arch is not i386, should return empty
        let result = analyze_thunk_reg(&mut ws).unwrap();
        assert_eq!(result.thunks_found, 0);
    }
}
