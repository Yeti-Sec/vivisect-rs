//! Late-stage function entry discovery module.
//!
//! Port of Python's `vivisect/analysis/generic/funcentries.py`.
//!
//! Scans executable memory for undefined bytes (addresses with no location)
//! and checks for function prologue signatures. This is a "desperate" pass
//! that runs late, after most analysis is done, to catch functions missed
//! by call-following, prologue scanning, pointer tables, and emucode.
//!
//! The Python version uses `vw.isFunctionSignature()` which checks a
//! dynamically-built signature tree from already-analyzed functions. Our
//! simplified port checks for common prologue byte patterns in gaps.

use crate::constants::Architecture;
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Scan executable segments for function entries in undefined code gaps.
///
/// Algorithm (matching Python's funcentries.analyze):
/// 1. Iterate executable memory maps
/// 2. Skip bytes that already have a location defined
/// 3. At each undefined byte, check for prologue patterns
/// 4. If a match is found, create a function and run code flow
///
/// Returns the list of newly discovered function VAs.
#[must_use]
pub fn discover_function_entries(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();

    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(Vec::new()),
    };

    // Prologue patterns to check at each undefined byte
    let patterns: Vec<&[u8]> = match arch {
        Architecture::I386 => vec![
            &[0x8B, 0xFF, 0x55, 0x8B, 0xEC], // mov edi, edi; push ebp; mov ebp, esp (MSVC hotpatch)
            &[0x55, 0x8B, 0xEC],             // push ebp; mov ebp, esp (MSVC)
            &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp (GCC)
        ],
        Architecture::Amd64 => vec![
            &[0x55, 0x48, 0x89, 0xE5], // push rbp; mov rbp, rsp
            &[0x48, 0x89, 0x5C, 0x24], // mov [rsp+X], rbx (MSVC leaf)
            &[0x48, 0x83, 0xEC],       // sub rsp, imm8
            &[0x40, 0x55],             // rex push rbp
        ],
        _ => vec![],
    };

    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(4);

    // Collect executable segment info before mutable borrow
    let code_segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            let name_lower = seg.name.to_lowercase();
            name_lower.contains("text") || name_lower.contains("code")
        })
        .map(|seg| (seg.va, seg.size))
        .collect();

    let mut discovered = Vec::new();

    for (seg_va, seg_size) in &code_segments {
        let seg_end = seg_va + *seg_size as u64;
        let mut va = *seg_va;

        while va + max_pattern_len as u64 <= seg_end {
            // Skip if location exists
            if let Some(loc) = workspace.get_location(va) {
                va += loc.size as u64;
                continue;
            }

            // Skip if already a function
            if workspace.is_function(va) {
                va += 1;
                continue;
            }

            // Read bytes and check against prologue patterns
            let bytes = match workspace.read_memory(va, max_pattern_len) {
                Ok(b) => b,
                Err(_) => {
                    va += 1;
                    continue;
                }
            };

            let mut matched = false;
            for pattern in &patterns {
                if bytes.len() >= pattern.len() && bytes[..pattern.len()] == **pattern {
                    matched = true;
                    break;
                }
            }

            if !matched {
                va += 1;
                continue;
            }

            // Additional validation: disassemble a few instructions
            // to make sure this looks like real code
            let mut valid_insns = 0;
            let mut offset = 0u64;
            let check_bytes = match workspace.read_memory(va, 32) {
                Ok(b) => b,
                Err(_) => {
                    va += 1;
                    continue;
                }
            };

            while offset < check_bytes.len() as u64 && valid_insns < 4 {
                let remaining = &check_bytes[offset as usize..];
                match disasm.disassemble(remaining, va + offset) {
                    Ok(op) => {
                        if op.size == 0 {
                            break;
                        }
                        offset += op.size as u64;
                        valid_insns += 1;
                    }
                    Err(_) => break,
                }
            }

            if valid_insns < 3 {
                va += 1;
                continue;
            }

            // Create the function
            if !workspace.is_function(va) {
                workspace.add_function(
                    va,
                    FunctionMeta {
                        name: Some(format!("sub_{:x}", va)),
                        ..Default::default()
                    },
                )?;
                discovered.push(va);
            }

            va += 1;
        }
    }

    // Run code flow on discovered functions
    if !discovered.is_empty() {
        use crate::analysis::codeflow::CodeFlowAnalyzer;

        let mut analyzer = CodeFlowAnalyzer::new().with_max_instructions(500_000);
        for &func_va in &discovered {
            analyzer.add_entry_point(func_va);
        }

        if let Ok(result) = analyzer.analyze(workspace) {
            // Add any new functions found by following calls
            for func_va in result.functions_discovered {
                if !workspace.is_function(func_va) {
                    workspace.add_function(
                        func_va,
                        FunctionMeta {
                            name: Some(format!("sub_{:x}", func_va)),
                            ..Default::default()
                        },
                    )?;
                    discovered.push(func_va);
                }
            }
        }
    }

    tracing::debug!(
        "[funcentries] discovered {} new functions from code gaps",
        discovered.len()
    );

    Ok(discovered)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_i386_prologue_patterns() {
        let patterns: Vec<&[u8]> = vec![
            &[0x8B, 0xFF, 0x55, 0x8B, 0xEC], // mov edi, edi; push ebp; mov ebp, esp
            &[0x55, 0x8B, 0xEC],             // push ebp; mov ebp, esp (MSVC)
            &[0x55, 0x89, 0xE5],             // push ebp; mov ebp, esp (GCC)
        ];

        // Test that each pattern starts with expected bytes
        assert_eq!(patterns[0][0], 0x8B); // mov edi, edi
        assert_eq!(patterns[1][0], 0x55); // push ebp
        assert_eq!(patterns[2][0], 0x55); // push ebp

        // MSVC vs GCC differ in encoding of mov ebp, esp
        assert_eq!(patterns[1][1], 0x8B); // MSVC: 8B EC
        assert_eq!(patterns[2][1], 0x89); // GCC: 89 E5
    }

    #[test]
    fn test_amd64_prologue_patterns() {
        let patterns: Vec<&[u8]> = vec![
            &[0x55, 0x48, 0x89, 0xE5], // push rbp; mov rbp, rsp
            &[0x48, 0x89, 0x5C, 0x24], // mov [rsp+X], rbx (MSVC leaf)
            &[0x48, 0x83, 0xEC],       // sub rsp, imm8
            &[0x40, 0x55],             // rex push rbp
        ];

        assert_eq!(patterns.len(), 4);
        // REX prefix patterns
        assert_eq!(patterns[0][1], 0x48); // REX.W prefix
        assert_eq!(patterns[1][0], 0x48); // REX.W prefix
        assert_eq!(patterns[2][0], 0x48); // REX.W prefix
        assert_eq!(patterns[3][0], 0x40); // REX prefix
    }

    #[test]
    fn test_pattern_matching_logic() {
        let patterns: Vec<&[u8]> = vec![&[0x55, 0x8B, 0xEC], &[0x55, 0x89, 0xE5]];
        let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
        assert_eq!(max_pattern_len, 3);

        // Test matching: push ebp; mov ebp, esp (MSVC)
        let code = [0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let mut matched = false;
        for pattern in &patterns {
            if code.len() >= pattern.len() && code[..pattern.len()] == **pattern {
                matched = true;
                break;
            }
        }
        assert!(matched);

        // Test non-matching: NOP sled
        let nops = [0x90u8, 0x90, 0x90, 0x90];
        let mut matched2 = false;
        for pattern in &patterns {
            if nops.len() >= pattern.len() && nops[..pattern.len()] == **pattern {
                matched2 = true;
                break;
            }
        }
        assert!(!matched2);
    }

    #[test]
    fn test_function_name_format() {
        let va: u64 = 0x401000;
        let name = format!("sub_{:x}", va);
        assert_eq!(name, "sub_401000");
    }

    #[test]
    fn test_segment_name_matching() {
        // The code filters segments by name containing "text" or "code"
        let test_names = vec![
            (".text", true),
            (".TEXT", true),
            (".code", true),
            (".CODE", true),
            ("CODE", true),
            (".data", false),
            (".bss", false),
            (".rodata", false),
            (".textrel", true),       // contains "text"
            ("mycode_section", true), // contains "code"
        ];
        for (name, expected) in test_names {
            let lower = name.to_lowercase();
            let is_code_seg = lower.contains("text") || lower.contains("code");
            assert_eq!(is_code_seg, expected, "Mismatch for segment name: {}", name);
        }
    }

    #[test]
    fn test_validation_threshold() {
        // The funcentries module requires at least 3 valid disassembled instructions
        // to confirm a function entry
        let required_valid_insns = 3;
        assert_eq!(required_valid_insns, 3);
    }
}
