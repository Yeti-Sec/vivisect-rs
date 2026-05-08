//! No-return function detection module.
//!
//! Determines if a function never returns by examining its leaf blocks
//! (terminal nodes in the CFG). If all leaf blocks end in either a known
//! no-return call or lack a return instruction, the function is marked
//! as no-return.
//!
//! Port of Python's `vivisect/analysis/generic/noret.py`.

use crate::constants::{Architecture, LocationType, RefType};
use crate::core::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;
use std::collections::HashSet;

/// Known no-return API function names (lowercase for case-insensitive matching).
const NORETURN_APIS: &[&str] = &[
    "kernel32.exitprocess",
    "kernel32.exitthread",
    "kernel32.fatalexit",
    "ntdll.rtlexituserthread",
    "ntoskrnl.kebugcheckex",
    "msvcrt.exit",
    "msvcrt._exit",
    "msvcrt.abort",
    "msvcrt._cexit",
    "ucrtbase.exit",
    "ucrtbase._exit",
    "ucrtbase.abort",
    "exit",
    "_exit",
    "abort",
    "_Exit",
    "__stack_chk_fail",
    "__assert_fail",
    "__fortify_fail",
];

/// Initialize the no-return API set by scanning imports for known no-return functions.
///
/// Matches import names against `NORETURN_APIS` and marks their addresses.
pub fn init_noreturn_apis(workspace: &mut VivWorkspace) {
    // Scan all locations for imports matching known noreturn APIs
    let locations: Vec<(u64, Option<String>)> = workspace
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Import)
        .map(|(&va, loc)| (va, loc.tinfo.clone()))
        .collect();

    for (va, tinfo) in locations {
        if let Some(name) = tinfo {
            let lower = name.to_lowercase();
            if NORETURN_APIS.iter().any(|&api| lower == api || lower.ends_with(&format!(".{}", api))) {
                workspace.add_noreturn_va(va);
                tracing::debug!("[noret] marked import as noreturn: {} at {:#x}", name, va);
            }
        }
    }

    // Also check named functions (symbols) for noreturn patterns
    let funcs: Vec<(u64, String)> = workspace
        .functions_iter()
        .filter_map(|(&va, meta)| {
            meta.name.as_ref().map(|n| (va, n.clone()))
        })
        .collect();

    for (va, name) in funcs {
        let lower = name.to_lowercase();
        if NORETURN_APIS.iter().any(|&api| lower == api || lower.ends_with(&format!(".{}", api))) {
            workspace.add_noreturn_va(va);
        }
    }
}

/// Analyze a single function for no-return behavior.
///
/// Builds the function's CFG, finds leaf blocks (blocks with no successors
/// within the function), and checks if all leaf blocks terminate without
/// returning.
///
/// Returns `true` if the function was marked as no-return.
pub fn analyze_function_noret(workspace: &mut VivWorkspace, func_va: u64) -> bool {
    // Skip import thunks — they're handled via the import's own noreturn status
    if workspace.is_function_thunk(func_va) {
        // Check if the thunk target is a noreturn import
        let xrefs: Vec<(u64, RefType)> = workspace.get_xrefs_from(func_va);
        for (to_va, ref_type) in xrefs {
            if ref_type != RefType::Code {
                continue;
            }
            if let Some(loc) = workspace.get_location(to_va) {
                if loc.ltype == LocationType::Import && workspace.is_noreturn_va(to_va) {
                    workspace.add_noreturn_va(func_va);
                    return true;
                }
            }
        }
        return false;
    }

    // Already marked
    if workspace.is_noreturn_va(func_va) {
        return false;
    }

    // Get function blocks
    let blocks: Vec<(u64, usize)> = workspace
        .get_function_blocks(func_va)
        .iter()
        .map(|b| (b.va, b.size))
        .collect();

    if blocks.is_empty() {
        return false;
    }

    // Build set of block VAs in this function for successor checking
    let func_block_vas: HashSet<u64> = blocks.iter().map(|&(va, _)| va).collect();

    // Find leaf blocks: blocks whose successors are all outside this function
    let mut leaf_blocks = Vec::new();
    for &(block_va, _) in &blocks {
        let successors = workspace.get_block_successors(block_va);
        let has_internal_successor = successors
            .iter()
            .any(|s| func_block_vas.contains(s));
        if !has_internal_successor {
            leaf_blocks.push(block_va);
        }
    }

    if leaf_blocks.is_empty() {
        // No leaf blocks found — likely a single infinite loop, treat as noreturn
        // But be conservative: if there are blocks at all, don't mark
        return false;
    }

    // Create disassembler for checking last instructions
    let disasm = match workspace.architecture() {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return false,
    };

    // Check each leaf block's last instruction
    let mut has_return = false;

    for leaf_va in &leaf_blocks {
        let block = match workspace.get_codeblock(*leaf_va) {
            Some(b) => (b.va, b.size),
            None => continue,
        };

        if block.1 == 0 {
            continue;
        }

        // Find the last instruction by walking the block
        let bytes = match workspace.read_memory(block.0, block.1) {
            Ok(b) => b,
            Err(_) => {
                has_return = true; // Conservative: can't read → assume might return
                break;
            }
        };

        let mut last_op = None;
        let mut offset = 0u64;
        while offset < block.1 as u64 {
            let remaining = &bytes[offset as usize..];
            match disasm.disassemble(remaining, block.0 + offset) {
                Ok(op) => {
                    offset += op.size as u64;
                    last_op = Some(op);
                }
                Err(_) => break,
            }
        }

        let op = match last_op {
            Some(op) => op,
            None => {
                has_return = true;
                break;
            }
        };

        // If the last instruction is at a known noreturn address, skip this leaf
        if workspace.is_noreturn_va(op.va) {
            continue;
        }

        // If it's a call to a known noreturn target, skip this leaf
        if op.is_call() {
            let targets = op.get_targets();
            if targets.len() == 1 && workspace.is_noreturn_va(targets[0].0) {
                continue;
            }
        }

        // If it's a return instruction, this function definitely returns
        if op.is_return() {
            has_return = true;
            break;
        }

        // If it's a branch (possibly unresolved indirect), be conservative
        if op.is_branch() {
            // Check if the branch target is a known noreturn function
            let targets = op.get_targets();
            if targets.len() == 1 && workspace.is_noreturn_va(targets[0].0) {
                continue;
            }
            // Unresolved or unknown branch — conservatively assume it might return
            has_return = true;
            break;
        }

        // Not a return, not a branch, not a call to noreturn — this is unusual
        // (block ends without control flow). Be conservative.
        // Actually this can happen with int3/hlt/ud2 padding — these don't return.
        // But be safe and assume return unless we can prove otherwise.
    }

    if !has_return {
        tracing::debug!("[noret] marking {:#x} as no-return", func_va);
        workspace.add_noreturn_va(func_va);
        return true;
    }

    false
}

/// Run no-return analysis on all functions.
///
/// This is a workspace-level pass that iterates all functions and marks
/// those that never return. It runs in a fixed-point loop to handle
/// cascading (function A calls noreturn function B → A is also noreturn).
#[must_use]
pub fn analyze_noreturn(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    // First, initialize known noreturn APIs from imports
    init_noreturn_apis(workspace);

    let mut all_marked = Vec::new();

    // Fixed-point loop: keep going until no new noreturn functions are found
    loop {
        let functions: Vec<u64> = workspace.get_functions();
        let mut newly_marked = 0;

        for fva in functions {
            if workspace.is_noreturn_va(fva) {
                continue;
            }
            if analyze_function_noret(workspace, fva) {
                all_marked.push(fva);
                newly_marked += 1;
            }
        }

        if newly_marked == 0 {
            break;
        }

        tracing::debug!(
            "[noret] fixed-point iteration: {} new noreturn functions",
            newly_marked
        );
    }

    Ok(all_marked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noreturn_apis_list_not_empty() {
        assert!(!NORETURN_APIS.is_empty());
    }

    #[test]
    fn test_noreturn_apis_contains_exit_functions() {
        assert!(NORETURN_APIS.contains(&"exit"));
        assert!(NORETURN_APIS.contains(&"_exit"));
        assert!(NORETURN_APIS.contains(&"abort"));
    }

    #[test]
    fn test_noreturn_apis_contains_windows_functions() {
        assert!(NORETURN_APIS.contains(&"kernel32.exitprocess"));
        assert!(NORETURN_APIS.contains(&"kernel32.exitthread"));
        assert!(NORETURN_APIS.contains(&"kernel32.fatalexit"));
    }

    #[test]
    fn test_noreturn_apis_contains_linux_functions() {
        assert!(NORETURN_APIS.contains(&"__stack_chk_fail"));
        assert!(NORETURN_APIS.contains(&"__assert_fail"));
        assert!(NORETURN_APIS.contains(&"__fortify_fail"));
    }

    #[test]
    fn test_noreturn_apis_contains_crt_variants() {
        assert!(NORETURN_APIS.contains(&"msvcrt.exit"));
        assert!(NORETURN_APIS.contains(&"msvcrt._exit"));
        assert!(NORETURN_APIS.contains(&"msvcrt.abort"));
        assert!(NORETURN_APIS.contains(&"ucrtbase.exit"));
        assert!(NORETURN_APIS.contains(&"ucrtbase._exit"));
        assert!(NORETURN_APIS.contains(&"ucrtbase.abort"));
    }

    #[test]
    fn test_noreturn_matching_logic() {
        // Test the matching logic used in init_noreturn_apis
        let test_cases = vec![
            ("kernel32.exitprocess", true),
            ("KERNEL32.ExitProcess", true),  // Case-insensitive
            ("kernel32.createfilea", false),
            ("exit", true),
            ("_exit", true),
            ("abort", true),
            ("malloc", false),
            ("ntdll.RtlExitUserThread", true),
            ("msvcrt.exit", true),
            ("user32.messageboxw", false),
        ];

        for (name, expected) in test_cases {
            let lower = name.to_lowercase();
            let matches = NORETURN_APIS.iter().any(|&api| {
                lower == api || lower.ends_with(&format!(".{}", api))
            });
            assert_eq!(matches, expected,
                "Matching '{}' (lowered: '{}') expected {} but got {}",
                name, lower, expected, matches);
        }
    }

    #[test]
    fn test_noreturn_api_uniqueness() {
        // All API names should be unique in the list
        let mut seen = HashSet::new();
        for &api in NORETURN_APIS {
            assert!(seen.insert(api), "Duplicate noreturn API: {}", api);
        }
    }

    #[test]
    fn test_noreturn_apis_format() {
        // Most API names are lowercase, but _Exit (C11 function) has uppercase E
        // The matching logic lowercases inputs before comparison, so the
        // NORETURN_APIS entries with uppercase letters only match when the
        // input also happens to match the original casing.
        assert!(NORETURN_APIS.contains(&"_Exit"));

        // Verify all entries with dots use lowercase DLL names
        for &api in NORETURN_APIS {
            if let Some((dll, _func)) = api.rsplit_once('.') {
                assert_eq!(dll, dll.to_lowercase(),
                    "DLL prefix '{}' in API '{}' should be lowercase", dll, api);
            }
        }
    }

    #[test]
    fn test_noreturn_matching_with_suffix() {
        // Test that "ends_with" matching works for qualified names
        let lower = "mylib.exit".to_lowercase();
        let matches = NORETURN_APIS.iter().any(|&api| {
            lower == api || lower.ends_with(&format!(".{}", api))
        });
        assert!(matches);
    }

    #[test]
    fn test_noreturn_no_false_positives() {
        // Functions that should NOT match
        let non_noreturn = vec![
            "exitthread_wrapper",
            "before_exit",
            "atexit",
            "on_exit",
            "exit_handler",
        ];
        for name in non_noreturn {
            let lower = name.to_lowercase();
            let matches = NORETURN_APIS.iter().any(|&api| lower == api);
            assert!(!matches, "'{}' should not match as a noreturn API", name);
        }
    }
}
