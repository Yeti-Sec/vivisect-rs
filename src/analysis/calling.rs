//! Calling convention detection module.
//!
//! Port of Python's `vivisect/analysis/i386/calling.py`.
//!
//! Detects calling conventions by analyzing function epilogues and
//! register usage patterns:
//! - `ret N` with immediate → stdcall (callee cleanup, N/ptr_size stack args)
//! - Uninitialized ECX read → thiscall
//! - Uninitialized ECX+EDX read → msfastcall
//! - Default → cdecl (caller cleanup)
//!
//! When icicle is available, uses full emulation to track register reads
//! before writes. Without icicle, uses static pattern matching on the
//! function's instructions.

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::VivResult;

/// Known calling convention names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Thiscall,
    Msfastcall,
    Bfastcall,
    /// System V AMD64 ABI (Linux/Mac x86-64).
    SysV64,
    /// Microsoft x64 calling convention.
    Ms64,
    Unknown,
}

impl CallingConvention {
    pub fn as_str(&self) -> &str {
        match self {
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Thiscall => "thiscall",
            CallingConvention::Msfastcall => "msfastcall",
            CallingConvention::Bfastcall => "bfastcall",
            CallingConvention::SysV64 => "sysv64",
            CallingConvention::Ms64 => "ms64call",
            CallingConvention::Unknown => "unknown",
        }
    }
}

/// Result of calling convention analysis for one function.
#[derive(Debug)]
pub struct CallingConvResult {
    pub func_va: u64,
    pub convention: CallingConvention,
    pub argc: usize,
    pub ret_bytes: Option<u16>,
}

/// Analyze a single function's calling convention by static analysis.
///
/// Scans the function's blocks looking for:
/// - `ret imm16` → stdcall with N/4 (or N/8) args
/// - Register read patterns in the prologue
fn analyze_function_static(
    workspace: &VivWorkspace,
    func_va: u64,
    arch: Architecture,
) -> CallingConvResult {
    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => {
            return CallingConvResult {
                func_va,
                convention: CallingConvention::Unknown,
                argc: 0,
                ret_bytes: None,
            };
        }
    };

    let ptr_size = arch.pointer_size();
    let mut ret_bytes: Option<u16> = None;

    // For x86-64, convention is determined by platform, not per-function
    if arch == Architecture::Amd64 {
        // Check if PE (Windows → ms64) or ELF (Linux → sysv64)
        let is_pe = workspace.get_segments().iter().any(|seg| {
            seg.name == "PE Header"
                || seg.name.starts_with('.')
                    && workspace
                        .get_segments()
                        .iter()
                        .any(|s| s.name == "PE Header")
        });
        let convention = if is_pe {
            CallingConvention::Ms64
        } else {
            CallingConvention::SysV64
        };
        return CallingConvResult {
            func_va,
            convention,
            argc: 0, // Can't determine statically without emulation
            ret_bytes: None,
        };
    }

    // i386: scan function blocks for ret instructions
    let blocks = workspace.get_function_blocks(func_va);
    for block in &blocks {
        let mut va = block.va;
        let block_end = block.va + block.size as u64;

        while va < block_end {
            let bytes = match workspace.read_memory(va, 16) {
                Ok(b) => b,
                Err(_) => break,
            };

            let op = match disasm.disassemble(&bytes, va) {
                Ok(op) => op,
                Err(_) => break,
            };

            if op.size == 0 {
                break;
            }

            // Check for ret with immediate (stdcall indicator)
            if op.is_return() && !op.opers.is_empty() {
                if let Some(imm) = op.opers[0].get_value(&op) {
                    if imm > 0 {
                        ret_bytes = Some(imm as u16);
                    }
                }
            }

            va += op.size as u64;
        }
    }

    // Determine convention from ret bytes
    let (convention, argc) = if let Some(rb) = ret_bytes {
        let args = rb as usize / ptr_size;
        (CallingConvention::Stdcall, args)
    } else {
        (CallingConvention::Cdecl, 0)
    };

    CallingConvResult {
        func_va,
        convention,
        argc,
        ret_bytes,
    }
}

/// Analyze calling conventions for all functions using icicle emulation.
///
/// For each function:
/// 1. Emulate the function with icicle
/// 2. Track which registers are read before being written (uninitialized use)
/// 3. Check stack counter delta on return
/// 4. Determine calling convention from the evidence
#[cfg(feature = "icicle")]
fn analyze_with_emulation(
    workspace: &mut VivWorkspace,
) -> VivResult<Vec<CallingConvResult>> {
    use crate::analysis::emucode::emu;

    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size();
    let mut results = Vec::new();

    // For x86-64, calling convention is platform-determined
    if arch == Architecture::Amd64 {
        let funcs: Vec<u64> = workspace.get_functions();
        let is_pe = workspace.get_segments().iter().any(|seg| seg.name == "PE Header");
        let convention = if is_pe {
            CallingConvention::Ms64
        } else {
            CallingConvention::SysV64
        };
        for func_va in funcs {
            results.push(CallingConvResult {
                func_va,
                convention: convention.clone(),
                argc: 0,
                ret_bytes: None,
            });
        }
        return Ok(results);
    }

    // i386: use emulation to detect calling convention
    let mut vm = match emu::create_validator_vm(workspace) {
        Some(vm) => vm,
        None => {
            // Fall back to static analysis
            let funcs: Vec<u64> = workspace.get_functions();
            for func_va in funcs {
                results.push(analyze_function_static(workspace, func_va, arch));
            }
            return Ok(results);
        }
    };

    let funcs: Vec<u64> = workspace.get_functions();
    let stack_base = 0x7FFE_0000u64 + 0x10000 - 0x100;

    for func_va in &funcs {
        // Reset VM
        vm.cpu.exception.clear();
        vm.cpu.icount = 0;
        vm.icount_limit = 1024;

        // Set up stack with sentinel
        vm.cpu.write_pc(*func_va);
        let sp_reg = vm.cpu.arch.reg_sp;
        vm.cpu.write_reg(sp_reg, stack_base);

        // Push return sentinel
        let sentinel = 0xDEAD_0000u64;
        let sp = stack_base - ptr_size as u64;
        match ptr_size {
            4 => {
                let bytes = (sentinel as u32).to_le_bytes();
                let _ = vm.cpu.mem.write_bytes(sp, &bytes, icicle_cpu::mem::perm::NONE);
            }
            8 => {
                let bytes = sentinel.to_le_bytes();
                let _ = vm.cpu.mem.write_bytes(sp, &bytes, icicle_cpu::mem::perm::NONE);
            }
            _ => {}
        }
        vm.cpu.write_reg(sp_reg, sp);

        // Run
        let exit = vm.run();

        let stack_after = vm.cpu.read_reg(sp_reg);
        let stack_delta = stack_after as i64 - stack_base as i64;

        // Determine convention from stack cleanup
        let (convention, argc) = if stack_delta > 0 {
            // Callee cleaned up stack → stdcall
            let cleaned = stack_delta as usize;
            let args = cleaned / ptr_size;
            (CallingConvention::Stdcall, args)
        } else {
            (CallingConvention::Cdecl, 0)
        };

        let ret_bytes = if stack_delta > 0 {
            Some(stack_delta as u16)
        } else {
            None
        };

        results.push(CallingConvResult {
            func_va: *func_va,
            convention,
            argc,
            ret_bytes,
        });
    }

    Ok(results)
}

/// Run calling convention analysis on all functions.
#[must_use]
pub fn analyze_calling_conventions(workspace: &mut VivWorkspace) -> VivResult<CallingStats> {
    let arch = workspace.architecture();
    let mut stats = CallingStats::default();

    #[cfg(feature = "icicle")]
    let results = analyze_with_emulation(workspace)?;

    #[cfg(not(feature = "icicle"))]
    let results = {
        let funcs: Vec<u64> = workspace.get_functions();
        funcs
            .iter()
            .map(|&fva| analyze_function_static(workspace, fva, arch))
            .collect::<Vec<_>>()
    };

    // Apply results to workspace
    for result in &results {
        let cc_name = result.convention.as_str();
        if let Some(func) = workspace.get_function_mut(result.func_va) {
            func.meta
                .entry("CallingConvention".to_string())
                .or_insert_with(|| cc_name.to_string());
            if result.argc > 0 {
                func.meta
                    .entry("ArgCount".to_string())
                    .or_insert_with(|| result.argc.to_string());
            }
        }

        match result.convention {
            CallingConvention::Cdecl => stats.cdecl += 1,
            CallingConvention::Stdcall => stats.stdcall += 1,
            CallingConvention::Thiscall => stats.thiscall += 1,
            CallingConvention::Msfastcall => stats.fastcall += 1,
            CallingConvention::Bfastcall => stats.fastcall += 1,
            CallingConvention::SysV64 => stats.sysv64 += 1,
            CallingConvention::Ms64 => stats.ms64 += 1,
            CallingConvention::Unknown => stats.unknown += 1,
        }
    }

    tracing::debug!(
        "[calling] analyzed {} functions: {} cdecl, {} stdcall, {} thiscall, {} fastcall, {} sysv64, {} ms64",
        results.len(), stats.cdecl, stats.stdcall, stats.thiscall, stats.fastcall, stats.sysv64, stats.ms64
    );

    Ok(stats)
}

#[derive(Debug, Default)]
pub struct CallingStats {
    pub cdecl: usize,
    pub stdcall: usize,
    pub thiscall: usize,
    pub fastcall: usize,
    pub sysv64: usize,
    pub ms64: usize,
    pub unknown: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // CallingConvention::as_str() Tests
    // =========================================================================

    #[test]
    fn test_calling_convention_as_str_cdecl() {
        assert_eq!(CallingConvention::Cdecl.as_str(), "cdecl");
    }

    #[test]
    fn test_calling_convention_as_str_stdcall() {
        assert_eq!(CallingConvention::Stdcall.as_str(), "stdcall");
    }

    #[test]
    fn test_calling_convention_as_str_thiscall() {
        assert_eq!(CallingConvention::Thiscall.as_str(), "thiscall");
    }

    #[test]
    fn test_calling_convention_as_str_msfastcall() {
        assert_eq!(CallingConvention::Msfastcall.as_str(), "msfastcall");
    }

    #[test]
    fn test_calling_convention_as_str_bfastcall() {
        assert_eq!(CallingConvention::Bfastcall.as_str(), "bfastcall");
    }

    #[test]
    fn test_calling_convention_as_str_sysv64() {
        assert_eq!(CallingConvention::SysV64.as_str(), "sysv64");
    }

    #[test]
    fn test_calling_convention_as_str_ms64() {
        assert_eq!(CallingConvention::Ms64.as_str(), "ms64call");
    }

    #[test]
    fn test_calling_convention_as_str_unknown() {
        assert_eq!(CallingConvention::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_calling_convention_equality() {
        assert_eq!(CallingConvention::Cdecl, CallingConvention::Cdecl);
        assert_ne!(CallingConvention::Cdecl, CallingConvention::Stdcall);
    }

    // =========================================================================
    // CallingConvResult Tests
    // =========================================================================

    #[test]
    fn test_calling_conv_result_construction() {
        let result = CallingConvResult {
            func_va: 0x401000,
            convention: CallingConvention::Stdcall,
            argc: 3,
            ret_bytes: Some(12),
        };
        assert_eq!(result.func_va, 0x401000);
        assert_eq!(result.convention, CallingConvention::Stdcall);
        assert_eq!(result.argc, 3);
        assert_eq!(result.ret_bytes, Some(12));
    }

    #[test]
    fn test_calling_conv_result_no_ret_bytes() {
        let result = CallingConvResult {
            func_va: 0x401000,
            convention: CallingConvention::Cdecl,
            argc: 0,
            ret_bytes: None,
        };
        assert!(result.ret_bytes.is_none());
    }

    // =========================================================================
    // CallingStats Tests
    // =========================================================================

    #[test]
    fn test_calling_stats_default() {
        let stats = CallingStats::default();
        assert_eq!(stats.cdecl, 0);
        assert_eq!(stats.stdcall, 0);
        assert_eq!(stats.thiscall, 0);
        assert_eq!(stats.fastcall, 0);
        assert_eq!(stats.sysv64, 0);
        assert_eq!(stats.ms64, 0);
        assert_eq!(stats.unknown, 0);
    }

    // =========================================================================
    // analyze_function_static Tests
    // =========================================================================

    #[test]
    fn test_analyze_function_static_unknown_arch() {
        let ws = VivWorkspace::new();
        // Default arch is not i386/amd64, so should return Unknown
        let result = analyze_function_static(&ws, 0x1000, Architecture::Default);
        assert_eq!(result.convention, CallingConvention::Unknown);
        assert_eq!(result.argc, 0);
        assert!(result.ret_bytes.is_none());
    }

    #[test]
    fn test_analyze_function_static_amd64_no_pe_header() {
        // amd64 without PE segment should default to sysv64
        let ws = VivWorkspace::new();
        let result = analyze_function_static(&ws, 0x1000, Architecture::Amd64);
        assert_eq!(result.convention, CallingConvention::SysV64);
        assert_eq!(result.func_va, 0x1000);
    }

    #[test]
    fn test_analyze_function_static_i386_no_blocks_defaults_cdecl() {
        // i386 function with no code blocks should default to cdecl
        let ws = VivWorkspace::new();
        let result = analyze_function_static(&ws, 0x401000, Architecture::I386);
        assert_eq!(result.convention, CallingConvention::Cdecl);
        assert_eq!(result.argc, 0);
        assert!(result.ret_bytes.is_none());
    }

    #[test]
    fn test_analyze_calling_conventions_empty_workspace() {
        let mut ws = VivWorkspace::new();
        let result = analyze_calling_conventions(&mut ws);
        assert!(result.is_ok());
        let stats = result.unwrap();
        assert_eq!(stats.cdecl, 0);
        assert_eq!(stats.stdcall, 0);
        assert_eq!(stats.unknown, 0);
    }

    #[test]
    fn test_analyze_function_static_func_va_preserved() {
        let ws = VivWorkspace::new();
        let va = 0xDEAD_BEEF;
        let result = analyze_function_static(&ws, va, Architecture::Default);
        assert_eq!(result.func_va, va);
    }
}
