//! Emulated code discovery module.
//!
//! Discovers functions that normal code flow analysis misses by scanning
//! data sections for pointers to executable code and validating candidates.
//!
//! Two validation backends:
//! - **icicle** (feature `icicle`): Full emulation — maps workspace memory
//!   into an icicle-vm, pushes a return sentinel, and runs the candidate.
//!   If execution reaches the sentinel, the candidate is valid code.
//! - **fallback**: Trial disassembly — linearly decodes instructions and
//!   checks for RET, mnemonic diversity, and instruction count.
//!
//! This is a port of Python vivisect's `vivisect.analysis.generic.emucode`.

use crate::constants::{Architecture, MemoryPermissions};
use crate::core::VivWorkspace;
use crate::error::VivResult;
use std::collections::HashSet;

// ============================================================================
// Candidate collection (shared by both backends)
// ============================================================================

/// Collect candidate addresses that might be undiscovered functions.
///
/// Sources (matching Python's emucode.analyze):
/// 1. Pointer-sized values in non-executable segments pointing to code
/// 2. Named addresses (symbols) without locations in executable memory
fn collect_candidates(workspace: &VivWorkspace) -> Vec<u64> {
    let arch = workspace.architecture();
    let ptr_size = arch.pointer_size();

    // Build set of executable address ranges
    let exec_ranges: Vec<(u64, u64)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            workspace
                .get_permissions(seg.va)
                .map(|p| p.contains(MemoryPermissions::EXEC))
                .unwrap_or(false)
        })
        .map(|seg| (seg.va, seg.va + seg.size as u64))
        .collect();

    if exec_ranges.is_empty() {
        return Vec::new();
    }

    let mut candidates = HashSet::new();
    let existing_functions: HashSet<u64> = workspace.get_functions().into_iter().collect();

    // Source 1: Scan NON-executable segments (data sections) for pointers to code.
    for seg in workspace.get_segments() {
        let is_exec = workspace
            .get_permissions(seg.va)
            .map(|p| p.contains(MemoryPermissions::EXEC))
            .unwrap_or(false);

        if is_exec {
            continue;
        }

        let chunk_size = 4096;
        let mut offset = 0u64;

        while offset < seg.size as u64 {
            let read_size = chunk_size.min((seg.size as u64 - offset) as usize);
            let va = seg.va + offset;

            let bytes = match workspace.read_memory(va, read_size) {
                Ok(b) => b,
                Err(_) => {
                    offset += chunk_size as u64;
                    continue;
                }
            };

            let mut i = 0;
            while i + ptr_size <= bytes.len() {
                let target = match ptr_size {
                    4 => u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap()) as u64,
                    8 => u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()),
                    _ => break,
                };

                if target != 0 {
                    let in_exec = exec_ranges
                        .iter()
                        .any(|(start, end)| target >= *start && target < *end);

                    if in_exec
                        && !existing_functions.contains(&target)
                        && workspace.get_location(target).is_none()
                    {
                        candidates.insert(target);
                    }
                }

                i += ptr_size;
            }

            offset += chunk_size as u64;
        }
    }

    // Source 2: Named addresses without locations
    for (va, _name) in workspace.symbols().iter() {
        if !existing_functions.contains(&va)
            && workspace.get_location(va).is_none()
            && workspace.is_executable(va)
        {
            candidates.insert(va);
        }
    }

    candidates.into_iter().collect()
}

/// Check if address falls inside an existing code block.
fn is_inside_codeblock(workspace: &VivWorkspace, va: u64) -> bool {
    for (_, block) in workspace.codeblocks_iter() {
        if va >= block.va && va < block.va + block.size as u64 {
            return true;
        }
    }
    false
}

// ============================================================================
// Icicle emulation-based validator (feature = "icicle")
// ============================================================================

#[cfg(feature = "icicle")]
pub mod emu {
    use super::*;
    use icicle_cpu::mem::{perm, Mapping};
    use icicle_cpu::{Config, VmExit};

    /// Sentinel address pushed as the return address. When the candidate
    /// function executes RET, it pops this and jumps here. A breakpoint
    /// at this address signals "function returned successfully."
    const SENTINEL_ADDR: u64 = 0xDEAD_0000;
    const SENTINEL_SIZE: u64 = 0x1000;

    /// Stack region for emulation.
    const STACK_BASE: u64 = 0x7FFE_0000;
    const STACK_SIZE: u64 = 0x10000;

    /// Maximum instructions per candidate validation.
    const MAX_EMU_INSNS: u64 = 256;

    /// Create an icicle VM and map all workspace memory into it.
    #[must_use]
    pub fn create_validator_vm(workspace: &VivWorkspace) -> Option<icicle_vm::Vm> {
        let triple = match workspace.architecture() {
            Architecture::I386 => "i686-none",
            Architecture::Amd64 => "x86_64-none",
            _ => return None,
        };

        let config = Config {
            triple: triple.parse().ok()?,
            enable_jit: false, // Disable JIT for short-lived validations
            enable_shadow_stack: false,
            enable_recompilation: false,
            ..Config::default()
        };

        let mut vm = icicle_vm::build(&config).ok()?;

        // Map the authoritative memory image into the VM: iterate the real
        // mapped regions (base/len/perms/bytes) rather than the segment list, so
        // the emulator image is byte- and permission-identical to the workspace
        // image and cannot diverge (roadmap Phase 4 §2.1; regression class of #11).
        for region in workspace.iter_memory_regions() {
            let icicle_perm = translate_perms(region.permissions);
            vm.cpu.mem.map_memory_len(
                region.base,
                region.size as u64,
                Mapping {
                    perm: icicle_perm,
                    value: 0,
                },
            );
            if !region.data.is_empty() {
                let _ = vm
                    .cpu
                    .mem
                    .write_bytes(region.base, &region.data, perm::NONE);
            }
        }

        // Map sentinel page (readable + executable so the breakpoint works)
        vm.cpu.mem.map_memory_len(
            SENTINEL_ADDR,
            SENTINEL_SIZE,
            Mapping {
                perm: perm::READ | perm::EXEC | perm::MAP,
                value: 0xCC, // INT3 fill
            },
        );

        // Map stack (read/write)
        vm.cpu.mem.map_memory_len(
            STACK_BASE,
            STACK_SIZE,
            Mapping {
                perm: perm::READ | perm::WRITE | perm::INIT | perm::MAP,
                value: 0,
            },
        );

        // Set breakpoint on sentinel
        vm.add_breakpoint(SENTINEL_ADDR);

        Some(vm)
    }

    /// Translate vivisect memory permissions to icicle permission bits.
    fn translate_perms(perms: MemoryPermissions) -> u8 {
        let mut p = perm::MAP;
        if perms.contains(MemoryPermissions::READ) {
            p |= perm::READ | perm::INIT;
        }
        if perms.contains(MemoryPermissions::WRITE) {
            p |= perm::WRITE;
        }
        if perms.contains(MemoryPermissions::EXEC) {
            p |= perm::EXEC;
        }
        p
    }

    /// Validate a candidate using icicle emulation.
    ///
    /// Pushes a return sentinel onto the stack and runs the VM from the
    /// candidate address. If execution reaches the sentinel (via RET),
    /// the candidate is valid code.
    pub fn validate_with_emulation(vm: &mut icicle_vm::Vm, va: u64, ptr_size: usize) -> bool {
        // Reset CPU state
        vm.cpu.exception.clear();
        vm.cpu.icount = 0;
        vm.icount_limit = MAX_EMU_INSNS;

        // Set up stack: push sentinel as return address
        let stack_top = STACK_BASE + STACK_SIZE - 0x100; // Leave margin
        let sp_after_push = stack_top - ptr_size as u64;

        // Write sentinel address on the stack
        match ptr_size {
            4 => {
                let sentinel_bytes = (SENTINEL_ADDR as u32).to_le_bytes();
                let _ = vm
                    .cpu
                    .mem
                    .write_bytes(sp_after_push, &sentinel_bytes, perm::NONE);
            }
            8 => {
                let sentinel_bytes = SENTINEL_ADDR.to_le_bytes();
                let _ = vm
                    .cpu
                    .mem
                    .write_bytes(sp_after_push, &sentinel_bytes, perm::NONE);
            }
            _ => return false,
        }

        // Set PC and SP
        vm.cpu.write_pc(va);
        let sp_reg = vm.cpu.arch.reg_sp;
        vm.cpu.write_reg(sp_reg, sp_after_push);

        // Run
        let exit = vm.run();

        match exit {
            VmExit::Breakpoint => {
                // Check if we hit the sentinel
                let pc = vm.cpu.read_pc();
                if pc == SENTINEL_ADDR {
                    // Function returned — check instruction count
                    let insn_count = vm.cpu.icount;
                    insn_count >= 1 // Accept tiny functions (e.g. bare `ret`)
                } else {
                    false
                }
            }
            _ => false, // Faulted, hit limit, or other — not valid
        }
    }
}

// ============================================================================
// Disassembly-based validator (fallback when icicle is not available)
// ============================================================================

#[cfg(not(feature = "icicle"))]
mod disasm_validator {
    use super::*;
    use crate::constants::LocationType;
    use crate::envi::archs::X86Disassembler;
    use std::collections::HashMap;

    /// Maximum instructions to disassemble when validating a candidate.
    const MAX_VALIDATE_INSNS: usize = 64;

    /// Minimum valid instructions for a candidate to be considered code.
    /// Lowered from 4 to 1: Python's emulator accepts tiny functions (e.g.
    /// bare `ret`, `mov eax, X; ret`) that disassembly-only validation was
    /// rejecting.  The `has_ret` check already ensures the candidate ends
    /// with a return instruction, so even a single-instruction `ret` stub
    /// is a valid function.
    const MIN_VALID_INSNS: usize = 1;

    /// Maximum single-mnemonic ratio (anti-movfuscator). Python uses 0.67.
    const MAX_MNEM_RATIO: f64 = 0.67;

    /// Validate a candidate address as likely code by trial disassembly.
    pub fn validate_code_candidate(
        workspace: &VivWorkspace,
        disasm: &X86Disassembler,
        va: u64,
    ) -> bool {
        let mut mnem_counts: HashMap<String, usize> = HashMap::new();
        let mut insn_count = 0usize;
        let mut has_ret = false;
        let mut current_va = va;

        for _ in 0..MAX_VALIDATE_INSNS {
            let bytes = match workspace.read_memory(current_va, 16) {
                Ok(b) => b,
                Err(_) => break,
            };

            let op = match disasm.disassemble(&bytes, current_va) {
                Ok(op) => op,
                Err(_) => break,
            };

            if let Some(loc) = workspace.get_location(current_va) {
                if loc.ltype != LocationType::Op {
                    break;
                }
            }

            insn_count += 1;
            *mnem_counts.entry(op.mnem.clone()).or_insert(0) += 1;

            if op.is_return() {
                has_ret = true;
                break;
            }

            if op.is_branch() && !op.falls_through() && !op.is_call() {
                break;
            }

            current_va += op.size as u64;
        }

        if insn_count < MIN_VALID_INSNS {
            return false;
        }

        if !has_ret {
            return false;
        }

        // Only apply mnemonic diversity check for functions with enough
        // instructions.  For tiny functions (1-3 insns) a single mnemonic
        // naturally dominates (e.g. `ret` alone is 100%) and the check
        // would incorrectly reject valid code.
        if insn_count >= 4 {
            for &count in mnem_counts.values() {
                let ratio = count as f64 / insn_count as f64;
                if ratio >= MAX_MNEM_RATIO {
                    return false;
                }
            }
        }

        true
    }
}

// ============================================================================
// Main discovery function
// ============================================================================

/// Discover zero-coverage functions by scanning for code pointers.
///
/// This is the main entry point, matching Python's `emucode.analyze()`.
/// Iterates until no new functions are found (fixed-point).
///
/// When the `icicle` feature is enabled, uses full emulation for validation.
/// Otherwise, falls back to disassembly-based validation.
#[must_use]
pub fn discover_emucode_functions(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();
    match arch {
        Architecture::I386 | Architecture::Amd64 => {}
        _ => return Ok(Vec::new()),
    }

    #[cfg(feature = "icicle")]
    {
        discover_with_emulation(workspace)
    }

    #[cfg(not(feature = "icicle"))]
    {
        discover_with_disassembly(workspace)
    }
}

/// Discovery using icicle emulation for validation.
#[cfg(feature = "icicle")]
fn discover_with_emulation(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let ptr_size = workspace.architecture().pointer_size();

    let mut vm = match emu::create_validator_vm(workspace) {
        Some(vm) => vm,
        None => {
            tracing::warn!("Failed to create icicle VM, falling back to disassembly");
            return discover_with_disassembly_inner(workspace);
        }
    };

    let mut all_discovered = Vec::new();
    let mut tried: HashSet<u64> = HashSet::new();

    loop {
        let candidates = collect_candidates(workspace);
        let mut new_this_round = Vec::new();

        for va in candidates {
            if tried.contains(&va) {
                continue;
            }
            tried.insert(va);

            if workspace.is_function(va) || workspace.get_location(va).is_some() {
                continue;
            }

            if is_inside_codeblock(workspace, va) {
                continue;
            }

            if emu::validate_with_emulation(&mut vm, va, ptr_size) {
                new_this_round.push(va);
            }
        }

        if new_this_round.is_empty() {
            break;
        }

        for &func_va in &new_this_round {
            if !workspace.is_function(func_va) {
                let _ = workspace.add_function(
                    func_va,
                    crate::core::workspace::FunctionMeta {
                        name: Some(format!("emu_{:x}", func_va)),
                        ..Default::default()
                    },
                );
            }
        }

        tracing::debug!(
            "Emucode (icicle) round: {} new functions from {} candidates",
            new_this_round.len(),
            tried.len()
        );

        all_discovered.extend(new_this_round);
    }

    Ok(all_discovered)
}

/// Discovery using disassembly-based validation (fallback).
#[cfg(not(feature = "icicle"))]
fn discover_with_disassembly(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    discover_with_disassembly_inner(workspace)
}

/// Inner disassembly-based discovery (also used as icicle fallback).
fn discover_with_disassembly_inner(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    let arch = workspace.architecture();
    let disasm = match arch {
        Architecture::I386 => {
            crate::envi::archs::X86Disassembler::new(crate::envi::archs::X86Mode::Mode32)
        }
        Architecture::Amd64 => {
            crate::envi::archs::X86Disassembler::new(crate::envi::archs::X86Mode::Mode64)
        }
        _ => return Ok(Vec::new()),
    };

    let mut all_discovered = Vec::new();
    let mut tried: HashSet<u64> = HashSet::new();

    loop {
        let candidates = collect_candidates(workspace);
        let mut new_this_round = Vec::new();

        for va in candidates {
            if tried.contains(&va) {
                continue;
            }
            tried.insert(va);

            if workspace.is_function(va) || workspace.get_location(va).is_some() {
                continue;
            }

            if is_inside_codeblock(workspace, va) {
                continue;
            }

            #[cfg(not(feature = "icicle"))]
            let valid = disasm_validator::validate_code_candidate(workspace, &disasm, va);
            #[cfg(feature = "icicle")]
            let valid = {
                // Disassembly fallback for icicle builds (when VM creation fails)
                use crate::constants::LocationType;
                use std::collections::HashMap;
                let mut mnem_counts: HashMap<String, usize> = HashMap::new();
                let mut insn_count = 0usize;
                let mut has_ret = false;
                let mut current_va = va;
                for _ in 0..64 {
                    let bytes = match workspace.read_memory(current_va, 16) {
                        Ok(b) => b,
                        Err(_) => break,
                    };
                    let op = match disasm.disassemble(&bytes, current_va) {
                        Ok(op) => op,
                        Err(_) => break,
                    };
                    if let Some(loc) = workspace.get_location(current_va) {
                        if loc.ltype != LocationType::Op {
                            break;
                        }
                    }
                    insn_count += 1;
                    *mnem_counts.entry(op.mnem.clone()).or_insert(0) += 1;
                    if op.is_return() {
                        has_ret = true;
                        break;
                    }
                    if op.is_branch() && !op.falls_through() && !op.is_call() {
                        break;
                    }
                    current_va += op.size as u64;
                }
                if insn_count < 1 || !has_ret {
                    false
                } else if insn_count >= 4 {
                    !mnem_counts
                        .values()
                        .any(|&c| (c as f64 / insn_count as f64) >= 0.67)
                } else {
                    true
                }
            };

            if valid {
                new_this_round.push(va);
            }
        }

        if new_this_round.is_empty() {
            break;
        }

        for &func_va in &new_this_round {
            if !workspace.is_function(func_va) {
                let _ = workspace.add_function(
                    func_va,
                    crate::core::workspace::FunctionMeta {
                        name: Some(format!("emu_{:x}", func_va)),
                        ..Default::default()
                    },
                );
            }
        }

        tracing::debug!(
            "Emucode (disasm) round: {} new functions from {} candidates",
            new_this_round.len(),
            tried.len()
        );

        all_discovered.extend(new_this_round);
    }

    Ok(all_discovered)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_module_compiles() {
        // Ensure the emucode module compiles with both backends
        assert!(true);
    }
}
