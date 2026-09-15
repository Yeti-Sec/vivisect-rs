//! ELF `__libc_start_main` analysis module.
//!
//! Port of Python's `vivisect/analysis/elf/libc_start_main.py`.
//!
//! Detects `main()` by finding calls to `__libc_start_main` and extracting
//! the first argument (which is the address of `main`).
//!
//! Algorithm:
//! 1. Find `__libc_start_main` import/symbol VA
//! 2. Find callers (typically `_start` or `__libc_csu_init`)
//! 3. Emulate (icicle) or pattern-match to extract first argument = `main` VA
//! 4. Create function at `main` and name it

use crate::constants::Architecture;
use crate::core::workspace::{FunctionMeta, VivWorkspace};
use crate::error::VivResult;

/// Find VAs of `__libc_start_main` in the workspace.
fn find_libc_start_main_vas(workspace: &VivWorkspace) -> Vec<u64> {
    let mut vas = Vec::new();
    for (va, name) in workspace.symbols().iter() {
        let lower = name.to_lowercase();
        if lower.contains("__libc_start_main") {
            vas.push(va);
        }
    }
    vas
}

/// Try to find main via pattern matching on the `_start` function.
///
/// Common x86-64 _start pattern:
///   mov rdi, <main_addr>   ; or lea rdi, [rip+...]
///   call __libc_start_main
///
/// Common x86 _start pattern:
///   push <main_addr>
///   call __libc_start_main
fn find_main_by_pattern(workspace: &VivWorkspace, lcsm_vas: &[u64]) -> Option<u64> {
    let arch = workspace.architecture();

    // Find callers of __libc_start_main
    for &lcsm_va in lcsm_vas {
        let xrefs = workspace.get_xrefs_to(lcsm_va);
        for (from_va, _ref_type) in &xrefs {
            // Read bytes before the call instruction to find the argument setup
            let call_va = *from_va;

            match arch {
                Architecture::Amd64 => {
                    // Look for `lea rdi, [rip+disp32]` pattern before call
                    // Opcode: 48 8d 3d XX XX XX XX (7 bytes)
                    if let Ok(bytes) = workspace.read_memory(call_va.saturating_sub(20), 25) {
                        let offset = 20; // call_va position in buffer
                                         // Scan backwards for lea rdi pattern
                        for back in 7..=20 {
                            if offset >= back && offset - back + 6 < bytes.len() {
                                let pos = offset - back;
                                // lea rdi, [rip+disp32]: 48 8d 3d XX XX XX XX
                                if bytes[pos] == 0x48
                                    && bytes[pos + 1] == 0x8D
                                    && bytes[pos + 2] == 0x3D
                                {
                                    let disp = i32::from_le_bytes([
                                        bytes[pos + 3],
                                        bytes[pos + 4],
                                        bytes[pos + 5],
                                        bytes[pos + 6],
                                    ]);
                                    let insn_end = call_va - back as u64 + 7;
                                    let main_va = (insn_end as i64 + disp as i64) as u64;
                                    if workspace.is_valid_pointer(main_va) {
                                        return Some(main_va);
                                    }
                                }
                                // mov rdi, imm64: 48 bf XX XX XX XX XX XX XX XX (10 bytes)
                                if back >= 10 && bytes[pos] == 0x48 && bytes[pos + 1] == 0xBF {
                                    let main_va = u64::from_le_bytes([
                                        bytes[pos + 2],
                                        bytes[pos + 3],
                                        bytes[pos + 4],
                                        bytes[pos + 5],
                                        bytes[pos + 6],
                                        bytes[pos + 7],
                                        bytes[pos + 8],
                                        bytes[pos + 9],
                                    ]);
                                    if workspace.is_valid_pointer(main_va) {
                                        return Some(main_va);
                                    }
                                }
                                // mov edi, imm32: bf XX XX XX XX (5 bytes) — position independent
                                if back >= 5 && bytes[pos] == 0xBF {
                                    let main_va = u32::from_le_bytes([
                                        bytes[pos + 1],
                                        bytes[pos + 2],
                                        bytes[pos + 3],
                                        bytes[pos + 4],
                                    ]) as u64;
                                    if workspace.is_valid_pointer(main_va) {
                                        return Some(main_va);
                                    }
                                }
                            }
                        }
                    }
                }
                Architecture::I386 => {
                    // Look for `push <main_addr>` before call
                    // push imm32: 68 XX XX XX XX (5 bytes)
                    if let Ok(bytes) = workspace.read_memory(call_va.saturating_sub(15), 20) {
                        let offset = 15;
                        for back in 5..=15 {
                            if offset >= back && offset - back + 4 < bytes.len() {
                                let pos = offset - back;
                                if bytes[pos] == 0x68 {
                                    let main_va = u32::from_le_bytes([
                                        bytes[pos + 1],
                                        bytes[pos + 2],
                                        bytes[pos + 3],
                                        bytes[pos + 4],
                                    ]) as u64;
                                    if workspace.is_valid_pointer(main_va) {
                                        return Some(main_va);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    None
}

/// Find main via icicle emulation.
///
/// Sets breakpoint on `__libc_start_main`, runs from `_start`,
/// reads first argument register when breakpoint hits.
#[cfg(feature = "icicle")]
fn find_main_by_emulation(workspace: &VivWorkspace, lcsm_vas: &[u64]) -> Option<u64> {
    use crate::analysis::emucode::emu;

    if lcsm_vas.is_empty() {
        return None;
    }

    let arch = workspace.architecture();
    let mut vm = emu::create_validator_vm(workspace)?;

    // Set breakpoints on all __libc_start_main VAs
    for &va in lcsm_vas {
        vm.add_breakpoint(va);
    }

    // Find _start or entry point
    let entry_points = workspace.entry_points();
    if entry_points.is_empty() {
        return None;
    }

    for &start_va in entry_points {
        // Reset VM state
        vm.cpu.exception.clear();
        vm.cpu.icount = 0;
        vm.icount_limit = 512; // _start is short

        // Set up stack
        let stack_top = 0x7FFE_0000u64 + 0x10000 - 0x100;
        vm.cpu.write_pc(start_va);
        let sp_reg = vm.cpu.arch.reg_sp;
        vm.cpu.write_reg(sp_reg, stack_top);

        // Run until breakpoint
        let exit = vm.run();

        match exit {
            icicle_cpu::VmExit::Breakpoint => {
                let pc = vm.cpu.read_pc();
                if lcsm_vas.contains(&pc) {
                    // Read first argument
                    let main_va = match arch {
                        Architecture::Amd64 => {
                            // System V ABI: first arg in rdi
                            #[allow(deprecated)]
                            let rdi = vm.cpu.arch.sleigh.get_reg("RDI")?.var;
                            vm.cpu.read_reg(rdi)
                        }
                        Architecture::I386 => {
                            // cdecl: first arg at [esp+4] (after call pushed return addr)
                            let esp = vm.cpu.read_reg(vm.cpu.arch.reg_sp);
                            let mut buf = [0u8; 4];
                            let _ = vm.cpu.mem.read_bytes(
                                esp + 4,
                                &mut buf,
                                icicle_cpu::mem::perm::NONE,
                            );
                            u32::from_le_bytes(buf) as u64
                        }
                        _ => return None,
                    };

                    if workspace.is_valid_pointer(main_va) {
                        return Some(main_va);
                    }
                }
            }
            _ => continue,
        }
    }

    None
}

/// Run libc_start_main analysis.
///
/// Finds `main()` function via `__libc_start_main` argument extraction.
#[must_use]
pub fn analyze_libc_start_main(workspace: &mut VivWorkspace) -> VivResult<LibcStartMainStats> {
    let mut stats = LibcStartMainStats::default();

    let lcsm_vas = find_libc_start_main_vas(workspace);
    if lcsm_vas.is_empty() {
        return Ok(stats);
    }

    // Try emulation first (more accurate), fall back to pattern matching
    #[cfg(feature = "icicle")]
    let main_va = find_main_by_emulation(workspace, &lcsm_vas)
        .or_else(|| find_main_by_pattern(workspace, &lcsm_vas));

    #[cfg(not(feature = "icicle"))]
    let main_va = find_main_by_pattern(workspace, &lcsm_vas);

    if let Some(main_va) = main_va {
        if !workspace.is_function(main_va) {
            workspace.add_function(
                main_va,
                FunctionMeta {
                    name: Some("main".to_string()),
                    ..Default::default()
                },
            )?;
            stats.main_found = true;
            stats.main_va = Some(main_va);
            tracing::info!("[libc_start_main] found main at 0x{:x}", main_va);
        } else {
            // Function exists, just name it
            let cur_name = workspace.get_name(main_va);
            if cur_name.is_none() || cur_name == Some(&format!("sub_{:x}", main_va)) {
                workspace.set_name(main_va, "main");
            }
            stats.main_found = true;
            stats.main_va = Some(main_va);
        }
    }

    Ok(stats)
}

#[derive(Debug, Default)]
pub struct LibcStartMainStats {
    pub main_found: bool,
    pub main_va: Option<u64>,
}
