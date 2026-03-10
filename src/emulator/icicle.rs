//! Icicle-based CPU emulation backend.
//!
//! This module provides a CPU emulator implementation using icicle-emu,
//! a SLEIGH-based multi-architecture emulator that uses Ghidra's processor
//! specifications for instruction translation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use icicle_cpu::{Config, ExceptionCode, VmExit, ValueSource};
use icicle_vm::Vm;

use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use super::{CpuEmulator, MemoryPermissions, StopReason};

/// Find the Ghidra processors path by checking multiple locations.
///
/// Search order:
/// 1. GHIDRA_SRC environment variable
/// 2. ICICLE_PROCESSORS environment variable (direct path to processors)
/// 3. Relative to current executable
/// 4. Common development paths
/// 5. Current directory
fn find_processors_path() -> Option<PathBuf> {
    // 1. Check GHIDRA_SRC env var
    if let Ok(ghidra_src) = std::env::var("GHIDRA_SRC") {
        let path = PathBuf::from(&ghidra_src).join("Ghidra/Processors");
        if path.exists() {
            return Some(path);
        }
    }

    // 2. Check ICICLE_PROCESSORS env var (direct path)
    if let Ok(processors) = std::env::var("ICICLE_PROCESSORS") {
        let path = PathBuf::from(&processors);
        if path.exists() {
            return Some(path);
        }
    }

    // 3. Check relative to current executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Check alongside executable
            let path = exe_dir.join("Ghidra/Processors");
            if path.exists() {
                return Some(path);
            }
            // Check one level up (for target/release layout)
            if let Some(parent) = exe_dir.parent() {
                let path = parent.join("Ghidra/Processors");
                if path.exists() {
                    return Some(path);
                }
                // Check two levels up
                if let Some(grandparent) = parent.parent() {
                    let path = grandparent.join("Ghidra/Processors");
                    if path.exists() {
                        return Some(path);
                    }
                }
            }
        }
    }

    // 4. Check common development paths
    let common_paths = [
        // Relative to rust-icicle-emu checkout
        PathBuf::from("../rust-icicle-emu/Ghidra/Processors"),
        PathBuf::from("../../rust-icicle-emu/Ghidra/Processors"),
        // Hardcoded development paths (Windows)
        PathBuf::from("deps/rust-icicle-emu/Ghidra/Processors"),
        // Hardcoded development paths (Unix)
        PathBuf::from("deps/rust-icicle-emu/Ghidra/Processors"),
        // Standard install locations
        PathBuf::from("/usr/share/ghidra/Processors"),
        PathBuf::from("/opt/ghidra/Ghidra/Processors"),
    ];

    for path in &common_paths {
        if path.exists() {
            return Some(path.clone());
        }
    }

    // 5. Check current directory
    let path = PathBuf::from("./Ghidra/Processors");
    if path.exists() {
        return Some(path);
    }

    None
}

/// Build icicle VM with automatic processor path discovery.
fn build_vm_auto(config: &Config) -> Result<Vm, VivError> {
    // Try to find the processors path
    if let Some(processors_path) = find_processors_path() {
        tracing::debug!("Using Ghidra processors at: {}", processors_path.display());
        icicle_vm::build_with_path(config, &processors_path).map_err(|e| VivError::Other {
            message: format!("Failed to build icicle VM: {}", e),
        })
    } else {
        // Fall back to default (will use GHIDRA_SRC or current dir)
        icicle_vm::build(config).map_err(|e| VivError::Other {
            message: format!(
                "Failed to build icicle VM: {}. \
                Set GHIDRA_SRC or ICICLE_PROCESSORS environment variable to the path \
                containing Ghidra processor specifications.",
                e
            ),
        })
    }
}

/// Icicle-based CPU emulator.
///
/// Wraps icicle-vm to provide CPU emulation using SLEIGH processor specifications.
/// Supports multiple architectures including x86, x86_64, ARM, ARM64, MIPS, RISC-V, etc.
pub struct IcicleEmulator {
    /// The underlying icicle VM.
    vm: Vm,
    /// Architecture string.
    arch_name: String,
    /// Pointer size in bytes.
    ptr_size: usize,
    /// Custom breakpoints (in addition to icicle's internal ones).
    breakpoints: HashSet<u64>,
}

impl IcicleEmulator {
    /// Create a new icicle emulator for the given architecture.
    pub fn new(arch: Architecture) -> VivResult<Self> {
        tracing::debug!("[viv-emu] new: arch={:?}", arch);
        let (triple, ptr_size) = Self::arch_to_triple(arch)?;
        let arch_name = format!("{:?}", arch);

        let config = Config {
            triple: triple.parse().map_err(|_| VivError::Other {
                message: format!("Failed to parse target triple: {}", triple),
            })?,
            enable_jit: true,
            enable_jit_mem: true,
            enable_shadow_stack: true,
            enable_recompilation: true,
            track_uninitialized: false,
            optimize_instructions: true,
            optimize_block: true,
        };

        let mut vm = build_vm_auto(&config)?;

        // Set instruction count limit to maximum to prevent premature InstructionLimit exits
        // This allows WorkspaceEmulator to control stepping via its own limits
        vm.icount_limit = u64::MAX;

        Ok(Self {
            vm,
            arch_name,
            ptr_size,
            breakpoints: HashSet::new(),
        })
    }

    /// Create an emulator from a target triple string.
    pub fn from_triple(triple: &str) -> VivResult<Self> {
        tracing::debug!("[viv-emu] from_triple: triple={}", triple);
        let config = Config {
            triple: triple.parse().map_err(|_| VivError::Other {
                message: format!("Failed to parse target triple: {}", triple),
            })?,
            enable_jit: true,
            enable_jit_mem: true,
            enable_shadow_stack: true,
            enable_recompilation: true,
            track_uninitialized: false,
            optimize_instructions: true,
            optimize_block: true,
        };

        let ptr_size = if triple.contains("64") { 8 } else { 4 };

        let mut vm = build_vm_auto(&config)?;

        // Set instruction count limit to maximum to prevent premature InstructionLimit exits
        vm.icount_limit = u64::MAX;

        Ok(Self {
            vm,
            arch_name: triple.to_string(),
            ptr_size,
            breakpoints: HashSet::new(),
        })
    }

    /// Map architecture enum to target-lexicon triple.
    fn arch_to_triple(arch: Architecture) -> VivResult<(&'static str, usize)> {
        match arch {
            Architecture::I386 => Ok(("i686-unknown-none", 4)),
            Architecture::Amd64 => Ok(("x86_64-unknown-none", 8)),
            Architecture::ArmV7 => Ok(("arm-unknown-none", 4)),
            Architecture::Thumb => Ok(("thumbv7-unknown-none", 4)),
            Architecture::Thumb16 => Ok(("thumbv6m-unknown-none", 4)),
            Architecture::A64 => Ok(("aarch64-unknown-none", 8)),
            Architecture::Mips32 => Ok(("mips-unknown-none", 4)),
            Architecture::Mips64 => Ok(("mips64-unknown-none", 8)),
            Architecture::PpcE32 | Architecture::PpcS32 => Ok(("powerpc-unknown-none", 4)),
            Architecture::PpcE64 | Architecture::PpcS64 => Ok(("powerpc64-unknown-none", 8)),
            Architecture::RiscV32 => Ok(("riscv32-unknown-none", 4)),
            Architecture::RiscV64 => Ok(("riscv64-unknown-none", 8)),
            Architecture::Msp430 => Ok(("msp430-unknown-none", 2)),
            Architecture::Sparc => Ok(("sparc-unknown-none", 4)),
            Architecture::Sparc64 => Ok(("sparc64-unknown-none", 8)),
            _ => Err(VivError::Other {
                message: format!("Unsupported architecture: {:?}", arch),
            }),
        }
    }

    /// Get direct access to the underlying icicle VM.
    pub fn vm(&self) -> &Vm {
        &self.vm
    }

    /// Get mutable access to the underlying icicle VM.
    pub fn vm_mut(&mut self) -> &mut Vm {
        &mut self.vm
    }

    /// Get access to the CPU state.
    pub fn cpu(&self) -> &icicle_cpu::Cpu {
        &self.vm.cpu
    }

    /// Get mutable access to the CPU state.
    pub fn cpu_mut(&mut self) -> &mut icicle_cpu::Cpu {
        &mut self.vm.cpu
    }

    /// Convert icicle VmExit to StopReason.
    fn convert_exit(&self, exit: VmExit) -> StopReason {
        let result = match exit {
            VmExit::Running => StopReason::ReachedTarget,
            VmExit::InstructionLimit => StopReason::StepLimit(self.vm.cpu.icount()),
            VmExit::Breakpoint => StopReason::Breakpoint(self.vm.cpu.read_pc()),
            VmExit::Interrupted => StopReason::Interrupted,
            VmExit::Halt => StopReason::Halted,
            VmExit::Killed => StopReason::Halted,
            VmExit::Deadlock => StopReason::Halted,
            VmExit::OutOfMemory => StopReason::OutOfMemory,
            VmExit::Unimplemented => StopReason::Exception(
                ExceptionCode::UnimplementedOp as u32,
                self.vm.cpu.exception.value,
            ),
            VmExit::UnhandledException((code, value)) => {
                match code {
                    ExceptionCode::InvalidInstruction => StopReason::InvalidInstruction(value),
                    ExceptionCode::ReadUnmapped
                    | ExceptionCode::ReadPerm
                    | ExceptionCode::WriteUnmapped
                    | ExceptionCode::WritePerm
                    | ExceptionCode::ExecViolation => StopReason::MemoryFault(value),
                    ExceptionCode::Syscall => StopReason::Syscall(value),
                    ExceptionCode::Halt | ExceptionCode::Sleep => StopReason::Halted,
                    _ => StopReason::Exception(code as u32, value),
                }
            }
        };
        tracing::trace!("[viv-emu] convert_exit: {:?} -> {:?}", exit, result);
        result
    }

    /// Convert memory permissions to icicle format.
    fn convert_perms(perms: MemoryPermissions) -> u8 {
        use icicle_mem::perm;
        let mut p = perm::NONE;
        if perms.read { p |= perm::READ; }
        if perms.write { p |= perm::WRITE; }
        if perms.exec { p |= perm::EXEC; }
        p |= perm::INIT;  // Mark as initialized
        p
    }

    /// Load binary data into memory.
    pub fn load_binary(&mut self, addr: u64, data: &[u8], executable: bool) -> VivResult<()> {
        tracing::debug!("[viv-emu] load_binary: addr={:#x}, size={:#x}", addr, data.len());
        let perms = if executable {
            MemoryPermissions::READ_EXEC
        } else {
            MemoryPermissions::READ_WRITE
        };

        self.map_memory(addr, data.len(), perms)?;
        self.write_memory(addr, data)?;
        Ok(())
    }

    /// Initialize stack memory.
    pub fn init_stack(&mut self, stack_base: u64, stack_size: usize) -> VivResult<()> {
        tracing::debug!("[viv-emu] init_stack: addr={:#x}, size={:#x}", stack_base, stack_size);
        self.map_memory(stack_base, stack_size, MemoryPermissions::READ_WRITE)?;
        // Set stack pointer to top of stack
        let sp = stack_base + stack_size as u64 - self.ptr_size as u64;
        self.set_sp(sp)
    }

    /// Hook an address to call a function before execution.
    pub fn hook_address<F>(&mut self, addr: u64, hook: F)
    where
        F: FnMut(&mut icicle_cpu::Cpu, u64) + 'static,
    {
        self.vm.hook_address(addr, hook);
    }

    /// Add instruction hooks at multiple addresses.
    pub fn hook_many_addresses<F>(&mut self, addrs: &[u64], hook: F)
    where
        F: FnMut(&mut icicle_cpu::Cpu, u64) + 'static,
    {
        self.vm.hook_many_addresses(addrs, hook);
    }

    /// Get the call stack (if shadow stack is enabled).
    pub fn get_callstack(&self) -> Vec<u64> {
        self.vm.get_callstack()
    }

    /// Save emulator state snapshot.
    pub fn save_snapshot(&mut self) {
        self.vm.save_snapshot();
    }

    /// Step backward by restoring a snapshot.
    pub fn step_back(&mut self, count: u64) -> Option<StopReason> {
        self.vm.step_back(count).map(|exit| self.convert_exit(exit))
    }

    /// Create a full snapshot of emulator state (CPU + memory).
    /// This is equivalent to Python's `emu.getEmuSnap()`.
    pub fn create_full_snapshot(&mut self) -> icicle_vm::Snapshot {
        tracing::trace!("[viv-emu] create_full_snapshot: pc={:#x}", self.get_pc());
        self.vm.snapshot()
    }

    /// Restore emulator state from a full snapshot.
    /// This is equivalent to Python's `emu.setEmuSnap()`.
    pub fn restore_full_snapshot(&mut self, snapshot: &icicle_vm::Snapshot) {
        tracing::trace!("[viv-emu] restore_full_snapshot: pc_before={:#x}", self.get_pc());
        self.vm.restore(snapshot);
    }

    /// Get direct access to memory subsystem for reading memory maps.
    pub fn memory(&mut self) -> &mut icicle_mem::Mmu {
        &mut self.vm.cpu.mem
    }

}


impl CpuEmulator for IcicleEmulator {
    fn architecture(&self) -> &str {
        &self.arch_name
    }

    fn pointer_size(&self) -> usize {
        self.ptr_size
    }

    fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    fn set_pc(&mut self, pc: u64) -> VivResult<()> {
        self.vm.cpu.write_pc(pc);
        Ok(())
    }

    fn get_sp(&self) -> u64 {
        let reg_sp = self.vm.cpu.arch.reg_sp;
        if reg_sp.size == 4 {
            self.vm.cpu.read_var::<u32>(reg_sp) as u64
        } else {
            self.vm.cpu.read_var::<u64>(reg_sp)
        }
    }

    fn set_sp(&mut self, sp: u64) -> VivResult<()> {
        let reg_sp = self.vm.cpu.arch.reg_sp;
        if reg_sp.size == 4 {
            self.vm.cpu.write_var::<u32>(reg_sp, sp as u32);
        } else {
            self.vm.cpu.write_var::<u64>(reg_sp, sp);
        }
        Ok(())
    }

    fn instruction_count(&self) -> u64 {
        self.vm.cpu.icount()
    }

    fn read_register(&mut self, name: &str) -> VivResult<u64> {
        tracing::trace!("[viv-emu] read_register: name={}", name);
        let var = self.vm.cpu.arch.sleigh.get_varnode(name).ok_or_else(|| VivError::Other {
            message: format!("Unknown register: {}", name),
        })?;
        Ok(self.vm.cpu.read_reg(var))
    }

    fn write_register(&mut self, name: &str, value: u64) -> VivResult<()> {
        tracing::trace!("[viv-emu] write_register: name={}, value={:#x}", name, value);
        let var = self.vm.cpu.arch.sleigh.get_varnode(name).ok_or_else(|| VivError::Other {
            message: format!("Unknown register: {}", name),
        })?;
        self.vm.cpu.write_reg(var, value);
        Ok(())
    }

    fn read_memory(&mut self, addr: u64, size: usize) -> VivResult<Vec<u8>> {
        tracing::trace!("[viv-emu] read_memory: addr={:#x}, size={}", addr, size);
        let mut buf = vec![0u8; size];
        self.vm.cpu.mem.read_bytes(addr, &mut buf, icicle_mem::perm::NONE)
            .map_err(|_e| VivError::InvalidMemory { address: addr })?;
        Ok(buf)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> VivResult<()> {
        tracing::trace!("[viv-emu] write_memory: addr={:#x}, size={}", addr, data.len());
        self.vm.cpu.mem.write_bytes(addr, data, icicle_mem::perm::NONE)
            .map_err(|_e| VivError::InvalidMemory { address: addr })
    }

    fn map_memory(&mut self, addr: u64, size: usize, perms: MemoryPermissions) -> VivResult<()> {
        tracing::debug!("[viv-emu] map_memory: addr={:#x}, size={:#x}, perms={:?}", addr, size, perms);
        let perm = Self::convert_perms(perms);
        self.vm.cpu.mem.map_memory_len(
            addr,
            size as u64,
            icicle_mem::Mapping { perm, value: 0 },
        );
        Ok(())
    }

    fn unmap_memory(&mut self, addr: u64, size: usize) -> VivResult<()> {
        self.vm.cpu.mem.unmap_memory_len(addr, size as u64);
        Ok(())
    }

    fn step(&mut self) -> VivResult<StopReason> {
        tracing::trace!("[viv-emu] step: pc={:#x}", self.get_pc());
        let exit = self.vm.step(1);
        // When stepping 1 instruction, InstructionLimit means "executed 1 instruction successfully"
        // Convert this to ReachedTarget (success) rather than StepLimit (stop)
        let result = match exit {
            VmExit::InstructionLimit => StopReason::ReachedTarget,
            other => self.convert_exit(other),
        };
        tracing::trace!("[viv-emu] step result: {:?}, pc={:#x}", result, self.get_pc());
        Ok(result)
    }

    fn run_to(&mut self, target_pc: u64, max_steps: u64) -> VivResult<(u64, StopReason)> {
        tracing::trace!("[viv-emu] run_to: target={:#x}, max_steps={}", target_pc, max_steps);
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount().saturating_add(max_steps);

        // Add temporary breakpoint
        let added = self.vm.add_breakpoint(target_pc);
        let exit = self.vm.run();

        if added {
            self.vm.remove_breakpoint(target_pc);
        }
        self.vm.icount_limit = old_limit;

        let steps = self.vm.cpu.icount();
        let reason = if self.vm.cpu.read_pc() == target_pc {
            StopReason::ReachedTarget
        } else {
            self.convert_exit(exit)
        };

        tracing::trace!("[viv-emu] run_to result: {:?}, pc={:#x}, steps={}", reason, self.get_pc(), self.instruction_count());
        Ok((steps, reason))
    }

    fn run(&mut self, max_steps: u64) -> VivResult<(u64, StopReason)> {
        tracing::trace!("[viv-emu] run: max_steps={}", max_steps);
        let old_limit = self.vm.icount_limit;
        let start_icount = self.vm.cpu.icount();
        self.vm.icount_limit = start_icount.saturating_add(max_steps);

        let exit = self.vm.run();

        self.vm.icount_limit = old_limit;
        let steps = self.vm.cpu.icount() - start_icount;

        Ok((steps, self.convert_exit(exit)))
    }

    fn add_breakpoint(&mut self, addr: u64) -> bool {
        tracing::trace!("[viv-emu] add_breakpoint: addr={:#x}", addr);
        self.breakpoints.insert(addr);
        self.vm.add_breakpoint(addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> bool {
        tracing::trace!("[viv-emu] remove_breakpoint: addr={:#x}", addr);
        self.breakpoints.remove(&addr);
        self.vm.remove_breakpoint(addr)
    }

    fn is_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains(&addr)
    }

    fn get_breakpoints(&self) -> Vec<u64> {
        self.breakpoints.iter().copied().collect()
    }

    fn clear_breakpoints(&mut self) {
        for &addr in &self.breakpoints.clone() {
            self.vm.remove_breakpoint(addr);
        }
        self.breakpoints.clear();
    }

    fn push(&mut self, value: u64) -> VivResult<()> {
        tracing::trace!("[viv-emu] push: value={:#x}", value);
        let sp = self.get_sp() - self.ptr_size as u64;
        self.set_sp(sp)?;

        let bytes = match self.ptr_size {
            4 => (value as u32).to_le_bytes().to_vec(),
            8 => value.to_le_bytes().to_vec(),
            _ => return Err(VivError::Other {
                message: "Unsupported pointer size".into(),
            }),
        };
        self.write_memory(sp, &bytes)
    }

    fn pop(&mut self) -> VivResult<u64> {
        let sp = self.get_sp();
        let bytes = self.read_memory(sp, self.ptr_size)?;

        let value = match self.ptr_size {
            4 => {
                let arr: [u8; 4] = bytes[..4].try_into().unwrap();
                u32::from_le_bytes(arr) as u64
            }
            8 => {
                let arr: [u8; 8] = bytes[..8].try_into().unwrap();
                u64::from_le_bytes(arr)
            }
            _ => return Err(VivError::Other {
                message: "Unsupported pointer size".into(),
            }),
        };

        self.set_sp(sp + self.ptr_size as u64)?;
        tracing::trace!("[viv-emu] pop: value={:#x}", value);
        Ok(value)
    }

    fn reset(&mut self) {
        self.vm.reset();
        self.breakpoints.clear();
    }

    fn get_disasm(&self, addr: u64) -> Option<String> {
        self.vm.get_disasm(addr).map(|s| s.to_string())
    }

    fn create_snapshot(&mut self) -> Box<dyn std::any::Any> {
        tracing::trace!("[viv-emu] create_snapshot: pc={:#x}", self.get_pc());
        Box::new(self.vm.snapshot())
    }

    fn restore_snapshot(&mut self, snapshot: &dyn std::any::Any) {
        tracing::trace!("[viv-emu] restore_snapshot: pc_before={:#x}", self.get_pc());
        if let Some(snap) = snapshot.downcast_ref::<icicle_vm::Snapshot>() {
            self.vm.restore(snap);
        } else {
            tracing::error!("restore_snapshot: incompatible snapshot type");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulator_creation() {
        // This test requires GHIDRA_SRC to be set for SLEIGH specs
        if std::env::var("GHIDRA_SRC").is_err() {
            eprintln!("Skipping test: GHIDRA_SRC not set");
            return;
        }

        let emu = IcicleEmulator::new(Architecture::Amd64);
        assert!(emu.is_ok());

        let emu = emu.unwrap();
        assert_eq!(emu.pointer_size(), 8);
    }

    #[test]
    fn test_memory_operations() {
        if std::env::var("GHIDRA_SRC").is_err() {
            eprintln!("Skipping test: GHIDRA_SRC not set");
            return;
        }

        let mut emu = match IcicleEmulator::new(Architecture::Amd64) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Map memory
        emu.map_memory(0x1000, 0x1000, MemoryPermissions::READ_WRITE).unwrap();

        // Write and read
        let data = b"Hello, World!";
        emu.write_memory(0x1000, data).unwrap();

        let read_back = emu.read_memory(0x1000, data.len()).unwrap();
        assert_eq!(&read_back, data);
    }

    #[test]
    fn test_register_operations() {
        if std::env::var("GHIDRA_SRC").is_err() {
            eprintln!("Skipping test: GHIDRA_SRC not set");
            return;
        }

        let mut emu = match IcicleEmulator::new(Architecture::Amd64) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Set and get PC
        emu.set_pc(0x401000).unwrap();
        assert_eq!(emu.get_pc(), 0x401000);

        // Set and get register by name
        emu.write_register("RAX", 0xDEADBEEF).unwrap();
        let rax = emu.read_register("RAX").unwrap();
        assert_eq!(rax, 0xDEADBEEF);
    }

    #[test]
    fn test_stack_operations() {
        if std::env::var("GHIDRA_SRC").is_err() {
            eprintln!("Skipping test: GHIDRA_SRC not set");
            return;
        }

        let mut emu = match IcicleEmulator::new(Architecture::Amd64) {
            Ok(e) => e,
            Err(_) => return,
        };

        // Initialize stack
        emu.init_stack(0x7FFF0000, 0x10000).unwrap();

        let initial_sp = emu.get_sp();

        // Push value
        emu.push(0x12345678).unwrap();
        assert_eq!(emu.get_sp(), initial_sp - 8);

        // Pop value
        let value = emu.pop().unwrap();
        assert_eq!(value, 0x12345678);
        assert_eq!(emu.get_sp(), initial_sp);
    }
}
