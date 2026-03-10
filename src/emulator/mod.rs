//! CPU Emulation backends for vivisect.
//!
//! This module provides pluggable CPU emulation backends for executing binary code.
//! The primary backend is icicle-emu, a SLEIGH-based multi-architecture emulator.

#[cfg(feature = "icicle")]
pub mod icicle;

#[cfg(feature = "icicle")]
pub use self::icicle::IcicleEmulator;

/// Re-export icicle_vm::Snapshot for full emulator state capture.
#[cfg(feature = "icicle")]
pub use icicle_vm::Snapshot as FullEmulatorSnapshot;

use std::any::Any;
use crate::error::{VivError, VivResult};
use crate::constants::Architecture;

/// Emulator stop reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// Normal completion (reached target address).
    ReachedTarget,
    /// Hit a breakpoint.
    Breakpoint(u64),
    /// Execution limit reached.
    StepLimit(u64),
    /// Invalid instruction at address.
    InvalidInstruction(u64),
    /// Memory access violation at address.
    MemoryFault(u64),
    /// Syscall/interrupt encountered.
    Syscall(u64),
    /// Program returned/exited.
    Returned,
    /// Emulator was halted.
    Halted,
    /// Interrupted by external signal.
    Interrupted,
    /// Out of memory.
    OutOfMemory,
    /// Unhandled exception with code and value.
    Exception(u32, u64),
}

/// Common trait for CPU emulators.
///
/// Note: This trait does not require `Send` because some emulator backends
/// (like icicle) use internal state that cannot be safely transferred between threads.
pub trait CpuEmulator {
    /// Get the architecture name.
    fn architecture(&self) -> &str;

    /// Get pointer size in bytes.
    fn pointer_size(&self) -> usize;

    /// Get current program counter.
    fn get_pc(&self) -> u64;

    /// Set program counter.
    fn set_pc(&mut self, pc: u64) -> VivResult<()>;

    /// Get current stack pointer.
    fn get_sp(&self) -> u64;

    /// Set stack pointer.
    fn set_sp(&mut self, sp: u64) -> VivResult<()>;

    /// Get instruction count executed so far.
    fn instruction_count(&self) -> u64;

    /// Read a register by name.
    fn read_register(&mut self, name: &str) -> VivResult<u64>;

    /// Write a register by name.
    fn write_register(&mut self, name: &str, value: u64) -> VivResult<()>;

    /// Read memory bytes.
    fn read_memory(&mut self, addr: u64, size: usize) -> VivResult<Vec<u8>>;

    /// Write memory bytes.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> VivResult<()>;

    /// Map memory region.
    fn map_memory(&mut self, addr: u64, size: usize, perms: MemoryPermissions) -> VivResult<()>;

    /// Unmap memory region.
    fn unmap_memory(&mut self, addr: u64, size: usize) -> VivResult<()>;

    /// Execute a single instruction.
    fn step(&mut self) -> VivResult<StopReason>;

    /// Execute until reaching target address or step limit.
    fn run_to(&mut self, target_pc: u64, max_steps: u64) -> VivResult<(u64, StopReason)>;

    /// Run until a stop condition is met.
    fn run(&mut self, max_steps: u64) -> VivResult<(u64, StopReason)>;

    /// Add a breakpoint at address.
    fn add_breakpoint(&mut self, addr: u64) -> bool;

    /// Remove a breakpoint at address.
    fn remove_breakpoint(&mut self, addr: u64) -> bool;

    /// Check if address has a breakpoint.
    fn is_breakpoint(&self, addr: u64) -> bool;

    /// Get all breakpoints.
    fn get_breakpoints(&self) -> Vec<u64>;

    /// Clear all breakpoints.
    fn clear_breakpoints(&mut self);

    /// Push a value onto the stack.
    fn push(&mut self, value: u64) -> VivResult<()>;

    /// Pop a value from the stack.
    fn pop(&mut self) -> VivResult<u64>;

    /// Reset the emulator state.
    fn reset(&mut self);

    /// Get disassembly for an address (if available).
    fn get_disasm(&self, addr: u64) -> Option<String>;

    /// Create a full snapshot of emulator state (CPU + memory).
    ///
    /// This is equivalent to Python vivisect's `emu.getEmuSnap()`.
    /// The returned `Box<dyn Any>` contains the backend-specific snapshot type.
    /// Use `restore_snapshot` to restore from a snapshot created by this method.
    fn create_snapshot(&mut self) -> Box<dyn Any>;

    /// Restore emulator state from a full snapshot.
    ///
    /// This is equivalent to Python vivisect's `emu.setEmuSnap()`.
    /// The snapshot must have been created by `create_snapshot` on the same
    /// emulator backend.
    fn restore_snapshot(&mut self, snapshot: &dyn Any);
}

/// Memory permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPermissions {
    /// Memory is readable.
    pub read: bool,
    /// Memory is writable.
    pub write: bool,
    /// Memory is executable.
    pub exec: bool,
}

impl MemoryPermissions {
    /// No permissions.
    pub const NONE: Self = Self { read: false, write: false, exec: false };
    /// Read-only.
    pub const READ: Self = Self { read: true, write: false, exec: false };
    /// Read-write.
    pub const READ_WRITE: Self = Self { read: true, write: true, exec: false };
    /// Read-execute.
    pub const READ_EXEC: Self = Self { read: true, write: false, exec: true };
    /// Read-write-execute.
    pub const ALL: Self = Self { read: true, write: true, exec: true };

    /// Create from Unix permission bits (rwx).
    pub fn from_unix(perms: u8) -> Self {
        Self {
            read: perms & 4 != 0,
            write: perms & 2 != 0,
            exec: perms & 1 != 0,
        }
    }

    /// Convert to Unix permission bits.
    pub fn to_unix(&self) -> u8 {
        let mut p = 0;
        if self.read { p |= 4; }
        if self.write { p |= 2; }
        if self.exec { p |= 1; }
        p
    }
}

impl Default for MemoryPermissions {
    fn default() -> Self {
        Self::NONE
    }
}

/// Create an emulator for the given architecture.
#[cfg(feature = "icicle")]
pub fn create_emulator(arch: Architecture) -> VivResult<Box<dyn CpuEmulator>> {
    tracing::debug!("[viv-emu] create_emulator: arch={:?}", arch);
    let emu = IcicleEmulator::new(arch)?;
    Ok(Box::new(emu))
}

/// Create an emulator for the given architecture (stub when icicle is not enabled).
#[cfg(not(feature = "icicle"))]
pub fn create_emulator(_arch: Architecture) -> VivResult<Box<dyn CpuEmulator>> {
    Err(VivError::Other {
        message: "No emulation backend available. Enable 'icicle' feature.".into(),
    })
}
