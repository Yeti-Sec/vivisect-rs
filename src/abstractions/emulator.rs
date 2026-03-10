//! Emulator abstraction trait.
//!
//! Defines the interface for CPU emulation backends.

use crate::abstractions::{MemoryAccess, MemoryMap, MemorySnapshot, RegisterContext, RegisterSnapshot};
use crate::error::{VivError, VivResult};
use std::collections::HashSet;

/// Complete emulator state snapshot.
#[derive(Clone, Debug)]
pub struct EmulatorSnapshot {
    pub pc: u64,
    pub sp: u64,
    pub registers: RegisterSnapshot,
    pub memory: MemorySnapshot,
}

/// Emulator execution result.
#[derive(Debug, Clone)]
pub enum EmulatorStopReason {
    /// Normal completion (reached target).
    ReachedTarget,
    /// Hit a breakpoint.
    Breakpoint(u64),
    /// Execution limit reached.
    StepLimit(usize),
    /// Invalid instruction.
    InvalidInstruction(u64),
    /// Memory access violation.
    MemoryFault(u64),
    /// Syscall/interrupt.
    Syscall(u64),
    /// Program returned/exited.
    Returned,
}

/// Trait for CPU emulation.
pub trait Emulator: MemoryAccess + MemoryMap + RegisterContext + Send {
    /// Get current program counter.
    fn get_pc(&self) -> u64 {
        self.get_program_counter()
    }

    /// Set program counter.
    fn set_pc(&mut self, pc: u64) -> VivResult<()> {
        self.set_program_counter(pc)
    }

    /// Get current stack pointer.
    fn get_sp(&self) -> u64 {
        self.get_stack_pointer()
    }

    /// Set stack pointer.
    fn set_sp(&mut self, sp: u64) -> VivResult<()> {
        self.set_stack_pointer(sp)
    }

    /// Execute a single instruction.
    fn step(&mut self) -> VivResult<()>;

    /// Execute until reaching target address or limit.
    fn run_to(&mut self, target_pc: u64, max_steps: usize) -> VivResult<(usize, EmulatorStopReason)> {
        let mut steps = 0;
        while self.get_pc() != target_pc && steps < max_steps {
            if self.is_breakpoint(self.get_pc()) && steps > 0 {
                return Ok((steps, EmulatorStopReason::Breakpoint(self.get_pc())));
            }
            self.step()?;
            steps += 1;
        }

        if steps >= max_steps {
            Ok((steps, EmulatorStopReason::StepLimit(max_steps)))
        } else {
            Ok((steps, EmulatorStopReason::ReachedTarget))
        }
    }

    /// Run until a stop condition is met.
    fn run(&mut self, max_steps: usize) -> VivResult<(usize, EmulatorStopReason)> {
        let mut steps = 0;
        while steps < max_steps {
            let pc = self.get_pc();
            if self.is_breakpoint(pc) && steps > 0 {
                return Ok((steps, EmulatorStopReason::Breakpoint(pc)));
            }
            match self.step() {
                Ok(_) => {}
                Err(VivError::InvalidInstruction { address }) => {
                    return Ok((steps, EmulatorStopReason::InvalidInstruction(address)));
                }
                Err(VivError::InvalidMemory { address }) => {
                    return Ok((steps, EmulatorStopReason::MemoryFault(address)));
                }
                Err(e) => return Err(e),
            }
            steps += 1;
        }
        Ok((steps, EmulatorStopReason::StepLimit(max_steps)))
    }

    /// Take a complete snapshot of emulator state.
    fn snapshot_state(&self) -> EmulatorSnapshot {
        EmulatorSnapshot {
            pc: self.get_pc(),
            sp: self.get_sp(),
            registers: RegisterContext::snapshot(self),
            memory: self.snapshot_memory(),
        }
    }

    /// Restore from a complete snapshot.
    fn restore_state(&mut self, snapshot: &EmulatorSnapshot) -> VivResult<()> {
        self.set_pc(snapshot.pc)?;
        self.set_sp(snapshot.sp)?;
        RegisterContext::restore(self, &snapshot.registers)?;
        self.restore_memory(&snapshot.memory)?;
        Ok(())
    }

    /// Add a breakpoint at address.
    fn add_breakpoint(&mut self, address: u64);

    /// Remove a breakpoint at address.
    fn remove_breakpoint(&mut self, address: u64);

    /// Check if address is a breakpoint.
    fn is_breakpoint(&self, address: u64) -> bool;

    /// Get all breakpoints.
    fn get_breakpoints(&self) -> Vec<u64>;

    /// Clear all breakpoints.
    fn clear_breakpoints(&mut self);

    /// Get the architecture name.
    fn architecture(&self) -> &str;

    /// Get pointer size in bytes.
    fn pointer_size(&self) -> usize;

    /// Push a value onto the stack.
    fn push(&mut self, value: u64) -> VivResult<()> {
        let psize = self.pointer_size();
        let sp = self.get_sp() - psize as u64;
        self.set_sp(sp)?;
        match psize {
            4 => self.write_u32_le(sp, value as u32),
            8 => self.write_u64_le(sp, value),
            _ => Err(VivError::Other {
                message: "Unsupported pointer size".into(),
            }),
        }
    }

    /// Pop a value from the stack.
    fn pop(&mut self) -> VivResult<u64> {
        let psize = self.pointer_size();
        let sp = self.get_sp();
        let value = match psize {
            4 => self.read_u32_le(sp)? as u64,
            8 => self.read_u64_le(sp)?,
            _ => {
                return Err(VivError::Other {
                    message: "Unsupported pointer size".into(),
                })
            }
        };
        self.set_sp(sp + psize as u64)?;
        Ok(value)
    }
}

/// A basic emulator implementation that can be extended.
pub struct BasicEmulator {
    breakpoints: HashSet<u64>,
}

impl BasicEmulator {
    pub fn new() -> Self {
        Self {
            breakpoints: HashSet::new(),
        }
    }
}

impl Default for BasicEmulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Mixin trait for breakpoint management.
pub trait BreakpointManager {
    fn breakpoints(&self) -> &HashSet<u64>;
    fn breakpoints_mut(&mut self) -> &mut HashSet<u64>;

    fn add_bp(&mut self, address: u64) {
        self.breakpoints_mut().insert(address);
    }

    fn remove_bp(&mut self, address: u64) {
        self.breakpoints_mut().remove(&address);
    }

    fn is_bp(&self, address: u64) -> bool {
        self.breakpoints().contains(&address)
    }

    fn get_bps(&self) -> Vec<u64> {
        self.breakpoints().iter().copied().collect()
    }

    fn clear_bps(&mut self) {
        self.breakpoints_mut().clear();
    }
}
