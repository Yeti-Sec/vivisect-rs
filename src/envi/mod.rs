//! Envi - Architecture abstraction layer.
//!
//! This module provides architecture-independent representations
//! for opcodes, operands, memory, and registers.

pub mod archs;
pub mod memory;
pub mod opcode;
pub mod operand;

pub use archs::*;
pub use opcode::*;
pub use operand::*;

use crate::constants::{Architecture, Endian};
use crate::error::VivResult;

/// Architecture module interface.
pub trait ArchitectureModule: Send + Sync {
    /// Get the architecture ID.
    fn arch_id(&self) -> Architecture;

    /// Get the architecture name.
    fn arch_name(&self) -> &str;

    /// Get the maximum instruction size.
    fn max_instruction_size(&self) -> usize;

    /// Get the pointer size in bytes.
    fn pointer_size(&self) -> usize;

    /// Get the endianness.
    fn endian(&self) -> Endian;

    /// Get the breakpoint instruction bytes.
    fn break_instruction(&self) -> Option<&[u8]>;

    /// Get the NOP instruction bytes.
    fn nop_instruction(&self) -> Option<&[u8]>;

    /// Parse an opcode from bytes.
    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode>;

    /// Get an emulator for this architecture.
    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>>;

    /// Get default calling convention name.
    fn default_calling_convention(&self) -> Option<&str>;

    /// Get pointer alignment.
    fn pointer_alignment(&self) -> usize {
        1
    }
}
