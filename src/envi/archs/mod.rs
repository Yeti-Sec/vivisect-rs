//! Architecture-specific implementations.
//!
//! This module contains disassemblers and emulators for specific CPU architectures.

pub mod x86;
pub mod arm;
pub mod mips;
pub mod ppc;
pub mod sparc;
pub mod riscv;
pub mod m68k;
pub mod superh;

// Re-export main types
pub use x86::{X86Disassembler, X86Mode};
pub use arm::{ArmDisassembler, ArmMode};
pub use mips::{MipsDisassembler, MipsMode};
pub use ppc::{PpcDisassembler, PpcMode};
pub use sparc::{SparcDisassembler, SparcMode};
pub use riscv::{RiscvDisassembler, RiscvMode};
pub use m68k::M68kDisassembler;
pub use superh::{SuperHDisassembler, SuperHMode};

/// Helper: disassemble one instruction via capstone into a vivisect Opcode.
pub(crate) fn capstone_disasm(
    cs: &capstone::Capstone,
    bytes: &[u8],
    va: u64,
) -> crate::error::VivResult<crate::envi::Opcode> {
    use crate::envi::opcode::OpcodeBuilder;
    use crate::error::VivError;

    let insns = cs.disasm_count(bytes, va, 1)
        .map_err(|e| VivError::Other { message: format!("disasm at {va:#x}: {e}") })?;

    let insn = insns.iter().next()
        .ok_or_else(|| VivError::Other { message: format!("no instruction at {va:#x}") })?;

    let mnem = insn.mnemonic().unwrap_or("???");
    let size = insn.len() as u8;

    Ok(OpcodeBuilder::new(va, mnem, size)
        .bytes(insn.bytes().to_vec())
        .build())
}
