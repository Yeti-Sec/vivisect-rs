//! Architecture-specific implementations.
//!
//! This module contains disassemblers and emulators for specific CPU architectures.

pub mod arm;
pub mod m68k;
pub mod mips;
pub mod ppc;
pub mod riscv;
pub mod sparc;
pub mod superh;
pub mod x86;

// Re-export main types
pub use arm::{ArmDisassembler, ArmMode};
pub use m68k::M68kDisassembler;
pub use mips::{MipsDisassembler, MipsMode};
pub use ppc::{PpcDisassembler, PpcMode};
pub use riscv::{RiscvDisassembler, RiscvMode};
pub use sparc::{SparcDisassembler, SparcMode};
pub use superh::{SuperHDisassembler, SuperHMode};
pub use x86::{X86Disassembler, X86Mode};

/// Helper: disassemble one instruction via capstone into a vivisect Opcode.
pub(crate) fn capstone_disasm(
    cs: &capstone::Capstone,
    bytes: &[u8],
    va: u64,
) -> crate::error::VivResult<crate::envi::Opcode> {
    use crate::envi::opcode::OpcodeBuilder;
    use crate::error::VivError;

    let insns = cs.disasm_count(bytes, va, 1).map_err(|e| VivError::Other {
        message: format!("disasm at {va:#x}: {e}"),
    })?;

    let insn = insns.iter().next().ok_or_else(|| VivError::Other {
        message: format!("no instruction at {va:#x}"),
    })?;

    let mnem = insn.mnemonic().unwrap_or("???");
    let size = insn.len() as u8;

    Ok(OpcodeBuilder::new(va, mnem, size)
        .bytes(insn.bytes().to_vec())
        .build())
}
