//! MIPS architecture support using Capstone.
//!
//! Provides disassembly for MIPS32 and MIPS64 architectures.

use crate::constants::{Architecture, BranchFlags, Endian, InstructionFlags};
use crate::envi::operand::{ImmediateOperand, Operand, RegisterOperand};
use crate::envi::{ArchitectureModule, Opcode, OpcodeBuilder};
use crate::error::{VivError, VivResult};
use capstone::prelude::*;
use capstone::{Capstone, Insn};
use std::sync::Mutex;

/// MIPS operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MipsMode {
    /// MIPS 32-bit mode.
    Mips32,
    /// MIPS 64-bit mode.
    Mips64,
    /// MIPS 32-bit little endian.
    Mips32Le,
    /// MIPS 64-bit little endian.
    Mips64Le,
}

impl MipsMode {
    /// Get pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        match self {
            MipsMode::Mips32 | MipsMode::Mips32Le => 4,
            MipsMode::Mips64 | MipsMode::Mips64Le => 8,
        }
    }

    /// Check if big endian.
    pub fn is_big_endian(&self) -> bool {
        matches!(self, MipsMode::Mips32 | MipsMode::Mips64)
    }
}

/// MIPS disassembler.
///
/// Uses a Mutex to make the Capstone instance thread-safe.
pub struct MipsDisassembler {
    cs: Mutex<Capstone>,
    mode: MipsMode,
}

// Safety: The Mutex provides the synchronization needed for Send + Sync
unsafe impl Send for MipsDisassembler {}
unsafe impl Sync for MipsDisassembler {}

impl MipsDisassembler {
    /// Create a new MIPS disassembler.
    #[must_use]
    pub fn new(mode: MipsMode) -> VivResult<Self> {
        let (cs_mode, endian) = match mode {
            MipsMode::Mips32 => (arch::mips::ArchMode::Mips32, arch::mips::ArchMode::Mips32),
            MipsMode::Mips64 => (arch::mips::ArchMode::Mips64, arch::mips::ArchMode::Mips64),
            MipsMode::Mips32Le => (arch::mips::ArchMode::Mips32, arch::mips::ArchMode::Mips32),
            MipsMode::Mips64Le => (arch::mips::ArchMode::Mips64, arch::mips::ArchMode::Mips64),
        };

        let mut builder = Capstone::new().mips().mode(cs_mode);

        // Set endianness
        if !mode.is_big_endian() {
            builder = builder.endian(capstone::Endian::Little);
        } else {
            builder = builder.endian(capstone::Endian::Big);
        }

        let cs = builder.detail(true).build().map_err(|e| VivError::Other {
            message: format!("Failed to create MIPS disassembler: {}", e),
        })?;

        Ok(Self { cs: Mutex::new(cs), mode })
    }

    /// Create a 32-bit MIPS disassembler (big endian).
    #[must_use]
    pub fn new_mips32() -> VivResult<Self> {
        Self::new(MipsMode::Mips32)
    }

    /// Create a 64-bit MIPS disassembler (big endian).
    #[must_use]
    pub fn new_mips64() -> VivResult<Self> {
        Self::new(MipsMode::Mips64)
    }

    /// Disassemble a single instruction.
    #[must_use]
    pub fn disassemble(&self, bytes: &[u8], va: u64) -> VivResult<Opcode> {
        let cs = self.cs.lock().map_err(|_| VivError::Other {
            message: "Failed to lock disassembler".into(),
        })?;

        let insns = cs.disasm_count(bytes, va, 1).map_err(|_| {
            VivError::InvalidInstruction { address: va }
        })?;

        if insns.is_empty() {
            return Err(VivError::InvalidInstruction { address: va });
        }

        let insn = &insns[0];
        self.instruction_to_opcode(insn, bytes)
    }

    /// Disassemble multiple instructions.
    pub fn disassemble_block(&self, bytes: &[u8], va: u64, max_count: usize) -> Vec<Opcode> {
        let cs = match self.cs.lock() {
            Ok(cs) => cs,
            Err(_) => return Vec::new(),
        };

        let insns = match cs.disasm_count(bytes, va, max_count) {
            Ok(i) => i,
            Err(_) => return Vec::new(),
        };

        let mut opcodes = Vec::new();
        let mut offset = 0usize;

        for insn in insns.iter() {
            let instr_bytes = &bytes[offset..offset + insn.len()];
            if let Ok(op) = self.instruction_to_opcode(insn, instr_bytes) {
                let is_ret = op.is_return();
                opcodes.push(op);
                offset += insn.len();

                if is_ret {
                    break;
                }
            } else {
                break;
            }
        }

        opcodes
    }

    /// Convert Capstone instruction to vivisect Opcode.
    fn instruction_to_opcode(&self, insn: &Insn, bytes: &[u8]) -> VivResult<Opcode> {
        let mnem = insn.mnemonic().unwrap_or("???").to_lowercase();
        let mut iflags = InstructionFlags::empty();

        // Determine instruction flags based on mnemonic
        match mnem.as_str() {
            // Unconditional branches
            "j" | "b" => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::NO_FALL;
            }
            // Calls
            "jal" | "jalr" | "bal" => {
                iflags |= InstructionFlags::CALL | InstructionFlags::BRANCH;
            }
            // Conditional branches
            "beq" | "bne" | "blez" | "bgtz" | "bltz" | "bgez" | "beqz" | "bnez" => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::COND;
            }
            // Returns
            "jr" => {
                // jr $ra is a return
                let op_str = insn.op_str().unwrap_or("");
                if op_str.contains("$ra") || op_str.contains("$31") {
                    iflags |= InstructionFlags::RET | InstructionFlags::NO_FALL;
                } else {
                    iflags |= InstructionFlags::BRANCH | InstructionFlags::NO_FALL;
                }
            }
            _ => {}
        }

        let builder = OpcodeBuilder::new(insn.address(), &mnem, insn.len() as u8)
            .opcode(insn.id().0 as u32)
            .flags(iflags)
            .bytes(bytes[..insn.len()].to_vec());

        Ok(builder.build())
    }

    /// Get the mode.
    pub fn mode(&self) -> MipsMode {
        self.mode
    }
}

impl ArchitectureModule for MipsDisassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode {
            MipsMode::Mips32 | MipsMode::Mips32Le => Architecture::Mips32,
            MipsMode::Mips64 | MipsMode::Mips64Le => Architecture::Mips64,
        }
    }

    fn arch_name(&self) -> &str {
        match self.mode {
            MipsMode::Mips32 | MipsMode::Mips32Le => "mips32",
            MipsMode::Mips64 | MipsMode::Mips64Le => "mips64",
        }
    }

    fn max_instruction_size(&self) -> usize {
        4 // MIPS instructions are always 4 bytes
    }

    fn pointer_size(&self) -> usize {
        self.mode.pointer_size()
    }

    fn endian(&self) -> Endian {
        if self.mode.is_big_endian() {
            Endian::Big
        } else {
            Endian::Little
        }
    }

    fn break_instruction(&self) -> Option<&[u8]> {
        if self.mode.is_big_endian() {
            Some(&[0x00, 0x00, 0x00, 0x0d]) // break
        } else {
            Some(&[0x0d, 0x00, 0x00, 0x00]) // break (LE)
        }
    }

    fn nop_instruction(&self) -> Option<&[u8]> {
        if self.mode.is_big_endian() {
            Some(&[0x00, 0x00, 0x00, 0x00]) // nop (sll $zero, $zero, 0)
        } else {
            Some(&[0x00, 0x00, 0x00, 0x00]) // nop
        }
    }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        self.disassemble(&bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "MIPS emulator: use CpuEmulator trait via vivutils-rs".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        match self.mode {
            MipsMode::Mips32 | MipsMode::Mips32Le => Some("o32"),
            MipsMode::Mips64 | MipsMode::Mips64Le => Some("n64"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mips32_disassembly() {
        let disasm = MipsDisassembler::new(MipsMode::Mips32Le).unwrap();

        // addiu $sp, $sp, -8
        let code = [0xf8, 0xff, 0xbd, 0x27];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.size, 4);
    }
}
