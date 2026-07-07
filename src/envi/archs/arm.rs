//! ARM architecture support using Capstone.
//!
//! Provides disassembly for ARM (32-bit) and ARM64 (AArch64) architectures.

use crate::constants::{Architecture, BranchFlags, Endian, InstructionFlags};
use crate::envi::operand::{ImmediateOperand, Operand, RegisterOperand};
use crate::envi::{ArchitectureModule, Opcode, OpcodeBuilder};
use crate::error::{VivError, VivResult};
use capstone::prelude::*;
use capstone::{Capstone, Insn};
use std::sync::Mutex;

/// ARM operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmMode {
    /// ARM 32-bit mode.
    Arm32,
    /// ARM 64-bit (AArch64) mode.
    Arm64,
    /// Thumb 16/32-bit mode.
    Thumb,
}

impl ArmMode {
    /// Get pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        match self {
            ArmMode::Arm32 | ArmMode::Thumb => 4,
            ArmMode::Arm64 => 8,
        }
    }
}

/// ARM disassembler.
///
/// Uses a Mutex to make the Capstone instance thread-safe.
pub struct ArmDisassembler {
    cs: Mutex<Capstone>,
    mode: ArmMode,
}

// Safety: The Mutex provides the synchronization needed for Send + Sync
unsafe impl Send for ArmDisassembler {}
unsafe impl Sync for ArmDisassembler {}

impl ArmDisassembler {
    /// Create a new ARM disassembler.
    #[must_use]
    pub fn new(mode: ArmMode) -> VivResult<Self> {
        let cs = match mode {
            ArmMode::Arm32 => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| VivError::Other {
                    message: format!("Failed to create ARM32 disassembler: {}", e),
                })?,
            ArmMode::Thumb => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .detail(true)
                .build()
                .map_err(|e| VivError::Other {
                    message: format!("Failed to create Thumb disassembler: {}", e),
                })?,
            ArmMode::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .map_err(|e| VivError::Other {
                    message: format!("Failed to create ARM64 disassembler: {}", e),
                })?,
        };

        Ok(Self { cs: Mutex::new(cs), mode })
    }

    /// Create a 32-bit ARM disassembler.
    #[must_use]
    pub fn new_arm32() -> VivResult<Self> {
        Self::new(ArmMode::Arm32)
    }

    /// Create a 64-bit ARM disassembler.
    #[must_use]
    pub fn new_arm64() -> VivResult<Self> {
        Self::new(ArmMode::Arm64)
    }

    /// Create a Thumb mode disassembler.
    #[must_use]
    pub fn new_thumb() -> VivResult<Self> {
        Self::new(ArmMode::Thumb)
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
                let is_branch = op.is_branch() && !op.falls_through();
                opcodes.push(op);
                offset += insn.len();

                // Stop at unconditional control flow
                if is_ret || is_branch {
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
            // Branch instructions
            "b" | "bx" | "bxj" => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::NO_FALL;
            }
            // Conditional branches (Bcc)
            m if m.starts_with("b") && m.len() > 1 && !m.starts_with("bic") && !m.starts_with("bfc") => {
                // Most B<cond> are conditional branches
                if !m.starts_with("bl") {
                    iflags |= InstructionFlags::BRANCH | InstructionFlags::COND;
                }
            }
            // Call instructions
            "bl" | "blx" => {
                iflags |= InstructionFlags::CALL | InstructionFlags::BRANCH;
            }
            // Return instructions
            "ret" => {
                iflags |= InstructionFlags::RET | InstructionFlags::NO_FALL;
            }
            // Pop can be a return if it loads PC
            "pop" | "ldm" | "ldmia" | "ldmib" | "ldmda" | "ldmdb" => {
                // Check if PC is in the register list (makes it a return)
                let op_str = insn.op_str().unwrap_or("");
                if op_str.contains("pc") || op_str.contains("r15") {
                    iflags |= InstructionFlags::RET | InstructionFlags::NO_FALL;
                }
            }
            // MOV PC, LR is effectively a return
            "mov" => {
                let op_str = insn.op_str().unwrap_or("");
                if op_str.starts_with("pc,") && op_str.contains("lr") {
                    iflags |= InstructionFlags::RET | InstructionFlags::NO_FALL;
                }
            }
            // Compare and branch (ARM64)
            "cbz" | "cbnz" | "tbz" | "tbnz" => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::COND;
            }
            _ => {}
        }

        // Build operands (simplified - just extract from op_str for now)
        let mut operands: Vec<Box<dyn Operand>> = Vec::new();

        // Parse operand string
        if let Some(op_str) = insn.op_str() {
            for part in op_str.split(',') {
                let part = part.trim();
                if part.starts_with('#') {
                    // Immediate value
                    let val_str = part.trim_start_matches('#').trim_start_matches("0x");
                    if let Ok(val) = u64::from_str_radix(val_str, 16) {
                        operands.push(Box::new(ImmediateOperand::new(val, 4)));
                    } else if let Ok(val) = val_str.parse::<i64>() {
                        operands.push(Box::new(ImmediateOperand::new(val as u64, 4)));
                    }
                } else if part.starts_with('r') || part.starts_with('x') || part.starts_with('w')
                    || part.starts_with('s') || part.starts_with('d') || part.starts_with('q')
                    || part == "sp" || part == "lr" || part == "pc" || part == "fp" {
                    // Register
                    let reg_num = if part == "sp" || part == "r13" {
                        13
                    } else if part == "lr" || part == "r14" {
                        14
                    } else if part == "pc" || part == "r15" {
                        15
                    } else if part == "fp" || part == "r11" {
                        11
                    } else if let Some(num_str) = part.strip_prefix('r')
                        .or_else(|| part.strip_prefix('x'))
                        .or_else(|| part.strip_prefix('w'))
                    {
                        num_str.parse().unwrap_or(0)
                    } else {
                        0
                    };

                    let size = match self.mode {
                        ArmMode::Arm64 => 8,
                        _ => 4,
                    };
                    operands.push(Box::new(RegisterOperand::new(reg_num, part.to_string(), size)));
                }
            }
        }

        let mut builder = OpcodeBuilder::new(insn.address(), &mnem, insn.len() as u8)
            .opcode(insn.id().0 as u32)
            .flags(iflags)
            .bytes(bytes[..insn.len()].to_vec());

        for oper in operands {
            builder = builder.operand(oper);
        }

        Ok(builder.build())
    }

    /// Get the mode.
    pub fn mode(&self) -> ArmMode {
        self.mode
    }
}

impl ArchitectureModule for ArmDisassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode {
            ArmMode::Arm32 => Architecture::ArmV7,
            ArmMode::Thumb => Architecture::Thumb,
            ArmMode::Arm64 => Architecture::A64,
        }
    }

    fn arch_name(&self) -> &str {
        match self.mode {
            ArmMode::Arm32 => "arm",
            ArmMode::Thumb => "thumb",
            ArmMode::Arm64 => "aarch64",
        }
    }

    fn max_instruction_size(&self) -> usize {
        match self.mode {
            ArmMode::Arm32 => 4,
            ArmMode::Thumb => 4, // Thumb-2 can be 4 bytes
            ArmMode::Arm64 => 4,
        }
    }

    fn pointer_size(&self) -> usize {
        self.mode.pointer_size()
    }

    fn endian(&self) -> Endian {
        Endian::Little // ARM is typically little-endian (can be big)
    }

    fn break_instruction(&self) -> Option<&[u8]> {
        match self.mode {
            ArmMode::Arm32 => Some(&[0x01, 0x00, 0x9f, 0xef]), // BKPT #1
            ArmMode::Thumb => Some(&[0x01, 0xBE]), // BKPT #1
            ArmMode::Arm64 => Some(&[0x00, 0x00, 0x20, 0xd4]), // BRK #0
        }
    }

    fn nop_instruction(&self) -> Option<&[u8]> {
        match self.mode {
            ArmMode::Arm32 => Some(&[0x00, 0xf0, 0x20, 0xe3]), // NOP
            ArmMode::Thumb => Some(&[0x00, 0xbf]), // NOP
            ArmMode::Arm64 => Some(&[0x1f, 0x20, 0x03, 0xd5]), // NOP
        }
    }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        self.disassemble(&bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "ARM emulator: use CpuEmulator trait via vivutils-rs".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        match self.mode {
            ArmMode::Arm32 | ArmMode::Thumb => Some("aapcs"),
            ArmMode::Arm64 => Some("aapcs64"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm32_disassembly() {
        let disasm = ArmDisassembler::new_arm32().unwrap();

        // mov r0, #0
        let code = [0x00, 0x00, 0xa0, 0xe3];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.mnem, "mov");
        assert_eq!(op.size, 4);

        // bx lr (return)
        let code = [0x1e, 0xff, 0x2f, 0xe1];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.mnem, "bx");
        assert!(op.is_branch());
    }

    #[test]
    fn test_arm64_disassembly() {
        let disasm = ArmDisassembler::new_arm64().unwrap();

        // mov x0, #0
        let code = [0x00, 0x00, 0x80, 0xd2];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.mnem, "mov");
        assert_eq!(op.size, 4);

        // ret
        let code = [0xc0, 0x03, 0x5f, 0xd6];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.mnem, "ret");
        assert!(op.is_return());
    }

    #[test]
    fn test_thumb_disassembly() {
        let disasm = ArmDisassembler::new_thumb().unwrap();

        // movs r0, #0
        let code = [0x00, 0x20];
        let op = disasm.disassemble(&code, 0x1000).unwrap();
        assert_eq!(op.mnem, "movs");
        assert_eq!(op.size, 2);
    }
}
