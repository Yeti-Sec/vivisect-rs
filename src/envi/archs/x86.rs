//! x86/x64 architecture support using iced-x86.
//!
//! Provides disassembly for Intel 32-bit (i386) and 64-bit (amd64) architectures.

use crate::constants::{Architecture, BranchFlags, Endian, InstructionFlags};
use crate::envi::operand::{DerefOperand, ImmediateOperand, Operand, PcRelativeOperand, RegisterOperand};
use crate::envi::{ArchitectureModule, Opcode, OpcodeBuilder};
use crate::error::{VivError, VivResult};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, OpKind, Register};

/// x86 operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Mode {
    /// 32-bit protected mode.
    Mode32,
    /// 64-bit long mode.
    Mode64,
}

impl X86Mode {
    /// Get the bitness for iced-x86.
    pub fn bitness(&self) -> u32 {
        match self {
            X86Mode::Mode32 => 32,
            X86Mode::Mode64 => 64,
        }
    }

    /// Get pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        match self {
            X86Mode::Mode32 => 4,
            X86Mode::Mode64 => 8,
        }
    }
}

/// x86/x64 disassembler.
///
/// Note: This struct is Send + Sync. The formatter is created on-demand
/// when needed for string formatting.
#[derive(Debug, Clone, Copy)]
pub struct X86Disassembler {
    mode: X86Mode,
}

impl X86Disassembler {
    /// Create a new x86 disassembler.
    pub fn new(mode: X86Mode) -> Self {
        Self { mode }
    }

    /// Create a 32-bit disassembler.
    pub fn new_32() -> Self {
        Self::new(X86Mode::Mode32)
    }

    /// Create a 64-bit disassembler.
    pub fn new_64() -> Self {
        Self::new(X86Mode::Mode64)
    }

    /// Create a formatter for string output.
    fn create_formatter() -> IntelFormatter {
        IntelFormatter::new()
    }

    /// Disassemble a single instruction.
    #[must_use]
    pub fn disassemble(&self, bytes: &[u8], va: u64) -> VivResult<Opcode> {
        let mut decoder = Decoder::with_ip(self.mode.bitness(), bytes, va, DecoderOptions::NONE);

        if !decoder.can_decode() {
            return Err(VivError::InvalidInstruction { address: va });
        }

        let instr = decoder.decode();

        if instr.is_invalid() {
            return Err(VivError::InvalidInstruction { address: va });
        }

        self.instruction_to_opcode(&instr, bytes)
    }

    /// Disassemble multiple instructions.
    pub fn disassemble_block(&self, bytes: &[u8], va: u64, max_count: usize) -> Vec<Opcode> {
        let mut decoder = Decoder::with_ip(self.mode.bitness(), bytes, va, DecoderOptions::NONE);
        let mut opcodes = Vec::new();
        let mut count = 0;

        while decoder.can_decode() && count < max_count {
            let instr = decoder.decode();
            if instr.is_invalid() {
                break;
            }

            let instr_bytes = &bytes[decoder.position() - instr.len()..decoder.position()];
            if let Ok(op) = self.instruction_to_opcode(&instr, instr_bytes) {
                opcodes.push(op);
            } else {
                break;
            }

            count += 1;

            // Stop at control flow instructions
            if instr.flow_control() != iced_x86::FlowControl::Next {
                break;
            }
        }

        opcodes
    }

    /// Convert iced-x86 instruction to vivisect Opcode.
    fn instruction_to_opcode(&self, instr: &Instruction, bytes: &[u8]) -> VivResult<Opcode> {
        // Get mnemonic
        let mut formatter = Self::create_formatter();
        let mut mnem_output = String::new();
        formatter.format_mnemonic(instr, &mut mnem_output);
        let mnem = mnem_output.trim().to_lowercase();

        // Determine instruction flags
        let mut iflags = InstructionFlags::empty();

        match instr.flow_control() {
            iced_x86::FlowControl::Next => {}
            iced_x86::FlowControl::UnconditionalBranch => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::NO_FALL;
            }
            iced_x86::FlowControl::ConditionalBranch => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::COND;
            }
            iced_x86::FlowControl::Call => {
                iflags |= InstructionFlags::CALL | InstructionFlags::BRANCH;
            }
            iced_x86::FlowControl::Return => {
                iflags |= InstructionFlags::RET | InstructionFlags::NO_FALL;
            }
            iced_x86::FlowControl::IndirectBranch => {
                iflags |= InstructionFlags::BRANCH | InstructionFlags::NO_FALL;
            }
            iced_x86::FlowControl::IndirectCall => {
                iflags |= InstructionFlags::CALL | InstructionFlags::BRANCH;
            }
            iced_x86::FlowControl::Interrupt => {
                // Interrupt instructions
            }
            iced_x86::FlowControl::XbeginXabortXend => {}
            iced_x86::FlowControl::Exception => {
                iflags |= InstructionFlags::NO_FALL;
            }
        }

        // Convert operands
        let mut operands: Vec<Box<dyn Operand>> = Vec::new();

        for i in 0..instr.op_count() {
            if let Some(oper) = self.convert_operand(instr, i as u32) {
                operands.push(oper);
            }
        }

        let op = OpcodeBuilder::new(instr.ip(), &mnem, instr.len() as u8)
            .opcode(instr.code() as u32)
            .flags(iflags)
            .bytes(bytes[..instr.len()].to_vec());

        // Add operands
        let mut builder = op;
        for oper in operands {
            builder = builder.operand(oper);
        }

        Ok(builder.build())
    }

    /// Convert iced-x86 operand to vivisect Operand.
    fn convert_operand(&self, instr: &Instruction, op_idx: u32) -> Option<Box<dyn Operand>> {
        let op_kind = instr.op_kind(op_idx);

        match op_kind {
            OpKind::Register => {
                let reg = instr.op_register(op_idx);
                Some(Box::new(RegisterOperand::new(
                    reg as usize,
                    format!("{:?}", reg).to_lowercase(),
                    register_size(reg),
                )))
            }
            OpKind::Immediate8 | OpKind::Immediate8_2nd => {
                Some(Box::new(ImmediateOperand::new(instr.immediate8() as u64, 1)))
            }
            OpKind::Immediate16 => {
                Some(Box::new(ImmediateOperand::new(instr.immediate16() as u64, 2)))
            }
            OpKind::Immediate32 => {
                Some(Box::new(ImmediateOperand::new(instr.immediate32() as u64, 4)))
            }
            OpKind::Immediate64 => {
                Some(Box::new(ImmediateOperand::new(instr.immediate64(), 8)))
            }
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                Some(Box::new(ImmediateOperand::signed(
                    instr.immediate8to64() as i64,
                    self.mode.pointer_size(),
                )))
            }
            OpKind::Immediate32to64 => {
                Some(Box::new(ImmediateOperand::signed(
                    instr.immediate32to64() as i64,
                    8,
                )))
            }
            OpKind::NearBranch16 => {
                let target = instr.near_branch16() as u64;
                let offset = target as i64 - (instr.ip() + instr.len() as u64) as i64;
                Some(Box::new(PcRelativeOperand::new(offset, 2)))
            }
            OpKind::NearBranch32 => {
                let target = instr.near_branch32() as u64;
                let offset = target as i64 - (instr.ip() + instr.len() as u64) as i64;
                Some(Box::new(PcRelativeOperand::new(offset, 4)))
            }
            OpKind::NearBranch64 => {
                let target = instr.near_branch64();
                let offset = target as i64 - (instr.ip() + instr.len() as u64) as i64;
                Some(Box::new(PcRelativeOperand::new(offset, 8)))
            }
            OpKind::Memory => {
                let base_reg = instr.memory_base();
                let index_reg = instr.memory_index();
                let scale = instr.memory_index_scale();
                let disp = instr.memory_displacement64() as i64;
                let size = memory_size_bytes(instr.memory_size());

                let base = if base_reg != Register::None {
                    Some((base_reg as usize, format!("{:?}", base_reg).to_lowercase()))
                } else {
                    None
                };

                let index = if index_reg != Register::None {
                    Some((index_reg as usize, format!("{:?}", index_reg).to_lowercase()))
                } else {
                    None
                };

                Some(Box::new(DerefOperand::sib(base, index, scale as u8, disp, size)))
            }
            _ => None,
        }
    }

    /// Get branch targets for an instruction.
    pub fn get_branches(&self, instr: &Instruction) -> Vec<(Option<u64>, BranchFlags)> {
        let mut branches = Vec::new();

        match instr.flow_control() {
            iced_x86::FlowControl::UnconditionalBranch => {
                let target = self.get_branch_target(instr);
                branches.push((target, BranchFlags::empty()));
            }
            iced_x86::FlowControl::ConditionalBranch => {
                let target = self.get_branch_target(instr);
                branches.push((target, BranchFlags::COND));
                // Fall through
                branches.push((Some(instr.next_ip()), BranchFlags::FALL | BranchFlags::COND));
            }
            iced_x86::FlowControl::Call => {
                let target = self.get_branch_target(instr);
                let mut flags = BranchFlags::PROC;
                if self.is_indirect_branch(instr) {
                    flags |= BranchFlags::DEREF;
                }
                branches.push((target, flags));
                // Call falls through
                branches.push((Some(instr.next_ip()), BranchFlags::FALL));
            }
            iced_x86::FlowControl::IndirectBranch => {
                branches.push((None, BranchFlags::DEREF));
            }
            iced_x86::FlowControl::IndirectCall => {
                branches.push((None, BranchFlags::PROC | BranchFlags::DEREF));
                branches.push((Some(instr.next_ip()), BranchFlags::FALL));
            }
            iced_x86::FlowControl::Return => {
                // No explicit branch target
            }
            iced_x86::FlowControl::Next => {
                branches.push((Some(instr.next_ip()), BranchFlags::FALL));
            }
            _ => {}
        }

        branches
    }

    /// Get branch target address.
    fn get_branch_target(&self, instr: &Instruction) -> Option<u64> {
        for i in 0..instr.op_count() {
            match instr.op_kind(i) {
                OpKind::NearBranch16 => return Some(instr.near_branch16() as u64),
                OpKind::NearBranch32 => return Some(instr.near_branch32() as u64),
                OpKind::NearBranch64 => return Some(instr.near_branch64()),
                OpKind::FarBranch16 => return Some(instr.far_branch16() as u64),
                OpKind::FarBranch32 => return Some(instr.far_branch32() as u64),
                _ => {}
            }
        }
        None
    }

    /// Check if branch is indirect.
    fn is_indirect_branch(&self, instr: &Instruction) -> bool {
        for i in 0..instr.op_count() {
            if instr.op_kind(i) == OpKind::Memory {
                return true;
            }
        }
        false
    }

    /// Format instruction as string.
    pub fn format(&self, instr: &Instruction) -> String {
        let mut formatter = Self::create_formatter();
        let mut output = String::new();
        formatter.format(instr, &mut output);
        output
    }

    /// Get the mode.
    pub fn mode(&self) -> X86Mode {
        self.mode
    }
}

impl ArchitectureModule for X86Disassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode {
            X86Mode::Mode32 => Architecture::I386,
            X86Mode::Mode64 => Architecture::Amd64,
        }
    }

    fn arch_name(&self) -> &str {
        match self.mode {
            X86Mode::Mode32 => "i386",
            X86Mode::Mode64 => "amd64",
        }
    }

    fn max_instruction_size(&self) -> usize {
        15 // x86 max instruction length
    }

    fn pointer_size(&self) -> usize {
        self.mode.pointer_size()
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn break_instruction(&self) -> Option<&[u8]> {
        Some(&[0xCC]) // INT3
    }

    fn nop_instruction(&self) -> Option<&[u8]> {
        Some(&[0x90]) // NOP
    }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        let disasm = X86Disassembler::new(self.mode);
        disasm.disassemble(&bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "x86 emulator not yet implemented".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        match self.mode {
            X86Mode::Mode32 => Some("cdecl"),
            X86Mode::Mode64 => Some("ms64call"), // or "sysv64" for Linux
        }
    }
}

/// Get register size in bytes.
fn register_size(reg: Register) -> usize {
    match reg {
        Register::AL | Register::AH | Register::BL | Register::BH | Register::CL
        | Register::CH | Register::DL | Register::DH | Register::SIL | Register::DIL
        | Register::SPL | Register::BPL | Register::R8L | Register::R9L | Register::R10L
        | Register::R11L | Register::R12L | Register::R13L | Register::R14L | Register::R15L => 1,

        Register::AX | Register::BX | Register::CX | Register::DX | Register::SI
        | Register::DI | Register::SP | Register::BP | Register::R8W | Register::R9W
        | Register::R10W | Register::R11W | Register::R12W | Register::R13W | Register::R14W
        | Register::R15W => 2,

        Register::EAX | Register::EBX | Register::ECX | Register::EDX | Register::ESI
        | Register::EDI | Register::ESP | Register::EBP | Register::R8D | Register::R9D
        | Register::R10D | Register::R11D | Register::R12D | Register::R13D | Register::R14D
        | Register::R15D | Register::EIP => 4,

        Register::RAX | Register::RBX | Register::RCX | Register::RDX | Register::RSI
        | Register::RDI | Register::RSP | Register::RBP | Register::R8 | Register::R9
        | Register::R10 | Register::R11 | Register::R12 | Register::R13 | Register::R14
        | Register::R15 | Register::RIP => 8,

        // XMM registers
        Register::XMM0 | Register::XMM1 | Register::XMM2 | Register::XMM3 | Register::XMM4
        | Register::XMM5 | Register::XMM6 | Register::XMM7 | Register::XMM8 | Register::XMM9
        | Register::XMM10 | Register::XMM11 | Register::XMM12 | Register::XMM13
        | Register::XMM14 | Register::XMM15 => 16,

        // YMM registers
        Register::YMM0 | Register::YMM1 | Register::YMM2 | Register::YMM3 | Register::YMM4
        | Register::YMM5 | Register::YMM6 | Register::YMM7 | Register::YMM8 | Register::YMM9
        | Register::YMM10 | Register::YMM11 | Register::YMM12 | Register::YMM13
        | Register::YMM14 | Register::YMM15 => 32,

        // Default
        _ => 4,
    }
}

/// Get memory operand size in bytes.
fn memory_size_bytes(size: iced_x86::MemorySize) -> usize {
    match size {
        iced_x86::MemorySize::UInt8 | iced_x86::MemorySize::Int8 => 1,
        iced_x86::MemorySize::UInt16 | iced_x86::MemorySize::Int16 => 2,
        iced_x86::MemorySize::UInt32 | iced_x86::MemorySize::Int32 | iced_x86::MemorySize::Float32 => 4,
        iced_x86::MemorySize::UInt64 | iced_x86::MemorySize::Int64 | iced_x86::MemorySize::Float64 => 8,
        iced_x86::MemorySize::UInt128 | iced_x86::MemorySize::Int128 | iced_x86::MemorySize::Float128 => 16,
        iced_x86::MemorySize::UInt256 | iced_x86::MemorySize::Int256 => 32,
        iced_x86::MemorySize::UInt512 | iced_x86::MemorySize::Int512 => 64,
        _ => 4, // Default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassemble_nop() {
        let mut disasm = X86Disassembler::new_32();
        let code = [0x90]; // NOP
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "nop");
        assert_eq!(op.size, 1);
    }

    #[test]
    fn test_disassemble_push() {
        let mut disasm = X86Disassembler::new_32();
        let code = [0x55]; // push ebp
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "push");
        assert_eq!(op.operand_count(), 1);
    }

    #[test]
    fn test_disassemble_mov() {
        let mut disasm = X86Disassembler::new_32();
        let code = [0xB8, 0x78, 0x56, 0x34, 0x12]; // mov eax, 0x12345678
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "mov");
        assert_eq!(op.size, 5);
    }

    #[test]
    fn test_disassemble_call() {
        let mut disasm = X86Disassembler::new_32();
        let code = [0xE8, 0xFB, 0xFF, 0xFF, 0xFF]; // call $-5 (relative)
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "call");
        assert!(op.is_call());
    }

    #[test]
    fn test_disassemble_ret() {
        let mut disasm = X86Disassembler::new_32();
        let code = [0xC3]; // ret
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "ret");
        assert!(op.is_return());
        assert!(!op.falls_through());
    }

    #[test]
    fn test_disassemble_64bit() {
        let mut disasm = X86Disassembler::new_64();
        let code = [0x48, 0x89, 0xE5]; // mov rbp, rsp
        let op = disasm.disassemble(&code, 0x401000).unwrap();
        assert_eq!(op.mnem, "mov");
        assert_eq!(op.size, 3);
    }

    #[test]
    fn test_disassemble_block() {
        let mut disasm = X86Disassembler::new_32();
        let code = [
            0x55,             // push ebp
            0x89, 0xE5,       // mov ebp, esp
            0x5D,             // pop ebp
            0xC3,             // ret
        ];
        let ops = disasm.disassemble_block(&code, 0x401000, 10);
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0].mnem, "push");
        assert_eq!(ops[3].mnem, "ret");
    }
}
