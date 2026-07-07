//! RISC-V architecture support (icicle Sleigh only, no capstone).

use crate::constants::{Architecture, Endian};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiscvMode { Rv32, Rv64 }

impl RiscvMode {
    pub fn pointer_size(&self) -> usize {
        match self { RiscvMode::Rv32 => 4, RiscvMode::Rv64 => 8 }
    }
}

pub struct RiscvDisassembler { mode: RiscvMode }

impl RiscvDisassembler {
    pub fn new(mode: RiscvMode) -> Self { Self { mode } }
}

impl crate::envi::ArchitectureModule for RiscvDisassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode { RiscvMode::Rv32 => Architecture::RiscV32, RiscvMode::Rv64 => Architecture::RiscV64 }
    }
    fn arch_name(&self) -> &str {
        match self.mode { RiscvMode::Rv32 => "riscv32", RiscvMode::Rv64 => "riscv64" }
    }
    fn max_instruction_size(&self) -> usize { 4 }
    fn pointer_size(&self) -> usize { self.mode.pointer_size() }
    fn endian(&self) -> Endian { Endian::Little }
    fn break_instruction(&self) -> Option<&[u8]> { Some(&[0x73, 0x00, 0x10, 0x00]) }
    fn nop_instruction(&self) -> Option<&[u8]> { Some(&[0x13, 0x00, 0x00, 0x00]) }

    fn parse_opcode(&self, _bytes: &[u8], _offset: usize, _va: u64) -> VivResult<Opcode> {
        Err(VivError::Other { message: "RISC-V disassembly requires icicle Sleigh backend".into() })
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other { message: "RISC-V emulator: use CpuEmulator trait via vivutils-rs".into() })
    }

    fn default_calling_convention(&self) -> Option<&str> { Some("riscv_ilp32") }
}
