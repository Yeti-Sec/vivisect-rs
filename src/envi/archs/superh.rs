//! SuperH (SH-4) architecture support (icicle Sleigh only).

use crate::constants::{Architecture, Endian};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperHMode {
    Sh4,
    Sh4Le,
}

pub struct SuperHDisassembler {
    mode: SuperHMode,
}

impl SuperHDisassembler {
    pub fn new(mode: SuperHMode) -> Self {
        Self { mode }
    }
}

impl crate::envi::ArchitectureModule for SuperHDisassembler {
    fn arch_id(&self) -> Architecture {
        Architecture::SuperH
    }
    fn arch_name(&self) -> &str {
        "superh"
    }
    fn max_instruction_size(&self) -> usize {
        2
    }
    fn pointer_size(&self) -> usize {
        4
    }
    fn endian(&self) -> Endian {
        match self.mode {
            SuperHMode::Sh4 => Endian::Big,
            SuperHMode::Sh4Le => Endian::Little,
        }
    }
    fn break_instruction(&self) -> Option<&[u8]> {
        Some(&[0xC3, 0x00])
    }
    fn nop_instruction(&self) -> Option<&[u8]> {
        Some(&[0x00, 0x09])
    }

    fn parse_opcode(&self, _bytes: &[u8], _offset: usize, _va: u64) -> VivResult<Opcode> {
        Err(VivError::Other {
            message: "SuperH disassembly requires icicle Sleigh backend".into(),
        })
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "SuperH emulator: use CpuEmulator trait via vivutils-rs".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        Some("sh4_abi")
    }
}
