//! SPARC architecture support.

use crate::constants::{Architecture, Endian};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparcMode {
    Sparc32,
    Sparc64,
}

impl SparcMode {
    pub fn pointer_size(&self) -> usize {
        match self {
            SparcMode::Sparc32 => 4,
            SparcMode::Sparc64 => 8,
        }
    }
}

pub struct SparcDisassembler {
    mode: SparcMode,
    cs: capstone::Capstone,
}

unsafe impl Send for SparcDisassembler {}
unsafe impl Sync for SparcDisassembler {}

impl SparcDisassembler {
    pub fn new(mode: SparcMode) -> VivResult<Self> {
        use capstone::prelude::*;
        let cs = match mode {
            SparcMode::Sparc32 => Capstone::new()
                .sparc()
                .mode(arch::sparc::ArchMode::Default)
                .build(),
            SparcMode::Sparc64 => Capstone::new()
                .sparc()
                .mode(arch::sparc::ArchMode::V9)
                .build(),
        }
        .map_err(|e| VivError::Other {
            message: format!("capstone SPARC: {e}"),
        })?;
        Ok(Self { mode, cs })
    }
}

impl crate::envi::ArchitectureModule for SparcDisassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode {
            SparcMode::Sparc32 => Architecture::Sparc,
            SparcMode::Sparc64 => Architecture::Sparc64,
        }
    }
    fn arch_name(&self) -> &str {
        match self.mode {
            SparcMode::Sparc32 => "sparc",
            SparcMode::Sparc64 => "sparc64",
        }
    }
    fn max_instruction_size(&self) -> usize {
        4
    }
    fn pointer_size(&self) -> usize {
        self.mode.pointer_size()
    }
    fn endian(&self) -> Endian {
        Endian::Big
    }
    fn break_instruction(&self) -> Option<&[u8]> {
        Some(&[0x91, 0xd0, 0x20, 0x01])
    }
    fn nop_instruction(&self) -> Option<&[u8]> {
        Some(&[0x01, 0x00, 0x00, 0x00])
    }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        crate::envi::archs::capstone_disasm(&self.cs, &bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "SPARC emulator: use CpuEmulator trait via vivutils-rs".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        Some("sparc_abi")
    }
}
