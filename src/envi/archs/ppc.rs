//! PowerPC architecture support.

use crate::constants::{Architecture, Endian};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpcMode {
    Ppc32,
    Ppc64,
}

impl PpcMode {
    pub fn pointer_size(&self) -> usize {
        match self {
            PpcMode::Ppc32 => 4,
            PpcMode::Ppc64 => 8,
        }
    }
}

pub struct PpcDisassembler {
    mode: PpcMode,
    cs: capstone::Capstone,
}

unsafe impl Send for PpcDisassembler {}
unsafe impl Sync for PpcDisassembler {}

impl PpcDisassembler {
    pub fn new(mode: PpcMode) -> VivResult<Self> {
        use capstone::prelude::*;
        let cs = match mode {
            PpcMode::Ppc32 => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode32)
                .build(),
            PpcMode::Ppc64 => Capstone::new()
                .ppc()
                .mode(arch::ppc::ArchMode::Mode64)
                .build(),
        }
        .map_err(|e| VivError::Other {
            message: format!("capstone PPC: {e}"),
        })?;
        Ok(Self { mode, cs })
    }
}

impl crate::envi::ArchitectureModule for PpcDisassembler {
    fn arch_id(&self) -> Architecture {
        match self.mode {
            PpcMode::Ppc32 => Architecture::PpcE32,
            PpcMode::Ppc64 => Architecture::PpcE64,
        }
    }
    fn arch_name(&self) -> &str {
        match self.mode {
            PpcMode::Ppc32 => "ppc32",
            PpcMode::Ppc64 => "ppc64",
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
        Some(&[0x7d, 0x82, 0x10, 0x08])
    }
    fn nop_instruction(&self) -> Option<&[u8]> {
        Some(&[0x60, 0x00, 0x00, 0x00])
    }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        crate::envi::archs::capstone_disasm(&self.cs, &bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other {
            message: "PPC emulator: use CpuEmulator trait via vivutils-rs".into(),
        })
    }

    fn default_calling_convention(&self) -> Option<&str> {
        Some("ppc_sysv")
    }
}
