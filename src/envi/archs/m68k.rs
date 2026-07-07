//! Motorola 68000 architecture support.

use crate::constants::{Architecture, Endian};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};

pub struct M68kDisassembler { cs: capstone::Capstone }

unsafe impl Send for M68kDisassembler {}
unsafe impl Sync for M68kDisassembler {}

impl M68kDisassembler {
    pub fn new() -> VivResult<Self> {
        use capstone::prelude::*;
        let cs = Capstone::new().m68k().mode(arch::m68k::ArchMode::M68k040).build()
            .map_err(|e| VivError::Other { message: format!("capstone M68K: {e}") })?;
        Ok(Self { cs })
    }
}

impl crate::envi::ArchitectureModule for M68kDisassembler {
    fn arch_id(&self) -> Architecture { Architecture::M68k }
    fn arch_name(&self) -> &str { "m68k" }
    fn max_instruction_size(&self) -> usize { 10 }
    fn pointer_size(&self) -> usize { 4 }
    fn endian(&self) -> Endian { Endian::Big }
    fn break_instruction(&self) -> Option<&[u8]> { Some(&[0x4E, 0x4F]) }
    fn nop_instruction(&self) -> Option<&[u8]> { Some(&[0x4E, 0x71]) }

    fn parse_opcode(&self, bytes: &[u8], offset: usize, va: u64) -> VivResult<Opcode> {
        crate::envi::archs::capstone_disasm(&self.cs, &bytes[offset..], va)
    }

    fn get_emulator(&self) -> VivResult<Box<dyn crate::abstractions::Emulator>> {
        Err(VivError::Other { message: "M68K emulator: use CpuEmulator trait via vivutils-rs".into() })
    }

    fn default_calling_convention(&self) -> Option<&str> { Some("m68k_sysv") }
}
