//! ELF (Executable and Linkable Format) parser.
//!
//! Uses goblin for parsing and wraps results in vivisect types.

use crate::abstractions::{ExportInfo, ImportInfo, SectionInfo};
use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use goblin::elf::Elf;
use std::path::Path;

/// ELF file parser.
pub struct ElfParser {
    /// Raw file data.
    data: Vec<u8>,
    /// Detected architecture.
    arch: Architecture,
    /// Is 64-bit.
    is_64: bool,
    /// Entry point.
    entry: u64,
    /// Sections.
    sections: Vec<SectionInfo>,
    /// Imports.
    imports: Vec<ImportInfo>,
    /// Exports.
    exports: Vec<ExportInfo>,
}

impl ElfParser {
    /// Load an ELF file from disk.
    pub fn load(path: &Path) -> VivResult<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Parse ELF from bytes.
    pub fn from_bytes(data: Vec<u8>) -> VivResult<Self> {
        let elf = Elf::parse(&data).map_err(|e| VivError::CorruptFile {
            file_format: "ELF".to_string(),
            message: e.to_string(),
        })?;

        // Determine architecture
        let arch = match (elf.header.e_machine, elf.is_64) {
            (goblin::elf::header::EM_386, false) => Architecture::I386,
            (goblin::elf::header::EM_X86_64, true) => Architecture::Amd64,
            (goblin::elf::header::EM_ARM, false) => Architecture::ArmV7,
            (goblin::elf::header::EM_AARCH64, true) => Architecture::A64,
            (goblin::elf::header::EM_MIPS, false) => Architecture::Mips32,
            (goblin::elf::header::EM_MIPS, true) => Architecture::Mips64,
            (goblin::elf::header::EM_PPC, false) => Architecture::PpcE32,
            (goblin::elf::header::EM_PPC64, true) => Architecture::PpcE64,
            (goblin::elf::header::EM_RISCV, false) => Architecture::RiscV32,
            (goblin::elf::header::EM_RISCV, true) => Architecture::RiscV64,
            _ => Architecture::Default,
        };

        // Capture values before consuming elf
        let is_64 = elf.is_64;
        let entry = elf.entry;

        // Parse sections
        let sections = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name)?;
                let flags = sh.sh_flags;

                Some(SectionInfo {
                    name: name.to_string(),
                    virtual_address: sh.sh_addr,
                    virtual_size: sh.sh_size as usize,
                    raw_size: sh.sh_size as usize,
                    raw_offset: sh.sh_offset as usize,
                    executable: (flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0,
                    writable: (flags & goblin::elf::section_header::SHF_WRITE as u64) != 0,
                    readable: (flags & goblin::elf::section_header::SHF_ALLOC as u64) != 0,
                })
            })
            .collect();

        // Parse imports (from dynamic symbols)
        let imports: Vec<ImportInfo> = elf
            .dynsyms
            .iter()
            .filter(|sym| sym.is_import())
            .filter_map(|sym| {
                let name = elf.dynstrtab.get_at(sym.st_name)?;
                Some(ImportInfo {
                    address: sym.st_value,
                    library: String::new(), // ELF doesn't have per-import library info
                    name: name.to_string(),
                    ordinal: None,
                })
            })
            .collect();

        // Parse exports (from dynamic symbols)
        let exports: Vec<ExportInfo> = elf
            .dynsyms
            .iter()
            .filter(|sym| !sym.is_import() && sym.st_value != 0)
            .filter_map(|sym| {
                let name = elf.dynstrtab.get_at(sym.st_name)?;
                if name.is_empty() {
                    return None;
                }
                Some(ExportInfo {
                    address: sym.st_value,
                    name: name.to_string(),
                    ordinal: None,
                })
            })
            .collect();

        // Drop elf before moving data
        drop(elf);

        Ok(Self {
            data,
            arch,
            is_64,
            entry,
            sections,
            imports,
            exports,
        })
    }

    /// Get the entry point address.
    pub fn entry_point(&self) -> u64 {
        self.entry
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Check if 64-bit.
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Get all sections.
    pub fn sections(&self) -> &[SectionInfo] {
        &self.sections
    }

    /// Get imports.
    pub fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    /// Get exports.
    pub fn exports(&self) -> &[ExportInfo] {
        &self.exports
    }

    /// Read bytes at a virtual address.
    pub fn read_va(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        // Find the section containing this VA
        for section in &self.sections {
            let section_end = section.virtual_address + section.virtual_size as u64;

            if va >= section.virtual_address && va < section_end {
                let offset_in_section = (va - section.virtual_address) as usize;
                let raw_offset = section.raw_offset + offset_in_section;

                if raw_offset + size <= self.data.len() {
                    return Ok(self.data[raw_offset..raw_offset + size].to_vec());
                }
            }
        }

        Err(VivError::InvalidMemory { address: va })
    }

    /// Get the raw data.
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Get image base (usually 0 for ELF, or first LOAD segment).
    pub fn image_base(&self) -> u64 {
        // For ELF, image base is typically the lowest load address
        self.sections
            .iter()
            .filter(|s| s.readable)
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(0)
    }
}
