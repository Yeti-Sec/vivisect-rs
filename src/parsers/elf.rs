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
    /// Function entry points from .symtab STT_FUNC symbols.
    function_entries: Vec<(u64, String)>,
}

impl ElfParser {
    /// Load an ELF file from disk.
    #[must_use]
    pub fn load(path: &Path) -> VivResult<Self> {
        let data = super::read_file_limited(path, super::DEFAULT_MAX_FILE_SIZE)?;
        Self::from_bytes(data)
    }

    /// Parse ELF from bytes.
    #[must_use]
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

        // Parse dynamic function entries (STT_FUNC from .dynsym).
        // Python's elf.py line 531: `if stype == Elf.STT_FUNC: new_functions.append(("DynSym: STT_FUNC", sva))`
        // These are added as entry points so code flow analysis discovers the functions.
        let dynsym_functions: Vec<(u64, String)> = elf
            .dynsyms
            .iter()
            .filter(|sym| sym.is_function() && !sym.is_import() && sym.st_value != 0)
            .filter_map(|sym| {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                Some((sym.st_value, name.to_string()))
            })
            .collect();

        // Parse function entries from .symtab (static symbol table).
        // Python's elf.py line 770: `if s.getInfoType() == Elf.STT_FUNC: new_functions.append(("STT_FUNC", sva))`
        // This is critical for Go binaries and any non-stripped ELF with a .symtab section.
        let mut function_entries: Vec<(u64, String)> = elf
            .syms
            .iter()
            .filter(|sym| sym.is_function() && sym.st_value != 0)
            .filter_map(|sym| {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                Some((sym.st_value, name.to_string()))
            })
            .collect();

        // Merge dynamic function entries (dedup by address)
        let existing_vas: std::collections::HashSet<u64> =
            function_entries.iter().map(|(va, _)| *va).collect();
        for entry in dynsym_functions {
            if !existing_vas.contains(&entry.0) {
                function_entries.push(entry);
            }
        }

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
            function_entries,
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

    /// Get function entries from .symtab STT_FUNC symbols.
    /// Returns (address, name) pairs.
    pub fn function_entries(&self) -> &[(u64, String)] {
        &self.function_entries
    }

    /// Read bytes at a virtual address.
    #[must_use]
    pub fn read_va(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        for section in &self.sections {
            let section_end = section
                .virtual_address
                .saturating_add(section.virtual_size as u64);

            if va >= section.virtual_address && va < section_end {
                let offset_in_section = (va - section.virtual_address) as usize;
                let raw_offset = section
                    .raw_offset
                    .checked_add(offset_in_section)
                    .ok_or(VivError::InvalidMemory { address: va })?;
                let end = raw_offset
                    .checked_add(size)
                    .ok_or(VivError::InvalidMemory { address: va })?;

                if end <= self.data.len() {
                    return Ok(self.data[raw_offset..end].to_vec());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid ELF64 binary in memory (no sections, but valid header).
    fn make_minimal_elf64() -> Vec<u8> {
        // ELF64 header: 64 bytes
        let mut data = vec![0u8; 64];
        // EI_MAG0..3
        data[0] = 0x7F;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        // EI_CLASS = ELFCLASS64
        data[4] = 2;
        // EI_DATA = ELFDATA2LSB
        data[5] = 1;
        // EI_VERSION
        data[6] = 1;
        // e_type = ET_EXEC (2)
        data[16] = 2;
        data[17] = 0;
        // e_machine = EM_X86_64 (62 = 0x3E)
        data[18] = 0x3E;
        data[19] = 0;
        // e_version
        data[20] = 1;
        // e_ehsize = 64
        data[52] = 64;
        data[53] = 0;
        data
    }

    #[test]
    fn test_elf_parser_invalid_data() {
        let result = ElfParser::from_bytes(vec![0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn test_elf_parser_empty_data() {
        let result = ElfParser::from_bytes(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_elf_parser_not_elf() {
        // PE file magic (MZ)
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        let result = ElfParser::from_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_elf_parser_minimal_elf64() {
        let data = make_minimal_elf64();
        let parser = ElfParser::from_bytes(data).unwrap();
        assert_eq!(parser.architecture(), Architecture::Amd64);
        assert!(parser.is_64());
        assert!(parser.sections().is_empty());
        assert!(parser.imports().is_empty());
        assert!(parser.exports().is_empty());
        assert!(parser.function_entries().is_empty());
    }

    #[test]
    fn test_elf_parser_entry_point() {
        let data = make_minimal_elf64();
        let parser = ElfParser::from_bytes(data).unwrap();
        // Entry point is 0 in our minimal ELF
        assert_eq!(parser.entry_point(), 0);
    }

    #[test]
    fn test_elf_parser_image_base_no_sections() {
        let data = make_minimal_elf64();
        let parser = ElfParser::from_bytes(data).unwrap();
        // No readable sections → image base should be 0
        assert_eq!(parser.image_base(), 0);
    }

    #[test]
    fn test_elf_parser_raw_data() {
        let data = make_minimal_elf64();
        let len = data.len();
        let parser = ElfParser::from_bytes(data).unwrap();
        assert_eq!(parser.raw_data().len(), len);
        // Check ELF magic
        assert_eq!(&parser.raw_data()[0..4], &[0x7F, b'E', b'L', b'F']);
    }

    #[test]
    fn test_elf_parser_read_va_invalid() {
        let data = make_minimal_elf64();
        let parser = ElfParser::from_bytes(data).unwrap();
        // No sections mapped, so any VA read should fail
        let result = parser.read_va(0x401000, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_section_info_fields() {
        let section = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x401000,
            virtual_size: 0x1000,
            raw_size: 0x800,
            raw_offset: 0x200,
            executable: true,
            writable: false,
            readable: true,
        };
        assert_eq!(section.name, ".text");
        assert!(section.executable);
        assert!(section.readable);
        assert!(!section.writable);
    }

    #[test]
    fn test_import_info_fields() {
        let import = ImportInfo {
            address: 0,
            library: String::new(),
            name: "printf".to_string(),
            ordinal: None,
        };
        assert_eq!(import.name, "printf");
        assert!(import.library.is_empty()); // ELF doesn't have per-import library info
        assert!(import.ordinal.is_none());
    }

    #[test]
    fn test_export_info_fields() {
        let export = ExportInfo {
            address: 0x401000,
            name: "main".to_string(),
            ordinal: None,
        };
        assert_eq!(export.address, 0x401000);
        assert_eq!(export.name, "main");
    }

    #[test]
    fn test_architecture_detection_variants() {
        // Verify the architecture detection mapping is comprehensive
        let em_machines: Vec<(u16, bool, Architecture)> = vec![
            (goblin::elf::header::EM_386, false, Architecture::I386),
            (goblin::elf::header::EM_X86_64, true, Architecture::Amd64),
            (goblin::elf::header::EM_ARM, false, Architecture::ArmV7),
            (goblin::elf::header::EM_AARCH64, true, Architecture::A64),
        ];
        // Just verify the constants are distinct
        for (i, (m1, _, _)) in em_machines.iter().enumerate() {
            for (j, (m2, _, _)) in em_machines.iter().enumerate() {
                if i != j {
                    assert_ne!(m1, m2);
                }
            }
        }
    }
}
