//! ELF (Executable and Linkable Format) parser.
//!
//! Uses goblin for parsing and wraps results in vivisect types.

use crate::abstractions::{ExportInfo, ImportInfo, SectionInfo};
use crate::constants::{Architecture, Endian};
use crate::error::{VivError, VivResult};
use goblin::elf::Elf;
use std::path::Path;

/// A loadable (`PT_LOAD`) program-header segment — the authoritative unit of the
/// ELF runtime memory image.
#[derive(Debug, Clone)]
pub struct LoadSegment {
    /// Virtual address the segment maps to.
    pub vaddr: u64,
    /// File offset of the segment's bytes.
    pub offset: usize,
    /// Number of bytes present in the file.
    pub filesz: usize,
    /// Size of the segment in memory (`>= filesz`; tail is zero-filled).
    pub memsz: usize,
    /// `PF_R`.
    pub read: bool,
    /// `PF_W`.
    pub write: bool,
    /// `PF_X`.
    pub exec: bool,
}

/// ELF file parser.
pub struct ElfParser {
    /// Raw file data.
    data: Vec<u8>,
    /// Detected architecture.
    arch: Architecture,
    /// Is 64-bit.
    is_64: bool,
    /// Little-endian (`EI_DATA == ELFDATA2LSB`).
    is_little: bool,
    /// Entry point.
    entry: u64,
    /// Sections.
    sections: Vec<SectionInfo>,
    /// `PT_LOAD` program-header segments (runtime memory image).
    load_segments: Vec<LoadSegment>,
    /// Imports.
    imports: Vec<ImportInfo>,
    /// Exports.
    exports: Vec<ExportInfo>,
    /// Function entry points from .symtab STT_FUNC symbols.
    function_entries: Vec<(u64, String)>,
}

/// Map PLT/dynamic relocations to workspace import entries (review finding #12).
///
/// Each `(r_offset, r_sym)` relocation names a GOT/PLT slot (`r_offset` — the VA
/// that the dynamic linker fills in) and the dynamic symbol it resolves to
/// (`r_sym`, an index into `sym_names`). This builds the
/// `relocation → symbol → GOT/PLT slot → import` relationship that plain
/// `.dynsym` scanning misses (undefined import symbols have `st_value == 0`, so
/// their real address is only known via the relocation's `r_offset`).
pub(crate) fn plt_relocs_to_imports(
    relocs: &[(u64, usize)],
    sym_names: &[String],
) -> Vec<ImportInfo> {
    relocs
        .iter()
        .filter_map(|&(offset, symidx)| {
            let name = sym_names.get(symidx)?;
            if name.is_empty() || offset == 0 {
                return None;
            }
            Some(ImportInfo {
                address: offset, // GOT/PLT slot VA
                library: String::new(),
                name: name.clone(),
                ordinal: None,
            })
        })
        .collect()
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
        let is_little = elf.little_endian;
        let entry = elf.entry;

        // PT_LOAD program-header segments: the authoritative runtime memory
        // image (review finding #4). Sections are retained only as metadata.
        let load_segments: Vec<LoadSegment> = elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|ph| LoadSegment {
                vaddr: ph.p_vaddr,
                offset: ph.p_offset as usize,
                filesz: ph.p_filesz as usize,
                memsz: ph.p_memsz as usize,
                read: ph.p_flags & goblin::elf::program_header::PF_R != 0,
                write: ph.p_flags & goblin::elf::program_header::PF_W != 0,
                exec: ph.p_flags & goblin::elf::program_header::PF_X != 0,
            })
            .collect();

        // Parse sections
        let sections = elf
            .section_headers
            .iter()
            .filter_map(|sh| {
                let name = elf.shdr_strtab.get_at(sh.sh_name)?;
                let flags = sh.sh_flags;

                // SHT_NOBITS (.bss) occupies no file space — report raw_size 0 so
                // the normalized mapping zero-fills the whole virtual_size rather
                // than copying unrelated file bytes (review finding #4 SHT_NOBITS).
                let is_nobits = sh.sh_type == goblin::elf::section_header::SHT_NOBITS;
                let raw_size = if is_nobits { 0 } else { sh.sh_size as usize };

                Some(SectionInfo {
                    name: name.to_string(),
                    virtual_address: sh.sh_addr,
                    virtual_size: sh.sh_size as usize,
                    raw_size,
                    raw_offset: sh.sh_offset as usize,
                    executable: (flags & goblin::elf::section_header::SHF_EXECINSTR as u64) != 0,
                    writable: (flags & goblin::elf::section_header::SHF_WRITE as u64) != 0,
                    readable: (flags & goblin::elf::section_header::SHF_ALLOC as u64) != 0,
                })
            })
            .collect();

        // Parse imports (from dynamic symbols).
        let mut imports: Vec<ImportInfo> = elf
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

        // Build the relocation → symbol → GOT/PLT-slot → import relationship
        // (review finding #12): undefined import symbols have st_value == 0, so
        // the real slot address is only known from the relocation's r_offset.
        let sym_names: Vec<String> = elf
            .dynsyms
            .iter()
            .map(|s| elf.dynstrtab.get_at(s.st_name).unwrap_or("").to_string())
            .collect();
        let mut reloc_pairs: Vec<(u64, usize)> = Vec::new();
        for r in elf.pltrelocs.iter() {
            reloc_pairs.push((r.r_offset, r.r_sym));
        }
        for r in elf.dynrelas.iter() {
            reloc_pairs.push((r.r_offset, r.r_sym));
        }
        for r in elf.dynrels.iter() {
            reloc_pairs.push((r.r_offset, r.r_sym));
        }
        // GOT/PLT-slot imports take precedence; merge, de-duplicating by slot VA.
        let mut got_imports = plt_relocs_to_imports(&reloc_pairs, &sym_names);
        let known: std::collections::HashSet<u64> = got_imports.iter().map(|i| i.address).collect();
        imports.retain(|i| i.address == 0 || !known.contains(&i.address));
        got_imports.append(&mut imports);
        let imports = got_imports;

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
            .map(|sym| {
                let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
                (sym.st_value, name.to_string())
            })
            .collect();

        // Parse function entries from .symtab (static symbol table).
        // Python's elf.py line 770: `if s.getInfoType() == Elf.STT_FUNC: new_functions.append(("STT_FUNC", sva))`
        // This is critical for Go binaries and any non-stripped ELF with a .symtab section.
        let mut function_entries: Vec<(u64, String)> = elf
            .syms
            .iter()
            .filter(|sym| sym.is_function() && sym.st_value != 0)
            .map(|sym| {
                let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
                (sym.st_value, name.to_string())
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
            is_little,
            entry,
            sections,
            load_segments,
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

    /// Endianness from the ELF identification (`EI_DATA`).
    pub fn endian(&self) -> Endian {
        if self.is_little {
            Endian::Little
        } else {
            Endian::Big
        }
    }

    /// Raw `PT_LOAD` segments.
    pub fn load_segments(&self) -> &[LoadSegment] {
        &self.load_segments
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

    #[test]
    fn test_plt_relocs_to_imports() {
        // symbol table by dynsym index; index 0 is the reserved null symbol.
        let names = vec![String::new(), "puts".to_string(), "malloc".to_string()];
        // (GOT slot VA, dynsym index)
        let relocs = vec![
            (0x404018, 1), // -> puts
            (0x404020, 2), // -> malloc
            (0x404028, 0), // reserved/relative reloc: no name -> dropped
            (0x000000, 1), // zero slot -> dropped
            (0x404030, 9), // out-of-range symbol index -> dropped
        ];
        let imports = plt_relocs_to_imports(&relocs, &names);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].address, 0x404018);
        assert_eq!(imports[0].name, "puts");
        assert_eq!(imports[1].address, 0x404020);
        assert_eq!(imports[1].name, "malloc");
    }

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
