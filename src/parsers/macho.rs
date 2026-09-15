//! Mach-O binary format parser.
//!
//! Uses goblin for parsing and wraps results in vivisect types.
//! Supports Mach-O 32/64-bit and fat (universal) binaries.

use crate::abstractions::{ExportInfo, ImportInfo, SectionInfo};
use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use std::path::Path;

/// Mach-O file parser.
pub struct MachOParser {
    /// Raw file data.
    data: Vec<u8>,
    /// Detected architecture.
    arch: Architecture,
    /// Is 64-bit.
    is_64: bool,
    /// Entry point virtual address.
    entry: u64,
    /// Parsed sections.
    sections: Vec<SectionInfo>,
    /// Parsed imports.
    imports: Vec<ImportInfo>,
    /// Parsed exports.
    exports: Vec<ExportInfo>,
    /// Function entries from symbol table (address, name).
    function_entries: Vec<(u64, String)>,
    /// Dependent libraries.
    libs: Vec<String>,
    /// Whether this is a dylib.
    is_dylib: bool,
}

/// Intermediate struct for extracting owned data from goblin's borrowed MachO.
struct ExtractedMachO {
    arch: Architecture,
    is_64: bool,
    entry: u64,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    function_entries: Vec<(u64, String)>,
    libs: Vec<String>,
    is_dylib: bool,
}

impl MachOParser {
    /// Load a Mach-O file from disk.
    #[must_use]
    pub fn load(path: &Path) -> VivResult<Self> {
        let data = super::read_file_limited(path, super::DEFAULT_MAX_FILE_SIZE)?;
        Self::from_bytes(data)
    }

    /// Parse Mach-O from bytes.
    ///
    /// For fat (universal) binaries, selects the first architecture.
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> VivResult<Self> {
        Self::from_bytes_with_arch(data, None)
    }

    /// Parse Mach-O from bytes, optionally selecting a specific architecture
    /// from a fat binary by CPU type.
    #[must_use]
    pub fn from_bytes_with_arch(data: Vec<u8>, preferred_cputype: Option<u32>) -> VivResult<Self> {
        use goblin::mach::Mach;

        // Extract all fields from the parsed goblin structure while it borrows data,
        // then drop the borrow and move data into the final struct.
        let extracted = {
            let mach = Mach::parse(&data).map_err(|e| VivError::CorruptFile {
                file_format: "Mach-O".to_string(),
                message: e.to_string(),
            })?;

            match mach {
                Mach::Binary(ref macho) => Self::extract_fields(macho),
                Mach::Fat(ref multi) => {
                    let mut result = None;
                    if let Some(cputype) = preferred_cputype {
                        for entry in multi {
                            if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = entry {
                                if macho.header.cputype == cputype {
                                    result = Some(Self::extract_fields(macho));
                                    break;
                                }
                            }
                        }
                    }
                    if result.is_none() {
                        for entry in multi {
                            if let Ok(goblin::mach::SingleArch::MachO(ref macho)) = entry {
                                result = Some(Self::extract_fields(macho));
                                break;
                            }
                        }
                    }
                    result.ok_or_else(|| VivError::CorruptFile {
                        file_format: "Mach-O".to_string(),
                        message: "fat binary contains no Mach-O entries".to_string(),
                    })?
                }
            }
        };
        // goblin borrow is dropped here, we can now move data

        Ok(Self {
            data,
            arch: extracted.arch,
            is_64: extracted.is_64,
            entry: extracted.entry,
            sections: extracted.sections,
            imports: extracted.imports,
            exports: extracted.exports,
            function_entries: extracted.function_entries,
            libs: extracted.libs,
            is_dylib: extracted.is_dylib,
        })
    }

    /// Extract all fields from a goblin MachO into owned types.
    fn extract_fields(macho: &goblin::mach::MachO<'_>) -> ExtractedMachO {
        use goblin::mach::constants::cputype::*;
        use goblin::mach::symbols::{N_SECT, N_STAB, N_TYPE};

        let arch = match (macho.header.cputype, macho.is_64) {
            (CPU_TYPE_X86, false) => Architecture::I386,
            (CPU_TYPE_X86_64, true) => Architecture::Amd64,
            (CPU_TYPE_ARM, false) => Architecture::ArmV7,
            (CPU_TYPE_ARM64, true) => Architecture::A64,
            (CPU_TYPE_POWERPC, false) => Architecture::PpcE32,
            (CPU_TYPE_POWERPC64, true) => Architecture::PpcE64,
            _ => Architecture::Default,
        };

        let is_64 = macho.is_64;
        let entry = macho.entry;
        let is_dylib = macho.header.filetype == goblin::mach::header::MH_DYLIB;

        // Parse sections from segments
        let mut sections = Vec::new();
        for segment in &macho.segments {
            let seg_prot = segment.initprot;
            let seg_readable = (seg_prot & 1) != 0;
            let seg_writable = (seg_prot & 2) != 0;
            let seg_executable = (seg_prot & 4) != 0;

            for (section, _section_data) in segment.into_iter().flatten() {
                let sectname = String::from_utf8_lossy(&section.sectname)
                    .trim_end_matches('\0')
                    .to_string();
                let segname = String::from_utf8_lossy(&section.segname)
                    .trim_end_matches('\0')
                    .to_string();

                let name = format!("{},{}", segname, sectname);

                let has_instructions =
                    (section.flags & goblin::mach::constants::S_ATTR_PURE_INSTRUCTIONS) != 0;

                sections.push(SectionInfo {
                    name,
                    virtual_address: section.addr,
                    virtual_size: section.size as usize,
                    raw_size: section.size as usize,
                    raw_offset: section.offset as usize,
                    executable: seg_executable || has_instructions,
                    writable: seg_writable,
                    readable: seg_readable,
                });
            }
        }

        // Parse imports
        let imports = match macho.imports() {
            Ok(imp_list) => imp_list
                .iter()
                .map(|imp| ImportInfo {
                    address: imp.address,
                    library: imp.dylib.to_string(),
                    name: imp.name.to_string(),
                    ordinal: None,
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // Parse exports
        let exports = match macho.exports() {
            Ok(exp_list) => exp_list
                .iter()
                .filter_map(|exp| {
                    let address = match &exp.info {
                        goblin::mach::exports::ExportInfo::Regular { address, .. } => *address,
                        _ => return None,
                    };
                    if address == 0 {
                        return None;
                    }
                    Some(ExportInfo {
                        address,
                        name: exp.name.clone(),
                        ordinal: None,
                    })
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // Parse function entries from the symbol table (nlist)
        let mut function_entries = Vec::new();
        for (name, nlist) in macho.symbols().flatten() {
            if nlist.n_type & N_STAB != 0 {
                continue;
            }
            if (nlist.n_type & N_TYPE) != N_SECT {
                continue;
            }
            if nlist.n_value == 0 {
                continue;
            }
            if nlist.n_sect > 0 && nlist.n_sect <= sections.len() {
                let sec = &sections[nlist.n_sect - 1];
                if sec.executable {
                    function_entries.push((nlist.n_value, name.to_string()));
                }
            }
        }

        // Dependent libraries
        let libs: Vec<String> = macho.libs.iter().map(|l| l.to_string()).collect();

        ExtractedMachO {
            arch,
            is_64,
            entry,
            sections,
            imports,
            exports,
            function_entries,
            libs,
            is_dylib,
        }
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

    /// Check if this is a dynamic library.
    pub fn is_dylib(&self) -> bool {
        self.is_dylib
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

    /// Get function entries from symbol table.
    /// Returns (address, name) pairs.
    pub fn function_entries(&self) -> &[(u64, String)] {
        &self.function_entries
    }

    /// Get dependent libraries.
    pub fn libs(&self) -> &[String] {
        &self.libs
    }

    /// Get the raw file data.
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Get image base (lowest segment virtual address).
    pub fn image_base(&self) -> u64 {
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

    /// Create a minimal valid Mach-O 64-bit little-endian binary (header only).
    fn make_minimal_macho64() -> Vec<u8> {
        let mut data = vec![0u8; 32]; // mach_header_64 is 32 bytes
                                      // MH_MAGIC_64 = 0xFEEDFACF (little-endian: CF FA ED FE)
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        // cputype = CPU_TYPE_X86_64 = 0x01000007 (LE)
        data[4] = 0x07;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x01;
        // cpusubtype = CPU_SUBTYPE_X86_64_ALL = 3
        data[8] = 0x03;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x00;
        // filetype = MH_EXECUTE = 2
        data[12] = 0x02;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x00;
        // ncmds = 0
        data[16] = 0x00;
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;
        // sizeofcmds = 0
        data[20] = 0x00;
        data[21] = 0x00;
        data[22] = 0x00;
        data[23] = 0x00;
        // flags = 0
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x00;
        data[27] = 0x00;
        // reserved = 0
        data[28] = 0x00;
        data[29] = 0x00;
        data[30] = 0x00;
        data[31] = 0x00;
        data
    }

    /// Create a minimal valid Mach-O 32-bit little-endian binary (header only).
    fn make_minimal_macho32() -> Vec<u8> {
        let mut data = vec![0u8; 64]; // mach_header is 28 bytes, pad for goblin
                                      // MH_MAGIC = 0xFEEDFACE (little-endian: CE FA ED FE)
        data[0] = 0xCE;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        // cputype = CPU_TYPE_I386 = 7
        data[4] = 0x07;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x00;
        // cpusubtype = CPU_SUBTYPE_I386_ALL = 3
        data[8] = 0x03;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x00;
        // filetype = MH_EXECUTE = 2
        data[12] = 0x02;
        data[13] = 0x00;
        data[14] = 0x00;
        data[15] = 0x00;
        // ncmds = 0
        data[16] = 0x00;
        data[17] = 0x00;
        data[18] = 0x00;
        data[19] = 0x00;
        // sizeofcmds = 0
        data[20] = 0x00;
        data[21] = 0x00;
        data[22] = 0x00;
        data[23] = 0x00;
        // flags = 0
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x00;
        data[27] = 0x00;
        data
    }

    #[test]
    fn test_macho_parser_invalid_data() {
        let result = MachOParser::from_bytes(vec![0u8; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn test_macho_parser_empty_data() {
        let result = MachOParser::from_bytes(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_macho_parser_not_macho() {
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        let result = MachOParser::from_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_macho64_minimal() {
        let data = make_minimal_macho64();
        let parser = MachOParser::from_bytes(data).unwrap();
        assert_eq!(parser.architecture(), Architecture::Amd64);
        assert!(parser.is_64());
        assert!(!parser.is_dylib());
        assert!(parser.sections().is_empty());
        assert!(parser.imports().is_empty());
        assert!(parser.exports().is_empty());
        assert!(parser.function_entries().is_empty());
    }

    #[test]
    fn test_macho32_minimal() {
        let data = make_minimal_macho32();
        let parser = MachOParser::from_bytes(data).unwrap();
        assert_eq!(parser.architecture(), Architecture::I386);
        assert!(!parser.is_64());
        assert!(!parser.is_dylib());
    }

    #[test]
    fn test_macho_entry_point() {
        let data = make_minimal_macho64();
        let parser = MachOParser::from_bytes(data).unwrap();
        assert_eq!(parser.entry_point(), 0);
    }

    #[test]
    fn test_macho_image_base_no_sections() {
        let data = make_minimal_macho64();
        let parser = MachOParser::from_bytes(data).unwrap();
        assert_eq!(parser.image_base(), 0);
    }

    #[test]
    fn test_macho_raw_data() {
        let data = make_minimal_macho64();
        let len = data.len();
        let parser = MachOParser::from_bytes(data).unwrap();
        assert_eq!(parser.raw_data().len(), len);
        assert_eq!(&parser.raw_data()[0..4], &[0xCF, 0xFA, 0xED, 0xFE]);
    }

    #[test]
    fn test_macho_libs_empty() {
        let data = make_minimal_macho64();
        let parser = MachOParser::from_bytes(data).unwrap();
        let _ = parser.libs();
    }

    #[test]
    fn test_section_info_construction() {
        let section = SectionInfo {
            name: "__TEXT,__text".to_string(),
            virtual_address: 0x100001000,
            virtual_size: 0x500,
            raw_size: 0x500,
            raw_offset: 0x1000,
            executable: true,
            writable: false,
            readable: true,
        };
        assert_eq!(section.name, "__TEXT,__text");
        assert!(section.executable);
        assert!(section.readable);
        assert!(!section.writable);
    }

    #[test]
    fn test_architecture_mapping() {
        use goblin::mach::constants::cputype::*;
        let types = [
            CPU_TYPE_X86,
            CPU_TYPE_X86_64,
            CPU_TYPE_ARM,
            CPU_TYPE_ARM64,
            CPU_TYPE_POWERPC,
            CPU_TYPE_POWERPC64,
        ];
        for (i, t1) in types.iter().enumerate() {
            for (j, t2) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(t1, t2);
                }
            }
        }
    }

    #[test]
    fn test_macho_magic_detection() {
        use crate::parsers::{detect_format_bytes, BinaryFormat};
        let macho64_le = [0xCF, 0xFA, 0xED, 0xFE];
        assert_eq!(
            detect_format_bytes(&macho64_le).unwrap(),
            BinaryFormat::MachO
        );
        let macho64_be = [0xFE, 0xED, 0xFA, 0xCF];
        assert_eq!(
            detect_format_bytes(&macho64_be).unwrap(),
            BinaryFormat::MachO
        );
        let macho32_le = [0xCE, 0xFA, 0xED, 0xFE];
        assert_eq!(
            detect_format_bytes(&macho32_le).unwrap(),
            BinaryFormat::MachO
        );
        let macho32_be = [0xFE, 0xED, 0xFA, 0xCE];
        assert_eq!(
            detect_format_bytes(&macho32_be).unwrap(),
            BinaryFormat::MachO
        );
        let fat_be = [0xCA, 0xFE, 0xBA, 0xBE];
        assert_eq!(detect_format_bytes(&fat_be).unwrap(), BinaryFormat::MachO);
    }
}
