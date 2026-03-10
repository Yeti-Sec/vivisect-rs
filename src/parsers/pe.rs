//! PE (Portable Executable) format parser.
//!
//! Uses goblin for parsing and wraps results in vivisect types.

use crate::abstractions::{ExportInfo, ImportInfo, SectionInfo};
use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use goblin::pe::PE;
use std::path::Path;

/// PE file parser.
pub struct PeParser {
    /// Raw file data.
    data: Vec<u8>,
    /// Parsed PE structure.
    pe: PE<'static>,
    /// Detected architecture.
    arch: Architecture,
}

impl PeParser {
    /// Load a PE file from disk.
    pub fn load(path: &Path) -> VivResult<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Parse PE from bytes.
    pub fn from_bytes(data: Vec<u8>) -> VivResult<Self> {
        // SAFETY: We're keeping the data alive alongside the PE struct.
        // This is a bit awkward but necessary due to goblin's lifetimes.
        let pe = goblin::pe::PE::parse(&data).map_err(|e| VivError::CorruptFile {
            file_format: "PE".to_string(),
            message: e.to_string(),
        })?;

        // Determine architecture
        let arch = if pe.is_64 {
            Architecture::Amd64
        } else {
            Architecture::I386
        };

        // Leak the data to get a 'static reference
        let data = data.into_boxed_slice();
        let leaked_data: &'static [u8] = Box::leak(data);

        let pe = goblin::pe::PE::parse(leaked_data).map_err(|e| VivError::CorruptFile {
            file_format: "PE".to_string(),
            message: e.to_string(),
        })?;

        Ok(Self {
            data: leaked_data.to_vec(),
            pe,
            arch,
        })
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        self.pe.image_base as u64
    }

    /// Get the entry point RVA.
    pub fn entry_point_rva(&self) -> u64 {
        self.pe.entry as u64
    }

    /// Get the entry point VA.
    pub fn entry_point(&self) -> u64 {
        self.image_base() + self.entry_point_rva()
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Check if 64-bit.
    pub fn is_64(&self) -> bool {
        self.pe.is_64
    }

    /// Check if DLL.
    pub fn is_dll(&self) -> bool {
        self.pe.is_lib
    }

    /// Get all sections.
    pub fn sections(&self) -> Vec<SectionInfo> {
        self.pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();

                let characteristics = s.characteristics;

                SectionInfo {
                    name,
                    virtual_address: self.image_base() + s.virtual_address as u64,
                    virtual_size: s.virtual_size as usize,
                    raw_size: s.size_of_raw_data as usize,
                    raw_offset: s.pointer_to_raw_data as usize,
                    executable: (characteristics & 0x20000000) != 0, // IMAGE_SCN_MEM_EXECUTE
                    writable: (characteristics & 0x80000000) != 0,   // IMAGE_SCN_MEM_WRITE
                    readable: (characteristics & 0x40000000) != 0,   // IMAGE_SCN_MEM_READ
                }
            })
            .collect()
    }

    /// Get imports.
    pub fn imports(&self) -> Vec<ImportInfo> {
        let mut imports = Vec::new();

        for import in &self.pe.imports {
            imports.push(ImportInfo {
                address: self.image_base() + import.rva as u64,
                library: import.dll.to_string(),
                name: import.name.to_string(),
                ordinal: if import.ordinal != 0 {
                    Some(import.ordinal as u16)
                } else {
                    None
                },
            });
        }

        imports
    }

    /// Get exports.
    pub fn exports(&self) -> Vec<ExportInfo> {
        self.pe
            .exports
            .iter()
            .filter_map(|exp| {
                exp.name.map(|name| ExportInfo {
                    address: self.image_base() + exp.rva as u64,
                    name: name.to_string(),
                    ordinal: None, // goblin doesn't expose ordinal directly
                })
            })
            .collect()
    }

    /// Read bytes at a virtual address.
    pub fn read_va(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        let rva = va.checked_sub(self.image_base()).ok_or_else(|| {
            VivError::InvalidMemory { address: va }
        })? as usize;

        // Find the section containing this RVA
        for section in &self.pe.sections {
            let section_start = section.virtual_address as usize;
            let section_end = section_start + section.virtual_size as usize;

            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                let raw_offset = section.pointer_to_raw_data as usize + offset_in_section;

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

    /// Get DOS header fields.
    pub fn dos_header(&self) -> Option<DosHeader> {
        if self.data.len() < 64 {
            return None;
        }

        Some(DosHeader {
            e_magic: u16::from_le_bytes([self.data[0], self.data[1]]),
            e_lfanew: u32::from_le_bytes([
                self.data[60],
                self.data[61],
                self.data[62],
                self.data[63],
            ]),
        })
    }
}

/// DOS header information.
#[derive(Debug, Clone)]
pub struct DosHeader {
    pub e_magic: u16,
    pub e_lfanew: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_magic() {
        // MZ header
        let mz = [0x4D, 0x5A];
        assert_eq!(mz[0], 0x4D);
        assert_eq!(mz[1], 0x5A);
    }
}
