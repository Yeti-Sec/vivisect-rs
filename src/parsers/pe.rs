//! PE (Portable Executable) format parser.
//!
//! Uses goblin for parsing and wraps results in vivisect types.
//! All data is extracted from goblin's borrowed PE struct during construction,
//! then the borrow is dropped — no leaked or self-referential data.

use crate::abstractions::{ExportInfo, ImportInfo, SectionInfo};
use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use goblin::pe::{options::ParseOptions, PE};
use std::path::Path;

/// Owned copy of a PE section header (goblin's SectionTable borrows the file).
#[derive(Debug, Clone)]
struct PeSectionHeader {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
    characteristics: u32,
}

/// Extracted data-directory entry (RVA + size).
#[derive(Debug, Clone, Copy)]
struct DataDirEntry {
    virtual_address: u32,
    size: u32,
}

/// PE file parser.
///
/// Stores only owned data — no lifetime dependency on goblin after construction.
pub struct PeParser {
    data: Vec<u8>,
    arch: Architecture,
    image_base: u64,
    entry_rva: u64,
    is_64: bool,
    is_lib: bool,
    sections: Vec<PeSectionHeader>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    additional_entries: Vec<u64>,
    header_size: usize,
}

/// Parse a PE from bytes, retrying without Authenticode certificate parsing if the
/// security directory entry is malformed (common in packed/trojan PE files).
fn pe_parse(data: &[u8]) -> Result<PE<'_>, goblin::error::Error> {
    match PE::parse(data) {
        Ok(pe) => Ok(pe),
        Err(goblin::error::Error::Malformed(msg)) if msg.contains("cert") => {
            let mut opts = ParseOptions::default();
            opts.parse_attribute_certificates = false;
            PE::parse_with_opts(data, &opts)
        }
        Err(e) => Err(e),
    }
}

/// Read bytes at a virtual address using raw data and section headers.
fn read_va_raw(
    data: &[u8],
    sections: &[PeSectionHeader],
    image_base: u64,
    va: u64,
    size: usize,
) -> VivResult<Vec<u8>> {
    let rva = va
        .checked_sub(image_base)
        .ok_or(VivError::InvalidMemory { address: va })? as usize;

    for section in sections {
        let section_start = section.virtual_address as usize;
        let section_end = section_start.saturating_add(section.virtual_size as usize);

        if rva >= section_start && rva < section_end {
            let offset_in_section = rva - section_start;
            let raw_offset = (section.pointer_to_raw_data as usize)
                .checked_add(offset_in_section)
                .ok_or(VivError::InvalidMemory { address: va })?;
            let end = raw_offset
                .checked_add(size)
                .ok_or(VivError::InvalidMemory { address: va })?;

            if end <= data.len() {
                return Ok(data[raw_offset..end].to_vec());
            }
        }
    }

    Err(VivError::InvalidMemory { address: va })
}

/// Build the normalized in-memory image bytes for a mapped region
/// (review finding #4):
///
/// - copy the raw bytes up to the *valid* raw size,
/// - zero-fill the remainder up to `virtual_size`,
/// - clamp raw spans that run past end-of-file (never read past the buffer),
/// - a raw size larger than the virtual size is truncated to the virtual size.
///
/// Returns exactly `virtual_size` bytes (empty when `virtual_size == 0`).
pub(crate) fn normalize_mapped_image(
    data: &[u8],
    raw_offset: usize,
    raw_size: usize,
    virtual_size: usize,
) -> Vec<u8> {
    if virtual_size == 0 {
        return Vec::new();
    }
    let mut bytes = vec![0u8; virtual_size];
    let avail = data.len().saturating_sub(raw_offset);
    let copy = raw_size.min(virtual_size).min(avail);
    if copy > 0 {
        bytes[..copy].copy_from_slice(&data[raw_offset..raw_offset + copy]);
    }
    bytes
}

/// Extract imports using IAT addresses from goblin's import data.
fn extract_imports_iat(pe: &PE<'_>, image_base: u64) -> Option<Vec<ImportInfo>> {
    let import_data = pe.import_data.as_ref()?;
    let ptr_size: usize = if pe.is_64 { 8 } else { 4 };
    let mut imports = Vec::new();

    for desc in &import_data.import_data {
        let dll_name = desc.name.to_string();
        let iat_rva = desc.import_directory_entry.import_address_table_rva as u64;
        let lookup_table = match desc.import_lookup_table.as_ref() {
            Some(lt) => lt,
            None => continue,
        };

        for (i, entry) in lookup_table.iter().enumerate() {
            let iat_entry_va = image_base + iat_rva + (i as u64 * ptr_size as u64);

            use goblin::pe::import::SyntheticImportLookupTableEntry;
            let (name, ordinal) = match entry {
                SyntheticImportLookupTableEntry::HintNameTableRVA((_rva, hint_entry)) => {
                    (hint_entry.name.to_string(), None)
                }
                SyntheticImportLookupTableEntry::OrdinalNumber(ord) => {
                    (format!("ORDINAL {}", ord), Some(*ord))
                }
            };

            imports.push(ImportInfo {
                address: iat_entry_va,
                library: dll_name.clone(),
                name,
                ordinal,
            });
        }
    }

    Some(imports)
}

/// Fallback: extract imports from goblin (uses ILT addresses).
fn extract_imports_goblin(pe: &PE<'_>, image_base: u64) -> Vec<ImportInfo> {
    pe.imports
        .iter()
        .map(|import| ImportInfo {
            address: image_base + import.rva as u64,
            library: import.dll.to_string(),
            name: import.name.to_string(),
            ordinal: if import.ordinal != 0 {
                Some(import.ordinal)
            } else {
                None
            },
        })
        .collect()
}

/// Discover additional entry points (TLS callbacks, CRT initializers, SafeSEH, .pdata).
fn extract_additional_entries(
    data: &[u8],
    sections: &[PeSectionHeader],
    image_base: u64,
    is_64: bool,
    tls_dir: Option<DataDirEntry>,
    load_config_dir: Option<DataDirEntry>,
    exception_dir: Option<DataDirEntry>,
) -> Vec<u64> {
    let mut entries = Vec::new();

    // TLS callbacks
    if let Some(tls_dd) = tls_dir {
        if tls_dd.virtual_address != 0 {
            let tls_rva = tls_dd.virtual_address as u64;
            let ptr_size = if is_64 { 8usize } else { 4 };
            let callbacks_field_offset = if is_64 { 24usize } else { 12 };
            if let Ok(tls_bytes) = read_va_raw(
                data,
                sections,
                image_base,
                image_base + tls_rva,
                callbacks_field_offset + ptr_size,
            ) {
                let callbacks_va = if is_64 {
                    u64::from_le_bytes(
                        tls_bytes[callbacks_field_offset..callbacks_field_offset + 8]
                            .try_into()
                            .unwrap_or([0; 8]),
                    )
                } else {
                    u32::from_le_bytes(
                        tls_bytes[callbacks_field_offset..callbacks_field_offset + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    ) as u64
                };

                if callbacks_va != 0 {
                    for i in 0..64u64 {
                        let cb_addr = callbacks_va + (i * ptr_size as u64);
                        if let Ok(cb_bytes) =
                            read_va_raw(data, sections, image_base, cb_addr, ptr_size)
                        {
                            let cb_va = if is_64 {
                                u64::from_le_bytes(cb_bytes.try_into().unwrap_or([0; 8]))
                            } else {
                                u32::from_le_bytes(cb_bytes[..4].try_into().unwrap_or([0; 4]))
                                    as u64
                            };
                            if cb_va == 0 {
                                break;
                            }
                            entries.push(cb_va);
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    // CRT initializer tables in .rdata
    let section_infos: Vec<SectionInfo> = sections
        .iter()
        .map(|s| SectionInfo {
            name: String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string(),
            virtual_address: image_base + s.virtual_address as u64,
            virtual_size: s.virtual_size as usize,
            raw_size: s.size_of_raw_data as usize,
            raw_offset: s.pointer_to_raw_data as usize,
            executable: (s.characteristics & 0x20000000) != 0,
            writable: (s.characteristics & 0x80000000) != 0,
            readable: (s.characteristics & 0x40000000) != 0,
        })
        .collect();

    let text_ranges: Vec<(u64, u64)> = section_infos
        .iter()
        .filter(|s| s.executable)
        .map(|s| (s.virtual_address, s.virtual_address + s.virtual_size as u64))
        .collect();

    if !text_ranges.is_empty() {
        let ptr_size = if is_64 { 8usize } else { 4usize };

        for section in &section_infos {
            if section.name.to_lowercase() != ".rdata" {
                continue;
            }

            let sec_data = match read_va_raw(
                data,
                sections,
                image_base,
                section.virtual_address,
                section.raw_size,
            ) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut consecutive_ptrs = 0u32;
            for offset in (0..sec_data.len().saturating_sub(ptr_size)).step_by(ptr_size) {
                let ptr_val = if ptr_size == 8 {
                    u64::from_le_bytes(sec_data[offset..offset + 8].try_into().unwrap_or([0; 8]))
                } else {
                    u32::from_le_bytes(sec_data[offset..offset + 4].try_into().unwrap_or([0; 4]))
                        as u64
                };

                let in_text = text_ranges
                    .iter()
                    .any(|(start, end)| ptr_val >= *start && ptr_val < *end);

                if in_text && ptr_val != 0 {
                    consecutive_ptrs += 1;
                    if consecutive_ptrs >= 2 {
                        entries.push(ptr_val);
                    }
                } else {
                    consecutive_ptrs = 0;
                }
            }
        }
    }

    // SafeSEH handler table
    if let Some(lc_dd) = load_config_dir {
        if lc_dd.virtual_address != 0 {
            let ptr_size = if is_64 { 8usize } else { 4usize };
            let seh_off = if is_64 { 0x60usize } else { 0x40usize };
            let min_size = seh_off + 2 * ptr_size;
            let lc_va = image_base + lc_dd.virtual_address as u64;

            if let Ok(lc_bytes) = read_va_raw(data, sections, image_base, lc_va, min_size) {
                let struct_size =
                    u32::from_le_bytes(lc_bytes[0..4].try_into().unwrap_or([0; 4])) as usize;

                if struct_size >= min_size {
                    let read_ptr = |off: usize| -> u64 {
                        if ptr_size == 8 {
                            u64::from_le_bytes(lc_bytes[off..off + 8].try_into().unwrap_or([0; 8]))
                        } else {
                            u32::from_le_bytes(lc_bytes[off..off + 4].try_into().unwrap_or([0; 4]))
                                as u64
                        }
                    };
                    let table_va = read_ptr(seh_off);
                    let count = read_ptr(seh_off + ptr_size);

                    if table_va != 0 && count > 0 && count < 1024 {
                        for i in 0..count {
                            let addr = table_va + i * ptr_size as u64;
                            if let Ok(eb) = read_va_raw(data, sections, image_base, addr, ptr_size)
                            {
                                let rva = if ptr_size == 8 {
                                    u64::from_le_bytes(eb.try_into().unwrap_or([0; 8]))
                                } else {
                                    u32::from_le_bytes(eb[..4].try_into().unwrap_or([0; 4])) as u64
                                };
                                if rva != 0 {
                                    entries.push(image_base + rva);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // AMD64 .pdata exception directory
    if is_64 {
        if let Some(exc_dd) = exception_dir {
            if exc_dd.virtual_address != 0 && exc_dd.size >= 12 {
                let exc_va = image_base + exc_dd.virtual_address as u64;
                let exc_end = exc_va + exc_dd.size as u64;
                let mut va = exc_va;

                while va + 12 <= exc_end {
                    let entry = match read_va_raw(data, sections, image_base, va, 12) {
                        Ok(b) => b,
                        Err(_) => break,
                    };

                    let begin_rva =
                        u32::from_le_bytes(entry[0..4].try_into().unwrap_or([0; 4])) as u64;
                    let unwind_rva =
                        u32::from_le_bytes(entry[8..12].try_into().unwrap_or([0; 4])) as u64;

                    if begin_rva == 0 || unwind_rva == 0 {
                        break;
                    }

                    let unwind_va = image_base + unwind_rva;
                    if let Ok(ui_bytes) = read_va_raw(data, sections, image_base, unwind_va, 1) {
                        let ver_flags = ui_bytes[0];
                        let version = ver_flags & 0x07;
                        let flags = ver_flags >> 3;
                        const UNW_FLAG_CHAININFO: u8 = 0x04;

                        if version == 1 && (flags & UNW_FLAG_CHAININFO) == 0 {
                            entries.push(image_base + begin_rva);
                        }
                    }

                    va += 12;
                }
            }
        }
    }

    entries.sort_unstable();
    entries.dedup();
    entries
}

impl PeParser {
    /// Load a PE file from disk.
    #[must_use]
    pub fn load(path: &Path) -> VivResult<Self> {
        let data = super::read_file_limited(path, super::DEFAULT_MAX_FILE_SIZE)?;
        Self::from_bytes(data)
    }

    /// Parse PE from bytes.
    ///
    /// Extracts all needed data from goblin's borrowed `PE` struct, then drops
    /// the borrow. No `Box::leak` or self-referential structs needed.
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> VivResult<Self> {
        let pe = pe_parse(&data).map_err(|e| VivError::CorruptFile {
            file_format: "PE".to_string(),
            message: e.to_string(),
        })?;

        let arch = if pe.is_64 {
            Architecture::Amd64
        } else {
            Architecture::I386
        };

        let image_base = pe.image_base as u64;
        let entry_rva = pe.entry as u64;
        let is_64 = pe.is_64;
        let is_lib = pe.is_lib;

        let header_size = pe
            .header
            .optional_header
            .map(|oh| oh.windows_fields.size_of_headers as usize)
            .unwrap_or(0x1000);

        let sections: Vec<PeSectionHeader> = pe
            .sections
            .iter()
            .map(|s| PeSectionHeader {
                name: s.name,
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                pointer_to_raw_data: s.pointer_to_raw_data,
                size_of_raw_data: s.size_of_raw_data,
                characteristics: s.characteristics,
            })
            .collect();

        let imports = extract_imports_iat(&pe, image_base)
            .unwrap_or_else(|| extract_imports_goblin(&pe, image_base));

        let exports: Vec<ExportInfo> = pe
            .exports
            .iter()
            .filter_map(|exp| {
                exp.name.map(|name| ExportInfo {
                    address: image_base + exp.rva as u64,
                    name: name.to_string(),
                    ordinal: None,
                })
            })
            .collect();

        let tls_dir = pe.header.optional_header.and_then(|oh| {
            oh.data_directories.get_tls_table().map(|dd| DataDirEntry {
                virtual_address: dd.virtual_address,
                size: dd.size,
            })
        });
        let load_config_dir = pe.header.optional_header.and_then(|oh| {
            oh.data_directories
                .get_load_config_table()
                .map(|dd| DataDirEntry {
                    virtual_address: dd.virtual_address,
                    size: dd.size,
                })
        });
        let exception_dir = pe.header.optional_header.and_then(|oh| {
            oh.data_directories
                .get_exception_table()
                .map(|dd| DataDirEntry {
                    virtual_address: dd.virtual_address,
                    size: dd.size,
                })
        });

        // Drop the PE borrow — all data has been extracted into owned fields.
        drop(pe);

        let additional_entries = extract_additional_entries(
            &data,
            &sections,
            image_base,
            is_64,
            tls_dir,
            load_config_dir,
            exception_dir,
        );

        Ok(Self {
            data,
            arch,
            image_base,
            entry_rva,
            is_64,
            is_lib,
            sections,
            imports,
            exports,
            additional_entries,
            header_size,
        })
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the entry point RVA.
    pub fn entry_point_rva(&self) -> u64 {
        self.entry_rva
    }

    /// Get the entry point VA.
    pub fn entry_point(&self) -> u64 {
        self.image_base + self.entry_rva
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Check if 64-bit.
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Check if DLL.
    pub fn is_dll(&self) -> bool {
        self.is_lib
    }

    /// Get all sections.
    pub fn sections(&self) -> Vec<SectionInfo> {
        self.sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();

                SectionInfo {
                    name,
                    virtual_address: self.image_base + s.virtual_address as u64,
                    virtual_size: s.virtual_size as usize,
                    raw_size: s.size_of_raw_data as usize,
                    raw_offset: s.pointer_to_raw_data as usize,
                    executable: (s.characteristics & 0x20000000) != 0,
                    writable: (s.characteristics & 0x80000000) != 0,
                    readable: (s.characteristics & 0x40000000) != 0,
                }
            })
            .collect()
    }

    /// Get imports using IAT (Import Address Table) addresses.
    pub fn imports(&self) -> Vec<ImportInfo> {
        self.imports.clone()
    }

    /// Get exports.
    pub fn exports(&self) -> Vec<ExportInfo> {
        self.exports.clone()
    }

    /// Get the raw data.
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }

    /// Get the size of the PE headers (for loading as a memory segment).
    pub fn header_size(&self) -> usize {
        self.header_size
    }

    /// Discover additional entry points beyond the PE header entry.
    ///
    /// Returns TLS callbacks, CRT initializer addresses, SafeSEH handlers,
    /// and .pdata exception entries. Computed during construction.
    pub fn additional_entry_points(&self) -> Vec<u64> {
        self.additional_entries.clone()
    }

    /// Get DOS header fields.
    #[must_use]
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

    // --- Mapped-memory normalization (#4) ---------------------------------

    #[test]
    fn normalize_zero_fills_virtual_tail() {
        // raw_size 4 < virtual_size 8 → 4 raw bytes then 4 zero bytes.
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let img = normalize_mapped_image(&data, 0, 4, 8);
        assert_eq!(img, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn normalize_truncates_raw_larger_than_virtual() {
        // raw_size 8 > virtual_size 4 → only 4 bytes mapped.
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let img = normalize_mapped_image(&data, 0, 8, 4);
        assert_eq!(img, vec![1, 2, 3, 4]);
    }

    #[test]
    fn normalize_clamps_out_of_file_raw_span() {
        // raw_offset points near EOF and raw_size claims more than is present:
        // copy only what's available, zero-fill the rest to virtual_size.
        let data = vec![0x10, 0x20, 0x30]; // 3 bytes
        let img = normalize_mapped_image(&data, 1, 100, 6);
        // available from offset 1 = [0x20, 0x30]; rest zero-filled to 6.
        assert_eq!(img, vec![0x20, 0x30, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn normalize_offset_past_eof_is_all_zero() {
        let data = vec![1, 2, 3];
        let img = normalize_mapped_image(&data, 10, 4, 4);
        assert_eq!(img, vec![0, 0, 0, 0]);
    }

    #[test]
    fn normalize_zero_virtual_size_is_empty() {
        let data = vec![1, 2, 3, 4];
        assert!(normalize_mapped_image(&data, 0, 4, 0).is_empty());
    }

    #[test]
    fn normalize_bss_style_no_raw_bytes() {
        // A .bss-style section: raw_size 0, virtual_size 0x10 → all zero, mapped.
        let data = vec![0xFFu8; 32];
        let img = normalize_mapped_image(&data, 0, 0, 0x10);
        assert_eq!(img.len(), 0x10);
        assert!(img.iter().all(|&b| b == 0));
    }
}
