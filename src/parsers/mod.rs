//! Binary format parsers.
//!
//! Provides parsers for PE, ELF, Mach-O and other binary formats,
//! using the goblin crate as the primary backend.

pub mod pe;
pub mod elf;
pub mod blob;

pub use pe::PeParser;
pub use elf::ElfParser;
pub use blob::BlobParser;

use crate::error::VivResult;
use std::path::Path;

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    Pe,
    Elf,
    MachO,
    Blob,
    Unknown,
}

/// Detect the format of a binary file.
pub fn detect_format(path: &Path) -> VivResult<BinaryFormat> {
    let data = std::fs::read(path)?;
    detect_format_bytes(&data)
}

/// Detect the format from bytes.
pub fn detect_format_bytes(data: &[u8]) -> VivResult<BinaryFormat> {
    if data.len() < 4 {
        return Ok(BinaryFormat::Unknown);
    }

    // Check magic bytes
    match &data[0..4] {
        // MZ - DOS/PE
        [0x4D, 0x5A, _, _] => Ok(BinaryFormat::Pe),
        // ELF
        [0x7F, 0x45, 0x4C, 0x46] => Ok(BinaryFormat::Elf),
        // Mach-O 32-bit
        [0xFE, 0xED, 0xFA, 0xCE] | [0xCE, 0xFA, 0xED, 0xFE] => Ok(BinaryFormat::MachO),
        // Mach-O 64-bit
        [0xFE, 0xED, 0xFA, 0xCF] | [0xCF, 0xFA, 0xED, 0xFE] => Ok(BinaryFormat::MachO),
        // Mach-O Fat Binary
        [0xCA, 0xFE, 0xBA, 0xBE] | [0xBE, 0xBA, 0xFE, 0xCA] => Ok(BinaryFormat::MachO),
        _ => Ok(BinaryFormat::Unknown),
    }
}
