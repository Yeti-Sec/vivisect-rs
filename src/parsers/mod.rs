//! Binary format parsers.
//!
//! Provides parsers for PE, ELF, Mach-O and other binary formats,
//! using the goblin crate as the primary backend.

pub mod blob;
pub mod elf;
pub mod macho;
pub mod pe;

pub use blob::BlobParser;
pub use elf::ElfParser;
pub use macho::MachOParser;
pub use pe::PeParser;

use crate::error::{VivError, VivResult};
use std::path::Path;

/// Default maximum file size for binary input (512 MB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Read a file with a size limit check before allocation.
///
/// Prevents OOM from adversarial or oversized inputs by checking
/// `std::fs::metadata` before reading.
#[must_use]
pub fn read_file_limited(path: &Path, max_size: u64) -> VivResult<Vec<u8>> {
    let metadata = std::fs::metadata(path)?;
    let file_size = metadata.len();
    if file_size > max_size {
        return Err(VivError::Other {
            message: format!(
                "File too large: {} bytes (limit: {} bytes). Path: {}",
                file_size,
                max_size,
                path.display()
            ),
        });
    }
    Ok(std::fs::read(path)?)
}

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
#[must_use]
pub fn detect_format(path: &Path) -> VivResult<BinaryFormat> {
    let data = read_file_limited(path, DEFAULT_MAX_FILE_SIZE)?;
    detect_format_bytes(&data)
}

/// Detect the format from bytes.
#[must_use]
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
