//! Blob (raw binary) parser.
//!
//! For analyzing raw binary data without file format metadata.

use crate::constants::Architecture;
use crate::error::{VivError, VivResult};
use std::path::Path;

/// Raw binary blob parser.
pub struct BlobParser {
    /// Raw data.
    data: Vec<u8>,
    /// Base address.
    base_address: u64,
    /// Architecture.
    arch: Architecture,
}

impl BlobParser {
    /// Load a blob from disk.
    #[must_use]
    pub fn load(path: &Path, base_address: u64, arch: Architecture) -> VivResult<Self> {
        let data = super::read_file_limited(path, super::DEFAULT_MAX_FILE_SIZE)?;
        Ok(Self::from_bytes(data, base_address, arch))
    }

    /// Create a blob from bytes.
    pub fn from_bytes(data: Vec<u8>, base_address: u64, arch: Architecture) -> Self {
        Self {
            data,
            base_address,
            arch,
        }
    }

    /// Get the base address.
    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Get the size.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get the end address.
    pub fn end_address(&self) -> u64 {
        self.base_address + self.data.len() as u64
    }

    /// Read bytes at a virtual address.
    #[must_use]
    pub fn read_va(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        if va < self.base_address {
            return Err(VivError::InvalidMemory { address: va });
        }

        let offset = (va - self.base_address) as usize;
        let end = offset
            .checked_add(size)
            .ok_or(VivError::InvalidMemory { address: va })?;
        if end > self.data.len() {
            return Err(VivError::InvalidMemory { address: va });
        }

        Ok(self.data[offset..end].to_vec())
    }

    /// Check if address is valid.
    pub fn is_valid(&self, va: u64) -> bool {
        va >= self.base_address && va < self.end_address()
    }

    /// Get the raw data.
    pub fn raw_data(&self) -> &[u8] {
        &self.data
    }
}
