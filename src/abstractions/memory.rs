//! Memory abstraction traits.

use crate::constants::MemoryPermissions;
use crate::error::VivResult;
use std::ops::Range;

/// A contiguous region of memory.
#[derive(Clone, Debug)]
pub struct MemoryRegion {
    /// Base address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: usize,
    /// Memory data.
    pub data: Vec<u8>,
    /// Access permissions.
    pub permissions: MemoryPermissions,
    /// Optional name/label for this region.
    pub name: Option<String>,
}

impl MemoryRegion {
    /// Create a new memory region.
    pub fn new(base: u64, size: usize, permissions: MemoryPermissions) -> Self {
        Self {
            base,
            size,
            data: vec![0u8; size],
            permissions,
            name: None,
        }
    }

    /// Create a memory region with data.
    pub fn with_data(base: u64, data: Vec<u8>, permissions: MemoryPermissions) -> Self {
        let size = data.len();
        Self {
            base,
            size,
            data,
            permissions,
            name: None,
        }
    }

    /// Create a named memory region.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the end address of this region.
    pub fn end(&self) -> u64 {
        self.base + self.size as u64
    }

    /// Get the address range.
    pub fn range(&self) -> Range<u64> {
        self.base..self.end()
    }

    /// Check if address is within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Check if an address range overlaps with this region.
    pub fn overlaps(&self, base: u64, size: usize) -> bool {
        let end = base + size as u64;
        !(end <= self.base || base >= self.end())
    }

    /// Read bytes from this region.
    pub fn read(&self, addr: u64, size: usize) -> VivResult<&[u8]> {
        if !self.contains(addr) {
            return Err(crate::error::VivError::InvalidMemory { address: addr });
        }
        let offset = (addr - self.base) as usize;
        let end = offset.checked_add(size).ok_or(crate::error::VivError::InvalidMemory { address: addr })?;
        if end > self.data.len() || end > self.size {
            return Err(crate::error::VivError::InvalidMemory { address: addr });
        }
        Ok(&self.data[offset..end])
    }

    /// Write bytes to this region.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> VivResult<()> {
        if !self.contains(addr) {
            return Err(crate::error::VivError::InvalidMemory { address: addr });
        }
        let offset = (addr - self.base) as usize;
        let end = offset.checked_add(data.len()).ok_or(crate::error::VivError::InvalidMemory { address: addr })?;
        if end > self.data.len() || end > self.size {
            return Err(crate::error::VivError::InvalidMemory { address: addr });
        }
        self.data[offset..end].copy_from_slice(data);
        Ok(())
    }
}

/// Memory snapshot for save/restore.
#[derive(Clone, Debug)]
pub struct MemorySnapshot {
    pub regions: Vec<MemoryRegion>,
}

/// Trait for objects that provide memory access.
pub trait MemoryAccess: Send + Sync {
    /// Read bytes from memory.
    fn read_memory(&self, addr: u64, size: usize) -> VivResult<Vec<u8>>;

    /// Write bytes to memory.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> VivResult<()>;

    /// Check if address is mapped.
    fn is_valid_address(&self, addr: u64) -> bool;

    /// Get memory permissions at address.
    fn get_permissions(&self, addr: u64) -> Option<MemoryPermissions>;

    /// Read a u8 from memory.
    fn read_u8(&self, addr: u64) -> VivResult<u8> {
        let bytes = self.read_memory(addr, 1)?;
        Ok(bytes[0])
    }

    /// Read a little-endian u16 from memory.
    fn read_u16_le(&self, addr: u64) -> VivResult<u16> {
        let bytes = self.read_memory(addr, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian u32 from memory.
    fn read_u32_le(&self, addr: u64) -> VivResult<u32> {
        let bytes = self.read_memory(addr, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian u64 from memory.
    fn read_u64_le(&self, addr: u64) -> VivResult<u64> {
        let bytes = self.read_memory(addr, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Write a u8 to memory.
    fn write_u8(&mut self, addr: u64, value: u8) -> VivResult<()> {
        self.write_memory(addr, &[value])
    }

    /// Write a little-endian u16 to memory.
    fn write_u16_le(&mut self, addr: u64, value: u16) -> VivResult<()> {
        self.write_memory(addr, &value.to_le_bytes())
    }

    /// Write a little-endian u32 to memory.
    fn write_u32_le(&mut self, addr: u64, value: u32) -> VivResult<()> {
        self.write_memory(addr, &value.to_le_bytes())
    }

    /// Write a little-endian u64 to memory.
    fn write_u64_le(&mut self, addr: u64, value: u64) -> VivResult<()> {
        self.write_memory(addr, &value.to_le_bytes())
    }
}

/// Trait for objects that manage memory maps.
pub trait MemoryMap: MemoryAccess {
    /// Add a memory region.
    fn add_memory_map(&mut self, base: u64, size: usize, permissions: MemoryPermissions, name: Option<String>) -> VivResult<()>;

    /// Remove a memory region.
    fn remove_memory_map(&mut self, base: u64) -> VivResult<()>;

    /// Get all memory regions.
    fn get_memory_maps(&self) -> Vec<(u64, usize, MemoryPermissions, Option<String>)>;

    /// Get the memory region containing an address.
    fn get_memory_map(&self, addr: u64) -> Option<(u64, usize, MemoryPermissions, Option<String>)>;

    /// Take a snapshot of all memory.
    fn snapshot_memory(&self) -> MemorySnapshot;

    /// Restore from a memory snapshot.
    fn restore_memory(&mut self, snapshot: &MemorySnapshot) -> VivResult<()>;
}
