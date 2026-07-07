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
    #[must_use]
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
    #[must_use]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MemoryPermissions;

    #[test]
    fn test_memory_region_new() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::RWX);
        assert_eq!(region.base, 0x1000);
        assert_eq!(region.size, 0x100);
        assert_eq!(region.data.len(), 0x100);
        assert!(region.data.iter().all(|&b| b == 0));
        assert_eq!(region.permissions, MemoryPermissions::RWX);
        assert!(region.name.is_none());
    }

    #[test]
    fn test_memory_region_with_data() {
        let data = vec![0x41, 0x42, 0x43, 0x44];
        let region = MemoryRegion::with_data(0x2000, data.clone(), MemoryPermissions::READ);
        assert_eq!(region.base, 0x2000);
        assert_eq!(region.size, 4);
        assert_eq!(region.data, data);
        assert_eq!(region.permissions, MemoryPermissions::READ);
    }

    #[test]
    fn test_memory_region_named() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::RW)
            .named("stack");
        assert_eq!(region.name.as_deref(), Some("stack"));
    }

    #[test]
    fn test_memory_region_end() {
        let region = MemoryRegion::new(0x1000, 0x200, MemoryPermissions::READ);
        assert_eq!(region.end(), 0x1200);
    }

    #[test]
    fn test_memory_region_range() {
        let region = MemoryRegion::new(0x1000, 0x200, MemoryPermissions::READ);
        let range = region.range();
        assert_eq!(range.start, 0x1000);
        assert_eq!(range.end, 0x1200);
    }

    #[test]
    fn test_memory_region_contains() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::READ);
        assert!(region.contains(0x1000));  // Start
        assert!(region.contains(0x10FF)); // Last byte
        assert!(!region.contains(0x0FFF)); // Before
        assert!(!region.contains(0x1100)); // After (exclusive end)
    }

    #[test]
    fn test_memory_region_overlaps() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::READ);
        // Overlapping cases
        assert!(region.overlaps(0x1050, 0x20));   // Fully inside
        assert!(region.overlaps(0x0F00, 0x200));   // Spans entire region
        assert!(region.overlaps(0x0FF0, 0x20));    // Overlaps start
        assert!(region.overlaps(0x10F0, 0x20));    // Overlaps end
        // Non-overlapping cases
        assert!(!region.overlaps(0x0F00, 0x100));  // Before region
        assert!(!region.overlaps(0x1100, 0x100));  // After region
        assert!(!region.overlaps(0x0E00, 0x200));  // Ends exactly at start
    }

    #[test]
    fn test_memory_region_read() {
        let data = vec![0x41, 0x42, 0x43, 0x44, 0x45];
        let region = MemoryRegion::with_data(0x1000, data, MemoryPermissions::READ);

        let result = region.read(0x1000, 3).unwrap();
        assert_eq!(result, &[0x41, 0x42, 0x43]);

        let result = region.read(0x1002, 2).unwrap();
        assert_eq!(result, &[0x43, 0x44]);
    }

    #[test]
    fn test_memory_region_read_full() {
        let data = vec![0x01, 0x02, 0x03];
        let region = MemoryRegion::with_data(0x1000, data, MemoryPermissions::READ);
        let result = region.read(0x1000, 3).unwrap();
        assert_eq!(result, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_memory_region_read_out_of_bounds() {
        let region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::READ);
        // Read past end
        assert!(region.read(0x1000, 0x20).is_err());
        // Read before start
        assert!(region.read(0x0FFF, 1).is_err());
        // Read at end boundary
        assert!(region.read(0x1010, 1).is_err());
    }

    #[test]
    fn test_memory_region_write() {
        let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::RW);
        region.write(0x1000, &[0xAA, 0xBB, 0xCC]).unwrap();

        let result = region.read(0x1000, 3).unwrap();
        assert_eq!(result, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_memory_region_write_at_offset() {
        let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::RW);
        region.write(0x1004, &[0x11, 0x22]).unwrap();

        // Bytes before should be 0
        let before = region.read(0x1000, 4).unwrap();
        assert_eq!(before, &[0x00, 0x00, 0x00, 0x00]);

        // Written bytes
        let written = region.read(0x1004, 2).unwrap();
        assert_eq!(written, &[0x11, 0x22]);
    }

    #[test]
    fn test_memory_region_write_out_of_bounds() {
        let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::RW);
        // Write past end
        assert!(region.write(0x1000, &[0u8; 0x20]).is_err());
        // Write before start
        assert!(region.write(0x0FFF, &[0u8]).is_err());
    }

    #[test]
    fn test_memory_region_read_write_roundtrip() {
        let mut region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::RW);
        let test_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        region.write(0x1010, &test_data).unwrap();
        let read_back = region.read(0x1010, test_data.len()).unwrap();
        assert_eq!(read_back, &test_data[..]);
    }

    #[test]
    fn test_memory_snapshot_construction() {
        let snapshot = MemorySnapshot {
            regions: vec![
                MemoryRegion::new(0x1000, 0x100, MemoryPermissions::RW),
                MemoryRegion::new(0x2000, 0x200, MemoryPermissions::RX),
            ],
        };
        assert_eq!(snapshot.regions.len(), 2);
        assert_eq!(snapshot.regions[0].base, 0x1000);
        assert_eq!(snapshot.regions[1].base, 0x2000);
    }

    #[test]
    fn test_memory_region_overlaps_edge_cases() {
        let region = MemoryRegion::new(0x1000, 0x100, MemoryPermissions::READ);
        // Zero-size overlap check at start boundary
        assert!(!region.overlaps(0x1000, 0));
        // Exactly touching at end
        assert!(!region.overlaps(0x1100, 0x10));
        // Exactly touching at start
        assert!(!region.overlaps(0x0F00, 0x100));
    }

    #[test]
    fn test_memory_region_write_overwrite() {
        let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::RW);
        region.write(0x1000, &[0x11, 0x22, 0x33]).unwrap();
        // Overwrite
        region.write(0x1000, &[0xAA, 0xBB]).unwrap();
        let result = region.read(0x1000, 3).unwrap();
        assert_eq!(result, &[0xAA, 0xBB, 0x33]);
    }
}
