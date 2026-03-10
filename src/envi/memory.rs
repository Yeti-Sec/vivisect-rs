//! Memory management for the envi layer.

use crate::abstractions::{MemoryAccess, MemoryMap, MemoryRegion, MemorySnapshot};
use crate::constants::MemoryPermissions;
use crate::error::{VivError, VivResult};
use std::collections::BTreeMap;

/// Memory object that manages multiple memory regions.
#[derive(Debug, Clone)]
pub struct MemoryObject {
    /// Memory regions indexed by base address.
    regions: BTreeMap<u64, MemoryRegion>,
}

impl MemoryObject {
    /// Create a new empty memory object.
    pub fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }

    /// Find the region containing an address.
    fn find_region(&self, addr: u64) -> Option<&MemoryRegion> {
        // Find the region with the largest base address <= addr
        self.regions
            .range(..=addr)
            .next_back()
            .map(|(_, r)| r)
            .filter(|r| r.contains(addr))
    }

    /// Find the region containing an address (mutable).
    fn find_region_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        // Find the base address first
        let base = self
            .regions
            .range(..=addr)
            .next_back()
            .filter(|(_, r)| r.contains(addr))
            .map(|(&base, _)| base)?;

        self.regions.get_mut(&base)
    }

    /// Add a memory region with data.
    pub fn add_memory(&mut self, base: u64, data: Vec<u8>, permissions: MemoryPermissions) -> VivResult<()> {
        // Check for overlaps
        let size = data.len();
        for region in self.regions.values() {
            if region.overlaps(base, size) {
                return Err(VivError::InvalidMemory { address: base });
            }
        }

        let region = MemoryRegion::with_data(base, data, permissions);
        self.regions.insert(base, region);
        Ok(())
    }

    /// Iterate over all regions.
    pub fn iter_regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.regions.values()
    }

    /// Get total mapped size.
    pub fn total_size(&self) -> usize {
        self.regions.values().map(|r| r.size).sum()
    }

    /// Get number of regions.
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }
}

impl Default for MemoryObject {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAccess for MemoryObject {
    fn read_memory(&self, addr: u64, size: usize) -> VivResult<Vec<u8>> {
        let region = self
            .find_region(addr)
            .ok_or(VivError::InvalidMemory { address: addr })?;

        let data = region.read(addr, size)?;
        Ok(data.to_vec())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> VivResult<()> {
        let region = self
            .find_region_mut(addr)
            .ok_or(VivError::InvalidMemory { address: addr })?;

        region.write(addr, data)
    }

    fn is_valid_address(&self, addr: u64) -> bool {
        self.find_region(addr).is_some()
    }

    fn get_permissions(&self, addr: u64) -> Option<MemoryPermissions> {
        self.find_region(addr).map(|r| r.permissions)
    }
}

impl MemoryMap for MemoryObject {
    fn add_memory_map(
        &mut self,
        base: u64,
        size: usize,
        permissions: MemoryPermissions,
        name: Option<String>,
    ) -> VivResult<()> {
        // Check for overlaps
        for region in self.regions.values() {
            if region.overlaps(base, size) {
                return Err(VivError::InvalidMemory { address: base });
            }
        }

        let mut region = MemoryRegion::new(base, size, permissions);
        region.name = name;
        self.regions.insert(base, region);
        Ok(())
    }

    fn remove_memory_map(&mut self, base: u64) -> VivResult<()> {
        self.regions
            .remove(&base)
            .ok_or(VivError::InvalidMemory { address: base })?;
        Ok(())
    }

    fn get_memory_maps(&self) -> Vec<(u64, usize, MemoryPermissions, Option<String>)> {
        self.regions
            .values()
            .map(|r| (r.base, r.size, r.permissions, r.name.clone()))
            .collect()
    }

    fn get_memory_map(&self, addr: u64) -> Option<(u64, usize, MemoryPermissions, Option<String>)> {
        self.find_region(addr)
            .map(|r| (r.base, r.size, r.permissions, r.name.clone()))
    }

    fn snapshot_memory(&self) -> MemorySnapshot {
        MemorySnapshot {
            regions: self.regions.values().cloned().collect(),
        }
    }

    fn restore_memory(&mut self, snapshot: &MemorySnapshot) -> VivResult<()> {
        self.regions.clear();
        for region in &snapshot.regions {
            self.regions.insert(region.base, region.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_object() {
        let mut mem = MemoryObject::new();

        // Add a region
        mem.add_memory_map(0x1000, 0x1000, MemoryPermissions::RWX, Some("test".into()))
            .unwrap();

        // Write and read
        mem.write_memory(0x1000, &[0x41, 0x42, 0x43, 0x44]).unwrap();
        let data = mem.read_memory(0x1000, 4).unwrap();
        assert_eq!(data, vec![0x41, 0x42, 0x43, 0x44]);

        // Read u32
        assert_eq!(mem.read_u32_le(0x1000).unwrap(), 0x44434241);
    }

    #[test]
    fn test_invalid_access() {
        let mem = MemoryObject::new();
        assert!(mem.read_memory(0x1000, 4).is_err());
    }
}
