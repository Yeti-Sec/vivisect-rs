//! Memory management for the envi layer.

use crate::abstractions::{MemoryAccess, MemoryMap, MemoryRegion, MemorySnapshot};
use crate::constants::{Endian, MemoryPermissions};
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

    /// Get the region containing an address, if any.
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.find_region(addr)
    }

    /// Add a memory region with data.
    #[must_use]
    pub fn add_memory(
        &mut self,
        base: u64,
        data: Vec<u8>,
        permissions: MemoryPermissions,
    ) -> VivResult<()> {
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

    /// Add a memory region with data and an optional name/label.
    ///
    /// Like [`add_memory`](Self::add_memory) but preserves the region name, which
    /// is required for a faithful persistence round-trip.
    #[must_use]
    pub fn add_named_memory(
        &mut self,
        base: u64,
        data: Vec<u8>,
        permissions: MemoryPermissions,
        name: Option<String>,
    ) -> VivResult<()> {
        let size = data.len();
        for region in self.regions.values() {
            if region.overlaps(base, size) {
                return Err(VivError::InvalidMemory { address: base });
            }
        }
        let mut region = MemoryRegion::with_data(base, data, permissions);
        region.name = name;
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

/// The single authoritative mapped-memory representation for a workspace.
///
/// `MemoryImage` owns the normalized region set **and** the endianness, and is
/// the one place bytes enter memory (via [`map_normalized`](Self::map_normalized),
/// which wraps `normalize_mapped_image`) and the one place they are read
/// (`read`/`read_ptr`/`region_at`). Loaders, workspace construction, analysis,
/// emulation, and persistence all derive from this same image, so the mapped
/// bytes, permissions, zero-fill, and endian cannot drift between subsystems
/// (roadmap Phase 4 / §2.1 unified memory contract).
#[derive(Debug, Clone)]
pub struct MemoryImage {
    mem: MemoryObject,
    endian: Endian,
}

impl MemoryImage {
    /// Create an empty image with the given endianness.
    pub fn new(endian: Endian) -> Self {
        Self {
            mem: MemoryObject::new(),
            endian,
        }
    }

    /// The image endianness (honored by the typed reads).
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Set the endianness (loaders/restore).
    pub fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }

    /// The single mapping entry point: copy `raw_size` bytes from `source` at
    /// `raw_offset`, zero-fill to `virtual_size`, clamp out-of-file spans, and
    /// map the result at `base` with `perms`/`name`. This is the ONLY way region
    /// bytes are produced, so every format gets identical zero-fill/`.bss`
    /// semantics. Errors on overlap (never silently dropped).
    #[must_use]
    pub fn map_normalized(
        &mut self,
        base: u64,
        source: &[u8],
        raw_offset: usize,
        raw_size: usize,
        virtual_size: usize,
        perms: MemoryPermissions,
        name: Option<String>,
    ) -> VivResult<()> {
        let bytes =
            crate::parsers::pe::normalize_mapped_image(source, raw_offset, raw_size, virtual_size);
        if bytes.is_empty() {
            return Ok(());
        }
        self.mem.add_named_memory(base, bytes, perms, name)
    }

    /// Map already-normalized bytes verbatim (used by persistence restore, where
    /// the bytes were normalized when first mapped).
    #[must_use]
    pub fn map_verbatim(
        &mut self,
        base: u64,
        data: Vec<u8>,
        perms: MemoryPermissions,
        name: Option<String>,
    ) -> VivResult<()> {
        self.mem.add_named_memory(base, data, perms, name)
    }

    /// Read `size` bytes at `addr` (all-or-nothing, within a single region).
    #[must_use]
    pub fn read(&self, addr: u64, size: usize) -> VivResult<Vec<u8>> {
        self.mem.read_memory(addr, size)
    }

    /// Write bytes at `addr`.
    #[must_use]
    pub fn write(&mut self, addr: u64, data: &[u8]) -> VivResult<()> {
        self.mem.write_memory(addr, data)
    }

    /// Read a u16 honoring the image endianness.
    #[must_use]
    pub fn read_u16(&self, addr: u64) -> VivResult<u16> {
        let b = self.read(addr, 2)?;
        let a = [b[0], b[1]];
        Ok(if self.endian.is_big() {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        })
    }

    /// Read a u32 honoring the image endianness.
    #[must_use]
    pub fn read_u32(&self, addr: u64) -> VivResult<u32> {
        let b = self.read(addr, 4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Ok(if self.endian.is_big() {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        })
    }

    /// Read a u64 honoring the image endianness.
    #[must_use]
    pub fn read_u64(&self, addr: u64) -> VivResult<u64> {
        let b = self.read(addr, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        Ok(if self.endian.is_big() {
            u64::from_be_bytes(a)
        } else {
            u64::from_le_bytes(a)
        })
    }

    /// Read a pointer of `width` (4 or 8) bytes honoring the image endianness.
    #[must_use]
    pub fn read_ptr(&self, addr: u64, width: usize) -> VivResult<u64> {
        match width {
            4 => Ok(self.read_u32(addr)? as u64),
            8 => self.read_u64(addr),
            _ => Err(VivError::InvalidMemory { address: addr }),
        }
    }

    /// Permissions of the region containing `addr`.
    pub fn permissions(&self, addr: u64) -> Option<MemoryPermissions> {
        self.mem.get_permissions(addr)
    }

    /// Whether `addr` is mapped.
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.mem.is_valid_address(addr)
    }

    /// Whether the region containing `addr` is executable.
    pub fn is_executable(&self, addr: u64) -> bool {
        self.permissions(addr)
            .map(|p| p.contains(MemoryPermissions::EXEC))
            .unwrap_or(false)
    }

    /// Iterate over mapped regions (base-ordered).
    pub fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        self.mem.iter_regions()
    }

    /// The region containing `addr`, if any.
    pub fn region_at(&self, addr: u64) -> Option<&MemoryRegion> {
        self.mem.region_at(addr)
    }

    /// Memory-map descriptors (base, size, perms, name).
    pub fn memory_maps(&self) -> Vec<(u64, usize, MemoryPermissions, Option<String>)> {
        self.mem.get_memory_maps()
    }

    /// Total mapped size.
    pub fn total_size(&self) -> usize {
        self.mem.total_size()
    }

    /// Stable digest over endian + all regions (base, size, perms, name, bytes).
    /// Shared by the workspace `semantic_digest` and the memory-image invariants.
    pub fn digest(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        let mut fold = |bytes: &[u8]| {
            for &byte in bytes {
                h ^= byte as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        };
        fold(&[if self.endian.is_big() { 1 } else { 0 }]);
        let mut regions: Vec<&MemoryRegion> = self.mem.iter_regions().collect();
        regions.sort_by_key(|r| r.base);
        fold(&(regions.len() as u64).to_le_bytes());
        for r in regions {
            fold(&r.base.to_le_bytes());
            fold(&(r.size as u64).to_le_bytes());
            fold(&(r.permissions.bits() as u64).to_le_bytes());
            match &r.name {
                Some(n) => {
                    fold(&[1]);
                    fold(n.as_bytes());
                }
                None => fold(&[0]),
            }
            fold(&r.data);
        }
        h
    }

    /// Serialize the mapped regions into persistence records
    /// (base, perms bits, name, data). `size` is intentionally omitted — it is
    /// rebuilt as `data.len()` on restore.
    pub fn to_records(&self) -> Vec<(u64, u8, Option<String>, Vec<u8>)> {
        self.mem
            .iter_regions()
            .map(|r| (r.base, r.permissions.bits(), r.name.clone(), r.data.clone()))
            .collect()
    }

    /// Rebuild an image from persistence records + endianness.
    #[must_use]
    pub fn from_records(
        endian: Endian,
        records: Vec<(u64, u8, Option<String>, Vec<u8>)>,
    ) -> VivResult<Self> {
        let mut img = Self::new(endian);
        for (base, perms, name, data) in records {
            img.map_verbatim(
                base,
                data,
                MemoryPermissions::from_bits_truncate(perms),
                name,
            )?;
        }
        Ok(img)
    }
}

impl Default for MemoryImage {
    fn default() -> Self {
        Self::new(Endian::Little)
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

    // --- MemoryImage (unified authoritative memory) ---------------------------

    #[test]
    fn test_memory_image_map_normalized_zero_fills() {
        let mut img = MemoryImage::new(Endian::Little);
        // raw 4 bytes, virtual size 8 -> tail zero-filled.
        img.map_normalized(
            0x1000,
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            0,
            4,
            8,
            MemoryPermissions::RX,
            Some(".text".into()),
        )
        .unwrap();
        assert_eq!(
            img.read(0x1000, 8).unwrap(),
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0]
        );
        assert_eq!(img.permissions(0x1000), Some(MemoryPermissions::RX));
        assert!(img.is_executable(0x1000));
        assert_eq!(img.region_at(0x1004).map(|r| r.base), Some(0x1000));
        assert!(img.region_at(0x2000).is_none());
    }

    #[test]
    fn test_memory_image_read_ptr_endian() {
        let bytes = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut le = MemoryImage::new(Endian::Little);
        le.map_verbatim(0x2000, bytes.to_vec(), MemoryPermissions::READ, None)
            .unwrap();
        let mut be = MemoryImage::new(Endian::Big);
        be.map_verbatim(0x2000, bytes.to_vec(), MemoryPermissions::READ, None)
            .unwrap();
        assert_eq!(le.read_u32(0x2000).unwrap(), 0x44332211);
        assert_eq!(be.read_u32(0x2000).unwrap(), 0x11223344);
        assert_eq!(le.read_ptr(0x2000, 8).unwrap(), 0x8877665544332211);
        assert_eq!(be.read_ptr(0x2000, 8).unwrap(), 0x1122334455667788);
        assert_ne!(le.read_u64(0x2000).unwrap(), be.read_u64(0x2000).unwrap());
    }

    #[test]
    fn test_memory_image_records_roundtrip_and_digest() {
        let mut img = MemoryImage::new(Endian::Little);
        img.map_normalized(
            0x1000,
            &[1, 2, 3, 4],
            0,
            4,
            6,
            MemoryPermissions::RX,
            Some(".text".into()),
        )
        .unwrap();
        img.map_normalized(
            0x2000,
            &[9, 9],
            0,
            2,
            2,
            MemoryPermissions::RW,
            Some(".data".into()),
        )
        .unwrap();
        let d0 = img.digest();
        let recs = img.to_records();
        let img2 = MemoryImage::from_records(img.endian(), recs).unwrap();
        assert_eq!(d0, img2.digest(), "record round-trip changed the digest");
        assert_eq!(img2.read(0x1000, 6).unwrap(), vec![1, 2, 3, 4, 0, 0]);
        assert_eq!(img2.permissions(0x2000), Some(MemoryPermissions::RW));
        // endian participates in the digest.
        let mut be = MemoryImage::from_records(Endian::Big, img.to_records()).unwrap();
        be.set_endian(Endian::Big);
        assert_ne!(d0, be.digest());
    }

    #[test]
    fn test_memory_region_len_matches_data() {
        // Structural invariant: every region's declared size equals its byte len.
        let mut img = MemoryImage::new(Endian::Little);
        img.map_normalized(0x400, &[7u8; 3], 0, 3, 10, MemoryPermissions::READ, None)
            .unwrap();
        for r in img.regions() {
            assert_eq!(r.size, r.data.len(), "region size/data length diverged");
        }
    }
}
