//! Location management for tracking defined regions in a workspace.
//!
//! Locations represent defined regions such as instructions, data, strings, etc.

use crate::constants::LocationType;
use std::collections::BTreeMap;

/// A location in the workspace.
#[derive(Debug, Clone)]
pub struct Location {
    /// Virtual address.
    pub va: u64,
    /// Size in bytes.
    pub size: usize,
    /// Location type.
    pub ltype: LocationType,
    /// Type-specific info (e.g., string content, type name).
    pub tinfo: Option<String>,
}

impl Location {
    /// Create a new location.
    pub fn new(va: u64, size: usize, ltype: LocationType) -> Self {
        Self {
            va,
            size,
            ltype,
            tinfo: None,
        }
    }

    /// Create a location with type info.
    pub fn with_info(va: u64, size: usize, ltype: LocationType, tinfo: String) -> Self {
        Self {
            va,
            size,
            ltype,
            tinfo: Some(tinfo),
        }
    }

    /// Get the end address (exclusive).
    pub fn end(&self) -> u64 {
        self.va + self.size as u64
    }

    /// Check if this location contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.va && addr < self.end()
    }

    /// Check if this location overlaps with another.
    pub fn overlaps(&self, other: &Location) -> bool {
        self.va < other.end() && other.va < self.end()
    }
}

/// Manager for locations using a BTreeMap for efficient range queries.
#[derive(Debug, Clone, Default)]
pub struct LocationManager {
    /// Locations indexed by start address.
    locations: BTreeMap<u64, Location>,
}

impl LocationManager {
    /// Create a new location manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a location.
    pub fn add(&mut self, location: Location) {
        self.locations.insert(location.va, location);
    }

    /// Add a location by components.
    pub fn add_location(&mut self, va: u64, size: usize, ltype: LocationType, tinfo: Option<String>) {
        let location = Location {
            va,
            size,
            ltype,
            tinfo,
        };
        self.locations.insert(va, location);
    }

    /// Remove a location.
    pub fn remove(&mut self, va: u64) -> Option<Location> {
        self.locations.remove(&va)
    }

    /// Get a location by exact address.
    pub fn get(&self, va: u64) -> Option<&Location> {
        self.locations.get(&va)
    }

    /// Get mutable location by exact address.
    pub fn get_mut(&mut self, va: u64) -> Option<&mut Location> {
        self.locations.get_mut(&va)
    }

    /// Find the location containing an address.
    pub fn get_containing(&self, addr: u64) -> Option<&Location> {
        // Use range query to find potential candidates
        for (_, loc) in self.locations.range(..=addr).rev() {
            if loc.contains(addr) {
                return Some(loc);
            }
            // If we've gone past potential containing locations, stop
            if loc.end() <= addr {
                break;
            }
        }
        None
    }

    /// Get all locations in an address range.
    pub fn get_range(&self, start: u64, end: u64) -> Vec<&Location> {
        self.locations
            .range(start..end)
            .map(|(_, loc)| loc)
            .collect()
    }

    /// Get all locations of a specific type.
    pub fn get_by_type(&self, ltype: LocationType) -> Vec<&Location> {
        self.locations
            .values()
            .filter(|loc| loc.ltype == ltype)
            .collect()
    }

    /// Get all instruction locations.
    pub fn get_instructions(&self) -> Vec<&Location> {
        self.get_by_type(LocationType::Op)
    }

    /// Get all string locations.
    pub fn get_strings(&self) -> Vec<&Location> {
        self.get_by_type(LocationType::String)
    }

    /// Get all data locations.
    pub fn get_data(&self) -> Vec<&Location> {
        // Include various data types
        self.locations
            .values()
            .filter(|loc| {
                matches!(
                    loc.ltype,
                    LocationType::Number
                        | LocationType::Pointer
                        | LocationType::Struct
                )
            })
            .collect()
    }

    /// Check if an address has a location.
    pub fn has_location(&self, va: u64) -> bool {
        self.locations.contains_key(&va)
    }

    /// Check if an address is within any defined location.
    pub fn is_defined(&self, addr: u64) -> bool {
        self.get_containing(addr).is_some()
    }

    /// Get number of locations.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Iterate over all locations.
    pub fn iter(&self) -> impl Iterator<Item = &Location> {
        self.locations.values()
    }

    /// Clear all locations.
    pub fn clear(&mut self) {
        self.locations.clear();
    }

    /// Get statistics about locations.
    pub fn stats(&self) -> LocationStats {
        let mut stats = LocationStats::default();

        for loc in self.locations.values() {
            match loc.ltype {
                LocationType::Op => stats.instructions += 1,
                LocationType::String => stats.strings += 1,
                LocationType::Number => stats.numbers += 1,
                LocationType::Pointer => stats.pointers += 1,
                LocationType::Struct => stats.structs += 1,
                _ => stats.other += 1,
            }
            stats.total_bytes += loc.size;
        }

        stats.total = self.locations.len();
        stats
    }
}

/// Location statistics.
#[derive(Debug, Clone, Default)]
pub struct LocationStats {
    /// Total number of locations.
    pub total: usize,
    /// Number of instructions.
    pub instructions: usize,
    /// Number of strings.
    pub strings: usize,
    /// Number of numbers.
    pub numbers: usize,
    /// Number of pointers.
    pub pointers: usize,
    /// Number of structs.
    pub structs: usize,
    /// Other location types.
    pub other: usize,
    /// Total bytes covered.
    pub total_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_contains() {
        let loc = Location::new(0x1000, 10, LocationType::Op);
        assert!(loc.contains(0x1000));
        assert!(loc.contains(0x1009));
        assert!(!loc.contains(0x100A));
        assert!(!loc.contains(0x0FFF));
    }

    #[test]
    fn test_location_manager() {
        let mut mgr = LocationManager::new();

        mgr.add_location(0x1000, 5, LocationType::Op, None);
        mgr.add_location(0x1005, 3, LocationType::Op, None);
        mgr.add_location(0x2000, 20, LocationType::String, Some("Hello".to_string()));

        assert_eq!(mgr.len(), 3);
        assert!(mgr.has_location(0x1000));
        assert!(!mgr.has_location(0x1001));

        // Test containing lookup
        assert!(mgr.get_containing(0x1002).is_some());
        assert!(mgr.get_containing(0x1004).is_some());
        assert!(mgr.get_containing(0x2010).is_some());
    }

    #[test]
    fn test_location_by_type() {
        let mut mgr = LocationManager::new();

        mgr.add_location(0x1000, 5, LocationType::Op, None);
        mgr.add_location(0x1005, 5, LocationType::Op, None);
        mgr.add_location(0x2000, 10, LocationType::String, None);
        mgr.add_location(0x3000, 4, LocationType::Number, None);

        assert_eq!(mgr.get_instructions().len(), 2);
        assert_eq!(mgr.get_strings().len(), 1);
    }

    #[test]
    fn test_location_stats() {
        let mut mgr = LocationManager::new();

        mgr.add_location(0x1000, 5, LocationType::Op, None);
        mgr.add_location(0x2000, 10, LocationType::String, None);
        mgr.add_location(0x3000, 4, LocationType::Pointer, None);

        let stats = mgr.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.instructions, 1);
        assert_eq!(stats.strings, 1);
        assert_eq!(stats.pointers, 1);
        assert_eq!(stats.total_bytes, 19);
    }
}
