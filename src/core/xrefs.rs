//! Cross-reference management.

use crate::constants::RefType;
use std::collections::HashMap;

/// Cross-reference entry.
#[derive(Debug, Clone, Copy)]
pub struct XRef {
    pub from: u64,
    pub to: u64,
    pub ref_type: RefType,
}

/// Manager for cross-references.
#[derive(Debug, Clone, Default)]
pub struct XRefManager {
    /// XRefs indexed by destination address.
    to_map: HashMap<u64, Vec<(u64, RefType)>>,
    /// XRefs indexed by source address.
    from_map: HashMap<u64, Vec<(u64, RefType)>>,
    /// Total count.
    count: usize,
}

impl XRefManager {
    /// Create a new XRef manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, from: u64, to: u64, ref_type: RefType) {
        self.to_map.entry(to).or_default().push((from, ref_type));
        self.from_map.entry(from).or_default().push((to, ref_type));
        self.count += 1;
    }

    /// Remove a cross-reference.
    pub fn remove_xref(&mut self, from: u64, to: u64, ref_type: RefType) {
        if let Some(refs) = self.to_map.get_mut(&to) {
            if let Some(pos) = refs.iter().position(|&(f, t)| f == from && t == ref_type) {
                refs.remove(pos);
                self.count -= 1;
            }
        }
        if let Some(refs) = self.from_map.get_mut(&from) {
            if let Some(pos) = refs.iter().position(|&(t, rt)| t == to && rt == ref_type) {
                refs.remove(pos);
            }
        }
    }

    /// Get cross-references TO an address.
    pub fn get_xrefs_to(&self, va: u64) -> Vec<(u64, RefType)> {
        self.to_map.get(&va).cloned().unwrap_or_default()
    }

    /// Get cross-references FROM an address.
    pub fn get_xrefs_from(&self, va: u64) -> Vec<(u64, RefType)> {
        self.from_map.get(&va).cloned().unwrap_or_default()
    }

    /// Get total number of xrefs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get all addresses that have xrefs TO them.
    pub fn get_xref_destinations(&self) -> Vec<u64> {
        self.to_map.keys().copied().collect()
    }

    /// Get all addresses that have xrefs FROM them.
    pub fn get_xref_sources(&self) -> Vec<u64> {
        self.from_map.keys().copied().collect()
    }

    /// Clear all xrefs.
    pub fn clear(&mut self) {
        self.to_map.clear();
        self.from_map.clear();
        self.count = 0;
    }

    /// Iterate over all xrefs as (from, to, ref_type) tuples.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64, RefType)> + '_ {
        self.from_map.iter().flat_map(|(&from, refs)| {
            refs.iter().map(move |&(to, ref_type)| (from, to, ref_type))
        })
    }

    /// Get all xrefs as a vector.
    pub fn all_xrefs(&self) -> Vec<XRef> {
        self.iter()
            .map(|(from, to, ref_type)| XRef { from, to, ref_type })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xref_manager() {
        let mut xrefs = XRefManager::new();

        xrefs.add_xref(0x401000, 0x402000, RefType::Code);
        xrefs.add_xref(0x401010, 0x402000, RefType::Code);
        xrefs.add_xref(0x401000, 0x403000, RefType::Data);

        assert_eq!(xrefs.len(), 3);

        let to_refs = xrefs.get_xrefs_to(0x402000);
        assert_eq!(to_refs.len(), 2);

        let from_refs = xrefs.get_xrefs_from(0x401000);
        assert_eq!(from_refs.len(), 2);
    }

    #[test]
    fn test_new_xref_manager_is_empty() {
        let xrefs = XRefManager::new();
        assert!(xrefs.is_empty());
        assert_eq!(xrefs.len(), 0);
    }

    #[test]
    fn test_add_xref_increments_count() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        assert_eq!(xrefs.len(), 1);
        assert!(!xrefs.is_empty());
        xrefs.add_xref(0x1000, 0x3000, RefType::Data);
        assert_eq!(xrefs.len(), 2);
    }

    #[test]
    fn test_get_xrefs_to_returns_all_sources() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x5000, RefType::Code);
        xrefs.add_xref(0x2000, 0x5000, RefType::Code);
        xrefs.add_xref(0x3000, 0x5000, RefType::Data);

        let to_refs = xrefs.get_xrefs_to(0x5000);
        assert_eq!(to_refs.len(), 3);
        // Check all sources are present
        let sources: Vec<u64> = to_refs.iter().map(|(from, _)| *from).collect();
        assert!(sources.contains(&0x1000));
        assert!(sources.contains(&0x2000));
        assert!(sources.contains(&0x3000));
    }

    #[test]
    fn test_get_xrefs_from_returns_all_targets() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x5000, RefType::Code);
        xrefs.add_xref(0x1000, 0x6000, RefType::Data);
        xrefs.add_xref(0x1000, 0x7000, RefType::Pointer);

        let from_refs = xrefs.get_xrefs_from(0x1000);
        assert_eq!(from_refs.len(), 3);
        let targets: Vec<u64> = from_refs.iter().map(|(to, _)| *to).collect();
        assert!(targets.contains(&0x5000));
        assert!(targets.contains(&0x6000));
        assert!(targets.contains(&0x7000));
    }

    #[test]
    fn test_get_xrefs_to_nonexistent_returns_empty() {
        let xrefs = XRefManager::new();
        assert!(xrefs.get_xrefs_to(0x9999).is_empty());
    }

    #[test]
    fn test_get_xrefs_from_nonexistent_returns_empty() {
        let xrefs = XRefManager::new();
        assert!(xrefs.get_xrefs_from(0x9999).is_empty());
    }

    #[test]
    fn test_duplicate_xrefs_are_both_stored() {
        let mut xrefs = XRefManager::new();
        // Adding the exact same xref twice should store both
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        assert_eq!(xrefs.len(), 2);

        let to_refs = xrefs.get_xrefs_to(0x2000);
        assert_eq!(to_refs.len(), 2);
        let from_refs = xrefs.get_xrefs_from(0x1000);
        assert_eq!(from_refs.len(), 2);
    }

    #[test]
    fn test_different_ref_types_same_addresses() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x1000, 0x2000, RefType::Data);
        xrefs.add_xref(0x1000, 0x2000, RefType::Pointer);
        assert_eq!(xrefs.len(), 3);

        let from_refs = xrefs.get_xrefs_from(0x1000);
        assert_eq!(from_refs.len(), 3);
        let ref_types: Vec<RefType> = from_refs.iter().map(|(_, rt)| *rt).collect();
        assert!(ref_types.contains(&RefType::Code));
        assert!(ref_types.contains(&RefType::Data));
        assert!(ref_types.contains(&RefType::Pointer));
    }

    #[test]
    fn test_remove_xref() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x1000, 0x3000, RefType::Data);
        assert_eq!(xrefs.len(), 2);

        xrefs.remove_xref(0x1000, 0x2000, RefType::Code);
        assert_eq!(xrefs.len(), 1);

        assert!(xrefs.get_xrefs_to(0x2000).is_empty());
        assert_eq!(xrefs.get_xrefs_from(0x1000).len(), 1);
        assert_eq!(xrefs.get_xrefs_from(0x1000)[0], (0x3000, RefType::Data));
    }

    #[test]
    fn test_remove_xref_nonexistent_is_noop() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        // Removing a nonexistent xref should not change anything
        xrefs.remove_xref(0xAAAA, 0xBBBB, RefType::Code);
        assert_eq!(xrefs.len(), 1);
    }

    #[test]
    fn test_remove_xref_wrong_type_is_noop() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        // Wrong ref_type should not remove
        xrefs.remove_xref(0x1000, 0x2000, RefType::Data);
        assert_eq!(xrefs.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x3000, 0x4000, RefType::Data);
        assert_eq!(xrefs.len(), 2);

        xrefs.clear();
        assert!(xrefs.is_empty());
        assert_eq!(xrefs.len(), 0);
        assert!(xrefs.get_xrefs_to(0x2000).is_empty());
    }

    #[test]
    fn test_get_xref_destinations() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x5000, RefType::Code);
        xrefs.add_xref(0x2000, 0x6000, RefType::Data);
        xrefs.add_xref(0x3000, 0x5000, RefType::Code);

        let mut dests = xrefs.get_xref_destinations();
        dests.sort();
        assert_eq!(dests, vec![0x5000, 0x6000]);
    }

    #[test]
    fn test_get_xref_sources() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x5000, RefType::Code);
        xrefs.add_xref(0x2000, 0x6000, RefType::Data);
        xrefs.add_xref(0x1000, 0x7000, RefType::Code);

        let mut srcs = xrefs.get_xref_sources();
        srcs.sort();
        assert_eq!(srcs, vec![0x1000, 0x2000]);
    }

    #[test]
    fn test_iter() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x3000, 0x4000, RefType::Data);

        let all: Vec<(u64, u64, RefType)> = xrefs.iter().collect();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_all_xrefs() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Code);
        xrefs.add_xref(0x3000, 0x4000, RefType::Pointer);

        let all = xrefs.all_xrefs();
        assert_eq!(all.len(), 2);
        // Each XRef should have correct fields
        let xref = all.iter().find(|x| x.from == 0x1000).unwrap();
        assert_eq!(xref.to, 0x2000);
        assert_eq!(xref.ref_type, RefType::Code);
    }

    #[test]
    fn test_xref_preserves_ref_type() {
        let mut xrefs = XRefManager::new();
        xrefs.add_xref(0x1000, 0x2000, RefType::Pointer);

        let to_refs = xrefs.get_xrefs_to(0x2000);
        assert_eq!(to_refs[0].1, RefType::Pointer);

        let from_refs = xrefs.get_xrefs_from(0x1000);
        assert_eq!(from_refs[0].1, RefType::Pointer);
    }
}
