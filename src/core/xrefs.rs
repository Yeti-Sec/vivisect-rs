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
}
