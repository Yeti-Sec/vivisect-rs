//! Symbol table management.

use std::collections::HashMap;

/// Symbol table for name-address mappings.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Address to name mapping.
    by_address: HashMap<u64, String>,
    /// Name to address mapping.
    by_name: HashMap<String, u64>,
}

impl SymbolTable {
    /// Create a new symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, address: u64, name: &str) {
        self.by_address.insert(address, name.to_string());
        self.by_name.insert(name.to_string(), address);
    }

    /// Remove a symbol by address.
    pub fn remove_by_address(&mut self, address: u64) -> Option<String> {
        if let Some(name) = self.by_address.remove(&address) {
            self.by_name.remove(&name);
            Some(name)
        } else {
            None
        }
    }

    /// Remove a symbol by name.
    pub fn remove_by_name(&mut self, name: &str) -> Option<u64> {
        if let Some(address) = self.by_name.remove(name) {
            self.by_address.remove(&address);
            Some(address)
        } else {
            None
        }
    }

    /// Get name by address.
    pub fn get_name(&self, address: u64) -> Option<&str> {
        self.by_address.get(&address).map(|s| s.as_str())
    }

    /// Get address by name.
    pub fn get_address(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).copied()
    }

    /// Check if address has a symbol.
    pub fn has_address(&self, address: u64) -> bool {
        self.by_address.contains_key(&address)
    }

    /// Check if name exists.
    pub fn has_name(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Get number of symbols.
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Get all addresses.
    pub fn addresses(&self) -> Vec<u64> {
        self.by_address.keys().copied().collect()
    }

    /// Get all names.
    pub fn names(&self) -> Vec<&str> {
        self.by_address.values().map(|s| s.as_str()).collect()
    }

    /// Iterate over all symbols.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &str)> {
        self.by_address.iter().map(|(&addr, name)| (addr, name.as_str()))
    }

    /// Search for symbols matching a pattern.
    pub fn search(&self, pattern: &str) -> Vec<(u64, &str)> {
        self.by_address
            .iter()
            .filter(|(_, name)| name.contains(pattern))
            .map(|(&addr, name)| (addr, name.as_str()))
            .collect()
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.by_address.clear();
        self.by_name.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table() {
        let mut symbols = SymbolTable::new();

        symbols.add_symbol(0x401000, "main");
        symbols.add_symbol(0x401100, "foo");
        symbols.add_symbol(0x401200, "bar");

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols.get_name(0x401000), Some("main"));
        assert_eq!(symbols.get_address("foo"), Some(0x401100));

        let search = symbols.search("oo");
        assert_eq!(search.len(), 1);
        assert_eq!(search[0].1, "foo");
    }
}
