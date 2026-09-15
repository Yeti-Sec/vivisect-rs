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
    #[must_use]
    pub fn remove_by_address(&mut self, address: u64) -> Option<String> {
        if let Some(name) = self.by_address.remove(&address) {
            self.by_name.remove(&name);
            Some(name)
        } else {
            None
        }
    }

    /// Remove a symbol by name.
    #[must_use]
    pub fn remove_by_name(&mut self, name: &str) -> Option<u64> {
        if let Some(address) = self.by_name.remove(name) {
            self.by_address.remove(&address);
            Some(address)
        } else {
            None
        }
    }

    /// Get name by address.
    #[must_use]
    pub fn get_name(&self, address: u64) -> Option<&str> {
        self.by_address.get(&address).map(|s| s.as_str())
    }

    /// Get address by name.
    #[must_use]
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
        self.by_address
            .iter()
            .map(|(&addr, name)| (addr, name.as_str()))
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

    #[test]
    fn test_new_symbol_table_is_empty() {
        let st = SymbolTable::new();
        assert!(st.is_empty());
        assert_eq!(st.len(), 0);
    }

    #[test]
    fn test_add_symbol_bidirectional() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "test_sym");
        assert_eq!(st.get_name(0x1000), Some("test_sym"));
        assert_eq!(st.get_address("test_sym"), Some(0x1000));
    }

    #[test]
    fn test_add_symbol_overwrites_existing_at_same_address() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "original");
        st.add_symbol(0x1000, "replaced");
        assert_eq!(st.get_name(0x1000), Some("replaced"));
        assert_eq!(st.get_address("replaced"), Some(0x1000));
        // The old name "original" may still map to 0x1000 in by_name
        // unless explicitly cleaned up — this tests the actual behavior.
    }

    #[test]
    fn test_get_name_nonexistent() {
        let st = SymbolTable::new();
        assert!(st.get_name(0xDEAD).is_none());
    }

    #[test]
    fn test_get_address_nonexistent() {
        let st = SymbolTable::new();
        assert!(st.get_address("nonexistent").is_none());
    }

    #[test]
    fn test_has_address() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "sym");
        assert!(st.has_address(0x1000));
        assert!(!st.has_address(0x2000));
    }

    #[test]
    fn test_has_name() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "sym");
        assert!(st.has_name("sym"));
        assert!(!st.has_name("other"));
    }

    #[test]
    fn test_remove_by_address() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "to_remove");
        st.add_symbol(0x2000, "to_keep");

        let removed = st.remove_by_address(0x1000);
        assert_eq!(removed, Some("to_remove".to_string()));
        assert!(st.get_name(0x1000).is_none());
        assert!(st.get_address("to_remove").is_none());
        // Other symbol unaffected
        assert_eq!(st.get_name(0x2000), Some("to_keep"));
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn test_remove_by_address_nonexistent() {
        let mut st = SymbolTable::new();
        assert!(st.remove_by_address(0xFFFF).is_none());
    }

    #[test]
    fn test_remove_by_name() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "to_remove");
        st.add_symbol(0x2000, "to_keep");

        let removed = st.remove_by_name("to_remove");
        assert_eq!(removed, Some(0x1000));
        assert!(st.get_name(0x1000).is_none());
        assert!(st.get_address("to_remove").is_none());
        assert_eq!(st.len(), 1);
    }

    #[test]
    fn test_remove_by_name_nonexistent() {
        let mut st = SymbolTable::new();
        assert!(st.remove_by_name("nope").is_none());
    }

    #[test]
    fn test_search_pattern_matching() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "kernel32.CreateFileA");
        st.add_symbol(0x2000, "kernel32.ReadFile");
        st.add_symbol(0x3000, "user32.MessageBoxA");
        st.add_symbol(0x4000, "ntdll.RtlInitUnicodeString");

        // Search for "kernel32"
        let results = st.search("kernel32");
        assert_eq!(results.len(), 2);

        // Search for "File"
        let results = st.search("File");
        assert_eq!(results.len(), 2);

        // Search for exact name
        let results = st.search("MessageBoxA");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0x3000);
    }

    #[test]
    fn test_search_no_match() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "alpha");
        let results = st.search("zzz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_empty_pattern_matches_all() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "a");
        st.add_symbol(0x2000, "b");
        let results = st.search("");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_addresses_and_names() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "alpha");
        st.add_symbol(0x2000, "beta");

        let mut addrs = st.addresses();
        addrs.sort();
        assert_eq!(addrs, vec![0x1000, 0x2000]);

        let mut names = st.names();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_iter() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "x");
        st.add_symbol(0x2000, "y");

        let mut items: Vec<(u64, &str)> = st.iter().collect();
        items.sort_by_key(|(addr, _)| *addr);
        assert_eq!(items, vec![(0x1000, "x"), (0x2000, "y")]);
    }

    #[test]
    fn test_clear() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "a");
        st.add_symbol(0x2000, "b");
        assert_eq!(st.len(), 2);

        st.clear();
        assert!(st.is_empty());
        assert_eq!(st.len(), 0);
        assert!(st.get_name(0x1000).is_none());
        assert!(st.get_address("a").is_none());
    }

    #[test]
    fn test_default_trait() {
        let st = SymbolTable::default();
        assert!(st.is_empty());
    }

    #[test]
    fn test_symbol_with_special_characters() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "std::io::_print");
        st.add_symbol(0x2000, "operator<<(int, int)");
        assert_eq!(st.get_name(0x1000), Some("std::io::_print"));
        assert_eq!(st.get_address("operator<<(int, int)"), Some(0x2000));
    }

    #[test]
    fn test_symbol_with_empty_name() {
        let mut st = SymbolTable::new();
        st.add_symbol(0x1000, "");
        assert_eq!(st.get_name(0x1000), Some(""));
        assert_eq!(st.get_address(""), Some(0x1000));
    }
}
