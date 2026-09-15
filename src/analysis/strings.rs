//! String detection and analysis.
//!
//! Provides utilities for finding ASCII and Unicode strings in binary data.

use crate::constants::LocationType;
use crate::core::VivWorkspace;
use crate::error::VivResult;

/// Minimum length for a string to be considered valid.
pub const MIN_STRING_LENGTH: usize = 4;

/// Maximum length for a string to be analyzed.
pub const MAX_STRING_LENGTH: usize = 4096;

/// A detected string.
#[derive(Debug, Clone)]
pub struct DetectedString {
    /// Virtual address of the string.
    pub va: u64,
    /// The string content.
    pub content: String,
    /// String encoding type.
    pub encoding: StringEncoding,
    /// Size in bytes (including null terminator if present).
    pub size: usize,
}

/// String encoding types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// ASCII/UTF-8 encoding.
    Ascii,
    /// UTF-16 Little Endian.
    Utf16Le,
    /// UTF-16 Big Endian.
    Utf16Be,
}

/// Check if a byte is a printable ASCII character.
#[inline]
fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\t' | b'\n' | b'\r')
}

/// Check if a byte could be part of an ASCII string.
#[inline]
fn is_string_char(b: u8) -> bool {
    is_printable_ascii(b)
}

/// Detect ASCII string at the given offset.
#[must_use]
pub fn detect_ascii_string(data: &[u8], offset: usize, min_len: usize) -> Option<DetectedString> {
    if offset >= data.len() {
        return None;
    }

    let mut end = offset;
    while end < data.len() && end - offset < MAX_STRING_LENGTH {
        let b = data[end];
        if b == 0 {
            // Null terminator
            break;
        }
        if !is_string_char(b) {
            return None;
        }
        end += 1;
    }

    let len = end - offset;
    if len < min_len {
        return None;
    }

    let content = String::from_utf8_lossy(&data[offset..end]).to_string();
    let size = if end < data.len() && data[end] == 0 {
        len + 1 // Include null terminator
    } else {
        len
    };

    Some(DetectedString {
        va: offset as u64,
        content,
        encoding: StringEncoding::Ascii,
        size,
    })
}

/// Detect UTF-16 LE string at the given offset.
#[must_use]
pub fn detect_utf16le_string(data: &[u8], offset: usize, min_len: usize) -> Option<DetectedString> {
    if offset + 1 >= data.len() {
        return None;
    }

    let mut chars = Vec::new();
    let mut pos = offset;

    while pos + 1 < data.len() && chars.len() < MAX_STRING_LENGTH {
        let low = data[pos];
        let high = data[pos + 1];

        if low == 0 && high == 0 {
            // Null terminator
            break;
        }

        let code_unit = u16::from_le_bytes([low, high]);

        // Check for ASCII range (most common in binaries)
        if code_unit < 0x20 || (code_unit > 0x7E && code_unit < 0x100) {
            // Allow tab, newline, carriage return
            if code_unit != 0x09 && code_unit != 0x0A && code_unit != 0x0D {
                return None;
            }
        }

        chars.push(code_unit);
        pos += 2;
    }

    if chars.len() < min_len {
        return None;
    }

    let content = String::from_utf16_lossy(&chars);
    let size = (pos - offset)
        + if pos + 1 < data.len() && data[pos] == 0 && data[pos + 1] == 0 {
            2 // Include null terminator
        } else {
            0
        };

    Some(DetectedString {
        va: offset as u64,
        content,
        encoding: StringEncoding::Utf16Le,
        size,
    })
}

/// Detect UTF-16 BE string at the given offset.
#[must_use]
pub fn detect_utf16be_string(data: &[u8], offset: usize, min_len: usize) -> Option<DetectedString> {
    if offset + 1 >= data.len() {
        return None;
    }

    let mut chars = Vec::new();
    let mut pos = offset;

    while pos + 1 < data.len() && chars.len() < MAX_STRING_LENGTH {
        let high = data[pos];
        let low = data[pos + 1];

        if low == 0 && high == 0 {
            break;
        }

        let code_unit = u16::from_be_bytes([high, low]);

        if (code_unit < 0x20 || (code_unit > 0x7E && code_unit < 0x100))
            && code_unit != 0x09
            && code_unit != 0x0A
            && code_unit != 0x0D
        {
            return None;
        }

        chars.push(code_unit);
        pos += 2;
    }

    if chars.len() < min_len {
        return None;
    }

    let content = String::from_utf16_lossy(&chars);
    let size = (pos - offset)
        + if pos + 1 < data.len() && data[pos] == 0 && data[pos + 1] == 0 {
            2
        } else {
            0
        };

    Some(DetectedString {
        va: offset as u64,
        content,
        encoding: StringEncoding::Utf16Be,
        size,
    })
}

/// String analysis configuration.
#[derive(Debug, Clone)]
pub struct StringAnalysisConfig {
    /// Minimum string length.
    pub min_length: usize,
    /// Detect ASCII strings.
    pub detect_ascii: bool,
    /// Detect UTF-16 strings.
    pub detect_utf16: bool,
    /// Detect UTF-16 BE strings.
    pub detect_utf16be: bool,
}

impl Default for StringAnalysisConfig {
    fn default() -> Self {
        Self {
            min_length: MIN_STRING_LENGTH,
            detect_ascii: true,
            detect_utf16: true,
            detect_utf16be: true,
        }
    }
}

/// Find all strings in a byte slice.
pub fn find_strings(data: &[u8], config: &StringAnalysisConfig) -> Vec<DetectedString> {
    let mut strings = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let mut found = false;

        // Try ASCII first
        if config.detect_ascii {
            if let Some(mut s) = detect_ascii_string(data, offset, config.min_length) {
                s.va = offset as u64;
                offset += s.size;
                strings.push(s);
                found = true;
            }
        }

        // Try UTF-16 LE if ASCII didn't match
        if !found
            && config.detect_utf16
            && offset + 1 < data.len()
            && data[offset + 1] == 0
            && is_printable_ascii(data[offset])
        {
            if let Some(mut s) = detect_utf16le_string(data, offset, config.min_length) {
                s.va = offset as u64;
                offset += s.size;
                strings.push(s);
                found = true;
            }
        }

        // Try UTF-16 BE if nothing else matched
        if !found
            && config.detect_utf16be
            && offset + 1 < data.len()
            && data[offset] == 0
            && is_printable_ascii(data[offset + 1])
        {
            if let Some(mut s) = detect_utf16be_string(data, offset, config.min_length) {
                s.va = offset as u64;
                offset += s.size;
                strings.push(s);
                found = true;
            }
        }

        if !found {
            offset += 1;
        }
    }

    strings
}

/// Analyze strings in a workspace memory region.
#[must_use]
pub fn analyze_workspace_strings(
    workspace: &mut VivWorkspace,
    va: u64,
    size: usize,
    config: &StringAnalysisConfig,
) -> VivResult<Vec<DetectedString>> {
    let data = workspace.read_memory(va, size)?;
    let mut strings = find_strings(&data, config);

    // Adjust addresses and add to workspace
    for s in &mut strings {
        s.va += va;
        workspace.add_location(s.va, s.size, LocationType::String, Some(s.content.clone()));
    }

    Ok(strings)
}

/// Calculate string entropy (useful for detecting encrypted/encoded strings).
pub fn string_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a string looks like a path.
pub fn is_path_string(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.starts_with("C:") || s.starts_with("./")
}

/// Check if a string looks like a URL.
pub fn is_url_string(s: &str) -> bool {
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ftp://")
        || s.starts_with("file://")
}

/// Check if a string looks like a registry key.
pub fn is_registry_string(s: &str) -> bool {
    s.starts_with("HKEY_") || s.starts_with("HKLM\\") || s.starts_with("HKCU\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ascii_string() {
        let data = b"Hello, World!\x00more data";
        let s = detect_ascii_string(data, 0, 4).unwrap();
        assert_eq!(s.content, "Hello, World!");
        assert_eq!(s.encoding, StringEncoding::Ascii);
        assert_eq!(s.size, 14); // Including null terminator
    }

    #[test]
    fn test_detect_utf16_string() {
        let data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
        let s = detect_utf16le_string(data, 0, 4).unwrap();
        assert_eq!(s.content, "Hello");
        assert_eq!(s.encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn test_find_strings() {
        let data = b"\x00\x00Hello\x00World\x00\x00\x00";
        let config = StringAnalysisConfig {
            min_length: 4,
            detect_ascii: true,
            detect_utf16: false,
            detect_utf16be: false,
        };
        let strings = find_strings(data, &config);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].content, "Hello");
        assert_eq!(strings[1].content, "World");
    }

    #[test]
    fn test_detect_utf16be_string() {
        // "Test" in UTF-16 BE: \x00T\x00e\x00s\x00t
        let data = b"\x00T\x00e\x00s\x00t\x00\x00";
        let s = detect_utf16be_string(data, 0, 4).unwrap();
        assert_eq!(s.content, "Test");
        assert_eq!(s.encoding, StringEncoding::Utf16Be);
    }

    #[test]
    fn test_detect_utf16be_too_short() {
        let data = b"\x00H\x00i\x00\x00";
        assert!(detect_utf16be_string(data, 0, 4).is_none());
    }

    #[test]
    fn test_find_strings_all_encodings() {
        // Mix: ASCII "AAAA", then UTF-16BE "\x00B\x00B\x00B\x00B"
        let mut data = Vec::new();
        data.extend_from_slice(b"AAAA\x00"); // ASCII
        data.extend_from_slice(b"\x00B\x00B\x00B\x00B\x00\x00"); // UTF-16BE
        let config = StringAnalysisConfig::default();
        let strings = find_strings(&data, &config);
        assert!(strings.iter().any(|s| s.content == "AAAA"));
        assert!(strings
            .iter()
            .any(|s| s.content == "BBBB" && s.encoding == StringEncoding::Utf16Be));
    }

    #[test]
    fn test_string_entropy() {
        // Low entropy (repetitive)
        let low = string_entropy("aaaaaaaaaa");
        // Higher entropy (varied)
        let high = string_entropy("abcdefghij");
        assert!(low < high);
    }

    #[test]
    fn test_string_classification() {
        assert!(is_path_string("C:\\Windows\\System32"));
        assert!(is_path_string("/usr/bin/bash"));
        assert!(is_url_string("https://example.com"));
        assert!(is_registry_string("HKEY_LOCAL_MACHINE"));
    }
}
