//! Utility functions and helpers.

/// Format an address for display.
pub fn format_address(addr: u64, size: usize) -> String {
    match size {
        4 => format!("{:08x}", addr),
        8 => format!("{:016x}", addr),
        _ => format!("{:x}", addr),
    }
}

/// Format bytes as hex string.
pub fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Align value up to boundary.
pub fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Align value down to boundary.
pub fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

/// Check if value is aligned.
pub fn is_aligned(value: u64, alignment: u64) -> bool {
    (value & (alignment - 1)) == 0
}

/// Sign extend a value.
pub fn sign_extend(value: u64, from_bits: usize, to_bits: usize) -> u64 {
    let sign_bit = 1u64 << (from_bits - 1);
    let to_mask = if to_bits >= 64 {
        u64::MAX
    } else {
        (1u64 << to_bits) - 1
    };
    if (value & sign_bit) != 0 {
        let mask = !((1u64 << from_bits) - 1);
        (value | mask) & to_mask
    } else {
        value & to_mask
    }
}

/// Extract bits from a value.
pub fn extract_bits(value: u64, start: usize, len: usize) -> u64 {
    (value >> start) & ((1u64 << len) - 1)
}

/// Insert bits into a value.
pub fn insert_bits(value: u64, bits: u64, start: usize, len: usize) -> u64 {
    let mask = ((1u64 << len) - 1) << start;
    (value & !mask) | ((bits << start) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alignment() {
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_down(0x1001, 0x1000), 0x1000);
        assert!(is_aligned(0x1000, 0x1000));
        assert!(!is_aligned(0x1001, 0x1000));
    }

    #[test]
    fn test_sign_extend() {
        // Sign extend 8-bit -1 (0xff) to 64-bit
        assert_eq!(sign_extend(0xff, 8, 64), 0xffffffffffffffff);
        // Sign extend 8-bit 127 (0x7f) to 64-bit
        assert_eq!(sign_extend(0x7f, 8, 64), 0x7f);
    }

    #[test]
    fn test_extract_bits() {
        assert_eq!(extract_bits(0xabcd, 4, 8), 0xbc);
        assert_eq!(extract_bits(0xabcd, 0, 4), 0xd);
    }
}
