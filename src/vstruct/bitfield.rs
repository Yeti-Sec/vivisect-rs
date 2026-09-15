//! Bitfield support for vstruct.

use crate::constants::Endian;
use crate::error::{VivError, VivResult};
use std::collections::HashMap;

/// A bitfield within a structure.
#[derive(Debug, Clone)]
pub struct BitField {
    /// The raw value.
    value: u64,
    /// Size in bytes.
    size: usize,
    /// Endianness.
    endian: Endian,
    /// Field definitions: name -> (bit_offset, bit_width).
    fields: HashMap<String, (usize, usize)>,
}

impl BitField {
    /// Create a new bitfield.
    pub fn new(size: usize, endian: Endian) -> Self {
        Self {
            value: 0,
            size,
            endian,
            fields: HashMap::new(),
        }
    }

    /// Define a field within the bitfield.
    #[must_use]
    pub fn define_field(
        &mut self,
        name: &str,
        bit_offset: usize,
        bit_width: usize,
    ) -> VivResult<()> {
        if bit_offset + bit_width > self.size * 8 {
            return Err(VivError::ParseError {
                message: format!(
                    "Field {} exceeds bitfield size: offset {} + width {} > {} bits",
                    name,
                    bit_offset,
                    bit_width,
                    self.size * 8
                ),
            });
        }
        self.fields
            .insert(name.to_string(), (bit_offset, bit_width));
        Ok(())
    }

    /// Get a field value.
    #[must_use]
    pub fn get_field(&self, name: &str) -> Option<u64> {
        let (offset, width) = self.fields.get(name)?;
        let mask = (1u64 << width) - 1;
        Some((self.value >> offset) & mask)
    }

    /// Set a field value.
    #[must_use]
    pub fn set_field(&mut self, name: &str, value: u64) -> VivResult<()> {
        let (offset, width) = self.fields.get(name).ok_or_else(|| VivError::ParseError {
            message: format!("Unknown field: {}", name),
        })?;
        let mask = (1u64 << width) - 1;
        let value = value & mask;
        // Clear the field bits
        self.value &= !(mask << offset);
        // Set the new value
        self.value |= value << offset;
        Ok(())
    }

    /// Get the raw value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Set the raw value.
    pub fn set_value(&mut self, value: u64) {
        self.value = value & ((1u64 << (self.size * 8)) - 1);
    }

    /// Parse from bytes.
    #[must_use]
    pub fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + self.size;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: format!("Not enough bytes for {} byte bitfield", self.size),
            });
        }

        let slice = &bytes[offset..end];
        self.value = match (self.endian, self.size) {
            (Endian::Little, 1) => slice[0] as u64,
            (Endian::Little, 2) => u16::from_le_bytes([slice[0], slice[1]]) as u64,
            (Endian::Little, 4) => {
                u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64
            }
            (Endian::Little, 8) => u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            (Endian::Big, 1) => slice[0] as u64,
            (Endian::Big, 2) => u16::from_be_bytes([slice[0], slice[1]]) as u64,
            (Endian::Big, 4) => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64,
            (Endian::Big, 8) => u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]),
            _ => {
                return Err(VivError::ParseError {
                    message: "Unsupported bitfield size".into(),
                })
            }
        };

        Ok(end)
    }

    /// Emit as bytes.
    pub fn emit(&self) -> Vec<u8> {
        match (self.endian, self.size) {
            (Endian::Little, 1) => vec![self.value as u8],
            (Endian::Little, 2) => (self.value as u16).to_le_bytes().to_vec(),
            (Endian::Little, 4) => (self.value as u32).to_le_bytes().to_vec(),
            (Endian::Little, 8) => self.value.to_le_bytes().to_vec(),
            (Endian::Big, 1) => vec![self.value as u8],
            (Endian::Big, 2) => (self.value as u16).to_be_bytes().to_vec(),
            (Endian::Big, 4) => (self.value as u32).to_be_bytes().to_vec(),
            (Endian::Big, 8) => self.value.to_be_bytes().to_vec(),
            _ => vec![0u8; self.size],
        }
    }

    /// Get size in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if empty (no fields defined).
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitfield() {
        let mut bf = BitField::new(4, Endian::Little);
        bf.define_field("lower4", 0, 4).unwrap();
        bf.define_field("upper4", 4, 4).unwrap();
        bf.define_field("byte2", 8, 8).unwrap();

        bf.parse(&[0xab, 0xcd, 0x00, 0x00], 0).unwrap();

        assert_eq!(bf.get_field("lower4"), Some(0xb));
        assert_eq!(bf.get_field("upper4"), Some(0xa));
        assert_eq!(bf.get_field("byte2"), Some(0xcd));

        bf.set_field("lower4", 0x5).unwrap();
        assert_eq!(bf.value() & 0xf, 0x5);
    }
}
