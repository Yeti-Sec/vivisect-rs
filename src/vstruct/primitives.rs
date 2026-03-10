//! Primitive types for binary structure parsing.
//!
//! Translated from Python's vstruct/primitives.py.

use crate::constants::Endian;
use crate::error::{VivError, VivResult};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::fmt;

// ============================================================================
// VStruct Base Trait
// ============================================================================

/// Base trait for all vstruct types.
pub trait VStructType: fmt::Debug {
    /// Parse bytes into this type.
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize>;

    /// Emit this type as bytes.
    fn emit(&self) -> Vec<u8>;

    /// Get the length of this type in bytes.
    fn len(&self) -> usize;

    /// Check if empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if this is a primitive type.
    fn is_primitive(&self) -> bool;

    /// Get the type name.
    fn type_name(&self) -> &'static str;

    /// Get/set endianness.
    fn endian(&self) -> Endian;
    fn set_endian(&mut self, endian: Endian);
}

// ============================================================================
// Numeric Primitives
// ============================================================================

/// Unsigned 8-bit integer.
#[derive(Debug, Clone, Copy, Default)]
pub struct VUint8 {
    pub value: u8,
}

impl VUint8 {
    pub fn new(value: u8) -> Self {
        Self { value }
    }
}

impl VStructType for VUint8 {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        if offset >= bytes.len() {
            return Err(VivError::ParseError {
                message: "Not enough bytes for u8".into(),
            });
        }
        self.value = bytes[offset];
        Ok(offset + 1)
    }

    fn emit(&self) -> Vec<u8> {
        vec![self.value]
    }

    fn len(&self) -> usize {
        1
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        "v_uint8"
    }

    fn endian(&self) -> Endian {
        Endian::Little // Doesn't matter for single byte
    }

    fn set_endian(&mut self, _endian: Endian) {}
}

/// Generic numeric type with configurable size and endianness.
#[derive(Debug, Clone)]
pub struct VNumber {
    pub value: u64,
    pub size: usize,
    pub endian: Endian,
    pub signed: bool,
}

impl VNumber {
    pub fn new(size: usize, endian: Endian, signed: bool) -> Self {
        Self {
            value: 0,
            size,
            endian,
            signed,
        }
    }

    pub fn with_value(mut self, value: u64) -> Self {
        self.set_value(value);
        self
    }

    fn max_value(&self) -> u64 {
        (1u64 << (self.size * 8)) - 1
    }

    pub fn set_value(&mut self, value: u64) {
        self.value = value & self.max_value();
    }

    pub fn get_signed_value(&self) -> i64 {
        let sign_bit = 1u64 << (self.size * 8 - 1);
        if self.signed && (self.value & sign_bit) != 0 {
            self.value as i64 - (self.max_value() as i64 + 1)
        } else {
            self.value as i64
        }
    }
}

impl VStructType for VNumber {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + self.size;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: format!("Not enough bytes for {} byte number", self.size),
            });
        }

        let slice = &bytes[offset..end];
        self.value = match (self.endian, self.size) {
            (Endian::Little, 1) => slice[0] as u64,
            (Endian::Little, 2) => LittleEndian::read_u16(slice) as u64,
            (Endian::Little, 4) => LittleEndian::read_u32(slice) as u64,
            (Endian::Little, 8) => LittleEndian::read_u64(slice),
            (Endian::Big, 1) => slice[0] as u64,
            (Endian::Big, 2) => BigEndian::read_u16(slice) as u64,
            (Endian::Big, 4) => BigEndian::read_u32(slice) as u64,
            (Endian::Big, 8) => BigEndian::read_u64(slice),
            _ => {
                // Handle non-standard sizes
                let mut val = 0u64;
                if self.endian.is_big() {
                    for &b in slice {
                        val = (val << 8) | (b as u64);
                    }
                } else {
                    for (i, &b) in slice.iter().enumerate() {
                        val |= (b as u64) << (i * 8);
                    }
                }
                val
            }
        };

        Ok(end)
    }

    fn emit(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size];
        match (self.endian, self.size) {
            (Endian::Little, 1) => buf[0] = self.value as u8,
            (Endian::Little, 2) => LittleEndian::write_u16(&mut buf, self.value as u16),
            (Endian::Little, 4) => LittleEndian::write_u32(&mut buf, self.value as u32),
            (Endian::Little, 8) => LittleEndian::write_u64(&mut buf, self.value),
            (Endian::Big, 1) => buf[0] = self.value as u8,
            (Endian::Big, 2) => BigEndian::write_u16(&mut buf, self.value as u16),
            (Endian::Big, 4) => BigEndian::write_u32(&mut buf, self.value as u32),
            (Endian::Big, 8) => BigEndian::write_u64(&mut buf, self.value),
            _ => {
                // Handle non-standard sizes
                let mut val = self.value;
                if self.endian.is_big() {
                    for i in (0..self.size).rev() {
                        buf[i] = (val & 0xff) as u8;
                        val >>= 8;
                    }
                } else {
                    for b in buf.iter_mut().take(self.size) {
                        *b = (val & 0xff) as u8;
                        val >>= 8;
                    }
                }
            }
        }
        buf
    }

    fn len(&self) -> usize {
        self.size
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        match (self.signed, self.size) {
            (false, 1) => "v_uint8",
            (false, 2) => "v_uint16",
            (false, 3) => "v_uint24",
            (false, 4) => "v_uint32",
            (false, 8) => "v_uint64",
            (true, 1) => "v_int8",
            (true, 2) => "v_int16",
            (true, 3) => "v_int24",
            (true, 4) => "v_int32",
            (true, 8) => "v_int64",
            _ => "v_number",
        }
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }
}

// Convenience type aliases
pub type VUint16 = VNumber;
pub type VUint24 = VNumber;
pub type VUint32 = VNumber;
pub type VUint64 = VNumber;
pub type VInt8 = VNumber;
pub type VInt16 = VNumber;
pub type VInt24 = VNumber;
pub type VInt32 = VNumber;
pub type VInt64 = VNumber;

/// Create unsigned integer types.
pub fn v_uint16(endian: Endian) -> VNumber {
    VNumber::new(2, endian, false)
}
pub fn v_uint24(endian: Endian) -> VNumber {
    VNumber::new(3, endian, false)
}
pub fn v_uint32(endian: Endian) -> VNumber {
    VNumber::new(4, endian, false)
}
pub fn v_uint64(endian: Endian) -> VNumber {
    VNumber::new(8, endian, false)
}

/// Create signed integer types.
pub fn v_int8(endian: Endian) -> VNumber {
    VNumber::new(1, endian, true)
}
pub fn v_int16(endian: Endian) -> VNumber {
    VNumber::new(2, endian, true)
}
pub fn v_int24(endian: Endian) -> VNumber {
    VNumber::new(3, endian, true)
}
pub fn v_int32(endian: Endian) -> VNumber {
    VNumber::new(4, endian, true)
}
pub fn v_int64(endian: Endian) -> VNumber {
    VNumber::new(8, endian, true)
}

// ============================================================================
// Pointer Types
// ============================================================================

/// Pointer type (architecture-sized).
#[derive(Debug, Clone)]
pub struct VPtr {
    inner: VNumber,
}

impl VPtr {
    pub fn new(size: usize, endian: Endian) -> Self {
        Self {
            inner: VNumber::new(size, endian, false),
        }
    }

    pub fn ptr32(endian: Endian) -> Self {
        Self::new(4, endian)
    }

    pub fn ptr64(endian: Endian) -> Self {
        Self::new(8, endian)
    }

    pub fn value(&self) -> u64 {
        self.inner.value
    }

    pub fn set_value(&mut self, value: u64) {
        self.inner.set_value(value);
    }
}

impl VStructType for VPtr {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        self.inner.parse(bytes, offset)
    }

    fn emit(&self) -> Vec<u8> {
        self.inner.emit()
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        match self.inner.size {
            4 => "v_ptr32",
            8 => "v_ptr64",
            _ => "v_ptr",
        }
    }

    fn endian(&self) -> Endian {
        self.inner.endian()
    }

    fn set_endian(&mut self, endian: Endian) {
        self.inner.set_endian(endian);
    }
}

// ============================================================================
// Float Types
// ============================================================================

/// Floating point number.
#[derive(Debug, Clone)]
pub struct VFloat {
    pub value: f64,
    pub size: usize, // 4 for float, 8 for double
    pub endian: Endian,
}

impl VFloat {
    pub fn float32(endian: Endian) -> Self {
        Self {
            value: 0.0,
            size: 4,
            endian,
        }
    }

    pub fn float64(endian: Endian) -> Self {
        Self {
            value: 0.0,
            size: 8,
            endian,
        }
    }

    pub fn set_value(&mut self, value: f64) {
        self.value = value;
    }
}

impl VStructType for VFloat {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + self.size;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: format!("Not enough bytes for {} byte float", self.size),
            });
        }

        let slice = &bytes[offset..end];
        self.value = match (self.endian, self.size) {
            (Endian::Little, 4) => LittleEndian::read_f32(slice) as f64,
            (Endian::Little, 8) => LittleEndian::read_f64(slice),
            (Endian::Big, 4) => BigEndian::read_f32(slice) as f64,
            (Endian::Big, 8) => BigEndian::read_f64(slice),
            _ => {
                return Err(VivError::ParseError {
                    message: "Unsupported float size".into(),
                })
            }
        };

        Ok(end)
    }

    fn emit(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size];
        match (self.endian, self.size) {
            (Endian::Little, 4) => LittleEndian::write_f32(&mut buf, self.value as f32),
            (Endian::Little, 8) => LittleEndian::write_f64(&mut buf, self.value),
            (Endian::Big, 4) => BigEndian::write_f32(&mut buf, self.value as f32),
            (Endian::Big, 8) => BigEndian::write_f64(&mut buf, self.value),
            _ => {}
        }
        buf
    }

    fn len(&self) -> usize {
        self.size
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        match self.size {
            4 => "v_float",
            8 => "v_double",
            _ => "v_float",
        }
    }

    fn endian(&self) -> Endian {
        self.endian
    }

    fn set_endian(&mut self, endian: Endian) {
        self.endian = endian;
    }
}

// ============================================================================
// Bytes Type
// ============================================================================

/// Fixed-width byte array.
#[derive(Debug, Clone)]
pub struct VBytes {
    pub value: Vec<u8>,
    pub size: usize,
}

impl VBytes {
    pub fn new(size: usize) -> Self {
        Self {
            value: vec![0u8; size],
            size,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            value: bytes.to_vec(),
            size: bytes.len(),
        }
    }

    pub fn set_value(&mut self, bytes: &[u8]) -> VivResult<()> {
        if bytes.len() != self.size {
            return Err(VivError::ParseError {
                message: format!("v_bytes field set to wrong length: expected {}, got {}", self.size, bytes.len()),
            });
        }
        self.value = bytes.to_vec();
        Ok(())
    }

    pub fn set_size(&mut self, size: usize) {
        self.size = size;
        self.value.resize(size, 0);
    }
}

impl VStructType for VBytes {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + self.size;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: format!("Not enough bytes for {} byte array", self.size),
            });
        }
        self.value = bytes[offset..end].to_vec();
        Ok(end)
    }

    fn emit(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        "v_bytes"
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn set_endian(&mut self, _endian: Endian) {}
}

impl fmt::Display for VBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.value))
    }
}

// ============================================================================
// String Types
// ============================================================================

/// Fixed-width string (null-padded).
#[derive(Debug, Clone)]
pub struct VStr {
    pub value: Vec<u8>,
    pub size: usize,
}

impl VStr {
    pub fn new(size: usize) -> Self {
        Self {
            value: vec![0u8; size],
            size,
        }
    }

    pub fn get_string(&self) -> String {
        let null_pos = self.value.iter().position(|&b| b == 0).unwrap_or(self.value.len());
        String::from_utf8_lossy(&self.value[..null_pos]).to_string()
    }

    pub fn set_string(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.value = bytes.iter().copied().take(self.size).collect();
        self.value.resize(self.size, 0);
    }
}

impl VStructType for VStr {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + self.size;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: format!("Not enough bytes for {} byte string", self.size),
            });
        }
        self.value = bytes[offset..end].to_vec();
        Ok(end)
    }

    fn emit(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn len(&self) -> usize {
        self.size
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        "v_str"
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn set_endian(&mut self, _endian: Endian) {}
}

/// Null-terminated string (dynamic length).
#[derive(Debug, Clone)]
pub struct VZStr {
    pub value: Vec<u8>,
    pub align: usize,
}

impl VZStr {
    pub fn new() -> Self {
        Self {
            value: vec![0],
            align: 1,
        }
    }

    pub fn with_align(align: usize) -> Self {
        Self {
            value: vec![0],
            align,
        }
    }

    pub fn get_string(&self) -> String {
        let null_pos = self.value.iter().position(|&b| b == 0).unwrap_or(self.value.len());
        String::from_utf8_lossy(&self.value[..null_pos]).to_string()
    }

    pub fn set_string(&mut self, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        let pad = self.align - (bytes.len() % self.align);
        bytes.resize(bytes.len() + pad, 0);
        self.value = bytes;
    }
}

impl Default for VZStr {
    fn default() -> Self {
        Self::new()
    }
}

impl VStructType for VZStr {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let null_pos = bytes[offset..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VivError::ParseError {
                message: "v_zstr found no NULL terminator".into(),
            })?;

        let end_pos = offset + null_pos;
        let diff = self.align - ((end_pos - offset) % self.align);
        let final_end = end_pos + diff;

        if final_end > bytes.len() {
            return Err(VivError::ParseError {
                message: "Not enough bytes for aligned zstr".into(),
            });
        }

        self.value = bytes[offset..final_end].to_vec();
        Ok(final_end)
    }

    fn emit(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn len(&self) -> usize {
        self.value.len()
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        "v_zstr"
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn set_endian(&mut self, _endian: Endian) {}
}

// ============================================================================
// GUID Type
// ============================================================================

/// Windows GUID structure.
#[derive(Debug, Clone, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_string(s: &str) -> VivResult<Self> {
        let s = s.replace(['{', '}', '-'], "");
        if s.len() != 32 {
            return Err(VivError::ParseError {
                message: "Invalid GUID string length".into(),
            });
        }

        let bytes = hex::decode(&s).map_err(|_| VivError::ParseError {
            message: "Invalid GUID hex string".into(),
        })?;

        let mut guid = Self::new();
        guid.data1 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        guid.data2 = u16::from_be_bytes([bytes[4], bytes[5]]);
        guid.data3 = u16::from_be_bytes([bytes[6], bytes[7]]);
        guid.data4.copy_from_slice(&bytes[8..16]);

        Ok(guid)
    }
}

impl VStructType for Guid {
    fn parse(&mut self, bytes: &[u8], offset: usize) -> VivResult<usize> {
        let end = offset + 16;
        if end > bytes.len() {
            return Err(VivError::ParseError {
                message: "Not enough bytes for GUID".into(),
            });
        }

        self.data1 = LittleEndian::read_u32(&bytes[offset..]);
        self.data2 = LittleEndian::read_u16(&bytes[offset + 4..]);
        self.data3 = LittleEndian::read_u16(&bytes[offset + 6..]);
        self.data4.copy_from_slice(&bytes[offset + 8..end]);

        Ok(end)
    }

    fn emit(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        LittleEndian::write_u32(&mut buf[0..4], self.data1);
        LittleEndian::write_u16(&mut buf[4..6], self.data2);
        LittleEndian::write_u16(&mut buf[6..8], self.data3);
        buf[8..16].copy_from_slice(&self.data4);
        buf
    }

    fn len(&self) -> usize {
        16
    }

    fn is_primitive(&self) -> bool {
        true
    }

    fn type_name(&self) -> &'static str {
        "GUID"
    }

    fn endian(&self) -> Endian {
        Endian::Little
    }

    fn set_endian(&mut self, _endian: Endian) {}
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uint32_le() {
        let mut num = v_uint32(Endian::Little);
        num.parse(&[0x78, 0x56, 0x34, 0x12], 0).unwrap();
        assert_eq!(num.value, 0x12345678);
        assert_eq!(num.emit(), vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_uint32_be() {
        let mut num = v_uint32(Endian::Big);
        num.parse(&[0x12, 0x34, 0x56, 0x78], 0).unwrap();
        assert_eq!(num.value, 0x12345678);
        assert_eq!(num.emit(), vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_guid() {
        let mut guid = Guid::new();
        let bytes = [
            0x01, 0x02, 0x03, 0x04, // data1
            0x05, 0x06, // data2
            0x07, 0x08, // data3
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // data4
        ];
        guid.parse(&bytes, 0).unwrap();
        assert_eq!(guid.data1, 0x04030201);
        assert_eq!(guid.data2, 0x0605);
        assert_eq!(guid.data3, 0x0807);
    }
}
