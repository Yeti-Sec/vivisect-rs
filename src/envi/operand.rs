//! Operand types for the envi architecture layer.
//!
//! Translated from Python's envi Operand classes.

use std::any::Any;
use std::fmt;

/// Base trait for all operand types.
pub trait Operand: fmt::Debug + Send + Sync {
    /// Downcast support.
    fn as_any(&self) -> &dyn Any;
    /// Get the operand value, optionally using an emulator for resolution.
    fn get_value(&self, op: &super::Opcode) -> Option<u64>;

    /// Check if this operand dereferences memory.
    fn is_deref(&self) -> bool {
        false
    }

    /// Check if this is an immediate value.
    fn is_immed(&self) -> bool {
        false
    }

    /// Check if this is a register operand.
    fn is_reg(&self) -> bool {
        false
    }

    /// Check if this can be resolved without emulation.
    fn is_discrete(&self) -> bool {
        false
    }

    /// Get the memory address if this is a deref operand.
    fn get_address(&self, _op: &super::Opcode) -> Option<u64> {
        None
    }

    /// Get a human-readable representation.
    fn repr(&self, op: &super::Opcode) -> String;

    /// Get the operand size in bytes.
    fn size(&self) -> usize {
        0
    }

    /// Clone into a boxed trait object.
    fn clone_box(&self) -> Box<dyn Operand>;
}

impl Clone for Box<dyn Operand> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

// ============================================================================
// Immediate Operand
// ============================================================================

/// An immediate (constant) value operand.
#[derive(Debug, Clone)]
pub struct ImmediateOperand {
    /// The immediate value.
    pub value: u64,
    /// Size of the immediate in bytes.
    pub size: usize,
    /// Is this a signed value?
    pub signed: bool,
}

impl ImmediateOperand {
    /// Create a new immediate operand.
    pub fn new(value: u64, size: usize) -> Self {
        Self {
            value,
            size,
            signed: false,
        }
    }

    /// Create a signed immediate operand.
    pub fn signed(value: i64, size: usize) -> Self {
        Self {
            value: value as u64,
            size,
            signed: true,
        }
    }

    /// Get as signed value.
    pub fn as_signed(&self) -> i64 {
        let sign_bit = 1u64 << (self.size * 8 - 1);
        if self.value & sign_bit != 0 {
            let mask = (1u64 << (self.size * 8)) - 1;
            (self.value | !mask) as i64
        } else {
            self.value as i64
        }
    }
}

impl Operand for ImmediateOperand {
    fn as_any(&self) -> &dyn Any { self }

    fn get_value(&self, _op: &super::Opcode) -> Option<u64> {
        Some(self.value)
    }

    fn is_immed(&self) -> bool {
        true
    }

    fn is_discrete(&self) -> bool {
        true
    }

    fn repr(&self, _op: &super::Opcode) -> String {
        if self.signed {
            let signed_val = self.as_signed();
            if signed_val < 0 {
                format!("-{:#x}", -signed_val)
            } else {
                format!("{:#x}", signed_val)
            }
        } else {
            format!("{:#x}", self.value)
        }
    }

    fn size(&self) -> usize {
        self.size
    }

    fn clone_box(&self) -> Box<dyn Operand> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Register Operand
// ============================================================================

/// A register operand.
#[derive(Debug, Clone)]
pub struct RegisterOperand {
    /// Register index.
    pub reg_index: usize,
    /// Register name.
    pub reg_name: String,
    /// Register size in bytes.
    pub reg_size: usize,
}

impl RegisterOperand {
    /// Create a new register operand.
    pub fn new(index: usize, name: impl Into<String>, size: usize) -> Self {
        Self {
            reg_index: index,
            reg_name: name.into(),
            reg_size: size,
        }
    }
}

impl Operand for RegisterOperand {
    fn as_any(&self) -> &dyn Any { self }

    fn get_value(&self, _op: &super::Opcode) -> Option<u64> {
        None
    }

    fn is_reg(&self) -> bool {
        true
    }

    fn repr(&self, _op: &super::Opcode) -> String {
        self.reg_name.clone()
    }

    fn size(&self) -> usize {
        self.reg_size
    }

    fn clone_box(&self) -> Box<dyn Operand> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Memory Dereference Operand
// ============================================================================

/// A memory dereference operand.
#[derive(Debug, Clone)]
pub struct DerefOperand {
    /// Base register index (if any).
    pub base_reg: Option<usize>,
    /// Base register name.
    pub base_name: Option<String>,
    /// Index register index (if any).
    pub index_reg: Option<usize>,
    /// Index register name.
    pub index_name: Option<String>,
    /// Scale factor for index.
    pub scale: u8,
    /// Displacement/offset.
    pub displacement: i64,
    /// Size of the dereference in bytes.
    pub deref_size: usize,
    /// Segment register (if any).
    pub segment: Option<String>,
}

impl DerefOperand {
    /// Create a simple base+displacement operand.
    pub fn base_disp(base: usize, base_name: impl Into<String>, disp: i64, size: usize) -> Self {
        Self {
            base_reg: Some(base),
            base_name: Some(base_name.into()),
            index_reg: None,
            index_name: None,
            scale: 1,
            displacement: disp,
            deref_size: size,
            segment: None,
        }
    }

    /// Create a displacement-only operand.
    pub fn displacement_only(disp: i64, size: usize) -> Self {
        Self {
            base_reg: None,
            base_name: None,
            index_reg: None,
            index_name: None,
            scale: 1,
            displacement: disp,
            deref_size: size,
            segment: None,
        }
    }

    /// Create a full SIB operand (base + index * scale + displacement).
    pub fn sib(
        base: Option<(usize, String)>,
        index: Option<(usize, String)>,
        scale: u8,
        disp: i64,
        size: usize,
    ) -> Self {
        Self {
            base_reg: base.as_ref().map(|(i, _)| *i),
            base_name: base.map(|(_, n)| n),
            index_reg: index.as_ref().map(|(i, _)| *i),
            index_name: index.map(|(_, n)| n),
            scale,
            displacement: disp,
            deref_size: size,
            segment: None,
        }
    }

    /// Set segment override.
    pub fn with_segment(mut self, segment: impl Into<String>) -> Self {
        self.segment = Some(segment.into());
        self
    }
}

impl Operand for DerefOperand {
    fn as_any(&self) -> &dyn Any { self }

    fn get_value(&self, _op: &super::Opcode) -> Option<u64> {
        None
    }

    fn is_deref(&self) -> bool {
        true
    }

    fn get_address(&self, _op: &super::Opcode) -> Option<u64> {
        // If no registers involved, we can compute the address
        if self.base_reg.is_none() && self.index_reg.is_none() {
            Some(self.displacement as u64)
        } else {
            None
        }
    }

    fn repr(&self, _op: &super::Opcode) -> String {
        let mut parts = Vec::new();

        // Segment prefix
        let seg_prefix = self.segment.as_ref().map(|s| format!("{}:", s)).unwrap_or_default();

        // Size prefix
        let size_prefix = match self.deref_size {
            1 => "byte ptr ",
            2 => "word ptr ",
            4 => "dword ptr ",
            8 => "qword ptr ",
            16 => "xmmword ptr ",
            _ => "",
        };

        // Build the address expression
        if let Some(base) = &self.base_name {
            parts.push(base.clone());
        }

        if let Some(index) = &self.index_name {
            if self.scale > 1 {
                parts.push(format!("{}*{}", index, self.scale));
            } else {
                parts.push(index.clone());
            }
        }

        let disp_str = if self.displacement != 0 || parts.is_empty() {
            if self.displacement >= 0 {
                if parts.is_empty() {
                    format!("{:#x}", self.displacement)
                } else {
                    format!("+{:#x}", self.displacement)
                }
            } else {
                format!("-{:#x}", -self.displacement)
            }
        } else {
            String::new()
        };

        if parts.is_empty() {
            format!("{}{}[{}]", seg_prefix, size_prefix, disp_str)
        } else {
            format!("{}{}[{}{}]", seg_prefix, size_prefix, parts.join("+"), disp_str)
        }
    }

    fn size(&self) -> usize {
        self.deref_size
    }

    fn clone_box(&self) -> Box<dyn Operand> {
        Box::new(self.clone())
    }
}

// ============================================================================
// PC-Relative Operand
// ============================================================================

/// A PC-relative address operand.
#[derive(Debug, Clone)]
pub struct PcRelativeOperand {
    /// The offset from the next instruction.
    pub offset: i64,
    /// Size of the operand in bytes.
    pub operand_size: usize,
}

impl PcRelativeOperand {
    /// Create a new PC-relative operand.
    pub fn new(offset: i64, size: usize) -> Self {
        Self {
            offset,
            operand_size: size,
        }
    }
}

impl Operand for PcRelativeOperand {
    fn as_any(&self) -> &dyn Any { self }

    fn get_value(&self, op: &super::Opcode) -> Option<u64> {
        let target = (op.va as i64) + (op.size as i64) + self.offset;
        Some(target as u64)
    }

    fn is_immed(&self) -> bool {
        true
    }

    fn is_discrete(&self) -> bool {
        true
    }

    fn repr(&self, op: &super::Opcode) -> String {
        if let Some(target) = self.get_value(op) {
            format!("{:#x}", target)
        } else {
            format!("$+{:#x}", self.offset)
        }
    }

    fn size(&self) -> usize {
        self.operand_size
    }

    fn clone_box(&self) -> Box<dyn Operand> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_immediate_operand() {
        let imm = ImmediateOperand::new(0x1234, 4);
        assert!(imm.is_immed());
        assert!(imm.is_discrete());
        assert!(!imm.is_reg());
        assert!(!imm.is_deref());
    }

    #[test]
    fn test_register_operand() {
        let reg = RegisterOperand::new(0, "eax", 4);
        assert!(reg.is_reg());
        assert!(!reg.is_immed());
        assert!(!reg.is_deref());
    }

    #[test]
    fn test_deref_operand() {
        let deref = DerefOperand::base_disp(0, "rbp", -8, 8);
        assert!(deref.is_deref());
        assert!(!deref.is_immed());
        assert!(!deref.is_reg());
    }
}
