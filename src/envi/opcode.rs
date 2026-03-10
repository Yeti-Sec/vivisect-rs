//! Opcode representation for the envi architecture layer.
//!
//! Translated from Python's envi Opcode class.

use crate::constants::{BranchFlags, InstructionFlags};
use crate::envi::operand::Operand;
use std::fmt;

/// A universal representation for an opcode/instruction.
#[derive(Debug, Clone)]
pub struct Opcode {
    /// Virtual address of the instruction.
    pub va: u64,
    /// Architecture-specific opcode value.
    pub opcode: u32,
    /// Instruction mnemonic.
    pub mnem: String,
    /// Instruction prefix flags.
    pub prefixes: u32,
    /// Size of the instruction in bytes.
    pub size: u8,
    /// Instruction operands.
    pub opers: Vec<Box<dyn Operand>>,
    /// Instruction flags (IF_*).
    pub iflags: InstructionFlags,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
}

impl Opcode {
    /// Create a new opcode.
    pub fn new(
        va: u64,
        opcode: u32,
        mnem: impl Into<String>,
        prefixes: u32,
        size: u8,
        operands: Vec<Box<dyn Operand>>,
        iflags: InstructionFlags,
    ) -> Self {
        Self {
            va,
            opcode,
            mnem: mnem.into(),
            prefixes,
            size,
            opers: operands,
            iflags,
            bytes: Vec::new(),
        }
    }

    /// Set the raw bytes.
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    /// Check if this is a call instruction.
    pub fn is_call(&self) -> bool {
        self.iflags.contains(InstructionFlags::CALL)
    }

    /// Check if this is a return instruction.
    pub fn is_return(&self) -> bool {
        self.iflags.contains(InstructionFlags::RET)
    }

    /// Check if this is a branch instruction.
    pub fn is_branch(&self) -> bool {
        self.iflags.contains(InstructionFlags::BRANCH)
    }

    /// Check if this is a conditional instruction.
    pub fn is_conditional(&self) -> bool {
        self.iflags.contains(InstructionFlags::COND)
    }

    /// Check if this instruction falls through to the next.
    pub fn falls_through(&self) -> bool {
        !self.iflags.contains(InstructionFlags::NO_FALL)
    }

    /// Get the address of the next instruction.
    pub fn next_va(&self) -> u64 {
        self.va + self.size as u64
    }

    /// Get branch targets.
    ///
    /// Returns a list of (target_va, branch_flags) tuples.
    pub fn get_branches(&self) -> Vec<(Option<u64>, BranchFlags)> {
        let mut branches = Vec::new();

        // Check operands for branch targets
        for oper in &self.opers {
            if let Some(target) = oper.get_value(self) {
                let mut flags = BranchFlags::empty();

                if self.is_call() {
                    flags |= BranchFlags::PROC;
                }
                if self.is_conditional() {
                    flags |= BranchFlags::COND;
                }
                if oper.is_deref() {
                    flags |= BranchFlags::DEREF;
                }

                branches.push((Some(target), flags));
                break; // Usually only first operand is the target
            }
        }

        // Add fall-through if applicable
        if self.falls_through() {
            branches.push((Some(self.next_va()), BranchFlags::FALL));
        }

        branches
    }

    /// Get branch targets (resolved, non-fall-through).
    pub fn get_targets(&self) -> Vec<(u64, BranchFlags)> {
        self.get_branches()
            .into_iter()
            .filter_map(|(target, flags)| {
                if flags.contains(BranchFlags::FALL) {
                    None
                } else {
                    target.map(|t| (t, flags))
                }
            })
            .collect()
    }

    /// Get an operand by index.
    pub fn get_operand(&self, index: usize) -> Option<&dyn Operand> {
        self.opers.get(index).map(|o| o.as_ref())
    }

    /// Get the number of operands.
    pub fn operand_count(&self) -> usize {
        self.opers.len()
    }

    /// Format with prefix if present.
    fn get_prefix_string(&self) -> String {
        // Override in architecture-specific implementations
        String::new()
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = self.get_prefix_string();
        let prefix_str = if prefix.is_empty() {
            String::new()
        } else {
            format!("{}: ", prefix)
        };

        let operands: Vec<String> = self.opers.iter().map(|o| o.repr(self)).collect();

        if operands.is_empty() {
            write!(f, "{}{}", prefix_str, self.mnem)
        } else {
            write!(f, "{}{} {}", prefix_str, self.mnem, operands.join(", "))
        }
    }
}

impl PartialEq for Opcode {
    fn eq(&self, other: &Self) -> bool {
        self.va == other.va
            && self.opcode == other.opcode
            && self.mnem == other.mnem
            && self.size == other.size
            && self.iflags == other.iflags
            && self.opers.len() == other.opers.len()
    }
}

impl Eq for Opcode {}

impl std::hash::Hash for Opcode {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.mnem.hash(state);
        self.size.hash(state);
    }
}

/// Builder for creating opcodes.
pub struct OpcodeBuilder {
    va: u64,
    opcode: u32,
    mnem: String,
    prefixes: u32,
    size: u8,
    opers: Vec<Box<dyn Operand>>,
    iflags: InstructionFlags,
    bytes: Vec<u8>,
}

impl OpcodeBuilder {
    /// Create a new opcode builder.
    pub fn new(va: u64, mnem: impl Into<String>, size: u8) -> Self {
        Self {
            va,
            opcode: 0,
            mnem: mnem.into(),
            prefixes: 0,
            size,
            opers: Vec::new(),
            iflags: InstructionFlags::empty(),
            bytes: Vec::new(),
        }
    }

    /// Set the opcode value.
    pub fn opcode(mut self, opcode: u32) -> Self {
        self.opcode = opcode;
        self
    }

    /// Set prefix flags.
    pub fn prefixes(mut self, prefixes: u32) -> Self {
        self.prefixes = prefixes;
        self
    }

    /// Add an operand.
    pub fn operand(mut self, oper: Box<dyn Operand>) -> Self {
        self.opers.push(oper);
        self
    }

    /// Add instruction flags.
    pub fn flags(mut self, flags: InstructionFlags) -> Self {
        self.iflags |= flags;
        self
    }

    /// Set raw bytes.
    pub fn bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = bytes;
        self
    }

    /// Mark as a call instruction.
    pub fn call(self) -> Self {
        self.flags(InstructionFlags::CALL | InstructionFlags::BRANCH)
    }

    /// Mark as a return instruction.
    pub fn ret(self) -> Self {
        self.flags(InstructionFlags::RET | InstructionFlags::NO_FALL)
    }

    /// Mark as an unconditional branch.
    pub fn branch(self) -> Self {
        self.flags(InstructionFlags::BRANCH | InstructionFlags::NO_FALL)
    }

    /// Mark as a conditional branch.
    pub fn cond_branch(self) -> Self {
        self.flags(InstructionFlags::BRANCH | InstructionFlags::COND)
    }

    /// Build the opcode.
    pub fn build(self) -> Opcode {
        Opcode {
            va: self.va,
            opcode: self.opcode,
            mnem: self.mnem,
            prefixes: self.prefixes,
            size: self.size,
            opers: self.opers,
            iflags: self.iflags,
            bytes: self.bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envi::operand::{ImmediateOperand, RegisterOperand};

    #[test]
    fn test_opcode_creation() {
        let op = OpcodeBuilder::new(0x401000, "mov", 5)
            .operand(Box::new(RegisterOperand::new(0, "eax", 4)))
            .operand(Box::new(ImmediateOperand::new(0x1234, 4)))
            .build();

        assert_eq!(op.va, 0x401000);
        assert_eq!(op.mnem, "mov");
        assert_eq!(op.size, 5);
        assert_eq!(op.operand_count(), 2);
    }

    #[test]
    fn test_opcode_display() {
        let op = OpcodeBuilder::new(0x401000, "push", 1)
            .operand(Box::new(RegisterOperand::new(0, "ebp", 4)))
            .build();

        assert_eq!(format!("{}", op), "push ebp");
    }

    #[test]
    fn test_branch_detection() {
        let call_op = OpcodeBuilder::new(0x401000, "call", 5)
            .call()
            .operand(Box::new(ImmediateOperand::new(0x402000, 4)))
            .build();

        assert!(call_op.is_call());
        assert!(call_op.is_branch());
        assert!(call_op.falls_through()); // Calls fall through

        let ret_op = OpcodeBuilder::new(0x401000, "ret", 1).ret().build();
        assert!(ret_op.is_return());
        assert!(!ret_op.falls_through());
    }
}
