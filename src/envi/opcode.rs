//! Opcode representation for the envi architecture layer.
//!
//! Translated from Python's envi Opcode class.

use crate::constants::{BranchFlags, InstructionFlags};
use crate::envi::operand::Operand;
use std::fmt;

/// Structured branch/call target classification.
///
/// Mirrors the roadmap's typed target model so unresolved indirect branches are
/// represented explicitly rather than silently absent (review finding #3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchTarget {
    /// A statically-known absolute target VA.
    Concrete(u64),
    /// A register-indirect target (`jmp rax`); value known only at runtime.
    Register(String),
    /// A memory-indirect target (`jmp [mem]`). `addr` is the effective address
    /// of the pointer when computable (absolute / RIP-relative), else `None`.
    Memory { addr: Option<u64> },
    /// An indirect target that could not be classified further.
    Unresolved,
}

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
    /// Returns a list of `(target_va, branch_flags)` tuples, faithful to Python
    /// `envi` `Opcode.getBranches()`:
    ///
    /// - The branch/call target is operand 0.
    /// - A **memory-indirect** target (`jmp [mem]`, `call [rip+x]`) sets
    ///   `BR_DEREF` and reports the *effective address of the pointer* via
    ///   `Operand::get_address` — `Some(addr)` when computable (absolute /
    ///   RIP-relative), `None` when it depends on a runtime register.
    /// - A **register-indirect** target (`jmp rax`, `call rcx`) reports `None`
    ///   without `BR_DEREF`.
    ///
    /// Unresolved indirect branches are **never dropped**: an entry with a
    /// `None` target is still emitted so downstream analysis knows an indirect
    /// transfer exists (previously these vanished, review finding #3).
    pub fn get_branches(&self) -> Vec<(Option<u64>, BranchFlags)> {
        let mut branches = Vec::new();

        // Only extract operand-based targets for branch/call instructions.
        // Non-branch instructions (mov, add, etc.) must NOT have their operand
        // values treated as branch targets — only fall-through.
        if self.is_branch() || self.is_call() {
            let mut flags = BranchFlags::empty();
            if self.is_call() {
                flags |= BranchFlags::PROC;
            }
            if self.is_conditional() {
                flags |= BranchFlags::COND;
            }

            // The control-flow target is operand 0 (matches Python envi).
            if let Some(oper) = self.opers.first() {
                let target = if oper.is_deref() {
                    flags |= BranchFlags::DEREF;
                    oper.get_address(self)
                } else {
                    oper.get_value(self)
                };
                branches.push((target, flags));
            } else if self.is_branch() {
                // Branch with no decoded operand — preserve as unresolved.
                branches.push((None, flags));
            }
        }

        // Add fall-through if applicable
        if self.falls_through() {
            branches.push((Some(self.next_va()), BranchFlags::FALL));
        }

        branches
    }

    /// Typed view of this instruction's branch/call targets.
    ///
    /// Complements [`get_branches`](Self::get_branches) with structure so callers
    /// can distinguish concrete, register-indirect, memory-indirect, and fully
    /// unresolved targets without re-inspecting operands.
    pub fn branch_targets(&self) -> Vec<(BranchTarget, BranchFlags)> {
        self.get_branches()
            .into_iter()
            .filter(|(_, flags)| !flags.contains(BranchFlags::FALL))
            .map(|(target, flags)| {
                let bt = match target {
                    Some(va) => BranchTarget::Concrete(va),
                    None => {
                        // No resolved address: classify from operand 0.
                        match self.opers.first() {
                            Some(o) if o.is_deref() => BranchTarget::Memory { addr: None },
                            Some(o) if o.is_reg() => BranchTarget::Register(o.repr(self)),
                            _ => BranchTarget::Unresolved,
                        }
                    }
                };
                (bt, flags)
            })
            .collect()
    }

    /// Whether this instruction has at least one indirect (register- or
    /// memory-based) branch/call target that cannot be resolved statically.
    pub fn has_indirect_branch(&self) -> bool {
        self.branch_targets().iter().any(|(t, _)| {
            matches!(
                t,
                BranchTarget::Register(_)
                    | BranchTarget::Memory { addr: None }
                    | BranchTarget::Unresolved
            )
        })
    }

    /// Get memory addresses referenced by non-branch operands.
    ///
    /// Returns addresses from LEA, MOV, and other data-referencing instructions
    /// that point to specific memory locations. Used for tracking data xrefs.
    ///
    /// Both resolved *values* (e.g. an immediate address) and computable
    /// *effective addresses* of memory operands are considered — the latter
    /// captures absolute and RIP-relative `[mem]` references (e.g.
    /// `lea rax, [rip+disp]`, `mov rax, [0x..]`) that previously produced no
    /// data xref (review finding #9).
    pub fn get_memory_references(&self) -> Vec<u64> {
        if self.is_branch() || self.is_call() || self.is_return() {
            return Vec::new();
        }
        let mut refs = Vec::new();
        for oper in &self.opers {
            let addr = if oper.is_deref() {
                oper.get_address(self)
            } else {
                oper.get_value(self)
            };
            if let Some(addr) = addr {
                if addr > 0x1000 {
                    refs.push(addr);
                }
            }
        }
        refs
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
    #[must_use]
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

    #[test]
    fn test_get_memory_references_non_branch() {
        // lea eax, [0x403000] — should produce a memory reference
        let op = OpcodeBuilder::new(0x401000, "lea", 6)
            .operand(Box::new(RegisterOperand::new(0, "eax", 4)))
            .operand(Box::new(ImmediateOperand::new(0x403000, 4)))
            .build();

        let refs = op.get_memory_references();
        assert_eq!(refs.len(), 1);
        assert!(refs.contains(&0x403000));
    }

    #[test]
    fn test_get_memory_references_branch_returns_empty() {
        // call 0x402000 — branches should NOT produce memory references
        let op = OpcodeBuilder::new(0x401000, "call", 5)
            .call()
            .operand(Box::new(ImmediateOperand::new(0x402000, 4)))
            .build();

        let refs = op.get_memory_references();
        assert!(refs.is_empty());
    }

    #[test]
    fn test_get_memory_references_filters_low_addresses() {
        // mov eax, 0x5 — small immediates should be filtered out (not addresses)
        let op = OpcodeBuilder::new(0x401000, "mov", 5)
            .operand(Box::new(RegisterOperand::new(0, "eax", 4)))
            .operand(Box::new(ImmediateOperand::new(5, 4)))
            .build();

        let refs = op.get_memory_references();
        assert!(refs.is_empty());
    }

    // --- Indirect branch preservation (#3), decoded from real x86 bytes ------

    use crate::constants::BranchFlags;
    use crate::envi::archs::{X86Disassembler, X86Mode};

    fn dis64(bytes: &[u8], va: u64) -> Opcode {
        X86Disassembler::new(X86Mode::Mode64)
            .disassemble(bytes, va)
            .expect("decode")
    }
    fn dis32(bytes: &[u8], va: u64) -> Opcode {
        X86Disassembler::new(X86Mode::Mode32)
            .disassemble(bytes, va)
            .expect("decode")
    }

    #[test]
    fn test_call_reg_indirect_preserved() {
        // FF D0 = call rax  (register-indirect call)
        let op = dis64(&[0xFF, 0xD0], 0x401000);
        assert!(op.is_call());
        let br = op.get_branches();
        // Must contain an unresolved (None) PROC target — not dropped.
        assert!(
            br.iter().any(|(t, f)| t.is_none()
                && f.contains(BranchFlags::PROC)
                && !f.contains(BranchFlags::FALL)),
            "call rax lost its indirect target: {:?}",
            br
        );
        // Call still falls through.
        assert!(br.iter().any(|(_, f)| f.contains(BranchFlags::FALL)));
        assert!(op.has_indirect_branch());
        assert_eq!(
            op.branch_targets(),
            vec![(BranchTarget::Register("rax".into()), BranchFlags::PROC)]
        );
    }

    #[test]
    fn test_jmp_reg_indirect_preserved() {
        // FF E0 = jmp rax  (register-indirect, no fall-through)
        let op = dis64(&[0xFF, 0xE0], 0x401000);
        assert!(op.is_branch());
        assert!(!op.falls_through());
        let br = op.get_branches();
        assert_eq!(br.len(), 1, "expected only the indirect target: {:?}", br);
        assert!(br[0].0.is_none() && !br[0].1.contains(BranchFlags::DEREF));
        assert!(op.has_indirect_branch());
    }

    #[test]
    fn test_call_mem_absolute_deref_resolves_pointer_addr() {
        // 32-bit: FF 15 34 12 00 00 = call dword ptr [0x1234]
        // Memory-indirect with an absolute pointer address → BR_DEREF + Some(0x1234).
        let op = dis32(&[0xFF, 0x15, 0x34, 0x12, 0x00, 0x00], 0x401000);
        assert!(op.is_call());
        let br = op.get_branches();
        assert!(
            br.iter().any(|(t, f)| *t == Some(0x1234)
                && f.contains(BranchFlags::PROC)
                && f.contains(BranchFlags::DEREF)),
            "call [0x1234] did not yield a DEREF xref to the pointer: {:?}",
            br
        );
        assert_eq!(
            op.branch_targets()
                .into_iter()
                .find(|(_, f)| f.contains(BranchFlags::DEREF))
                .map(|(t, _)| t),
            Some(BranchTarget::Concrete(0x1234))
        );
    }

    #[test]
    fn test_call_mem_reg_indirect_deref_unresolved() {
        // 64-bit: FF 10 = call qword ptr [rax]
        // Memory-indirect through a register → BR_DEREF with None (runtime addr).
        let op = dis64(&[0xFF, 0x10], 0x401000);
        assert!(op.is_call());
        let br = op.get_branches();
        assert!(
            br.iter().any(|(t, f)| t.is_none()
                && f.contains(BranchFlags::PROC)
                && f.contains(BranchFlags::DEREF)),
            "call [rax] lost its indirect target: {:?}",
            br
        );
        assert!(op.has_indirect_branch());
    }

    #[test]
    fn test_direct_call_still_concrete() {
        // E8 rel32 = call <direct>; must remain a concrete, non-DEREF target.
        let op = dis64(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x401000);
        assert!(op.is_call());
        assert!(!op.has_indirect_branch());
        let targets = op.branch_targets();
        assert_eq!(targets.len(), 1);
        assert!(matches!(targets[0].0, BranchTarget::Concrete(_)));
        assert!(!targets[0].1.contains(BranchFlags::DEREF));
    }

    // --- RIP-relative / effective-address data references (#9) --------------

    #[test]
    fn test_lea_rip_relative_data_reference() {
        // 48 8d 05 10 00 00 00 = lea rax, [rip+0x10] at 0x1000 (len 7).
        // Effective address = 0x1000 + 7 + 0x10 = 0x1017.
        let op = dis64(&[0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(op.mnem, "lea");
        let refs = op.get_memory_references();
        assert!(
            refs.contains(&0x1017),
            "rip-relative lea lost its data reference: {:?}",
            refs
        );
    }

    #[test]
    fn test_mov_rip_relative_data_reference() {
        // 48 8b 05 10 00 00 00 = mov rax, [rip+0x10] at 0x1000 (len 7) -> 0x1017.
        let op = dis64(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00], 0x1000);
        assert_eq!(op.mnem, "mov");
        assert!(op.get_memory_references().contains(&0x1017));
    }

    #[test]
    fn test_stack_deref_produces_no_data_reference() {
        // 48 8b 45 f8 = mov rax, [rbp-8]: a register-relative stack access is
        // NOT a static data reference.
        let op = dis64(&[0x48, 0x8b, 0x45, 0xf8], 0x1000);
        assert!(op.get_memory_references().is_empty());
    }
}
