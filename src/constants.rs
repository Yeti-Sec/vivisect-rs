//! Constants and enumerations for the vivisect framework.
//!
//! Translated from Python's vivisect/const.py and envi/__init__.py.

use bitflags::bitflags;

// ============================================================================
// Workspace Events (VWE_*)
// All events in a vivisect workspace are notified async.
// ============================================================================

/// Workspace event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum WorkspaceEvent {
    AddLocation = 1,
    DelLocation = 2,
    AddSegment = 3,
    DelSegment = 4,
    AddReloc = 5,
    DelReloc = 6,
    AddModule = 7,      // Deprecated
    DelModule = 8,      // Deprecated
    AddFModule = 9,     // Deprecated
    DelFModule = 10,    // Deprecated
    AddFunction = 11,
    DelFunction = 12,
    SetFuncArgs = 13,
    SetFuncMeta = 14,
    AddCodeBlock = 15,
    DelCodeBlock = 16,
    AddXref = 17,
    DelXref = 18,
    SetName = 19,
    AddMmap = 20,
    DelMmap = 21,
    AddExport = 22,
    DelExport = 23,
    SetMeta = 24,
    Comment = 25,
    AddFile = 26,
    DelFile = 27,
    SetFileMeta = 28,
    AddColor = 29,
    DelColor = 30,
    AddVaSet = 31,
    DelVaSet = 32,
    AddFref = 33,
    DelFref = 34,
    SetVaSetRow = 35,
    DelVaSetRow = 36,
    AddFsig = 37,
    DelFsig = 38,
    FollowMe = 39,      // Legacy
    Chat = 40,
    SymHint = 41,
    AutoAnalFin = 42,
    WriteMem = 43,
    Endian = 44,
}

/// Maximum workspace event value.
pub const VWE_MAX: u32 = 45;

/// Transient event mask.
pub const VTE_MASK: u32 = 0x80000000;

// ============================================================================
// Reference Types (REF_*)
// ============================================================================

/// Cross-reference types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RefType {
    /// A branch/call reference.
    Code = 1,
    /// A memory dereference.
    Data = 2,
    /// A pointer immediate.
    Pointer = 3,
}

impl RefType {
    /// Get human-readable name for reference type.
    pub fn name(&self) -> &'static str {
        match self {
            RefType::Code => "Code",
            RefType::Data => "Data",
            RefType::Pointer => "Pointer",
        }
    }
}

// ============================================================================
// Location Types (LOC_*)
// ============================================================================

/// Location types in the workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LocationType {
    /// An undefined "non-location".
    Undefined = 0,
    /// A numerical value (non-pointer).
    Number = 1,
    /// A null-terminated string.
    String = 2,
    /// A null-terminated unicode string.
    Unicode = 3,
    /// A known-derefable pointer.
    Pointer = 4,
    /// An opcode.
    Op = 5,
    /// A custom structure.
    Struct = 6,
    /// A CLSID.
    Clsid = 7,
    /// A C++ vtable.
    VfTable = 8,
    /// An import pointer.
    Import = 9,
    /// Padding bytes.
    Pad = 10,
}

impl LocationType {
    /// Get human-readable name for location type.
    pub fn name(&self) -> &'static str {
        match self {
            LocationType::Undefined => "Undefined",
            LocationType::Number => "Num/Int",
            LocationType::String => "String",
            LocationType::Unicode => "Unicode",
            LocationType::Pointer => "Pointer",
            LocationType::Op => "Opcode",
            LocationType::Struct => "Structure",
            LocationType::Clsid => "Clsid",
            LocationType::VfTable => "VFTable",
            LocationType::Import => "Import Entry",
            LocationType::Pad => "Pad",
        }
    }
}

/// Maximum location type value.
pub const LOC_MAX: u8 = 11;

// ============================================================================
// Tuple Field Indices
// ============================================================================

/// Location tuple field indices.
pub mod location_fields {
    pub const VA: usize = 0;
    pub const SIZE: usize = 1;
    pub const LTYPE: usize = 2;
    pub const TINFO: usize = 3;
}

/// Code block tuple field indices.
pub mod codeblock_fields {
    pub const VA: usize = 0;
    pub const SIZE: usize = 1;
    pub const FUNC_VA: usize = 2;
}

/// Memory map tuple field indices.
pub mod mmap_fields {
    pub const VA: usize = 0;
    pub const SIZE: usize = 1;
    pub const PERMS: usize = 2;
    pub const FNAME: usize = 3;
}

/// Segment tuple field indices.
pub mod segment_fields {
    pub const VA: usize = 0;
    pub const SIZE: usize = 1;
    pub const NAME: usize = 2;
    pub const FNAME: usize = 3;
}

/// XREF tuple field indices.
pub mod xref_fields {
    pub const FROM: usize = 0;
    pub const TO: usize = 1;
    pub const RTYPE: usize = 2;
    pub const RFLAG: usize = 3;
}

// ============================================================================
// Export Types
// ============================================================================

/// Export types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ExportType {
    Untyped = 0xffffffff,
    Function = 0,
    Data = 1,
}

// ============================================================================
// Relocation Types
// ============================================================================

/// Relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RelocationType {
    /// VA contains a pointer to a VA.
    BaseReloc = 0,
    /// Add base and offset to a pointer at memory location.
    BaseOff = 1,
    /// Like BaseOff but treated as a pointer.
    BasePtr = 2,
}

// ============================================================================
// Architecture Constants
// ============================================================================

/// Architecture identifiers (shifted by 16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Architecture {
    Default = 0 << 16,
    I386 = 1 << 16,
    Amd64 = 2 << 16,
    ArmV7 = 3 << 16,
    Thumb16 = 4 << 16,
    Thumb = 5 << 16,
    Msp430 = 6 << 16,
    H8 = 7 << 16,
    A64 = 8 << 16,
    RiscV32 = 9 << 16,
    RiscV64 = 10 << 16,
    PpcE32 = 11 << 16,
    PpcE64 = 12 << 16,
    PpcS32 = 13 << 16,
    PpcS64 = 14 << 16,
    PpcVle = 15 << 16,
    PpcD = 16 << 16,
    Mcs51 = 17 << 16,
    RxV2 = 18 << 16,
    Sparc = 19 << 16,
    Sparc64 = 20 << 16,
    Mips32 = 21 << 16,
    Mips64 = 22 << 16,
}

impl Architecture {
    /// Get architecture name.
    pub fn name(&self) -> &'static str {
        match self {
            Architecture::Default => "default",
            Architecture::I386 => "i386",
            Architecture::Amd64 => "amd64",
            Architecture::ArmV7 => "arm",
            Architecture::Thumb16 => "thumb16",
            Architecture::Thumb => "thumb",
            Architecture::Msp430 => "msp430",
            Architecture::H8 => "h8",
            Architecture::A64 => "a64",
            Architecture::RiscV32 => "rv32",
            Architecture::RiscV64 => "rv64",
            Architecture::PpcE32 => "ppc32-embedded",
            Architecture::PpcE64 => "ppc-embedded",
            Architecture::PpcS32 => "ppc32-server",
            Architecture::PpcS64 => "ppc-server",
            Architecture::PpcVle => "ppc-vle",
            Architecture::PpcD => "ppc-desktop",
            Architecture::Mcs51 => "mcs51",
            Architecture::RxV2 => "rxv2",
            Architecture::Sparc => "sparc",
            Architecture::Sparc64 => "sparc64",
            Architecture::Mips32 => "mips32",
            Architecture::Mips64 => "mips64",
        }
    }

    /// Get pointer size for architecture.
    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::I386 | Architecture::ArmV7 | Architecture::Thumb16
            | Architecture::Thumb | Architecture::Msp430 | Architecture::H8
            | Architecture::RiscV32 | Architecture::PpcE32 | Architecture::PpcS32
            | Architecture::PpcVle | Architecture::PpcD | Architecture::Mcs51
            | Architecture::RxV2 | Architecture::Sparc | Architecture::Mips32 => 4,

            Architecture::Amd64 | Architecture::A64 | Architecture::RiscV64
            | Architecture::PpcE64 | Architecture::PpcS64 | Architecture::Sparc64
            | Architecture::Mips64 => 8,

            Architecture::Default => std::mem::size_of::<usize>(),
        }
    }
}

/// Architecture mask for extracting arch from flags.
pub const ARCH_MASK: u32 = 0xffff0000;

// ============================================================================
// Instruction Flags (IF_*)
// ============================================================================

bitflags! {
    /// Instruction flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InstructionFlags: u32 {
        /// Instruction does NOT fall through.
        const NO_FALL = 0x01;
        /// Privileged mode instruction.
        const PRIV = 0x02;
        /// Instruction branches to a procedure (call).
        const CALL = 0x04;
        /// Instruction is a branch.
        const BRANCH = 0x08;
        /// Instruction terminates a procedure (return).
        const RET = 0x10;
        /// Instruction is conditional.
        const COND = 0x20;
        /// Instruction repeats.
        const REPEAT = 0x40;
        /// Conditional branch (COND | BRANCH).
        const BRANCH_COND = Self::COND.bits() | Self::BRANCH.bits();
    }
}

// ============================================================================
// Branch Flags (BR_*)
// ============================================================================

bitflags! {
    /// Branch flags returned by getBranches().
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BranchFlags: u32 {
        /// Branch target is a procedure (call).
        const PROC = 1 << 0;
        /// Branch is conditional.
        const COND = 1 << 1;
        /// Branch target is dereferenced into PC.
        const DEREF = 1 << 2;
        /// Branch target is base of pointer array.
        const TABLE = 1 << 3;
        /// Branch is fall-through.
        const FALL = 1 << 4;
        /// Branch switches opcode formats.
        const ARCH = 1 << 5;
    }
}

// ============================================================================
// Memory Permissions
// ============================================================================

bitflags! {
    /// Memory region permissions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryPermissions: u8 {
        /// Readable.
        const READ = 0x01;
        /// Writable.
        const WRITE = 0x02;
        /// Executable.
        const EXEC = 0x04;
        /// Read + Write.
        const RW = Self::READ.bits() | Self::WRITE.bits();
        /// Read + Execute.
        const RX = Self::READ.bits() | Self::EXEC.bits();
        /// Read + Write + Execute.
        const RWX = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

// ============================================================================
// Endianness
// ============================================================================

/// Byte order/endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Endian {
    /// Little-endian (LSB first).
    #[default]
    Little,
    /// Big-endian (MSB first).
    Big,
}

impl Endian {
    /// Check if big-endian.
    pub fn is_big(&self) -> bool {
        matches!(self, Endian::Big)
    }

    /// Check if little-endian.
    pub fn is_little(&self) -> bool {
        matches!(self, Endian::Little)
    }
}

// ============================================================================
// Symboliks Types
// ============================================================================

/// Symboliks effect types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EffectType {
    Debug = 0,
    SetVar = 1,
    ReadMem = 2,
    WriteMem = 3,
    CallFunc = 4,
    Constrain = 5,
}

/// Symboliks object types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SymbolikType {
    Var = 0,
    Arg = 1,
    Call = 2,
    Mem = 3,
    Sext = 4,
    Const = 5,
    Lookup = 6,
    Not = 7,
    // Operators
    OperAdd = 0x00010001,
    OperSub = 0x00010002,
    OperMul = 0x00010003,
    OperDiv = 0x00010004,
    OperAnd = 0x00010005,
    OperOr = 0x00010006,
    OperXor = 0x00010007,
    OperMod = 0x00010008,
    OperLshift = 0x00010009,
    OperRshift = 0x0001000a,
    OperPow = 0x0001000b,
    // Constraints
    ConEq = 0x00020001,
    ConNe = 0x00020002,
    ConGt = 0x00020003,
    ConGe = 0x00020004,
    ConLt = 0x00020005,
    ConLe = 0x00020006,
    ConUnk = 0x00020007,
    ConNotUnk = 0x00020008,
}

/// Mask for symbolik operator type.
pub const SYMT_OPER: u32 = 0x00010000;
/// Mask for symbolik constraint type.
pub const SYMT_CON: u32 = 0x00020000;

// ============================================================================
// VA Set Types
// ============================================================================

/// VA set column types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VaSetType {
    Address = 0,
    Integer = 1,
    String = 2,
    HexTup = 3,
    Complex = 4,
}

// ============================================================================
// API Fields
// ============================================================================

/// API tuple field indices.
pub mod api_fields {
    pub const RET_TYPE: usize = 0;
    pub const RET_NAME: usize = 1;
    pub const CCONV: usize = 2;
    pub const FUNC_NAME: usize = 3;
    pub const ARG_START: usize = 4;
}

// ============================================================================
// Local Symbol Types
// ============================================================================

/// Function local symbol types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LocalSymbolType {
    /// Symbol info is (typestr, name) tuple.
    Name = 0,
    /// Symbol info is an argument index.
    FuncArg = 1,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Architecture Tests
    // =========================================================================

    #[test]
    fn test_architecture_pointer_size_32bit() {
        assert_eq!(Architecture::I386.pointer_size(), 4);
        assert_eq!(Architecture::ArmV7.pointer_size(), 4);
        assert_eq!(Architecture::Thumb16.pointer_size(), 4);
        assert_eq!(Architecture::Thumb.pointer_size(), 4);
        assert_eq!(Architecture::Msp430.pointer_size(), 4);
        assert_eq!(Architecture::H8.pointer_size(), 4);
        assert_eq!(Architecture::RiscV32.pointer_size(), 4);
        assert_eq!(Architecture::PpcE32.pointer_size(), 4);
        assert_eq!(Architecture::PpcS32.pointer_size(), 4);
        assert_eq!(Architecture::PpcVle.pointer_size(), 4);
        assert_eq!(Architecture::PpcD.pointer_size(), 4);
        assert_eq!(Architecture::Mcs51.pointer_size(), 4);
        assert_eq!(Architecture::RxV2.pointer_size(), 4);
        assert_eq!(Architecture::Sparc.pointer_size(), 4);
        assert_eq!(Architecture::Mips32.pointer_size(), 4);
    }

    #[test]
    fn test_architecture_pointer_size_64bit() {
        assert_eq!(Architecture::Amd64.pointer_size(), 8);
        assert_eq!(Architecture::A64.pointer_size(), 8);
        assert_eq!(Architecture::RiscV64.pointer_size(), 8);
        assert_eq!(Architecture::PpcE64.pointer_size(), 8);
        assert_eq!(Architecture::PpcS64.pointer_size(), 8);
        assert_eq!(Architecture::Sparc64.pointer_size(), 8);
        assert_eq!(Architecture::Mips64.pointer_size(), 8);
    }

    #[test]
    fn test_architecture_default_pointer_size() {
        let size = Architecture::Default.pointer_size();
        assert_eq!(size, std::mem::size_of::<usize>());
    }

    #[test]
    fn test_architecture_name_common() {
        assert_eq!(Architecture::I386.name(), "i386");
        assert_eq!(Architecture::Amd64.name(), "amd64");
        assert_eq!(Architecture::ArmV7.name(), "arm");
        assert_eq!(Architecture::A64.name(), "a64");
        assert_eq!(Architecture::Default.name(), "default");
    }

    #[test]
    fn test_architecture_name_all_variants() {
        // Ensure every variant returns a non-empty name
        let archs = [
            Architecture::Default, Architecture::I386, Architecture::Amd64,
            Architecture::ArmV7, Architecture::Thumb16, Architecture::Thumb,
            Architecture::Msp430, Architecture::H8, Architecture::A64,
            Architecture::RiscV32, Architecture::RiscV64,
            Architecture::PpcE32, Architecture::PpcE64,
            Architecture::PpcS32, Architecture::PpcS64,
            Architecture::PpcVle, Architecture::PpcD,
            Architecture::Mcs51, Architecture::RxV2,
            Architecture::Sparc, Architecture::Sparc64,
            Architecture::Mips32, Architecture::Mips64,
        ];
        for arch in &archs {
            let name = arch.name();
            assert!(!name.is_empty(), "Architecture {:?} has empty name", arch);
        }
    }

    #[test]
    fn test_architecture_repr_values() {
        // Verify the shifted encoding
        assert_eq!(Architecture::Default as u32, 0);
        assert_eq!(Architecture::I386 as u32, 1 << 16);
        assert_eq!(Architecture::Amd64 as u32, 2 << 16);
    }

    // =========================================================================
    // LocationType Tests
    // =========================================================================

    #[test]
    fn test_location_type_name() {
        assert_eq!(LocationType::Undefined.name(), "Undefined");
        assert_eq!(LocationType::Number.name(), "Num/Int");
        assert_eq!(LocationType::String.name(), "String");
        assert_eq!(LocationType::Unicode.name(), "Unicode");
        assert_eq!(LocationType::Pointer.name(), "Pointer");
        assert_eq!(LocationType::Op.name(), "Opcode");
        assert_eq!(LocationType::Struct.name(), "Structure");
        assert_eq!(LocationType::Clsid.name(), "Clsid");
        assert_eq!(LocationType::VfTable.name(), "VFTable");
        assert_eq!(LocationType::Import.name(), "Import Entry");
        assert_eq!(LocationType::Pad.name(), "Pad");
    }

    #[test]
    fn test_location_type_repr_values() {
        assert_eq!(LocationType::Undefined as u8, 0);
        assert_eq!(LocationType::Op as u8, 5);
        assert_eq!(LocationType::Import as u8, 9);
        assert_eq!(LocationType::Pad as u8, 10);
    }

    #[test]
    fn test_location_type_equality() {
        assert_eq!(LocationType::Op, LocationType::Op);
        assert_ne!(LocationType::Op, LocationType::String);
    }

    // =========================================================================
    // RefType Tests
    // =========================================================================

    #[test]
    fn test_ref_type_name() {
        assert_eq!(RefType::Code.name(), "Code");
        assert_eq!(RefType::Data.name(), "Data");
        assert_eq!(RefType::Pointer.name(), "Pointer");
    }

    #[test]
    fn test_ref_type_repr() {
        assert_eq!(RefType::Code as u8, 1);
        assert_eq!(RefType::Data as u8, 2);
        assert_eq!(RefType::Pointer as u8, 3);
    }

    #[test]
    fn test_ref_type_equality() {
        assert_eq!(RefType::Code, RefType::Code);
        assert_ne!(RefType::Code, RefType::Data);
    }

    // =========================================================================
    // Endian Tests
    // =========================================================================

    #[test]
    fn test_endian_default_is_little() {
        let e = Endian::default();
        assert!(e.is_little());
        assert!(!e.is_big());
    }

    #[test]
    fn test_endian_big() {
        let e = Endian::Big;
        assert!(e.is_big());
        assert!(!e.is_little());
    }

    #[test]
    fn test_endian_little() {
        let e = Endian::Little;
        assert!(e.is_little());
        assert!(!e.is_big());
    }

    // =========================================================================
    // MemoryPermissions Tests
    // =========================================================================

    #[test]
    fn test_memory_permissions_individual() {
        assert!(MemoryPermissions::READ.contains(MemoryPermissions::READ));
        assert!(!MemoryPermissions::READ.contains(MemoryPermissions::WRITE));
        assert!(!MemoryPermissions::READ.contains(MemoryPermissions::EXEC));
    }

    #[test]
    fn test_memory_permissions_combined() {
        let rw = MemoryPermissions::RW;
        assert!(rw.contains(MemoryPermissions::READ));
        assert!(rw.contains(MemoryPermissions::WRITE));
        assert!(!rw.contains(MemoryPermissions::EXEC));
    }

    #[test]
    fn test_memory_permissions_rwx() {
        let rwx = MemoryPermissions::RWX;
        assert!(rwx.contains(MemoryPermissions::READ));
        assert!(rwx.contains(MemoryPermissions::WRITE));
        assert!(rwx.contains(MemoryPermissions::EXEC));
    }

    #[test]
    fn test_memory_permissions_rx() {
        let rx = MemoryPermissions::RX;
        assert!(rx.contains(MemoryPermissions::READ));
        assert!(!rx.contains(MemoryPermissions::WRITE));
        assert!(rx.contains(MemoryPermissions::EXEC));
    }

    #[test]
    fn test_memory_permissions_from_bits() {
        let perms = MemoryPermissions::from_bits_truncate(0x05);
        assert!(perms.contains(MemoryPermissions::READ));
        assert!(!perms.contains(MemoryPermissions::WRITE));
        assert!(perms.contains(MemoryPermissions::EXEC));
    }

    // =========================================================================
    // InstructionFlags Tests
    // =========================================================================

    #[test]
    fn test_instruction_flags_no_fall() {
        let flags = InstructionFlags::NO_FALL;
        assert!(flags.contains(InstructionFlags::NO_FALL));
        assert!(!flags.contains(InstructionFlags::CALL));
    }

    #[test]
    fn test_instruction_flags_branch_cond() {
        let flags = InstructionFlags::BRANCH_COND;
        assert!(flags.contains(InstructionFlags::BRANCH));
        assert!(flags.contains(InstructionFlags::COND));
    }

    #[test]
    fn test_instruction_flags_combination() {
        let flags = InstructionFlags::CALL | InstructionFlags::NO_FALL;
        assert!(flags.contains(InstructionFlags::CALL));
        assert!(flags.contains(InstructionFlags::NO_FALL));
        assert!(!flags.contains(InstructionFlags::RET));
    }

    // =========================================================================
    // WorkspaceEvent Tests
    // =========================================================================

    #[test]
    fn test_workspace_event_repr() {
        assert_eq!(WorkspaceEvent::AddLocation as u32, 1);
        assert_eq!(WorkspaceEvent::AddFunction as u32, 11);
        assert_eq!(WorkspaceEvent::AddXref as u32, 17);
        assert_eq!(WorkspaceEvent::SetName as u32, 19);
        assert_eq!(WorkspaceEvent::WriteMem as u32, 43);
    }

    // =========================================================================
    // Symbolik Types Tests
    // =========================================================================

    #[test]
    fn test_constraint_type_masks() {
        assert_eq!(SYMT_OPER, 0x00010000);
        assert_eq!(SYMT_CON, 0x00020000);
        // Operators should have SYMT_OPER in their repr
        assert_ne!(SymbolikType::OperAdd as u32 & SYMT_OPER, 0);
        // Constraints should have SYMT_CON in their repr
        assert_ne!(SymbolikType::ConEq as u32 & SYMT_CON, 0);
    }

    #[test]
    fn test_effect_type_values() {
        assert_eq!(EffectType::Debug as u8, 0);
        assert_eq!(EffectType::SetVar as u8, 1);
        assert_eq!(EffectType::Constrain as u8, 5);
    }

    // =========================================================================
    // BranchFlags Tests
    // =========================================================================

    #[test]
    fn test_branch_flags() {
        let flags = BranchFlags::PROC | BranchFlags::COND;
        assert!(flags.contains(BranchFlags::PROC));
        assert!(flags.contains(BranchFlags::COND));
        assert!(!flags.contains(BranchFlags::DEREF));
    }

    #[test]
    fn test_branch_flags_fall() {
        let flags = BranchFlags::FALL;
        assert!(flags.contains(BranchFlags::FALL));
        assert!(!flags.contains(BranchFlags::TABLE));
    }
}
