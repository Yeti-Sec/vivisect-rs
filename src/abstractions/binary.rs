//! Binary analysis abstraction traits.

use crate::constants::{Architecture, RefType};
use crate::error::VivResult;
use std::path::Path;

/// Information about a function in the binary.
#[derive(Clone, Debug)]
pub struct FunctionInfo {
    /// Function start address.
    pub address: u64,
    /// Function name (if known).
    pub name: Option<String>,
    /// Function size in bytes.
    pub size: usize,
    /// Basic blocks within this function.
    pub basic_blocks: Vec<BasicBlock>,
    /// Calling convention name.
    pub calling_convention: Option<String>,
}

/// A basic block in control flow.
#[derive(Clone, Debug)]
pub struct BasicBlock {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Instructions in this block.
    pub instructions: Vec<Instruction>,
    /// Successor addresses.
    pub successors: Vec<u64>,
}

impl BasicBlock {
    /// Get size in bytes.
    pub fn size(&self) -> usize {
        (self.end - self.start) as usize
    }
}

/// A single instruction.
#[derive(Clone, Debug)]
pub struct Instruction {
    /// Instruction address.
    pub address: u64,
    /// Size in bytes.
    pub size: u8,
    /// Mnemonic (e.g., "mov", "push").
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Raw bytes.
    pub bytes: Vec<u8>,
}

impl Instruction {
    /// Get full disassembly string.
    pub fn disasm(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
}

/// Cross-reference information.
#[derive(Clone, Debug)]
pub struct XRef {
    /// Source address.
    pub from: u64,
    /// Target address.
    pub to: u64,
    /// Reference type.
    pub ref_type: XRefType,
}

/// Cross-reference type.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum XRefType {
    /// Function call.
    Call,
    /// Jump/branch.
    Jump,
    /// Data reference.
    Data,
}

impl From<RefType> for XRefType {
    fn from(rt: RefType) -> Self {
        match rt {
            RefType::Code => XRefType::Call,
            RefType::Data => XRefType::Data,
            RefType::Pointer => XRefType::Data,
        }
    }
}

/// Import entry.
#[derive(Clone, Debug)]
pub struct ImportInfo {
    /// Address where import is referenced.
    pub address: u64,
    /// Library/DLL name.
    pub library: String,
    /// Function name.
    pub name: String,
    /// Ordinal (if applicable).
    pub ordinal: Option<u16>,
}

/// Export entry.
#[derive(Clone, Debug)]
pub struct ExportInfo {
    /// Address of exported symbol.
    pub address: u64,
    /// Export name.
    pub name: String,
    /// Ordinal (if applicable).
    pub ordinal: Option<u16>,
}

/// Section/segment information.
#[derive(Clone, Debug)]
pub struct SectionInfo {
    /// Section name.
    pub name: String,
    /// Virtual address.
    pub virtual_address: u64,
    /// Virtual size.
    pub virtual_size: usize,
    /// Raw data size.
    pub raw_size: usize,
    /// Raw data offset in file.
    pub raw_offset: usize,
    /// Is executable.
    pub executable: bool,
    /// Is writable.
    pub writable: bool,
    /// Is readable.
    pub readable: bool,
}

/// Trait for binary analysis backends.
pub trait BinaryAnalyzer: Send + Sync {
    /// Load a binary file.
    fn load(path: &Path) -> VivResult<Self>
    where
        Self: Sized;

    /// Load from bytes.
    fn load_bytes(bytes: &[u8]) -> VivResult<Self>
    where
        Self: Sized;

    /// Get the file format name (PE, ELF, Mach-O, etc.).
    fn format(&self) -> &str;

    /// Get the architecture.
    fn architecture(&self) -> Architecture;

    /// Get the image base address.
    fn image_base(&self) -> u64;

    /// Get the entry point address.
    fn entry_point(&self) -> u64;

    /// Get all sections.
    fn sections(&self) -> Vec<SectionInfo>;

    /// Get section by name.
    fn section_by_name(&self, name: &str) -> Option<SectionInfo>;

    /// Get section containing address.
    fn section_at(&self, addr: u64) -> Option<SectionInfo>;

    /// Get all imports.
    fn imports(&self) -> Vec<ImportInfo>;

    /// Get all exports.
    fn exports(&self) -> Vec<ExportInfo>;

    /// Read bytes at virtual address.
    fn read_va(&self, addr: u64, size: usize) -> VivResult<Vec<u8>>;

    /// Get all discovered functions.
    fn functions(&self) -> Vec<FunctionInfo>;

    /// Get function at address.
    fn function_at(&self, addr: u64) -> Option<FunctionInfo>;

    /// Get cross-references to an address.
    fn xrefs_to(&self, addr: u64) -> Vec<XRef>;

    /// Get cross-references from an address.
    fn xrefs_from(&self, addr: u64) -> Vec<XRef>;

    /// Disassemble at address.
    fn disassemble(&self, addr: u64) -> VivResult<Instruction>;

    /// Disassemble a range.
    fn disassemble_range(&self, start: u64, end: u64) -> VivResult<Vec<Instruction>>;

    /// Check if address is executable code.
    fn is_code(&self, addr: u64) -> bool;

    /// Check if address is valid (mapped).
    fn is_valid(&self, addr: u64) -> bool;
}
