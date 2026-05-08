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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_info_construction() {
        let func = FunctionInfo {
            address: 0x401000,
            name: Some("main".to_string()),
            size: 256,
            basic_blocks: Vec::new(),
            calling_convention: Some("cdecl".to_string()),
        };
        assert_eq!(func.address, 0x401000);
        assert_eq!(func.name.as_deref(), Some("main"));
        assert_eq!(func.size, 256);
        assert!(func.basic_blocks.is_empty());
        assert_eq!(func.calling_convention.as_deref(), Some("cdecl"));
    }

    #[test]
    fn test_function_info_no_name() {
        let func = FunctionInfo {
            address: 0x402000,
            name: None,
            size: 64,
            basic_blocks: Vec::new(),
            calling_convention: None,
        };
        assert!(func.name.is_none());
        assert!(func.calling_convention.is_none());
    }

    #[test]
    fn test_basic_block_size() {
        let bb = BasicBlock {
            start: 0x401000,
            end: 0x401020,
            instructions: Vec::new(),
            successors: vec![0x401020, 0x401050],
        };
        assert_eq!(bb.size(), 0x20);
        assert_eq!(bb.successors.len(), 2);
    }

    #[test]
    fn test_basic_block_zero_size() {
        let bb = BasicBlock {
            start: 0x401000,
            end: 0x401000,
            instructions: Vec::new(),
            successors: Vec::new(),
        };
        assert_eq!(bb.size(), 0);
    }

    #[test]
    fn test_instruction_disasm_with_operands() {
        let instr = Instruction {
            address: 0x401000,
            size: 3,
            mnemonic: "mov".to_string(),
            operands: "eax, ebx".to_string(),
            bytes: vec![0x89, 0xD8, 0x90],
        };
        assert_eq!(instr.disasm(), "mov eax, ebx");
    }

    #[test]
    fn test_instruction_disasm_no_operands() {
        let instr = Instruction {
            address: 0x401000,
            size: 1,
            mnemonic: "nop".to_string(),
            operands: String::new(),
            bytes: vec![0x90],
        };
        assert_eq!(instr.disasm(), "nop");
    }

    #[test]
    fn test_instruction_disasm_ret() {
        let instr = Instruction {
            address: 0x401000,
            size: 1,
            mnemonic: "ret".to_string(),
            operands: String::new(),
            bytes: vec![0xC3],
        };
        assert_eq!(instr.disasm(), "ret");
    }

    #[test]
    fn test_xref_construction() {
        let xref = XRef {
            from: 0x401000,
            to: 0x402000,
            ref_type: XRefType::Call,
        };
        assert_eq!(xref.from, 0x401000);
        assert_eq!(xref.to, 0x402000);
        assert_eq!(xref.ref_type, XRefType::Call);
    }

    #[test]
    fn test_xref_types() {
        assert_ne!(XRefType::Call, XRefType::Jump);
        assert_ne!(XRefType::Call, XRefType::Data);
        assert_ne!(XRefType::Jump, XRefType::Data);
    }

    #[test]
    fn test_xref_type_from_ref_type() {
        assert_eq!(XRefType::from(RefType::Code), XRefType::Call);
        assert_eq!(XRefType::from(RefType::Data), XRefType::Data);
        assert_eq!(XRefType::from(RefType::Pointer), XRefType::Data);
    }

    #[test]
    fn test_import_info_construction() {
        let imp = ImportInfo {
            address: 0x42E000,
            library: "kernel32.dll".to_string(),
            name: "ExitProcess".to_string(),
            ordinal: Some(42),
        };
        assert_eq!(imp.address, 0x42E000);
        assert_eq!(imp.library, "kernel32.dll");
        assert_eq!(imp.name, "ExitProcess");
        assert_eq!(imp.ordinal, Some(42));
    }

    #[test]
    fn test_import_info_no_ordinal() {
        let imp = ImportInfo {
            address: 0x42E008,
            library: "msvcrt.dll".to_string(),
            name: "printf".to_string(),
            ordinal: None,
        };
        assert!(imp.ordinal.is_none());
    }

    #[test]
    fn test_export_info_construction() {
        let exp = ExportInfo {
            address: 0x401000,
            name: "DllMain".to_string(),
            ordinal: Some(1),
        };
        assert_eq!(exp.address, 0x401000);
        assert_eq!(exp.name, "DllMain");
        assert_eq!(exp.ordinal, Some(1));
    }

    #[test]
    fn test_section_info_construction() {
        let sec = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x401000,
            virtual_size: 0x1000,
            raw_size: 0x800,
            raw_offset: 0x200,
            executable: true,
            writable: false,
            readable: true,
        };
        assert_eq!(sec.name, ".text");
        assert_eq!(sec.virtual_address, 0x401000);
        assert_eq!(sec.virtual_size, 0x1000);
        assert_eq!(sec.raw_size, 0x800);
        assert!(sec.executable);
        assert!(!sec.writable);
        assert!(sec.readable);
    }

    #[test]
    fn test_section_info_data_section() {
        let sec = SectionInfo {
            name: ".data".to_string(),
            virtual_address: 0x402000,
            virtual_size: 0x2000,
            raw_size: 0x1000,
            raw_offset: 0xA00,
            executable: false,
            writable: true,
            readable: true,
        };
        assert!(!sec.executable);
        assert!(sec.writable);
        assert!(sec.readable);
    }

    #[test]
    fn test_function_info_clone() {
        let func = FunctionInfo {
            address: 0x401000,
            name: Some("test".to_string()),
            size: 128,
            basic_blocks: vec![BasicBlock {
                start: 0x401000,
                end: 0x401080,
                instructions: Vec::new(),
                successors: Vec::new(),
            }],
            calling_convention: None,
        };
        let cloned = func.clone();
        assert_eq!(cloned.address, func.address);
        assert_eq!(cloned.name, func.name);
        assert_eq!(cloned.basic_blocks.len(), 1);
        assert_eq!(cloned.basic_blocks[0].size(), 0x80);
    }

    #[test]
    fn test_instruction_clone() {
        let instr = Instruction {
            address: 0x401000,
            size: 5,
            mnemonic: "call".to_string(),
            operands: "0x402000".to_string(),
            bytes: vec![0xE8, 0xFB, 0x0F, 0x00, 0x00],
        };
        let cloned = instr.clone();
        assert_eq!(cloned.address, instr.address);
        assert_eq!(cloned.size, instr.size);
        assert_eq!(cloned.disasm(), "call 0x402000");
        assert_eq!(cloned.bytes.len(), 5);
    }
}
