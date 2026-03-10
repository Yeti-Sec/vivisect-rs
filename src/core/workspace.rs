//! VivWorkspace - The main workspace for binary analysis.
//!
//! Translated from Python's vivisect/base.py VivWorkspaceCore.

use crate::abstractions::MemoryAccess;
use crate::constants::{Architecture, Endian, LocationType, MemoryPermissions, RefType};
use crate::core::callgraph::{CallGraph, CallGraphBuilder};
use crate::core::cfg::{CfgBuilder, ControlFlowGraph};
use crate::core::{SymbolTable, XRefManager};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::envi::memory::MemoryObject;
use crate::error::{VivError, VivResult};
use crate::parsers::{detect_format_bytes, BinaryFormat, ElfParser, PeParser};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A location in the workspace.
#[derive(Debug, Clone)]
pub struct Location {
    /// Virtual address.
    pub va: u64,
    /// Size in bytes.
    pub size: usize,
    /// Location type.
    pub ltype: LocationType,
    /// Type-specific info.
    pub tinfo: Option<String>,
}

/// A code block in a function.
#[derive(Debug, Clone)]
pub struct CodeBlock {
    /// Start address.
    pub va: u64,
    /// Size in bytes.
    pub size: usize,
    /// Function this block belongs to.
    pub func_va: u64,
}

/// Function metadata.
#[derive(Debug, Clone, Default)]
pub struct FunctionMeta {
    /// Function name.
    pub name: Option<String>,
    /// Calling convention.
    pub calling_convention: Option<String>,
    /// Return type.
    pub ret_type: Option<String>,
    /// Arguments.
    pub args: Vec<(String, String)>, // (type, name)
    /// Local variables.
    pub locals: Vec<(u64, String, String)>, // (offset, type, name)
    /// Custom metadata.
    pub meta: HashMap<String, String>,
}

/// Segment/section information.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Virtual address.
    pub va: u64,
    /// Size.
    pub size: usize,
    /// Segment name.
    pub name: String,
    /// File name.
    pub filename: String,
}

/// The main vivisect workspace.
pub struct VivWorkspace {
    /// Memory object.
    memory: MemoryObject,
    /// Architecture.
    arch: Architecture,
    /// Endianness.
    endian: Endian,
    /// Locations by address.
    locations: IndexMap<u64, Location>,
    /// Functions by address.
    functions: IndexMap<u64, FunctionMeta>,
    /// Code blocks.
    codeblocks: IndexMap<u64, CodeBlock>,
    /// Segments.
    segments: Vec<Segment>,
    /// Symbol table.
    symbols: SymbolTable,
    /// Cross-references.
    xrefs: XRefManager,
    /// Comments.
    comments: HashMap<u64, String>,
    /// Workspace metadata.
    meta: HashMap<String, String>,
    /// Entry points.
    entry_points: Vec<u64>,
    /// Files loaded.
    files: Vec<FileInfo>,
}

/// Information about a loaded file.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Normalized file name.
    pub name: String,
    /// Base address.
    pub base_addr: u64,
    /// File format.
    pub format: BinaryFormat,
    /// MD5 hash.
    pub md5: Option<String>,
}

impl VivWorkspace {
    /// Create a new empty workspace.
    pub fn new() -> Self {
        Self {
            memory: MemoryObject::new(),
            arch: Architecture::Default,
            endian: Endian::Little,
            locations: IndexMap::new(),
            functions: IndexMap::new(),
            codeblocks: IndexMap::new(),
            segments: Vec::new(),
            symbols: SymbolTable::new(),
            xrefs: XRefManager::new(),
            comments: HashMap::new(),
            meta: HashMap::new(),
            entry_points: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Load a binary file into the workspace.
    pub fn load_from_file(&mut self, path: &Path) -> VivResult<()> {
        tracing::debug!("[workspace] load_from_file: path={}", path.display());
        let data = std::fs::read(path)?;
        let format = detect_format_bytes(&data)?;

        match format {
            BinaryFormat::Pe => self.load_pe_bytes(&data, path),
            BinaryFormat::Elf => self.load_elf_bytes(&data, path),
            _ => Err(VivError::Other {
                message: format!("Unsupported format: {:?}", format),
            }),
        }
    }

    /// Load PE file from bytes.
    fn load_pe_bytes(&mut self, data: &[u8], path: &Path) -> VivResult<()> {
        let pe = PeParser::from_bytes(data.to_vec())?;

        self.arch = pe.architecture();
        self.endian = Endian::Little; // PE is always little-endian

        // Add file info
        self.files.push(FileInfo {
            name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            base_addr: pe.image_base(),
            format: BinaryFormat::Pe,
            md5: None,
        });

        // Add sections as memory maps
        for section in pe.sections() {
            let perms = MemoryPermissions::from_bits_truncate(
                (if section.readable { 1 } else { 0 })
                    | (if section.writable { 2 } else { 0 })
                    | (if section.executable { 4 } else { 0 }),
            );

            // Read section data
            if section.raw_size > 0 {
                if let Ok(section_data) = pe.read_va(section.virtual_address, section.raw_size) {
                    self.memory.add_memory(section.virtual_address, section_data, perms)?;
                }
            }

            self.segments.push(Segment {
                va: section.virtual_address,
                size: section.virtual_size,
                name: section.name.clone(),
                filename: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            });
        }

        // Add entry point
        let entry = pe.entry_point();
        self.entry_points.push(entry);

        // Add exports as symbols/functions
        for export in pe.exports() {
            self.symbols.add_symbol(export.address, &export.name);
            // TODO: Add as function if in executable section
        }

        // Add imports as symbols
        let import_count = pe.imports().len();
        for import in pe.imports() {
            let name = if import.library.is_empty() {
                import.name.clone()
            } else {
                format!("{}.{}", import.library, import.name)
            };
            self.symbols.add_symbol(import.address, &name);
        }

        tracing::debug!(
            "[workspace] loaded PE: arch={:?}, entry={:#x}, sections={}, imports={}, exports={}",
            self.arch,
            entry,
            self.segments.len(),
            import_count,
            pe.exports().len()
        );

        Ok(())
    }

    /// Load ELF file from bytes.
    fn load_elf_bytes(&mut self, data: &[u8], path: &Path) -> VivResult<()> {
        let elf = ElfParser::from_bytes(data.to_vec())?;

        self.arch = elf.architecture();
        // ELF endianness would need to be determined from header

        // Add file info
        self.files.push(FileInfo {
            name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            base_addr: elf.image_base(),
            format: BinaryFormat::Elf,
            md5: None,
        });

        // Add sections
        for section in elf.sections() {
            if section.virtual_size == 0 {
                continue;
            }

            let perms = MemoryPermissions::from_bits_truncate(
                (if section.readable { 1 } else { 0 })
                    | (if section.writable { 2 } else { 0 })
                    | (if section.executable { 4 } else { 0 }),
            );

            if section.raw_size > 0 {
                if let Ok(section_data) = elf.read_va(section.virtual_address, section.raw_size) {
                    let _ = self.memory.add_memory(section.virtual_address, section_data, perms);
                }
            }

            self.segments.push(Segment {
                va: section.virtual_address,
                size: section.virtual_size,
                name: section.name.clone(),
                filename: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
            });
        }

        // Add entry point
        let entry = elf.entry_point();
        if entry != 0 {
            self.entry_points.push(entry);
        }

        // Add exports as symbols
        for export in elf.exports() {
            self.symbols.add_symbol(export.address, &export.name);
        }

        tracing::debug!(
            "[workspace] loaded ELF: arch={:?}, entry={:#x}, sections={}, exports={}",
            self.arch,
            entry,
            self.segments.len(),
            elf.exports().len()
        );

        Ok(())
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Get the endianness.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Get entry points.
    pub fn entry_points(&self) -> &[u64] {
        &self.entry_points
    }

    /// Add a function at address.
    pub fn add_function(&mut self, va: u64, meta: FunctionMeta) -> VivResult<()> {
        tracing::trace!("[workspace] add_function: va={:#x}", va);
        if self.functions.contains_key(&va) {
            return Err(VivError::InvalidFunction { va });
        }
        self.functions.insert(va, meta);
        Ok(())
    }

    /// Get a function by address.
    pub fn get_function(&self, va: u64) -> Option<&FunctionMeta> {
        self.functions.get(&va)
    }

    /// Get all function addresses.
    pub fn get_functions(&self) -> Vec<u64> {
        self.functions.keys().copied().collect()
    }

    /// Get function by name.
    pub fn get_function_by_name(&self, name: &str) -> Option<u64> {
        for (&va, meta) in &self.functions {
            if let Some(func_name) = &meta.name {
                if func_name == name {
                    return Some(va);
                }
            }
        }
        // Also check symbol table
        self.symbols.get_address(name)
    }

    /// Get mutable function metadata.
    pub fn get_function_mut(&mut self, va: u64) -> Option<&mut FunctionMeta> {
        self.functions.get_mut(&va)
    }

    /// Set function name.
    pub fn set_function_name(&mut self, va: u64, name: &str) {
        if let Some(meta) = self.functions.get_mut(&va) {
            meta.name = Some(name.to_string());
        }
        self.symbols.add_symbol(va, name);
    }

    /// Get all functions with their metadata.
    pub fn functions_iter(&self) -> impl Iterator<Item = (&u64, &FunctionMeta)> {
        self.functions.iter()
    }

    /// Get function count.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Check if address is a function start.
    pub fn is_function(&self, va: u64) -> bool {
        self.functions.contains_key(&va)
    }

    /// Get all code blocks for a function.
    pub fn get_function_blocks(&self, func_va: u64) -> Vec<&CodeBlock> {
        self.codeblocks
            .values()
            .filter(|b| b.func_va == func_va)
            .collect()
    }

    /// Calculate function size (sum of all blocks).
    pub fn get_function_size(&self, func_va: u64) -> usize {
        self.codeblocks
            .values()
            .filter(|b| b.func_va == func_va)
            .map(|b| b.size)
            .sum()
    }

    /// Add a location.
    pub fn add_location(&mut self, va: u64, size: usize, ltype: LocationType, tinfo: Option<String>) {
        self.locations.insert(va, Location { va, size, ltype, tinfo });
    }

    /// Get location at address.
    pub fn get_location(&self, va: u64) -> Option<&Location> {
        self.locations.get(&va)
    }

    /// Add a code block.
    pub fn add_codeblock(&mut self, va: u64, size: usize, func_va: u64) {
        self.codeblocks.insert(va, CodeBlock { va, size, func_va });
    }

    /// Get code block at address.
    pub fn get_codeblock(&self, va: u64) -> Option<&CodeBlock> {
        self.codeblocks.get(&va)
    }

    /// Set a name/symbol.
    pub fn set_name(&mut self, va: u64, name: &str) {
        self.symbols.add_symbol(va, name);
    }

    /// Get name at address.
    pub fn get_name(&self, va: u64) -> Option<&str> {
        self.symbols.get_name(va)
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, from_va: u64, to_va: u64, ref_type: RefType) {
        tracing::trace!("[workspace] add_xref: from={:#x}, to={:#x}, ref_type={:?}", from_va, to_va, ref_type);
        self.xrefs.add_xref(from_va, to_va, ref_type);
    }

    /// Get cross-references to an address.
    pub fn get_xrefs_to(&self, va: u64) -> Vec<(u64, RefType)> {
        self.xrefs.get_xrefs_to(va)
    }

    /// Get cross-references from an address.
    pub fn get_xrefs_from(&self, va: u64) -> Vec<(u64, RefType)> {
        self.xrefs.get_xrefs_from(va)
    }

    /// Add a comment.
    pub fn set_comment(&mut self, va: u64, comment: &str) {
        self.comments.insert(va, comment.to_string());
    }

    /// Get comment at address.
    pub fn get_comment(&self, va: u64) -> Option<&str> {
        self.comments.get(&va).map(|s| s.as_str())
    }

    /// Iterate over all comments.
    pub fn comments_iter(&self) -> impl Iterator<Item = (&u64, &String)> {
        self.comments.iter()
    }

    /// Iterate over all locations.
    pub fn locations_iter(&self) -> impl Iterator<Item = (&u64, &Location)> {
        self.locations.iter()
    }

    /// Iterate over all code blocks.
    pub fn codeblocks_iter(&self) -> impl Iterator<Item = (&u64, &CodeBlock)> {
        self.codeblocks.iter()
    }

    /// Set workspace metadata.
    pub fn set_meta(&mut self, key: &str, value: &str) {
        self.meta.insert(key.to_string(), value.to_string());
    }

    /// Get workspace metadata.
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.meta.get(key).map(|s| s.as_str())
    }

    /// Read memory.
    pub fn read_memory(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        self.memory.read_memory(va, size)
    }

    /// Check if address is valid.
    pub fn is_valid_pointer(&self, va: u64) -> bool {
        self.memory.is_valid_address(va)
    }

    /// Get all segments.
    pub fn get_segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Get loaded files.
    pub fn get_files(&self) -> &[FileInfo] {
        &self.files
    }

    /// Get the symbol table.
    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    /// Get statistics about the workspace.
    pub fn stats(&self) -> WorkspaceStats {
        WorkspaceStats {
            functions: self.functions.len(),
            locations: self.locations.len(),
            codeblocks: self.codeblocks.len(),
            segments: self.segments.len(),
            symbols: self.symbols.len(),
            xrefs: self.xrefs.len(),
            memory_size: self.memory.total_size(),
        }
    }

    // =========================================================================
    // CFG METHODS - Compute successors/predecessors from xrefs
    // These implement the missing functionality identified in the review.
    // =========================================================================

    /// Get successor blocks for a code block.
    ///
    /// Successors are computed on-demand from xrefs at the terminal instruction,
    /// exactly like Python vivisect does it.
    pub fn get_block_successors(&self, block_va: u64) -> Vec<u64> {
        tracing::trace!("[workspace] get_block_successors: block_va={:#x}", block_va);
        let block = match self.codeblocks.get(&block_va) {
            Some(b) => b,
            None => return Vec::new(),
        };

        let mut successors = Vec::new();

        // Check xrefs from the last ~15 bytes of the block (max x86 instruction size)
        let check_start = if block.size > 15 {
            block.va + block.size as u64 - 15
        } else {
            block.va
        };

        for offset in 0..block.size.min(15) {
            let addr = check_start + offset as u64;
            if addr >= block.va + block.size as u64 {
                break;
            }

            for (target, ref_type) in self.xrefs.get_xrefs_from(addr) {
                if ref_type == RefType::Code {
                    // Check if target is a known block start
                    if self.codeblocks.contains_key(&target) && !successors.contains(&target) {
                        successors.push(target);
                    }
                }
            }
        }

        // Check for fall-through by looking at the terminal instruction
        if let Ok(falls_through) = self.block_falls_through(block_va) {
            if falls_through {
                let next_addr = block.va + block.size as u64;
                if self.codeblocks.contains_key(&next_addr) && !successors.contains(&next_addr) {
                    successors.push(next_addr);
                }
            }
        }

        tracing::trace!("[workspace] get_block_successors: block_va={:#x}, successors={:?}", block_va, successors);
        successors
    }

    /// Get predecessor blocks for a code block.
    pub fn get_block_predecessors(&self, block_va: u64) -> Vec<u64> {
        let block = match self.codeblocks.get(&block_va) {
            Some(b) => b,
            None => return Vec::new(),
        };

        let mut predecessors = Vec::new();

        // Get xrefs TO the start of this block
        for (from_addr, ref_type) in self.xrefs.get_xrefs_to(block.va) {
            if ref_type == RefType::Code {
                // Find which block contains this address
                for other_block in self.codeblocks.values() {
                    if from_addr >= other_block.va
                        && from_addr < other_block.va + other_block.size as u64
                    {
                        if !predecessors.contains(&other_block.va) {
                            predecessors.push(other_block.va);
                        }
                        break;
                    }
                }
            }
        }

        // Check for fall-through predecessors
        for other_block in self.codeblocks.values() {
            let fall_through_addr = other_block.va + other_block.size as u64;
            if fall_through_addr == block.va {
                // Verify the other block actually falls through
                if let Ok(true) = self.block_falls_through(other_block.va) {
                    if !predecessors.contains(&other_block.va) {
                        predecessors.push(other_block.va);
                    }
                }
            }
        }

        predecessors
    }

    /// Check if a block falls through to the next address.
    fn block_falls_through(&self, block_va: u64) -> VivResult<bool> {
        let block = self.codeblocks.get(&block_va).ok_or(VivError::InvalidFunction { va: block_va })?;

        // Find the terminal instruction
        let term_va = self.find_terminal_instruction(block_va, block.size)?;

        // Disassemble to check if it falls through
        let bytes = self.read_memory(term_va, 16)?;

        let disasm = match self.arch {
            Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
            Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
            _ => return Ok(true), // Assume fall-through for unknown archs
        };

        match disasm.disassemble(&bytes, term_va) {
            Ok(op) => Ok(op.falls_through()),
            Err(_) => Ok(true), // Assume fall-through on error
        }
    }

    /// Find the terminal instruction address in a block.
    fn find_terminal_instruction(&self, block_va: u64, block_size: usize) -> VivResult<u64> {
        // Walk backwards from end of block to find last instruction
        // For simplicity, we scan forward and track the last valid instruction
        let bytes = self.read_memory(block_va, block_size)?;

        let disasm = match self.arch {
            Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
            Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
            _ => return Ok(block_va), // Default to block start
        };

        let mut current_va = block_va;
        let mut last_va = block_va;
        let end_va = block_va + block_size as u64;

        while current_va < end_va {
            let offset = (current_va - block_va) as usize;
            if offset >= bytes.len() {
                break;
            }

            match disasm.disassemble(&bytes[offset..], current_va) {
                Ok(op) => {
                    last_va = current_va;
                    current_va += op.size as u64;
                }
                Err(_) => break,
            }
        }

        Ok(last_va)
    }

    /// Build a control flow graph for a function.
    pub fn build_function_cfg(&self, func_va: u64) -> ControlFlowGraph {
        // Convert codeblocks to HashMap for the builder
        let blocks_map: HashMap<u64, CodeBlock> = self
            .codeblocks
            .iter()
            .map(|(&va, block)| (va, block.clone()))
            .collect();

        let builder = CfgBuilder::new(&blocks_map, &self.xrefs);
        builder.build_function_cfg(func_va)
    }

    /// Build the complete call graph for the workspace.
    pub fn build_call_graph(&self) -> CallGraph {
        let functions: HashSet<u64> = self.functions.keys().copied().collect();

        // Maximum reasonable code block size (64 KB). Blocks larger than this
        // are likely corrupt metadata (e.g., negative sizes from integer underflow
        // in the disassembler) and would cause the addr_to_func HashMap to
        // allocate excessive memory. Such blocks are skipped entirely.
        const MAX_BLOCK_SIZE: usize = 64 * 1024;

        // Build mapping from addresses to their containing function
        let mut addr_to_func: HashMap<u64, u64> = HashMap::new();
        for block in self.codeblocks.values() {
            if block.size > MAX_BLOCK_SIZE {
                log::warn!(
                    "Skipping code block at {:#x} with corrupt size {} bytes (func {:#x}) in call graph",
                    block.va,
                    block.size,
                    block.func_va,
                );
                continue;
            }
            for offset in 0..block.size {
                addr_to_func.insert(block.va + offset as u64, block.func_va);
            }
        }

        let builder = CallGraphBuilder::new(&self.xrefs, &functions);
        builder.build(&addr_to_func)
    }

    /// Get functions that call the given function.
    pub fn get_callers(&self, func_va: u64) -> Vec<u64> {
        let cg = self.build_call_graph();
        cg.get_caller_vas(func_va)
    }

    /// Get functions called by the given function.
    pub fn get_callees(&self, func_va: u64) -> Vec<u64> {
        let cg = self.build_call_graph();
        cg.get_callee_vas(func_va)
    }

    /// Get all code blocks as a HashMap (for CFG building).
    pub fn get_codeblocks_map(&self) -> HashMap<u64, CodeBlock> {
        self.codeblocks
            .iter()
            .map(|(&va, block)| (va, block.clone()))
            .collect()
    }

    /// Get the xref manager (for CFG building).
    pub fn xrefs(&self) -> &XRefManager {
        &self.xrefs
    }

    // =========================================================================
    // ANALYSIS ORCHESTRATION
    // =========================================================================

    /// Run all default analysis modules.
    ///
    /// This is the main analysis entry point, similar to Python's vw.analyze().
    pub fn analyze(&mut self) -> crate::analysis::orchestration::AnalysisResult {
        tracing::debug!("[workspace] analyze: starting analysis pipeline");
        let mut orchestrator = crate::analysis::orchestration::create_default_orchestrator();
        orchestrator.analyze(self)
    }

    /// Run analysis with a custom orchestrator.
    pub fn analyze_with(
        &mut self,
        orchestrator: &mut crate::analysis::orchestration::AnalysisOrchestrator,
    ) -> crate::analysis::orchestration::AnalysisResult {
        orchestrator.analyze(self)
    }
}

impl Default for VivWorkspace {
    fn default() -> Self {
        Self::new()
    }
}

/// Workspace statistics.
#[derive(Debug, Clone)]
pub struct WorkspaceStats {
    pub functions: usize,
    pub locations: usize,
    pub codeblocks: usize,
    pub segments: usize,
    pub symbols: usize,
    pub xrefs: usize,
    pub memory_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_creation() {
        let ws = VivWorkspace::new();
        assert_eq!(ws.architecture(), Architecture::Default);
        assert!(ws.get_functions().is_empty());
    }

    #[test]
    fn test_symbol_management() {
        let mut ws = VivWorkspace::new();
        ws.set_name(0x401000, "main");
        assert_eq!(ws.get_name(0x401000), Some("main"));
    }
}
