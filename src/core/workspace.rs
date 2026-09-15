//! VivWorkspace - The main workspace for binary analysis.
//!
//! Translated from Python's vivisect/base.py VivWorkspaceCore.

use crate::constants::{Architecture, Endian, LocationType, MemoryPermissions, RefType};
use crate::core::callgraph::{CallGraph, CallGraphBuilder};
use crate::core::cfg::{CfgBuilder, ControlFlowGraph};
use crate::core::{SymbolTable, XRefManager};
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::envi::memory::MemoryImage;
use crate::error::{VivError, VivResult};
use crate::parsers::{detect_format_bytes, BinaryFormat, ElfParser, MachOParser, PeParser};
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
    /// The single authoritative mapped-memory image (bytes + permissions +
    /// endianness). Every loader, analysis, emulator, and persistence path
    /// derives from this one image (roadmap Phase 4 §2.1).
    image: MemoryImage,
    /// Architecture.
    arch: Architecture,
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
    /// Functions created since last drain (for orchestrator cascade).
    pending_functions: Vec<u64>,
    /// Addresses known to never return (noreturn functions/APIs).
    noreturn_vas: HashSet<u64>,
    /// VA sets — named collections of address-keyed rows.
    /// Port of Python's `self.vasets` / `self.vasetdefs`.
    va_sets: HashMap<String, VaSet>,
    /// Workspace event listeners (callback IDs).
    event_listeners: Vec<(u32, Box<dyn Fn(WorkspaceEvent) + Send + Sync>)>,
    /// Next event listener ID.
    next_listener_id: u32,
    /// Workspace configuration.
    pub config: WorkspaceConfig,
    /// Monotonic generation counter — incremented on every mutation.
    /// Consumers can cache results and compare against this to detect staleness.
    generation: u64,
}

/// A VA set: a named collection of address-keyed rows with typed columns.
///
/// Port of Python's VA sets used for tracking thunk_reg, ResolvedImports,
/// FuncWrappers, PointersFromFile, etc.
#[derive(Debug, Clone, Default)]
pub struct VaSet {
    /// Column definitions: (name, type_name).
    pub columns: Vec<(String, String)>,
    /// Rows keyed by address.
    pub rows: IndexMap<u64, Vec<String>>,
}

/// Workspace event types (port of Python's VWE_* constants).
#[derive(Debug, Clone)]
pub enum WorkspaceEvent {
    AddLocation { va: u64, size: usize },
    DelLocation { va: u64 },
    AddFunction { va: u64 },
    DelFunction { va: u64 },
    SetFuncMeta { va: u64, key: String, value: String },
    AddCodeBlock { va: u64, size: usize, func_va: u64 },
    AddXref { from_va: u64, to_va: u64 },
    SetName { va: u64, name: String },
    SetMeta { key: String, value: String },
    AddFile { name: String },
}

/// Workspace configuration.
///
/// Port of Python's `EnviConfig` / `self.config`.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceConfig {
    /// Analysis configuration.
    pub analysis: AnalysisConfig,
}

/// Analysis-specific configuration.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Minimum string length for string detection.
    pub min_string_length: usize,
    /// Maximum paths for symbolic analysis.
    pub max_sym_paths: usize,
    /// Pointer table minimum length.
    pub pointertable_min_len: usize,
    /// Enable emucode analysis.
    pub emucode_enabled: bool,
    /// Maximum function size (bytes) for analysis.
    pub max_function_size: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            max_sym_paths: 1000,
            pointertable_min_len: 4,
            emucode_enabled: true,
            max_function_size: 0x100000,
        }
    }
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
            image: MemoryImage::new(Endian::Little),
            arch: Architecture::Default,
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
            pending_functions: Vec::new(),
            noreturn_vas: HashSet::new(),
            va_sets: HashMap::new(),
            event_listeners: Vec::new(),
            next_listener_id: 0,
            config: WorkspaceConfig::default(),
            generation: 0,
        }
    }

    /// Get the current generation counter. Incremented on every workspace mutation.
    /// Consumers can cache results and compare against this to detect staleness.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Load a binary file into the workspace.
    #[must_use]
    pub fn load_from_file(&mut self, path: &Path) -> VivResult<()> {
        tracing::debug!("[workspace] load_from_file: path={}", path.display());
        let data = crate::parsers::read_file_limited(path, crate::parsers::DEFAULT_MAX_FILE_SIZE)?;
        let format = detect_format_bytes(&data)?;
        crate::trace::emit(crate::trace::EventKind::LoaderDetect, None, None, || {
            format!("format={:?} path={}", format, path.display())
        });

        match format {
            BinaryFormat::Pe => self.load_pe_bytes(&data, path),
            BinaryFormat::Elf => self.load_elf_bytes(&data, path),
            BinaryFormat::MachO => self.load_macho_bytes(&data, path),
            _ => Err(VivError::Other {
                message: format!("Unsupported format: {:?}", format),
            }),
        }
    }

    /// Load PE file from bytes.
    fn load_pe_bytes(&mut self, data: &[u8], path: &Path) -> VivResult<()> {
        let pe = PeParser::from_bytes(data.to_vec())?;

        self.arch = pe.architecture();
        self.image.set_endian(Endian::Little); // PE is always little-endian

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Compute the sample MD5 so function identities are stable and unique
        // across samples (review finding #14): identities are "{md5}:{va}", not
        // "unknown:{va}".
        let md5 = format!("{:x}", md5::compute(data));
        self.set_meta("StorageName", &filename);
        self.set_meta("md5", &md5);

        // Add file info
        self.files.push(FileInfo {
            name: filename.clone(),
            base_addr: pe.image_base(),
            format: BinaryFormat::Pe,
            md5: Some(md5),
        });

        // Map the PE headers at image_base (matching Python vivisect) through the
        // single normalized mapping entry point — zero-filled to SizeOfHeaders.
        let header_size = pe.header_size();
        if header_size > 0 {
            let _ = self.image.map_normalized(
                pe.image_base(),
                pe.raw_data(),
                0,
                header_size,
                header_size,
                MemoryPermissions::READ,
                Some(filename.clone()),
            );
            self.segments.push(Segment {
                va: pe.image_base(),
                size: header_size,
                name: filename.clone(),
                filename: filename.clone(),
            });
        }

        // Add sections as memory maps
        for section in pe.sections() {
            let perms = MemoryPermissions::from_bits_truncate(
                (if section.readable { 1 } else { 0 })
                    | (if section.writable { 2 } else { 0 })
                    | (if section.executable { 4 } else { 0 }),
            );

            // Map the section's full VirtualSize through the single normalized
            // mapping entry point: raw bytes copied up to raw size, zero-filled
            // to VirtualSize (review finding #4).
            if section.virtual_size > 0 {
                let _ = self.image.map_normalized(
                    section.virtual_address,
                    pe.raw_data(),
                    section.raw_offset,
                    section.raw_size,
                    section.virtual_size,
                    perms,
                    Some(section.name.clone()),
                );
                crate::trace::emit(
                    crate::trace::EventKind::LoaderMapRegion,
                    Some(section.virtual_address),
                    None,
                    || {
                        format!(
                            "map {} va={:#x} vsize={:#x} perms={:?}",
                            section.name, section.virtual_address, section.virtual_size, perms
                        )
                    },
                );
            }

            self.segments.push(Segment {
                va: section.virtual_address,
                size: section.virtual_size,
                name: section.name.clone(),
                filename: filename.clone(),
            });
        }

        // Add primary entry point
        let entry = pe.entry_point();
        self.entry_points.push(entry);

        // Fix 2: Add additional entry points (TLS callbacks, CRT initializers)
        for ep in pe.additional_entry_points() {
            if ep != entry && !self.entry_points.contains(&ep) {
                self.entry_points.push(ep);
            }
        }

        // Add exports as symbols and entry points
        for export in pe.exports() {
            self.symbols.add_symbol(export.address, &export.name);
            // Add exported functions as entry points for analysis
            if !self.entry_points.contains(&export.address) {
                self.entry_points.push(export.address);
            }
        }

        // Fix 4: Add imports as symbols using IAT addresses.
        // Also add import locations for analysis to recognize indirect calls.
        let imports = pe.imports();
        let import_count = imports.len();
        let ptr_size = if pe.is_64() { 8usize } else { 4usize };
        for import in &imports {
            let name = if import.library.is_empty() {
                import.name.clone()
            } else {
                format!("{}.{}", import.library, import.name)
            };
            self.symbols.add_symbol(import.address, &name);
            // Mark as import location so code flow analysis knows
            // indirect calls through these addresses are import calls
            self.add_location(import.address, ptr_size, LocationType::Import, Some(name));
        }

        tracing::debug!(
            "[workspace] loaded PE: arch={:?}, entry={:#x}, entries={}, sections={}, imports={}, exports={}",
            self.arch,
            entry,
            self.entry_points.len(),
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
        self.image.set_endian(elf.endian()); // propagate endianness (review finding #4)

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        // Sample MD5 for stable/unique function identities (review finding #14).
        let md5 = format!("{:x}", md5::compute(data));
        self.set_meta("StorageName", &filename);
        self.set_meta("md5", &md5);

        // Add file info
        self.files.push(FileInfo {
            name: filename.clone(),
            base_addr: elf.image_base(),
            format: BinaryFormat::Elf,
            md5: Some(md5),
        });

        // Map the runtime image from PT_LOAD program headers when present, all
        // through the single normalized entry point: p_filesz copied, zero-filled
        // to p_memsz, permissions from p_flags (review finding #4). Sections are
        // then recorded as metadata only.
        if !elf.load_segments().is_empty() {
            for seg in elf.load_segments() {
                if seg.memsz == 0 {
                    continue;
                }
                let mut perms = MemoryPermissions::empty();
                if seg.read {
                    perms |= MemoryPermissions::READ;
                }
                if seg.write {
                    perms |= MemoryPermissions::WRITE;
                }
                if seg.exec {
                    perms |= MemoryPermissions::EXEC;
                }
                let (base, memsz) = (seg.vaddr, seg.memsz);
                let _ = self.image.map_normalized(
                    seg.vaddr,
                    elf.raw_data(),
                    seg.offset,
                    seg.filesz,
                    seg.memsz,
                    perms,
                    None,
                );
                crate::trace::emit(
                    crate::trace::EventKind::LoaderMapRegion,
                    Some(base),
                    None,
                    || {
                        format!(
                            "PT_LOAD va={:#x} memsz={:#x} perms={:?}",
                            base, memsz, perms
                        )
                    },
                );
            }
            // Sections as metadata (no memory — PT_LOAD is authoritative).
            for section in elf.sections() {
                if section.virtual_size == 0 {
                    continue;
                }
                self.segments.push(Segment {
                    va: section.virtual_address,
                    size: section.virtual_size,
                    name: section.name.clone(),
                    filename: filename.clone(),
                });
            }
        } else {
            // No program headers (e.g. relocatable object): map allocatable
            // sections through the same normalized path so SHT_NOBITS/.bss
            // (raw_size 0) is present and zero-filled to virtual_size.
            for section in elf.sections() {
                if section.virtual_size == 0 {
                    continue;
                }
                let perms = MemoryPermissions::from_bits_truncate(
                    (if section.readable { 1 } else { 0 })
                        | (if section.writable { 2 } else { 0 })
                        | (if section.executable { 4 } else { 0 }),
                );
                let _ = self.image.map_normalized(
                    section.virtual_address,
                    elf.raw_data(),
                    section.raw_offset,
                    section.raw_size,
                    section.virtual_size,
                    perms,
                    Some(section.name.clone()),
                );
                self.segments.push(Segment {
                    va: section.virtual_address,
                    size: section.virtual_size,
                    name: section.name.clone(),
                    filename: filename.clone(),
                });
            }
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

        // Register dynamic imports (GOT/PLT slots resolved from relocations) as
        // symbols + Import locations, so code-flow/thunk analysis can recognize
        // indirect calls through them — completing the reloc → symbol → slot →
        // import relationship (review finding #12), mirroring the PE loader.
        let elf_ptr_size = if elf.is_64() { 8usize } else { 4usize };
        for import in elf.imports() {
            if import.address == 0 || import.name.is_empty() {
                continue;
            }
            self.symbols.add_symbol(import.address, &import.name);
            self.add_location(
                import.address,
                elf_ptr_size,
                LocationType::Import,
                Some(import.name.clone()),
            );
        }

        // Add function entries from .symtab STT_FUNC symbols as entry points.
        // This matches Python's elf.py which adds STT_FUNC symbols via addEntryPoint().
        // Critical for Go binaries and non-stripped ELFs with rich symbol tables.
        let func_entries = elf.function_entries().to_vec();
        let mut symtab_count = 0usize;
        for (fva, fname) in &func_entries {
            if *fva != 0 && self.image.is_mapped(*fva) {
                if !self.entry_points.contains(fva) {
                    self.entry_points.push(*fva);
                    symtab_count += 1;
                }
                if !fname.is_empty() {
                    self.symbols.add_symbol(*fva, fname);
                }
            }
        }

        tracing::debug!(
            "[workspace] loaded ELF: arch={:?}, entry={:#x}, sections={}, exports={}, symtab_funcs={}",
            self.arch,
            entry,
            self.segments.len(),
            elf.exports().len(),
            symtab_count,
        );

        Ok(())
    }

    /// Load a Mach-O file from bytes.
    ///
    /// Wires the existing Mach-O parser into the primary workspace-loading
    /// workflow (review finding #10). Segment sections are mapped through the
    /// same normalized zero-fill path as PE/ELF.
    fn load_macho_bytes(&mut self, data: &[u8], path: &Path) -> VivResult<()> {
        let macho = MachOParser::from_bytes(data.to_vec())?;

        self.arch = macho.architecture();
        // Mach-O on the supported architectures (x86_64 / arm64 / i386) is
        // little-endian.
        self.image.set_endian(Endian::Little);

        let filename = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let md5 = format!("{:x}", md5::compute(data));
        self.set_meta("StorageName", &filename);
        self.set_meta("md5", &md5);

        self.files.push(FileInfo {
            name: filename.clone(),
            base_addr: macho.image_base(),
            format: BinaryFormat::MachO,
            md5: Some(md5),
        });

        // Map sections (derived from LC_SEGMENT load commands) through the
        // shared normalize path: raw bytes copied, zero-filled to virtual size.
        for section in macho.sections() {
            if section.virtual_size == 0 {
                continue;
            }
            let perms = MemoryPermissions::from_bits_truncate(
                (if section.readable { 1 } else { 0 })
                    | (if section.writable { 2 } else { 0 })
                    | (if section.executable { 4 } else { 0 }),
            );
            let base = section.virtual_address;
            let vsize = section.virtual_size;
            let _ = self.image.map_normalized(
                base,
                macho.raw_data(),
                section.raw_offset,
                section.raw_size,
                section.virtual_size,
                perms,
                Some(section.name.clone()),
            );
            crate::trace::emit(
                crate::trace::EventKind::LoaderMapRegion,
                Some(base),
                None,
                || {
                    format!(
                        "macho {} va={:#x} vsize={:#x} perms={:?}",
                        section.name, base, vsize, perms
                    )
                },
            );
            self.segments.push(Segment {
                va: section.virtual_address,
                size: section.virtual_size,
                name: section.name.clone(),
                filename: filename.clone(),
            });
        }

        let entry = macho.entry_point();
        if entry != 0 && !self.entry_points.contains(&entry) {
            self.entry_points.push(entry);
        }

        for export in macho.exports() {
            self.symbols.add_symbol(export.address, &export.name);
        }

        for (fva, fname) in macho.function_entries().to_vec() {
            if fva != 0 && self.image.is_mapped(fva) {
                if !self.entry_points.contains(&fva) {
                    self.entry_points.push(fva);
                }
                if !fname.is_empty() {
                    self.symbols.add_symbol(fva, &fname);
                }
            }
        }

        tracing::debug!(
            "[workspace] loaded Mach-O: arch={:?}, entry={:#x}, sections={}, exports={}",
            self.arch,
            entry,
            self.segments.len(),
            macho.exports().len(),
        );

        Ok(())
    }

    /// Get the architecture.
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Get the endianness.
    pub fn endian(&self) -> Endian {
        self.image.endian()
    }

    /// Get the pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        self.arch.pointer_size()
    }

    /// Get entry points.
    pub fn entry_points(&self) -> &[u64] {
        &self.entry_points
    }

    /// Add a function at address.
    ///
    /// Newly created functions are tracked in a pending list. The analysis
    /// orchestrator drains this list after each workspace module and runs
    /// per-function analysis modules on each new function, matching Python
    /// vivisect's `makeFunction()` → `analyzeFunction()` cascade.
    #[must_use]
    pub fn add_function(&mut self, va: u64, meta: FunctionMeta) -> VivResult<()> {
        tracing::trace!("[workspace] add_function: va={:#x}", va);
        if self.functions.contains_key(&va) {
            return Err(VivError::InvalidFunction { va });
        }
        self.functions.insert(va, meta);
        self.pending_functions.push(va);
        self.generation += 1;
        crate::trace::emit(
            crate::trace::EventKind::AnalysisFunctionAdd,
            Some(va),
            Some(va),
            || format!("add_function va={:#x}", va),
        );
        Ok(())
    }

    /// Drain newly-created functions that haven't been processed by
    /// per-function analysis modules yet.
    pub fn drain_pending_functions(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.pending_functions)
    }

    /// Get a function by address.
    #[must_use]
    pub fn get_function(&self, va: u64) -> Option<&FunctionMeta> {
        self.functions.get(&va)
    }

    /// Get all function addresses.
    pub fn get_functions(&self) -> Vec<u64> {
        self.functions.keys().copied().collect()
    }

    /// Get function by name.
    #[must_use]
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
    #[must_use]
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
    pub fn add_location(
        &mut self,
        va: u64,
        size: usize,
        ltype: LocationType,
        tinfo: Option<String>,
    ) {
        self.locations.insert(
            va,
            Location {
                va,
                size,
                ltype,
                tinfo,
            },
        );
        self.generation += 1;
    }

    /// Get location at address (exact start match only).
    ///
    /// See [`get_location_containing`](Self::get_location_containing) for the
    /// Python `getLocation` containment semantics.
    #[must_use]
    pub fn get_location(&self, va: u64) -> Option<&Location> {
        self.locations.get(&va)
    }

    /// Find the location *containing* `va` — the location `L` with
    /// `L.va <= va < L.va + L.size` (Python vivisect `getLocation` semantics).
    ///
    /// Unlike [`get_location`](Self::get_location) (exact start only), this
    /// resolves an address that falls in the *middle* of a multi-byte location,
    /// which is what predecessor/`va - 1` lookups require (review finding #5).
    #[must_use]
    pub fn get_location_containing(&self, va: u64) -> Option<&Location> {
        // Exact start is the common (and cheapest) case.
        if let Some(loc) = self.locations.get(&va) {
            return Some(loc);
        }
        // Otherwise the nearest location starting at/below `va` whose extent
        // covers it. Locations do not overlap in a well-formed workspace, so at
        // most one qualifies; `max_by_key` picks the closest start defensively.
        self.locations
            .values()
            .filter(|l| l.va <= va && va < l.va.saturating_add(l.size as u64))
            .max_by_key(|l| l.va)
    }

    /// Add a code block.
    pub fn add_codeblock(&mut self, va: u64, size: usize, func_va: u64) {
        self.codeblocks.insert(va, CodeBlock { va, size, func_va });
        self.generation += 1;
        crate::trace::emit(
            crate::trace::EventKind::AnalysisBlockAdd,
            Some(va),
            Some(func_va),
            || format!("block va={:#x} size={} func={:#x}", va, size, func_va),
        );
    }

    /// Get code block at address.
    #[must_use]
    pub fn get_codeblock(&self, va: u64) -> Option<&CodeBlock> {
        self.codeblocks.get(&va)
    }

    /// Set a name/symbol.
    pub fn set_name(&mut self, va: u64, name: &str) {
        self.symbols.add_symbol(va, name);
    }

    /// Get name at address.
    #[must_use]
    pub fn get_name(&self, va: u64) -> Option<&str> {
        self.symbols.get_name(va)
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, from_va: u64, to_va: u64, ref_type: RefType) {
        tracing::trace!(
            "[workspace] add_xref: from={:#x}, to={:#x}, ref_type={:?}",
            from_va,
            to_va,
            ref_type
        );
        self.xrefs.add_xref(from_va, to_va, ref_type);
        crate::trace::emit(
            crate::trace::EventKind::XrefAdd,
            Some(from_va),
            None,
            || format!("xref {:#x} -> {:#x} {:?}", from_va, to_va, ref_type),
        );
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
    #[must_use]
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
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.meta.get(key).map(|s| s.as_str())
    }

    /// Read memory.
    #[must_use]
    pub fn read_memory(&self, va: u64, size: usize) -> VivResult<Vec<u8>> {
        self.image.read(va, size)
    }

    /// Decode the instruction at `va` using the workspace's architecture.
    ///
    /// This is the single authoritative decode entry point: it selects the
    /// architecture decoder from the workspace (rejecting unsupported
    /// architectures via [`ArchitectureCapabilities`], never defaulting to x86 —
    /// review findings #7/#8) so consumers such as `vivutils-rs` do not
    /// re-implement decoder/mode selection. Reads up to the max instruction
    /// length, tolerating a region boundary near `va`.
    #[must_use]
    pub fn parse_opcode(&self, va: u64) -> VivResult<crate::envi::Opcode> {
        let disasm = match self.arch {
            Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
            Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
            _ => {
                return Err(VivError::ArchModNotDefined {
                    arch: format!("{:?}", self.arch),
                })
            }
        };
        // Read the largest available window up to the x86 max instruction size.
        let mut bytes = Vec::new();
        for size in (1..=16).rev() {
            if let Ok(b) = self.read_memory(va, size) {
                bytes = b;
                break;
            }
        }
        if bytes.is_empty() {
            return Err(VivError::InvalidMemory { address: va });
        }
        disasm.disassemble(&bytes, va)
    }

    /// Check if address is valid.
    pub fn is_valid_pointer(&self, va: u64) -> bool {
        self.image.is_mapped(va)
    }

    /// Get memory permissions at address.
    #[must_use]
    pub fn get_permissions(&self, va: u64) -> Option<MemoryPermissions> {
        self.image.permissions(va)
    }

    /// Check if address is in executable memory.
    pub fn is_executable(&self, va: u64) -> bool {
        self.image.is_executable(va)
    }

    /// Check if an address is a known no-return address.
    pub fn is_noreturn_va(&self, va: u64) -> bool {
        self.noreturn_vas.contains(&va)
    }

    /// Mark an address as no-return.
    pub fn add_noreturn_va(&mut self, va: u64) {
        self.noreturn_vas.insert(va);
    }

    /// Check if a function is marked as a thunk.
    pub fn is_function_thunk(&self, va: u64) -> bool {
        self.functions
            .get(&va)
            .and_then(|m| m.meta.get("Thunk"))
            .is_some()
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
            memory_size: self.image.total_size(),
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

        tracing::trace!(
            "[workspace] get_block_successors: block_va={:#x}, successors={:?}",
            block_va,
            successors
        );
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
        let block = self
            .codeblocks
            .get(&block_va)
            .ok_or(VivError::InvalidFunction { va: block_va })?;

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

        // Build sorted interval list of (block_start, block_end, func_va) for
        // efficient address→function lookup via binary search. This replaces
        // the O(total_code_bytes) HashMap approach that allocated one entry per
        // byte of code — a 10MB .text section would create 10M entries.
        let mut intervals: Vec<(u64, u64, u64)> = self
            .codeblocks
            .values()
            .map(|block| (block.va, block.va + block.size as u64, block.func_va))
            .collect();
        intervals.sort_by_key(|&(start, _, _)| start);

        // Wrap in a closure that does binary search for address lookup
        let lookup = |addr: u64| -> Option<u64> {
            let idx = intervals.partition_point(|&(start, _, _)| start <= addr);
            if idx > 0 {
                let (start, end, func_va) = intervals[idx - 1];
                if addr >= start && addr < end {
                    return Some(func_va);
                }
            }
            None
        };

        let builder = CallGraphBuilder::new(&self.xrefs, &functions);
        builder.build_with_lookup(&lookup)
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

    // =========================================================================
    // VA SET METHODS — Port of Python's vasets API
    // =========================================================================

    /// Create a new VA set with column definitions.
    pub fn add_va_set(&mut self, name: &str, columns: Vec<(String, String)>) {
        self.va_sets
            .entry(name.to_string())
            .or_insert_with(|| VaSet {
                columns,
                rows: IndexMap::new(),
            });
    }

    /// Get a VA set by name.
    #[must_use]
    pub fn get_va_set(&self, name: &str) -> Option<&VaSet> {
        self.va_sets.get(name)
    }

    /// Set a row in a VA set. Creates the set if it doesn't exist.
    pub fn set_va_set_row(&mut self, name: &str, va: u64, values: Vec<String>) {
        let set = self
            .va_sets
            .entry(name.to_string())
            .or_insert_with(|| VaSet {
                columns: Vec::new(),
                rows: IndexMap::new(),
            });
        set.rows.insert(va, values);
    }

    /// Get all rows from a VA set.
    pub fn get_va_set_rows(&self, name: &str) -> Vec<(u64, &[String])> {
        match self.va_sets.get(name) {
            Some(set) => set
                .rows
                .iter()
                .map(|(&va, vals)| (va, vals.as_slice()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Delete a VA set.
    pub fn del_va_set(&mut self, name: &str) {
        self.va_sets.remove(name);
    }

    /// Get all VA set names.
    pub fn get_va_set_names(&self) -> Vec<&str> {
        self.va_sets.keys().map(|s| s.as_str()).collect()
    }

    // =========================================================================
    // EVENT SYSTEM — Port of Python's VWE_* event dispatch
    // =========================================================================

    /// Register an event listener. Returns a listener ID for removal.
    pub fn add_event_listener<F>(&mut self, callback: F) -> u32
    where
        F: Fn(WorkspaceEvent) + Send + Sync + 'static,
    {
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.event_listeners.push((id, Box::new(callback)));
        id
    }

    /// Remove an event listener by ID.
    pub fn remove_event_listener(&mut self, id: u32) {
        self.event_listeners.retain(|(lid, _)| *lid != id);
    }

    /// Fire an event to all registered listeners.
    fn fire_event(&self, event: WorkspaceEvent) {
        for (_, callback) in &self.event_listeners {
            callback(event.clone());
        }
    }

    // =========================================================================
    // WRITE MEMORY — needed for linker and import resolution
    // =========================================================================

    /// Write bytes to workspace memory.
    #[must_use]
    pub fn write_memory(&mut self, va: u64, data: &[u8]) -> VivResult<()> {
        self.image.write(va, data)
    }

    // =========================================================================
    // FILE METADATA — needed for PE/ELF analysis modules
    // =========================================================================

    /// Get file metadata by file name and key.
    #[must_use]
    pub fn get_file_meta(&self, filename: &str, key: &str) -> Option<&str> {
        let meta_key = format!("{}:{}", filename, key);
        self.meta.get(&meta_key).map(|s| s.as_str())
    }

    /// Set file metadata.
    pub fn set_file_meta(&mut self, filename: &str, key: &str, value: &str) {
        let meta_key = format!("{}:{}", filename, key);
        self.meta.insert(meta_key, value.to_string());
    }

    // =========================================================================
    // PERSISTENCE SUPPORT — setters, enumerations, and the semantic digest.
    // These make a complete save/reload round-trip possible (review finding #1).
    // =========================================================================

    /// Set the architecture (used by workspace restore).
    pub fn set_architecture(&mut self, arch: Architecture) {
        self.arch = arch;
        self.generation += 1;
    }

    /// Set the endianness (used by workspace restore).
    pub fn set_endian(&mut self, endian: Endian) {
        self.image.set_endian(endian);
        self.generation += 1;
    }

    /// Add a mapped memory region with data and an optional name.
    ///
    /// Used to restore persisted memory. Errors on overlap, exactly like the
    /// loader path.
    #[must_use]
    pub fn add_memory_region(
        &mut self,
        base: u64,
        data: Vec<u8>,
        perms: MemoryPermissions,
        name: Option<String>,
    ) -> VivResult<()> {
        self.image.map_verbatim(base, data, perms, name)?;
        self.generation += 1;
        Ok(())
    }

    /// Iterate over mapped memory regions.
    pub fn iter_memory_regions(&self) -> impl Iterator<Item = &crate::abstractions::MemoryRegion> {
        self.image.regions()
    }

    /// The mapped memory region containing `va`, if any (region-based bounds
    /// lookup so consumers stop deriving geometry from the segment list).
    pub fn region_at(&self, va: u64) -> Option<&crate::abstractions::MemoryRegion> {
        self.image.region_at(va)
    }

    /// Borrow the authoritative memory image.
    pub fn memory_image(&self) -> &MemoryImage {
        &self.image
    }

    /// Iterate over all workspace metadata key/value pairs.
    pub fn metadata_iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.meta.iter()
    }

    /// Get all no-return addresses (sorted).
    pub fn get_noreturn_vas(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.noreturn_vas.iter().copied().collect();
        v.sort_unstable();
        v
    }

    /// Add a segment record (used by workspace restore).
    pub fn add_segment(&mut self, seg: Segment) {
        self.segments.push(seg);
        self.generation += 1;
    }

    /// Add a loaded-file record (used by workspace restore).
    pub fn add_file(&mut self, file: FileInfo) {
        self.files.push(file);
        self.generation += 1;
    }

    /// Add an entry point, preserving order and de-duplicating.
    pub fn add_entry_point(&mut self, va: u64) {
        if !self.entry_points.contains(&va) {
            self.entry_points.push(va);
            self.generation += 1;
        }
    }

    /// Compute a deterministic digest over all semantically-relevant workspace
    /// state. Collections stored in hashed containers are canonicalized (sorted)
    /// so the digest is independent of internal iteration order; the invariant
    /// `semantic_digest(W) == semantic_digest(load(save(W)))` holds by
    /// construction when persistence is complete.
    pub fn semantic_digest(&self) -> u64 {
        fn pu64(buf: &mut Vec<u8>, v: u64) {
            buf.extend_from_slice(&v.to_le_bytes());
        }
        fn pstr(buf: &mut Vec<u8>, s: &str) {
            pu64(buf, s.len() as u64);
            buf.extend_from_slice(s.as_bytes());
        }
        fn pbytes(buf: &mut Vec<u8>, d: &[u8]) {
            pu64(buf, d.len() as u64);
            buf.extend_from_slice(d);
        }
        fn postr(buf: &mut Vec<u8>, s: &Option<String>) {
            match s {
                Some(x) => {
                    buf.push(1);
                    pstr(buf, x);
                }
                None => buf.push(0),
            }
        }

        let mut buf: Vec<u8> = Vec::new();

        // Architecture / endian.
        pstr(&mut buf, self.arch.name());
        buf.push(if self.image.endian().is_big() { 1 } else { 0 });

        // Entry points (order is semantic — primary first).
        buf.extend_from_slice(b"EP");
        pu64(&mut buf, self.entry_points.len() as u64);
        for &va in &self.entry_points {
            pu64(&mut buf, va);
        }

        // Memory regions (BTreeMap is already base-ordered).
        buf.extend_from_slice(b"MEM");
        let mut regions: Vec<_> = self.image.regions().collect();
        regions.sort_by_key(|r| r.base);
        pu64(&mut buf, regions.len() as u64);
        for r in regions {
            pu64(&mut buf, r.base);
            pu64(&mut buf, r.size as u64);
            pu64(&mut buf, r.permissions.bits() as u64);
            postr(&mut buf, &r.name);
            pbytes(&mut buf, &r.data);
        }

        // Segments (order preserved).
        buf.extend_from_slice(b"SEG");
        pu64(&mut buf, self.segments.len() as u64);
        for s in &self.segments {
            pu64(&mut buf, s.va);
            pu64(&mut buf, s.size as u64);
            pstr(&mut buf, &s.name);
            pstr(&mut buf, &s.filename);
        }

        // Files (order preserved).
        buf.extend_from_slice(b"FILE");
        pu64(&mut buf, self.files.len() as u64);
        for f in &self.files {
            pstr(&mut buf, &f.name);
            pu64(&mut buf, f.base_addr);
            pstr(&mut buf, &format!("{:?}", f.format));
            postr(&mut buf, &f.md5);
        }

        // Functions (canonicalized by va).
        buf.extend_from_slice(b"FUNC");
        let mut funcs: Vec<_> = self.functions.iter().collect();
        funcs.sort_by_key(|(&va, _)| va);
        pu64(&mut buf, funcs.len() as u64);
        for (&va, m) in funcs {
            pu64(&mut buf, va);
            postr(&mut buf, &m.name);
            postr(&mut buf, &m.calling_convention);
            postr(&mut buf, &m.ret_type);
            pu64(&mut buf, m.args.len() as u64);
            for (t, n) in &m.args {
                pstr(&mut buf, t);
                pstr(&mut buf, n);
            }
            pu64(&mut buf, m.locals.len() as u64);
            for (off, t, n) in &m.locals {
                pu64(&mut buf, *off);
                pstr(&mut buf, t);
                pstr(&mut buf, n);
            }
            let mut mk: Vec<_> = m.meta.iter().collect();
            mk.sort_by(|a, b| a.0.cmp(b.0));
            pu64(&mut buf, mk.len() as u64);
            for (k, v) in mk {
                pstr(&mut buf, k);
                pstr(&mut buf, v);
            }
        }

        // Locations (canonicalized by va).
        buf.extend_from_slice(b"LOC");
        let mut locs: Vec<_> = self.locations.iter().collect();
        locs.sort_by_key(|(&va, _)| va);
        pu64(&mut buf, locs.len() as u64);
        for (&va, l) in locs {
            pu64(&mut buf, va);
            pu64(&mut buf, l.size as u64);
            pu64(&mut buf, l.ltype as u64);
            postr(&mut buf, &l.tinfo);
        }

        // Code blocks (canonicalized by va).
        buf.extend_from_slice(b"CB");
        let mut cbs: Vec<_> = self.codeblocks.iter().collect();
        cbs.sort_by_key(|(&va, _)| va);
        pu64(&mut buf, cbs.len() as u64);
        for (&va, cb) in cbs {
            pu64(&mut buf, va);
            pu64(&mut buf, cb.size as u64);
            pu64(&mut buf, cb.func_va);
        }

        // Symbols (canonicalized by (addr, name)).
        buf.extend_from_slice(b"SYM");
        let mut syms: Vec<(u64, String)> = self
            .symbols
            .iter()
            .map(|(a, n)| (a, n.to_string()))
            .collect();
        syms.sort();
        pu64(&mut buf, syms.len() as u64);
        for (a, n) in &syms {
            pu64(&mut buf, *a);
            pstr(&mut buf, n);
        }

        // Xrefs (canonicalized).
        buf.extend_from_slice(b"XREF");
        let mut xr: Vec<(u64, u64, u8)> =
            self.xrefs.iter().map(|(f, t, r)| (f, t, r as u8)).collect();
        xr.sort();
        pu64(&mut buf, xr.len() as u64);
        for (f, t, r) in &xr {
            pu64(&mut buf, *f);
            pu64(&mut buf, *t);
            buf.push(*r);
        }

        // Comments (canonicalized by va).
        buf.extend_from_slice(b"CMT");
        let mut cmts: Vec<_> = self.comments.iter().collect();
        cmts.sort_by_key(|(&va, _)| va);
        pu64(&mut buf, cmts.len() as u64);
        for (&va, c) in cmts {
            pu64(&mut buf, va);
            pstr(&mut buf, c);
        }

        // Workspace metadata (canonicalized by key).
        buf.extend_from_slice(b"META");
        let mut meta: Vec<_> = self.meta.iter().collect();
        meta.sort_by(|a, b| a.0.cmp(b.0));
        pu64(&mut buf, meta.len() as u64);
        for (k, v) in meta {
            pstr(&mut buf, k);
            pstr(&mut buf, v);
        }

        // No-return addresses (sorted).
        buf.extend_from_slice(b"NORET");
        let nr = self.get_noreturn_vas();
        pu64(&mut buf, nr.len() as u64);
        for va in nr {
            pu64(&mut buf, va);
        }

        // VA sets (canonicalized by name, rows by va).
        buf.extend_from_slice(b"VASET");
        let mut names: Vec<_> = self.va_sets.keys().cloned().collect();
        names.sort();
        pu64(&mut buf, names.len() as u64);
        for name in &names {
            pstr(&mut buf, name);
            let set = &self.va_sets[name];
            pu64(&mut buf, set.columns.len() as u64);
            for (c, t) in &set.columns {
                pstr(&mut buf, c);
                pstr(&mut buf, t);
            }
            let mut rows: Vec<_> = set.rows.iter().collect();
            rows.sort_by_key(|(&va, _)| va);
            pu64(&mut buf, rows.len() as u64);
            for (&va, vals) in rows {
                pu64(&mut buf, va);
                pu64(&mut buf, vals.len() as u64);
                for v in vals {
                    pstr(&mut buf, v);
                }
            }
        }

        // FNV-1a 64-bit over the canonical buffer.
        let mut h: u64 = 0xcbf29ce484222325;
        for &byte in &buf {
            h ^= byte as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
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
    use std::sync::{Arc, Mutex};

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

    // =========================================================================
    // VA SET TESTS
    // =========================================================================

    #[test]
    fn test_add_va_set_creates_empty_set() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("test_set", vec![("col1".to_string(), "int".to_string())]);
        let set = ws.get_va_set("test_set");
        assert!(set.is_some());
        let set = set.unwrap();
        assert_eq!(set.columns.len(), 1);
        assert_eq!(set.columns[0].0, "col1");
        assert!(set.rows.is_empty());
    }

    #[test]
    fn test_add_va_set_does_not_overwrite_existing() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("test_set", vec![("col1".to_string(), "int".to_string())]);
        ws.set_va_set_row("test_set", 0x1000, vec!["value1".to_string()]);
        // Adding again with same name should NOT overwrite
        ws.add_va_set(
            "test_set",
            vec![("col_different".to_string(), "str".to_string())],
        );
        let set = ws.get_va_set("test_set").unwrap();
        assert_eq!(set.columns[0].0, "col1"); // original columns preserved
        assert_eq!(set.rows.len(), 1); // rows preserved
    }

    #[test]
    fn test_set_va_set_row_and_get_rows() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("imports", vec![("name".to_string(), "str".to_string())]);
        ws.set_va_set_row("imports", 0x1000, vec!["kernel32.CreateFileA".to_string()]);
        ws.set_va_set_row("imports", 0x2000, vec!["user32.MessageBoxA".to_string()]);

        let rows = ws.get_va_set_rows("imports");
        assert_eq!(rows.len(), 2);
        // Check one of the rows
        let found = rows.iter().find(|(va, _)| *va == 0x1000);
        assert!(found.is_some());
        assert_eq!(found.unwrap().1, &["kernel32.CreateFileA".to_string()]);
    }

    #[test]
    fn test_set_va_set_row_overwrites_existing_va() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("s", vec![]);
        ws.set_va_set_row("s", 0x1000, vec!["old".to_string()]);
        ws.set_va_set_row("s", 0x1000, vec!["new".to_string()]);

        let rows = ws.get_va_set_rows("s");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, &["new".to_string()]);
    }

    #[test]
    fn test_set_va_set_row_auto_creates_set() {
        let mut ws = VivWorkspace::new();
        // Setting a row on a nonexistent set should create it
        ws.set_va_set_row("auto_set", 0x5000, vec!["data".to_string()]);
        let set = ws.get_va_set("auto_set");
        assert!(set.is_some());
        assert_eq!(set.unwrap().rows.len(), 1);
    }

    #[test]
    fn test_del_va_set() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("to_delete", vec![]);
        ws.set_va_set_row("to_delete", 0x100, vec!["a".to_string()]);
        ws.del_va_set("to_delete");
        assert!(ws.get_va_set("to_delete").is_none());
        assert!(ws.get_va_set_rows("to_delete").is_empty());
    }

    #[test]
    fn test_del_va_set_nonexistent_is_noop() {
        let mut ws = VivWorkspace::new();
        ws.del_va_set("nonexistent"); // should not panic
    }

    #[test]
    fn test_get_va_set_names() {
        let mut ws = VivWorkspace::new();
        ws.add_va_set("alpha", vec![]);
        ws.add_va_set("beta", vec![]);
        ws.add_va_set("gamma", vec![]);
        let mut names = ws.get_va_set_names();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn test_get_va_set_rows_nonexistent_returns_empty() {
        let ws = VivWorkspace::new();
        assert!(ws.get_va_set_rows("nope").is_empty());
    }

    // =========================================================================
    // EVENT SYSTEM TESTS
    // =========================================================================

    #[test]
    fn test_add_event_listener_returns_incrementing_ids() {
        let mut ws = VivWorkspace::new();
        let id1 = ws.add_event_listener(|_| {});
        let id2 = ws.add_event_listener(|_| {});
        let id3 = ws.add_event_listener(|_| {});
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(id3, 2);
    }

    #[test]
    fn test_fire_event_invokes_all_listeners() {
        let mut ws = VivWorkspace::new();
        let counter = Arc::new(Mutex::new(0u32));
        let c1 = counter.clone();
        let c2 = counter.clone();
        ws.add_event_listener(move |_| {
            *c1.lock().unwrap() += 1;
        });
        ws.add_event_listener(move |_| {
            *c2.lock().unwrap() += 1;
        });

        ws.fire_event(WorkspaceEvent::SetMeta {
            key: "test".to_string(),
            value: "val".to_string(),
        });

        assert_eq!(*counter.lock().unwrap(), 2);
    }

    #[test]
    fn test_remove_event_listener() {
        let mut ws = VivWorkspace::new();
        let counter = Arc::new(Mutex::new(0u32));
        let c = counter.clone();
        let id = ws.add_event_listener(move |_| {
            *c.lock().unwrap() += 1;
        });
        ws.fire_event(WorkspaceEvent::SetMeta {
            key: "k".to_string(),
            value: "v".to_string(),
        });
        assert_eq!(*counter.lock().unwrap(), 1);

        ws.remove_event_listener(id);
        ws.fire_event(WorkspaceEvent::SetMeta {
            key: "k".to_string(),
            value: "v".to_string(),
        });
        // Counter should NOT have increased
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn test_remove_nonexistent_listener_is_noop() {
        let mut ws = VivWorkspace::new();
        ws.remove_event_listener(999); // should not panic
    }

    #[test]
    fn test_fire_event_with_no_listeners() {
        let ws = VivWorkspace::new();
        // Should not panic when no listeners registered
        ws.fire_event(WorkspaceEvent::AddFunction { va: 0x1000 });
    }

    // =========================================================================
    // FILE METADATA TESTS
    // =========================================================================

    #[test]
    fn test_set_and_get_file_meta() {
        let mut ws = VivWorkspace::new();
        ws.set_file_meta("test.exe", "imagebase", "0x400000");
        assert_eq!(ws.get_file_meta("test.exe", "imagebase"), Some("0x400000"));
    }

    #[test]
    fn test_get_file_meta_missing_key() {
        let ws = VivWorkspace::new();
        assert!(ws.get_file_meta("test.exe", "nonexistent").is_none());
    }

    #[test]
    fn test_file_meta_different_files_same_key() {
        let mut ws = VivWorkspace::new();
        ws.set_file_meta("a.exe", "arch", "x86");
        ws.set_file_meta("b.exe", "arch", "x64");
        assert_eq!(ws.get_file_meta("a.exe", "arch"), Some("x86"));
        assert_eq!(ws.get_file_meta("b.exe", "arch"), Some("x64"));
    }

    #[test]
    fn test_file_meta_overwrites_same_key() {
        let mut ws = VivWorkspace::new();
        ws.set_file_meta("test.dll", "subsystem", "GUI");
        ws.set_file_meta("test.dll", "subsystem", "Console");
        assert_eq!(ws.get_file_meta("test.dll", "subsystem"), Some("Console"));
    }

    // =========================================================================
    // WRITE MEMORY TESTS
    // =========================================================================

    #[test]
    fn test_write_memory_and_read_back() {
        let mut ws = VivWorkspace::new();
        // First add a memory region
        let _ = ws.add_memory_region(0x1000, vec![0u8; 0x100], MemoryPermissions::RW, None);
        // Write data
        let result = ws.write_memory(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(result.is_ok());
        // Read it back
        let data = ws.read_memory(0x1000, 4).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_write_memory_to_unmapped_address_fails() {
        let mut ws = VivWorkspace::new();
        let result = ws.write_memory(0xDEAD_0000, &[0x41, 0x42]);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_memory_partial_overwrite() {
        let mut ws = VivWorkspace::new();
        let _ = ws.add_memory_region(0x2000, vec![0xAA; 8], MemoryPermissions::RW, None);
        ws.write_memory(0x2002, &[0xBB, 0xCC]).unwrap();
        let data = ws.read_memory(0x2000, 8).unwrap();
        assert_eq!(data, vec![0xAA, 0xAA, 0xBB, 0xCC, 0xAA, 0xAA, 0xAA, 0xAA]);
    }

    // =========================================================================
    // WORKSPACE CONFIG DEFAULTS TESTS
    // =========================================================================

    #[test]
    fn test_workspace_config_defaults() {
        let config = WorkspaceConfig::default();
        assert_eq!(config.analysis.min_string_length, 4);
        assert_eq!(config.analysis.max_sym_paths, 1000);
        assert_eq!(config.analysis.pointertable_min_len, 4);
        assert!(config.analysis.emucode_enabled);
        assert_eq!(config.analysis.max_function_size, 0x100000);
    }

    #[test]
    fn test_analysis_config_defaults() {
        let ac = AnalysisConfig::default();
        assert_eq!(ac.min_string_length, 4);
        assert_eq!(ac.max_sym_paths, 1000);
        assert_eq!(ac.pointertable_min_len, 4);
        assert!(ac.emucode_enabled);
        assert_eq!(ac.max_function_size, 0x100000);
    }

    #[test]
    fn test_new_workspace_has_default_config() {
        let ws = VivWorkspace::new();
        assert_eq!(ws.config.analysis.min_string_length, 4);
        assert!(ws.config.analysis.emucode_enabled);
    }

    // =========================================================================
    // WORKSPACE GENERAL TESTS
    // =========================================================================

    #[test]
    fn test_default_trait_impl() {
        let ws = VivWorkspace::default();
        assert_eq!(ws.architecture(), Architecture::Default);
        assert_eq!(ws.endian(), Endian::Little);
    }

    #[test]
    fn test_workspace_stats_empty() {
        let ws = VivWorkspace::new();
        let stats = ws.stats();
        assert_eq!(stats.functions, 0);
        assert_eq!(stats.locations, 0);
        assert_eq!(stats.codeblocks, 0);
        assert_eq!(stats.segments, 0);
        assert_eq!(stats.symbols, 0);
        assert_eq!(stats.xrefs, 0);
        assert_eq!(stats.memory_size, 0);
    }

    #[test]
    fn test_add_function_and_query() {
        let mut ws = VivWorkspace::new();
        let meta = FunctionMeta {
            name: Some("test_func".to_string()),
            ..Default::default()
        };
        ws.add_function(0x401000, meta).unwrap();
        assert!(ws.is_function(0x401000));
        assert_eq!(ws.function_count(), 1);
        assert_eq!(ws.get_functions(), vec![0x401000]);
        let f = ws.get_function(0x401000).unwrap();
        assert_eq!(f.name.as_deref(), Some("test_func"));
    }

    #[test]
    fn test_add_duplicate_function_fails() {
        let mut ws = VivWorkspace::new();
        ws.add_function(0x401000, FunctionMeta::default()).unwrap();
        let result = ws.add_function(0x401000, FunctionMeta::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_pending_functions_drain() {
        let mut ws = VivWorkspace::new();
        ws.add_function(0x1000, FunctionMeta::default()).unwrap();
        ws.add_function(0x2000, FunctionMeta::default()).unwrap();
        let pending = ws.drain_pending_functions();
        assert_eq!(pending, vec![0x1000, 0x2000]);
        // Second drain should be empty
        assert!(ws.drain_pending_functions().is_empty());
    }

    #[test]
    fn test_set_function_name() {
        let mut ws = VivWorkspace::new();
        ws.add_function(0x3000, FunctionMeta::default()).unwrap();
        ws.set_function_name(0x3000, "my_func");
        let f = ws.get_function(0x3000).unwrap();
        assert_eq!(f.name.as_deref(), Some("my_func"));
        // Also sets a symbol
        assert_eq!(ws.get_name(0x3000), Some("my_func"));
    }

    #[test]
    fn test_get_function_by_name() {
        let mut ws = VivWorkspace::new();
        let meta = FunctionMeta {
            name: Some("entry".to_string()),
            ..Default::default()
        };
        ws.add_function(0x5000, meta).unwrap();
        assert_eq!(ws.get_function_by_name("entry"), Some(0x5000));
        assert!(ws.get_function_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_add_location_and_get() {
        let mut ws = VivWorkspace::new();
        ws.add_location(0x1000, 4, LocationType::Op, None);
        let loc = ws.get_location(0x1000).unwrap();
        assert_eq!(loc.va, 0x1000);
        assert_eq!(loc.size, 4);
        assert_eq!(loc.ltype, LocationType::Op);
        assert!(loc.tinfo.is_none());
    }

    #[test]
    fn test_add_codeblock() {
        let mut ws = VivWorkspace::new();
        ws.add_codeblock(0x1000, 32, 0x1000);
        ws.add_codeblock(0x1020, 16, 0x1000);
        let blocks = ws.get_function_blocks(0x1000);
        assert_eq!(blocks.len(), 2);
        assert_eq!(ws.get_function_size(0x1000), 48);
    }

    #[test]
    fn test_parse_opcode_decodes_and_rejects_unsupported() {
        use crate::constants::MemoryPermissions;
        let mut ws = VivWorkspace::new();
        ws.set_architecture(Architecture::Amd64);
        ws.add_memory_region(
            0x1000,
            vec![0x48, 0x31, 0xc0, 0xc3, 0x00, 0x00, 0x00, 0x00], // xor rax,rax; ret
            MemoryPermissions::RX,
            None,
        )
        .unwrap();

        // Authoritative decode via the workspace arch.
        assert_eq!(ws.parse_opcode(0x1000).unwrap().mnem, "xor");
        // Near the region end it still decodes (shrinking read window).
        assert_eq!(ws.parse_opcode(0x1003).unwrap().mnem, "ret");

        // An unsupported architecture errors rather than defaulting to x86.
        let mut ws2 = VivWorkspace::new();
        ws2.set_architecture(Architecture::ArmV7);
        ws2.add_memory_region(0x1000, vec![0u8; 16], MemoryPermissions::RX, None)
            .unwrap();
        assert!(ws2.parse_opcode(0x1000).is_err());
    }

    #[test]
    fn test_get_location_containing() {
        let mut ws = VivWorkspace::new();
        // A 5-byte instruction at 0x1000 and a 3-byte one at 0x1005.
        ws.add_location(0x1000, 5, LocationType::Op, None);
        ws.add_location(0x1005, 3, LocationType::Op, None);

        // Exact starts resolve for both APIs.
        assert_eq!(ws.get_location(0x1000).unwrap().va, 0x1000);
        assert_eq!(ws.get_location_containing(0x1000).unwrap().va, 0x1000);

        // An address in the MIDDLE of the first instruction: exact lookup misses,
        // containing lookup resolves to the enclosing location (finding #5).
        assert!(ws.get_location(0x1004).is_none());
        assert_eq!(ws.get_location_containing(0x1004).unwrap().va, 0x1000);
        assert_eq!(ws.get_location_containing(0x1002).unwrap().va, 0x1000);
        assert_eq!(ws.get_location_containing(0x1005).unwrap().va, 0x1005);

        // Outside any location.
        assert!(ws.get_location_containing(0x2000).is_none());
        assert!(ws.get_location_containing(0x1008).is_none());
    }

    #[test]
    fn test_comment_set_and_get() {
        let mut ws = VivWorkspace::new();
        ws.set_comment(0x401000, "function prologue");
        assert_eq!(ws.get_comment(0x401000), Some("function prologue"));
        assert!(ws.get_comment(0x999).is_none());
    }

    #[test]
    fn test_meta_set_and_get() {
        let mut ws = VivWorkspace::new();
        ws.set_meta("format", "PE");
        assert_eq!(ws.get_meta("format"), Some("PE"));
        assert!(ws.get_meta("missing").is_none());
    }

    #[test]
    fn test_noreturn_va() {
        let mut ws = VivWorkspace::new();
        assert!(!ws.is_noreturn_va(0x1000));
        ws.add_noreturn_va(0x1000);
        assert!(ws.is_noreturn_va(0x1000));
    }

    #[test]
    fn test_is_function_thunk() {
        let mut ws = VivWorkspace::new();
        let mut meta = FunctionMeta::default();
        meta.meta.insert("Thunk".to_string(), "0x2000".to_string());
        ws.add_function(0x1000, meta).unwrap();
        assert!(ws.is_function_thunk(0x1000));

        ws.add_function(0x3000, FunctionMeta::default()).unwrap();
        assert!(!ws.is_function_thunk(0x3000));
    }

    #[test]
    fn test_entry_points_start_empty() {
        let ws = VivWorkspace::new();
        assert!(ws.entry_points().is_empty());
    }

    #[test]
    fn test_pointer_size() {
        let ws = VivWorkspace::new();
        // Default architecture pointer size depends on platform
        let ptr_size = ws.pointer_size();
        assert!(ptr_size == 4 || ptr_size == 8);
    }

    #[test]
    fn test_is_valid_pointer_unmapped() {
        let ws = VivWorkspace::new();
        assert!(!ws.is_valid_pointer(0xDEAD_BEEF));
    }

    #[test]
    fn test_is_executable_unmapped() {
        let ws = VivWorkspace::new();
        assert!(!ws.is_executable(0x1000));
    }
}
