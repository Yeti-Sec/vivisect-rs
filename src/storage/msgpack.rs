//! MessagePack / JSON workspace storage.
//!
//! Persists the complete semantically-relevant workspace state so that a
//! save→reload round-trip is faithful (review finding #1). The acceptance
//! invariant is:
//!
//! ```text
//! semantic_digest(W) == semantic_digest(load(save(W)))
//! ```
//!
//! Schema is versioned via [`WorkspaceData::version`]. v2 (this module) persists
//! architecture, endianness, workspace metadata, mapped memory (bytes +
//! permissions + name), segments, files, entry points, locations, functions,
//! code blocks, symbols, xrefs, comments, no-return addresses, and VA sets.

use crate::constants::{Architecture, Endian, LocationType, MemoryPermissions, RefType};
use crate::core::workspace::{FileInfo, FunctionMeta, Segment};
use crate::core::VivWorkspace;
use crate::error::{VivError, VivResult};
use crate::parsers::BinaryFormat;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

/// Current persistence schema version.
pub const SCHEMA_VERSION: u32 = 2;

/// Serializable workspace representation (complete v2 schema).
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceData {
    /// Format version.
    pub version: u32,
    /// Architecture canonical name (`Architecture::name`).
    pub arch: String,
    /// Endianness (true = big).
    pub big_endian: bool,
    /// Workspace metadata (sorted key/value pairs).
    pub metadata: Vec<(String, String)>,
    /// Mapped memory regions (bytes + permissions + name).
    pub memory_maps: Vec<MemoryMapData>,
    /// Segments.
    pub segments: Vec<SegmentData>,
    /// Loaded files.
    pub files: Vec<FileData>,
    /// Entry points (order preserved; primary first).
    pub entry_points: Vec<u64>,
    /// Locations.
    pub locations: Vec<LocationData>,
    /// Functions.
    pub functions: Vec<FunctionData>,
    /// Code blocks.
    pub codeblocks: Vec<CodeBlockData>,
    /// Symbols: (va, name).
    pub symbols: Vec<(u64, String)>,
    /// Cross-references: (from, to, rtype).
    pub xrefs: Vec<(u64, u64, u8)>,
    /// Comments: (va, comment).
    pub comments: Vec<(u64, String)>,
    /// No-return addresses.
    pub noreturn: Vec<u64>,
    /// VA sets.
    pub va_sets: Vec<VaSetData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMapData {
    pub base: u64,
    pub perms: u8,
    pub name: Option<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocationData {
    pub va: u64,
    pub size: usize,
    pub ltype: u8,
    pub tinfo: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FunctionData {
    pub va: u64,
    pub name: Option<String>,
    pub calling_convention: Option<String>,
    pub ret_type: Option<String>,
    pub args: Vec<(String, String)>,
    pub locals: Vec<(u64, String, String)>,
    pub meta: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeBlockData {
    pub va: u64,
    pub size: usize,
    pub func_va: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SegmentData {
    pub va: u64,
    pub size: usize,
    pub name: String,
    pub filename: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileData {
    pub name: String,
    pub base_addr: u64,
    pub format: String,
    pub md5: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VaSetData {
    pub name: String,
    pub columns: Vec<(String, String)>,
    pub rows: Vec<(u64, Vec<String>)>,
}

/// Save workspace to msgpack file.
#[must_use]
pub fn save_workspace(workspace: &VivWorkspace, path: &Path) -> VivResult<()> {
    crate::trace::emit(crate::trace::EventKind::WorkspaceSave, None, None, || {
        format!("msgpack path={}", path.display())
    });
    let data = workspace_to_data(workspace);
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    rmp_serde::encode::write(&mut writer, &data).map_err(|e| VivError::Other {
        message: format!("Failed to serialize workspace: {}", e),
    })?;
    Ok(())
}

/// Load workspace from msgpack file.
#[must_use]
pub fn load_workspace(path: &Path) -> VivResult<VivWorkspace> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let data: WorkspaceData =
        rmp_serde::decode::from_read(reader).map_err(|e| VivError::InvalidWorkspace {
            name: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    crate::trace::emit(crate::trace::EventKind::WorkspaceLoad, None, None, || {
        format!("msgpack path={} v{}", path.display(), data.version)
    });
    data_to_workspace(data)
}

/// Save workspace to JSON file.
#[must_use]
pub fn save_workspace_json(workspace: &VivWorkspace, path: &Path) -> VivResult<()> {
    let data = workspace_to_data(workspace);
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &data).map_err(|e| VivError::Other {
        message: format!("Failed to serialize workspace to JSON: {}", e),
    })?;
    Ok(())
}

/// Load workspace from JSON file.
#[must_use]
pub fn load_workspace_json(path: &Path) -> VivResult<VivWorkspace> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let data: WorkspaceData =
        serde_json::from_reader(reader).map_err(|e| VivError::InvalidWorkspace {
            name: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        })?;
    data_to_workspace(data)
}

fn format_name(fmt: BinaryFormat) -> &'static str {
    match fmt {
        BinaryFormat::Pe => "Pe",
        BinaryFormat::Elf => "Elf",
        BinaryFormat::MachO => "MachO",
        BinaryFormat::Blob => "Blob",
        BinaryFormat::Unknown => "Unknown",
    }
}

fn parse_format(s: &str) -> VivResult<BinaryFormat> {
    Ok(match s {
        "Pe" => BinaryFormat::Pe,
        "Elf" => BinaryFormat::Elf,
        "MachO" => BinaryFormat::MachO,
        "Blob" => BinaryFormat::Blob,
        "Unknown" => BinaryFormat::Unknown,
        other => {
            return Err(VivError::Other {
                message: format!("unknown binary format in workspace: {}", other),
            })
        }
    })
}

/// Convert workspace to serializable data (complete state).
fn workspace_to_data(workspace: &VivWorkspace) -> WorkspaceData {
    let metadata: Vec<(String, String)> = {
        let mut m: Vec<(String, String)> = workspace
            .metadata_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        m.sort();
        m
    };

    let memory_maps: Vec<MemoryMapData> = workspace
        .iter_memory_regions()
        .map(|r| MemoryMapData {
            base: r.base,
            perms: r.permissions.bits(),
            name: r.name.clone(),
            data: r.data.clone(),
        })
        .collect();

    let segments: Vec<SegmentData> = workspace
        .get_segments()
        .iter()
        .map(|s| SegmentData {
            va: s.va,
            size: s.size,
            name: s.name.clone(),
            filename: s.filename.clone(),
        })
        .collect();

    let files: Vec<FileData> = workspace
        .get_files()
        .iter()
        .map(|f| FileData {
            name: f.name.clone(),
            base_addr: f.base_addr,
            format: format_name(f.format).to_string(),
            md5: f.md5.clone(),
        })
        .collect();

    let functions: Vec<FunctionData> = workspace
        .functions_iter()
        .map(|(&va, meta)| {
            let mut fmeta: Vec<(String, String)> = meta
                .meta
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            fmeta.sort();
            FunctionData {
                va,
                name: meta.name.clone(),
                calling_convention: meta.calling_convention.clone(),
                ret_type: meta.ret_type.clone(),
                args: meta.args.clone(),
                locals: meta.locals.clone(),
                meta: fmeta,
            }
        })
        .collect();

    let codeblocks: Vec<CodeBlockData> = workspace
        .codeblocks_iter()
        .map(|(&va, cb)| CodeBlockData {
            va,
            size: cb.size,
            func_va: cb.func_va,
        })
        .collect();

    let symbols: Vec<(u64, String)> = workspace
        .symbols()
        .iter()
        .map(|(addr, name)| (addr, name.to_string()))
        .collect();

    let xrefs: Vec<(u64, u64, u8)> = workspace
        .xrefs()
        .iter()
        .map(|(from, to, rtype)| (from, to, rtype as u8))
        .collect();

    let comments: Vec<(u64, String)> = workspace
        .comments_iter()
        .map(|(&va, comment)| (va, comment.clone()))
        .collect();

    let locations: Vec<LocationData> = workspace
        .locations_iter()
        .map(|(&va, loc)| LocationData {
            va,
            size: loc.size,
            ltype: loc.ltype as u8,
            tinfo: loc.tinfo.clone(),
        })
        .collect();

    let va_sets: Vec<VaSetData> = workspace
        .get_va_set_names()
        .iter()
        .filter_map(|name| {
            workspace.get_va_set(name).map(|set| VaSetData {
                name: name.to_string(),
                columns: set.columns.clone(),
                rows: set
                    .rows
                    .iter()
                    .map(|(&va, vals)| (va, vals.clone()))
                    .collect(),
            })
        })
        .collect();

    WorkspaceData {
        version: SCHEMA_VERSION,
        arch: workspace.architecture().name().to_string(),
        big_endian: workspace.endian().is_big(),
        metadata,
        memory_maps,
        segments,
        files,
        entry_points: workspace.entry_points().to_vec(),
        locations,
        functions,
        codeblocks,
        symbols,
        xrefs,
        comments,
        noreturn: workspace.get_noreturn_vas(),
        va_sets,
    }
}

/// Convert serializable data back into a workspace (complete state).
fn data_to_workspace(data: WorkspaceData) -> VivResult<VivWorkspace> {
    let mut workspace = VivWorkspace::new();

    // Architecture: never silently default an unknown value.
    let arch = Architecture::from_name(&data.arch).ok_or_else(|| VivError::Other {
        message: format!("unknown architecture in workspace: {}", data.arch),
    })?;
    workspace.set_architecture(arch);
    workspace.set_endian(if data.big_endian {
        Endian::Big
    } else {
        Endian::Little
    });

    // Workspace metadata.
    for (k, v) in &data.metadata {
        workspace.set_meta(k, v);
    }

    // Mapped memory (bytes + perms + name).
    for m in data.memory_maps {
        let perms = MemoryPermissions::from_bits_truncate(m.perms);
        workspace.add_memory_region(m.base, m.data, perms, m.name)?;
    }

    // Segments.
    for s in data.segments {
        workspace.add_segment(Segment {
            va: s.va,
            size: s.size,
            name: s.name,
            filename: s.filename,
        });
    }

    // Files.
    for f in data.files {
        workspace.add_file(FileInfo {
            name: f.name,
            base_addr: f.base_addr,
            format: parse_format(&f.format)?,
            md5: f.md5,
        });
    }

    // Entry points (order preserved).
    for va in data.entry_points {
        workspace.add_entry_point(va);
    }

    // Symbols.
    for (addr, name) in data.symbols {
        workspace.set_name(addr, &name);
    }

    // Functions.
    for func in data.functions {
        let meta = FunctionMeta {
            name: func.name,
            calling_convention: func.calling_convention,
            ret_type: func.ret_type,
            args: func.args,
            locals: func.locals,
            meta: func.meta.into_iter().collect(),
        };
        let _ = workspace.add_function(func.va, meta);
    }

    // Locations.
    for loc in data.locations {
        let ltype = location_type_from_u8(loc.ltype);
        workspace.add_location(loc.va, loc.size, ltype, loc.tinfo);
    }

    // Code blocks.
    for cb in data.codeblocks {
        workspace.add_codeblock(cb.va, cb.size, cb.func_va);
    }

    // Xrefs.
    for (from, to, rtype) in data.xrefs {
        workspace.add_xref(from, to, ref_type_from_u8(rtype));
    }

    // Comments.
    for (va, comment) in data.comments {
        workspace.set_comment(va, &comment);
    }

    // No-return addresses.
    for va in data.noreturn {
        workspace.add_noreturn_va(va);
    }

    // VA sets.
    for vs in data.va_sets {
        workspace.add_va_set(&vs.name, vs.columns);
        for (va, vals) in vs.rows {
            workspace.set_va_set_row(&vs.name, va, vals);
        }
    }

    Ok(workspace)
}

fn location_type_from_u8(v: u8) -> LocationType {
    match v {
        0 => LocationType::Undefined,
        1 => LocationType::Number,
        2 => LocationType::String,
        3 => LocationType::Unicode,
        4 => LocationType::Pointer,
        5 => LocationType::Op,
        6 => LocationType::Struct,
        7 => LocationType::Clsid,
        8 => LocationType::VfTable,
        9 => LocationType::Import,
        10 => LocationType::Pad,
        _ => LocationType::Undefined,
    }
}

fn ref_type_from_u8(v: u8) -> RefType {
    match v {
        1 => RefType::Code,
        2 => RefType::Data,
        3 => RefType::Pointer,
        _ => RefType::Code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{Architecture, Endian, LocationType, MemoryPermissions, RefType};
    use crate::core::workspace::FunctionMeta;

    /// Build a workspace exercising every persisted subsystem.
    fn build_rich_workspace() -> VivWorkspace {
        let mut ws = VivWorkspace::new();
        ws.set_architecture(Architecture::Amd64);
        ws.set_endian(Endian::Little);
        ws.set_meta("StorageName", "sample.exe");
        ws.set_meta("md5", "deadbeef");

        // Memory regions with real bytes + permissions + names.
        ws.add_memory_region(
            0x140001000,
            vec![0x48, 0x89, 0x5c, 0x24, 0x08, 0xc3],
            MemoryPermissions::RX,
            Some(".text".to_string()),
        )
        .unwrap();
        ws.add_memory_region(
            0x140002000,
            vec![0xde, 0xad, 0xbe, 0xef],
            MemoryPermissions::RW,
            Some(".data".to_string()),
        )
        .unwrap();

        // Segments / files / entry points.
        ws.add_segment(crate::core::workspace::Segment {
            va: 0x140001000,
            size: 0x1000,
            name: ".text".to_string(),
            filename: "sample.exe".to_string(),
        });
        ws.add_file(crate::core::workspace::FileInfo {
            name: "sample.exe".to_string(),
            base_addr: 0x140000000,
            format: BinaryFormat::Pe,
            md5: Some("deadbeef".to_string()),
        });
        ws.add_entry_point(0x140001000);
        ws.add_entry_point(0x140001100);

        // Functions with full metadata.
        let mut meta = FunctionMeta {
            name: Some("main".to_string()),
            calling_convention: Some("ms64call".to_string()),
            ret_type: Some("int".to_string()),
            args: vec![("int".to_string(), "argc".to_string())],
            locals: vec![(0xfff8, "int".to_string(), "x".to_string())],
            ..Default::default()
        };
        meta.meta
            .insert("Thunk".to_string(), "0x140001100".to_string());
        ws.add_function(0x140001000, meta).unwrap();

        // Locations, code blocks, symbols, xrefs, comments.
        ws.add_location(0x140001000, 6, LocationType::Op, None);
        ws.add_location(
            0x140002000,
            4,
            LocationType::Pointer,
            Some("ptr".to_string()),
        );
        ws.add_codeblock(0x140001000, 6, 0x140001000);
        ws.set_name(0x140001000, "main");
        ws.set_name(0x140002000, "g_data");
        ws.add_xref(0x140001000, 0x140002000, RefType::Data);
        ws.add_xref(0x140001000, 0x140001100, RefType::Code);
        ws.set_comment(0x140001000, "entry");
        ws.add_noreturn_va(0x140001100);

        // VA set.
        ws.add_va_set(
            "ResolvedImports",
            vec![("name".to_string(), "str".to_string())],
        );
        ws.set_va_set_row(
            "ResolvedImports",
            0x140002000,
            vec!["kernel32.ExitProcess".to_string()],
        );

        ws
    }

    #[test]
    fn msgpack_roundtrip_preserves_semantic_digest() {
        let ws = build_rich_workspace();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws.viv");

        save_workspace(&ws, &path).unwrap();
        let reloaded = load_workspace(&path).unwrap();

        assert_eq!(
            ws.semantic_digest(),
            reloaded.semantic_digest(),
            "msgpack round-trip changed the semantic digest"
        );
    }

    #[test]
    fn json_roundtrip_preserves_semantic_digest() {
        let ws = build_rich_workspace();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws.json");

        save_workspace_json(&ws, &path).unwrap();
        let reloaded = load_workspace_json(&path).unwrap();

        assert_eq!(ws.semantic_digest(), reloaded.semantic_digest());
    }

    #[test]
    fn roundtrip_preserves_specific_fields() {
        let ws = build_rich_workspace();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ws.viv");
        save_workspace(&ws, &path).unwrap();
        let r = load_workspace(&path).unwrap();

        // Architecture / endian.
        assert_eq!(r.architecture(), Architecture::Amd64);
        assert_eq!(r.endian(), Endian::Little);

        // Memory bytes + permissions survive.
        assert_eq!(
            r.read_memory(0x140001000, 6).unwrap(),
            vec![0x48, 0x89, 0x5c, 0x24, 0x08, 0xc3]
        );
        assert_eq!(r.get_permissions(0x140001000), Some(MemoryPermissions::RX));
        assert_eq!(
            r.read_memory(0x140002000, 4).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );

        // Segments / files / entry points.
        assert_eq!(r.get_segments().len(), 1);
        assert_eq!(r.get_files().len(), 1);
        assert_eq!(r.get_files()[0].format, BinaryFormat::Pe);
        assert_eq!(r.entry_points(), &[0x140001000, 0x140001100]);

        // Function metadata.
        let f = r.get_function(0x140001000).unwrap();
        assert_eq!(f.calling_convention.as_deref(), Some("ms64call"));
        assert_eq!(f.args, vec![("int".to_string(), "argc".to_string())]);
        assert!(r.is_function_thunk(0x140001000));

        // Metadata / noreturn / va-set.
        assert_eq!(r.get_meta("StorageName"), Some("sample.exe"));
        assert!(r.is_noreturn_va(0x140001100));
        assert_eq!(r.get_va_set_rows("ResolvedImports").len(), 1);
    }

    #[test]
    fn unknown_architecture_is_rejected_not_defaulted() {
        // A corrupt/foreign arch name must error, never silently become Default.
        let json = r#"{
            "version": 2, "arch": "totally-bogus", "big_endian": false,
            "metadata": [], "memory_maps": [], "segments": [], "files": [],
            "entry_points": [], "locations": [], "functions": [], "codeblocks": [],
            "symbols": [], "xrefs": [], "comments": [], "noreturn": [], "va_sets": []
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, json).unwrap();
        assert!(load_workspace_json(&path).is_err());
    }

    #[test]
    fn empty_workspace_roundtrips() {
        let ws = VivWorkspace::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.viv");
        save_workspace(&ws, &path).unwrap();
        let r = load_workspace(&path).unwrap();
        assert_eq!(ws.semantic_digest(), r.semantic_digest());
    }
}
