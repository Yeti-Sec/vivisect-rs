//! MessagePack-based workspace storage.
//!
//! Provides serialization compatible with Python vivisect's msgpack format.

use crate::core::VivWorkspace;
use crate::error::{VivError, VivResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

/// Serializable workspace representation.
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceData {
    /// Format version.
    pub version: u32,
    /// Architecture name.
    pub arch: String,
    /// Endianness (true = big).
    pub big_endian: bool,
    /// Metadata.
    pub metadata: HashMap<String, String>,
    /// Memory maps: (base, size, perms, name, data_base64).
    pub memory_maps: Vec<MemoryMapData>,
    /// Locations: (va, size, ltype, tinfo).
    pub locations: Vec<LocationData>,
    /// Functions: (va, name, meta).
    pub functions: Vec<FunctionData>,
    /// Segments.
    pub segments: Vec<SegmentData>,
    /// Symbols: (va, name).
    pub symbols: Vec<(u64, String)>,
    /// Cross-references: (from, to, rtype).
    pub xrefs: Vec<(u64, u64, u8)>,
    /// Comments: (va, comment).
    pub comments: Vec<(u64, String)>,
    /// Entry points.
    pub entry_points: Vec<u64>,
    /// Files.
    pub files: Vec<FileData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MemoryMapData {
    pub base: u64,
    pub size: usize,
    pub perms: u8,
    pub name: Option<String>,
    // Note: actual memory data would be stored separately or base64 encoded
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
    pub meta: HashMap<String, String>,
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

/// Save workspace to msgpack file.
#[must_use]
pub fn save_workspace(workspace: &VivWorkspace, path: &Path) -> VivResult<()> {
    let data = workspace_to_data(workspace);

    let file = File::create(path)?;
    let writer = BufWriter::new(file);

    rmp_serde::encode::write(&mut std::io::BufWriter::new(writer), &data).map_err(|e| {
        VivError::Other {
            message: format!("Failed to serialize workspace: {}", e),
        }
    })?;

    Ok(())
}

/// Load workspace from msgpack file.
#[must_use]
pub fn load_workspace(path: &Path) -> VivResult<VivWorkspace> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let data: WorkspaceData = rmp_serde::decode::from_read(reader).map_err(|e| {
        VivError::InvalidWorkspace {
            name: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        }
    })?;

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

    let data: WorkspaceData = serde_json::from_reader(reader).map_err(|e| {
        VivError::InvalidWorkspace {
            name: path.to_string_lossy().to_string(),
            reason: e.to_string(),
        }
    })?;

    data_to_workspace(data)
}

/// Convert workspace to serializable data.
fn workspace_to_data(workspace: &VivWorkspace) -> WorkspaceData {
    // Collect symbols
    let symbols: Vec<(u64, String)> = workspace
        .symbols()
        .iter()
        .map(|(addr, name)| (addr, name.to_string()))
        .collect();

    // Collect segments
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

    // Collect files
    let files: Vec<FileData> = workspace
        .get_files()
        .iter()
        .map(|f| FileData {
            name: f.name.clone(),
            base_addr: f.base_addr,
            format: format!("{:?}", f.format),
            md5: f.md5.clone(),
        })
        .collect();

    // Collect functions
    let functions: Vec<FunctionData> = workspace
        .functions_iter()
        .map(|(&va, meta)| FunctionData {
            va,
            name: meta.name.clone(),
            calling_convention: meta.calling_convention.clone(),
            ret_type: meta.ret_type.clone(),
            args: meta.args.clone(),
            meta: meta.meta.clone(),
        })
        .collect();

    // Collect xrefs
    let xrefs: Vec<(u64, u64, u8)> = workspace
        .xrefs()
        .iter()
        .map(|(from, to, rtype)| (from, to, rtype as u8))
        .collect();

    // Collect comments
    let comments: Vec<(u64, String)> = workspace
        .comments_iter()
        .map(|(&va, comment)| (va, comment.clone()))
        .collect();

    // Collect locations
    let locations: Vec<LocationData> = workspace
        .locations_iter()
        .map(|(&va, loc)| LocationData {
            va,
            size: loc.size,
            ltype: loc.ltype as u8,
            tinfo: loc.tinfo.clone(),
        })
        .collect();

    WorkspaceData {
        version: 1,
        arch: format!("{:?}", workspace.architecture()),
        big_endian: workspace.endian().is_big(),
        metadata: HashMap::new(),
        memory_maps: Vec::new(), // Memory is re-loaded from file
        locations,
        functions,
        segments,
        symbols,
        xrefs,
        comments,
        entry_points: workspace.entry_points().to_vec(),
        files,
    }
}

/// Convert serializable data to workspace.
fn data_to_workspace(data: WorkspaceData) -> VivResult<VivWorkspace> {
    use crate::constants::{LocationType, RefType};
    use crate::core::workspace::FunctionMeta;

    let mut workspace = VivWorkspace::new();

    // Restore symbols
    for (addr, name) in data.symbols {
        workspace.set_name(addr, &name);
    }

    // Restore functions
    for func in data.functions {
        let meta = FunctionMeta {
            name: func.name,
            calling_convention: func.calling_convention,
            ret_type: func.ret_type,
            args: func.args,
            locals: Vec::new(),
            meta: func.meta,
        };
        let _ = workspace.add_function(func.va, meta);
    }

    // Restore locations
    for loc in data.locations {
        let ltype = match loc.ltype {
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
        };
        workspace.add_location(loc.va, loc.size, ltype, loc.tinfo);
    }

    // Restore xrefs
    for (from, to, rtype) in data.xrefs {
        let ref_type = match rtype {
            1 => RefType::Code,
            2 => RefType::Data,
            3 => RefType::Pointer,
            _ => RefType::Code,
        };
        workspace.add_xref(from, to, ref_type);
    }

    // Restore comments
    for (va, comment) in data.comments {
        workspace.set_comment(va, &comment);
    }

    Ok(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_serialization() {
        let mut workspace = VivWorkspace::new();
        workspace.set_name(0x401000, "main");
        workspace.set_name(0x401100, "foo");

        let data = workspace_to_data(&workspace);
        assert_eq!(data.symbols.len(), 2);
    }
}
