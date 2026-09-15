//! Workspace storage and serialization.
//!
//! This module handles saving and loading workspaces to/from disk.

pub mod msgpack;

pub use msgpack::*;

use crate::core::VivWorkspace;
use crate::error::VivResult;
use std::path::Path;

/// Storage format type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFormat {
    /// MessagePack format (default, Python compatible).
    MsgPack,
    /// JSON format (human readable).
    Json,
}

/// Save a workspace to a file.
#[must_use]
pub fn save_workspace(
    workspace: &VivWorkspace,
    path: &Path,
    format: StorageFormat,
) -> VivResult<()> {
    match format {
        StorageFormat::MsgPack => msgpack::save_workspace(workspace, path),
        StorageFormat::Json => msgpack::save_workspace_json(workspace, path),
    }
}

/// Load a workspace from a file.
#[must_use]
pub fn load_workspace(path: &Path) -> VivResult<VivWorkspace> {
    // Detect format by extension
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext {
        "json" => msgpack::load_workspace_json(path),
        _ => msgpack::load_workspace(path),
    }
}
