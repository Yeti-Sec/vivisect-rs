//! Import API metadata module.
//!
//! Port of Python's `vivisect/analysis/generic/impapi.py`.
//!
//! Annotates functions with their API signatures (calling convention,
//! return type, argument types/names) by looking up function names in
//! a pre-built database of known Windows and POSIX API definitions.
//!
//! The API database is extracted from Python vivisect's impapi module
//! and embedded as JSON. It contains ~7500 Windows i386 entries and
//! ~6600 Windows amd64 entries covering kernel32, ntdll, msvcrt,
//! user32, advapi32, gdi32, ole32, rpcrt4, ws2_32, and shell32.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;

/// A single API argument definition.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiArg {
    #[serde(rename = "type")]
    pub arg_type: String,
    pub name: Option<String>,
}

/// A single API definition.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiDef {
    pub ret_type: String,
    pub callconv: String,
    pub callname: String,
    pub args: Vec<ApiArg>,
}

/// Raw JSON structure matching the fixtures/impapi.json layout.
#[derive(Debug, Deserialize)]
struct ImpApiRaw {
    windows_i386: HashMap<String, ApiDef>,
    windows_amd64: HashMap<String, ApiDef>,
    #[serde(default)]
    posix_i386: HashMap<String, ApiDef>,
    #[serde(default)]
    posix_amd64: HashMap<String, ApiDef>,
}

/// Merged per-architecture API databases (Windows + POSIX combined).
struct ImpApiData {
    i386: HashMap<String, ApiDef>,
    amd64: HashMap<String, ApiDef>,
}

static IMPAPI_DATA: OnceLock<ImpApiData> = OnceLock::new();

fn get_impapi_data() -> &'static ImpApiData {
    IMPAPI_DATA.get_or_init(|| {
        let json = include_str!("../../fixtures/impapi.json");
        let raw: ImpApiRaw =
            serde_json::from_str(json).expect("Failed to parse embedded impapi.json");

        // Merge Windows + POSIX per architecture (keys don't conflict:
        // Windows uses "kernel32.func", POSIX uses "*.func")
        let mut i386 = raw.windows_i386;
        i386.extend(raw.posix_i386);

        let mut amd64 = raw.windows_amd64;
        amd64.extend(raw.posix_amd64);

        ImpApiData { i386, amd64 }
    })
}

/// Get the merged API database for a given architecture.
pub fn get_api_db(arch: Architecture) -> &'static HashMap<String, ApiDef> {
    let data = get_impapi_data();
    match arch {
        Architecture::Amd64 => &data.amd64,
        _ => &data.i386,
    }
}

/// Look up a function name in the API database.
///
/// Tries the name as-is (lowercase), then for thunk functions strips
/// the `thunk_` prefix and tries with common library prefixes.
#[must_use]
pub fn lookup_api<'a>(db: &'a HashMap<String, ApiDef>, name: &str) -> Option<&'a ApiDef> {
    let key = name.to_lowercase();

    // Direct lookup (handles names like "kernel32.ExitProcess")
    if let Some(api) = db.get(&key) {
        return Some(api);
    }

    // Normalize: strip ".dll" from library prefix
    // e.g., "kernel32.dll.getcommandlinea" → "kernel32.getcommandlinea"
    let normalized = normalize_import_name(&key);
    if normalized != key {
        if let Some(api) = db.get(&normalized) {
            return Some(api);
        }
    }

    // For thunks, strip "thunk_" prefix and try with library names
    let basename = if let Some(b) = key.strip_prefix("thunk_") {
        b
    } else {
        return None;
    };

    static LIBS: &[&str] = &[
        "kernel32", "ntdll", "msvcrt", "user32", "advapi32",
        "gdi32", "ole32", "rpcrt4", "ws2_32", "shell32",
        "msvcr71", "msvcr80", "msvcr90", "msvcr100",
        "msvcr110", "msvcr120",
    ];
    for lib in LIBS {
        let prefixed = format!("{}.{}", lib, basename);
        if let Some(api) = db.get(&prefixed) {
            return Some(api);
        }
    }

    None
}

/// Normalize an import name by stripping ".dll" from the library prefix.
///
/// Examples:
/// - `"kernel32.dll.exitprocess"` → `"kernel32.exitprocess"`
/// - `"ntdll.dll.rtlallocateheap"` → `"ntdll.rtlallocateheap"`
/// - `"kernel32.exitprocess"` → `"kernel32.exitprocess"` (unchanged)
fn normalize_import_name(name: &str) -> String {
    // Look for ".dll." pattern and remove the ".dll" part
    if let Some(pos) = name.find(".dll.") {
        let mut result = String::with_capacity(name.len() - 4);
        result.push_str(&name[..pos]);
        result.push_str(&name[pos + 4..]); // skip ".dll"
        result
    } else {
        name.to_string()
    }
}

/// Apply an API definition to a function's metadata.
fn apply_api(workspace: &mut VivWorkspace, func_va: u64, api: &ApiDef) {
    if let Some(meta) = workspace.get_function_mut(func_va) {
        meta.calling_convention = Some(api.callconv.clone());
        meta.ret_type = Some(api.ret_type.clone());
        meta.args = api
            .args
            .iter()
            .enumerate()
            .map(|(i, arg)| {
                let name = arg
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("arg{}", i));
                (arg.arg_type.clone(), name)
            })
            .collect();
    }
}

/// Run import API analysis on all functions in the workspace.
///
/// For each function:
/// 1. Get the function's name (from symbol table or FunctionMeta)
/// 2. If it's a thunk, get the original import name from metadata
/// 3. Look up in the API database
/// 4. If found, set calling_convention, ret_type, and args
///
/// Returns the number of functions annotated.
pub fn analyze_impapi(workspace: &mut VivWorkspace) -> usize {
    let arch = workspace.architecture();
    let db = get_api_db(arch);

    // Collect function VAs and their lookup names
    let func_info: Vec<(u64, String)> = workspace
        .get_functions()
        .iter()
        .filter_map(|&va| {
            // Priority 1: thunk metadata (has the original import name like "kernel32.ExitProcess")
            if let Some(meta) = workspace.get_function(va) {
                if let Some(thunk_target) = meta.meta.get("Thunk") {
                    if !thunk_target.is_empty() {
                        return Some((va, thunk_target.clone()));
                    }
                }
            }

            // Priority 2: symbol/function name
            if let Some(name) = workspace.get_name(va) {
                return Some((va, name.to_string()));
            }
            if let Some(meta) = workspace.get_function(va) {
                if let Some(name) = &meta.name {
                    return Some((va, name.clone()));
                }
            }

            None
        })
        .collect();

    let mut count = 0;
    for (va, name) in &func_info {
        if let Some(api) = lookup_api(db, name) {
            apply_api(workspace, *va, api);
            count += 1;
        }
    }

    tracing::debug!("[impapi] annotated {} functions with API metadata", count);
    count
}
