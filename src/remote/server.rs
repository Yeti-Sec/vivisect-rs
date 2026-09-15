//! REST API server for remote workspace access.
//!
//! Replaces Python's Cobra RPC framework (40K LOC) with a lightweight
//! axum-based HTTP server. Provides JSON endpoints for workspace queries.
//!
//! Security: defaults to localhost-only binding with bearer token auth.
//!
//! Endpoints:
//! - GET  /api/info              — workspace metadata
//! - GET  /api/functions         — list all functions
//! - GET  /api/function/:va      — function details + blocks
//! - GET  /api/imports           — list imports
//! - GET  /api/segments          — list memory segments
//! - GET  /api/xrefs/to/:va     — xrefs pointing to address
//! - GET  /api/xrefs/from/:va   — xrefs from address
//! - GET  /api/names             — all named addresses
//! - GET  /api/strings           — detected strings
//! - GET  /api/memory/:va/:size — read memory (hex encoded)
//! - GET  /api/cfg/:va          — function CFG (serialized)

use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;

use crate::constants::LocationType;
use crate::core::workspace::VivWorkspace;

/// Default bind address (localhost only).
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";

/// Shared workspace state wrapped in Arc for concurrent access.
type SharedWorkspace = Arc<VivWorkspace>;

/// REST API server for workspace access.
pub struct WorkspaceServer {
    workspace: SharedWorkspace,
    auth_token: String,
}

impl WorkspaceServer {
    /// Create a new server wrapping a workspace.
    ///
    /// Generates a random bearer token for authentication.
    pub fn new(workspace: Arc<VivWorkspace>) -> Self {
        let auth_token = generate_token();
        Self {
            workspace,
            auth_token,
        }
    }

    /// Create a new server with an explicit bearer token.
    pub fn with_token(workspace: Arc<VivWorkspace>, token: String) -> Self {
        Self {
            workspace,
            auth_token: token,
        }
    }

    /// Get the authentication token (for display to the user at startup).
    pub fn token(&self) -> &str {
        &self.auth_token
    }

    /// Build the axum router with auth middleware.
    pub fn router(&self) -> Router {
        let token = Arc::new(self.auth_token.clone());

        Router::new()
            .route("/api/info", get(get_info))
            .route("/api/functions", get(get_functions))
            .route("/api/function/{va}", get(get_function))
            .route("/api/imports", get(get_imports))
            .route("/api/segments", get(get_segments))
            .route("/api/xrefs/to/{va}", get(get_xrefs_to))
            .route("/api/xrefs/from/{va}", get(get_xrefs_from))
            .route("/api/names", get(get_names))
            .route("/api/strings", get(get_strings))
            .route("/api/memory/{va}/{size}", get(get_memory))
            .route("/api/cfg/{va}", get(get_cfg))
            .layer(middleware::from_fn_with_state(token, auth_middleware))
            .with_state(self.workspace.clone())
    }

    /// Run the server on the given address.
    ///
    /// Defaults to `127.0.0.1:8080` if no address is provided.
    /// Warns if binding to a non-loopback address.
    pub async fn run(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !addr.starts_with("127.0.0.1")
            && !addr.starts_with("localhost")
            && !addr.starts_with("[::1]")
        {
            tracing::warn!(
                "[remote] WARNING: binding to non-loopback address '{}'. \
                 The workspace API will be accessible from the network.",
                addr
            );
        }

        tracing::info!("[remote] workspace server listening on {}", addr);
        tracing::info!("[remote] auth token: {}", self.auth_token);

        let router = self.router();
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, router).await?;
        Ok(())
    }
}

/// Generate a random hex token for bearer auth.
fn generate_token() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let s = RandomState::new();
    let mut h = s.build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    let a = h.finish();
    let mut h = s.build_hasher();
    h.write_u64(a.wrapping_mul(0x517cc1b727220a95));
    let b = h.finish();
    format!("{:016x}{:016x}", a, b)
}

/// Bearer token auth middleware.
async fn auth_middleware(
    State(token): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let provided = &header[7..];
            if provided == token.as_str() {
                Ok(next.run(request).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// ── Response types ──

#[derive(Serialize)]
struct InfoResponse {
    architecture: String,
    endian: String,
    segments: usize,
    functions: usize,
    locations: usize,
    codeblocks: usize,
    entry_points: Vec<String>,
}

#[derive(Serialize)]
struct FunctionEntry {
    va: String,
    name: Option<String>,
    block_count: usize,
}

#[derive(Serialize)]
struct FunctionDetail {
    va: String,
    name: Option<String>,
    blocks: Vec<BlockEntry>,
    meta: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct BlockEntry {
    va: String,
    size: usize,
}

#[derive(Serialize)]
struct ImportEntry {
    va: String,
    name: String,
}

#[derive(Serialize)]
struct SegmentEntry {
    va: String,
    size: usize,
    name: String,
}

#[derive(Serialize)]
struct XrefEntry {
    from_va: String,
    to_va: String,
    ref_type: String,
}

#[derive(Serialize)]
struct NameEntry {
    va: String,
    name: String,
}

#[derive(Serialize)]
struct StringEntry {
    va: String,
    content: String,
    size: usize,
}

#[derive(Serialize)]
struct MemoryResponse {
    va: String,
    size: usize,
    hex: String,
}

// ── Handlers ──

fn parse_va(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>()
            .ok()
            .or_else(|| u64::from_str_radix(s, 16).ok())
    }
}

async fn get_info(State(ws): State<SharedWorkspace>) -> Json<InfoResponse> {
    let stats = ws.stats();
    Json(InfoResponse {
        architecture: format!("{:?}", ws.architecture()),
        endian: format!("{:?}", ws.endian()),
        segments: stats.segments,
        functions: stats.functions,
        locations: stats.locations,
        codeblocks: stats.codeblocks,
        entry_points: ws
            .entry_points()
            .iter()
            .map(|va| format!("{:#x}", va))
            .collect(),
    })
}

async fn get_functions(State(ws): State<SharedWorkspace>) -> Json<Vec<FunctionEntry>> {
    let funcs: Vec<FunctionEntry> = ws
        .get_functions()
        .iter()
        .map(|&va| {
            let name = ws.get_name(va).map(|s| s.to_string());
            let blocks = ws.get_function_blocks(va);
            FunctionEntry {
                va: format!("{:#x}", va),
                name,
                block_count: blocks.len(),
            }
        })
        .collect();
    Json(funcs)
}

async fn get_function(
    State(ws): State<SharedWorkspace>,
    Path(va_str): Path<String>,
) -> Result<Json<FunctionDetail>, StatusCode> {
    let va = parse_va(&va_str).ok_or(StatusCode::BAD_REQUEST)?;
    let func = ws.get_function(va).ok_or(StatusCode::NOT_FOUND)?;

    let blocks: Vec<BlockEntry> = ws
        .get_function_blocks(va)
        .iter()
        .map(|b| BlockEntry {
            va: format!("{:#x}", b.va),
            size: b.size,
        })
        .collect();

    Ok(Json(FunctionDetail {
        va: format!("{:#x}", va),
        name: func.name.clone(),
        blocks,
        meta: func.meta.clone(),
    }))
}

async fn get_imports(State(ws): State<SharedWorkspace>) -> Json<Vec<ImportEntry>> {
    let imports: Vec<ImportEntry> = ws
        .locations_iter()
        .filter(|(_, loc)| loc.ltype == LocationType::Import)
        .map(|(&va, loc)| {
            let name = loc
                .tinfo
                .clone()
                .or_else(|| ws.get_name(va).map(|s| s.to_string()))
                .unwrap_or_else(|| format!("import_{:x}", va));
            ImportEntry {
                va: format!("{:#x}", va),
                name,
            }
        })
        .collect();
    Json(imports)
}

async fn get_segments(State(ws): State<SharedWorkspace>) -> Json<Vec<SegmentEntry>> {
    let segs: Vec<SegmentEntry> = ws
        .get_segments()
        .iter()
        .map(|s| SegmentEntry {
            va: format!("{:#x}", s.va),
            size: s.size,
            name: s.name.clone(),
        })
        .collect();
    Json(segs)
}

async fn get_xrefs_to(
    State(ws): State<SharedWorkspace>,
    Path(va_str): Path<String>,
) -> Result<Json<Vec<XrefEntry>>, StatusCode> {
    let va = parse_va(&va_str).ok_or(StatusCode::BAD_REQUEST)?;
    let xrefs: Vec<XrefEntry> = ws
        .get_xrefs_to(va)
        .iter()
        .map(|(from_va, ref_type)| XrefEntry {
            from_va: format!("{:#x}", from_va),
            to_va: format!("{:#x}", va),
            ref_type: format!("{:?}", ref_type),
        })
        .collect();
    Ok(Json(xrefs))
}

async fn get_xrefs_from(
    State(ws): State<SharedWorkspace>,
    Path(va_str): Path<String>,
) -> Result<Json<Vec<XrefEntry>>, StatusCode> {
    let va = parse_va(&va_str).ok_or(StatusCode::BAD_REQUEST)?;
    let xrefs: Vec<XrefEntry> = ws
        .get_xrefs_from(va)
        .iter()
        .map(|(to_va, ref_type)| XrefEntry {
            from_va: format!("{:#x}", va),
            to_va: format!("{:#x}", to_va),
            ref_type: format!("{:?}", ref_type),
        })
        .collect();
    Ok(Json(xrefs))
}

async fn get_names(State(ws): State<SharedWorkspace>) -> Json<Vec<NameEntry>> {
    let names: Vec<NameEntry> = ws
        .symbols()
        .iter()
        .map(|(va, name)| NameEntry {
            va: format!("{:#x}", va),
            name: name.to_string(),
        })
        .collect();
    Json(names)
}

async fn get_strings(State(ws): State<SharedWorkspace>) -> Json<Vec<StringEntry>> {
    let strings: Vec<StringEntry> = ws
        .locations_iter()
        .filter(|(_, loc)| matches!(loc.ltype, LocationType::String | LocationType::Unicode))
        .map(|(&va, loc)| StringEntry {
            va: format!("{:#x}", va),
            content: loc.tinfo.clone().unwrap_or_default(),
            size: loc.size,
        })
        .collect();
    Json(strings)
}

async fn get_memory(
    State(ws): State<SharedWorkspace>,
    Path((va_str, size_str)): Path<(String, String)>,
) -> Result<Json<MemoryResponse>, StatusCode> {
    let va = parse_va(&va_str).ok_or(StatusCode::BAD_REQUEST)?;
    let size: usize = size_str.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let size = size.min(0x10000); // Cap at 64KB

    let data = ws
        .read_memory(va, size)
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MemoryResponse {
        va: format!("{:#x}", va),
        size: data.len(),
        hex: hex::encode(&data),
    }))
}

async fn get_cfg(
    State(ws): State<SharedWorkspace>,
    Path(va_str): Path<String>,
) -> Result<Json<crate::core::cfg::SerializableCfg>, StatusCode> {
    let va = parse_va(&va_str).ok_or(StatusCode::BAD_REQUEST)?;
    if !ws.is_function(va) {
        return Err(StatusCode::NOT_FOUND);
    }
    let cfg = ws.build_function_cfg(va);
    Ok(Json(cfg.to_serializable()))
}
