//! Remote workspace server.
//!
//! Replaces Python's Cobra RPC with a modern REST API using axum.
//! Provides HTTP endpoints for querying workspace state remotely.
//!
//! Feature-gated behind `remote` (requires tokio + axum).
//!
//! ## Usage
//!
//! ```rust,no_run
//! use vivisect::remote::server::{WorkspaceServer, DEFAULT_BIND_ADDR};
//! use vivisect::core::VivWorkspace;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let workspace = VivWorkspace::new();
//!     let server = WorkspaceServer::new(Arc::new(workspace));
//!     println!("Auth token: {}", server.token());
//!     server.run(DEFAULT_BIND_ADDR).await.unwrap();
//! }
//! ```

pub mod server;
