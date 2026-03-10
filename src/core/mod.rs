//! Core vivisect functionality.
//!
//! This module contains the main workspace and analysis types.

pub mod callgraph;
pub mod cfg;
pub mod frozen;
pub mod locations;
pub mod symbols;
pub mod workspace;
pub mod xrefs;

pub use callgraph::CallGraph;
pub use cfg::{CfgBuilder, CfgEdgeType, CfgNode, ControlFlowGraph};
pub use frozen::FrozenWorkspace;
pub use locations::{Location, LocationManager, LocationStats};
pub use symbols::SymbolTable;
pub use workspace::VivWorkspace;
pub use xrefs::XRefManager;
