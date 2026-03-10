//! # Vivisect
//!
//! A pure Rust disassembler, debugger, emulator, and static analysis framework.
//!
//! This is a Rust port of the Python vivisect project, providing:
//!
//! - Multi-architecture disassembly
//! - Binary format parsing (PE, ELF, Mach-O)
//! - CPU emulation
//! - Static analysis and code flow tracking
//! - Cross-reference management
//! - Symbol and name management
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use vivisect::core::VivWorkspace;
//! use std::path::Path;
//!
//! fn main() -> vivisect::error::VivResult<()> {
//!     // Create a new workspace
//!     let mut workspace = VivWorkspace::new();
//!
//!     // Load a binary
//!     workspace.load_from_file(Path::new("target.exe"))?;
//!
//!     // Get entry points
//!     for entry in workspace.entry_points() {
//!         println!("Entry point: {:#x}", entry);
//!     }
//!
//!     // Get statistics
//!     let stats = workspace.stats();
//!     println!("Segments: {}", stats.segments);
//!     println!("Symbols: {}", stats.symbols);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture
//!
//! The crate is organized into several modules:
//!
//! - [`constants`] - Enums and bitflags for instruction flags, reference types, etc.
//! - [`error`] - Error types using thiserror
//! - [`abstractions`] - Trait definitions for emulators, memory, registers
//! - [`envi`] - Architecture abstraction layer (opcodes, operands, memory)
//! - [`vstruct`] - Binary structure parsing primitives
//! - [`parsers`] - Binary format parsers (PE, ELF, Mach-O)
//! - [`core`] - Main workspace and analysis functionality
//! - [`utils`] - Utility functions

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod abstractions;
pub mod analysis;
pub mod constants;
pub mod core;
pub mod emulator;
pub mod envi;
pub mod error;
pub mod parsers;
pub mod storage;
pub mod symboliks;
pub mod utils;
pub mod vstruct;

// Re-exports for convenience
pub use constants::*;
pub use error::{VivError, VivResult};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Crate name.
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(VERSION, "0.1.0");
    }
}
