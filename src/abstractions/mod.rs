//! Core abstraction traits for the vivisect framework.
//!
//! These traits define the interfaces for pluggable implementations
//! of emulation, binary analysis, and memory management.

pub mod binary;
pub mod driver;
pub mod emulator;
pub mod memory;
pub mod monitor;
pub mod registers;

pub use binary::*;
pub use driver::*;
pub use emulator::*;
pub use memory::*;
pub use monitor::*;
pub use registers::*;
