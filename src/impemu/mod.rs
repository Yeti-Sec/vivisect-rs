//! Import emulation subsystem.
//!
//! Port of Python's `vivisect/impemu/` — provides a workspace-aware emulator
//! that can run functions with API stubs for imported functions.
//!
//! Architecture:
//! - `WorkspaceEmulator` wraps icicle-vm (or disassembly fallback)
//! - `EmulationMonitor` provides hooks for prehook/posthook per instruction
//! - Platform stubs provide no-op or minimal implementations of OS APIs
//!
//! The emulator maps workspace memory into the VM, sets up a stack,
//! and runs code. When a call to an imported function is detected,
//! the stub handles it (e.g., returning 0 for most APIs, or stopping
//! execution for ExitProcess).

pub mod monitor;
pub mod workspace_emu;

pub use monitor::{EmulationMonitor, MonitorAction};
pub use workspace_emu::WorkspaceEmulator;
