//! Thread-safe read-only workspace wrapper.
//!
//! After analysis completes, a [`VivWorkspace`] can be frozen into a
//! [`FrozenWorkspace`] that is `Send + Sync`, enabling concurrent read
//! access from multiple threads without any locking overhead.
//!
//! # Example
//!
//! ```rust,no_run
//! use vivisect::core::{VivWorkspace, FrozenWorkspace};
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! let mut ws = VivWorkspace::new();
//! ws.load_from_file(Path::new("target.exe")).unwrap();
//! ws.analyze();
//!
//! // Freeze the workspace for concurrent access
//! let frozen = Arc::new(FrozenWorkspace::freeze(ws));
//!
//! // Spawn threads that share the workspace
//! let ws1 = Arc::clone(&frozen);
//! let ws2 = Arc::clone(&frozen);
//!
//! let t1 = std::thread::spawn(move || {
//!     ws1.get_functions().len()
//! });
//! let t2 = std::thread::spawn(move || {
//!     ws2.read_memory(0x401000, 16).ok()
//! });
//!
//! t1.join().unwrap();
//! t2.join().unwrap();
//! ```
//!
//! # Safety
//!
//! All fields of `VivWorkspace` are standard Rust collections (`HashMap`,
//! `IndexMap`, `BTreeMap`, `Vec`) that are inherently `Sync`. There is no
//! interior mutability (`RefCell`, `Cell`), no raw pointers, and no `unsafe`
//! code in the workspace itself. The only reason `VivWorkspace` isn't
//! automatically `Sync` is that the compiler can't prove the absence of
//! mutable aliasing — `FrozenWorkspace` enforces this by only exposing
//! `&self` methods via `Deref`.

use super::workspace::VivWorkspace;
use std::ops::Deref;

/// A fully-analyzed workspace that is safe for concurrent read access.
///
/// Created by calling [`FrozenWorkspace::freeze`] on a `VivWorkspace`
/// after analysis is complete. All `&self` methods on `VivWorkspace` are
/// accessible through `Deref`, while `&mut self` methods (mutation) are
/// statically prevented by the type system.
///
/// This wrapper has **zero runtime overhead** — no locks, no atomic
/// operations, no indirection. It simply restricts the API surface to
/// read-only methods and provides the `Send + Sync` bounds.
pub struct FrozenWorkspace(VivWorkspace);

// SAFETY: All fields of VivWorkspace are Sync-compatible standard library
// types (HashMap, IndexMap, BTreeMap, Vec, String, primitives). No interior
// mutability, no raw pointers. FrozenWorkspace only exposes &self methods,
// so no concurrent mutation can occur.
unsafe impl Sync for FrozenWorkspace {}
unsafe impl Send for FrozenWorkspace {}

impl FrozenWorkspace {
    /// Consume a fully-analyzed `VivWorkspace`, producing a thread-safe
    /// read-only handle.
    ///
    /// After freezing, all `&self` methods on `VivWorkspace` remain
    /// accessible (via `Deref`), but mutation is statically prevented.
    ///
    /// # When to freeze
    ///
    /// Freeze after all analysis, function discovery, and library marking
    /// is complete — i.e., after `workspace.analyze()` and any FLIRT
    /// signature matching or manual function registration.
    pub fn freeze(ws: VivWorkspace) -> Self {
        Self(ws)
    }

    /// Unwrap back into a mutable `VivWorkspace`.
    ///
    /// Use this if you need to perform further mutation (e.g., mark
    /// additional library functions) after a frozen read phase.
    pub fn thaw(self) -> VivWorkspace {
        self.0
    }
}

impl Deref for FrozenWorkspace {
    type Target = VivWorkspace;

    #[inline]
    fn deref(&self) -> &VivWorkspace {
        &self.0
    }
}

impl std::fmt::Debug for FrozenWorkspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.0.stats();
        f.debug_struct("FrozenWorkspace")
            .field("functions", &stats.functions)
            .field("codeblocks", &stats.codeblocks)
            .field("segments", &stats.segments)
            .field("symbols", &stats.symbols)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freeze_and_thaw() {
        let ws = VivWorkspace::new();
        assert!(ws.get_functions().is_empty());

        let frozen = FrozenWorkspace::freeze(ws);
        assert!(frozen.get_functions().is_empty());
        assert_eq!(frozen.function_count(), 0);

        // Thaw back to mutable
        let mut ws = frozen.thaw();
        ws.set_name(0x401000, "main");
        assert_eq!(ws.get_name(0x401000), Some("main"));
    }

    #[test]
    fn test_frozen_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FrozenWorkspace>();
    }

    #[test]
    fn test_deref_access() {
        let ws = VivWorkspace::new();
        let frozen = FrozenWorkspace::freeze(ws);

        // All &self methods should work via Deref
        let _ = frozen.architecture();
        let _ = frozen.endian();
        let _ = frozen.entry_points();
        let _ = frozen.get_functions();
        let _ = frozen.function_count();
        let _ = frozen.stats();
        let _ = frozen.get_segments();
        let _ = frozen.get_files();
    }

    #[test]
    fn test_concurrent_reads() {
        use std::sync::Arc;

        let ws = VivWorkspace::new();
        let frozen = Arc::new(FrozenWorkspace::freeze(ws));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let ws = Arc::clone(&frozen);
                std::thread::spawn(move || {
                    ws.get_functions().len() + ws.function_count()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), 0);
        }
    }
}
