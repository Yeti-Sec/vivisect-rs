//! Symbolic execution framework for vivisect.
//!
//! Provides symbolic value tracking, expression trees, effects,
//! and a symbolic emulator that can produce function summaries
//! for binary comparison.

pub mod analysis;
pub mod effect;
pub mod emulator;
pub mod reducer;
pub mod solver;
pub mod translator;
pub mod value;
pub mod workspace;

pub use analysis::{SymbolikAnalysisContext, SymbolikGraph, SymbolikOutput};
pub use effect::SymbolicEffect;
pub use emulator::{SymbolicEmulator, SymbolicSummary};
pub use translator::SymbolikTranslator;
pub use value::{ConstraintOp, Op, SymbolicValue};
