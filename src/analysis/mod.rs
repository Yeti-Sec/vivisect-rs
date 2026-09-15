//! Analysis modules for binary analysis.
//!
//! This module contains analysis passes for function discovery,
//! code flow analysis, and other static analysis techniques.

pub mod arm_analysis;
pub mod calling;
pub mod codeflow;
pub mod crypto;
pub mod elfctors;
pub mod elfplt;
pub mod elfplt_late;
pub mod emucode;
pub mod funcentries;
pub mod golang;
pub mod hotpatch;
pub mod impapi;
pub mod importcalls;
pub mod instrhook;
pub mod libc_start_main;
pub mod linker;
pub mod msvc;
pub mod noret;
pub mod orchestration;
pub mod pe_analysis;
pub mod pointers;
pub mod pointertables;
pub mod relocations;
pub mod strings;
pub mod switchcase;
pub mod symswitchcase;
pub mod thunk_reg;
pub mod thunks;
pub mod vftables;

// Re-export codeflow types with explicit names to avoid conflicts
pub use codeflow::{
    analyze_function, scan_function_prologues, BasicBlockInfo, CodeFlowAnalyzer, FunctionAnalysis,
};
// Rename codeflow::AnalysisResult to avoid conflict with orchestration::AnalysisResult
pub use codeflow::AnalysisResult as CodeFlowResult;

pub use orchestration::*;
pub use strings::*;
