//! Analysis modules for binary analysis.
//!
//! This module contains analysis passes for function discovery,
//! code flow analysis, and other static analysis techniques.

pub mod codeflow;
pub mod orchestration;
pub mod strings;

// Re-export codeflow types with explicit names to avoid conflicts
pub use codeflow::{
    analyze_function, scan_function_prologues, BasicBlockInfo, CodeFlowAnalyzer, FunctionAnalysis,
};
// Rename codeflow::AnalysisResult to avoid conflict with orchestration::AnalysisResult
pub use codeflow::AnalysisResult as CodeFlowResult;

pub use orchestration::*;
pub use strings::*;
