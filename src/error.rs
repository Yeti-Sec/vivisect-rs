//! Error types for the vivisect framework.
//!
//! This module contains all error types used throughout the crate,
//! translated from Python's vivisect/exc.py.

use thiserror::Error;

/// Main error type for vivisect operations.
#[derive(Debug, Error)]
pub enum VivError {
    /// Analysis error.
    #[error("Analysis error: {message}")]
    AnalysisError { message: String },

    /// Blob loader requires architecture specification.
    #[error("Blob loader requires arch option (-O viv.parsers.blob.arch=\"<archname>\")")]
    BlobArchRequired,

    /// Hit an invalid/out instruction during disassembly.
    #[error("Hit out instruction at {va:#x}")]
    BadOutInstruction { va: u64 },

    /// Invalid location in workspace.
    #[error("Invalid location {va:#x}: {message}")]
    InvalidLocation { va: u64, message: String },

    /// Duplicate name in symbol table.
    #[error("Duplicate name: {name} at {orig_va:#x} and {new_va:#x}")]
    DuplicateName {
        orig_va: u64,
        new_va: u64,
        name: String,
    },

    /// Invalid VA set specified.
    #[error("Invalid VA set specified: {name}")]
    InvalidVaSet { name: String },

    /// VA is not a function.
    #[error("VA {va:#x} is not a function")]
    InvalidFunction { va: u64 },

    /// VA is not in a code block.
    #[error("VA {va:#x} is not in a code block")]
    InvalidCodeBlock { va: u64 },

    /// Hit known bad opcode bytes.
    #[error("Hit known bad opcode bytes at {va:#x}")]
    BadOpBytes { va: u64 },

    /// Unknown calling convention.
    #[error("Function {fva:#x} has unknown calling convention: {cc:?}")]
    UnknownCallingConvention { fva: u64, cc: Option<String> },

    /// Invalid workspace data.
    #[error("Failed to load {name}: {reason}")]
    InvalidWorkspace { name: String, reason: String },

    /// Architecture module not defined.
    #[error("Architecture module not defined for {arch}")]
    ArchModNotDefined { arch: String },

    /// Architecture not supported for file format.
    #[error("Architecture {arch} is not supported for {file_format}")]
    InvalidArchitecture { file_format: String, arch: String },

    /// Corrupt file encountered.
    #[error("{file_format}: corrupt file: {message}")]
    CorruptFile {
        file_format: String,
        message: String,
    },

    /// Symbol index not found.
    #[error("getSymIdx cannot determine the Index register")]
    SymIdxNotFound,

    /// Complex symbol index not found.
    #[error("getComplexIdx cannot determine the Index register")]
    NoComplexSymIdx,

    /// Invalid memory access.
    #[error("Invalid memory access at {address:#x}")]
    InvalidMemory { address: u64 },

    /// Execution limit reached.
    #[error("Execution limit reached after {count} instructions")]
    ExecutionLimit { count: usize },

    /// Invalid instruction at address.
    #[error("Invalid instruction at {address:#x}")]
    InvalidInstruction { address: u64 },

    /// Breakpoint hit.
    #[error("Breakpoint hit at {address:#x}")]
    Breakpoint { address: u64 },

    /// Invalid register name.
    #[error("Unknown register: {name}")]
    InvalidRegister { name: String },

    /// Parse error.
    #[error("Parse error: {message}")]
    ParseError { message: String },

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error with message.
    #[error("{message}")]
    Other { message: String },
}

/// Specialized PE file corruption error.
#[derive(Debug, Error)]
#[error("PE: corrupt file: {message}")]
pub struct CorruptPeError {
    pub message: String,
}

impl From<CorruptPeError> for VivError {
    fn from(e: CorruptPeError) -> Self {
        VivError::CorruptFile {
            file_format: "PE".to_string(),
            message: e.message,
        }
    }
}

/// Specialized ELF file corruption error.
#[derive(Debug, Error)]
#[error("ELF: corrupt file: {message}")]
pub struct CorruptElfError {
    pub message: String,
}

impl From<CorruptElfError> for VivError {
    fn from(e: CorruptElfError) -> Self {
        VivError::CorruptFile {
            file_format: "ELF".to_string(),
            message: e.message,
        }
    }
}

/// Result type alias for vivisect operations.
pub type VivResult<T> = Result<T, VivError>;
