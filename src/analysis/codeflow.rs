//! Code flow analysis for function and basic block discovery.
//!
//! This module provides algorithms for discovering functions and
//! basic blocks through code flow analysis.

use crate::constants::{Architecture, BranchFlags, LocationType, RefType};
use crate::core::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::{VivError, VivResult};
use std::collections::{HashSet, VecDeque};

/// Code flow analysis context.
pub struct CodeFlowAnalyzer {
    /// Visited addresses.
    visited: HashSet<u64>,
    /// Pending addresses to analyze.
    pending: VecDeque<u64>,
    /// Discovered function entry points.
    functions: HashSet<u64>,
    /// Discovered basic block starts.
    block_starts: HashSet<u64>,
    /// Maximum number of instructions to analyze per run.
    max_instructions: usize,
}

impl CodeFlowAnalyzer {
    /// Create a new code flow analyzer.
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            pending: VecDeque::new(),
            functions: HashSet::new(),
            block_starts: HashSet::new(),
            max_instructions: 100000,
        }
    }

    /// Set maximum instructions to analyze.
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }

    /// Add an entry point to analyze.
    pub fn add_entry_point(&mut self, va: u64) {
        if !self.visited.contains(&va) {
            self.pending.push_back(va);
            self.functions.insert(va);
            self.block_starts.insert(va);
        }
    }

    /// Run code flow analysis on a workspace.
    pub fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisResult> {
        let arch = workspace.architecture();

        // Create appropriate disassembler
        let disasm = match arch {
            Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
            Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
            _ => {
                return Err(VivError::ArchModNotDefined {
                    arch: format!("{:?}", arch),
                })
            }
        };

        let mut instruction_count = 0;
        let mut discovered_functions = Vec::new();
        let mut discovered_blocks = Vec::new();

        while let Some(va) = self.pending.pop_front() {
            if self.visited.contains(&va) {
                continue;
            }

            if instruction_count >= self.max_instructions {
                break;
            }

            // Try to read bytes at this address
            let bytes = match workspace.read_memory(va, 16) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Disassemble instruction
            let op = match disasm.disassemble(&bytes, va) {
                Ok(o) => o,
                Err(_) => continue,
            };

            self.visited.insert(va);
            instruction_count += 1;

            // Add location to workspace
            workspace.add_location(va, op.size as usize, LocationType::Op, None);

            // Process branches
            for (target, flags) in op.get_branches() {
                if let Some(target_va) = target {
                    // Add xref
                    let ref_type = if flags.contains(BranchFlags::PROC) {
                        RefType::Code
                    } else {
                        RefType::Code
                    };
                    workspace.add_xref(va, target_va, ref_type);

                    // Handle call targets as potential functions
                    if flags.contains(BranchFlags::PROC) && !flags.contains(BranchFlags::DEREF) {
                        if !self.functions.contains(&target_va) {
                            self.functions.insert(target_va);
                            self.block_starts.insert(target_va);
                            discovered_functions.push(target_va);
                        }
                        if !self.visited.contains(&target_va) {
                            self.pending.push_back(target_va);
                        }
                    }

                    // Handle branch targets as block starts
                    if flags.contains(BranchFlags::COND) || !flags.contains(BranchFlags::FALL) {
                        if !flags.contains(BranchFlags::FALL) && !flags.contains(BranchFlags::DEREF) {
                            if !self.block_starts.contains(&target_va) {
                                self.block_starts.insert(target_va);
                                discovered_blocks.push(target_va);
                            }
                            if !self.visited.contains(&target_va) {
                                self.pending.push_back(target_va);
                            }
                        }
                    }

                    // Handle fall-through
                    if flags.contains(BranchFlags::FALL) {
                        if !self.visited.contains(&target_va) {
                            self.pending.push_front(target_va); // Priority for linear flow
                        }
                    }
                }
            }

            // If this is a conditional branch, the fall-through is a new block
            if op.is_branch() && op.is_conditional() {
                let next_va = va + op.size as u64;
                if !self.block_starts.contains(&next_va) {
                    self.block_starts.insert(next_va);
                    discovered_blocks.push(next_va);
                }
            }
        }

        Ok(AnalysisResult {
            instructions_analyzed: instruction_count,
            functions_discovered: discovered_functions,
            blocks_discovered: discovered_blocks,
        })
    }

    /// Get all discovered function addresses.
    pub fn get_functions(&self) -> Vec<u64> {
        self.functions.iter().copied().collect()
    }

    /// Get all discovered block start addresses.
    pub fn get_block_starts(&self) -> Vec<u64> {
        self.block_starts.iter().copied().collect()
    }

    /// Check if an address has been visited.
    pub fn is_visited(&self, va: u64) -> bool {
        self.visited.contains(&va)
    }

    /// Reset the analyzer state.
    pub fn reset(&mut self) {
        self.visited.clear();
        self.pending.clear();
        self.functions.clear();
        self.block_starts.clear();
    }
}

impl Default for CodeFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of code flow analysis.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    /// Number of instructions analyzed.
    pub instructions_analyzed: usize,
    /// Newly discovered function entry points.
    pub functions_discovered: Vec<u64>,
    /// Newly discovered basic block starts.
    pub blocks_discovered: Vec<u64>,
}

/// Analyze a function starting at the given address.
pub fn analyze_function(
    workspace: &mut VivWorkspace,
    func_va: u64,
) -> VivResult<FunctionAnalysis> {
    let arch = workspace.architecture();

    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => {
            return Err(VivError::ArchModNotDefined {
                arch: format!("{:?}", arch),
            })
        }
    };

    let mut visited: HashSet<u64> = HashSet::new();
    let mut pending: VecDeque<u64> = VecDeque::new();
    let mut blocks: Vec<BasicBlockInfo> = Vec::new();
    let mut current_block_start = func_va;
    let mut current_block_instrs: Vec<u64> = Vec::new();

    pending.push_back(func_va);

    while let Some(va) = pending.pop_front() {
        if visited.contains(&va) {
            continue;
        }

        // Check if this starts a new block
        if va != current_block_start && !current_block_instrs.is_empty() {
            // Save current block
            if let Some(&last_va) = current_block_instrs.last() {
                let block_end = last_va + 1; // Approximate
                blocks.push(BasicBlockInfo {
                    start: current_block_start,
                    end: block_end,
                    instructions: current_block_instrs.len(),
                });
            }
            current_block_start = va;
            current_block_instrs.clear();
        }

        let bytes = match workspace.read_memory(va, 16) {
            Ok(b) => b,
            Err(_) => break,
        };

        let op = match disasm.disassemble(&bytes, va) {
            Ok(o) => o,
            Err(_) => break,
        };

        visited.insert(va);
        current_block_instrs.push(va);

        // Check for end of block conditions
        let mut is_block_end = false;

        if op.is_return() {
            is_block_end = true;
        } else if op.is_branch() && !op.is_call() {
            is_block_end = true;

            // Add branch targets to pending
            for (target, flags) in op.get_branches() {
                if let Some(target_va) = target {
                    if !flags.contains(BranchFlags::DEREF) && !visited.contains(&target_va) {
                        pending.push_back(target_va);
                    }
                }
            }
        } else {
            // Continue linear flow
            let next_va = va + op.size as u64;
            if !visited.contains(&next_va) {
                pending.push_front(next_va);
            }
        }

        if is_block_end && !current_block_instrs.is_empty() {
            let block_end = va + op.size as u64;
            blocks.push(BasicBlockInfo {
                start: current_block_start,
                end: block_end,
                instructions: current_block_instrs.len(),
            });
            current_block_start = va + op.size as u64;
            current_block_instrs.clear();
        }
    }

    // Don't forget the last block if not empty
    if !current_block_instrs.is_empty() {
        if let Some(&last_va) = current_block_instrs.last() {
            blocks.push(BasicBlockInfo {
                start: current_block_start,
                end: last_va + 1,
                instructions: current_block_instrs.len(),
            });
        }
    }

    Ok(FunctionAnalysis {
        entry: func_va,
        blocks,
        size: visited.len(),
    })
}

/// Basic block information.
#[derive(Debug, Clone)]
pub struct BasicBlockInfo {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Number of instructions.
    pub instructions: usize,
}

/// Function analysis result.
#[derive(Debug, Clone)]
pub struct FunctionAnalysis {
    /// Function entry point.
    pub entry: u64,
    /// Basic blocks in this function.
    pub blocks: Vec<BasicBlockInfo>,
    /// Total number of instructions.
    pub size: usize,
}

/// Scan executable segments for function prologue byte patterns.
///
/// Discovers functions that were missed by call-following analysis,
/// such as functions only reached via indirect calls or function pointers.
/// This is similar to IDA's function prologue scanning and Python vivisect's
/// `FuncEntrySignature` analysis pass.
pub fn scan_function_prologues(workspace: &mut VivWorkspace) -> VivResult<Vec<u64>> {
    use crate::core::workspace::FunctionMeta;

    let arch = workspace.architecture();

    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => return Ok(Vec::new()),
    };

    // Define prologue patterns per architecture
    let patterns: Vec<&[u8]> = match arch {
        Architecture::I386 => vec![
            &[0x55, 0x8B, 0xEC],       // push ebp; mov ebp, esp (MSVC)
            &[0x55, 0x89, 0xE5],       // push ebp; mov ebp, esp (GCC)
            &[0x55, 0x8B, 0xEC, 0x83], // push ebp; mov ebp, esp; sub esp (MSVC with local vars)
            &[0x55, 0x8B, 0xEC, 0x81], // push ebp; mov ebp, esp; sub esp (MSVC large frame)
        ],
        Architecture::Amd64 => vec![
            &[0x55, 0x48, 0x89, 0xE5],             // push rbp; mov rbp, rsp
            &[0x48, 0x89, 0x5C, 0x24],             // mov [rsp+X], rbx (MSVC leaf)
            &[0x48, 0x83, 0xEC],                   // sub rsp, imm8
            &[0x40, 0x55],                         // rex push rbp
            &[0x48, 0x8B, 0xC4],                   // mov rax, rsp (MSVC frame)
        ],
        _ => vec![],
    };

    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let min_pattern_len = patterns.iter().map(|p| p.len()).min().unwrap_or(3);

    // Collect code segment info (name + va + size) before mutable borrow
    let code_segments: Vec<(u64, usize)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            let name_lower = seg.name.to_lowercase();
            name_lower.contains("text") || name_lower.contains("code")
        })
        .map(|seg| (seg.va, seg.size))
        .collect();

    let mut discovered = Vec::new();

    for (seg_va, seg_size) in &code_segments {
        // Read entire segment
        let seg_bytes = match workspace.read_memory(*seg_va, *seg_size) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Scan for each pattern
        for pattern in &patterns {
            if seg_bytes.len() < pattern.len() {
                continue;
            }

            for offset in 0..=(seg_bytes.len() - pattern.len()) {
                if &seg_bytes[offset..offset + pattern.len()] != *pattern {
                    continue;
                }

                let candidate_va = seg_va + offset as u64;

                // Skip if already a known function
                if workspace.is_function(candidate_va) {
                    continue;
                }

                // Skip if this address is already defined as code (middle of existing instruction)
                if workspace.get_location(candidate_va).is_some() {
                    continue;
                }

                // Validate: try disassembling at least 3 instructions successfully
                let valid = validate_prologue_candidate(
                    &disasm,
                    &seg_bytes[offset..],
                    candidate_va,
                );

                if valid {
                    let meta = FunctionMeta::default();
                    if workspace.add_function(candidate_va, meta).is_ok() {
                        discovered.push(candidate_va);
                    }
                }
            }
        }
    }

    // Deduplicate (patterns may overlap)
    discovered.sort_unstable();
    discovered.dedup();

    Ok(discovered)
}

/// Validate a prologue candidate by disassembling several instructions.
///
/// Returns true if at least 3 valid instructions can be decoded and
/// the sequence looks like reasonable function code.
fn validate_prologue_candidate(
    disasm: &X86Disassembler,
    bytes: &[u8],
    start_va: u64,
) -> bool {
    let mut va = start_va;
    let mut valid_insns = 0;
    let max_check = 8; // Check up to 8 instructions
    let mut saw_ret = false;

    for _ in 0..max_check {
        let offset = (va - start_va) as usize;
        if offset + 1 >= bytes.len() {
            break;
        }

        let remaining = &bytes[offset..];
        match disasm.disassemble(remaining, va) {
            Ok(op) => {
                if op.size == 0 {
                    break;
                }
                valid_insns += 1;
                if op.is_return() {
                    saw_ret = true;
                    break;
                }
                va += op.size as u64;
            }
            Err(_) => break,
        }
    }

    // Need at least 3 valid instructions
    // (very short functions like `push ebp; xor eax,eax; ret` are 3 insns)
    valid_insns >= 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = CodeFlowAnalyzer::new();
        assert!(analyzer.get_functions().is_empty());
    }

    #[test]
    fn test_validate_prologue_candidate() {
        let disasm = X86Disassembler::new(X86Mode::Mode32);
        // push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret
        let bytes = [0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x5D, 0xC3];
        assert!(validate_prologue_candidate(&disasm, &bytes, 0x401000));
    }

    #[test]
    fn test_validate_prologue_garbage() {
        let disasm = X86Disassembler::new(X86Mode::Mode32);
        // Random bytes that won't form valid instructions
        let bytes = [0x55, 0xFF, 0xFF];
        // May or may not decode — but even if it does, only 1-2 insns
        // The key is it shouldn't crash
        let _ = validate_prologue_candidate(&disasm, &bytes, 0x401000);
    }
}
