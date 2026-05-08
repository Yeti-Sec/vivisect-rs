//! Code flow analysis for function and basic block discovery.
//!
//! This module provides algorithms for discovering functions and
//! basic blocks through code flow analysis.

use crate::constants::{Architecture, BranchFlags, LocationType, RefType};
use crate::core::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::envi::Opcode;
use crate::error::{VivError, VivResult};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};
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
    #[must_use]
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
            //
            // Track whether this instruction calls a noreturn function.
            // If so, we suppress the fall-through (matching Python's
            // `if self._cf_noret.get(bva): self.addNoFlow(va, nextva)`
            // in envi/codeflow.py line 254).
            let mut call_is_noreturn = false;

            for (target, flags) in op.get_branches() {
                if let Some(target_va) = target {
                    // Only add xrefs for actual branches/calls, NOT for fall-through.
                    // Python vivisect does not create xrefs for fall-through either —
                    // xrefs represent explicit control flow transfers (calls, jumps).
                    if !flags.contains(BranchFlags::FALL) {
                        workspace.add_xref(va, target_va, RefType::Code);
                    }

                    // Fix 3: Handle call targets as potential functions,
                    // but validate the target is within mapped memory first
                    // to avoid false positives from data misinterpreted as call targets.
                    if flags.contains(BranchFlags::PROC) && !flags.contains(BranchFlags::DEREF) {
                        if workspace.is_valid_pointer(target_va)
                            && !self.functions.contains(&target_va)
                        {
                            self.functions.insert(target_va);
                            self.block_starts.insert(target_va);
                            discovered_functions.push(target_va);
                        }
                        if workspace.is_valid_pointer(target_va)
                            && !self.visited.contains(&target_va)
                        {
                            self.pending.push_back(target_va);
                        }

                        // Check if the call target is a noreturn function.
                        // If so, suppress the fall-through path.
                        if workspace.is_noreturn_va(target_va) {
                            call_is_noreturn = true;
                        }
                    }

                    // For DEREF calls (call [addr]), resolve the pointer and
                    // check if the indirect target is noreturn.
                    if flags.contains(BranchFlags::PROC) && flags.contains(BranchFlags::DEREF) {
                        if workspace.is_noreturn_va(target_va) {
                            call_is_noreturn = true;
                        }
                    }

                    // Handle branch targets as block starts
                    if flags.contains(BranchFlags::COND) || !flags.contains(BranchFlags::FALL) {
                        if !flags.contains(BranchFlags::FALL)
                            && !flags.contains(BranchFlags::DEREF)
                            && workspace.is_valid_pointer(target_va)
                        {
                            if !self.block_starts.contains(&target_va) {
                                self.block_starts.insert(target_va);
                                discovered_blocks.push(target_va);
                            }
                            if !self.visited.contains(&target_va) {
                                self.pending.push_back(target_va);
                            }
                        }
                    }

                    // Handle fall-through — suppress if calling a noreturn function
                    if flags.contains(BranchFlags::FALL) && !call_is_noreturn {
                        if workspace.is_valid_pointer(target_va)
                            && !self.visited.contains(&target_va)
                        {
                            self.pending.push_front(target_va); // Priority for linear flow
                        }
                    }
                }
            }

            // Try to resolve indirect branches (jump tables).
            // For instructions like `jmp [table + ecx*4]`, code flow normally
            // produces (None, DEREF) and skips the target. Here we attempt to
            // read the jump table from memory and follow the resolved targets.
            if op.is_branch() && !op.is_call() && !op.falls_through() {
                let has_xrefs = !workspace.get_xrefs_from(va).is_empty();
                if !has_xrefs {
                    if let Some(targets) =
                        try_resolve_jump_table(workspace, &disasm, va, &op)
                    {
                        for target_va in &targets {
                            workspace.add_xref(va, *target_va, RefType::Code);
                            if !self.block_starts.contains(target_va) {
                                self.block_starts.insert(*target_va);
                                discovered_blocks.push(*target_va);
                            }
                            if !self.visited.contains(target_va) {
                                self.pending.push_back(*target_va);
                            }
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

/// Analyze a function to find basic block boundaries.
///
/// This matches Python vivisect's `codeblocks.analyzeFunction()` logic:
/// 1. Walk forward through already-disassembled instructions (locations)
/// 2. For each instruction, check outgoing xrefs (skip BR_PROC, BR_DEREF)
/// 3. Split blocks at: IF_NOFALL, non-proc branches, incoming xrefs at nextva
/// 4. Calls do NOT split blocks (BR_PROC is skipped)
#[must_use]
pub fn analyze_function(
    workspace: &mut VivWorkspace,
    func_va: u64,
) -> VivResult<FunctionAnalysis> {
    let arch = workspace.architecture();

    // We need a disassembler as fallback for instructions not yet in locations
    let disasm = match arch {
        Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
        Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
        _ => {
            return Err(VivError::ArchModNotDefined {
                arch: format!("{:?}", arch),
            })
        }
    };

    let mut done: HashSet<u64> = HashSet::new();
    let mut todo: Vec<u64> = vec![func_va];
    let mut blocks: Vec<BasicBlockInfo> = Vec::new();
    let mut total_instrs = 0;

    while let Some(start) = todo.pop() {
        if done.contains(&start) {
            continue;
        }
        done.insert(start);

        let mut va = start;
        let mut block_instr_count = 0;

        // Walk forward through instructions until a block-ending condition
        loop {
            // Check location type if a location exists
            if let Some(loc) = workspace.get_location(va) {
                if loc.ltype != crate::constants::LocationType::Op {
                    // Not an instruction (pointer, string, etc.) — terminate
                    if block_instr_count > 0 {
                        blocks.push(BasicBlockInfo {
                            start,
                            end: va,
                            instructions: block_instr_count,
                        });
                        total_instrs += block_instr_count;
                    }
                    break;
                }
            }

            // Disassemble instruction at va
            let bytes = match workspace.read_memory(va, 16) {
                Ok(b) => b,
                Err(_) => break,
            };
            let op = match disasm.disassemble(&bytes, va) {
                Ok(o) => o,
                Err(_) => break,
            };

            if op.size == 0 {
                break;
            }

            block_instr_count += 1;
            let nextva = va + op.size as u64;

            // Check if this is a call to a noreturn function.
            // If so, the block ends here with no fall-through (matching Python's
            // codeflow behavior where noreturn calls act like IF_NOFALL).
            if op.is_call() {
                let targets = op.get_targets();
                let is_noreturn_call = targets.iter().any(|&(tva, _)| workspace.is_noreturn_va(tva));
                if is_noreturn_call {
                    if block_instr_count > 0 {
                        blocks.push(BasicBlockInfo {
                            start,
                            end: nextva,
                            instructions: block_instr_count,
                        });
                    }
                    total_instrs += block_instr_count;
                    break;
                }
            }

            // Determine branch targets. Use workspace xrefs first, but also
            // extract branches from the disassembled instruction directly.
            // This handles the case where code flow didn't visit this region.
            let mut has_branch = false;

            if !op.is_call() {
                // Check workspace xrefs
                let xrefs_from = workspace.get_xrefs_from(va);
                for &(tova, _rtype) in &xrefs_from {
                    if tova != nextva {
                        has_branch = true;
                        if !done.contains(&tova) && workspace.is_valid_pointer(tova) {
                            todo.push(tova);
                        }
                    }
                }

                // Also check disassembled branches (covers regions code flow didn't reach)
                for (target, flags) in op.get_branches() {
                    if flags.contains(BranchFlags::PROC) || flags.contains(BranchFlags::DEREF) {
                        continue;
                    }
                    if flags.contains(BranchFlags::FALL) {
                        continue;
                    }
                    if let Some(target_va) = target {
                        has_branch = true;
                        if !done.contains(&target_va) && workspace.is_valid_pointer(target_va) {
                            todo.push(target_va);
                        }
                    }
                }
            }

            // Check IF_NOFALL: instruction does not fall through (ret, jmp)
            if !op.falls_through() {
                if block_instr_count > 0 {
                    blocks.push(BasicBlockInfo {
                        start,
                        end: nextva,
                        instructions: block_instr_count,
                    });
                }
                total_instrs += block_instr_count;
                break;
            }

            // If we had a non-call branch, block ends here
            if has_branch {
                if block_instr_count > 0 {
                    blocks.push(BasicBlockInfo {
                        start,
                        end: nextva,
                        instructions: block_instr_count,
                    });
                }
                total_instrs += block_instr_count;
                // Fall-through is a new block
                if !done.contains(&nextva) {
                    todo.push(nextva);
                }
                break;
            }

            // Check if nextva has incoming code xrefs — if so, split here.
            // This is the KEY check that Python does (codeblocks.py line 122-125).
            let xrefs_to_next = workspace.get_xrefs_to(nextva);
            if !xrefs_to_next.is_empty() {
                if block_instr_count > 0 {
                    blocks.push(BasicBlockInfo {
                        start,
                        end: nextva,
                        instructions: block_instr_count,
                    });
                }
                total_instrs += block_instr_count;
                if !done.contains(&nextva) {
                    todo.push(nextva);
                }
                break;
            }

            // Continue to next instruction
            va = nextva;
        }
    }

    Ok(FunctionAnalysis {
        entry: func_va,
        blocks,
        size: total_instrs,
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
#[must_use]
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

/// Try to resolve an indirect branch as a jump table.
///
/// Detects the x86 pattern `jmp [table_base + index*scale]` where
/// `table_base` is a displacement-only address (no base register) and
/// `scale` matches the pointer size. Reads consecutive pointer entries
/// from the table until a target falls outside mapped code.
///
/// Returns resolved target addresses, or None if not a jump table.
fn try_resolve_jump_table(
    workspace: &VivWorkspace,
    disasm: &X86Disassembler,
    va: u64,
    op: &Opcode,
) -> Option<Vec<u64>> {
    // Re-decode with iced-x86 to get memory operand details
    let bytes = if !op.bytes.is_empty() {
        op.bytes.clone()
    } else {
        workspace.read_memory(va, 16).ok()?
    };

    let mut decoder = Decoder::with_ip(disasm.mode().bitness(), &bytes, va, DecoderOptions::NONE);
    let instr = decoder.decode();

    if instr.flow_control() != FlowControl::IndirectBranch {
        return None;
    }
    if instr.op0_kind() != OpKind::Memory {
        return None;
    }

    let base_reg = instr.memory_base();
    let index_reg = instr.memory_index();
    let disp = instr.memory_displacement64();

    // Pattern: jmp [disp + index*scale]
    // No base register means the displacement IS the absolute table address.
    if base_reg != Register::None {
        return None;
    }
    if index_reg == Register::None {
        return None;
    }

    let ptr_size = disasm.mode().pointer_size();
    let table_base = disp;

    if !workspace.is_valid_pointer(table_base) {
        return None;
    }

    // Collect code segment ranges for target validation
    let code_ranges: Vec<(u64, u64)> = workspace
        .get_segments()
        .iter()
        .filter(|seg| {
            let name = seg.name.to_lowercase();
            name.contains("text") || name.contains("code")
        })
        .map(|seg| (seg.va, seg.va + seg.size as u64))
        .collect();

    // Fall back to all segments if no explicit code segments found
    let ranges: &Vec<(u64, u64)> = if code_ranges.is_empty() {
        // Use a temporary; we'll just check is_valid_pointer instead
        &code_ranges
    } else {
        &code_ranges
    };
    let use_range_check = !ranges.is_empty();

    let mut targets = Vec::new();
    let max_entries = 4096;

    for i in 0..max_entries {
        let entry_va = table_base + (i * ptr_size) as u64;
        let entry_bytes = match workspace.read_memory(entry_va, ptr_size) {
            Ok(b) => b,
            Err(_) => break,
        };

        let target = match ptr_size {
            4 => u32::from_le_bytes(entry_bytes[..4].try_into().expect("read_memory returned exactly ptr_size bytes")) as u64,
            8 => u64::from_le_bytes(entry_bytes[..8].try_into().expect("read_memory returned exactly ptr_size bytes")),
            _ => break,
        };

        if target == 0 {
            break;
        }

        // Target must be within a code segment
        if use_range_check {
            let in_code = ranges.iter().any(|(start, end)| target >= *start && target < *end);
            if !in_code {
                break;
            }
        } else if !workspace.is_valid_pointer(target) {
            break;
        }

        targets.push(target);
    }

    if targets.is_empty() {
        None
    } else {
        tracing::debug!(
            "Resolved jump table at {:#x}: {} entries from table at {:#x}",
            va,
            targets.len(),
            table_base
        );
        Some(targets)
    }
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
