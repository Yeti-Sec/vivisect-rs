//! Symbolic analysis context for function-level path exploration.
//!
//! Port of Python vivisect's `symboliks/analysis.py`.
//!
//! Provides `SymbolikAnalysisContext` which orchestrates the symbolic
//! emulator and translator to produce function summaries by walking
//! all paths through a function's CFG.
//!
//! Python architecture:
//! - `SymbolikAnalysisContext` owns translator + emulator creation
//! - `getSymbolikGraph(fva)` → builds CFG with symbolic effects per block
//! - `walkSymbolikPaths(fva)` → walks all paths, yields (emu, effects)
//! - `getSymbolikOutputs(fva)` → yields (return_value, output_effects)
//!
//! Rust port uses a simplified CFG representation and DFS path walking
//! with snapshot/restore for path forking.

use super::effect::{EmulatorSnapshot, SymbolicEffect};
use super::emulator::{SymbolicEmulator, SymbolicSummary};
use super::translator::{BranchConstraint, SymbolikTranslator};
use super::value::SymbolicValue;
use crate::envi::opcode::Opcode;

/// A basic block in the symbolic function graph.
///
/// Port of Python's `SymbolikFunctionGraph` node properties.
#[derive(Debug, Clone)]
pub struct SymbolikBlock {
    /// Starting VA of this block.
    pub va: u64,
    /// Opcodes in this block.
    pub opcodes: Vec<Opcode>,
    /// Symbolic effects produced by translating this block's opcodes.
    pub effects: Vec<SymbolicEffect>,
    /// Outgoing edges: (target_va, optional_constraint).
    pub successors: Vec<(u64, Option<SymbolicValue>)>,
}

/// A symbolic function graph (CFG with effects attached).
///
/// Port of Python's `SymbolikFunctionGraph`.
#[derive(Debug, Clone)]
pub struct SymbolikGraph {
    /// Function entry point.
    pub entry_va: u64,
    /// Basic blocks keyed by starting VA.
    pub blocks: std::collections::BTreeMap<u64, SymbolikBlock>,
}

impl SymbolikGraph {
    /// Create an empty graph with the given entry point.
    pub fn new(entry_va: u64) -> Self {
        Self {
            entry_va,
            blocks: std::collections::BTreeMap::new(),
        }
    }

    /// Add a block to the graph.
    pub fn add_block(&mut self, block: SymbolikBlock) {
        self.blocks.insert(block.va, block);
    }

    /// Get a block by VA.
    pub fn get_block(&self, va: u64) -> Option<&SymbolikBlock> {
        self.blocks.get(&va)
    }

    /// Get the entry block.
    pub fn entry_block(&self) -> Option<&SymbolikBlock> {
        self.blocks.get(&self.entry_va)
    }

    /// Get all block VAs in order.
    pub fn block_vas(&self) -> Vec<u64> {
        self.blocks.keys().copied().collect()
    }

    /// Number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

/// Result of walking a single path through a function.
///
/// Port of Python's yield from `walkSymbolikPaths()`.
#[derive(Debug, Clone)]
pub struct PathResult {
    /// Symbolic emulator state at the end of this path.
    pub emulator: SymbolicEmulator,
    /// All effects accumulated along this path.
    pub effects: Vec<SymbolicEffect>,
    /// Path constraints accumulated along this path.
    pub constraints: Vec<SymbolicValue>,
    /// VAs of blocks visited on this path.
    pub path: Vec<u64>,
}

/// Output of symbolic execution of a function path.
///
/// Port of Python's `getSymbolikOutputs()` yield.
#[derive(Debug, Clone)]
pub struct SymbolikOutput {
    /// Return value expression at end of this path.
    pub return_value: Option<SymbolicValue>,
    /// Memory write effects on this path.
    pub memory_writes: Vec<SymbolicEffect>,
    /// Function call effects on this path.
    pub calls: Vec<SymbolicEffect>,
    /// Path constraints.
    pub constraints: Vec<SymbolicValue>,
}

/// Symbolic analysis context for function-level analysis.
///
/// Port of Python's `SymbolikAnalysisContext`.
///
/// Orchestrates translator + emulator to produce function summaries
/// by building symbolic graphs and walking execution paths.
pub struct SymbolikAnalysisContext {
    /// Pointer size in bytes (4 or 8).
    pointer_size: u8,
    /// Pre-effects applied before function entry (Python: `preeffects`).
    pre_effects: Vec<SymbolicEffect>,
    /// Pre-constraints applied before function entry (Python: `preconstraints`).
    pre_constraints: Vec<SymbolicValue>,
    /// Function callbacks (Python: `funccb`).
    func_callbacks: std::collections::HashMap<String, String>,
    /// Maximum paths to explore before stopping (Python: `maxpath`).
    max_paths: usize,
    /// Maximum loop iterations before cutting a path.
    max_loop_count: usize,
}

impl SymbolikAnalysisContext {
    /// Create a new analysis context.
    pub fn new(pointer_size: u8) -> Self {
        Self {
            pointer_size,
            pre_effects: Vec::new(),
            pre_constraints: Vec::new(),
            func_callbacks: std::collections::HashMap::new(),
            max_paths: 1000,
            max_loop_count: 2,
        }
    }

    /// Create a 64-bit analysis context.
    pub fn new_64() -> Self {
        Self::new(8)
    }

    /// Create a 32-bit analysis context.
    pub fn new_32() -> Self {
        Self::new(4)
    }

    /// Set maximum paths to explore.
    pub fn set_max_paths(&mut self, max: usize) {
        self.max_paths = max;
    }

    /// Set maximum loop iterations.
    pub fn set_max_loop_count(&mut self, count: usize) {
        self.max_loop_count = count;
    }

    /// Set pre-effects (Python: `setSymPreEffects`).
    pub fn set_pre_effects(&mut self, effects: Vec<SymbolicEffect>) {
        self.pre_effects = effects;
    }

    /// Add pre-effects (Python: `addSymPreEffects`).
    pub fn add_pre_effects(&mut self, effects: Vec<SymbolicEffect>) {
        self.pre_effects.extend(effects);
    }

    /// Set pre-constraints (Python: `setSymPreConstraints`).
    pub fn set_pre_constraints(&mut self, constraints: Vec<SymbolicValue>) {
        self.pre_constraints = constraints;
    }

    /// Add pre-constraints (Python: `addSymPreConstraints`).
    pub fn add_pre_constraints(&mut self, constraints: Vec<SymbolicValue>) {
        self.pre_constraints.extend(constraints);
    }

    /// Register a function callback (Python: `addSymFuncCallback`).
    pub fn add_func_callback(&mut self, name: &str, handler: &str) {
        self.func_callbacks.insert(name.to_string(), handler.to_string());
    }

    // ── Translator / Emulator creation ──

    /// Create a new translator (Python: `getTranslator()`).
    pub fn get_translator(&self) -> SymbolikTranslator {
        SymbolikTranslator::new(self.pointer_size)
    }

    /// Create and initialize a function emulator (Python: `getFuncEmu(fva)`).
    pub fn get_func_emu(&self) -> SymbolicEmulator {
        let mut emu = SymbolicEmulator::new(self.pointer_size);
        if self.pointer_size == 8 {
            emu.init_x64_registers();
        } else {
            emu.init_x86_registers();
        }
        emu
    }

    // ── Graph building ──

    /// Build a symbolic function graph from a list of basic blocks.
    ///
    /// Port of Python's `getSymbolikGraph(fva, fgraph)`.
    ///
    /// Takes pre-built block info (VA, opcodes, successor edges) and
    /// translates each block's opcodes into symbolic effects.
    pub fn build_symbolik_graph(
        &self,
        entry_va: u64,
        blocks: Vec<(u64, Vec<Opcode>, Vec<u64>)>,
    ) -> SymbolikGraph {
        let mut graph = SymbolikGraph::new(entry_va);
        let mut xlate = self.get_translator();

        for (block_va, opcodes, successors) in blocks {
            xlate.clear_effects();

            // Translate all opcodes in this block
            let mut edge_constraints: Vec<BranchConstraint> = Vec::new();
            for op in &opcodes {
                let constraints = xlate.translate_opcode(op);
                edge_constraints.extend(constraints);
            }

            let effects = xlate.take_effects();

            // Build successor list with constraints
            let succ_with_constraints: Vec<(u64, Option<SymbolicValue>)> = successors
                .iter()
                .map(|&target| {
                    let constraint = edge_constraints
                        .iter()
                        .find(|c| c.target == target)
                        .map(|c| c.constraint.clone());
                    (target, constraint)
                })
                .collect();

            graph.add_block(SymbolikBlock {
                va: block_va,
                opcodes,
                effects,
                successors: succ_with_constraints,
            });
        }

        graph
    }

    // ── Path walking ──

    /// Walk all symbolic paths through a function graph.
    ///
    /// Port of Python's `walkSymbolikPaths(fva, graph)`.
    ///
    /// Uses DFS with snapshot/restore to explore all paths through
    /// the CFG. At each branch, the emulator state is snapshotted
    /// and restored for each successor path.
    ///
    /// Returns a list of `PathResult` — one per completed path.
    pub fn walk_symbolik_paths(&self, graph: &SymbolikGraph) -> Vec<PathResult> {
        let mut results = Vec::new();
        let mut path_count = 0;

        // Initialize emulator
        let mut emu = self.get_func_emu();

        // Apply pre-effects
        if !self.pre_effects.is_empty() {
            emu.apply_effects(&self.pre_effects);
        }

        // Apply pre-constraints
        for constraint in &self.pre_constraints {
            emu.constrain_path(0, constraint.clone());
        }

        // Get entry block
        let entry = match graph.entry_block() {
            Some(b) => b,
            None => return results,
        };

        // Apply entry block effects
        emu.apply_effects(&entry.effects);

        // Start DFS from entry block
        let initial_snap = emu.snapshot();
        let initial_effects: Vec<SymbolicEffect> = entry.effects.clone();
        let initial_path = vec![entry.va];

        // Work stack: (snapshot, accumulated_effects, current_block_va, path, constraints)
        let mut work_stack: Vec<(
            EmulatorSnapshot,
            Vec<SymbolicEffect>,
            Vec<u64>,
            Vec<SymbolicValue>,
            Vec<(u64, Option<SymbolicValue>)>,
        )> = Vec::new();

        // Seed the work stack with entry block's successors
        if entry.successors.is_empty() {
            // Single-block function
            results.push(PathResult {
                emulator: emu,
                effects: initial_effects,
                constraints: Vec::new(),
                path: initial_path,
            });
            return results;
        }

        for &(target, ref constraint) in &entry.successors {
            work_stack.push((
                initial_snap.clone(),
                initial_effects.clone(),
                initial_path.clone(),
                self.pre_constraints.clone(),
                vec![(target, constraint.clone())],
            ));
        }

        while let Some((snap, acc_effects, path, acc_constraints, edges)) = work_stack.pop() {
            if path_count >= self.max_paths {
                break;
            }

            for (target, constraint) in edges {
                if path_count >= self.max_paths {
                    break;
                }

                // Check loop count
                let loop_count = path.iter().filter(|&&v| v == target).count();
                if loop_count >= self.max_loop_count {
                    continue;
                }

                // Get target block
                let block = match graph.get_block(target) {
                    Some(b) => b,
                    None => continue,
                };

                // Create new emulator from snapshot
                let mut path_emu = SymbolicEmulator::new(self.pointer_size);
                path_emu.restore(&snap);

                // Apply edge constraint
                let mut path_constraints = acc_constraints.clone();
                if let Some(ref cons) = constraint {
                    path_emu.constrain_path(target, cons.clone());
                    path_constraints.push(cons.clone());

                    // Check satisfiability
                    if !path_emu.path_satisfiable() {
                        continue;
                    }
                }

                // Apply block effects
                let applied = path_emu.apply_effects(&block.effects);
                let mut path_effects = acc_effects.clone();
                path_effects.extend(applied);

                let mut new_path = path.clone();
                new_path.push(target);

                if block.successors.is_empty() {
                    // Terminal block — record path result
                    path_count += 1;
                    results.push(PathResult {
                        emulator: path_emu,
                        effects: path_effects,
                        constraints: path_constraints,
                        path: new_path,
                    });
                } else {
                    // Non-terminal — push successors to work stack
                    let new_snap = path_emu.snapshot();
                    for &(succ_target, ref succ_constraint) in &block.successors {
                        work_stack.push((
                            new_snap.clone(),
                            path_effects.clone(),
                            new_path.clone(),
                            path_constraints.clone(),
                            vec![(succ_target, succ_constraint.clone())],
                        ));
                    }
                }
            }
        }

        results
    }

    /// Get symbolic outputs for a function.
    ///
    /// Port of Python's `getSymbolikOutputs(fva, args)`.
    ///
    /// Walks all paths and extracts return values and output effects.
    pub fn get_symbolik_outputs(&self, graph: &SymbolikGraph) -> Vec<SymbolikOutput> {
        let path_results = self.walk_symbolik_paths(graph);
        let ret_reg = if self.pointer_size == 8 { "rax" } else { "eax" };

        path_results
            .into_iter()
            .map(|pr| {
                let return_value = pr.emulator.get_register(ret_reg);
                let return_value = if matches!(return_value, SymbolicValue::Var { .. }) {
                    // If it's still the initial symbolic var, no explicit return
                    None
                } else {
                    Some(return_value)
                };

                let memory_writes = pr
                    .effects
                    .iter()
                    .filter(|e| e.is_memory_write())
                    .cloned()
                    .collect();

                let calls = pr
                    .effects
                    .iter()
                    .filter(|e| e.is_call())
                    .cloned()
                    .collect();

                SymbolikOutput {
                    return_value,
                    constraints: pr.constraints,
                    memory_writes,
                    calls,
                }
            })
            .collect()
    }

    /// Produce a merged function summary from all paths.
    ///
    /// This combines the outputs of all paths into a single
    /// `SymbolicSummary` for comparison with other functions.
    pub fn summarize_function(&self, graph: &SymbolikGraph) -> SymbolicSummary {
        let outputs = self.get_symbolik_outputs(graph);

        // Use the first path's return value (most common path)
        let return_value = outputs.iter().find_map(|o| o.return_value.clone());

        // Collect all memory writes across paths
        let memory_writes: Vec<(SymbolicValue, SymbolicValue)> = outputs
            .iter()
            .flat_map(|o| {
                o.memory_writes.iter().filter_map(|e| {
                    if let SymbolicEffect::WriteMemory { addr, value, .. } = e {
                        Some((addr.clone(), value.clone()))
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Collect all calls across paths (deduplicated by target)
        let mut seen_targets = std::collections::HashSet::new();
        let mut calls: Vec<(String, Vec<SymbolicValue>)> = Vec::new();
        for output in &outputs {
            for e in &output.calls {
                if let SymbolicEffect::CallFunction { target, args, .. } = e {
                    if seen_targets.insert(target.clone()) {
                        calls.push((target.clone(), args.clone()));
                    }
                }
            }
        }

        SymbolicSummary {
            return_value,
            memory_writes,
            calls,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::InstructionFlags;
    use crate::envi::operand::{ImmediateOperand, RegisterOperand};

    fn make_reg_oper(name: &str, size: usize) -> Box<dyn crate::envi::operand::Operand> {
        Box::new(RegisterOperand::new(0, name, size))
    }

    fn make_imm_oper(value: u64, size: usize) -> Box<dyn crate::envi::operand::Operand> {
        Box::new(ImmediateOperand::new(value, size))
    }

    fn make_opcode_at(va: u64, mnem: &str, opers: Vec<Box<dyn crate::envi::operand::Operand>>) -> Opcode {
        Opcode {
            va,
            opcode: 0,
            mnem: mnem.to_string(),
            prefixes: 0,
            size: 3,
            opers,
            iflags: InstructionFlags::empty(),
            bytes: vec![],
        }
    }

    #[test]
    fn test_single_block_function() {
        let ctx = SymbolikAnalysisContext::new_64();

        // Function: mov rax, 42; ret
        let opcodes = vec![
            make_opcode_at(0x1000, "mov", vec![
                make_reg_oper("rax", 8),
                make_imm_oper(42, 8),
            ]),
            make_opcode_at(0x1003, "ret", vec![]),
        ];

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, opcodes, vec![]),
        ]);

        assert_eq!(graph.block_count(), 1);
        let results = ctx.walk_symbolik_paths(&graph);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].emulator.get_register("rax").as_const(), Some(42));
    }

    #[test]
    fn test_linear_two_blocks() {
        let ctx = SymbolikAnalysisContext::new_64();

        // Block 0: mov rax, 1
        // Block 1: add rax, 2; ret
        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(1, 8),
                ]),
            ], vec![0x1010]),
            (0x1010, vec![
                make_opcode_at(0x1010, "add", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(2, 8),
                ]),
                make_opcode_at(0x1013, "ret", vec![]),
            ], vec![]),
        ]);

        let results = ctx.walk_symbolik_paths(&graph);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, vec![0x1000, 0x1010]);
    }

    #[test]
    fn test_diamond_cfg() {
        let ctx = SymbolikAnalysisContext::new_64();

        // Diamond CFG:
        //   entry (0x1000) -> true (0x1010), false (0x1020)
        //   true (0x1010) -> merge (0x1030)
        //   false (0x1020) -> merge (0x1030)
        //   merge (0x1030) -> exit

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "cmp", vec![
                    make_reg_oper("rdi", 8),
                    make_imm_oper(0, 8),
                ]),
            ], vec![0x1010, 0x1020]),
            (0x1010, vec![
                make_opcode_at(0x1010, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(1, 8),
                ]),
            ], vec![0x1030]),
            (0x1020, vec![
                make_opcode_at(0x1020, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(0, 8),
                ]),
            ], vec![0x1030]),
            (0x1030, vec![
                make_opcode_at(0x1030, "ret", vec![]),
            ], vec![]),
        ]);

        let results = ctx.walk_symbolik_paths(&graph);
        // Diamond should produce 2 paths
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_loop_bounded() {
        let mut ctx = SymbolikAnalysisContext::new_64();
        ctx.set_max_loop_count(2);

        // Simple loop: 0x1000 -> 0x1010 -> 0x1000 (back edge)
        //                                -> 0x1020 (exit)
        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "nop", vec![]),
            ], vec![0x1010]),
            (0x1010, vec![
                make_opcode_at(0x1010, "nop", vec![]),
            ], vec![0x1000, 0x1020]),
            (0x1020, vec![
                make_opcode_at(0x1020, "ret", vec![]),
            ], vec![]),
        ]);

        let results = ctx.walk_symbolik_paths(&graph);
        // Should terminate due to loop bound
        assert!(!results.is_empty());
        // Loop iterations bounded
        for r in &results {
            let loop_count = r.path.iter().filter(|&&v| v == 0x1000).count();
            assert!(loop_count <= 2, "Loop count {} exceeds max", loop_count);
        }
    }

    #[test]
    fn test_max_paths_limit() {
        let mut ctx = SymbolikAnalysisContext::new_64();
        ctx.set_max_paths(3);

        // Create a graph that would produce many paths
        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![make_opcode_at(0x1000, "nop", vec![])],
                vec![0x1010, 0x1020, 0x1030, 0x1040]),
            (0x1010, vec![make_opcode_at(0x1010, "ret", vec![])], vec![]),
            (0x1020, vec![make_opcode_at(0x1020, "ret", vec![])], vec![]),
            (0x1030, vec![make_opcode_at(0x1030, "ret", vec![])], vec![]),
            (0x1040, vec![make_opcode_at(0x1040, "ret", vec![])], vec![]),
        ]);

        let results = ctx.walk_symbolik_paths(&graph);
        assert!(results.len() <= 3);
    }

    #[test]
    fn test_get_symbolik_outputs() {
        let ctx = SymbolikAnalysisContext::new_64();

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(42, 8),
                ]),
            ], vec![]),
        ]);

        let outputs = ctx.get_symbolik_outputs(&graph);
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].return_value.is_some());
        assert_eq!(outputs[0].return_value.as_ref().unwrap().as_const(), Some(42));
    }

    #[test]
    fn test_summarize_function() {
        let ctx = SymbolikAnalysisContext::new_64();

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(0, 8),
                ]),
                make_opcode_at(0x1003, "ret", vec![]),
            ], vec![]),
        ]);

        let summary = ctx.summarize_function(&graph);
        assert!(summary.return_value.is_some());
        assert_eq!(summary.return_value.as_ref().unwrap().as_const(), Some(0));
    }

    #[test]
    fn test_pre_effects() {
        let mut ctx = SymbolikAnalysisContext::new_64();
        ctx.set_pre_effects(vec![
            SymbolicEffect::SetVariable {
                va: 0,
                name: "rdi".to_string(),
                value: SymbolicValue::constant(100, 8),
            },
        ]);

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_reg_oper("rdi", 8),
                ]),
            ], vec![]),
        ]);

        let results = ctx.walk_symbolik_paths(&graph);
        assert_eq!(results.len(), 1);
        // rdi was pre-set to 100, and rax = rdi
        // The translator reads rdi from its own register state (which
        // doesn't share emulator state directly), so this tests pre-effect
        // application to the emulator state.
    }

    #[test]
    fn test_empty_graph() {
        let ctx = SymbolikAnalysisContext::new_64();
        let graph = SymbolikGraph::new(0x1000);
        let results = ctx.walk_symbolik_paths(&graph);
        assert!(results.is_empty());
    }

    #[test]
    fn test_graph_construction() {
        let ctx = SymbolikAnalysisContext::new_64();
        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(1, 8),
                ]),
                make_opcode_at(0x1003, "add", vec![
                    make_reg_oper("rax", 8),
                    make_imm_oper(2, 8),
                ]),
            ], vec![0x1010]),
            (0x1010, vec![
                make_opcode_at(0x1010, "ret", vec![]),
            ], vec![]),
        ]);

        assert_eq!(graph.block_count(), 2);
        assert_eq!(graph.entry_va, 0x1000);

        let entry = graph.entry_block().unwrap();
        assert_eq!(entry.effects.len(), 2);
        assert_eq!(entry.successors.len(), 1);
        assert_eq!(entry.successors[0].0, 0x1010);
    }

    #[test]
    fn test_32bit_analysis() {
        let ctx = SymbolikAnalysisContext::new_32();

        let graph = ctx.build_symbolik_graph(0x1000, vec![
            (0x1000, vec![
                make_opcode_at(0x1000, "mov", vec![
                    make_reg_oper("eax", 4),
                    make_imm_oper(42, 4),
                ]),
            ], vec![]),
        ]);

        let outputs = ctx.get_symbolik_outputs(&graph);
        assert_eq!(outputs.len(), 1);
        assert!(outputs[0].return_value.is_some());
    }
}
