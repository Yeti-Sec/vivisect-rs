//! Analysis module orchestration.
//!
//! This module provides the infrastructure for running analysis passes
//! in order, similar to Python vivisect's analyze() method.

use crate::core::VivWorkspace;
use crate::error::VivResult;
use std::fmt::Debug;

/// Trait for analysis modules.
///
/// Analysis modules are run in order during workspace.analyze().
/// Each module can discover functions, add xrefs, annotate code, etc.
pub trait AnalysisModule: Send + Sync + Debug {
    /// Get the module name.
    fn name(&self) -> &str;

    /// Get module priority (lower = runs earlier).
    /// Default priorities:
    /// - 0-99: Parsing/loading
    /// - 100-199: Entry point discovery
    /// - 200-299: Code flow analysis
    /// - 300-399: Function analysis
    /// - 400-499: Data analysis
    /// - 500+: Post-processing
    fn priority(&self) -> u32 {
        200
    }

    /// Check if this module should run for the given workspace.
    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        let _ = workspace;
        true
    }

    /// Run the analysis module.
    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats>;
}

/// Statistics from an analysis pass.
#[derive(Debug, Clone, Default)]
pub struct AnalysisStats {
    /// Number of functions discovered.
    pub functions_discovered: usize,
    /// Number of basic blocks discovered.
    pub blocks_discovered: usize,
    /// Number of xrefs added.
    pub xrefs_added: usize,
    /// Number of locations added.
    pub locations_added: usize,
    /// Number of strings found.
    pub strings_found: usize,
    /// Custom metrics.
    pub custom: std::collections::HashMap<String, usize>,
}

impl AnalysisStats {
    /// Create new empty stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a custom metric.
    pub fn add_custom(&mut self, name: impl Into<String>, value: usize) {
        self.custom.insert(name.into(), value);
    }

    /// Merge stats from another analysis.
    pub fn merge(&mut self, other: &AnalysisStats) {
        self.functions_discovered += other.functions_discovered;
        self.blocks_discovered += other.blocks_discovered;
        self.xrefs_added += other.xrefs_added;
        self.locations_added += other.locations_added;
        self.strings_found += other.strings_found;
        for (k, v) in &other.custom {
            *self.custom.entry(k.clone()).or_insert(0) += v;
        }
    }
}

/// Result of running all analysis modules.
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// Stats from each module.
    pub module_stats: Vec<(String, AnalysisStats)>,
    /// Total combined stats.
    pub total: AnalysisStats,
    /// Modules that failed.
    pub failures: Vec<(String, String)>,
}

impl AnalysisResult {
    /// Create new empty result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add module result.
    pub fn add_module(&mut self, name: String, stats: AnalysisStats) {
        self.total.merge(&stats);
        self.module_stats.push((name, stats));
    }

    /// Add module failure.
    pub fn add_failure(&mut self, name: String, error: String) {
        self.failures.push((name, error));
    }

    /// Check if any modules failed.
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }
}

/// Analysis orchestrator that manages and runs analysis modules.
#[derive(Default)]
pub struct AnalysisOrchestrator {
    /// Registered modules (sorted by priority).
    modules: Vec<Box<dyn AnalysisModule>>,
    /// Whether modules are sorted.
    sorted: bool,
}

impl AnalysisOrchestrator {
    /// Create a new orchestrator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an analysis module.
    pub fn add_module(&mut self, module: Box<dyn AnalysisModule>) {
        self.modules.push(module);
        self.sorted = false;
    }

    /// Get the number of registered modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get module names in order.
    pub fn module_names(&mut self) -> Vec<String> {
        self.ensure_sorted();
        self.modules.iter().map(|m| m.name().to_string()).collect()
    }

    /// Ensure modules are sorted by priority.
    fn ensure_sorted(&mut self) {
        if !self.sorted {
            self.modules.sort_by_key(|m| m.priority());
            self.sorted = true;
        }
    }

    /// Run all analysis modules in order.
    pub fn analyze(&mut self, workspace: &mut VivWorkspace) -> AnalysisResult {
        self.ensure_sorted();

        let mut result = AnalysisResult::new();

        for module in &mut self.modules {
            let name = module.name().to_string();

            if !module.should_run(workspace) {
                continue;
            }

            match module.analyze(workspace) {
                Ok(stats) => {
                    result.add_module(name, stats);
                }
                Err(e) => {
                    result.add_failure(name, e.to_string());
                }
            }
        }

        result
    }
}

impl Debug for AnalysisOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisOrchestrator")
            .field("module_count", &self.modules.len())
            .finish()
    }
}

// ============================================================================
// Built-in Analysis Modules
// ============================================================================

/// Entry point analysis module.
///
/// Adds functions at known entry points (from PE/ELF headers, exports, etc.)
#[derive(Debug, Default)]
pub struct EntryPointAnalysis;

impl EntryPointAnalysis {
    /// Create new entry point analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for EntryPointAnalysis {
    fn name(&self) -> &str {
        "generic.entrypoints"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();

        // Collect entry points first to avoid borrow issues
        let entries: Vec<u64> = workspace.entry_points().to_vec();

        // Add functions at entry points
        for entry in entries {
            if !workspace.is_function(entry) {
                workspace.add_function(
                    entry,
                    crate::core::workspace::FunctionMeta {
                        name: Some(format!("entry_{:x}", entry)),
                        ..Default::default()
                    },
                )?;
                stats.functions_discovered += 1;
            }
        }

        Ok(stats)
    }
}

/// Code flow analysis module.
///
/// Discovers functions and basic blocks through recursive disassembly.
#[derive(Debug)]
pub struct CodeFlowAnalysis {
    /// Maximum instructions to analyze.
    max_instructions: usize,
}

impl CodeFlowAnalysis {
    /// Create new code flow analysis.
    pub fn new() -> Self {
        Self {
            max_instructions: 1_000_000,
        }
    }

    /// Set maximum instructions.
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }
}

impl Default for CodeFlowAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for CodeFlowAnalysis {
    fn name(&self) -> &str {
        "generic.codeflow"
    }

    fn priority(&self) -> u32 {
        200
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::codeflow::CodeFlowAnalyzer;

        let mut stats = AnalysisStats::new();
        let mut analyzer = CodeFlowAnalyzer::new().with_max_instructions(self.max_instructions);

        // Add entry points to analyzer
        for &entry in workspace.entry_points() {
            analyzer.add_entry_point(entry);
        }

        // Add known function addresses
        for func_va in workspace.get_functions() {
            analyzer.add_entry_point(func_va);
        }

        // Run analysis
        let result = analyzer.analyze(workspace)?;

        stats.functions_discovered = result.functions_discovered.len();
        stats.blocks_discovered = result.blocks_discovered.len();
        stats.add_custom("instructions_analyzed", result.instructions_analyzed);

        // Add discovered functions to workspace
        for func_va in result.functions_discovered {
            if !workspace.is_function(func_va) {
                workspace.add_function(
                    func_va,
                    crate::core::workspace::FunctionMeta {
                        name: Some(format!("sub_{:x}", func_va)),
                        ..Default::default()
                    },
                )?;
            }
        }

        Ok(stats)
    }
}

/// Basic block analysis module.
///
/// Builds basic blocks for discovered functions.
#[derive(Debug, Default)]
pub struct BasicBlockAnalysis;

impl BasicBlockAnalysis {
    /// Create new basic block analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for BasicBlockAnalysis {
    fn name(&self) -> &str {
        "generic.codeblocks"
    }

    fn priority(&self) -> u32 {
        250
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::codeflow::analyze_function;

        let mut stats = AnalysisStats::new();

        // Analyze each function
        let functions: Vec<u64> = workspace.get_functions();

        for func_va in functions {
            if let Ok(analysis) = analyze_function(workspace, func_va) {
                // Add blocks to workspace
                for block in &analysis.blocks {
                    if block.end > block.start {
                        let size = (block.end - block.start) as usize;
                        workspace.add_codeblock(block.start, size, func_va);
                        stats.blocks_discovered += 1;
                    } else {
                        log::trace!(
                            "Skipping invalid block {:#x}..{:#x} in function {:#x}: end <= start",
                            block.start, block.end, func_va
                        );
                    }
                }
            }
        }

        Ok(stats)
    }
}

/// String analysis module.
#[derive(Debug)]
pub struct StringAnalysis {
    /// Minimum string length.
    min_length: usize,
}

impl StringAnalysis {
    /// Create new string analysis.
    pub fn new() -> Self {
        Self { min_length: 4 }
    }

    /// Set minimum string length.
    pub fn with_min_length(mut self, len: usize) -> Self {
        self.min_length = len;
        self
    }
}

impl Default for StringAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for StringAnalysis {
    fn name(&self) -> &str {
        "generic.strings"
    }

    fn priority(&self) -> u32 {
        400
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        // String analysis would scan data sections for strings
        // For now, this is a placeholder
        let stats = AnalysisStats::new();
        Ok(stats)
    }
}

/// Create a default analysis orchestrator with standard modules.
pub fn create_default_orchestrator() -> AnalysisOrchestrator {
    let mut orch = AnalysisOrchestrator::new();
    orch.add_module(Box::new(EntryPointAnalysis::new()));
    orch.add_module(Box::new(CodeFlowAnalysis::new()));
    orch.add_module(Box::new(BasicBlockAnalysis::new()));
    orch.add_module(Box::new(StringAnalysis::new()));
    orch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestModule {
        name: String,
        priority: u32,
    }

    impl AnalysisModule for TestModule {
        fn name(&self) -> &str {
            &self.name
        }

        fn priority(&self) -> u32 {
            self.priority
        }

        fn analyze(&mut self, _workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
            Ok(AnalysisStats::new())
        }
    }

    #[test]
    fn test_orchestrator_ordering() {
        let mut orch = AnalysisOrchestrator::new();

        orch.add_module(Box::new(TestModule {
            name: "third".to_string(),
            priority: 300,
        }));
        orch.add_module(Box::new(TestModule {
            name: "first".to_string(),
            priority: 100,
        }));
        orch.add_module(Box::new(TestModule {
            name: "second".to_string(),
            priority: 200,
        }));

        let names = orch.module_names();
        assert_eq!(names, vec!["first", "second", "third"]);
    }
}
