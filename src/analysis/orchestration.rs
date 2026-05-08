//! Analysis module orchestration.
//!
//! This module provides the infrastructure for running analysis passes,
//! matching Python vivisect's two-tier analysis architecture:
//!
//! - **Workspace modules** (`AnalysisModule`): Run once in registration order
//!   by `analyze()`. These discover functions, resolve imports, etc.
//!
//! - **Function modules** (`FuncAnalysisModule`): Run per-function whenever
//!   new functions are created. These build code blocks, detect thunks,
//!   analyze calling conventions, etc.
//!
//! The orchestrator runs workspace modules sequentially. After each workspace
//! module, it drains any newly-created functions and runs all function modules
//! on each, matching Python's `makeFunction()` → `analyzeFunction()` cascade.

use crate::core::VivWorkspace;
use crate::error::VivResult;
use std::fmt::Debug;
use std::time::{Duration, Instant};

/// Configurable limits for analysis to prevent runaway processing.
#[derive(Debug, Clone)]
pub struct AnalysisLimits {
    /// Maximum wall-clock time for the entire analysis pass.
    pub timeout: Duration,
    /// Maximum number of functions to process before aborting.
    pub max_functions: usize,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_functions: 500_000,
        }
    }
}

/// Trait for workspace-level analysis modules.
///
/// These are registered via `add_module()` and run once in registration
/// order during `analyze()`. Registration order matters — modules depend
/// on side effects from predecessors. Do NOT sort by priority.
///
/// Corresponds to Python vivisect's `amodlist`.
pub trait AnalysisModule: Send + Sync + Debug {
    /// Get the module name.
    fn name(&self) -> &str;

    /// Advisory priority (for documentation only — execution uses registration order).
    ///
    /// Ranges:
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

/// Trait for per-function analysis modules.
///
/// These are registered via `add_func_module()` and run on each function
/// as it is created. After each workspace module completes, the orchestrator
/// drains newly-created functions and runs all func modules on each one.
/// If func modules create additional functions, those are also processed
/// until no new functions remain.
///
/// Corresponds to Python vivisect's `fmodlist`.
pub trait FuncAnalysisModule: Send + Sync + Debug {
    /// Get the module name.
    fn name(&self) -> &str;

    /// Check if this module should run for the given function.
    fn should_run(&self, workspace: &VivWorkspace, func_va: u64) -> bool {
        let _ = (workspace, func_va);
        true
    }

    /// Analyze a single function.
    fn analyze_function(
        &mut self,
        workspace: &mut VivWorkspace,
        func_va: u64,
    ) -> VivResult<AnalysisStats>;
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
///
/// Modules execute in **registration order** (insertion order), NOT by
/// priority. This matches Python vivisect's `amodlist` behavior where
/// ordering is implicit in the `addAnalysisModule()` call sequence.
///
/// After each workspace module runs, the orchestrator drains pending
/// functions and runs all function modules on each new function,
/// matching Python's `makeFunction()` → `analyzeFunction()` cascade.
pub struct AnalysisOrchestrator {
    /// Workspace-level modules (run once, in registration order).
    modules: Vec<Box<dyn AnalysisModule>>,
    /// Per-function modules (run on each new function, in registration order).
    func_modules: Vec<Box<dyn FuncAnalysisModule>>,
    /// Resource limits for the analysis pass.
    limits: AnalysisLimits,
}

impl AnalysisOrchestrator {
    /// Create a new orchestrator with default limits.
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            func_modules: Vec::new(),
            limits: AnalysisLimits::default(),
        }
    }

    /// Set resource limits for analysis.
    pub fn set_limits(&mut self, limits: AnalysisLimits) {
        self.limits = limits;
    }

    /// Add a workspace-level analysis module.
    ///
    /// Modules run in registration order — the order you call `add_module()`
    /// determines execution order. This is intentional and matches Python
    /// vivisect's behavior.
    pub fn add_module(&mut self, module: Box<dyn AnalysisModule>) {
        self.modules.push(module);
    }

    /// Add a per-function analysis module.
    ///
    /// Function modules run on each newly-created function after each
    /// workspace module completes. They also run in registration order.
    pub fn add_func_module(&mut self, module: Box<dyn FuncAnalysisModule>) {
        self.func_modules.push(module);
    }

    /// Get the number of registered workspace modules.
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the number of registered function modules.
    pub fn func_module_count(&self) -> usize {
        self.func_modules.len()
    }

    /// Get workspace module names in registration order.
    pub fn module_names(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.name().to_string()).collect()
    }

    /// Get function module names in registration order.
    pub fn func_module_names(&self) -> Vec<String> {
        self.func_modules
            .iter()
            .map(|m| m.name().to_string())
            .collect()
    }

    /// Run all registered per-function modules on a list of new functions.
    ///
    /// Drains pending functions in a loop: if func modules create additional
    /// functions, those are also processed until convergence.
    fn run_func_modules(
        func_modules: &mut [Box<dyn FuncAnalysisModule>],
        workspace: &mut VivWorkspace,
        result: &mut AnalysisResult,
        limits: &AnalysisLimits,
        start: Instant,
        total_funcs: &mut usize,
    ) {
        loop {
            let pending = workspace.drain_pending_functions();
            if pending.is_empty() {
                break;
            }

            for func_va in pending {
                *total_funcs += 1;
                if *total_funcs > limits.max_functions {
                    tracing::warn!(
                        "[orchestrator] function cap reached ({} functions), aborting func cascade",
                        limits.max_functions
                    );
                    return;
                }
                if start.elapsed() > limits.timeout {
                    tracing::warn!(
                        "[orchestrator] analysis timeout ({:?}) reached during func cascade",
                        limits.timeout
                    );
                    return;
                }

                for fmod in func_modules.iter_mut() {
                    let fname = fmod.name().to_string();

                    if !fmod.should_run(workspace, func_va) {
                        continue;
                    }

                    match fmod.analyze_function(workspace, func_va) {
                        Ok(stats) => {
                            result.add_module(
                                format!("{}@{:#x}", fname, func_va),
                                stats,
                            );
                        }
                        Err(e) => {
                            result.add_failure(
                                format!("{}@{:#x}", fname, func_va),
                                e.to_string(),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Run all analysis modules in registration order.
    ///
    /// For each workspace module:
    /// 1. Run the module (which may create functions via `add_function()`)
    /// 2. Drain newly-created functions
    /// 3. Run all func modules on each new function (cascade)
    /// 4. Repeat drain until no new functions remain
    pub fn analyze(&mut self, workspace: &mut VivWorkspace) -> AnalysisResult {
        let start = Instant::now();
        let mut total_funcs: usize = 0;

        // Clear any pre-existing pending functions so the cascade
        // starts clean (e.g., functions added during file loading).
        let preloaded = workspace.drain_pending_functions();
        if !preloaded.is_empty() {
            tracing::debug!(
                "[orchestrator] {} functions existed before analysis",
                preloaded.len()
            );
        }

        let mut result = AnalysisResult::new();

        for i in 0..self.modules.len() {
            if start.elapsed() > self.limits.timeout {
                tracing::warn!(
                    "[orchestrator] analysis timeout ({:?}) reached after module {}/{}",
                    self.limits.timeout,
                    i,
                    self.modules.len()
                );
                break;
            }

            let name = self.modules[i].name().to_string();

            if !self.modules[i].should_run(workspace) {
                tracing::trace!("[orchestrator] skipping module: {}", name);
                continue;
            }

            tracing::debug!("[orchestrator] running workspace module: {}", name);

            match self.modules[i].analyze(workspace) {
                Ok(stats) => {
                    tracing::debug!(
                        "[orchestrator] {} complete: {} functions, {} blocks",
                        name,
                        stats.functions_discovered,
                        stats.blocks_discovered
                    );
                    result.add_module(name, stats);
                }
                Err(e) => {
                    tracing::warn!("[orchestrator] {} failed: {}", name, e);
                    result.add_failure(name, e.to_string());
                }
            }

            // Cascade: run func modules on any newly-created functions
            if !self.func_modules.is_empty() {
                Self::run_func_modules(
                    &mut self.func_modules,
                    workspace,
                    &mut result,
                    &self.limits,
                    start,
                    &mut total_funcs,
                );

                if total_funcs > self.limits.max_functions {
                    tracing::warn!(
                        "[orchestrator] function cap ({}) exceeded, stopping analysis",
                        self.limits.max_functions
                    );
                    break;
                }
            }
        }

        tracing::info!(
            "[orchestrator] analysis complete in {:?}: {} functions processed, {} modules run, {} failures",
            start.elapsed(),
            total_funcs,
            result.module_stats.len(),
            result.failures.len()
        );

        result
    }
}

impl Debug for AnalysisOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisOrchestrator")
            .field("module_count", &self.modules.len())
            .field("func_module_count", &self.func_modules.len())
            .field("limits", &self.limits)
            .finish()
    }
}

impl Default for AnalysisOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Built-in Workspace Analysis Modules
// ============================================================================

/// Import-Export linker module (workspace-level).
///
/// Connects imported symbols to exported symbols in multi-file workspaces.
/// Runs first in the pipeline to resolve cross-file references before
/// function discovery begins.
///
/// Port of Python's `vivisect/analysis/generic/linker.py`.
#[derive(Debug, Default)]
pub struct LinkerAnalysis;

impl LinkerAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for LinkerAnalysis {
    fn name(&self) -> &str {
        "generic.linker"
    }

    fn priority(&self) -> u32 {
        50
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::linker::analyze_linker;

        let mut stats = AnalysisStats::new();
        match analyze_linker(workspace) {
            Ok(lstats) => {
                stats.add_custom("imports_resolved", lstats.resolved);
            }
            Err(e) => {
                tracing::warn!("[linker] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

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
        use crate::analysis::noret::init_noreturn_apis;

        let mut stats = AnalysisStats::new();

        // Initialize noreturn API set from imports BEFORE code flow runs.
        // Python does this during import loading (base.py line 218), so by the
        // time codeflow.py runs, it already knows which imports are noreturn.
        // This allows the code flow analyzer to suppress fall-through after
        // calls to noreturn functions (e.g., ExitProcess, abort).
        init_noreturn_apis(workspace);

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

/// Function prologue scanning module.
///
/// Discovers functions by scanning for known prologue byte patterns
/// (e.g. `push ebp; mov ebp, esp` for x86). This catches functions
/// that were missed by call-following analysis — for example, functions
/// only reached via indirect calls or function pointers.
#[derive(Debug, Default)]
pub struct PrologueScanAnalysis;

impl PrologueScanAnalysis {
    /// Create new prologue scan analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for PrologueScanAnalysis {
    fn name(&self) -> &str {
        "generic.prologuescan"
    }

    fn priority(&self) -> u32 {
        210
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        // Skip for Go binaries — prologue pattern matching produces false
        // positives in Go runtime code; pclntab is the authoritative source
        workspace.get_meta("go_pclntab_parsed").is_none()
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::codeflow::scan_function_prologues;

        let mut stats = AnalysisStats::new();

        let discovered = scan_function_prologues(workspace)?;
        stats.functions_discovered = discovered.len();

        // Run code flow analysis on newly discovered functions
        if !discovered.is_empty() {
            use crate::analysis::codeflow::CodeFlowAnalyzer;

            let mut analyzer = CodeFlowAnalyzer::new().with_max_instructions(500_000);
            for &func_va in &discovered {
                analyzer.add_entry_point(func_va);
            }

            if let Ok(result) = analyzer.analyze(workspace) {
                // Add any new functions discovered by following calls from prologue-found functions
                for func_va in result.functions_discovered {
                    if !workspace.is_function(func_va) {
                        workspace.add_function(
                            func_va,
                            crate::core::workspace::FunctionMeta {
                                name: Some(format!("sub_{:x}", func_va)),
                                ..Default::default()
                            },
                        )?;
                        stats.functions_discovered += 1;
                    }
                }

                stats.blocks_discovered += result.blocks_discovered.len();
                stats.add_custom("prologue_instructions", result.instructions_analyzed);
            }
        }

        Ok(stats)
    }
}

/// Emulated code discovery module.
///
/// Discovers zero-coverage functions by scanning memory for pointers to
/// executable code and validating candidates via trial disassembly. This
/// is a simplified port of Python's `emucode` analysis module.
///
/// Must run AFTER code flow and prologue scan so that pointer xrefs and
/// initial function discovery are complete.
#[derive(Debug, Default)]
pub struct EmuCodeAnalysis;

impl EmuCodeAnalysis {
    /// Create new emucode analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for EmuCodeAnalysis {
    fn name(&self) -> &str {
        "generic.emucode"
    }

    fn priority(&self) -> u32 {
        300
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::emucode::discover_emucode_functions;

        let mut stats = AnalysisStats::new();

        match discover_emucode_functions(workspace) {
            Ok(discovered) => {
                stats.functions_discovered = discovered.len();
                stats.add_custom("emucode_functions", discovered.len());
            }
            Err(e) => {
                tracing::warn!("[emucode] discovery failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// Thunk scan analysis module (workspace-level).
///
/// Scans all functions for non-import thunks: single-block functions that
/// unconditionally branch/call to another known function. These are typically
/// trampolines or wrapper stubs.
///
/// Must run AFTER code blocks are built (so single-block check works) and
/// AFTER emucode (so all functions are discovered).
#[derive(Debug, Default)]
pub struct ThunkScanAnalysis;

impl ThunkScanAnalysis {
    /// Create new thunk scan analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for ThunkScanAnalysis {
    fn name(&self) -> &str {
        "generic.thunks"
    }

    fn priority(&self) -> u32 {
        310
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::thunks::scan_thunks;

        let mut stats = AnalysisStats::new();

        match scan_thunks(workspace) {
            Ok(thunks) => {
                stats.add_custom("thunks_found", thunks.len());
                tracing::debug!("[thunks] identified {} non-import thunks", thunks.len());
            }
            Err(e) => {
                tracing::warn!("[thunks] scan failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// No-return function detection module (workspace-level).
///
/// Identifies functions that never return by checking if all leaf blocks
/// (terminal CFG nodes) end in a known no-return call or lack a return
/// instruction. Uses a fixed-point loop for cascading detection.
///
/// Must run AFTER thunks (to skip import thunks) and AFTER code blocks
/// are built (to find leaf blocks).
#[derive(Debug, Default)]
pub struct NoReturnAnalysis;

impl NoReturnAnalysis {
    /// Create new no-return analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for NoReturnAnalysis {
    fn name(&self) -> &str {
        "generic.noret"
    }

    fn priority(&self) -> u32 {
        320
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::noret::analyze_noreturn;

        let mut stats = AnalysisStats::new();

        match analyze_noreturn(workspace) {
            Ok(marked) => {
                stats.add_custom("noreturn_functions", marked.len());
                tracing::debug!("[noret] marked {} functions as no-return", marked.len());
            }
            Err(e) => {
                tracing::warn!("[noret] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// String analysis module (workspace-level, runs late).
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
        500
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::strings::{
            detect_ascii_string, detect_utf16le_string, StringEncoding,
        };
        use crate::constants::LocationType;

        let mut stats = AnalysisStats::new();
        let min_len = self.min_length;

        // Collect data segments (non-code sections like .rdata, .data, .rodata)
        let segments: Vec<(u64, usize)> = workspace
            .get_segments()
            .iter()
            .filter(|seg| {
                let name_lower = seg.name.to_lowercase();
                !name_lower.contains("text")
                    && !name_lower.contains("code")
                    && seg.size > 0
            })
            .map(|seg| (seg.va, seg.size))
            .collect();

        let mut string_count = 0usize;

        for (seg_va, seg_size) in segments {
            let data = match workspace.read_memory(seg_va, seg_size) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let mut offset = 0usize;
            while offset < data.len() {
                let va = seg_va + offset as u64;

                // Skip if location already exists
                if workspace.get_location(va).is_some() {
                    offset += 1;
                    continue;
                }

                // Try UTF-16 LE first (check for ASCII char + null byte pattern)
                if offset + 3 < data.len()
                    && (0x20..=0x7E).contains(&data[offset])
                    && data[offset + 1] == 0
                    && (0x20..=0x7E).contains(&data[offset + 2])
                    && data[offset + 3] == 0
                {
                    if let Some(s) = detect_utf16le_string(&data, offset, min_len) {
                        workspace.add_location(
                            va,
                            s.size,
                            LocationType::Unicode,
                            Some(s.content.clone()),
                        );
                        workspace.set_name(va, &s.content);
                        string_count += 1;
                        offset += s.size;
                        continue;
                    }
                }

                // Try ASCII
                if let Some(s) = detect_ascii_string(&data, offset, min_len) {
                    workspace.add_location(
                        va,
                        s.size,
                        LocationType::String,
                        Some(s.content.clone()),
                    );
                    string_count += 1;
                    offset += s.size;
                    continue;
                }

                offset += 1;
            }
        }

        stats.add_custom("strings_found", string_count);
        tracing::debug!("[strings] found {} strings in data sections", string_count);
        Ok(stats)
    }
}

/// Late-stage pointer chain analysis module (workspace-level).
///
/// Processes ALL free-hanging pointers (not just tables):
/// 1. Follows existing LOC_POINTER targets to create strings/functions
/// 2. Finds remaining free-hanging pointers and follows them
/// 3. Names pointers based on target names (`ptr_<target>`)
///
/// Port of Python's `vivisect/analysis/generic/pointers.py`.
#[derive(Debug, Default)]
pub struct PointerAnalysis;

impl PointerAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for PointerAnalysis {
    fn name(&self) -> &str {
        "generic.pointers"
    }

    fn priority(&self) -> u32 {
        450
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::pointers::analyze_pointers;

        let mut stats = AnalysisStats::new();

        match analyze_pointers(workspace) {
            Ok(pstats) => {
                stats.functions_discovered = pstats.followed;
                stats.add_custom("pointers_created", pstats.pointers_created);
                stats.add_custom("pointers_followed", pstats.followed);
                stats.add_custom("pointers_named", pstats.pointers_named);
            }
            Err(e) => {
                tracing::warn!("[pointers] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// Pointer table analysis module (workspace-level).
///
/// Scans all memory for pointer-aligned values that form consecutive tables.
/// For pointers targeting code sections, creates functions at the target.
/// This discovers vtables, callback arrays, and similar structures.
///
/// Port of Python's `vivisect/analysis/generic/pointertables.py`.
#[derive(Debug, Default)]
pub struct PointerTableAnalysis;

impl PointerTableAnalysis {
    /// Create new pointer table analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for PointerTableAnalysis {
    fn name(&self) -> &str {
        "generic.pointertables"
    }

    fn priority(&self) -> u32 {
        350
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::pointertables::analyze_pointertables;

        let mut stats = AnalysisStats::new();

        match analyze_pointertables(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("pointertable_functions", funcs.len());
                tracing::debug!(
                    "[pointertables] discovered {} functions from pointer tables",
                    funcs.len()
                );
            }
            Err(e) => {
                tracing::warn!("[pointertables] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// Late-stage function entry discovery module (workspace-level).
///
/// Scans executable memory for undefined bytes and checks for function
/// prologue signatures. This is a "desperate" pass that runs late to
/// catch functions missed by call-following, prologue scanning, pointer
/// tables, and emucode.
///
/// Port of Python's `vivisect/analysis/generic/funcentries.py`.
#[derive(Debug, Default)]
pub struct FuncEntriesAnalysis;

impl FuncEntriesAnalysis {
    /// Create new function entries analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for FuncEntriesAnalysis {
    fn name(&self) -> &str {
        "generic.funcentries"
    }

    fn priority(&self) -> u32 {
        360
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        // Skip for Go binaries — code gap scanning produces false positives
        // in Go runtime code; pclntab is the authoritative source
        workspace.get_meta("go_pclntab_parsed").is_none()
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::funcentries::discover_function_entries;

        let mut stats = AnalysisStats::new();

        match discover_function_entries(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("funcentries_discovered", funcs.len());
                tracing::debug!(
                    "[funcentries] discovered {} functions from code gaps",
                    funcs.len()
                );
            }
            Err(e) => {
                tracing::warn!("[funcentries] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// Import call discovery module (workspace-level, i386 only).
///
/// Scans undefined memory for `call [dword ptr imm32]` instructions
/// targeting LOC_IMPORT locations. Runs code flow analysis from
/// discovered call sites to find unreachable functions.
///
/// Port of Python's `vivisect/analysis/i386/importcalls.py`.
#[derive(Debug, Default)]
pub struct ImportCallsAnalysis;

impl ImportCallsAnalysis {
    /// Create new import calls analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for ImportCallsAnalysis {
    fn name(&self) -> &str {
        "i386.importcalls"
    }

    fn priority(&self) -> u32 {
        370
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        matches!(
            workspace.architecture(),
            crate::constants::Architecture::I386
        )
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::importcalls::analyze_importcalls;

        let mut stats = AnalysisStats::new();

        match analyze_importcalls(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("importcall_functions", funcs.len());
                tracing::debug!(
                    "[importcalls] discovered {} functions from import call sites",
                    funcs.len()
                );
            }
            Err(e) => {
                tracing::warn!("[importcalls] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

// ============================================================================
// Built-in Per-Function Analysis Modules
// ============================================================================

/// Basic block analysis (per-function).
///
/// Builds basic blocks for a single function. This is a per-function module
/// matching Python vivisect's `codeblocks.analyzeFunction()`.
#[derive(Debug, Default)]
pub struct BasicBlockAnalysis;

impl BasicBlockAnalysis {
    /// Create new basic block analysis.
    pub fn new() -> Self {
        Self
    }
}

impl FuncAnalysisModule for BasicBlockAnalysis {
    fn name(&self) -> &str {
        "generic.codeblocks"
    }

    fn analyze_function(
        &mut self,
        workspace: &mut VivWorkspace,
        func_va: u64,
    ) -> VivResult<AnalysisStats> {
        use crate::analysis::codeflow::analyze_function;
        use crate::envi::archs::{X86Disassembler, X86Mode};

        let mut stats = AnalysisStats::new();

        if let Ok(analysis) = analyze_function(workspace, func_va) {
            for block in &analysis.blocks {
                if block.end > block.start {
                    let size = (block.end - block.start) as usize;
                    workspace.add_codeblock(block.start, size, func_va);
                    stats.blocks_discovered += 1;
                } else {
                    tracing::trace!(
                        "Skipping invalid block {:#x}..{:#x} in function {:#x}: end <= start",
                        block.start,
                        block.end,
                        func_va
                    );
                }
            }
        }

        // Create call xrefs for all call instructions in this function.
        // The initial CodeFlowAnalyzer only creates xrefs for functions it
        // discovers from entry points. Functions discovered later (by
        // prologue scan, emucode, pointer tables, etc.) need their internal
        // call instructions to produce xrefs too.
        let arch = workspace.architecture();
        let disasm = match arch {
            crate::constants::Architecture::I386 => Some(X86Disassembler::new(X86Mode::Mode32)),
            crate::constants::Architecture::Amd64 => Some(X86Disassembler::new(X86Mode::Mode64)),
            _ => None,
        };

        if let Some(disasm) = disasm {
            let blocks: Vec<(u64, usize)> = workspace
                .get_function_blocks(func_va)
                .iter()
                .map(|b| (b.va, b.size))
                .collect();

            for (block_va, block_size) in blocks {
                let mut va = block_va;
                let block_end = block_va + block_size as u64;
                while va < block_end {
                    let bytes = match workspace.read_memory(va, 16) {
                        Ok(b) => b,
                        Err(_) => break,
                    };
                    let op = match disasm.disassemble(&bytes, va) {
                        Ok(o) if o.size > 0 => o,
                        _ => break,
                    };

                    // Create xrefs for call/branch targets
                    if op.is_call() || (op.is_branch() && !op.falls_through()) {
                        for (target, flags) in op.get_branches() {
                            if let Some(target_va) = target {
                                if !flags.contains(crate::constants::BranchFlags::FALL)
                                    && workspace.is_valid_pointer(target_va)
                                {
                                    workspace.add_xref(
                                        va,
                                        target_va,
                                        crate::constants::RefType::Code,
                                    );
                                }
                            }
                        }
                    }

                    va += op.size as u64;
                }
            }
        }

        Ok(stats)
    }
}

/// Import thunk analysis (per-function).
///
/// Checks if a function has code xrefs to import locations and marks it
/// as an import thunk. Runs on each newly-created function.
///
/// Matches Python's `thunks.analyzeFunction()`.
#[derive(Debug, Default)]
pub struct ThunkFuncAnalysis;

impl ThunkFuncAnalysis {
    /// Create new thunk function analysis.
    pub fn new() -> Self {
        Self
    }
}

impl FuncAnalysisModule for ThunkFuncAnalysis {
    fn name(&self) -> &str {
        "generic.thunks_func"
    }

    fn analyze_function(
        &mut self,
        workspace: &mut VivWorkspace,
        func_va: u64,
    ) -> VivResult<AnalysisStats> {
        use crate::analysis::thunks::analyze_import_thunk;

        let stats = AnalysisStats::new();
        analyze_import_thunk(workspace, func_va);
        Ok(stats)
    }
}

/// Import API metadata analysis (per-function).
///
/// Annotates functions with their API signatures (calling convention,
/// return type, argument types/names) by looking up function names in
/// the embedded API database. For thunks, uses the original import name
/// from thunk metadata.
///
/// Port of Python's `vivisect/analysis/generic/impapi.py`.
#[derive(Debug, Default)]
pub struct ImpApiAnalysis;

impl ImpApiAnalysis {
    /// Create new import API analysis.
    pub fn new() -> Self {
        Self
    }
}

impl FuncAnalysisModule for ImpApiAnalysis {
    fn name(&self) -> &str {
        "generic.impapi"
    }

    fn analyze_function(
        &mut self,
        workspace: &mut VivWorkspace,
        func_va: u64,
    ) -> VivResult<AnalysisStats> {
        use crate::analysis::impapi::{get_api_db, lookup_api};

        let mut stats = AnalysisStats::new();

        let arch = workspace.architecture();
        let db = get_api_db(arch);

        // Get the lookup name for this function
        let lookup_name = {
            // Priority 1: thunk metadata (original import name)
            let thunk_name = workspace
                .get_function(func_va)
                .and_then(|m| m.meta.get("Thunk").cloned());

            if let Some(name) = thunk_name {
                if !name.is_empty() {
                    Some(name)
                } else {
                    None
                }
            } else {
                // Priority 2: symbol name
                workspace
                    .get_name(func_va)
                    .map(|s| s.to_string())
                    .or_else(|| {
                        workspace
                            .get_function(func_va)
                            .and_then(|m| m.name.clone())
                    })
            }
        };

        if let Some(name) = lookup_name {
            if let Some(api) = lookup_api(db, &name) {
                if let Some(meta) = workspace.get_function_mut(func_va) {
                    meta.calling_convention = Some(api.callconv.clone());
                    meta.ret_type = Some(api.ret_type.clone());
                    meta.args = api
                        .args
                        .iter()
                        .enumerate()
                        .map(|(i, arg)| {
                            let arg_name = arg
                                .name
                                .clone()
                                .unwrap_or_else(|| format!("arg{}", i));
                            (arg.arg_type.clone(), arg_name)
                        })
                        .collect();
                    stats.add_custom("impapi_annotated", 1);
                }
            }
        }

        Ok(stats)
    }
}

/// MSVC security cookie function discovery module (workspace-level).
///
/// Finds security_check_cookie functions by VAMP byte patterns, extracts
/// the global security cookie address, then scans code for instructions
/// referencing the cookie. Creates functions at code block starts that
/// reference the cookie but aren't yet recognized as function entries.
///
/// Port of Python's `vivisect/analysis/ms/msvcfunc.py`.
///
/// Must run AFTER function entries (so code blocks exist) and BEFORE
/// thunk scan (so newly discovered functions get processed).
#[derive(Debug, Default)]
pub struct MsvcFuncAnalysis;

impl MsvcFuncAnalysis {
    /// Create new MSVC function analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for MsvcFuncAnalysis {
    fn name(&self) -> &str {
        "ms.msvcfunc"
    }

    fn priority(&self) -> u32 {
        380
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        matches!(
            workspace.architecture(),
            crate::constants::Architecture::I386 | crate::constants::Architecture::Amd64
        )
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::msvc::discover_msvc_functions;

        let mut stats = AnalysisStats::new();

        match discover_msvc_functions(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("msvcfunc_discovered", funcs.len());
                tracing::debug!(
                    "[msvcfunc] discovered {} functions from security cookie refs",
                    funcs.len()
                );
            }
            Err(e) => {
                tracing::warn!("[msvcfunc] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

// ============================================================================
// Default Orchestrator Factory
// ============================================================================

/// ELF constructor/destructor analysis module (workspace-level).
///
/// Parses `.ctors`, `.dtors`, `.init_array`, and `.fini_array` sections
/// to discover constructor and destructor functions.
///
/// Port of Python's `vivisect/analysis/elf/__init__.py`.
#[derive(Debug, Default)]
pub struct ElfCtorsAnalysis;

impl ElfCtorsAnalysis {
    /// Create new ELF ctors analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for ElfCtorsAnalysis {
    fn name(&self) -> &str {
        "elf.ctors"
    }

    fn priority(&self) -> u32 {
        150
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        workspace.get_segments().iter().any(|s| {
            matches!(
                s.name.as_str(),
                ".ctors" | ".dtors" | ".init_array" | ".fini_array"
            )
        })
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::elfctors::discover_elf_ctors;

        let mut stats = AnalysisStats::new();

        match discover_elf_ctors(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("elf_ctor_functions", funcs.len());
            }
            Err(e) => {
                tracing::warn!("[elfctors] analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// Go pclntab analysis module (workspace-level).
///
/// Parses the `.gopclntab` section in Go binaries to extract the exact
/// function table. This provides definitive function entry points for
/// all Go functions in the binary.
///
/// Runs after entry points and code flow so that basic analysis is done,
/// but before late-stage discovery modules.
#[derive(Debug, Default)]
pub struct GolangAnalysis;

impl GolangAnalysis {
    /// Create new Go analysis.
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for GolangAnalysis {
    fn name(&self) -> &str {
        "golang.pclntab"
    }

    fn priority(&self) -> u32 {
        250
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        workspace
            .get_segments()
            .iter()
            .any(|s| s.name == ".gopclntab")
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::golang::discover_go_functions;

        let mut stats = AnalysisStats::new();

        match discover_go_functions(workspace) {
            Ok(funcs) => {
                stats.functions_discovered = funcs.len();
                stats.add_custom("go_pclntab_functions", funcs.len());
                tracing::debug!(
                    "[golang] discovered {} functions from pclntab",
                    funcs.len()
                );
            }
            Err(e) => {
                tracing::warn!("[golang] pclntab analysis failed: {}", e);
            }
        }

        Ok(stats)
    }
}

/// ELF PLT analysis module (workspace-level).
///
/// Identifies PLT stubs and names them based on their GOT targets.
/// Port of Python's `vivisect/analysis/elf/elfplt.py`.
#[derive(Debug, Default)]
pub struct ElfPltAnalysis;

impl ElfPltAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for ElfPltAnalysis {
    fn name(&self) -> &str {
        "elf.elfplt"
    }

    fn priority(&self) -> u32 {
        115
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        // Only run on ELF binaries
        workspace.get_segments().iter().any(|seg| {
            seg.name.starts_with(".plt")
        })
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::elfplt::analyze_elfplt;

        let mut stats = AnalysisStats::new();
        match analyze_elfplt(workspace) {
            Ok(pstats) => {
                stats.functions_discovered = pstats.plt_entries;
                stats.add_custom("plt_entries", pstats.plt_entries);
            }
            Err(e) => {
                tracing::warn!("[elfplt] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

/// ELF `__libc_start_main` analysis module (workspace-level).
///
/// Detects `main()` by finding calls to `__libc_start_main` and extracting
/// the first argument. Uses icicle emulation when available.
/// Port of Python's `vivisect/analysis/elf/libc_start_main.py`.
#[derive(Debug, Default)]
pub struct LibcStartMainAnalysis;

impl LibcStartMainAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for LibcStartMainAnalysis {
    fn name(&self) -> &str {
        "elf.libc_start_main"
    }

    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, workspace: &VivWorkspace) -> bool {
        // Only run if __libc_start_main symbol exists
        workspace.symbols().iter().any(|(_, name)| {
            name.to_lowercase().contains("__libc_start_main")
        })
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::libc_start_main::analyze_libc_start_main;

        let mut stats = AnalysisStats::new();
        match analyze_libc_start_main(workspace) {
            Ok(lstats) => {
                if lstats.main_found {
                    stats.functions_discovered = 1;
                    stats.add_custom("main_found", 1);
                    if let Some(va) = lstats.main_va {
                        stats.add_custom("main_va", va as usize);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("[libc_start_main] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

/// Calling convention detection module (workspace-level).
///
/// Detects calling conventions for all functions:
/// - `ret N` → stdcall (callee cleanup)
/// - Register tracking → thiscall/fastcall
/// - x86-64: platform-based (ms64 or sysv64)
/// - Default: cdecl
///
/// Port of Python's `vivisect/analysis/i386/calling.py`.
#[derive(Debug, Default)]
pub struct CallingConventionAnalysis;

impl CallingConventionAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for CallingConventionAnalysis {
    fn name(&self) -> &str {
        "generic.calling"
    }

    fn priority(&self) -> u32 {
        460
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::calling::analyze_calling_conventions;

        let mut stats = AnalysisStats::new();
        match analyze_calling_conventions(workspace) {
            Ok(cstats) => {
                stats.add_custom("cdecl", cstats.cdecl);
                stats.add_custom("stdcall", cstats.stdcall);
                stats.add_custom("thiscall", cstats.thiscall);
                stats.add_custom("fastcall", cstats.fastcall);
                stats.add_custom("sysv64", cstats.sysv64);
                stats.add_custom("ms64", cstats.ms64);
            }
            Err(e) => {
                tracing::warn!("[calling] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

/// Symbolic switch case analysis module (workspace-level).
///
/// Finds indirect jumps (switch statements), resolves jump table bases,
/// enumerates case targets, and creates code flow for each case.
///
/// Port of Python's `vivisect/analysis/generic/symswitchcase.py`.
#[derive(Debug, Default)]
pub struct SwitchCaseAnalysis;

impl SwitchCaseAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for SwitchCaseAnalysis {
    fn name(&self) -> &str {
        "generic.symswitchcase"
    }

    fn priority(&self) -> u32 {
        470
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::symswitchcase::analyze_symswitchcase;

        let mut stats = AnalysisStats::new();
        match analyze_symswitchcase(workspace) {
            Ok(sstats) => {
                stats.add_custom("switches_found", sstats.switches_found);
                stats.add_custom("switch_cases", sstats.total_cases);
                stats.add_custom("cases_wired", sstats.cases_wired);
            }
            Err(e) => {
                tracing::warn!("[symswitchcase] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

/// Non-symbolic switch case resolution via backward instruction scanning.
///
/// Port of Python's `vivisect/analysis/generic/switchcase.py`.
/// Runs before `symswitchcase` to resolve MSVC-style RVA jump tables.
#[derive(Debug, Default)]
pub struct NonSymSwitchCaseAnalysis;

impl NonSymSwitchCaseAnalysis {
    pub fn new() -> Self {
        Self
    }
}

impl AnalysisModule for NonSymSwitchCaseAnalysis {
    fn name(&self) -> &str {
        "generic.switchcase"
    }

    fn priority(&self) -> u32 {
        465
    }

    fn should_run(&self, ws: &VivWorkspace) -> bool {
        matches!(
            ws.architecture(),
            crate::constants::Architecture::I386 | crate::constants::Architecture::Amd64
        )
    }

    fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        use crate::analysis::switchcase::analyze_switchcase;

        let mut stats = AnalysisStats::new();
        match analyze_switchcase(workspace) {
            Ok(sstats) => {
                stats.add_custom("nonsym_switches_found", sstats.switches_found);
                stats.add_custom("nonsym_switch_cases", sstats.total_cases);
                stats.add_custom("nonsym_cases_wired", sstats.cases_wired);
            }
            Err(e) => {
                tracing::warn!("[switchcase] analysis failed: {}", e);
            }
        }
        Ok(stats)
    }
}

/// PE-specific relocation section analysis (workspace-level).
#[derive(Debug, Default)]
pub struct PeAnalysis;
impl PeAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for PeAnalysis {
    fn name(&self) -> &str { "pe" }
    fn priority(&self) -> u32 { 112 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.get_segments().iter().any(|s| s.name == "PE Header")
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::pe_analysis::analyze_pe(ws) {
            stats.add_custom("reloc_entries", s.reloc_entries);
        }
        Ok(stats)
    }
}

/// Relocation target analysis (workspace-level).
#[derive(Debug, Default)]
pub struct RelocationAnalysis;
impl RelocationAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for RelocationAnalysis {
    fn name(&self) -> &str { "generic.relocations" }
    fn priority(&self) -> u32 { 140 }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::relocations::analyze_relocations(ws) {
            stats.add_custom("reloc_targets", s.targets_resolved);
        }
        Ok(stats)
    }
}

/// i386 instruction hook analysis (workspace-level).
#[derive(Debug, Default)]
pub struct InstrHookAnalysis;
impl InstrHookAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for InstrHookAnalysis {
    fn name(&self) -> &str { "i386.instrhook" }
    fn priority(&self) -> u32 { 155 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        matches!(ws.architecture(), crate::constants::Architecture::I386 | crate::constants::Architecture::Amd64)
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::instrhook::analyze_instrhook(ws) {
            stats.add_custom("stos_pointers", s.pointers_found);
        }
        Ok(stats)
    }
}

/// i386 PIC thunk register detection (workspace-level).
#[derive(Debug, Default)]
pub struct ThunkRegAnalysis;
impl ThunkRegAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for ThunkRegAnalysis {
    fn name(&self) -> &str { "i386.thunk_reg" }
    fn priority(&self) -> u32 { 160 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.architecture() == crate::constants::Architecture::I386
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::thunk_reg::analyze_thunk_reg(ws) {
            stats.add_custom("pic_thunks", s.thunks_found);
        }
        Ok(stats)
    }
}

/// ARM analysis (workspace-level).
#[derive(Debug, Default)]
pub struct ArmAnalysis;
impl ArmAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for ArmAnalysis {
    fn name(&self) -> &str { "arm.emulation" }
    fn priority(&self) -> u32 { 165 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        matches!(ws.architecture(), crate::constants::Architecture::ArmV7 | crate::constants::Architecture::Thumb)
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::arm_analysis::analyze_arm(ws) {
            stats.add_custom("arm_funcs", s.functions_analyzed);
        }
        Ok(stats)
    }
}

/// AArch64 analysis (workspace-level).
#[derive(Debug, Default)]
pub struct Aarch64Analysis;
impl Aarch64Analysis { pub fn new() -> Self { Self } }
impl AnalysisModule for Aarch64Analysis {
    fn name(&self) -> &str { "aarch64.emulation" }
    fn priority(&self) -> u32 { 166 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.architecture() == crate::constants::Architecture::A64
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::arm_analysis::analyze_aarch64(ws) {
            stats.add_custom("aarch64_funcs", s.functions_analyzed);
        }
        Ok(stats)
    }
}

/// VfTable detection (workspace-level).
#[derive(Debug, Default)]
pub struct VfTableAnalysis;
impl VfTableAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for VfTableAnalysis {
    fn name(&self) -> &str { "ms.vftables" }
    fn priority(&self) -> u32 { 475 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.get_segments().iter().any(|s| s.name == "PE Header")
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::vftables::analyze_vftables(ws) {
            stats.add_custom("vftables", s.vftables_found);
            stats.add_custom("vtable_entries", s.total_entries);
        }
        Ok(stats)
    }
}

/// Hotpatch pad detection (workspace-level).
#[derive(Debug, Default)]
pub struct HotpatchAnalysis;
impl HotpatchAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for HotpatchAnalysis {
    fn name(&self) -> &str { "ms.hotpatch" }
    fn priority(&self) -> u32 { 478 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.get_segments().iter().any(|s| s.name == "PE Header")
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::hotpatch::analyze_hotpatch(ws) {
            stats.add_custom("hotpatch_pads", s.pads_found);
        }
        Ok(stats)
    }
}

/// Late ELF PLT gap-filling (workspace-level).
#[derive(Debug, Default)]
pub struct ElfPltLateAnalysis;
impl ElfPltLateAnalysis { pub fn new() -> Self { Self } }
impl AnalysisModule for ElfPltLateAnalysis {
    fn name(&self) -> &str { "elf.elfplt_late" }
    fn priority(&self) -> u32 { 490 }
    fn should_run(&self, ws: &VivWorkspace) -> bool {
        ws.get_segments().iter().any(|s| s.name.to_lowercase().starts_with(".plt"))
    }
    fn analyze(&mut self, ws: &mut VivWorkspace) -> VivResult<AnalysisStats> {
        let mut stats = AnalysisStats::new();
        if let Ok(s) = crate::analysis::elfplt_late::analyze_elfplt_late(ws) {
            stats.functions_discovered = s.functions_created;
            stats.add_custom("plt_late_funcs", s.functions_created);
        }
        Ok(stats)
    }
}

/// MSVC VAMP signature analysis (per-function).
///
/// Names functions matching MSVC runtime patterns: security_check_cookie,
/// SEH prolog/epilog, GS prolog, alloca_probe, etc. Marks matched functions
/// as thunks to the signature name.
///
/// Port of Python's `vivisect/analysis/ms/msvc.py`.
#[derive(Debug, Default)]
pub struct MsvcVampAnalysis;

impl MsvcVampAnalysis {
    /// Create new MSVC VAMP analysis.
    pub fn new() -> Self {
        Self
    }
}

impl FuncAnalysisModule for MsvcVampAnalysis {
    fn name(&self) -> &str {
        "ms.msvc"
    }

    fn should_run(&self, workspace: &VivWorkspace, _func_va: u64) -> bool {
        matches!(
            workspace.architecture(),
            crate::constants::Architecture::I386 | crate::constants::Architecture::Amd64
        )
    }

    fn analyze_function(
        &mut self,
        workspace: &mut VivWorkspace,
        func_va: u64,
    ) -> VivResult<AnalysisStats> {
        use crate::analysis::msvc::analyze_msvc_function;

        let mut stats = AnalysisStats::new();
        if analyze_msvc_function(workspace, func_va) {
            stats.add_custom("msvc_vamp_matched", 1);
        }
        Ok(stats)
    }
}

/// Create a default analysis orchestrator with standard modules.
///
/// Registration order matches Python vivisect's `addAnalysisModules()`:
/// 1. Entry points (workspace) — creates initial functions
/// 2. Code flow (workspace) — recursive descent, discovers more functions
/// 3. ELF ctors (workspace) — .ctors/.dtors/.init_array/.fini_array functions
/// 4. Go pclntab (workspace) — Go binary function table (if .gopclntab exists)
/// 5. Prologue scan (workspace) — pattern-based function discovery
/// 6. Emucode (workspace) — pointer-scan-based function discovery
/// 7. Pointer tables (workspace) — discover functions from data pointer arrays
/// 8. Function entries (workspace) — late-stage function discovery from code gaps
/// 9. Import calls (workspace, i386) — call [dword ptr] targeting imports
/// 10. MSVC func (workspace) — security cookie function discovery
/// 11. Thunk scan (workspace) — identify non-import thunks
/// 12. No-return (workspace) — detect functions that never return
/// 13. Pointers (workspace) — late-stage pointer chain resolution and naming
/// 14. Strings (workspace) — string detection in data sections
///
/// Per-function modules (run on each new function after creation):
/// 1. Code blocks — builds basic blocks for the function
/// 2. Import thunks — identifies import thunks per-function
/// 3. Import API — annotates functions with API metadata
/// 4. MSVC VAMP — names MSVC runtime functions by byte patterns
pub fn create_default_orchestrator() -> AnalysisOrchestrator {
    let mut orch = AnalysisOrchestrator::new();

    // Workspace modules — registration order is execution order
    // Registration order matches Python vivisect's addAnalysisModules()
    orch.add_module(Box::new(LinkerAnalysis::new()));         // 1. generic.linker
    orch.add_module(Box::new(EntryPointAnalysis::new()));     // 2. generic.entrypoints
    orch.add_module(Box::new(PeAnalysis::new()));             // 3. pe
    orch.add_module(Box::new(ElfCtorsAnalysis::new()));       // 4. elf (ctors/dtors)
    orch.add_module(Box::new(ElfPltAnalysis::new()));         // 5. elf.elfplt
    orch.add_module(Box::new(LibcStartMainAnalysis::new()));  // 6. elf.libc_start_main
    orch.add_module(Box::new(CodeFlowAnalysis::new()));       // (codeflow runs after format-specific)
    orch.add_module(Box::new(RelocationAnalysis::new()));     // 7. generic.relocations
    orch.add_module(Box::new(PointerTableAnalysis::new()));   // 8. generic.pointertables
    orch.add_module(Box::new(ImportCallsAnalysis::new()));    // 10. i386.importcalls
    orch.add_module(Box::new(GolangAnalysis::new()));         // 11. golang
    orch.add_module(Box::new(InstrHookAnalysis::new()));      // 12. i386.instrhook
    orch.add_module(Box::new(ThunkRegAnalysis::new()));       // 13. i386.thunk_reg (PIC thunks)
    orch.add_module(Box::new(ArmAnalysis::new()));            // 16. arm.emulation
    orch.add_module(Box::new(Aarch64Analysis::new()));        // 17. aarch64.emulation
    orch.add_module(Box::new(PrologueScanAnalysis::new()));   // (after arch-specific)
    orch.add_module(Box::new(EmuCodeAnalysis::new()));        // 20. generic.emucode
    orch.add_module(Box::new(FuncEntriesAnalysis::new()));    // 26. generic.funcentries
    orch.add_module(Box::new(MsvcFuncAnalysis::new()));       // ms.msvcfunc
    orch.add_module(Box::new(ThunkScanAnalysis::new()));      // 23. generic.thunks
    orch.add_module(Box::new(NoReturnAnalysis::new()));       // 24. generic.noret
    orch.add_module(Box::new(CallingConventionAnalysis::new())); // 9. calling
    orch.add_module(Box::new(NonSymSwitchCaseAnalysis::new())); // generic.switchcase (non-symbolic, before sym)
    orch.add_module(Box::new(SwitchCaseAnalysis::new()));     // 27. generic.symswitchcase
    orch.add_module(Box::new(VfTableAnalysis::new()));        // 28. ms.vftables
    orch.add_module(Box::new(HotpatchAnalysis::new()));       // 29. ms.hotpatch
    orch.add_module(Box::new(PointerAnalysis::new()));        // 25. generic.pointers
    orch.add_module(Box::new(StringAnalysis::new()));         // (last: strings)
    orch.add_module(Box::new(ElfPltLateAnalysis::new()));     // 31. elf.elfplt_late

    // Per-function modules — run on each newly-created function
    orch.add_func_module(Box::new(BasicBlockAnalysis::new()));
    orch.add_func_module(Box::new(ThunkFuncAnalysis::new()));
    orch.add_func_module(Box::new(ImpApiAnalysis::new()));
    orch.add_func_module(Box::new(MsvcVampAnalysis::new()));

    orch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestModule {
        name: String,
    }

    impl AnalysisModule for TestModule {
        fn name(&self) -> &str {
            &self.name
        }

        fn analyze(&mut self, _workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
            Ok(AnalysisStats::new())
        }
    }

    #[test]
    fn test_orchestrator_registration_order() {
        let mut orch = AnalysisOrchestrator::new();

        // Add in arbitrary order — should stay in registration order
        orch.add_module(Box::new(TestModule {
            name: "third".to_string(),
        }));
        orch.add_module(Box::new(TestModule {
            name: "first".to_string(),
        }));
        orch.add_module(Box::new(TestModule {
            name: "second".to_string(),
        }));

        let names = orch.module_names();
        assert_eq!(names, vec!["third", "first", "second"]);
    }

    #[derive(Debug)]
    struct FuncCreatingModule {
        funcs_to_create: Vec<u64>,
    }

    impl AnalysisModule for FuncCreatingModule {
        fn name(&self) -> &str {
            "test.func_creator"
        }

        fn analyze(&mut self, workspace: &mut VivWorkspace) -> VivResult<AnalysisStats> {
            let mut stats = AnalysisStats::new();
            for &va in &self.funcs_to_create {
                if !workspace.is_function(va) {
                    workspace.add_function(
                        va,
                        crate::core::workspace::FunctionMeta::default(),
                    )?;
                    stats.functions_discovered += 1;
                }
            }
            Ok(stats)
        }
    }

    #[derive(Debug)]
    struct TrackingFuncModule {
        analyzed: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
    }

    impl FuncAnalysisModule for TrackingFuncModule {
        fn name(&self) -> &str {
            "test.tracker"
        }

        fn analyze_function(
            &mut self,
            _workspace: &mut VivWorkspace,
            func_va: u64,
        ) -> VivResult<AnalysisStats> {
            self.analyzed.lock().unwrap().push(func_va);
            Ok(AnalysisStats::new())
        }
    }

    #[test]
    fn test_func_module_cascade() {
        let tracked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

        let mut orch = AnalysisOrchestrator::new();
        orch.add_module(Box::new(FuncCreatingModule {
            funcs_to_create: vec![0x1000, 0x2000, 0x3000],
        }));
        orch.add_func_module(Box::new(TrackingFuncModule {
            analyzed: tracked.clone(),
        }));

        let mut ws = VivWorkspace::new();
        let _result = orch.analyze(&mut ws);

        let analyzed = tracked.lock().unwrap();
        assert_eq!(analyzed.len(), 3);
        assert!(analyzed.contains(&0x1000));
        assert!(analyzed.contains(&0x2000));
        assert!(analyzed.contains(&0x3000));
    }

    #[test]
    fn test_default_orchestrator_structure() {
        let orch = create_default_orchestrator();
        assert_eq!(orch.module_count(), 29); // all workspace modules
        assert_eq!(orch.func_module_count(), 4); // codeblocks, thunks_func, impapi, msvc_vamp
    }
}
