//! Emulation monitor and hook traits.
//!
//! This module provides callback interfaces for emulation monitoring,
//! translating Python vivisect's monitor/hook patterns to Rust traits.

use crate::envi::opcode::Opcode;
use std::fmt::Debug;

/// Result of a monitor callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorResult {
    /// Continue execution normally.
    Continue,
    /// Stop execution.
    Stop,
    /// Skip this instruction (don't execute it).
    Skip,
    /// Execution already handled by monitor (for hooks).
    Handled,
}

impl Default for MonitorResult {
    fn default() -> Self {
        Self::Continue
    }
}

/// API/function call information for hook handling.
#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// Address of the function being called.
    pub target_va: u64,
    /// Address of the call instruction.
    pub call_site: u64,
    /// Return address (address after the call).
    pub return_addr: u64,
    /// Function name if known.
    pub name: Option<String>,
    /// Library name if known (for imports).
    pub library: Option<String>,
    /// Arguments (register/stack values).
    pub arguments: Vec<u64>,
}

impl FunctionCall {
    /// Create a new function call info.
    pub fn new(target_va: u64, call_site: u64, return_addr: u64) -> Self {
        Self {
            target_va,
            call_site,
            return_addr,
            name: None,
            library: None,
            arguments: Vec::new(),
        }
    }

    /// Set the function name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the library name.
    pub fn with_library(mut self, library: impl Into<String>) -> Self {
        self.library = Some(library.into());
        self
    }

    /// Set arguments.
    pub fn with_arguments(mut self, args: Vec<u64>) -> Self {
        self.arguments = args;
        self
    }

    /// Get the fully qualified name (library.function or just function).
    pub fn qualified_name(&self) -> Option<String> {
        match (&self.library, &self.name) {
            (Some(lib), Some(name)) => Some(format!("{}.{}", lib, name)),
            (None, Some(name)) => Some(name.clone()),
            _ => None,
        }
    }
}

/// Trait for emulation monitors.
///
/// Monitors receive callbacks at various points during emulation,
/// allowing observation and modification of execution.
///
/// This corresponds to Python vivisect's EmulationMonitor pattern.
pub trait Monitor: Send + Debug {
    /// Called before each instruction is executed.
    ///
    /// Return `MonitorResult::Skip` to prevent execution of this instruction.
    fn prehook(&mut self, pc: u64, op: &Opcode) -> MonitorResult {
        let _ = (pc, op);
        MonitorResult::Continue
    }

    /// Called after each instruction is executed.
    fn posthook(&mut self, pc: u64, op: &Opcode) -> MonitorResult {
        let _ = (pc, op);
        MonitorResult::Continue
    }

    /// Called when a function call is detected.
    ///
    /// This is called for CALL instructions before the call is made.
    fn on_call(&mut self, call: &FunctionCall) -> MonitorResult {
        let _ = call;
        MonitorResult::Continue
    }

    /// Called when a function returns.
    fn on_return(&mut self, from_va: u64, to_va: u64) -> MonitorResult {
        let _ = (from_va, to_va);
        MonitorResult::Continue
    }

    /// Called on memory read.
    fn on_memory_read(&mut self, addr: u64, size: usize, value: &[u8]) -> MonitorResult {
        let _ = (addr, size, value);
        MonitorResult::Continue
    }

    /// Called on memory write.
    fn on_memory_write(&mut self, addr: u64, size: usize, value: &[u8]) -> MonitorResult {
        let _ = (addr, size, value);
        MonitorResult::Continue
    }

    /// Called when execution stops.
    fn on_stop(&mut self, pc: u64, reason: &str) {
        let _ = (pc, reason);
    }

    /// Get the monitor name (for debugging).
    fn name(&self) -> &str {
        "unnamed_monitor"
    }
}

/// Result of a hook handler.
#[derive(Debug, Clone)]
pub enum HookResult {
    /// Hook did not handle the call, continue normally.
    NotHandled,
    /// Hook handled the call, set return value.
    Handled { return_value: u64 },
    /// Hook handled the call, no return value.
    HandledVoid,
    /// Hook wants to stop emulation.
    Stop,
}

/// Trait for function hooks.
///
/// Hooks intercept specific function calls and can provide
/// simulated implementations (e.g., for library functions).
///
/// This corresponds to Python vivisect's hook system.
pub trait Hook: Send + Debug {
    /// Get the function name(s) this hook handles.
    fn handles(&self) -> Vec<String>;

    /// Check if this hook handles a specific function.
    fn can_handle(&self, name: &str) -> bool {
        self.handles().iter().any(|h| h == name)
    }

    /// Handle a function call.
    ///
    /// # Arguments
    /// * `call` - Information about the function call
    /// * `read_arg` - Closure to read argument at index
    ///
    /// # Returns
    /// `HookResult` indicating how the call was handled.
    fn handle(&mut self, call: &FunctionCall) -> HookResult;
}

/// A hook that matches by function address.
pub trait AddressHook: Send + Debug {
    /// Get the addresses this hook handles.
    fn addresses(&self) -> Vec<u64>;

    /// Check if this hook handles a specific address.
    fn can_handle_address(&self, addr: u64) -> bool {
        self.addresses().contains(&addr)
    }

    /// Handle a function call at the given address.
    fn handle(&mut self, call: &FunctionCall) -> HookResult;
}

/// Breakpoint callback trait.
pub trait BreakpointCallback: Send + Debug {
    /// Called when a breakpoint is hit.
    ///
    /// Return true to continue execution, false to stop.
    fn on_breakpoint(&mut self, addr: u64) -> bool;
}

/// Simple logging monitor that prints execution trace.
#[derive(Debug, Default)]
pub struct TracingMonitor {
    /// Number of instructions traced.
    pub instruction_count: usize,
    /// Whether to print each instruction.
    pub verbose: bool,
    /// Maximum instructions before stopping.
    pub max_instructions: Option<usize>,
}

impl TracingMonitor {
    /// Create a new tracing monitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable verbose output.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set maximum instruction limit.
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.max_instructions = Some(limit);
        self
    }
}

impl Monitor for TracingMonitor {
    fn prehook(&mut self, pc: u64, op: &Opcode) -> MonitorResult {
        self.instruction_count += 1;

        if self.verbose {
            println!("{:#010x}: {}", pc, op);
        }

        if let Some(max) = self.max_instructions {
            if self.instruction_count >= max {
                return MonitorResult::Stop;
            }
        }

        MonitorResult::Continue
    }

    fn name(&self) -> &str {
        "TracingMonitor"
    }
}

/// Monitor that collects coverage information.
#[derive(Debug, Default)]
pub struct CoverageMonitor {
    /// Set of executed addresses.
    pub executed: std::collections::HashSet<u64>,
    /// Set of executed basic blocks (first instruction of each block).
    pub blocks: std::collections::HashSet<u64>,
    /// Instruction count.
    pub instruction_count: usize,
}

impl CoverageMonitor {
    /// Create a new coverage monitor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of unique addresses executed.
    pub fn unique_addresses(&self) -> usize {
        self.executed.len()
    }

    /// Check if an address was executed.
    pub fn was_executed(&self, addr: u64) -> bool {
        self.executed.contains(&addr)
    }

    /// Get coverage as a percentage given total code size.
    pub fn coverage_percent(&self, total_addresses: usize) -> f64 {
        if total_addresses == 0 {
            return 0.0;
        }
        (self.executed.len() as f64 / total_addresses as f64) * 100.0
    }
}

impl Monitor for CoverageMonitor {
    fn prehook(&mut self, pc: u64, _op: &Opcode) -> MonitorResult {
        self.executed.insert(pc);
        self.instruction_count += 1;
        MonitorResult::Continue
    }

    fn name(&self) -> &str {
        "CoverageMonitor"
    }
}

/// Monitor that stops execution at specific addresses.
#[derive(Debug)]
pub struct StopAtMonitor {
    /// Addresses to stop at.
    pub stop_addresses: std::collections::HashSet<u64>,
    /// The address where we stopped (if any).
    pub stopped_at: Option<u64>,
}

impl StopAtMonitor {
    /// Create a new stop-at monitor.
    pub fn new(addresses: impl IntoIterator<Item = u64>) -> Self {
        Self {
            stop_addresses: addresses.into_iter().collect(),
            stopped_at: None,
        }
    }

    /// Add an address to stop at.
    pub fn add_stop(&mut self, addr: u64) {
        self.stop_addresses.insert(addr);
    }
}

impl Monitor for StopAtMonitor {
    fn prehook(&mut self, pc: u64, _op: &Opcode) -> MonitorResult {
        if self.stop_addresses.contains(&pc) {
            self.stopped_at = Some(pc);
            return MonitorResult::Stop;
        }
        MonitorResult::Continue
    }

    fn name(&self) -> &str {
        "StopAtMonitor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envi::opcode::OpcodeBuilder;

    #[test]
    fn test_tracing_monitor() {
        let mut monitor = TracingMonitor::new().with_limit(10);
        let op = OpcodeBuilder::new(0x401000, "nop", 1).build();

        for i in 0..15 {
            let result = monitor.prehook(0x401000 + i, &op);
            if i >= 9 {
                assert_eq!(result, MonitorResult::Stop);
            } else {
                assert_eq!(result, MonitorResult::Continue);
            }
        }

        assert_eq!(monitor.instruction_count, 15);
    }

    #[test]
    fn test_coverage_monitor() {
        let mut monitor = CoverageMonitor::new();
        let op = OpcodeBuilder::new(0x401000, "nop", 1).build();

        monitor.prehook(0x401000, &op);
        monitor.prehook(0x401001, &op);
        monitor.prehook(0x401000, &op); // Duplicate

        assert_eq!(monitor.unique_addresses(), 2);
        assert!(monitor.was_executed(0x401000));
        assert!(monitor.was_executed(0x401001));
        assert!(!monitor.was_executed(0x401002));
    }

    #[test]
    fn test_function_call() {
        let call = FunctionCall::new(0x402000, 0x401050, 0x401055)
            .with_name("printf")
            .with_library("libc");

        assert_eq!(call.qualified_name(), Some("libc.printf".to_string()));
    }
}
