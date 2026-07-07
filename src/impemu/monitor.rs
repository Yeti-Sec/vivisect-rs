//! Emulation monitors — hooks for intercepting execution.
//!
//! Port of Python's `vivisect/impemu/monitor.py`.
//!
//! Monitors provide prehook/posthook callbacks that fire before and after
//! each instruction. They can inspect/modify emulator state and control
//! whether execution should continue, stop, or skip the instruction.

use crate::envi::opcode::Opcode;

/// Action returned by monitor hooks to control execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorAction {
    /// Continue normal execution.
    Continue,
    /// Stop emulation immediately.
    Stop,
    /// Skip this instruction (don't execute it).
    Skip,
}

/// Trait for emulation monitors.
///
/// Monitors are attached to a WorkspaceEmulator and receive callbacks
/// during execution. They can track state, detect patterns, and
/// control execution flow.
///
/// Port of Python's `AnalysisMonitor` class.
pub trait EmulationMonitor: Send {
    /// Called before each instruction is executed.
    ///
    /// Arguments:
    /// - `va`: current instruction address
    /// - `op`: the decoded opcode (if available)
    ///
    /// Return `MonitorAction` to control execution.
    fn prehook(&mut self, va: u64, op: Option<&Opcode>) -> MonitorAction {
        let _ = (va, op);
        MonitorAction::Continue
    }

    /// Called after each instruction is executed.
    fn posthook(&mut self, va: u64, op: Option<&Opcode>) {
        let _ = (va, op);
    }

    /// Called when a function call is detected.
    ///
    /// Arguments:
    /// - `call_va`: address of the call instruction
    /// - `target_va`: target of the call
    /// - `target_name`: resolved name of the target (if known)
    ///
    /// Return `MonitorAction::Stop` to halt on this call.
    fn on_call(&mut self, call_va: u64, target_va: u64, target_name: Option<&str>) -> MonitorAction {
        let _ = (call_va, target_va, target_name);
        MonitorAction::Continue
    }

    /// Called when a return instruction is executed.
    fn on_return(&mut self, va: u64) -> MonitorAction {
        let _ = va;
        MonitorAction::Continue
    }

    /// Called when emulation encounters an error.
    fn on_error(&mut self, va: u64, error: &str) {
        let _ = (va, error);
    }

    /// Get the name of this monitor (for logging).
    fn name(&self) -> &str {
        "monitor"
    }
}

/// A simple monitor that tracks execution paths.
#[derive(Debug, Default)]
pub struct PathTracker {
    /// Instruction addresses visited during emulation.
    pub visited: Vec<u64>,
    /// Call targets encountered.
    pub calls: Vec<(u64, u64)>,
    /// Maximum instructions to track.
    pub max_insns: usize,
}

impl PathTracker {
    /// Create a new path tracker with default limits.
    pub fn new() -> Self {
        Self {
            visited: Vec::new(),
            calls: Vec::new(),
            max_insns: 10000,
        }
    }

    /// Create with a custom instruction limit.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            max_insns: limit,
            ..Self::new()
        }
    }
}

impl EmulationMonitor for PathTracker {
    fn prehook(&mut self, va: u64, _op: Option<&Opcode>) -> MonitorAction {
        self.visited.push(va);
        if self.visited.len() >= self.max_insns {
            MonitorAction::Stop
        } else {
            MonitorAction::Continue
        }
    }

    fn on_call(&mut self, call_va: u64, target_va: u64, _target_name: Option<&str>) -> MonitorAction {
        self.calls.push((call_va, target_va));
        MonitorAction::Continue
    }

    fn name(&self) -> &str {
        "path_tracker"
    }
}

/// A monitor that stops execution at a specific address (breakpoint).
#[derive(Debug)]
pub struct BreakpointMonitor {
    /// Addresses to break at.
    pub breakpoints: std::collections::HashSet<u64>,
    /// Whether a breakpoint was hit.
    pub hit: bool,
    /// The address that was hit.
    pub hit_va: Option<u64>,
}

impl BreakpointMonitor {
    /// Create a breakpoint monitor for a single address.
    pub fn at(va: u64) -> Self {
        let mut bps = std::collections::HashSet::new();
        bps.insert(va);
        Self {
            breakpoints: bps,
            hit: false,
            hit_va: None,
        }
    }

    /// Create with multiple breakpoints.
    pub fn at_many(vas: &[u64]) -> Self {
        Self {
            breakpoints: vas.iter().copied().collect(),
            hit: false,
            hit_va: None,
        }
    }
}

impl EmulationMonitor for BreakpointMonitor {
    fn prehook(&mut self, va: u64, _op: Option<&Opcode>) -> MonitorAction {
        if self.breakpoints.contains(&va) {
            self.hit = true;
            self.hit_va = Some(va);
            MonitorAction::Stop
        } else {
            MonitorAction::Continue
        }
    }

    fn name(&self) -> &str {
        "breakpoint"
    }
}

/// A monitor that stops on calls to specific functions.
#[derive(Debug)]
pub struct CallMonitor {
    /// Function names to stop on.
    pub target_names: std::collections::HashSet<String>,
    /// Whether a target call was hit.
    pub hit: bool,
    /// The call VA and target VA that was hit.
    pub hit_info: Option<(u64, u64, String)>,
}

impl CallMonitor {
    /// Create a call monitor for specific function names.
    pub fn for_functions(names: &[&str]) -> Self {
        Self {
            target_names: names.iter().map(|s| s.to_lowercase()).collect(),
            hit: false,
            hit_info: None,
        }
    }
}

impl EmulationMonitor for CallMonitor {
    fn on_call(&mut self, call_va: u64, target_va: u64, target_name: Option<&str>) -> MonitorAction {
        if let Some(name) = target_name {
            if self.target_names.contains(&name.to_lowercase()) {
                self.hit = true;
                self.hit_info = Some((call_va, target_va, name.to_string()));
                return MonitorAction::Stop;
            }
        }
        MonitorAction::Continue
    }

    fn name(&self) -> &str {
        "call_monitor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // MonitorAction Tests
    // =========================================================================

    #[test]
    fn test_monitor_action_eq() {
        assert_eq!(MonitorAction::Continue, MonitorAction::Continue);
        assert_eq!(MonitorAction::Stop, MonitorAction::Stop);
        assert_eq!(MonitorAction::Skip, MonitorAction::Skip);
        assert_ne!(MonitorAction::Continue, MonitorAction::Stop);
        assert_ne!(MonitorAction::Continue, MonitorAction::Skip);
        assert_ne!(MonitorAction::Stop, MonitorAction::Skip);
    }

    // =========================================================================
    // PathTracker Tests
    // =========================================================================

    #[test]
    fn test_path_tracker_new() {
        let tracker = PathTracker::new();
        assert!(tracker.visited.is_empty());
        assert!(tracker.calls.is_empty());
        assert_eq!(tracker.max_insns, 10000);
    }

    #[test]
    fn test_path_tracker_with_limit() {
        let tracker = PathTracker::with_limit(100);
        assert_eq!(tracker.max_insns, 100);
        assert!(tracker.visited.is_empty());
        assert!(tracker.calls.is_empty());
    }

    #[test]
    fn test_path_tracker_default_trait() {
        let tracker = PathTracker::default();
        assert!(tracker.visited.is_empty());
        assert!(tracker.calls.is_empty());
    }

    #[test]
    fn test_path_tracker_prehook_records_va() {
        let mut tracker = PathTracker::new();
        let action = tracker.prehook(0x1000, None);
        assert_eq!(action, MonitorAction::Continue);
        assert_eq!(tracker.visited, vec![0x1000]);
    }

    #[test]
    fn test_path_tracker_prehook_multiple_visits() {
        let mut tracker = PathTracker::new();
        tracker.prehook(0x1000, None);
        tracker.prehook(0x1004, None);
        tracker.prehook(0x1008, None);
        assert_eq!(tracker.visited, vec![0x1000, 0x1004, 0x1008]);
    }

    #[test]
    fn test_path_tracker_prehook_stops_at_limit() {
        let mut tracker = PathTracker::with_limit(3);
        assert_eq!(tracker.prehook(0x1000, None), MonitorAction::Continue);
        assert_eq!(tracker.prehook(0x1001, None), MonitorAction::Continue);
        assert_eq!(tracker.prehook(0x1002, None), MonitorAction::Stop);
        assert_eq!(tracker.visited.len(), 3);
    }

    #[test]
    fn test_path_tracker_stops_exactly_at_limit_one() {
        let mut tracker = PathTracker::with_limit(1);
        assert_eq!(tracker.prehook(0x1000, None), MonitorAction::Stop);
        assert_eq!(tracker.visited.len(), 1);
    }

    #[test]
    fn test_path_tracker_on_call_records() {
        let mut tracker = PathTracker::new();
        let action = tracker.on_call(0x1000, 0x2000, Some("malloc"));
        assert_eq!(action, MonitorAction::Continue);
        assert_eq!(tracker.calls.len(), 1);
        assert_eq!(tracker.calls[0], (0x1000, 0x2000));
    }

    #[test]
    fn test_path_tracker_on_call_multiple() {
        let mut tracker = PathTracker::new();
        tracker.on_call(0x1000, 0x2000, None);
        tracker.on_call(0x1010, 0x3000, Some("func_b"));
        tracker.on_call(0x1020, 0x4000, Some("func_c"));
        assert_eq!(tracker.calls.len(), 3);
        assert_eq!(tracker.calls[0], (0x1000, 0x2000));
        assert_eq!(tracker.calls[1], (0x1010, 0x3000));
        assert_eq!(tracker.calls[2], (0x1020, 0x4000));
    }

    #[test]
    fn test_path_tracker_on_call_ignores_name() {
        // PathTracker records all calls regardless of name
        let mut tracker = PathTracker::new();
        tracker.on_call(0x1000, 0x2000, None);
        assert_eq!(tracker.calls.len(), 1);
    }

    #[test]
    fn test_path_tracker_name() {
        let tracker = PathTracker::new();
        assert_eq!(tracker.name(), "path_tracker");
    }

    #[test]
    fn test_path_tracker_visited_preserves_duplicates() {
        // Same address visited multiple times (e.g., loop)
        let mut tracker = PathTracker::new();
        tracker.prehook(0x1000, None);
        tracker.prehook(0x1004, None);
        tracker.prehook(0x1000, None); // loop back
        assert_eq!(tracker.visited, vec![0x1000, 0x1004, 0x1000]);
    }

    // =========================================================================
    // BreakpointMonitor Tests
    // =========================================================================

    #[test]
    fn test_breakpoint_monitor_at_single() {
        let bp = BreakpointMonitor::at(0x1000);
        assert!(bp.breakpoints.contains(&0x1000));
        assert_eq!(bp.breakpoints.len(), 1);
        assert!(!bp.hit);
        assert!(bp.hit_va.is_none());
    }

    #[test]
    fn test_breakpoint_monitor_at_many() {
        let bp = BreakpointMonitor::at_many(&[0x1000, 0x2000, 0x3000]);
        assert_eq!(bp.breakpoints.len(), 3);
        assert!(bp.breakpoints.contains(&0x1000));
        assert!(bp.breakpoints.contains(&0x2000));
        assert!(bp.breakpoints.contains(&0x3000));
        assert!(!bp.hit);
    }

    #[test]
    fn test_breakpoint_monitor_at_many_empty() {
        let bp = BreakpointMonitor::at_many(&[]);
        assert!(bp.breakpoints.is_empty());
        assert!(!bp.hit);
    }

    #[test]
    fn test_breakpoint_monitor_at_many_deduplicates() {
        let bp = BreakpointMonitor::at_many(&[0x1000, 0x1000, 0x1000]);
        assert_eq!(bp.breakpoints.len(), 1);
    }

    #[test]
    fn test_breakpoint_monitor_prehook_hit() {
        let mut bp = BreakpointMonitor::at(0x401000);
        assert!(!bp.hit);
        assert_eq!(bp.prehook(0x400000, None), MonitorAction::Continue);
        assert!(!bp.hit);
        assert_eq!(bp.prehook(0x401000, None), MonitorAction::Stop);
        assert!(bp.hit);
        assert_eq!(bp.hit_va, Some(0x401000));
    }

    #[test]
    fn test_breakpoint_monitor_prehook_miss() {
        let mut bp = BreakpointMonitor::at(0x1000);
        let action = bp.prehook(0x2000, None);
        assert_eq!(action, MonitorAction::Continue);
        assert!(!bp.hit);
        assert!(bp.hit_va.is_none());
    }

    #[test]
    fn test_breakpoint_monitor_prehook_multiple_breakpoints() {
        let mut bp = BreakpointMonitor::at_many(&[0x1000, 0x2000]);
        assert_eq!(bp.prehook(0x1500, None), MonitorAction::Continue);
        assert_eq!(bp.prehook(0x2000, None), MonitorAction::Stop);
        assert!(bp.hit);
        assert_eq!(bp.hit_va, Some(0x2000));
    }

    #[test]
    fn test_breakpoint_monitor_empty_never_hits() {
        let mut bp = BreakpointMonitor::at_many(&[]);
        assert_eq!(bp.prehook(0x1000, None), MonitorAction::Continue);
        assert_eq!(bp.prehook(0x2000, None), MonitorAction::Continue);
        assert!(!bp.hit);
    }

    #[test]
    fn test_breakpoint_monitor_name() {
        let bp = BreakpointMonitor::at(0x1000);
        assert_eq!(bp.name(), "breakpoint");
    }

    // =========================================================================
    // CallMonitor Tests
    // =========================================================================

    #[test]
    fn test_call_monitor_for_functions() {
        let cm = CallMonitor::for_functions(&["CreateFileA", "WriteFile"]);
        assert_eq!(cm.target_names.len(), 2);
        assert!(cm.target_names.contains("createfilea")); // stored lowercase
        assert!(cm.target_names.contains("writefile"));
        assert!(!cm.hit);
        assert!(cm.hit_info.is_none());
    }

    #[test]
    fn test_call_monitor_for_functions_empty() {
        let cm = CallMonitor::for_functions(&[]);
        assert!(cm.target_names.is_empty());
        assert!(!cm.hit);
    }

    #[test]
    fn test_call_monitor_on_call_match() {
        let mut cm = CallMonitor::for_functions(&["ExitProcess", "abort"]);
        assert!(!cm.hit);
        assert_eq!(cm.on_call(0x1000, 0x2000, Some("malloc")), MonitorAction::Continue);
        assert!(!cm.hit);
        assert_eq!(cm.on_call(0x1000, 0x2000, Some("ExitProcess")), MonitorAction::Stop);
        assert!(cm.hit);
        let (call_va, target_va, name) = cm.hit_info.unwrap();
        assert_eq!(call_va, 0x1000);
        assert_eq!(target_va, 0x2000);
        assert_eq!(name, "ExitProcess");
    }

    #[test]
    fn test_call_monitor_on_call_case_insensitive() {
        let mut cm = CallMonitor::for_functions(&["exitprocess"]);
        assert_eq!(cm.on_call(0x1000, 0x2000, Some("ExitProcess")), MonitorAction::Stop);
        assert!(cm.hit);
    }

    #[test]
    fn test_call_monitor_on_call_case_insensitive_mixed() {
        let mut cm = CallMonitor::for_functions(&["ExItPrOcEsS"]);
        assert_eq!(cm.on_call(0x1000, 0x2000, Some("exitprocess")), MonitorAction::Stop);
        assert!(cm.hit);
    }

    #[test]
    fn test_call_monitor_on_call_no_match() {
        let mut cm = CallMonitor::for_functions(&["CreateFileA"]);
        let action = cm.on_call(0x1000, 0x2000, Some("ReadFile"));
        assert_eq!(action, MonitorAction::Continue);
        assert!(!cm.hit);
        assert!(cm.hit_info.is_none());
    }

    #[test]
    fn test_call_monitor_on_call_no_name() {
        let mut cm = CallMonitor::for_functions(&["CreateFileA"]);
        let action = cm.on_call(0x1000, 0x2000, None);
        assert_eq!(action, MonitorAction::Continue);
        assert!(!cm.hit);
    }

    #[test]
    fn test_call_monitor_on_call_empty_targets_never_matches() {
        let mut cm = CallMonitor::for_functions(&[]);
        assert_eq!(cm.on_call(0x1000, 0x2000, Some("anything")), MonitorAction::Continue);
        assert!(!cm.hit);
    }

    #[test]
    fn test_call_monitor_name() {
        let cm = CallMonitor::for_functions(&["test"]);
        assert_eq!(cm.name(), "call_monitor");
    }

    // =========================================================================
    // Default EmulationMonitor Trait Tests
    // =========================================================================

    /// A minimal struct to test default trait implementations.
    struct DefaultMonitor;
    impl EmulationMonitor for DefaultMonitor {}

    #[test]
    fn test_default_prehook_returns_continue() {
        let mut m = DefaultMonitor;
        assert_eq!(m.prehook(0x1000, None), MonitorAction::Continue);
    }

    #[test]
    fn test_default_on_call_returns_continue() {
        let mut m = DefaultMonitor;
        assert_eq!(m.on_call(0x1000, 0x2000, Some("func")), MonitorAction::Continue);
    }

    #[test]
    fn test_default_on_return_returns_continue() {
        let mut m = DefaultMonitor;
        assert_eq!(m.on_return(0x1000), MonitorAction::Continue);
    }

    #[test]
    fn test_default_name() {
        let m = DefaultMonitor;
        assert_eq!(m.name(), "monitor");
    }

    #[test]
    fn test_default_posthook_does_not_panic() {
        let mut m = DefaultMonitor;
        m.posthook(0x1000, None); // should not panic
    }

    #[test]
    fn test_default_on_error_does_not_panic() {
        let mut m = DefaultMonitor;
        m.on_error(0x1000, "test error"); // should not panic
    }
}
