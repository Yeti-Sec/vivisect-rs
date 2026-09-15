//! Workspace-aware emulator.
//!
//! Port of Python's `vivisect/impemu/emulator.py`.
//!
//! Wraps icicle-vm (when available) or provides disassembly-based stepping
//! to emulate functions within a workspace context. Handles:
//! - Memory mapping from workspace segments
//! - Stack setup with sentinel return address
//! - Import call interception and stubbing
//! - Monitor hook dispatch (prehook/posthook)
//! - Instruction count limiting

use std::collections::HashMap;

use crate::constants::Architecture;
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::error::{VivError, VivResult};

use super::monitor::{EmulationMonitor, MonitorAction};

/// Sentinel address pushed as return address.
const SENTINEL_ADDR: u64 = 0xDEAD_0000;

/// Stack region for emulation.
const STACK_BASE: u64 = 0x7FFE_0000;
const STACK_SIZE: u64 = 0x10000;

/// Default maximum instructions per emulation run.
const DEFAULT_MAX_INSNS: u64 = 100_000;

/// Result of running a function through the emulator.
#[derive(Debug)]
pub struct EmulationResult {
    /// Whether the function returned normally.
    pub returned: bool,
    /// Number of instructions executed.
    pub insn_count: u64,
    /// Return value (from eax/rax).
    pub return_value: Option<u64>,
    /// Final stack pointer value.
    pub final_sp: u64,
    /// Stack cleanup amount (bytes cleaned by callee).
    pub stack_cleanup: i64,
    /// Whether execution was stopped by a monitor.
    pub stopped_by_monitor: bool,
    /// Addresses of calls made during execution.
    pub calls_made: Vec<(u64, u64)>,
}

/// Known API stubs that control execution behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiStubAction {
    /// Return immediately with value 0.
    ReturnZero,
    /// Return immediately with value 1 (success).
    ReturnOne,
    /// Stop emulation (noreturn function).
    StopExecution,
    /// Skip the call entirely.
    Skip,
}

/// Workspace-aware emulator.
///
/// Port of Python's `WorkspaceEmulator`. Maps workspace memory into
/// an execution context and runs functions with API stubbing.
pub struct WorkspaceEmulator {
    /// Maximum instructions to execute.
    pub max_insns: u64,
    /// Known API stubs: import name → action.
    api_stubs: HashMap<String, ApiStubAction>,
    /// Monitor for execution hooks.
    monitor: Option<Box<dyn EmulationMonitor>>,
}

impl WorkspaceEmulator {
    /// Create a new workspace emulator.
    pub fn new() -> Self {
        let mut emu = Self {
            max_insns: DEFAULT_MAX_INSNS,
            api_stubs: HashMap::new(),
            monitor: None,
        };
        emu.init_default_stubs();
        emu
    }

    /// Set the maximum instruction count.
    pub fn set_max_insns(&mut self, max: u64) {
        self.max_insns = max;
    }

    /// Attach an emulation monitor.
    pub fn set_monitor(&mut self, monitor: Box<dyn EmulationMonitor>) {
        self.monitor = Some(monitor);
    }

    /// Take the monitor back (consuming it from the emulator).
    #[must_use]
    pub fn take_monitor(&mut self) -> Option<Box<dyn EmulationMonitor>> {
        self.monitor.take()
    }

    /// Add a custom API stub.
    pub fn add_api_stub(&mut self, name: &str, action: &str) {
        let stub_action = match action {
            "return_zero" => ApiStubAction::ReturnZero,
            "return_one" => ApiStubAction::ReturnOne,
            "stop" => ApiStubAction::StopExecution,
            "skip" => ApiStubAction::Skip,
            _ => ApiStubAction::ReturnZero,
        };
        self.api_stubs.insert(name.to_lowercase(), stub_action);
    }

    /// Initialize default API stubs for common Windows/POSIX functions.
    fn init_default_stubs(&mut self) {
        // Noreturn functions → stop execution
        for name in &[
            "exitprocess",
            "exit",
            "_exit",
            "abort",
            "terminateprocess",
            "exitthread",
            "rtlexituserthread",
            "_cexit",
            "_c_exit",
            "fatalexit",
            "fatalappexita",
            "fatalappexitw",
        ] {
            self.api_stubs
                .insert(name.to_string(), ApiStubAction::StopExecution);
        }

        // Memory allocation → return non-null (stack-based fake ptr)
        for name in &[
            "malloc",
            "calloc",
            "realloc",
            "virtualalloc",
            "virtualallocex",
            "heapalloc",
            "localalloc",
            "globalalloc",
            "cotaskmemalloc",
            "sysstringlen",
        ] {
            self.api_stubs
                .insert(name.to_string(), ApiStubAction::ReturnOne);
        }

        // Free functions → return success
        for name in &[
            "free",
            "virtualfree",
            "heapfree",
            "localfree",
            "globalfree",
            "cotaskmemfree",
        ] {
            self.api_stubs
                .insert(name.to_string(), ApiStubAction::ReturnZero);
        }

        // Handle/success functions → return non-zero
        for name in &[
            "getprocessheap",
            "getmodulehandlea",
            "getmodulehandlew",
            "loadlibrarya",
            "loadlibraryw",
            "loadlibraryexa",
            "loadlibraryexw",
            "getprocaddress",
            "createfilea",
            "createfilew",
            "openprocess",
            "createmutexa",
            "createmutexw",
            "initializecriticalsection",
            "entercriticalsection",
            "leavecriticalsection",
        ] {
            self.api_stubs
                .insert(name.to_string(), ApiStubAction::ReturnOne);
        }

        // Query functions → return zero (no error)
        for name in &[
            "getlasterror",
            "setlasterror",
            "closehandle",
            "regclosekey",
            "regopenkeyexa",
            "regopenkeyexw",
            "sleep",
            "gettickcount",
            "getversion",
        ] {
            self.api_stubs
                .insert(name.to_string(), ApiStubAction::ReturnZero);
        }
    }

    /// Look up an API stub action by function name.
    fn get_stub_action(&self, name: &str) -> Option<ApiStubAction> {
        // Normalize: strip DLL prefix and case
        let lower = name.to_lowercase();
        if let Some(action) = self.api_stubs.get(&lower) {
            return Some(*action);
        }

        // Try stripping "dll.funcname" prefix
        if let Some(func) = lower.rsplit_once('.').map(|(_, f)| f) {
            if let Some(action) = self.api_stubs.get(func) {
                return Some(*action);
            }
        }

        None
    }

    /// Run a function using disassembly-based stepping.
    ///
    /// This is the fallback when icicle is not available. It disassembles
    /// and steps through instructions, handling calls by checking for
    /// import stubs.
    #[must_use]
    pub fn run_function(
        &mut self,
        workspace: &VivWorkspace,
        func_va: u64,
    ) -> VivResult<EmulationResult> {
        let arch = workspace.architecture();
        let ptr_size = arch.pointer_size();

        let disasm = match arch {
            Architecture::I386 => X86Disassembler::new(X86Mode::Mode32),
            Architecture::Amd64 => X86Disassembler::new(X86Mode::Mode64),
            _ => {
                return Err(VivError::AnalysisError {
                    message: format!("unsupported architecture: {:?}", arch),
                })
            }
        };

        let mut result = EmulationResult {
            returned: false,
            insn_count: 0,
            return_value: None,
            final_sp: STACK_BASE + STACK_SIZE - 0x100,
            stack_cleanup: 0,
            stopped_by_monitor: false,
            calls_made: Vec::new(),
        };

        let initial_sp = result.final_sp - ptr_size as u64; // After push sentinel
        let mut pc = func_va;
        let mut insn_count = 0u64;

        while insn_count < self.max_insns {
            // Read and decode
            let bytes = match workspace.read_memory(pc, 16) {
                Ok(b) => b,
                Err(_) => {
                    if pc == SENTINEL_ADDR {
                        result.returned = true;
                        break;
                    }
                    break;
                }
            };

            let op = match disasm.disassemble(&bytes, pc) {
                Ok(op) if op.size > 0 => op,
                _ => break,
            };

            // Monitor prehook
            if let Some(ref mut mon) = self.monitor {
                match mon.prehook(pc, Some(&op)) {
                    MonitorAction::Stop => {
                        result.stopped_by_monitor = true;
                        break;
                    }
                    MonitorAction::Skip => {
                        pc += op.size as u64;
                        insn_count += 1;
                        continue;
                    }
                    MonitorAction::Continue => {}
                }
            }

            // Handle special instructions
            if op.is_return() {
                // Check for ret N (stack cleanup)
                if !op.opers.is_empty() {
                    if let Some(cleanup) = op.opers[0].get_value(&op) {
                        result.stack_cleanup = cleanup as i64;
                    }
                }
                result.returned = true;

                if let Some(ref mut mon) = self.monitor {
                    mon.on_return(pc);
                }
                break;
            }

            if op.is_call() {
                // Resolve call target
                let target = op.opers.first().and_then(|o| o.get_value(&op)).unwrap_or(0);

                if target != 0 {
                    let target_name = workspace.get_name(target).map(|s| s.to_string());

                    // Check monitor
                    if let Some(ref mut mon) = self.monitor {
                        let name_ref = target_name.as_deref();
                        match mon.on_call(pc, target, name_ref) {
                            MonitorAction::Stop => {
                                result.stopped_by_monitor = true;
                                break;
                            }
                            MonitorAction::Skip => {
                                pc += op.size as u64;
                                insn_count += 1;
                                continue;
                            }
                            MonitorAction::Continue => {}
                        }
                    }

                    result.calls_made.push((pc, target));

                    // Check for API stub
                    let stub_name = target_name.as_deref().unwrap_or("");
                    if let Some(action) = self.get_stub_action(stub_name) {
                        match action {
                            ApiStubAction::StopExecution => break,
                            ApiStubAction::ReturnZero
                            | ApiStubAction::ReturnOne
                            | ApiStubAction::Skip => {
                                // Skip the call, continue after it
                                pc += op.size as u64;
                                insn_count += 1;
                                continue;
                            }
                        }
                    }

                    // For non-stubbed calls in the workspace, we could recurse
                    // but for safety we just skip them
                    pc += op.size as u64;
                    insn_count += 1;
                    continue;
                }
            }

            // For branches, follow the target if it's concrete
            if op.is_branch() && !op.is_call() && !op.is_return() {
                if let Some(target) = op.opers.first().and_then(|o| o.get_value(&op)) {
                    if workspace.is_valid_pointer(target) {
                        pc = target;
                        insn_count += 1;

                        if let Some(ref mut mon) = self.monitor {
                            mon.posthook(pc, None);
                        }
                        continue;
                    }
                }
                // Can't resolve branch target → stop
                break;
            }

            // Monitor posthook
            if let Some(ref mut mon) = self.monitor {
                mon.posthook(pc, Some(&op));
            }

            // Advance to next instruction
            pc += op.size as u64;
            insn_count += 1;
        }

        result.insn_count = insn_count;
        result.final_sp = initial_sp; // Approximate

        Ok(result)
    }

    /// Run a function using icicle-vm for full emulation.
    #[cfg(feature = "icicle")]
    #[must_use]
    pub fn run_function_icicle(
        &mut self,
        workspace: &VivWorkspace,
        func_va: u64,
    ) -> VivResult<EmulationResult> {
        use crate::analysis::emucode::emu;

        let arch = workspace.architecture();
        let ptr_size = arch.pointer_size();

        let mut vm =
            emu::create_validator_vm(workspace).ok_or_else(|| VivError::AnalysisError {
                message: format!("unsupported architecture: {:?}", arch),
            })?;

        // Set up stack
        let stack_top = STACK_BASE + STACK_SIZE - 0x100;
        let sp = stack_top - ptr_size as u64;

        // Push sentinel return address
        match ptr_size {
            4 => {
                let bytes = (SENTINEL_ADDR as u32).to_le_bytes();
                let _ = vm
                    .cpu
                    .mem
                    .write_bytes(sp, &bytes, icicle_cpu::mem::perm::NONE);
            }
            8 => {
                let bytes = SENTINEL_ADDR.to_le_bytes();
                let _ = vm
                    .cpu
                    .mem
                    .write_bytes(sp, &bytes, icicle_cpu::mem::perm::NONE);
            }
            _ => {}
        }

        vm.cpu.write_pc(func_va);
        vm.cpu.write_reg(vm.cpu.arch.reg_sp, sp);
        vm.icount_limit = self.max_insns;

        let exit = vm.run();

        let final_sp = vm.cpu.read_reg(vm.cpu.arch.reg_sp);
        let returned =
            matches!(exit, icicle_cpu::VmExit::Breakpoint) && vm.cpu.read_pc() == SENTINEL_ADDR;

        // Read return value from eax/rax
        #[allow(deprecated)]
        let ret_reg = match arch {
            Architecture::Amd64 => vm.cpu.arch.sleigh.get_reg("RAX").map(|r| r.var),
            Architecture::I386 => vm.cpu.arch.sleigh.get_reg("EAX").map(|r| r.var),
            _ => None,
        };
        let return_value = ret_reg.map(|r| vm.cpu.read_reg(r));

        Ok(EmulationResult {
            returned,
            insn_count: vm.cpu.icount,
            return_value,
            final_sp,
            stack_cleanup: (final_sp as i64) - (stack_top as i64),
            stopped_by_monitor: false,
            calls_made: Vec::new(),
        })
    }
}

impl Default for WorkspaceEmulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workspace_emulator_new() {
        let emu = WorkspaceEmulator::new();
        assert_eq!(emu.max_insns, DEFAULT_MAX_INSNS);
        assert!(!emu.api_stubs.is_empty()); // Default stubs should be populated
        assert!(emu.monitor.is_none());
    }

    #[test]
    fn test_workspace_emulator_default() {
        let emu = WorkspaceEmulator::default();
        assert_eq!(emu.max_insns, DEFAULT_MAX_INSNS);
    }

    #[test]
    fn test_set_max_insns() {
        let mut emu = WorkspaceEmulator::new();
        emu.set_max_insns(500);
        assert_eq!(emu.max_insns, 500);
    }

    #[test]
    fn test_default_max_insns_constant() {
        assert_eq!(DEFAULT_MAX_INSNS, 100_000);
    }

    #[test]
    fn test_sentinel_addr_constant() {
        assert_eq!(SENTINEL_ADDR, 0xDEAD_0000);
    }

    #[test]
    fn test_stack_constants() {
        assert_eq!(STACK_BASE, 0x7FFE_0000);
        assert_eq!(STACK_SIZE, 0x10000);
        // Stack should be at least 64KB
        assert!(STACK_SIZE >= 0x10000);
    }

    #[test]
    fn test_add_api_stub() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("MyCustomFunc", "return_zero");
        let action = emu.get_stub_action("MyCustomFunc");
        assert_eq!(action, Some(ApiStubAction::ReturnZero));
    }

    #[test]
    fn test_add_api_stub_return_one() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("AllocSomething", "return_one");
        let action = emu.get_stub_action("AllocSomething");
        assert_eq!(action, Some(ApiStubAction::ReturnOne));
    }

    #[test]
    fn test_add_api_stub_stop() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("FatalError", "stop");
        let action = emu.get_stub_action("FatalError");
        assert_eq!(action, Some(ApiStubAction::StopExecution));
    }

    #[test]
    fn test_add_api_stub_skip() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("SkippableFunc", "skip");
        let action = emu.get_stub_action("SkippableFunc");
        assert_eq!(action, Some(ApiStubAction::Skip));
    }

    #[test]
    fn test_add_api_stub_unknown_action() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("UnknownAction", "bogus");
        // Unknown action defaults to ReturnZero
        let action = emu.get_stub_action("UnknownAction");
        assert_eq!(action, Some(ApiStubAction::ReturnZero));
    }

    #[test]
    fn test_get_stub_action_case_insensitive() {
        let mut emu = WorkspaceEmulator::new();
        emu.add_api_stub("MyFunc", "return_one");
        // Lookup is case-insensitive (stored lowercase)
        assert_eq!(
            emu.get_stub_action("myfunc"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("MYFUNC"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("MyFunc"),
            Some(ApiStubAction::ReturnOne)
        );
    }

    #[test]
    fn test_get_stub_action_with_dll_prefix() {
        let emu = WorkspaceEmulator::new();
        // Default stubs include "exit" → StopExecution
        // Looking up "msvcrt.exit" should match by stripping the DLL prefix
        let action = emu.get_stub_action("msvcrt.exit");
        assert_eq!(action, Some(ApiStubAction::StopExecution));
    }

    #[test]
    fn test_get_stub_action_nonexistent() {
        let emu = WorkspaceEmulator::new();
        assert_eq!(emu.get_stub_action("nonexistent_function_xyz"), None);
    }

    #[test]
    fn test_default_stubs_noreturn() {
        let emu = WorkspaceEmulator::new();
        // exitprocess, exit, _exit, abort should be StopExecution
        assert_eq!(
            emu.get_stub_action("exitprocess"),
            Some(ApiStubAction::StopExecution)
        );
        assert_eq!(
            emu.get_stub_action("exit"),
            Some(ApiStubAction::StopExecution)
        );
        assert_eq!(
            emu.get_stub_action("_exit"),
            Some(ApiStubAction::StopExecution)
        );
        assert_eq!(
            emu.get_stub_action("abort"),
            Some(ApiStubAction::StopExecution)
        );
        assert_eq!(
            emu.get_stub_action("terminateprocess"),
            Some(ApiStubAction::StopExecution)
        );
    }

    #[test]
    fn test_default_stubs_memory_alloc() {
        let emu = WorkspaceEmulator::new();
        // Memory allocators return non-null (ReturnOne)
        assert_eq!(
            emu.get_stub_action("malloc"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("calloc"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("virtualalloc"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("heapalloc"),
            Some(ApiStubAction::ReturnOne)
        );
    }

    #[test]
    fn test_default_stubs_free() {
        let emu = WorkspaceEmulator::new();
        // Free functions return zero (success)
        assert_eq!(emu.get_stub_action("free"), Some(ApiStubAction::ReturnZero));
        assert_eq!(
            emu.get_stub_action("virtualfree"),
            Some(ApiStubAction::ReturnZero)
        );
        assert_eq!(
            emu.get_stub_action("heapfree"),
            Some(ApiStubAction::ReturnZero)
        );
    }

    #[test]
    fn test_default_stubs_handle_functions() {
        let emu = WorkspaceEmulator::new();
        // Handle/success functions return non-zero
        assert_eq!(
            emu.get_stub_action("getprocessheap"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("loadlibrarya"),
            Some(ApiStubAction::ReturnOne)
        );
        assert_eq!(
            emu.get_stub_action("getprocaddress"),
            Some(ApiStubAction::ReturnOne)
        );
    }

    #[test]
    fn test_default_stubs_query_functions() {
        let emu = WorkspaceEmulator::new();
        // Query functions return zero (no error)
        assert_eq!(
            emu.get_stub_action("getlasterror"),
            Some(ApiStubAction::ReturnZero)
        );
        assert_eq!(
            emu.get_stub_action("closehandle"),
            Some(ApiStubAction::ReturnZero)
        );
        assert_eq!(
            emu.get_stub_action("sleep"),
            Some(ApiStubAction::ReturnZero)
        );
    }

    #[test]
    fn test_set_and_take_monitor() {
        struct TestMonitor;
        impl super::super::monitor::EmulationMonitor for TestMonitor {}
        // SAFETY: TestMonitor contains no data, so is trivially Send.
        unsafe impl Send for TestMonitor {}

        let mut emu = WorkspaceEmulator::new();
        assert!(emu.monitor.is_none());
        emu.set_monitor(Box::new(TestMonitor));
        assert!(emu.monitor.is_some());
        let taken = emu.take_monitor();
        assert!(taken.is_some());
        assert!(emu.monitor.is_none());
    }

    #[test]
    fn test_emulation_result_construction() {
        let result = EmulationResult {
            returned: true,
            insn_count: 42,
            return_value: Some(0),
            final_sp: STACK_BASE + STACK_SIZE - 0x100,
            stack_cleanup: 8,
            stopped_by_monitor: false,
            calls_made: vec![(0x401000, 0x402000)],
        };
        assert!(result.returned);
        assert_eq!(result.insn_count, 42);
        assert_eq!(result.return_value, Some(0));
        assert_eq!(result.stack_cleanup, 8);
        assert!(!result.stopped_by_monitor);
        assert_eq!(result.calls_made.len(), 1);
    }

    #[test]
    fn test_api_stub_action_eq() {
        assert_eq!(ApiStubAction::ReturnZero, ApiStubAction::ReturnZero);
        assert_ne!(ApiStubAction::ReturnZero, ApiStubAction::ReturnOne);
        assert_ne!(ApiStubAction::ReturnZero, ApiStubAction::StopExecution);
        assert_ne!(ApiStubAction::ReturnZero, ApiStubAction::Skip);
    }

    #[test]
    fn test_api_stub_action_copy() {
        let a = ApiStubAction::StopExecution;
        let b = a; // Copy
        assert_eq!(a, b);
    }
}
