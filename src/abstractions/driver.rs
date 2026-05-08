//! Emulator driver - wraps an emulator with monitors and hooks.
//!
//! This implements the driver/controller pattern from Python vivisect,
//! where the driver orchestrates emulation with callbacks.

use crate::abstractions::emulator::Emulator;
use crate::abstractions::monitor::{
    AddressHook, FunctionCall, Hook, HookResult, Monitor, MonitorResult,
};
use crate::envi::opcode::Opcode;
use crate::error::{VivError, VivResult};
use std::collections::HashMap;

/// Emulator driver that wraps an emulator with monitors and hooks.
///
/// This pattern comes from Python vivisect's EmulatorDriver class,
/// which provides:
/// - Pre/post instruction hooks via monitors
/// - Function call interception via hooks
/// - Controlled execution with callbacks
pub struct EmulatorDriver<E: Emulator> {
    /// The underlying emulator.
    emu: E,
    /// Registered monitors.
    monitors: Vec<Box<dyn Monitor>>,
    /// Named function hooks.
    hooks: Vec<Box<dyn Hook>>,
    /// Address-based hooks.
    address_hooks: HashMap<u64, Box<dyn AddressHook>>,
    /// Function name to address mapping (for hook lookup).
    func_names: HashMap<String, u64>,
    /// Maximum instructions per run.
    max_instructions: usize,
    /// Whether to follow calls into functions.
    follow_calls: bool,
    /// Stack of return addresses (for call tracking).
    call_stack: Vec<u64>,
    /// Instructions executed in current run.
    instructions_executed: usize,
}

impl<E: Emulator> EmulatorDriver<E> {
    /// Create a new emulator driver.
    pub fn new(emu: E) -> Self {
        Self {
            emu,
            monitors: Vec::new(),
            hooks: Vec::new(),
            address_hooks: HashMap::new(),
            func_names: HashMap::new(),
            max_instructions: 1_000_000,
            follow_calls: true,
            call_stack: Vec::new(),
            instructions_executed: 0,
        }
    }

    /// Get a reference to the underlying emulator.
    pub fn emulator(&self) -> &E {
        &self.emu
    }

    /// Get a mutable reference to the underlying emulator.
    pub fn emulator_mut(&mut self) -> &mut E {
        &mut self.emu
    }

    /// Set maximum instructions per run.
    pub fn with_max_instructions(mut self, max: usize) -> Self {
        self.max_instructions = max;
        self
    }

    /// Set whether to follow calls.
    pub fn with_follow_calls(mut self, follow: bool) -> Self {
        self.follow_calls = follow;
        self
    }

    /// Add a monitor.
    pub fn add_monitor(&mut self, monitor: Box<dyn Monitor>) {
        self.monitors.push(monitor);
    }

    /// Add a named function hook.
    pub fn add_hook(&mut self, hook: Box<dyn Hook>) {
        self.hooks.push(hook);
    }

    /// Add an address-based hook.
    pub fn add_address_hook(&mut self, addr: u64, hook: Box<dyn AddressHook>) {
        self.address_hooks.insert(addr, hook);
    }

    /// Register a function name for hook lookup.
    pub fn register_function(&mut self, name: impl Into<String>, addr: u64) {
        self.func_names.insert(name.into(), addr);
    }

    /// Get the number of monitors.
    pub fn monitor_count(&self) -> usize {
        self.monitors.len()
    }

    /// Get the number of hooks.
    pub fn hook_count(&self) -> usize {
        self.hooks.len() + self.address_hooks.len()
    }

    /// Run monitors' prehook callbacks.
    fn run_prehooks(&mut self, pc: u64, op: &Opcode) -> MonitorResult {
        for monitor in &mut self.monitors {
            match monitor.prehook(pc, op) {
                MonitorResult::Continue => continue,
                result => return result,
            }
        }
        MonitorResult::Continue
    }

    /// Run monitors' posthook callbacks.
    fn run_posthooks(&mut self, pc: u64, op: &Opcode) -> MonitorResult {
        for monitor in &mut self.monitors {
            match monitor.posthook(pc, op) {
                MonitorResult::Continue => continue,
                result => return result,
            }
        }
        MonitorResult::Continue
    }

    /// Run monitors' on_call callbacks.
    fn run_call_monitors(&mut self, call: &FunctionCall) -> MonitorResult {
        for monitor in &mut self.monitors {
            match monitor.on_call(call) {
                MonitorResult::Continue => continue,
                result => return result,
            }
        }
        MonitorResult::Continue
    }

    /// Try to find a hook for a function call.
    fn find_hook(&mut self, call: &FunctionCall) -> Option<HookResult> {
        // First check address hooks
        if let Some(hook) = self.address_hooks.get_mut(&call.target_va) {
            let result = hook.handle(call);
            if !matches!(result, HookResult::NotHandled) {
                return Some(result);
            }
        }

        // Then check named hooks
        if let Some(name) = &call.name {
            for hook in &mut self.hooks {
                if hook.can_handle(name) {
                    let result = hook.handle(call);
                    if !matches!(result, HookResult::NotHandled) {
                        return Some(result);
                    }
                }
            }

            // Try qualified name
            if let Some(qname) = call.qualified_name() {
                for hook in &mut self.hooks {
                    if hook.can_handle(&qname) {
                        let result = hook.handle(call);
                        if !matches!(result, HookResult::NotHandled) {
                            return Some(result);
                        }
                    }
                }
            }
        }

        None
    }

    /// Get function name for an address.
    fn get_function_name(&self, addr: u64) -> Option<String> {
        for (name, &func_addr) in &self.func_names {
            if func_addr == addr {
                return Some(name.clone());
            }
        }
        None
    }

    /// Handle a call instruction.
    fn handle_call(&mut self, op: &Opcode, target: u64) -> VivResult<bool> {
        let call_site = op.va;
        let return_addr = op.va + op.size as u64;

        let mut call = FunctionCall::new(target, call_site, return_addr);
        if let Some(name) = self.get_function_name(target) {
            call.name = Some(name);
        }

        // Run call monitors
        match self.run_call_monitors(&call) {
            MonitorResult::Stop => return Ok(false),
            MonitorResult::Skip | MonitorResult::Handled => {
                // Skip the call, move to return address
                self.emu.set_pc(return_addr)?;
                return Ok(true);
            }
            MonitorResult::Continue => {}
        }

        // Try to find a hook
        if let Some(hook_result) = self.find_hook(&call) {
            match hook_result {
                HookResult::Handled { return_value } => {
                    // Set return value and skip to return address
                    self.emu.set_register("rax", return_value)?;
                    self.emu.set_pc(return_addr)?;
                    return Ok(true);
                }
                HookResult::HandledVoid => {
                    self.emu.set_pc(return_addr)?;
                    return Ok(true);
                }
                HookResult::Stop => return Ok(false),
                HookResult::NotHandled => {}
            }
        }

        // No hook handled it
        if self.follow_calls {
            // Push return address and track call
            self.call_stack.push(return_addr);
            // Let the emulator execute the call normally
            Ok(true)
        } else {
            // Skip the call, move to return address
            self.emu.set_pc(return_addr)?;
            Ok(true)
        }
    }

    /// Run emulation until a stop condition.
    #[must_use]
    pub fn run(&mut self) -> VivResult<(usize, DriverStopReason)> {
        self.instructions_executed = 0;

        while self.instructions_executed < self.max_instructions {
            let pc = self.emu.get_pc();

            // Check breakpoints
            if self.emu.is_breakpoint(pc) && self.instructions_executed > 0 {
                return Ok((
                    self.instructions_executed,
                    DriverStopReason::Breakpoint(pc),
                ));
            }

            // Step the emulator
            match self.emu.step() {
                Ok(_) => {}
                Err(VivError::InvalidInstruction { address }) => {
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::InvalidInstruction(address),
                    ));
                }
                Err(VivError::InvalidMemory { address }) => {
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::MemoryFault(address),
                    ));
                }
                Err(e) => return Err(e),
            }

            self.instructions_executed += 1;

            // Check if we returned to a tracked call
            let new_pc = self.emu.get_pc();
            if let Some(&expected_return) = self.call_stack.last() {
                if new_pc == expected_return {
                    self.call_stack.pop();
                    // Notify monitors
                    for monitor in &mut self.monitors {
                        monitor.on_return(pc, new_pc);
                    }
                }
            }
        }

        Ok((
            self.instructions_executed,
            DriverStopReason::StepLimit(self.max_instructions),
        ))
    }

    /// Run until reaching a specific address.
    #[must_use]
    pub fn run_to(&mut self, target: u64) -> VivResult<(usize, DriverStopReason)> {
        self.instructions_executed = 0;

        while self.instructions_executed < self.max_instructions {
            let pc = self.emu.get_pc();

            if pc == target {
                return Ok((self.instructions_executed, DriverStopReason::ReachedTarget));
            }

            // Check breakpoints
            if self.emu.is_breakpoint(pc) && self.instructions_executed > 0 {
                return Ok((
                    self.instructions_executed,
                    DriverStopReason::Breakpoint(pc),
                ));
            }

            match self.emu.step() {
                Ok(_) => {}
                Err(VivError::InvalidInstruction { address }) => {
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::InvalidInstruction(address),
                    ));
                }
                Err(VivError::InvalidMemory { address }) => {
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::MemoryFault(address),
                    ));
                }
                Err(e) => return Err(e),
            }

            self.instructions_executed += 1;
        }

        Ok((
            self.instructions_executed,
            DriverStopReason::StepLimit(self.max_instructions),
        ))
    }

    /// Run a function (from entry to return).
    #[must_use]
    pub fn run_function(&mut self, func_va: u64) -> VivResult<(usize, DriverStopReason)> {
        // Set PC to function entry
        self.emu.set_pc(func_va)?;

        // Push a sentinel return address
        let sentinel = 0xDEAD_BEEF_CAFE_BABEu64;
        self.emu.push(sentinel)?;

        self.instructions_executed = 0;

        while self.instructions_executed < self.max_instructions {
            let pc = self.emu.get_pc();

            // Check if we hit the sentinel (function returned)
            if pc == sentinel {
                return Ok((self.instructions_executed, DriverStopReason::FunctionReturned));
            }

            // Check breakpoints
            if self.emu.is_breakpoint(pc) && self.instructions_executed > 0 {
                return Ok((
                    self.instructions_executed,
                    DriverStopReason::Breakpoint(pc),
                ));
            }

            match self.emu.step() {
                Ok(_) => {}
                Err(VivError::InvalidInstruction { address }) => {
                    // If we're at the sentinel, function returned
                    if address == sentinel {
                        return Ok((
                            self.instructions_executed,
                            DriverStopReason::FunctionReturned,
                        ));
                    }
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::InvalidInstruction(address),
                    ));
                }
                Err(VivError::InvalidMemory { address }) => {
                    if address == sentinel {
                        return Ok((
                            self.instructions_executed,
                            DriverStopReason::FunctionReturned,
                        ));
                    }
                    return Ok((
                        self.instructions_executed,
                        DriverStopReason::MemoryFault(address),
                    ));
                }
                Err(e) => return Err(e),
            }

            self.instructions_executed += 1;
        }

        Ok((
            self.instructions_executed,
            DriverStopReason::StepLimit(self.max_instructions),
        ))
    }

    /// Get the current call stack depth.
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Get instructions executed in last run.
    pub fn instructions_executed(&self) -> usize {
        self.instructions_executed
    }

    /// Clear all monitors.
    pub fn clear_monitors(&mut self) {
        self.monitors.clear();
    }

    /// Clear all hooks.
    pub fn clear_hooks(&mut self) {
        self.hooks.clear();
        self.address_hooks.clear();
    }
}

/// Reason why the driver stopped execution.
#[derive(Debug, Clone)]
pub enum DriverStopReason {
    /// Reached target address.
    ReachedTarget,
    /// Hit a breakpoint.
    Breakpoint(u64),
    /// Step limit reached.
    StepLimit(usize),
    /// Function returned normally.
    FunctionReturned,
    /// Invalid instruction.
    InvalidInstruction(u64),
    /// Memory fault.
    MemoryFault(u64),
    /// Monitor requested stop.
    MonitorStop,
    /// Hook requested stop.
    HookStop,
}

/// A debugger-style driver with more control.
pub struct DebuggerDriver<E: Emulator> {
    /// Base driver.
    inner: EmulatorDriver<E>,
    /// Maximum hits per instruction (to avoid infinite loops).
    max_hit: usize,
    /// Hit counts per address.
    hit_counts: HashMap<u64, usize>,
}

impl<E: Emulator> DebuggerDriver<E> {
    /// Create a new debugger driver.
    pub fn new(emu: E) -> Self {
        Self {
            inner: EmulatorDriver::new(emu),
            max_hit: 1000,
            hit_counts: HashMap::new(),
        }
    }

    /// Set maximum hits per instruction.
    pub fn with_max_hit(mut self, max: usize) -> Self {
        self.max_hit = max;
        self
    }

    /// Get the underlying emulator driver.
    pub fn driver(&self) -> &EmulatorDriver<E> {
        &self.inner
    }

    /// Get mutable access to the underlying driver.
    pub fn driver_mut(&mut self) -> &mut EmulatorDriver<E> {
        &mut self.inner
    }

    /// Add a monitor.
    pub fn add_monitor(&mut self, monitor: Box<dyn Monitor>) {
        self.inner.add_monitor(monitor);
    }

    /// Run with hit counting.
    #[must_use]
    pub fn run(&mut self) -> VivResult<(usize, DriverStopReason)> {
        let mut steps = 0;
        let max = self.inner.max_instructions;

        while steps < max {
            let pc = self.inner.emu.get_pc();

            // Check hit count
            let count = self.hit_counts.entry(pc).or_insert(0);
            *count += 1;
            if *count > self.max_hit {
                return Ok((steps, DriverStopReason::StepLimit(steps)));
            }

            match self.inner.emu.step() {
                Ok(_) => {}
                Err(e) => return Err(e),
            }

            steps += 1;
        }

        Ok((steps, DriverStopReason::StepLimit(max)))
    }

    /// Get hit count for an address.
    pub fn get_hit_count(&self, addr: u64) -> usize {
        self.hit_counts.get(&addr).copied().unwrap_or(0)
    }

    /// Reset hit counts.
    pub fn reset_hits(&mut self) {
        self.hit_counts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abstractions::memory::{MemoryRegion, MemorySnapshot};
    use crate::abstractions::monitor::{FunctionCall, HookResult};
    use crate::abstractions::registers::{BasicRegisterContext, RegisterContext, RegisterSnapshot};
    use crate::constants::MemoryPermissions;
    use std::collections::HashSet;

    /// Mock emulator for driver tests.
    /// Always steps PC forward by 1 and stops after hitting an invalid address.
    #[derive(Debug)]
    struct MockEmulator {
        regs: BasicRegisterContext,
        memory: Vec<MemoryRegion>,
        breakpoints: HashSet<u64>,
        // Valid PC range: [start, end)
        valid_range: (u64, u64),
    }

    impl MockEmulator {
        fn new(start: u64, size: u64) -> Self {
            let mut regs = BasicRegisterContext::new();
            let rip = regs.add_register("rip", 64);
            let rsp = regs.add_register("rsp", 64);
            let rax = regs.add_register("rax", 64);
            regs.set_pc_register(rip);
            regs.set_sp_register(rsp);
            let _ = rax;
            regs.set_register("rip", start).unwrap();
            regs.set_register("rsp", 0x7FFE0000).unwrap();

            let mem = MemoryRegion::new(start, size as usize, MemoryPermissions::RWX);

            Self {
                regs,
                memory: vec![mem],
                breakpoints: HashSet::new(),
                valid_range: (start, start + size),
            }
        }
    }

    // Implement required traits for MockEmulator
    impl crate::abstractions::MemoryAccess for MockEmulator {
        fn read_memory(&self, addr: u64, size: usize) -> crate::error::VivResult<Vec<u8>> {
            for region in &self.memory {
                if region.contains(addr) {
                    let data = region.read(addr, size)?;
                    return Ok(data.to_vec());
                }
            }
            Err(crate::error::VivError::InvalidMemory { address: addr })
        }

        fn write_memory(&mut self, addr: u64, data: &[u8]) -> crate::error::VivResult<()> {
            for region in &mut self.memory {
                if region.contains(addr) {
                    return region.write(addr, data);
                }
            }
            Err(crate::error::VivError::InvalidMemory { address: addr })
        }

        fn is_valid_address(&self, addr: u64) -> bool {
            self.memory.iter().any(|r| r.contains(addr))
        }

        fn get_permissions(&self, addr: u64) -> Option<MemoryPermissions> {
            self.memory.iter().find(|r| r.contains(addr)).map(|r| r.permissions)
        }
    }

    impl crate::abstractions::MemoryMap for MockEmulator {
        fn add_memory_map(&mut self, base: u64, size: usize, permissions: MemoryPermissions, name: Option<String>) -> crate::error::VivResult<()> {
            let mut region = MemoryRegion::new(base, size, permissions);
            if let Some(n) = name {
                region = region.named(n);
            }
            self.memory.push(region);
            Ok(())
        }

        fn remove_memory_map(&mut self, base: u64) -> crate::error::VivResult<()> {
            self.memory.retain(|r| r.base != base);
            Ok(())
        }

        fn get_memory_maps(&self) -> Vec<(u64, usize, MemoryPermissions, Option<String>)> {
            self.memory.iter().map(|r| (r.base, r.size, r.permissions, r.name.clone())).collect()
        }

        fn get_memory_map(&self, addr: u64) -> Option<(u64, usize, MemoryPermissions, Option<String>)> {
            self.memory.iter().find(|r| r.contains(addr)).map(|r| (r.base, r.size, r.permissions, r.name.clone()))
        }

        fn snapshot_memory(&self) -> MemorySnapshot {
            MemorySnapshot { regions: self.memory.clone() }
        }

        fn restore_memory(&mut self, snapshot: &MemorySnapshot) -> crate::error::VivResult<()> {
            self.memory = snapshot.regions.clone();
            Ok(())
        }
    }

    impl crate::abstractions::RegisterContext for MockEmulator {
        fn get_register(&self, name: &str) -> crate::error::VivResult<u64> {
            self.regs.get_register(name)
        }
        fn set_register(&mut self, name: &str, value: u64) -> crate::error::VivResult<()> {
            self.regs.set_register(name, value)
        }
        fn get_register_by_index(&self, index: usize) -> crate::error::VivResult<u64> {
            self.regs.get_register_by_index(index)
        }
        fn set_register_by_index(&mut self, index: usize, value: u64) -> crate::error::VivResult<()> {
            self.regs.set_register_by_index(index, value)
        }
        fn get_register_names(&self) -> Vec<String> {
            self.regs.get_register_names()
        }
        fn get_register_info(&self, name: &str) -> Option<crate::abstractions::RegisterInfo> {
            self.regs.get_register_info(name)
        }
        fn get_register_info_by_index(&self, index: usize) -> Option<crate::abstractions::RegisterInfo> {
            self.regs.get_register_info_by_index(index)
        }
        fn get_pc_name(&self) -> &str {
            self.regs.get_pc_name()
        }
        fn get_sp_name(&self) -> &str {
            self.regs.get_sp_name()
        }
        fn snapshot(&self) -> RegisterSnapshot {
            self.regs.snapshot()
        }
        fn restore(&mut self, snapshot: &RegisterSnapshot) -> crate::error::VivResult<()> {
            self.regs.restore(snapshot)
        }
    }

    impl Emulator for MockEmulator {
        fn step(&mut self) -> crate::error::VivResult<()> {
            let pc = self.get_pc();
            if pc < self.valid_range.0 || pc >= self.valid_range.1 {
                return Err(crate::error::VivError::InvalidInstruction { address: pc });
            }
            self.set_pc(pc + 1)?;
            Ok(())
        }

        fn add_breakpoint(&mut self, address: u64) {
            self.breakpoints.insert(address);
        }
        fn remove_breakpoint(&mut self, address: u64) {
            self.breakpoints.remove(&address);
        }
        fn is_breakpoint(&self, address: u64) -> bool {
            self.breakpoints.contains(&address)
        }
        fn get_breakpoints(&self) -> Vec<u64> {
            self.breakpoints.iter().copied().collect()
        }
        fn clear_breakpoints(&mut self) {
            self.breakpoints.clear();
        }
        fn architecture(&self) -> &str {
            "amd64"
        }
        fn pointer_size(&self) -> usize {
            8
        }
    }

    // -- EmulatorDriver tests --

    #[test]
    fn test_driver_construction() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let driver = EmulatorDriver::new(emu);
        assert_eq!(driver.monitor_count(), 0);
        assert_eq!(driver.hook_count(), 0);
        assert_eq!(driver.call_depth(), 0);
        assert_eq!(driver.instructions_executed(), 0);
    }

    #[test]
    fn test_driver_with_max_instructions() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let driver = EmulatorDriver::new(emu).with_max_instructions(500);
        assert_eq!(driver.max_instructions, 500);
    }

    #[test]
    fn test_driver_with_follow_calls() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let driver = EmulatorDriver::new(emu).with_follow_calls(false);
        assert!(!driver.follow_calls);
    }

    #[test]
    fn test_driver_emulator_access() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let driver = EmulatorDriver::new(emu);
        assert_eq!(driver.emulator().get_pc(), 0x1000);
    }

    #[test]
    fn test_driver_emulator_mut_access() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);
        driver.emulator_mut().set_pc(0x1050).unwrap();
        assert_eq!(driver.emulator().get_pc(), 0x1050);
    }

    #[test]
    fn test_driver_register_function() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);
        driver.register_function("main", 0x1000);
        driver.register_function("helper", 0x1050);
        assert_eq!(driver.get_function_name(0x1000), Some("main".to_string()));
        assert_eq!(driver.get_function_name(0x1050), Some("helper".to_string()));
        assert_eq!(driver.get_function_name(0x9999), None);
    }

    #[test]
    fn test_driver_add_address_hook() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);

        #[derive(Debug)]
        struct TestAddressHook;
        impl crate::abstractions::monitor::AddressHook for TestAddressHook {
            fn addresses(&self) -> Vec<u64> { vec![0x1000] }
            fn handle(&mut self, _call: &FunctionCall) -> HookResult {
                HookResult::Handled { return_value: 42 }
            }
        }

        driver.add_address_hook(0x1000, Box::new(TestAddressHook));
        assert_eq!(driver.hook_count(), 1);
    }

    #[test]
    fn test_driver_clear_monitors() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);

        #[derive(Debug)]
        struct NoopMonitor;
        impl crate::abstractions::monitor::Monitor for NoopMonitor {
            fn name(&self) -> &str { "noop" }
        }

        driver.add_monitor(Box::new(NoopMonitor));
        assert_eq!(driver.monitor_count(), 1);
        driver.clear_monitors();
        assert_eq!(driver.monitor_count(), 0);
    }

    #[test]
    fn test_driver_clear_hooks() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);

        #[derive(Debug)]
        struct TestHook;
        impl crate::abstractions::monitor::Hook for TestHook {
            fn handles(&self) -> Vec<String> { vec!["test".to_string()] }
            fn handle(&mut self, _call: &FunctionCall) -> HookResult {
                HookResult::NotHandled
            }
        }

        #[derive(Debug)]
        struct TestAddrHook;
        impl crate::abstractions::monitor::AddressHook for TestAddrHook {
            fn addresses(&self) -> Vec<u64> { vec![0x1000] }
            fn handle(&mut self, _call: &FunctionCall) -> HookResult {
                HookResult::NotHandled
            }
        }

        driver.add_hook(Box::new(TestHook));
        driver.add_address_hook(0x1000, Box::new(TestAddrHook));
        assert_eq!(driver.hook_count(), 2);
        driver.clear_hooks();
        assert_eq!(driver.hook_count(), 0);
    }

    #[test]
    fn test_driver_run_step_limit() {
        let emu = MockEmulator::new(0x1000, 0x1000);
        let mut driver = EmulatorDriver::new(emu).with_max_instructions(10);
        let (steps, reason) = driver.run().unwrap();
        assert_eq!(steps, 10);
        assert!(matches!(reason, DriverStopReason::StepLimit(10)));
    }

    #[test]
    fn test_driver_run_invalid_instruction() {
        // Create emulator with only 5 bytes of valid memory
        let emu = MockEmulator::new(0x1000, 5);
        let mut driver = EmulatorDriver::new(emu);
        let (steps, reason) = driver.run().unwrap();
        // After stepping 5 times, PC is at 0x1005 which is invalid
        assert_eq!(steps, 5);
        assert!(matches!(reason, DriverStopReason::InvalidInstruction(0x1005)));
    }

    #[test]
    fn test_driver_run_to_target() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);
        let (steps, reason) = driver.run_to(0x1005).unwrap();
        assert_eq!(steps, 5);
        assert!(matches!(reason, DriverStopReason::ReachedTarget));
        assert_eq!(driver.emulator().get_pc(), 0x1005);
    }

    #[test]
    fn test_driver_run_to_with_step_limit() {
        let emu = MockEmulator::new(0x1000, 0x1000);
        let mut driver = EmulatorDriver::new(emu).with_max_instructions(3);
        // Target is far away, should hit step limit first
        let (steps, reason) = driver.run_to(0x2000).unwrap();
        assert_eq!(steps, 3);
        assert!(matches!(reason, DriverStopReason::StepLimit(3)));
    }

    #[test]
    fn test_driver_run_breakpoint() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut driver = EmulatorDriver::new(emu);
        driver.emulator_mut().add_breakpoint(0x1003);
        let (steps, reason) = driver.run().unwrap();
        // Should stop at breakpoint after stepping to 0x1003
        assert_eq!(steps, 3);
        assert!(matches!(reason, DriverStopReason::Breakpoint(0x1003)));
    }

    // -- DebuggerDriver tests --

    #[test]
    fn test_debugger_driver_construction() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let dbg = DebuggerDriver::new(emu);
        assert_eq!(dbg.get_hit_count(0x1000), 0);
    }

    #[test]
    fn test_debugger_driver_with_max_hit() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let dbg = DebuggerDriver::new(emu).with_max_hit(5);
        assert_eq!(dbg.max_hit, 5);
    }

    #[test]
    fn test_debugger_driver_hit_counts() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut dbg = DebuggerDriver::new(emu).with_max_hit(1000);
        let _ = dbg.run(); // Run some steps
        // After running, addresses 0x1000..0x1000+N should have hit counts
        assert!(dbg.get_hit_count(0x1000) > 0);
    }

    #[test]
    fn test_debugger_driver_reset_hits() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let mut dbg = DebuggerDriver::new(emu).with_max_hit(1000);
        let _ = dbg.run();
        dbg.reset_hits();
        assert_eq!(dbg.get_hit_count(0x1000), 0);
    }

    #[test]
    fn test_debugger_driver_access() {
        let emu = MockEmulator::new(0x1000, 0x100);
        let dbg = DebuggerDriver::new(emu);
        assert_eq!(dbg.driver().emulator().get_pc(), 0x1000);
    }

    // -- DriverStopReason tests --

    #[test]
    fn test_driver_stop_reason_debug() {
        let reason = DriverStopReason::Breakpoint(0x401000);
        let s = format!("{:?}", reason);
        assert!(s.contains("Breakpoint"));
    }

    #[test]
    fn test_driver_stop_reason_clone() {
        let reason = DriverStopReason::StepLimit(1000);
        let cloned = reason.clone();
        assert!(matches!(cloned, DriverStopReason::StepLimit(1000)));
    }

    #[test]
    fn test_driver_stop_reason_variants() {
        let _r1 = DriverStopReason::ReachedTarget;
        let _r2 = DriverStopReason::Breakpoint(0x1000);
        let _r3 = DriverStopReason::StepLimit(100);
        let _r4 = DriverStopReason::FunctionReturned;
        let _r5 = DriverStopReason::InvalidInstruction(0x2000);
        let _r6 = DriverStopReason::MemoryFault(0x3000);
        let _r7 = DriverStopReason::MonitorStop;
        let _r8 = DriverStopReason::HookStop;
    }
}
