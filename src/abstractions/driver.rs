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

            // TODO: Disassemble instruction at PC
            // For now, we'll use the basic step() without opcode info

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

    // Note: Full tests would require a mock emulator implementation
}
