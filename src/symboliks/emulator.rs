//! Symbolic emulator for producing function summaries.
//!
//! Port of Python vivisect's `symboliks/emulator.py` and
//! `symboliks/analysis.py:SymbolikFunctionEmulator`.
//!
//! Tracks symbolic state (registers and memory) through instruction
//! execution and produces summaries capturing a function's behavior.
//!
//! Key Python concepts ported:
//! - `_sym_vars` → `registers` HashMap
//! - `_sym_mem` → `memory` BTreeMap
//! - `getSymSnapshot()` / `setSymSnapshot()` → `snapshot()` / `restore()`
//! - `applyEffects()` → `apply_effects()`
//! - `getSymVariable()` → `get_register()`
//! - `setSymVariable()` → `set_register()`
//! - `readSymMemory()` → `read_memory()`
//! - `writeSymMemory()` → `write_memory()`

use super::effect::{EmulatorSnapshot, SymbolicEffect};
use super::reducer::reduce;
use super::value::{Op, SymbolicValue};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Symbolic execution state tracking register and memory values.
///
/// Port of Python's `SymbolikEmulator` and `SymbolikFunctionEmulator`.
#[derive(Debug, Clone)]
pub struct SymbolicEmulator {
    /// Current register values (symbolic). Python: `_sym_vars`
    registers: HashMap<String, SymbolicValue>,
    /// Memory state: map from concrete addresses to symbolic values. Python: `_sym_mem`
    memory: BTreeMap<u64, SymbolicValue>,
    /// Collected effects during execution.
    effects: Vec<SymbolicEffect>,
    /// Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    pointer_size: u8,
    /// Path constraints accumulated during execution.
    constraints: Vec<SymbolicValue>,
    /// Metadata dictionary (Python: `_sym_meta`).
    metadata: HashMap<String, u64>,
}

impl SymbolicEmulator {
    /// Create a new symbolic emulator with the given pointer size.
    pub fn new(pointer_size: u8) -> Self {
        Self {
            registers: HashMap::new(),
            memory: BTreeMap::new(),
            effects: Vec::new(),
            pointer_size,
            constraints: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Create a 64-bit emulator.
    pub fn new_64() -> Self {
        Self::new(8)
    }

    /// Create a 32-bit emulator.
    pub fn new_32() -> Self {
        Self::new(4)
    }

    /// Get the pointer size in bytes.
    pub fn pointer_size(&self) -> u8 {
        self.pointer_size
    }

    /// Initialize a register with a symbolic variable.
    pub fn init_register(&mut self, name: &str) {
        let var = SymbolicValue::var(name, self.pointer_size);
        self.registers.insert(name.to_string(), var);
    }

    /// Initialize standard x86-64 registers as symbolic.
    pub fn init_x64_registers(&mut self) {
        for name in &[
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        ] {
            self.init_register(name);
        }
    }

    /// Initialize standard x86-32 registers as symbolic.
    pub fn init_x86_registers(&mut self) {
        for name in &["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"] {
            self.init_register(name);
        }
    }

    /// Get the current symbolic value of a register.
    ///
    /// Port of Python's `getSymVariable(name, create=True)`.
    /// If the register hasn't been set, returns a fresh symbolic variable.
    pub fn get_register(&self, name: &str) -> SymbolicValue {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymbolicValue::var(name, self.pointer_size))
    }

    /// Set a register to a symbolic value and record the effect.
    ///
    /// Port of Python's `setSymVariable(name, symval)`.
    pub fn set_register(&mut self, va: u64, name: &str, value: SymbolicValue) {
        let reduced = reduce(&value);
        self.effects.push(SymbolicEffect::SetVariable {
            va,
            name: name.to_string(),
            value: reduced.clone(),
        });
        self.registers.insert(name.to_string(), reduced);
    }

    /// Set a register without recording an effect (for initialization).
    pub fn set_register_silent(&mut self, name: &str, value: SymbolicValue) {
        self.registers.insert(name.to_string(), reduce(&value));
    }

    /// Read from memory at a symbolic address.
    ///
    /// Port of Python's `readSymMemory(symaddr, symsize)`.
    pub fn read_memory(&mut self, va: u64, addr: &SymbolicValue, size: u8) -> SymbolicValue {
        self.effects.push(SymbolicEffect::ReadMemory {
            va,
            addr: addr.clone(),
            size,
        });

        // If the address is concrete, check our memory map
        if let Some(concrete_addr) = addr.as_const() {
            if let Some(value) = self.memory.get(&concrete_addr) {
                return value.clone();
            }
        }

        // Return a symbolic memory read
        SymbolicValue::mem(addr.clone(), size)
    }

    /// Write to memory at a symbolic address.
    ///
    /// Port of Python's `writeSymMemory(symaddr, symval)`.
    pub fn write_memory(&mut self, va: u64, addr: &SymbolicValue, size: u8, value: SymbolicValue) {
        let reduced = reduce(&value);
        self.effects.push(SymbolicEffect::WriteMemory {
            va,
            addr: addr.clone(),
            size,
            value: reduced.clone(),
        });

        // If address is concrete, track in memory map
        if let Some(concrete_addr) = addr.as_const() {
            self.memory.insert(concrete_addr, reduced);
        }
    }

    /// Record a function call effect.
    pub fn call_function(&mut self, va: u64, target: &str, args: Vec<SymbolicValue>) {
        self.effects.push(SymbolicEffect::CallFunction {
            va,
            target: target.to_string(),
            args,
        });
    }

    /// Record a path constraint.
    pub fn constrain_path(&mut self, va: u64, constraint: SymbolicValue) {
        self.constraints.push(constraint.clone());
        self.effects.push(SymbolicEffect::ConstrainPath {
            va,
            constraint,
        });
    }

    /// Apply a list of effects to the emulator state.
    ///
    /// Port of Python's `applyEffects(effects)`. Each effect updates
    /// the emulator state (register assignments update registers,
    /// memory writes update memory map).
    ///
    /// Returns the effects with expressions reduced against current state.
    pub fn apply_effects(&mut self, effects: &[SymbolicEffect]) -> Vec<SymbolicEffect> {
        let mut applied = Vec::with_capacity(effects.len());
        for effect in effects {
            let updated = self.apply_effect(effect);
            applied.push(updated);
        }
        applied
    }

    /// Apply a single effect to the emulator state.
    ///
    /// Port of Python's `effect.applyEffect(emu)`.
    fn apply_effect(&mut self, effect: &SymbolicEffect) -> SymbolicEffect {
        match effect {
            SymbolicEffect::SetVariable { va, name, value } => {
                let reduced = reduce(value);
                self.registers.insert(name.clone(), reduced.clone());
                SymbolicEffect::SetVariable {
                    va: *va,
                    name: name.clone(),
                    value: reduced,
                }
            }
            SymbolicEffect::ReadMemory { va, addr, size } => {
                // Record the read but don't modify state
                SymbolicEffect::ReadMemory {
                    va: *va,
                    addr: reduce(addr),
                    size: *size,
                }
            }
            SymbolicEffect::WriteMemory { va, addr, size, value } => {
                let reduced_val = reduce(value);
                let reduced_addr = reduce(addr);
                if let Some(concrete_addr) = reduced_addr.as_const() {
                    self.memory.insert(concrete_addr, reduced_val.clone());
                }
                SymbolicEffect::WriteMemory {
                    va: *va,
                    addr: reduced_addr,
                    size: *size,
                    value: reduced_val,
                }
            }
            SymbolicEffect::ConstrainPath { va, constraint } => {
                let reduced = reduce(constraint);
                self.constraints.push(reduced.clone());
                SymbolicEffect::ConstrainPath {
                    va: *va,
                    constraint: reduced,
                }
            }
            SymbolicEffect::CallFunction { va, target, args } => {
                let reduced_args: Vec<SymbolicValue> = args.iter().map(|a| reduce(a)).collect();
                SymbolicEffect::CallFunction {
                    va: *va,
                    target: target.clone(),
                    args: reduced_args,
                }
            }
            SymbolicEffect::Debug { .. } => effect.clone(),
        }
    }

    /// Take a snapshot of the current emulator state.
    ///
    /// Port of Python's `getSymSnapshot()`.
    pub fn snapshot(&self) -> EmulatorSnapshot {
        EmulatorSnapshot {
            variables: self.registers.clone(),
            memory: self.memory.clone(),
        }
    }

    /// Restore emulator state from a snapshot.
    ///
    /// Port of Python's `setSymSnapshot(snap)`.
    pub fn restore(&mut self, snap: &EmulatorSnapshot) {
        self.registers = snap.variables.clone();
        self.memory = snap.memory.clone();
    }

    /// Get metadata value.
    #[must_use]
    pub fn get_meta(&self, key: &str) -> Option<u64> {
        self.metadata.get(key).copied()
    }

    /// Set metadata value.
    pub fn set_meta(&mut self, key: &str, value: u64) {
        self.metadata.insert(key.to_string(), value);
    }

    /// Get all accumulated path constraints.
    pub fn constraints(&self) -> &[SymbolicValue] {
        &self.constraints
    }

    /// Check if current path constraints are satisfiable.
    ///
    /// Uses Python's `isDiscrete()` + `solve()` approach:
    /// if a constraint can be reduced to a concrete boolean, check it.
    pub fn path_satisfiable(&self) -> bool {
        for constraint in &self.constraints {
            let reduced = reduce(constraint);
            if reduced.is_discrete() {
                if reduced.solve() == 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Process a mov-like instruction: dst = src.
    pub fn process_mov(&mut self, va: u64, dst_reg: &str, src: SymbolicValue) {
        self.set_register(va, dst_reg, src);
    }

    /// Process an arithmetic instruction: dst = dst op src.
    pub fn process_arith(&mut self, va: u64, op: Op, dst_reg: &str, src: SymbolicValue) {
        let dst_val = self.get_register(dst_reg);
        let result = SymbolicValue::oper(op, dst_val, src);
        self.set_register(va, dst_reg, result);
    }

    /// Process a push instruction (write to stack, decrement SP).
    pub fn process_push(&mut self, va: u64, value: SymbolicValue, sp_name: &str) {
        let sp = self.get_register(sp_name);
        let new_sp = SymbolicValue::sub(sp, SymbolicValue::constant(self.pointer_size as u64, self.pointer_size));
        self.set_register(va, sp_name, new_sp.clone());
        self.write_memory(va, &new_sp, self.pointer_size, value);
    }

    /// Process a pop instruction (read from stack, increment SP).
    pub fn process_pop(&mut self, va: u64, dst_reg: &str, sp_name: &str) -> SymbolicValue {
        let sp = self.get_register(sp_name);
        let value = self.read_memory(va, &sp, self.pointer_size);
        let new_sp = SymbolicValue::add(sp, SymbolicValue::constant(self.pointer_size as u64, self.pointer_size));
        self.set_register(va, sp_name, new_sp);
        self.set_register(va, dst_reg, value.clone());
        value
    }

    /// Check if an address is in the stack region.
    ///
    /// Port of Python's `isStackMemory(symvar)`.
    pub fn is_stack_memory(&self, addr: &SymbolicValue, stack_base: u64, stack_size: u64) -> bool {
        if let Some(concrete) = addr.as_const() {
            concrete >= stack_base.wrapping_sub(stack_size) && concrete <= stack_base
        } else {
            false
        }
    }

    /// Get all recorded effects.
    pub fn effects(&self) -> &[SymbolicEffect] {
        &self.effects
    }

    /// Consume and return all effects, clearing the internal log.
    pub fn take_effects(&mut self) -> Vec<SymbolicEffect> {
        std::mem::take(&mut self.effects)
    }

    /// Produce a function summary from the current symbolic state.
    ///
    /// The summary captures:
    /// - Return value expression (rax/eax)
    /// - Memory write expressions
    /// - Called functions with arguments
    pub fn summarize(&self) -> SymbolicSummary {
        let return_reg = if self.pointer_size == 8 { "rax" } else { "eax" };

        let return_value = self.registers.get(return_reg).cloned();

        let memory_writes: Vec<(SymbolicValue, SymbolicValue)> = self
            .effects
            .iter()
            .filter_map(|e| match e {
                SymbolicEffect::WriteMemory { addr, value, .. } => {
                    Some((addr.clone(), value.clone()))
                }
                _ => None,
            })
            .collect();

        let calls: Vec<(String, Vec<SymbolicValue>)> = self
            .effects
            .iter()
            .filter_map(|e| match e {
                SymbolicEffect::CallFunction { target, args, .. } => {
                    Some((target.clone(), args.clone()))
                }
                _ => None,
            })
            .collect();

        SymbolicSummary {
            return_value,
            memory_writes,
            calls,
        }
    }

    /// Reset the emulator state (keep register initialization).
    pub fn reset(&mut self) {
        self.effects.clear();
        self.memory.clear();
        self.constraints.clear();
    }
}

/// Summary of a function's symbolic behavior.
///
/// Captures what a function computes in terms of its inputs,
/// enabling comparison between functions in different binaries.
#[derive(Debug, Clone)]
pub struct SymbolicSummary {
    /// The return value expression (if rax/eax was set).
    pub return_value: Option<SymbolicValue>,
    /// Memory writes: (address_expr, value_expr).
    pub memory_writes: Vec<(SymbolicValue, SymbolicValue)>,
    /// Function calls: (target, args).
    pub calls: Vec<(String, Vec<SymbolicValue>)>,
}

impl SymbolicSummary {
    /// Compute a hash of this summary for quick comparison.
    pub fn structural_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash return value structure
        if let Some(ref ret) = self.return_value {
            1u8.hash(&mut hasher);
            ret.structural_hash().hash(&mut hasher);
        } else {
            0u8.hash(&mut hasher);
        }

        // Hash memory write count and structures
        self.memory_writes.len().hash(&mut hasher);
        for (addr, val) in &self.memory_writes {
            addr.structural_hash().hash(&mut hasher);
            val.structural_hash().hash(&mut hasher);
        }

        // Hash call count and targets
        self.calls.len().hash(&mut hasher);
        for (target, args) in &self.calls {
            target.hash(&mut hasher);
            args.len().hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Check if two summaries are structurally equivalent.
    ///
    /// This ignores concrete constant values and compares only
    /// the shape of expressions (which registers/params feed into
    /// which operations and outputs).
    pub fn structurally_equivalent(&self, other: &SymbolicSummary) -> bool {
        // Compare return values
        match (&self.return_value, &other.return_value) {
            (Some(a), Some(b)) => {
                if !a.structurally_equivalent(b) {
                    return false;
                }
            }
            (None, None) => {}
            _ => return false,
        }

        // Compare memory write count
        if self.memory_writes.len() != other.memory_writes.len() {
            return false;
        }

        // Compare call count and targets
        if self.calls.len() != other.calls.len() {
            return false;
        }

        for ((t1, a1), (t2, a2)) in self.calls.iter().zip(other.calls.iter()) {
            if t1 != t2 || a1.len() != a2.len() {
                return false;
            }
        }

        true
    }

    /// Compute a similarity score between two summaries (0.0 - 1.0).
    pub fn similarity(&self, other: &SymbolicSummary) -> f64 {
        let mut score = 0.0;
        let mut max_score = 0.0;

        // Return value comparison (weight: 3)
        max_score += 3.0;
        match (&self.return_value, &other.return_value) {
            (Some(a), Some(b)) => {
                if a.structurally_equivalent(b) {
                    score += 3.0;
                } else {
                    score += 1.0; // Both have return values
                }
            }
            (None, None) => score += 3.0,
            _ => {}
        }

        // Memory write count similarity (weight: 2)
        max_score += 2.0;
        let w1 = self.memory_writes.len();
        let w2 = other.memory_writes.len();
        if w1 == w2 {
            score += 2.0;
        } else {
            let max_w = w1.max(w2) as f64;
            if max_w > 0.0 {
                let min_w = w1.min(w2) as f64;
                score += 2.0 * (min_w / max_w);
            }
        }

        // Call count and target similarity (weight: 3)
        max_score += 3.0;
        if self.calls.len() == other.calls.len() {
            score += 1.0;
            let matching_targets = self
                .calls
                .iter()
                .zip(other.calls.iter())
                .filter(|((t1, _), (t2, _))| t1 == t2)
                .count();
            if !self.calls.is_empty() {
                score += 2.0 * (matching_targets as f64 / self.calls.len() as f64);
            } else {
                score += 2.0;
            }
        }

        if max_score > 0.0 {
            score / max_score
        } else {
            1.0
        }
    }
}

impl fmt::Display for SymbolicSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SymbolicSummary {{")?;
        if let Some(ref ret) = self.return_value {
            writeln!(f, "  return: {}", ret)?;
        }
        for (addr, val) in &self.memory_writes {
            writeln!(f, "  write [{}] = {}", addr, val)?;
        }
        for (target, args) in &self.calls {
            let arg_strs: Vec<String> = args.iter().map(|a| format!("{}", a)).collect();
            writeln!(f, "  call {}({})", target, arg_strs.join(", "))?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulator_register_tracking() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        let rax = emu.get_register("rax");
        assert!(matches!(rax, SymbolicValue::Var { ref name, .. } if name == "rax"));
    }

    #[test]
    fn test_emulator_mov() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        emu.process_mov(0x1000, "rax", SymbolicValue::constant(42, 8));
        assert_eq!(emu.get_register("rax").as_const(), Some(42));
    }

    #[test]
    fn test_emulator_arithmetic() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        // rax = 10
        emu.process_mov(0x1000, "rax", SymbolicValue::constant(10, 8));
        // rax = rax + 5
        emu.process_arith(0x1005, Op::Add, "rax", SymbolicValue::constant(5, 8));

        assert_eq!(emu.get_register("rax").as_const(), Some(15));
    }

    #[test]
    fn test_emulator_symbolic_arithmetic() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        // rax = rax + 5 (symbolic)
        emu.process_arith(0x1000, Op::Add, "rax", SymbolicValue::constant(5, 8));

        let result = emu.get_register("rax");
        // Should be (rax + 5), not a constant
        assert!(!result.is_const());
    }

    #[test]
    fn test_emulator_push_pop() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        // Set rsp to a known value for testing
        emu.process_mov(0x1000, "rsp", SymbolicValue::constant(0x7FFF0000, 8));
        emu.process_mov(0x1005, "rbp", SymbolicValue::constant(0xDEAD, 8));

        // push rbp
        emu.process_push(0x100A, SymbolicValue::constant(0xDEAD, 8), "rsp");

        // rsp should have decreased by 8
        let rsp = emu.get_register("rsp");
        assert_eq!(rsp.as_const(), Some(0x7FFF0000 - 8));
    }

    #[test]
    fn test_summary_generation() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        // Simulate: rax = rbx + rcx
        let rbx = emu.get_register("rbx");
        let rcx = emu.get_register("rcx");
        let result = SymbolicValue::add(rbx, rcx);
        emu.set_register(0x1000, "rax", result);

        // Simulate: call printf(rdi)
        let rdi = emu.get_register("rdi");
        emu.call_function(0x1010, "printf", vec![rdi]);

        let summary = emu.summarize();
        assert!(summary.return_value.is_some());
        assert_eq!(summary.calls.len(), 1);
        assert_eq!(summary.calls[0].0, "printf");
    }

    #[test]
    fn test_summary_structural_equivalence() {
        // Two functions that both compute: return arg0 + arg1
        let mut emu1 = SymbolicEmulator::new_64();
        emu1.init_x64_registers();
        let rdi1 = emu1.get_register("rdi");
        let rsi1 = emu1.get_register("rsi");
        emu1.set_register(0x1000, "rax", SymbolicValue::add(rdi1, rsi1));

        let mut emu2 = SymbolicEmulator::new_64();
        emu2.init_x64_registers();
        let rdi2 = emu2.get_register("rdi");
        let rsi2 = emu2.get_register("rsi");
        emu2.set_register(0x2000, "rax", SymbolicValue::add(rdi2, rsi2));

        let s1 = emu1.summarize();
        let s2 = emu2.summarize();

        assert!(s1.structurally_equivalent(&s2));
    }

    #[test]
    fn test_summary_structural_non_equivalence() {
        // Function 1: return arg0 + arg1
        let mut emu1 = SymbolicEmulator::new_64();
        emu1.init_x64_registers();
        let rdi1 = emu1.get_register("rdi");
        let rsi1 = emu1.get_register("rsi");
        emu1.set_register(0x1000, "rax", SymbolicValue::add(rdi1, rsi1));

        // Function 2: return arg0 - arg1
        let mut emu2 = SymbolicEmulator::new_64();
        emu2.init_x64_registers();
        let rdi2 = emu2.get_register("rdi");
        let rsi2 = emu2.get_register("rsi");
        emu2.set_register(0x2000, "rax", SymbolicValue::sub(rdi2, rsi2));

        let s1 = emu1.summarize();
        let s2 = emu2.summarize();

        assert!(!s1.structurally_equivalent(&s2));
    }

    #[test]
    fn test_summary_similarity() {
        // Two identical summaries should have similarity 1.0
        let mut emu1 = SymbolicEmulator::new_64();
        emu1.init_x64_registers();
        emu1.set_register(0x1000, "rax", SymbolicValue::constant(0, 8));
        emu1.call_function(0x1010, "puts", vec![SymbolicValue::var("rdi", 8)]);

        let mut emu2 = SymbolicEmulator::new_64();
        emu2.init_x64_registers();
        emu2.set_register(0x2000, "rax", SymbolicValue::constant(0, 8));
        emu2.call_function(0x2010, "puts", vec![SymbolicValue::var("rdi", 8)]);

        let s1 = emu1.summarize();
        let s2 = emu2.summarize();

        let sim = s1.similarity(&s2);
        assert!(sim > 0.9, "Expected high similarity, got {}", sim);
    }

    #[test]
    fn test_memory_tracking() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        let addr = SymbolicValue::constant(0x1000, 8);
        let value = SymbolicValue::constant(42, 4);

        emu.write_memory(0x100, &addr, 4, value);
        let read_back = emu.read_memory(0x104, &addr, 4);

        assert_eq!(read_back.as_const(), Some(42));
    }

    #[test]
    fn test_effects_collection() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        emu.process_mov(0x1000, "rax", SymbolicValue::constant(1, 8));
        emu.process_arith(0x1005, Op::Add, "rax", SymbolicValue::constant(2, 8));

        assert_eq!(emu.effects().len(), 2);
        assert!(emu.effects()[0].sets_variable("rax"));
        assert!(emu.effects()[1].sets_variable("rax"));
    }

    #[test]
    fn test_snapshot_restore() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        emu.process_mov(0x1000, "rax", SymbolicValue::constant(42, 8));
        let snap = emu.snapshot();

        emu.process_mov(0x1005, "rax", SymbolicValue::constant(99, 8));
        assert_eq!(emu.get_register("rax").as_const(), Some(99));

        emu.restore(&snap);
        assert_eq!(emu.get_register("rax").as_const(), Some(42));
    }

    #[test]
    fn test_apply_effects() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        let effects = vec![
            SymbolicEffect::SetVariable {
                va: 0x1000,
                name: "rax".to_string(),
                value: SymbolicValue::constant(42, 8),
            },
            SymbolicEffect::SetVariable {
                va: 0x1005,
                name: "rbx".to_string(),
                value: SymbolicValue::add(
                    SymbolicValue::constant(3, 8),
                    SymbolicValue::constant(4, 8),
                ),
            },
        ];

        let applied = emu.apply_effects(&effects);

        assert_eq!(emu.get_register("rax").as_const(), Some(42));
        assert_eq!(emu.get_register("rbx").as_const(), Some(7));
        // Applied effects should have reduced values
        assert_eq!(applied[1].variable_value().unwrap().as_const(), Some(7));
    }

    #[test]
    fn test_path_constraints() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        // Add a satisfiable constraint: 5 == 5
        emu.constrain_path(
            0x1000,
            SymbolicValue::constraint(
                super::super::value::ConstraintOp::Eq,
                SymbolicValue::constant(5, 8),
                SymbolicValue::constant(5, 8),
            ),
        );
        assert!(emu.path_satisfiable());

        // Add an unsatisfiable constraint: 5 == 6
        emu.constrain_path(
            0x1005,
            SymbolicValue::constraint(
                super::super::value::ConstraintOp::Eq,
                SymbolicValue::constant(5, 8),
                SymbolicValue::constant(6, 8),
            ),
        );
        assert!(!emu.path_satisfiable());
    }

    #[test]
    fn test_set_register_silent() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        emu.set_register_silent("rax", SymbolicValue::constant(42, 8));
        assert_eq!(emu.get_register("rax").as_const(), Some(42));
        // No effect should be recorded
        assert_eq!(emu.effects().len(), 0);
    }

    #[test]
    fn test_take_effects() {
        let mut emu = SymbolicEmulator::new_64();
        emu.init_x64_registers();

        emu.process_mov(0x1000, "rax", SymbolicValue::constant(1, 8));
        assert_eq!(emu.effects().len(), 1);

        let effects = emu.take_effects();
        assert_eq!(effects.len(), 1);
        assert_eq!(emu.effects().len(), 0);
    }
}
