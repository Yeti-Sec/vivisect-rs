//! Symbolic effects produced by instruction execution.
//!
//! Port of Python vivisect's `symboliks/effects.py`.
//! Effects represent the side-effects of executing an instruction
//! in terms of symbolic values: register writes, memory reads/writes,
//! path constraints, and function calls.
//!
//! In Python, each effect class has an `applyEffect(emu)` method that
//! updates the emulator state and returns an updated copy of the effect
//! (with expressions resolved against current state). This Rust port
//! uses a standalone `apply_effect()` function with the same semantics.

use super::reducer::reduce;
use super::value::SymbolicValue;
use std::fmt;

/// A side-effect produced by symbolic execution of an instruction.
///
/// Port of Python's effect classes:
/// - `SetVariable` → `effects.SetVariable`
/// - `ReadMemory` → `effects.ReadMemory`
/// - `WriteMemory` → `effects.WriteMemory`
/// - `ConstrainPath` → `effects.ConstrainPath`
/// - `CallFunction` → `effects.CallFunction`
/// - `Debug` → `effects.DebugEffect` (unsupported instruction marker)
#[derive(Debug, Clone)]
pub enum SymbolicEffect {
    /// Set a register or variable to a symbolic value.
    SetVariable {
        /// Address of the instruction that produced this effect.
        va: u64,
        /// Name of the variable (register name).
        name: String,
        /// The symbolic value being assigned.
        value: SymbolicValue,
    },

    /// Read from memory at a symbolic address.
    ReadMemory {
        /// Address of the instruction.
        va: u64,
        /// Symbolic address being read.
        addr: SymbolicValue,
        /// Size of the read in bytes.
        size: u8,
    },

    /// Write to memory at a symbolic address.
    WriteMemory {
        /// Address of the instruction.
        va: u64,
        /// Symbolic address being written to.
        addr: SymbolicValue,
        /// Size of the write in bytes.
        size: u8,
        /// The symbolic value being written.
        value: SymbolicValue,
    },

    /// A path constraint from a conditional branch.
    ConstrainPath {
        /// Address of the branch instruction.
        va: u64,
        /// The constraint expression (evaluates to true on this path).
        constraint: SymbolicValue,
    },

    /// A function call with symbolic arguments.
    CallFunction {
        /// Address of the call instruction.
        va: u64,
        /// Call target (address or name).
        target: String,
        /// Arguments passed to the function.
        args: Vec<SymbolicValue>,
    },

    /// Debug/unsupported instruction marker (Python: `DebugEffect`).
    Debug {
        /// Address of the instruction.
        va: u64,
        /// Debug message.
        message: String,
    },
}

/// Snapshot of emulator variable and memory state.
///
/// Port of Python's `getSymSnapshot()` / `setSymSnapshot()`.
#[derive(Debug, Clone)]
pub struct EmulatorSnapshot {
    /// Variable state (register values).
    pub variables: std::collections::HashMap<String, SymbolicValue>,
    /// Memory state.
    pub memory: std::collections::BTreeMap<u64, SymbolicValue>,
}

impl SymbolicEffect {
    /// Get the virtual address of the instruction that produced this effect.
    pub fn va(&self) -> u64 {
        match self {
            SymbolicEffect::SetVariable { va, .. } => *va,
            SymbolicEffect::ReadMemory { va, .. } => *va,
            SymbolicEffect::WriteMemory { va, .. } => *va,
            SymbolicEffect::ConstrainPath { va, .. } => *va,
            SymbolicEffect::CallFunction { va, .. } => *va,
            SymbolicEffect::Debug { va, .. } => *va,
        }
    }

    /// Check if this effect modifies a specific variable.
    pub fn sets_variable(&self, var_name: &str) -> bool {
        matches!(self, SymbolicEffect::SetVariable { name, .. } if name == var_name)
    }

    /// Check if this effect writes to memory.
    pub fn is_memory_write(&self) -> bool {
        matches!(self, SymbolicEffect::WriteMemory { .. })
    }

    /// Check if this effect reads from memory.
    pub fn is_memory_read(&self) -> bool {
        matches!(self, SymbolicEffect::ReadMemory { .. })
    }

    /// Check if this effect is a function call.
    pub fn is_call(&self) -> bool {
        matches!(self, SymbolicEffect::CallFunction { .. })
    }

    /// Check if this effect is a path constraint.
    pub fn is_constraint(&self) -> bool {
        matches!(self, SymbolicEffect::ConstrainPath { .. })
    }

    /// Reduce all symbolic values in this effect.
    ///
    /// Port of Python's `effect.reduce(emu)`.
    pub fn reduced(&self) -> SymbolicEffect {
        match self {
            SymbolicEffect::SetVariable { va, name, value } => SymbolicEffect::SetVariable {
                va: *va,
                name: name.clone(),
                value: reduce(value),
            },
            SymbolicEffect::ReadMemory { va, addr, size } => SymbolicEffect::ReadMemory {
                va: *va,
                addr: reduce(addr),
                size: *size,
            },
            SymbolicEffect::WriteMemory {
                va,
                addr,
                size,
                value,
            } => SymbolicEffect::WriteMemory {
                va: *va,
                addr: reduce(addr),
                size: *size,
                value: reduce(value),
            },
            SymbolicEffect::ConstrainPath { va, constraint } => SymbolicEffect::ConstrainPath {
                va: *va,
                constraint: reduce(constraint),
            },
            SymbolicEffect::CallFunction { va, target, args } => SymbolicEffect::CallFunction {
                va: *va,
                target: target.clone(),
                args: args.iter().map(reduce).collect(),
            },
            SymbolicEffect::Debug { .. } => self.clone(),
        }
    }

    /// Get the variable name if this is a SetVariable effect.
    #[must_use]
    pub fn variable_name(&self) -> Option<&str> {
        match self {
            SymbolicEffect::SetVariable { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Get the value if this is a SetVariable effect.
    #[must_use]
    pub fn variable_value(&self) -> Option<&SymbolicValue> {
        match self {
            SymbolicEffect::SetVariable { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Get the write address and value if this is a WriteMemory effect.
    #[must_use]
    pub fn write_info(&self) -> Option<(&SymbolicValue, u8, &SymbolicValue)> {
        match self {
            SymbolicEffect::WriteMemory {
                addr, size, value, ..
            } => Some((addr, *size, value)),
            _ => None,
        }
    }

    /// Get the call target and args if this is a CallFunction effect.
    #[must_use]
    pub fn call_info(&self) -> Option<(&str, &[SymbolicValue])> {
        match self {
            SymbolicEffect::CallFunction { target, args, .. } => Some((target, args)),
            _ => None,
        }
    }
}

impl fmt::Display for SymbolicEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolicEffect::SetVariable { va, name, value } => {
                write!(f, "{:#x}: {} = {}", va, name, value)
            }
            SymbolicEffect::ReadMemory { va, addr, size } => {
                write!(f, "{:#x}: read [{}]:{}", va, addr, size)
            }
            SymbolicEffect::WriteMemory {
                va,
                addr,
                size,
                value,
            } => {
                write!(f, "{:#x}: [{}]:{} = {}", va, addr, size, value)
            }
            SymbolicEffect::ConstrainPath { va, constraint } => {
                write!(f, "{:#x}: constrain({})", va, constraint)
            }
            SymbolicEffect::CallFunction { va, target, args } => {
                let arg_strs: Vec<String> = args.iter().map(|a| format!("{}", a)).collect();
                write!(f, "{:#x}: call {}({})", va, target, arg_strs.join(", "))
            }
            SymbolicEffect::Debug { va, message } => {
                write!(f, "{:#x}: DEBUG: {}", va, message)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_variable_effect() {
        let effect = SymbolicEffect::SetVariable {
            va: 0x401000,
            name: "rax".to_string(),
            value: SymbolicValue::constant(42, 8),
        };
        assert_eq!(effect.va(), 0x401000);
        assert!(effect.sets_variable("rax"));
        assert!(!effect.sets_variable("rbx"));
    }

    #[test]
    fn test_write_memory_effect() {
        let effect = SymbolicEffect::WriteMemory {
            va: 0x401004,
            addr: SymbolicValue::var("rsp", 8),
            size: 8,
            value: SymbolicValue::var("rbp", 8),
        };
        assert!(effect.is_memory_write());
        assert!(!effect.is_call());
    }

    #[test]
    fn test_call_effect() {
        let effect = SymbolicEffect::CallFunction {
            va: 0x401008,
            target: "printf".to_string(),
            args: vec![
                SymbolicValue::constant(0x402000, 8),
                SymbolicValue::var("rsi", 8),
            ],
        };
        assert!(effect.is_call());
        assert!(!effect.is_memory_write());
    }

    #[test]
    fn test_effect_display() {
        let effect = SymbolicEffect::SetVariable {
            va: 0x401000,
            name: "rax".to_string(),
            value: SymbolicValue::add(SymbolicValue::var("rbx", 8), SymbolicValue::constant(1, 8)),
        };
        let s = format!("{}", effect);
        assert!(s.contains("rax"));
        assert!(s.contains("rbx"));
    }

    #[test]
    fn test_effect_reduced() {
        let effect = SymbolicEffect::SetVariable {
            va: 0x401000,
            name: "rax".to_string(),
            value: SymbolicValue::add(SymbolicValue::constant(3, 8), SymbolicValue::constant(4, 8)),
        };
        let reduced = effect.reduced();
        match reduced {
            SymbolicEffect::SetVariable { value, .. } => {
                assert_eq!(value.as_const(), Some(7));
            }
            _ => panic!("Expected SetVariable"),
        }
    }

    #[test]
    fn test_accessor_methods() {
        let effect = SymbolicEffect::SetVariable {
            va: 0x401000,
            name: "rax".to_string(),
            value: SymbolicValue::constant(42, 8),
        };
        assert_eq!(effect.variable_name(), Some("rax"));
        assert_eq!(effect.variable_value().unwrap().as_const(), Some(42));

        let call = SymbolicEffect::CallFunction {
            va: 0x401008,
            target: "puts".to_string(),
            args: vec![SymbolicValue::var("rdi", 8)],
        };
        let (target, args) = call.call_info().unwrap();
        assert_eq!(target, "puts");
        assert_eq!(args.len(), 1);
    }

    #[test]
    fn test_debug_effect() {
        let effect = SymbolicEffect::Debug {
            va: 0x401000,
            message: "unsupported: vmovaps".to_string(),
        };
        assert_eq!(effect.va(), 0x401000);
        let s = format!("{}", effect);
        assert!(s.contains("vmovaps"));
    }
}
