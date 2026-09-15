//! Symbolic value representation.
//!
//! Port of Python vivisect's `symboliks/common.py`.
//! Models values that flow through a program during symbolic execution.
//! Each value is either concrete (known constant), symbolic (unknown),
//! or a compound expression built from operations on other values.
//!
//! Key difference from Python: Rust uses an enum rather than a class
//! hierarchy, but the semantics match:
//! - `Const` → Python `Const`
//! - `Var` → Python `Var`
//! - `Arg` → Python `Arg`
//! - `Mem` → Python `Mem`
//! - `Oper` → Python operator classes (`o_add`, `o_sub`, etc.)
//! - `Call` → Python `Call`
//! - `Constraint` → Python constraint classes (`eq`, `ne`, `lt`, etc.)

use std::fmt;
use std::hash::{Hash, Hasher};

/// Arithmetic/logic operations on symbolic values.
///
/// Maps to Python's `o_add`, `o_sub`, `o_mul`, etc. operator classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// Addition (Python: `o_add`)
    Add,
    /// Subtraction (Python: `o_sub`)
    Sub,
    /// Multiplication (Python: `o_mul`)
    Mul,
    /// Unsigned division (Python: `o_div`)
    Div,
    /// Modulo (Python: `o_mod`)
    Mod,
    /// Bitwise AND (Python: `o_and`)
    And,
    /// Bitwise OR (Python: `o_or`)
    Or,
    /// Bitwise XOR (Python: `o_xor`)
    Xor,
    /// Left shift (Python: `o_lshift`)
    Shl,
    /// Logical right shift (Python: `o_rshift`)
    Shr,
    /// Arithmetic right shift
    Sar,
    /// Bitwise NOT (Python: `cnot`, unary)
    Not,
    /// Negation (unary)
    Neg,
    /// Sign-extend (Python: `o_sextend`)
    SignExtend,
    /// Zero-extend
    ZeroExtend,
    /// Power (Python: `o_pow`)
    Pow,
}

/// Constraint/predicate operations (Python: `eq`, `ne`, `lt`, `gt`, `le`, `ge`).
///
/// These map to Python's constraint classes that represent branch conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintOp {
    /// Equal (Python: `eq`)
    Eq,
    /// Not equal (Python: `ne`)
    Ne,
    /// Less than (Python: `lt`)
    Lt,
    /// Less than or equal (Python: `le`)
    Le,
    /// Greater than (Python: `gt`)
    Gt,
    /// Greater than or equal (Python: `ge`)
    Ge,
    /// Unsigned less than
    Ult,
    /// Unsigned greater than
    Ugt,
}

impl ConstraintOp {
    /// Get the opposite constraint (Python's `getInverse`).
    pub fn inverse(self) -> Self {
        match self {
            ConstraintOp::Eq => ConstraintOp::Ne,
            ConstraintOp::Ne => ConstraintOp::Eq,
            ConstraintOp::Lt => ConstraintOp::Ge,
            ConstraintOp::Le => ConstraintOp::Gt,
            ConstraintOp::Gt => ConstraintOp::Le,
            ConstraintOp::Ge => ConstraintOp::Lt,
            ConstraintOp::Ult => ConstraintOp::Ugt,
            ConstraintOp::Ugt => ConstraintOp::Ult,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Add => write!(f, "+"),
            Op::Sub => write!(f, "-"),
            Op::Mul => write!(f, "*"),
            Op::Div => write!(f, "/"),
            Op::Mod => write!(f, "%"),
            Op::And => write!(f, "&"),
            Op::Or => write!(f, "|"),
            Op::Xor => write!(f, "^"),
            Op::Shl => write!(f, "<<"),
            Op::Shr => write!(f, ">>"),
            Op::Sar => write!(f, ">>>"),
            Op::Not => write!(f, "~"),
            Op::Neg => write!(f, "-"),
            Op::SignExtend => write!(f, "sext"),
            Op::ZeroExtend => write!(f, "zext"),
            Op::Pow => write!(f, "**"),
        }
    }
}

impl fmt::Display for ConstraintOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstraintOp::Eq => write!(f, "=="),
            ConstraintOp::Ne => write!(f, "!="),
            ConstraintOp::Lt => write!(f, "<"),
            ConstraintOp::Le => write!(f, "<="),
            ConstraintOp::Gt => write!(f, ">"),
            ConstraintOp::Ge => write!(f, ">="),
            ConstraintOp::Ult => write!(f, "<u"),
            ConstraintOp::Ugt => write!(f, ">u"),
        }
    }
}

/// A symbolic value in the execution state.
///
/// Port of Python's SymbolikBase hierarchy. Values form an expression
/// tree that represents how a result was computed from initial symbolic
/// inputs.
///
/// Python class mapping:
/// - `Const` → `common.Const`
/// - `Var` → `common.Var`
/// - `Arg` → `common.Arg` (function arguments for cross-boundary analysis)
/// - `Mem` → `common.Mem`
/// - `Oper` → `common.Operator` subclasses
/// - `Call` → `common.Call`
/// - `Constraint` → `common.eq`/`ne`/`lt`/`gt`/`le`/`ge`
#[derive(Debug, Clone)]
pub enum SymbolicValue {
    /// A known constant value (Python: `Const`).
    Const {
        /// The concrete value.
        value: u64,
        /// Width in bytes (1, 2, 4, 8).
        width: u8,
    },

    /// A symbolic variable — register or named value (Python: `Var`).
    Var {
        /// Variable name (e.g., "rax", "eflags").
        name: String,
        /// Width in bytes.
        width: u8,
    },

    /// A function argument (Python: `Arg`).
    ///
    /// Distinct from Var so we can track which function inputs
    /// flow to which outputs during cross-function analysis.
    Arg {
        /// Argument index (0-based).
        index: usize,
        /// Width in bytes.
        width: u8,
    },

    /// A memory dereference (Python: `Mem`).
    Mem {
        /// Address expression.
        addr: Box<SymbolicValue>,
        /// Read size in bytes.
        width: u8,
    },

    /// A binary or unary operation (Python: `Operator` subclasses).
    Oper {
        /// The operation.
        op: Op,
        /// Left-hand operand.
        lhs: Box<SymbolicValue>,
        /// Right-hand operand (Const(0,0) for unary ops).
        rhs: Box<SymbolicValue>,
    },

    /// A function call result (Python: `Call`).
    Call {
        /// Target address or name.
        target: String,
        /// Arguments passed to the call.
        args: Vec<SymbolicValue>,
        /// Return value width in bytes.
        width: u8,
    },

    /// A constraint/predicate (Python: `eq`, `ne`, `lt`, `gt`, `le`, `ge`).
    ///
    /// Represents a branch condition. Used for path constraint tracking.
    Constraint {
        /// The comparison operation.
        op: ConstraintOp,
        /// Left-hand side.
        lhs: Box<SymbolicValue>,
        /// Right-hand side.
        rhs: Box<SymbolicValue>,
    },
}

impl SymbolicValue {
    /// Create a constant value.
    pub fn constant(value: u64, width: u8) -> Self {
        SymbolicValue::Const { value, width }
    }

    /// Create a symbolic variable.
    pub fn var(name: impl Into<String>, width: u8) -> Self {
        SymbolicValue::Var {
            name: name.into(),
            width,
        }
    }

    /// Create a function argument (Python: `Arg(idx, width)`).
    pub fn arg(index: usize, width: u8) -> Self {
        SymbolicValue::Arg { index, width }
    }

    /// Create a memory read.
    pub fn mem(addr: SymbolicValue, width: u8) -> Self {
        SymbolicValue::Mem {
            addr: Box::new(addr),
            width,
        }
    }

    /// Create a binary operation.
    pub fn oper(op: Op, lhs: SymbolicValue, rhs: SymbolicValue) -> Self {
        SymbolicValue::Oper {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Create a constraint.
    pub fn constraint(op: ConstraintOp, lhs: SymbolicValue, rhs: SymbolicValue) -> Self {
        SymbolicValue::Constraint {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        }
    }

    /// Create an addition.
    pub fn add(lhs: SymbolicValue, rhs: SymbolicValue) -> Self {
        Self::oper(Op::Add, lhs, rhs)
    }

    /// Create a subtraction.
    pub fn sub(lhs: SymbolicValue, rhs: SymbolicValue) -> Self {
        Self::oper(Op::Sub, lhs, rhs)
    }

    /// Check if this is a concrete constant (Python: `isDiscrete`).
    pub fn is_discrete(&self) -> bool {
        match self {
            SymbolicValue::Const { .. } => true,
            SymbolicValue::Oper { lhs, rhs, .. } => lhs.is_discrete() && rhs.is_discrete(),
            SymbolicValue::Constraint { lhs, rhs, .. } => lhs.is_discrete() && rhs.is_discrete(),
            _ => false,
        }
    }

    /// Check if this is a concrete constant.
    pub fn is_const(&self) -> bool {
        matches!(self, SymbolicValue::Const { .. })
    }

    /// Try to extract the concrete value.
    #[must_use]
    pub fn as_const(&self) -> Option<u64> {
        match self {
            SymbolicValue::Const { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Get the width in bytes.
    pub fn width(&self) -> u8 {
        match self {
            SymbolicValue::Const { width, .. } => *width,
            SymbolicValue::Var { width, .. } => *width,
            SymbolicValue::Arg { width, .. } => *width,
            SymbolicValue::Mem { width, .. } => *width,
            SymbolicValue::Oper { lhs, .. } => lhs.width(),
            SymbolicValue::Call { width, .. } => *width,
            SymbolicValue::Constraint { .. } => 1, // Bool
        }
    }

    /// Solve to a deterministic value (Python: `solve`/`varsolve`).
    ///
    /// Uses MD5 hash of variable names to produce deterministic values,
    /// matching Python's behavior where each Var hashes to a stable
    /// numeric value for comparison.
    pub fn solve(&self) -> u64 {
        match self {
            SymbolicValue::Const { value, .. } => *value,
            SymbolicValue::Var { name, width } => varsolve(name, *width),
            SymbolicValue::Arg { index, width } => varsolve(&format!("arg{}", index), *width),
            SymbolicValue::Mem { addr, .. } => {
                // Hash-based solve of the address
                addr.solve().wrapping_mul(0x9e3779b97f4a7c15)
            }
            SymbolicValue::Oper { op, lhs, rhs } => {
                let l = lhs.solve();
                let r = rhs.solve();
                solve_op(*op, l, r)
            }
            SymbolicValue::Call { target, args, .. } => {
                let mut h = varsolve(target, 8);
                for arg in args {
                    h = h.wrapping_add(arg.solve());
                }
                h
            }
            SymbolicValue::Constraint { op, lhs, rhs } => {
                let l = lhs.solve();
                let r = rhs.solve();
                match op {
                    ConstraintOp::Eq => {
                        if l == r {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Ne => {
                        if l != r {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Lt => {
                        if (l as i64) < (r as i64) {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Le => {
                        if (l as i64) <= (r as i64) {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Gt => {
                        if (l as i64) > (r as i64) {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Ge => {
                        if (l as i64) >= (r as i64) {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Ult => {
                        if l < r {
                            1
                        } else {
                            0
                        }
                    }
                    ConstraintOp::Ugt => {
                        if l > r {
                            1
                        } else {
                            0
                        }
                    }
                }
            }
        }
    }

    /// Walk the expression tree, calling the callback for each node.
    ///
    /// Port of Python's `walkTree(cb, ctx)`.
    pub fn walk_tree(&self, cb: &mut dyn FnMut(&SymbolicValue)) {
        cb(self);
        match self {
            SymbolicValue::Mem { addr, .. } => addr.walk_tree(cb),
            SymbolicValue::Oper { lhs, rhs, .. } => {
                lhs.walk_tree(cb);
                rhs.walk_tree(cb);
            }
            SymbolicValue::Call { args, .. } => {
                for arg in args {
                    arg.walk_tree(cb);
                }
            }
            SymbolicValue::Constraint { lhs, rhs, .. } => {
                lhs.walk_tree(cb);
                rhs.walk_tree(cb);
            }
            _ => {}
        }
    }

    /// Substitute all occurrences of a named variable with a value.
    ///
    /// Port of Python's expression substitution pattern. Creates a new
    /// expression tree with all `Var(name)` nodes replaced by `replacement`.
    pub fn substitute(&self, var_name: &str, replacement: &SymbolicValue) -> SymbolicValue {
        match self {
            SymbolicValue::Var { name, .. } if name == var_name => replacement.clone(),
            SymbolicValue::Const { .. } | SymbolicValue::Var { .. } | SymbolicValue::Arg { .. } => {
                self.clone()
            }
            SymbolicValue::Mem { addr, width } => SymbolicValue::Mem {
                addr: Box::new(addr.substitute(var_name, replacement)),
                width: *width,
            },
            SymbolicValue::Oper { op, lhs, rhs } => SymbolicValue::Oper {
                op: *op,
                lhs: Box::new(lhs.substitute(var_name, replacement)),
                rhs: Box::new(rhs.substitute(var_name, replacement)),
            },
            SymbolicValue::Constraint { op, lhs, rhs } => SymbolicValue::Constraint {
                op: *op,
                lhs: Box::new(lhs.substitute(var_name, replacement)),
                rhs: Box::new(rhs.substitute(var_name, replacement)),
            },
            SymbolicValue::Call {
                target,
                args,
                width,
            } => SymbolicValue::Call {
                target: target.clone(),
                args: args
                    .iter()
                    .map(|a| a.substitute(var_name, replacement))
                    .collect(),
                width: *width,
            },
        }
    }

    /// Apply a transformation function to every node in the tree (bottom-up).
    ///
    /// The transformer receives each node and can return Some(new_node) to replace
    /// it, or None to keep the original. Children are transformed first.
    #[must_use]
    pub fn transform(&self, f: &dyn Fn(&SymbolicValue) -> Option<SymbolicValue>) -> SymbolicValue {
        // Transform children first (bottom-up)
        let transformed = match self {
            SymbolicValue::Mem { addr, width } => SymbolicValue::Mem {
                addr: Box::new(addr.transform(f)),
                width: *width,
            },
            SymbolicValue::Oper { op, lhs, rhs } => SymbolicValue::Oper {
                op: *op,
                lhs: Box::new(lhs.transform(f)),
                rhs: Box::new(rhs.transform(f)),
            },
            SymbolicValue::Constraint { op, lhs, rhs } => SymbolicValue::Constraint {
                op: *op,
                lhs: Box::new(lhs.transform(f)),
                rhs: Box::new(rhs.transform(f)),
            },
            SymbolicValue::Call {
                target,
                args,
                width,
            } => SymbolicValue::Call {
                target: target.clone(),
                args: args.iter().map(|a| a.transform(f)).collect(),
                width: *width,
            },
            other => other.clone(),
        };

        // Apply transformer to this node
        f(&transformed).unwrap_or(transformed)
    }

    /// Collect all variable names referenced in this expression.
    pub fn collect_variables(&self) -> std::collections::HashSet<String> {
        let mut vars = std::collections::HashSet::new();
        self.walk_tree(&mut |node| {
            if let SymbolicValue::Var { name, .. } = node {
                vars.insert(name.clone());
            }
        });
        vars
    }

    /// Compute a structural hash for comparison.
    /// Two structurally equivalent expressions will have the same hash.
    pub fn structural_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash_structure(&mut hasher);
        hasher.finish()
    }

    fn hash_structure(&self, hasher: &mut impl Hasher) {
        match self {
            SymbolicValue::Const { value, width } => {
                0u8.hash(hasher);
                value.hash(hasher);
                width.hash(hasher);
            }
            SymbolicValue::Var { name, width } => {
                1u8.hash(hasher);
                name.hash(hasher);
                width.hash(hasher);
            }
            SymbolicValue::Arg { index, width } => {
                5u8.hash(hasher);
                index.hash(hasher);
                width.hash(hasher);
            }
            SymbolicValue::Mem { addr, width } => {
                2u8.hash(hasher);
                addr.hash_structure(hasher);
                width.hash(hasher);
            }
            SymbolicValue::Oper { op, lhs, rhs } => {
                3u8.hash(hasher);
                op.hash(hasher);
                lhs.hash_structure(hasher);
                rhs.hash_structure(hasher);
            }
            SymbolicValue::Call { target, args, .. } => {
                4u8.hash(hasher);
                target.hash(hasher);
                for arg in args {
                    arg.hash_structure(hasher);
                }
            }
            SymbolicValue::Constraint { op, lhs, rhs } => {
                6u8.hash(hasher);
                op.hash(hasher);
                lhs.hash_structure(hasher);
                rhs.hash_structure(hasher);
            }
        }
    }

    /// Check structural equivalence (ignoring concrete constant values,
    /// comparing only the shape of the expression tree).
    ///
    /// This is used for comparing function summaries across binaries
    /// where the same computation may use different constant addresses.
    pub fn structurally_equivalent(&self, other: &SymbolicValue) -> bool {
        match (self, other) {
            (SymbolicValue::Const { width: w1, .. }, SymbolicValue::Const { width: w2, .. }) => {
                w1 == w2
            }
            (
                SymbolicValue::Var {
                    name: n1,
                    width: w1,
                },
                SymbolicValue::Var {
                    name: n2,
                    width: w2,
                },
            ) => n1 == n2 && w1 == w2,
            (
                SymbolicValue::Arg {
                    index: i1,
                    width: w1,
                },
                SymbolicValue::Arg {
                    index: i2,
                    width: w2,
                },
            ) => i1 == i2 && w1 == w2,
            (
                SymbolicValue::Mem {
                    addr: a1,
                    width: w1,
                },
                SymbolicValue::Mem {
                    addr: a2,
                    width: w2,
                },
            ) => w1 == w2 && a1.structurally_equivalent(a2),
            (
                SymbolicValue::Oper {
                    op: o1,
                    lhs: l1,
                    rhs: r1,
                },
                SymbolicValue::Oper {
                    op: o2,
                    lhs: l2,
                    rhs: r2,
                },
            ) => o1 == o2 && l1.structurally_equivalent(l2) && r1.structurally_equivalent(r2),
            (
                SymbolicValue::Call {
                    target: t1,
                    args: a1,
                    ..
                },
                SymbolicValue::Call {
                    target: t2,
                    args: a2,
                    ..
                },
            ) => {
                t1 == t2
                    && a1.len() == a2.len()
                    && a1
                        .iter()
                        .zip(a2.iter())
                        .all(|(x, y)| x.structurally_equivalent(y))
            }
            (
                SymbolicValue::Constraint {
                    op: o1,
                    lhs: l1,
                    rhs: r1,
                },
                SymbolicValue::Constraint {
                    op: o2,
                    lhs: l2,
                    rhs: r2,
                },
            ) => o1 == o2 && l1.structurally_equivalent(l2) && r1.structurally_equivalent(r2),
            _ => false,
        }
    }

    /// Normalize for architecture-independent comparison.
    ///
    /// Port of Python's `archind.wipeAstArch()`.
    /// Replaces register names with generic `regN` names based on
    /// first-occurrence order, enabling cross-architecture comparison.
    pub fn normalize_arch_independent(&self) -> SymbolicValue {
        let mut reg_map = std::collections::HashMap::new();
        let mut counter = 0usize;
        self.normalize_inner(&mut reg_map, &mut counter)
    }

    fn normalize_inner(
        &self,
        reg_map: &mut std::collections::HashMap<String, usize>,
        counter: &mut usize,
    ) -> SymbolicValue {
        match self {
            SymbolicValue::Const { .. } => self.clone(),
            SymbolicValue::Var { name, width } => {
                let idx = reg_map.entry(name.clone()).or_insert_with(|| {
                    let c = *counter;
                    *counter += 1;
                    c
                });
                SymbolicValue::var(format!("reg{}", idx), *width)
            }
            SymbolicValue::Arg { .. } => self.clone(),
            SymbolicValue::Mem { addr, width } => {
                SymbolicValue::mem(addr.normalize_inner(reg_map, counter), *width)
            }
            SymbolicValue::Oper { op, lhs, rhs } => SymbolicValue::oper(
                *op,
                lhs.normalize_inner(reg_map, counter),
                rhs.normalize_inner(reg_map, counter),
            ),
            SymbolicValue::Call {
                target,
                args,
                width,
            } => SymbolicValue::Call {
                target: target.clone(),
                args: args
                    .iter()
                    .map(|a| a.normalize_inner(reg_map, counter))
                    .collect(),
                width: *width,
            },
            SymbolicValue::Constraint { op, lhs, rhs } => SymbolicValue::constraint(
                *op,
                lhs.normalize_inner(reg_map, counter),
                rhs.normalize_inner(reg_map, counter),
            ),
        }
    }
}

/// Compute a deterministic hash for a variable name.
///
/// Port of Python's `varsolve()` which uses MD5 hash of the name
/// to produce a stable numeric value for each variable.
fn varsolve(name: &str, width: u8) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let raw = hasher.finish();
    let mask = if width >= 8 {
        u64::MAX
    } else {
        (1u64 << (width as u64 * 8)) - 1
    };
    raw & mask
}

/// Solve an operation on two concrete values.
fn solve_op(op: Op, lhs: u64, rhs: u64) -> u64 {
    match op {
        Op::Add => lhs.wrapping_add(rhs),
        Op::Sub => lhs.wrapping_sub(rhs),
        Op::Mul => lhs.wrapping_mul(rhs),
        Op::Div => {
            if rhs == 0 {
                0
            } else {
                lhs / rhs
            }
        }
        Op::Mod => {
            if rhs == 0 {
                0
            } else {
                lhs % rhs
            }
        }
        Op::And => lhs & rhs,
        Op::Or => lhs | rhs,
        Op::Xor => lhs ^ rhs,
        Op::Shl => lhs.wrapping_shl(rhs as u32),
        Op::Shr => lhs.wrapping_shr(rhs as u32),
        Op::Sar => ((lhs as i64).wrapping_shr(rhs as u32)) as u64,
        Op::Not => !lhs,
        Op::Neg => (-(lhs as i64)) as u64,
        Op::SignExtend => lhs, // Simplified
        Op::ZeroExtend => lhs,
        Op::Pow => lhs.wrapping_pow(rhs as u32),
    }
}

impl fmt::Display for SymbolicValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolicValue::Const { value, width } => {
                write!(f, "{:#x}:{}", value, width)
            }
            SymbolicValue::Var { name, width } => {
                write!(f, "{}:{}", name, width)
            }
            SymbolicValue::Arg { index, width } => {
                write!(f, "arg{}:{}", index, width)
            }
            SymbolicValue::Mem { addr, width } => {
                write!(f, "[{}]:{}", addr, width)
            }
            SymbolicValue::Oper { op, lhs, rhs } => match op {
                Op::Not | Op::Neg => write!(f, "({} {})", op, lhs),
                _ => write!(f, "({} {} {})", lhs, op, rhs),
            },
            SymbolicValue::Call { target, args, .. } => {
                let arg_strs: Vec<String> = args.iter().map(|a| format!("{}", a)).collect();
                write!(f, "{}({})", target, arg_strs.join(", "))
            }
            SymbolicValue::Constraint { op, lhs, rhs } => {
                write!(f, "({} {} {})", lhs, op, rhs)
            }
        }
    }
}

impl PartialEq for SymbolicValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                SymbolicValue::Const {
                    value: v1,
                    width: w1,
                },
                SymbolicValue::Const {
                    value: v2,
                    width: w2,
                },
            ) => v1 == v2 && w1 == w2,
            (
                SymbolicValue::Var {
                    name: n1,
                    width: w1,
                },
                SymbolicValue::Var {
                    name: n2,
                    width: w2,
                },
            ) => n1 == n2 && w1 == w2,
            (
                SymbolicValue::Arg {
                    index: i1,
                    width: w1,
                },
                SymbolicValue::Arg {
                    index: i2,
                    width: w2,
                },
            ) => i1 == i2 && w1 == w2,
            _ => self.solve() == other.solve(),
        }
    }
}

impl Eq for SymbolicValue {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_const_creation() {
        let v = SymbolicValue::constant(42, 4);
        assert!(v.is_const());
        assert!(v.is_discrete());
        assert_eq!(v.as_const(), Some(42));
        assert_eq!(v.width(), 4);
    }

    #[test]
    fn test_var_creation() {
        let v = SymbolicValue::var("rax", 8);
        assert!(!v.is_const());
        assert!(!v.is_discrete());
        assert_eq!(v.as_const(), None);
        assert_eq!(v.width(), 8);
    }

    #[test]
    fn test_arg_creation() {
        let a = SymbolicValue::arg(0, 8);
        assert!(matches!(a, SymbolicValue::Arg { index: 0, width: 8 }));
        assert_eq!(format!("{}", a), "arg0:8");
    }

    #[test]
    fn test_display() {
        let c = SymbolicValue::constant(0x10, 4);
        assert_eq!(format!("{}", c), "0x10:4");

        let v = SymbolicValue::var("rax", 8);
        assert_eq!(format!("{}", v), "rax:8");

        let add = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        assert_eq!(format!("{}", add), "(rax:8 + 0x4:8)");
    }

    #[test]
    fn test_constraint_display() {
        let c = SymbolicValue::constraint(
            ConstraintOp::Eq,
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(0, 8),
        );
        assert_eq!(format!("{}", c), "(rax:8 == 0x0:8)");
    }

    #[test]
    fn test_constraint_inverse() {
        assert_eq!(ConstraintOp::Eq.inverse(), ConstraintOp::Ne);
        assert_eq!(ConstraintOp::Lt.inverse(), ConstraintOp::Ge);
        assert_eq!(ConstraintOp::Gt.inverse(), ConstraintOp::Le);
    }

    #[test]
    fn test_solve_deterministic() {
        let v = SymbolicValue::var("rax", 8);
        let solve1 = v.solve();
        let solve2 = v.solve();
        assert_eq!(solve1, solve2);
    }

    #[test]
    fn test_solve_const() {
        let c = SymbolicValue::constant(42, 4);
        assert_eq!(c.solve(), 42);
    }

    #[test]
    fn test_solve_add() {
        let expr = SymbolicValue::add(SymbolicValue::constant(3, 8), SymbolicValue::constant(4, 8));
        assert_eq!(expr.solve(), 7);
    }

    #[test]
    fn test_structural_equivalence() {
        let a = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        let b = SymbolicValue::add(
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(8, 8), // Different constant value
        );
        // Structurally equivalent: both are (var + const)
        assert!(a.structurally_equivalent(&b));
    }

    #[test]
    fn test_structural_non_equivalence() {
        let a = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        let b = SymbolicValue::sub(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        assert!(!a.structurally_equivalent(&b));
    }

    #[test]
    fn test_mem_value() {
        let addr = SymbolicValue::add(
            SymbolicValue::var("rbp", 8),
            SymbolicValue::constant(0x10, 8),
        );
        let mem = SymbolicValue::mem(addr, 4);
        assert_eq!(mem.width(), 4);
        assert_eq!(format!("{}", mem), "[(rbp:8 + 0x10:8)]:4");
    }

    #[test]
    fn test_walk_tree() {
        let expr = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        let mut count = 0;
        expr.walk_tree(&mut |_| count += 1);
        assert_eq!(count, 3); // add, var, const
    }

    #[test]
    fn test_normalize_arch_independent() {
        // (rax + rbx) should normalize to (reg0 + reg1)
        let expr = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::var("rbx", 8));
        let normalized = expr.normalize_arch_independent();
        let s = format!("{}", normalized);
        assert!(s.contains("reg0"));
        assert!(s.contains("reg1"));
        assert!(!s.contains("rax"));
        assert!(!s.contains("rbx"));
    }

    #[test]
    fn test_normalize_preserves_args() {
        // arg0 should stay as arg0 after normalization
        let expr = SymbolicValue::add(SymbolicValue::arg(0, 8), SymbolicValue::var("rax", 8));
        let normalized = expr.normalize_arch_independent();
        let s = format!("{}", normalized);
        assert!(s.contains("arg0"));
    }

    #[test]
    fn test_is_discrete() {
        // Pure constants are discrete
        assert!(SymbolicValue::constant(42, 4).is_discrete());

        // Operations on constants are discrete
        let expr = SymbolicValue::add(SymbolicValue::constant(3, 4), SymbolicValue::constant(4, 4));
        assert!(expr.is_discrete());

        // Variables are not discrete
        assert!(!SymbolicValue::var("rax", 8).is_discrete());

        // Operations involving variables are not discrete
        let expr = SymbolicValue::add(SymbolicValue::var("rax", 8), SymbolicValue::constant(4, 8));
        assert!(!expr.is_discrete());
    }
}
