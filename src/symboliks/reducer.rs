//! Expression simplification and reduction.
//!
//! Port of Python vivisect's `symboliks/reducers.py`.
//! Implements constant folding, algebraic identity simplifications,
//! and constraint reduction for symbolic expressions.
//!
//! Python's reducer system uses pattern matching via `ismatch()` and
//! `reduceoper()`. This Rust port uses direct match arms for the same
//! effect, covering:
//! - Constant folding (both operands concrete)
//! - Identity operations (x + 0, x * 1, x & ~0, x | 0, x ^ 0)
//! - Annihilation (x * 0, x & 0)
//! - Self-cancellation (x - x, x ^ x)
//! - Double negation (~~x, --x)
//! - Shift simplifications (x << 0, x >> 0)
//! - Idempotent ops (x & x, x | x)
//! - Constant strength reduction (x * power_of_2 → x << log2)
//! - Constraint folding

use super::value::{ConstraintOp, Op, SymbolicValue};

/// Apply constant folding: if both operands are concrete, compute the result.
///
/// Port of the constant-folding path in Python's `reduceoper()`.
///
/// Uses `u128` intermediates for `Mul` and `Pow` to match Python's
/// arbitrary-precision arithmetic. While `wrapping_*` on `u64` gives
/// mathematically equivalent results after masking for widths ≤ 8, using
/// `u128` provides defense-in-depth and directly mirrors the Python
/// computation path (compute full-precision, then mask to width).
fn fold_constants(op: Op, lhs: u64, rhs: u64, width: u8) -> Option<u64> {
    let bits = width as u32 * 8;
    let mask: u128 = if bits >= 64 {
        u64::MAX as u128
    } else {
        (1u128 << bits) - 1
    };

    let result: u128 = match op {
        Op::Add => (lhs as u128).wrapping_add(rhs as u128),
        Op::Sub => (lhs as u128).wrapping_sub(rhs as u128),
        Op::Mul => (lhs as u128) * (rhs as u128),
        Op::Div => {
            if rhs == 0 {
                return None;
            }
            (lhs / rhs) as u128
        }
        Op::Mod => {
            if rhs == 0 {
                return None;
            }
            (lhs % rhs) as u128
        }
        Op::And => (lhs & rhs) as u128,
        Op::Or => (lhs | rhs) as u128,
        Op::Xor => (lhs ^ rhs) as u128,
        Op::Shl => {
            if rhs >= 128 {
                0
            } else {
                (lhs as u128) << (rhs as u32)
            }
        }
        Op::Shr => {
            if rhs >= 64 {
                0
            } else {
                (lhs >> (rhs as u32)) as u128
            }
        }
        Op::Sar => {
            let signed = lhs as i64;
            if rhs >= 64 {
                // Arithmetic shift fills with sign bit
                (if signed < 0 { u64::MAX } else { 0 }) as u128
            } else {
                (signed.wrapping_shr(rhs as u32) as u64) as u128
            }
        }
        Op::Not => (!lhs) as u128,
        Op::Neg => ((-(lhs as i64)) as u64) as u128,
        Op::SignExtend | Op::ZeroExtend => lhs as u128,
        Op::Pow => {
            // Use u128 to handle 2**64 and similar large powers correctly
            (lhs as u128).wrapping_pow(rhs as u32)
        }
    };

    Some((result & mask) as u64)
}

/// Fold a constraint with concrete operands.
fn fold_constraint(op: ConstraintOp, lhs: u64, rhs: u64) -> u64 {
    match op {
        ConstraintOp::Eq => if lhs == rhs { 1 } else { 0 },
        ConstraintOp::Ne => if lhs != rhs { 1 } else { 0 },
        ConstraintOp::Lt => if (lhs as i64) < (rhs as i64) { 1 } else { 0 },
        ConstraintOp::Le => if (lhs as i64) <= (rhs as i64) { 1 } else { 0 },
        ConstraintOp::Gt => if (lhs as i64) > (rhs as i64) { 1 } else { 0 },
        ConstraintOp::Ge => if (lhs as i64) >= (rhs as i64) { 1 } else { 0 },
        ConstraintOp::Ult => if lhs < rhs { 1 } else { 0 },
        ConstraintOp::Ugt => if lhs > rhs { 1 } else { 0 },
    }
}

/// Reduce a symbolic expression by applying simplifications.
///
/// Port of Python's `reduceoper()` and the reducer pipeline.
///
/// Simplifications applied:
/// - Constant folding (both operands constant)
/// - Identity operations (x + 0, x * 1, x | 0, x ^ 0)
/// - Annihilation (x * 0, x & 0)
/// - Self-cancellation (x - x, x ^ x)
/// - Idempotent operations (x & x = x, x | x = x)
/// - Double negation (~~x = x, --x = x)
/// - Shift simplifications (x << 0, x >> 0)
/// - Strength reduction (x * 2^n → x << n)
/// - Constraint reduction (constant constraint folding, x == x → 1)
pub fn reduce(value: &SymbolicValue) -> SymbolicValue {
    match value {
        SymbolicValue::Oper { op, lhs, rhs } => {
            // First, reduce children
            let lhs_reduced = reduce(lhs);
            let rhs_reduced = reduce(rhs);

            // Constant folding
            if let (Some(l), Some(r)) = (lhs_reduced.as_const(), rhs_reduced.as_const()) {
                let width = lhs_reduced.width();
                if let Some(result) = fold_constants(*op, l, r, width) {
                    return SymbolicValue::constant(result, width);
                }
            }

            // Algebraic identity simplifications
            match op {
                // x + 0 = x, 0 + x = x
                Op::Add if rhs_reduced.as_const() == Some(0) => return lhs_reduced,
                Op::Add if lhs_reduced.as_const() == Some(0) => return rhs_reduced,

                // x - 0 = x
                Op::Sub if rhs_reduced.as_const() == Some(0) => return lhs_reduced,

                // x * 1 = x, 1 * x = x
                Op::Mul if rhs_reduced.as_const() == Some(1) => return lhs_reduced,
                Op::Mul if lhs_reduced.as_const() == Some(1) => return rhs_reduced,

                // x * 0 = 0, 0 * x = 0
                Op::Mul if rhs_reduced.as_const() == Some(0) => {
                    return SymbolicValue::constant(0, lhs_reduced.width());
                }
                Op::Mul if lhs_reduced.as_const() == Some(0) => {
                    return SymbolicValue::constant(0, rhs_reduced.width());
                }

                // Strength reduction: x * 2^n → x << n (Python: reduceoper for o_mul)
                Op::Mul => {
                    if let Some(rval) = rhs_reduced.as_const() {
                        if rval > 0 && rval.is_power_of_two() {
                            let shift = rval.trailing_zeros() as u64;
                            return SymbolicValue::oper(
                                Op::Shl,
                                lhs_reduced,
                                SymbolicValue::constant(shift, rhs_reduced.width()),
                            );
                        }
                    }
                }

                // x & 0 = 0, 0 & x = 0
                Op::And if rhs_reduced.as_const() == Some(0) => {
                    return SymbolicValue::constant(0, lhs_reduced.width());
                }
                Op::And if lhs_reduced.as_const() == Some(0) => {
                    return SymbolicValue::constant(0, rhs_reduced.width());
                }

                // x | 0 = x, 0 | x = x
                Op::Or if rhs_reduced.as_const() == Some(0) => return lhs_reduced,
                Op::Or if lhs_reduced.as_const() == Some(0) => return rhs_reduced,

                // x ^ 0 = x
                Op::Xor if rhs_reduced.as_const() == Some(0) => return lhs_reduced,

                // x << 0 = x, x >> 0 = x, x >>> 0 = x
                Op::Shl if rhs_reduced.as_const() == Some(0) => return lhs_reduced,
                Op::Shr if rhs_reduced.as_const() == Some(0) => return lhs_reduced,
                Op::Sar if rhs_reduced.as_const() == Some(0) => return lhs_reduced,

                // x / 1 = x
                Op::Div if rhs_reduced.as_const() == Some(1) => return lhs_reduced,

                // 0 / x = 0 (when x != 0, but we can't prove that statically)
                // x % 1 = 0
                Op::Mod if rhs_reduced.as_const() == Some(1) => {
                    return SymbolicValue::constant(0, lhs_reduced.width());
                }

                // x ** 0 = 1
                Op::Pow if rhs_reduced.as_const() == Some(0) => {
                    return SymbolicValue::constant(1, lhs_reduced.width());
                }
                // x ** 1 = x
                Op::Pow if rhs_reduced.as_const() == Some(1) => return lhs_reduced,

                _ => {}
            }

            // Self-cancellation: x - x = 0, x ^ x = 0
            if matches!(op, Op::Sub | Op::Xor) {
                if lhs_reduced == rhs_reduced {
                    return SymbolicValue::constant(0, lhs_reduced.width());
                }
            }

            // Idempotent: x & x = x, x | x = x
            if matches!(op, Op::And | Op::Or) {
                if lhs_reduced == rhs_reduced {
                    return lhs_reduced;
                }
            }

            // Double negation: ~~x = x (Python: cnot(cnot(x)) → x)
            if *op == Op::Not {
                if let SymbolicValue::Oper {
                    op: Op::Not,
                    lhs: inner,
                    ..
                } = &lhs_reduced
                {
                    return (**inner).clone();
                }
            }

            // Double negation: --x = x
            if *op == Op::Neg {
                if let SymbolicValue::Oper {
                    op: Op::Neg,
                    lhs: inner,
                    ..
                } = &lhs_reduced
                {
                    return (**inner).clone();
                }
            }

            // (x + c1) + c2 → x + (c1 + c2) (constant folding through associativity)
            if *op == Op::Add {
                if let Some(c2) = rhs_reduced.as_const() {
                    if let SymbolicValue::Oper {
                        op: Op::Add,
                        lhs: inner_lhs,
                        rhs: inner_rhs,
                    } = &lhs_reduced
                    {
                        if let Some(c1) = inner_rhs.as_const() {
                            let width = rhs_reduced.width();
                            let mask = if width >= 8 {
                                u64::MAX
                            } else {
                                (1u64 << (width as u64 * 8)) - 1
                            };
                            let combined = c1.wrapping_add(c2) & mask;
                            if combined == 0 {
                                return (**inner_lhs).clone();
                            }
                            return SymbolicValue::add(
                                (**inner_lhs).clone(),
                                SymbolicValue::constant(combined, width),
                            );
                        }
                    }
                }
            }

            // (x - c1) - c2 → x - (c1 + c2)
            if *op == Op::Sub {
                if let Some(c2) = rhs_reduced.as_const() {
                    if let SymbolicValue::Oper {
                        op: Op::Sub,
                        lhs: inner_lhs,
                        rhs: inner_rhs,
                    } = &lhs_reduced
                    {
                        if let Some(c1) = inner_rhs.as_const() {
                            let width = rhs_reduced.width();
                            let mask = if width >= 8 {
                                u64::MAX
                            } else {
                                (1u64 << (width as u64 * 8)) - 1
                            };
                            let combined = c1.wrapping_add(c2) & mask;
                            return SymbolicValue::sub(
                                (**inner_lhs).clone(),
                                SymbolicValue::constant(combined, width),
                            );
                        }
                    }
                }
            }

            SymbolicValue::oper(*op, lhs_reduced, rhs_reduced)
        }

        // Reduce constraints (Python: constraint classes have reduce methods)
        SymbolicValue::Constraint { op, lhs, rhs } => {
            let lhs_reduced = reduce(lhs);
            let rhs_reduced = reduce(rhs);

            // Constant folding for constraints
            if let (Some(l), Some(r)) = (lhs_reduced.as_const(), rhs_reduced.as_const()) {
                let result = fold_constraint(*op, l, r);
                return SymbolicValue::constant(result, 1);
            }

            // x == x → 1, x != x → 0
            if lhs_reduced == rhs_reduced {
                match op {
                    ConstraintOp::Eq | ConstraintOp::Le | ConstraintOp::Ge => {
                        return SymbolicValue::constant(1, 1);
                    }
                    ConstraintOp::Ne | ConstraintOp::Lt | ConstraintOp::Gt
                    | ConstraintOp::Ult | ConstraintOp::Ugt => {
                        return SymbolicValue::constant(0, 1);
                    }
                }
            }

            SymbolicValue::constraint(*op, lhs_reduced, rhs_reduced)
        }

        SymbolicValue::Mem { addr, width } => {
            let addr_reduced = reduce(addr);
            SymbolicValue::mem(addr_reduced, *width)
        }

        // Reduce inside Call arguments
        SymbolicValue::Call { target, args, width } => {
            let reduced_args: Vec<SymbolicValue> = args.iter().map(|a| reduce(a)).collect();
            SymbolicValue::Call {
                target: target.clone(),
                args: reduced_args,
                width: *width,
            }
        }

        // Leaf nodes pass through unchanged
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_folding_add() {
        let expr = SymbolicValue::add(
            SymbolicValue::constant(3, 8),
            SymbolicValue::constant(4, 8),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(7));
    }

    #[test]
    fn test_constant_folding_sub() {
        let expr = SymbolicValue::sub(
            SymbolicValue::constant(10, 4),
            SymbolicValue::constant(3, 4),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(7));
    }

    #[test]
    fn test_constant_folding_and() {
        let expr = SymbolicValue::oper(
            Op::And,
            SymbolicValue::constant(0xFF, 4),
            SymbolicValue::constant(0x0F, 4),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(0x0F));
    }

    #[test]
    fn test_identity_add_zero() {
        let expr = SymbolicValue::add(
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(0, 8),
        );
        let result = reduce(&expr);
        assert!(matches!(result, SymbolicValue::Var { ref name, .. } if name == "rax"));
    }

    #[test]
    fn test_identity_mul_one() {
        let expr = SymbolicValue::oper(
            Op::Mul,
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(1, 8),
        );
        let result = reduce(&expr);
        assert!(matches!(result, SymbolicValue::Var { ref name, .. } if name == "rax"));
    }

    #[test]
    fn test_annihilation_mul_zero() {
        let expr = SymbolicValue::oper(
            Op::Mul,
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(0, 8),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(0));
    }

    #[test]
    fn test_self_cancel_xor() {
        let v = SymbolicValue::var("rax", 8);
        let expr = SymbolicValue::oper(Op::Xor, v.clone(), v);
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(0));
    }

    #[test]
    fn test_self_cancel_sub() {
        let v = SymbolicValue::var("rcx", 8);
        let expr = SymbolicValue::sub(v.clone(), v);
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(0));
    }

    #[test]
    fn test_nested_reduction() {
        // (rax + 0) + (3 + 4) => rax + 7
        let expr = SymbolicValue::add(
            SymbolicValue::add(
                SymbolicValue::var("rax", 8),
                SymbolicValue::constant(0, 8),
            ),
            SymbolicValue::add(
                SymbolicValue::constant(3, 8),
                SymbolicValue::constant(4, 8),
            ),
        );
        let result = reduce(&expr);
        // Should reduce to rax + 7
        match &result {
            SymbolicValue::Oper { op: Op::Add, lhs, rhs } => {
                assert!(matches!(lhs.as_ref(), SymbolicValue::Var { ref name, .. } if name == "rax"));
                assert_eq!(rhs.as_const(), Some(7));
            }
            _ => panic!("Expected Add operation, got: {:?}", result),
        }
    }

    #[test]
    fn test_div_by_zero_no_fold() {
        let expr = SymbolicValue::oper(
            Op::Div,
            SymbolicValue::constant(10, 4),
            SymbolicValue::constant(0, 4),
        );
        let result = reduce(&expr);
        // Should not fold - division by zero
        assert!(!result.is_const());
    }

    #[test]
    fn test_width_masking() {
        // 0xFF + 0x01 in 1-byte width should be 0x00
        let expr = SymbolicValue::add(
            SymbolicValue::constant(0xFF, 1),
            SymbolicValue::constant(0x01, 1),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(0x00));
    }

    #[test]
    fn test_strength_reduction_mul_power_of_two() {
        // rax * 8 → rax << 3
        let expr = SymbolicValue::oper(
            Op::Mul,
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(8, 8),
        );
        let result = reduce(&expr);
        match &result {
            SymbolicValue::Oper { op: Op::Shl, rhs, .. } => {
                assert_eq!(rhs.as_const(), Some(3));
            }
            _ => panic!("Expected Shl operation, got: {:?}", result),
        }
    }

    #[test]
    fn test_idempotent_and() {
        let v = SymbolicValue::var("rax", 8);
        let expr = SymbolicValue::oper(Op::And, v.clone(), v);
        let result = reduce(&expr);
        assert!(matches!(result, SymbolicValue::Var { ref name, .. } if name == "rax"));
    }

    #[test]
    fn test_idempotent_or() {
        let v = SymbolicValue::var("rbx", 8);
        let expr = SymbolicValue::oper(Op::Or, v.clone(), v);
        let result = reduce(&expr);
        assert!(matches!(result, SymbolicValue::Var { ref name, .. } if name == "rbx"));
    }

    #[test]
    fn test_constraint_folding_eq() {
        let c = SymbolicValue::constraint(
            ConstraintOp::Eq,
            SymbolicValue::constant(5, 4),
            SymbolicValue::constant(5, 4),
        );
        let result = reduce(&c);
        assert_eq!(result.as_const(), Some(1));
    }

    #[test]
    fn test_constraint_folding_ne() {
        let c = SymbolicValue::constraint(
            ConstraintOp::Ne,
            SymbolicValue::constant(3, 4),
            SymbolicValue::constant(5, 4),
        );
        let result = reduce(&c);
        assert_eq!(result.as_const(), Some(1));
    }

    #[test]
    fn test_constraint_self_eq() {
        // x == x → 1
        let v = SymbolicValue::var("rax", 8);
        let c = SymbolicValue::constraint(ConstraintOp::Eq, v.clone(), v);
        let result = reduce(&c);
        assert_eq!(result.as_const(), Some(1));
    }

    #[test]
    fn test_constraint_self_ne() {
        // x != x → 0
        let v = SymbolicValue::var("rax", 8);
        let c = SymbolicValue::constraint(ConstraintOp::Ne, v.clone(), v);
        let result = reduce(&c);
        assert_eq!(result.as_const(), Some(0));
    }

    #[test]
    fn test_double_neg() {
        // --x = x
        let v = SymbolicValue::var("rax", 8);
        let neg_neg = SymbolicValue::oper(
            Op::Neg,
            SymbolicValue::oper(Op::Neg, v.clone(), SymbolicValue::constant(0, 0)),
            SymbolicValue::constant(0, 0),
        );
        let result = reduce(&neg_neg);
        assert!(matches!(result, SymbolicValue::Var { ref name, .. } if name == "rax"));
    }

    #[test]
    fn test_associative_add_constants() {
        // (rax + 3) + 4 → rax + 7
        let expr = SymbolicValue::add(
            SymbolicValue::add(
                SymbolicValue::var("rax", 8),
                SymbolicValue::constant(3, 8),
            ),
            SymbolicValue::constant(4, 8),
        );
        let result = reduce(&expr);
        match &result {
            SymbolicValue::Oper { op: Op::Add, lhs, rhs } => {
                assert!(matches!(lhs.as_ref(), SymbolicValue::Var { ref name, .. } if name == "rax"));
                assert_eq!(rhs.as_const(), Some(7));
            }
            _ => panic!("Expected Add operation, got: {:?}", result),
        }
    }

    #[test]
    fn test_pow_zero() {
        // x ** 0 = 1
        let expr = SymbolicValue::oper(
            Op::Pow,
            SymbolicValue::var("rax", 8),
            SymbolicValue::constant(0, 8),
        );
        let result = reduce(&expr);
        assert_eq!(result.as_const(), Some(1));
    }

    #[test]
    fn test_reduce_call_args() {
        // call("foo", [3 + 4]) → call("foo", [7])
        let call = SymbolicValue::Call {
            target: "foo".to_string(),
            args: vec![SymbolicValue::add(
                SymbolicValue::constant(3, 8),
                SymbolicValue::constant(4, 8),
            )],
            width: 8,
        };
        let result = reduce(&call);
        match &result {
            SymbolicValue::Call { args, .. } => {
                assert_eq!(args[0].as_const(), Some(7));
            }
            _ => panic!("Expected Call, got: {:?}", result),
        }
    }
}
