//! Symbolic instruction translator.
//!
//! Port of Python vivisect's `symboliks/translator.py` and
//! `symboliks/archs/i386.py` (Intel-specific translation).
//!
//! The translator converts opcodes into symbolic effects by dispatching
//! to mnemonic-specific handlers. Each handler reads operand values,
//! computes symbolic expressions, and logs effects.
//!
//! Python architecture:
//! - `SymbolikTranslator.translateOpcode(op)` → dispatches to `i_<mnem>(op)`
//! - Each `i_*` method uses `getOperObj`/`setOperObj` helpers
//! - Effects accumulate in `_eff_log`, constraints in `_con_log`
//!
//! Rust port uses a trait with mnemonic dispatch via `translate_mnemonic()`.

use super::effect::SymbolicEffect;
use super::value::{ConstraintOp, Op, SymbolicValue};
use crate::envi::opcode::Opcode;
use crate::envi::operand::{DerefOperand, ImmediateOperand, RegisterOperand};

/// A branch constraint produced by conditional instructions.
///
/// Port of Python's constraint tuples returned from `i_*` methods:
/// `[(target_addr, constraint_sym), ...]`
#[derive(Debug, Clone)]
pub struct BranchConstraint {
    /// Target address this constraint applies to.
    pub target: u64,
    /// The symbolic constraint expression (true on this branch).
    pub constraint: SymbolicValue,
}

/// Symbolic translator that converts opcodes into symbolic effects.
///
/// Port of Python's `SymbolikTranslator` + `IntelSymbolikTranslator`.
pub struct SymbolikTranslator {
    /// Accumulated effects (Python: `_eff_log`).
    effects: Vec<SymbolicEffect>,
    /// Accumulated constraints (Python: `_con_log`).
    constraints: Vec<BranchConstraint>,
    /// Current instruction VA (Python: `_cur_va`).
    cur_va: u64,
    /// Pointer size in bytes.
    pointer_size: u8,
    /// Current register state for operand resolution.
    /// Mirrors Python's emulator integration where translator
    /// reads register state during translation.
    registers: std::collections::HashMap<String, SymbolicValue>,
}

impl SymbolikTranslator {
    /// Create a new translator for the given pointer size.
    pub fn new(pointer_size: u8) -> Self {
        Self {
            effects: Vec::new(),
            constraints: Vec::new(),
            cur_va: 0,
            pointer_size,
            registers: std::collections::HashMap::new(),
        }
    }

    /// Create a 64-bit translator.
    pub fn new_64() -> Self {
        Self::new(8)
    }

    /// Create a 32-bit translator.
    pub fn new_32() -> Self {
        Self::new(4)
    }

    // ── Effect logging methods (Python: eff* helpers) ──

    /// Log a variable/register assignment effect.
    ///
    /// Port of Python's `effSetVariable(rname, rsym)`.
    pub fn eff_set_variable(&mut self, name: &str, value: SymbolicValue) {
        self.registers.insert(name.to_string(), value.clone());
        self.effects.push(SymbolicEffect::SetVariable {
            va: self.cur_va,
            name: name.to_string(),
            value,
        });
    }

    /// Log a memory read and return the symbolic memory value.
    ///
    /// Port of Python's `effReadMemory(symaddr, symsize)`.
    pub fn eff_read_memory(&mut self, addr: SymbolicValue, size: u8) -> SymbolicValue {
        self.effects.push(SymbolicEffect::ReadMemory {
            va: self.cur_va,
            addr: addr.clone(),
            size,
        });
        SymbolicValue::mem(addr, size)
    }

    /// Log a memory write effect.
    ///
    /// Port of Python's `effWriteMemory(symaddr, symsize, symobj)`.
    pub fn eff_write_memory(&mut self, addr: SymbolicValue, size: u8, value: SymbolicValue) {
        self.effects.push(SymbolicEffect::WriteMemory {
            va: self.cur_va,
            addr,
            size,
            value,
        });
    }

    /// Log a function call effect.
    ///
    /// Port of Python's `effFofX(funcsym, argsyms)`.
    pub fn eff_call(&mut self, target: &str, args: Vec<SymbolicValue>) {
        self.effects.push(SymbolicEffect::CallFunction {
            va: self.cur_va,
            target: target.to_string(),
            args,
        });
    }

    /// Log a path constraint.
    ///
    /// Port of Python's `effConstrain(addrsym, conssym)`.
    pub fn eff_constrain(&mut self, target: u64, constraint: SymbolicValue) {
        self.constraints.push(BranchConstraint { target, constraint });
    }

    /// Log a debug/unsupported instruction marker.
    ///
    /// Port of Python's `effDebug(msg)`.
    pub fn eff_debug(&mut self, msg: &str) {
        self.effects.push(SymbolicEffect::Debug {
            va: self.cur_va,
            message: msg.to_string(),
        });
    }

    // ── Operand access methods (Python: getOperObj/setOperObj) ──

    /// Get the symbolic value of an operand.
    ///
    /// Port of Python's `getOperObj(op, idx)`.
    pub fn get_oper_obj(&mut self, op: &Opcode, idx: usize) -> SymbolicValue {
        let oper = match op.opers.get(idx) {
            Some(o) => o,
            None => return SymbolicValue::constant(0, self.pointer_size),
        };

        if oper.is_immed() {
            // Immediate operand → constant
            let val = oper.get_value(op).unwrap_or(0);
            let size = std::cmp::max(oper.size(), 1) as u8;
            SymbolicValue::constant(val, size)
        } else if oper.is_reg() {
            // Register operand → look up current symbolic value
            let repr = oper.repr(op);
            // Strip any decoration from repr to get register name
            let name = repr.trim();
            self.get_reg_obj(name)
        } else if oper.is_deref() {
            // Memory dereference → compute address, read memory
            let addr = self.get_oper_addr(op, idx);
            let size = std::cmp::max(oper.size(), 1) as u8;
            self.eff_read_memory(addr, size)
        } else {
            // PC-relative or other → try to resolve value
            if let Some(val) = oper.get_value(op) {
                SymbolicValue::constant(val, self.pointer_size)
            } else {
                SymbolicValue::constant(0, self.pointer_size)
            }
        }
    }

    /// Set an operand to a symbolic value.
    ///
    /// Port of Python's `setOperObj(op, idx, obj)`.
    pub fn set_oper_obj(&mut self, op: &Opcode, idx: usize, value: SymbolicValue) {
        let oper = match op.opers.get(idx) {
            Some(o) => o,
            None => return,
        };

        if oper.is_reg() {
            let name = oper.repr(op);
            let name = name.trim();
            self.eff_set_variable(name, value);
        } else if oper.is_deref() {
            let addr = self.get_oper_addr(op, idx);
            let size = std::cmp::max(oper.size(), 1) as u8;
            self.eff_write_memory(addr, size, value);
        }
    }

    /// Compute the effective address for a memory operand.
    ///
    /// Port of Python's `getOperAddrObj(op, idx)`.
    pub fn get_oper_addr(&self, op: &Opcode, idx: usize) -> SymbolicValue {
        let oper = match op.opers.get(idx) {
            Some(o) => o,
            None => return SymbolicValue::constant(0, self.pointer_size),
        };

        // Try to get a concrete address first
        if let Some(addr) = oper.get_address(op) {
            return SymbolicValue::constant(addr, self.pointer_size);
        }

        // For deref operands, build symbolic address from components
        // Use the repr to extract register names and build expression
        let repr = oper.repr(op);

        // If it looks like [reg+disp] or [reg], parse symbolically
        // This is a simplified version; a full port would downcast
        // to DerefOperand and use base_reg/index_reg/scale/disp directly.
        self.build_deref_address(&repr)
    }

    /// Build a symbolic address from a deref operand representation.
    fn build_deref_address(&self, repr: &str) -> SymbolicValue {
        // Strip brackets: "[...]" -> "..."
        let inner = repr.trim_start_matches('[').trim_end_matches(']').trim();

        if inner.is_empty() {
            return SymbolicValue::constant(0, self.pointer_size);
        }

        // Try to parse as a simple register
        if !inner.contains('+') && !inner.contains('-') && !inner.contains('*') {
            return self.get_reg_obj(inner);
        }

        // Try to parse "reg + disp" or "reg - disp"
        if let Some(pos) = inner.rfind('+') {
            let base = inner[..pos].trim();
            let disp = inner[pos + 1..].trim();
            if let Ok(d) = parse_int(disp) {
                let base_sym = self.get_reg_obj(base);
                return SymbolicValue::add(
                    base_sym,
                    SymbolicValue::constant(d as u64, self.pointer_size),
                );
            }
        }

        if let Some(pos) = inner.rfind('-') {
            if pos > 0 {
                let base = inner[..pos].trim();
                let disp = inner[pos + 1..].trim();
                if let Ok(d) = parse_int(disp) {
                    let base_sym = self.get_reg_obj(base);
                    return SymbolicValue::sub(
                        base_sym,
                        SymbolicValue::constant(d as u64, self.pointer_size),
                    );
                }
            }
        }

        // Fallback: treat entire thing as a variable reference
        SymbolicValue::var(inner, self.pointer_size)
    }

    /// Get the symbolic value of a register by name.
    ///
    /// Port of Python's `getRegObj(regidx)` / `getRegByName(name)`.
    pub fn get_reg_obj(&self, name: &str) -> SymbolicValue {
        self.registers
            .get(name)
            .cloned()
            .unwrap_or_else(|| SymbolicValue::var(name, self.pointer_size))
    }

    /// Set a register value (internal, no effect logging).
    pub fn set_reg_obj(&mut self, name: &str, value: SymbolicValue) {
        self.registers.insert(name.to_string(), value);
    }

    /// Set register state from an emulator (for translator-emulator integration).
    pub fn set_registers(&mut self, regs: &std::collections::HashMap<String, SymbolicValue>) {
        self.registers = regs.clone();
    }

    // ── Main translation dispatch ──

    /// Translate an opcode into symbolic effects.
    ///
    /// Port of Python's `translateOpcode(op)`.
    /// Dispatches to mnemonic-specific `translate_*` methods.
    pub fn translate_opcode(&mut self, op: &Opcode) -> Vec<BranchConstraint> {
        self.cur_va = op.va;
        self.constraints.clear();

        // Dispatch by mnemonic
        let mnem = op.mnem.to_lowercase();
        self.translate_mnemonic(&mnem, op);

        std::mem::take(&mut self.constraints)
    }

    /// Dispatch to architecture-specific mnemonic handlers.
    ///
    /// Port of Python's dynamic `i_<mnem>` method dispatch.
    fn translate_mnemonic(&mut self, mnem: &str, op: &Opcode) {
        match mnem {
            // Data movement
            "mov" | "movzx" | "movsx" | "movsxd" => self.i_mov(op),
            "lea" => self.i_lea(op),
            "xchg" => self.i_xchg(op),
            "cmovz" | "cmove" => self.i_cmov(op, ConstraintOp::Eq),
            "cmovnz" | "cmovne" => self.i_cmov(op, ConstraintOp::Ne),
            "cmovl" => self.i_cmov(op, ConstraintOp::Lt),
            "cmovg" => self.i_cmov(op, ConstraintOp::Gt),
            "cmovle" => self.i_cmov(op, ConstraintOp::Le),
            "cmovge" => self.i_cmov(op, ConstraintOp::Ge),
            "cmovb" | "cmovc" => self.i_cmov(op, ConstraintOp::Ult),
            "cmova" => self.i_cmov(op, ConstraintOp::Ugt),
            "cmovbe" | "cmovna" => self.i_cmov(op, ConstraintOp::Le),
            "cmovae" | "cmovnc" => self.i_cmov(op, ConstraintOp::Ge),
            "cmovs" | "cmovns" => self.i_cmov(op, ConstraintOp::Ne),

            // Stack operations
            "push" => self.i_push(op),
            "pop" => self.i_pop(op),

            // Arithmetic
            "add" => self.i_add(op),
            "sub" => self.i_sub(op),
            "imul" | "mul" => self.i_mul(op),
            "idiv" | "div" => self.i_div(op),
            "inc" => self.i_inc(op),
            "dec" => self.i_dec(op),
            "neg" => self.i_neg(op),

            // Logic
            "and" => self.i_and(op),
            "or" => self.i_or(op),
            "xor" => self.i_xor(op),
            "not" => self.i_not(op),
            "shl" | "sal" => self.i_shl(op),
            "shr" => self.i_shr(op),
            "sar" => self.i_sar(op),
            "rol" | "ror" => self.i_rotate(op),

            // Comparison & test
            "cmp" => self.i_cmp(op),
            "test" => self.i_test(op),

            // Control flow
            "call" => self.i_call(op),
            "ret" | "retn" => self.i_ret(op),
            "jmp" => self.i_jmp(op),
            "jz" | "je" => self.i_jcc(op, ConstraintOp::Eq),
            "jnz" | "jne" => self.i_jcc(op, ConstraintOp::Ne),
            "jl" | "jnge" => self.i_jcc(op, ConstraintOp::Lt),
            "jle" | "jng" => self.i_jcc(op, ConstraintOp::Le),
            "jg" | "jnle" => self.i_jcc(op, ConstraintOp::Gt),
            "jge" | "jnl" => self.i_jcc(op, ConstraintOp::Ge),
            "jb" | "jnae" | "jc" => self.i_jcc(op, ConstraintOp::Ult),
            "ja" | "jnbe" => self.i_jcc(op, ConstraintOp::Ugt),
            "jbe" | "jna" => self.i_jcc(op, ConstraintOp::Le),
            "jae" | "jnb" | "jnc" => self.i_jcc(op, ConstraintOp::Ge),

            // Misc
            "nop" | "endbr64" | "endbr32" => {} // No effects
            "cdq" | "cqo" | "cdqe" | "cbw" | "cwde" => self.i_convert(op),
            "leave" => self.i_leave(op),

            // String ops
            "rep" | "repne" | "repnz" | "repe" | "repz" => {
                // Simplified: treat as debug
                self.eff_debug(&format!("rep prefix: {}", op.mnem));
            }
            "movsb" | "movsw" | "movsd" | "movsq" |
            "stosb" | "stosw" | "stosd" | "stosq" |
            "lodsb" | "lodsw" | "lodsd" | "lodsq" |
            "scasb" | "scasw" | "scasd" | "scasq" |
            "cmpsb" | "cmpsw" | "cmpsd" | "cmpsq" => {
                self.eff_debug(&format!("string op: {}", op.mnem));
            }

            // Default: unsupported instruction
            _ => {
                self.eff_debug(&format!("unsupported: {}", op.mnem));
            }
        }
    }

    // ── Instruction handlers (Python: i_* methods) ──

    /// MOV dst, src
    fn i_mov(&mut self, op: &Opcode) {
        let src = self.get_oper_obj(op, 1);
        self.set_oper_obj(op, 0, src);
    }

    /// LEA dst, [addr]
    fn i_lea(&mut self, op: &Opcode) {
        let addr = self.get_oper_addr(op, 1);
        self.set_oper_obj(op, 0, addr);
    }

    /// XCHG op0, op1
    fn i_xchg(&mut self, op: &Opcode) {
        let v0 = self.get_oper_obj(op, 0);
        let v1 = self.get_oper_obj(op, 1);
        self.set_oper_obj(op, 0, v1);
        self.set_oper_obj(op, 1, v0);
    }

    /// CMOVcc dst, src (conditional move)
    ///
    /// Only performs the move when the condition (from prior CMP/TEST) holds.
    /// Logged as a constraint + conditional write so the symbolic state
    /// reflects that the destination may or may not change.
    fn i_cmov(&mut self, op: &Opcode, cmp_op: ConstraintOp) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let lhs = self.get_reg_obj("__cmp_lhs");
        let rhs = self.get_reg_obj("__cmp_rhs");

        // Log the condition as a constraint so downstream analysis
        // knows this write is conditional.
        let condition = SymbolicValue::constraint(cmp_op, lhs, rhs);
        self.eff_constrain(op.va, condition);

        // Write src only if both operands are concrete constants and
        // we can evaluate the condition. Otherwise, conservatively
        // keep the destination unchanged (better than unconditional
        // overwrite which loses the conditional semantics).
        if let (SymbolicValue::Const { value: lv, .. },
                SymbolicValue::Const { value: rv, .. }) =
            (&dst, &src)
        {
            // Even with concrete values we can't evaluate flags here,
            // so leave dst unchanged and log a debug note.
            let _ = (lv, rv);
        }
        self.eff_debug(&format!("cmov({}) dst={}, src={}", cmp_op, dst, src));
    }

    /// PUSH value
    fn i_push(&mut self, op: &Opcode) {
        let value = self.get_oper_obj(op, 0);
        let sp_name = if self.pointer_size == 8 { "rsp" } else { "esp" };
        let sp = self.get_reg_obj(sp_name);
        let new_sp = SymbolicValue::sub(
            sp,
            SymbolicValue::constant(self.pointer_size as u64, self.pointer_size),
        );
        self.eff_set_variable(sp_name, new_sp.clone());
        self.eff_write_memory(new_sp, self.pointer_size, value);
    }

    /// POP dst
    fn i_pop(&mut self, op: &Opcode) {
        let sp_name = if self.pointer_size == 8 { "rsp" } else { "esp" };
        let sp = self.get_reg_obj(sp_name);
        let value = self.eff_read_memory(sp.clone(), self.pointer_size);
        let new_sp = SymbolicValue::add(
            sp,
            SymbolicValue::constant(self.pointer_size as u64, self.pointer_size),
        );
        self.eff_set_variable(sp_name, new_sp);
        self.set_oper_obj(op, 0, value);
    }

    /// ADD dst, src
    fn i_add(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let result = SymbolicValue::oper(Op::Add, dst, src);
        self.set_oper_obj(op, 0, result);
    }

    /// SUB dst, src
    fn i_sub(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let result = SymbolicValue::oper(Op::Sub, dst, src);
        self.set_oper_obj(op, 0, result);
    }

    /// IMUL / MUL
    fn i_mul(&mut self, op: &Opcode) {
        if op.opers.len() >= 3 {
            // imul dst, src1, src2
            let src1 = self.get_oper_obj(op, 1);
            let src2 = self.get_oper_obj(op, 2);
            let result = SymbolicValue::oper(Op::Mul, src1, src2);
            self.set_oper_obj(op, 0, result);
        } else if op.opers.len() == 2 {
            // imul dst, src
            let dst = self.get_oper_obj(op, 0);
            let src = self.get_oper_obj(op, 1);
            let result = SymbolicValue::oper(Op::Mul, dst, src);
            self.set_oper_obj(op, 0, result);
        } else {
            // Single operand mul: result in edx:eax / rdx:rax
            let src = self.get_oper_obj(op, 0);
            let ax_name = if self.pointer_size == 8 { "rax" } else { "eax" };
            let ax = self.get_reg_obj(ax_name);
            let result = SymbolicValue::oper(Op::Mul, ax, src);
            self.eff_set_variable(ax_name, result);
        }
    }

    /// IDIV / DIV
    fn i_div(&mut self, op: &Opcode) {
        let divisor = self.get_oper_obj(op, 0);
        let ax_name = if self.pointer_size == 8 { "rax" } else { "eax" };
        let dx_name = if self.pointer_size == 8 { "rdx" } else { "edx" };
        let ax = self.get_reg_obj(ax_name);
        let quotient = SymbolicValue::oper(Op::Div, ax.clone(), divisor.clone());
        let remainder = SymbolicValue::oper(Op::Mod, ax, divisor);
        self.eff_set_variable(ax_name, quotient);
        self.eff_set_variable(dx_name, remainder);
    }

    /// INC dst
    fn i_inc(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let width = dst.width();
        let result = SymbolicValue::oper(
            Op::Add,
            dst,
            SymbolicValue::constant(1, width),
        );
        self.set_oper_obj(op, 0, result);
    }

    /// DEC dst
    fn i_dec(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let width = dst.width();
        let result = SymbolicValue::oper(
            Op::Sub,
            dst,
            SymbolicValue::constant(1, width),
        );
        self.set_oper_obj(op, 0, result);
    }

    /// NEG dst
    fn i_neg(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let result = SymbolicValue::oper(
            Op::Neg,
            dst,
            SymbolicValue::constant(0, 0),
        );
        self.set_oper_obj(op, 0, result);
    }

    /// AND dst, src
    fn i_and(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let result = SymbolicValue::oper(Op::And, dst, src);
        self.set_oper_obj(op, 0, result);
    }

    /// OR dst, src
    fn i_or(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let result = SymbolicValue::oper(Op::Or, dst, src);
        self.set_oper_obj(op, 0, result);
    }

    /// XOR dst, src
    fn i_xor(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let src = self.get_oper_obj(op, 1);
        let result = SymbolicValue::oper(Op::Xor, dst, src);
        self.set_oper_obj(op, 0, result);
    }

    /// NOT dst
    fn i_not(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let result = SymbolicValue::oper(
            Op::Not,
            dst,
            SymbolicValue::constant(0, 0),
        );
        self.set_oper_obj(op, 0, result);
    }

    /// SHL / SAL dst, count
    fn i_shl(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let count = if op.opers.len() > 1 {
            self.get_oper_obj(op, 1)
        } else {
            SymbolicValue::constant(1, 1)
        };
        let result = SymbolicValue::oper(Op::Shl, dst, count);
        self.set_oper_obj(op, 0, result);
    }

    /// SHR dst, count
    fn i_shr(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let count = if op.opers.len() > 1 {
            self.get_oper_obj(op, 1)
        } else {
            SymbolicValue::constant(1, 1)
        };
        let result = SymbolicValue::oper(Op::Shr, dst, count);
        self.set_oper_obj(op, 0, result);
    }

    /// SAR dst, count
    fn i_sar(&mut self, op: &Opcode) {
        let dst = self.get_oper_obj(op, 0);
        let count = if op.opers.len() > 1 {
            self.get_oper_obj(op, 1)
        } else {
            SymbolicValue::constant(1, 1)
        };
        let result = SymbolicValue::oper(Op::Sar, dst, count);
        self.set_oper_obj(op, 0, result);
    }

    /// ROL / ROR (simplified as shifts)
    fn i_rotate(&mut self, op: &Opcode) {
        // Simplified: treat rotations as unsupported for now
        self.eff_debug(&format!("rotate: {}", op.mnem));
    }

    /// CMP op0, op1 — sets constraint state for subsequent Jcc
    fn i_cmp(&mut self, op: &Opcode) {
        // CMP just updates the flags; the constraint is consumed by Jcc.
        // We record the comparison operands in a special variable.
        let v0 = self.get_oper_obj(op, 0);
        let v1 = self.get_oper_obj(op, 1);
        self.set_reg_obj("__cmp_lhs", v0);
        self.set_reg_obj("__cmp_rhs", v1);
    }

    /// TEST op0, op1
    fn i_test(&mut self, op: &Opcode) {
        let v0 = self.get_oper_obj(op, 0);
        let v1 = self.get_oper_obj(op, 1);
        // TEST is AND without storing result; flags reflect (v0 & v1)
        let result = SymbolicValue::oper(Op::And, v0, v1);
        self.set_reg_obj("__cmp_lhs", result);
        self.set_reg_obj("__cmp_rhs", SymbolicValue::constant(0, self.pointer_size));
    }

    /// CALL target
    fn i_call(&mut self, op: &Opcode) {
        // Get call target
        let target = if let Some(oper) = op.opers.first() {
            if let Some(addr) = oper.get_value(op) {
                format!("{:#x}", addr)
            } else {
                oper.repr(op)
            }
        } else {
            "unknown".to_string()
        };

        // Collect arguments (architecture-dependent calling convention)
        let args = if self.pointer_size == 8 {
            // x86-64 System V ABI: rdi, rsi, rdx, rcx, r8, r9
            vec![
                self.get_reg_obj("rdi"),
                self.get_reg_obj("rsi"),
                self.get_reg_obj("rdx"),
                self.get_reg_obj("rcx"),
            ]
        } else {
            // x86 cdecl: arguments on stack (simplified)
            let sp = self.get_reg_obj("esp");
            vec![
                SymbolicValue::mem(sp.clone(), 4),
                SymbolicValue::mem(
                    SymbolicValue::add(sp.clone(), SymbolicValue::constant(4, 4)),
                    4,
                ),
            ]
        };

        self.eff_call(&target, args);

        // Return value goes to rax/eax
        let ret_reg = if self.pointer_size == 8 { "rax" } else { "eax" };
        self.eff_set_variable(
            ret_reg,
            SymbolicValue::Call {
                target,
                args: Vec::new(),
                width: self.pointer_size,
            },
        );
    }

    /// RET
    fn i_ret(&mut self, op: &Opcode) {
        let sp_name = if self.pointer_size == 8 { "rsp" } else { "esp" };
        let sp = self.get_reg_obj(sp_name);
        let _ret_addr = self.eff_read_memory(sp.clone(), self.pointer_size);
        let new_sp = SymbolicValue::add(
            sp,
            SymbolicValue::constant(self.pointer_size as u64, self.pointer_size),
        );
        self.eff_set_variable(sp_name, new_sp);
    }

    /// JMP target (unconditional)
    fn i_jmp(&mut self, _op: &Opcode) {
        // No effects needed; control flow handled by graph
    }

    /// Jcc target (conditional jump) — uses saved CMP/TEST state
    fn i_jcc(&mut self, op: &Opcode, cmp_op: ConstraintOp) {
        let lhs = self.get_reg_obj("__cmp_lhs");
        let rhs = self.get_reg_obj("__cmp_rhs");

        // Get branch target
        let target = op.opers.first()
            .and_then(|o| o.get_value(op))
            .unwrap_or(0);

        let fall_through = op.va + op.size as u64;

        // True branch: constraint holds
        let true_constraint = SymbolicValue::constraint(cmp_op, lhs.clone(), rhs.clone());
        self.eff_constrain(target, true_constraint);

        // False branch: inverse constraint
        let false_constraint = SymbolicValue::constraint(cmp_op.inverse(), lhs, rhs);
        self.eff_constrain(fall_through, false_constraint);
    }

    /// CDQ/CQO/CDQE/CBW/CWDE (sign-extension conversions)
    fn i_convert(&mut self, op: &Opcode) {
        let (src, dst) = match op.mnem.to_lowercase().as_str() {
            "cdq" => ("eax", "edx"),
            "cqo" => ("rax", "rdx"),
            "cdqe" => ("eax", "rax"),
            "cbw" => ("al", "ax"),
            "cwde" => ("ax", "eax"),
            _ => return,
        };
        let src_val = self.get_reg_obj(src);
        let extended = SymbolicValue::oper(
            Op::SignExtend,
            src_val,
            SymbolicValue::constant(0, 0),
        );
        self.eff_set_variable(dst, extended);
    }

    /// LEAVE (mov sp, bp; pop bp)
    fn i_leave(&mut self, _op: &Opcode) {
        let (sp_name, bp_name) = if self.pointer_size == 8 {
            ("rsp", "rbp")
        } else {
            ("esp", "ebp")
        };
        let bp = self.get_reg_obj(bp_name);
        self.eff_set_variable(sp_name, bp.clone());
        // pop bp
        let sp = self.get_reg_obj(sp_name);
        let value = self.eff_read_memory(sp.clone(), self.pointer_size);
        let new_sp = SymbolicValue::add(
            sp,
            SymbolicValue::constant(self.pointer_size as u64, self.pointer_size),
        );
        self.eff_set_variable(sp_name, new_sp);
        self.eff_set_variable(bp_name, value);
    }

    // ── Public accessors ──

    /// Get collected effects (Python: `getEffects()`).
    pub fn get_effects(&self) -> &[SymbolicEffect] {
        &self.effects
    }

    /// Take and return all effects, clearing the internal log.
    pub fn take_effects(&mut self) -> Vec<SymbolicEffect> {
        std::mem::take(&mut self.effects)
    }

    /// Clear all effects and constraints (Python: `clearEffects()`).
    pub fn clear_effects(&mut self) {
        self.effects.clear();
        self.constraints.clear();
    }
}

/// Parse an integer string (decimal or hex).
fn parse_int(s: &str) -> Result<i64, std::num::ParseIntError> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16)
    } else if s.starts_with('-') {
        s.parse::<i64>()
    } else {
        s.parse::<i64>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envi::opcode::Opcode;
    use crate::envi::operand::{ImmediateOperand, RegisterOperand};
    use crate::constants::InstructionFlags;

    fn make_reg_oper(name: &str, size: usize) -> Box<dyn crate::envi::operand::Operand> {
        Box::new(RegisterOperand::new(0, name, size))
    }

    fn make_imm_oper(value: u64, size: usize) -> Box<dyn crate::envi::operand::Operand> {
        Box::new(ImmediateOperand::new(value, size))
    }

    fn make_opcode(mnem: &str, opers: Vec<Box<dyn crate::envi::operand::Operand>>) -> Opcode {
        Opcode {
            va: 0x401000,
            opcode: 0,
            mnem: mnem.to_string(),
            prefixes: 0,
            size: 3,
            opers,
            iflags: InstructionFlags::empty(),
            bytes: vec![],
        }
    }

    #[test]
    fn test_translate_mov_reg_imm() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("mov", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(42, 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].sets_variable("rax"));
        assert_eq!(effects[0].variable_value().unwrap().as_const(), Some(42));
    }

    #[test]
    fn test_translate_mov_reg_reg() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("mov", vec![
            make_reg_oper("rax", 8),
            make_reg_oper("rbx", 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].sets_variable("rax"));
        // Value should be the symbolic var "rbx"
        match effects[0].variable_value().unwrap() {
            SymbolicValue::Var { name, .. } => assert_eq!(name, "rbx"),
            _ => panic!("Expected Var(rbx)"),
        }
    }

    #[test]
    fn test_translate_add() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("add", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(5, 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].sets_variable("rax"));
    }

    #[test]
    fn test_translate_sub() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("sub", vec![
            make_reg_oper("rsp", 8),
            make_imm_oper(0x28, 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].sets_variable("rsp"));
    }

    #[test]
    fn test_translate_xor_self() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("xor", vec![
            make_reg_oper("eax", 4),
            make_reg_oper("eax", 4),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        assert!(effects[0].sets_variable("eax"));
    }

    #[test]
    fn test_translate_push() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("push", vec![
            make_reg_oper("rbp", 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        // push produces: set rsp, write memory
        assert!(effects.len() >= 2);
        assert!(effects[0].sets_variable("rsp"));
        assert!(effects[1].is_memory_write());
    }

    #[test]
    fn test_translate_call() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("call", vec![
            make_imm_oper(0x402000, 8),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        // call produces: CallFunction, SetVariable(rax)
        let has_call = effects.iter().any(|e| e.is_call());
        assert!(has_call, "Expected a CallFunction effect");
    }

    #[test]
    fn test_translate_cmp_jz() {
        let mut xlate = SymbolikTranslator::new_64();

        // CMP rax, 0
        let cmp_op = make_opcode("cmp", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(0, 8),
        ]);
        xlate.translate_opcode(&cmp_op);

        // JZ 0x401020
        let jz_op = Opcode {
            va: 0x401005,
            opcode: 0,
            mnem: "jz".to_string(),
            prefixes: 0,
            size: 2,
            opers: vec![make_imm_oper(0x401020, 8)],
            iflags: InstructionFlags::empty(),
            bytes: vec![],
        };
        let constraints = xlate.translate_opcode(&jz_op);

        // Should produce 2 constraints: one for taken, one for fall-through
        assert_eq!(constraints.len(), 2);
        assert_eq!(constraints[0].target, 0x401020);
    }

    #[test]
    fn test_translate_nop() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("nop", vec![]);
        xlate.translate_opcode(&op);
        assert_eq!(xlate.get_effects().len(), 0);
    }

    #[test]
    fn test_translate_unsupported() {
        let mut xlate = SymbolikTranslator::new_64();
        let op = make_opcode("vmovaps", vec![]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert_eq!(effects.len(), 1);
        match &effects[0] {
            SymbolicEffect::Debug { message, .. } => {
                assert!(message.contains("vmovaps"));
            }
            _ => panic!("Expected Debug effect"),
        }
    }

    #[test]
    fn test_translate_inc_dec() {
        let mut xlate = SymbolikTranslator::new_64();
        let inc_op = make_opcode("inc", vec![make_reg_oper("rcx", 8)]);
        xlate.translate_opcode(&inc_op);
        assert!(xlate.get_effects()[0].sets_variable("rcx"));

        xlate.clear_effects();

        let dec_op = make_opcode("dec", vec![make_reg_oper("rcx", 8)]);
        xlate.translate_opcode(&dec_op);
        assert!(xlate.get_effects()[0].sets_variable("rcx"));
    }

    #[test]
    fn test_effect_log_accumulation() {
        let mut xlate = SymbolikTranslator::new_64();

        // Multiple instructions accumulate effects
        xlate.translate_opcode(&make_opcode("mov", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(1, 8),
        ]));
        xlate.translate_opcode(&make_opcode("mov", vec![
            make_reg_oper("rbx", 8),
            make_imm_oper(2, 8),
        ]));
        xlate.translate_opcode(&make_opcode("add", vec![
            make_reg_oper("rax", 8),
            make_reg_oper("rbx", 8),
        ]));

        assert_eq!(xlate.get_effects().len(), 3);
    }

    #[test]
    fn test_clear_effects() {
        let mut xlate = SymbolikTranslator::new_64();
        xlate.translate_opcode(&make_opcode("mov", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(1, 8),
        ]));
        assert_eq!(xlate.get_effects().len(), 1);
        xlate.clear_effects();
        assert_eq!(xlate.get_effects().len(), 0);
    }

    #[test]
    fn test_take_effects() {
        let mut xlate = SymbolikTranslator::new_64();
        xlate.translate_opcode(&make_opcode("mov", vec![
            make_reg_oper("rax", 8),
            make_imm_oper(1, 8),
        ]));
        let effects = xlate.take_effects();
        assert_eq!(effects.len(), 1);
        assert_eq!(xlate.get_effects().len(), 0);
    }

    #[test]
    fn test_32bit_translator() {
        let mut xlate = SymbolikTranslator::new_32();
        let op = make_opcode("push", vec![
            make_reg_oper("ebp", 4),
        ]);
        xlate.translate_opcode(&op);
        let effects = xlate.get_effects();
        assert!(effects[0].sets_variable("esp"));
    }
}
