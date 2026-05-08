//! Non-symbolic switch case analysis.
//!
//! Port of Python's `vivisect/analysis/generic/switchcase.py`.
//!
//! Uses backward instruction scanning to resolve MSVC-style RVA-based
//! jump tables. Looks for the pattern:
//!   jmp reg            (indirect jump via register)
//!   ...
//!   add reg, imgbase   (rebase RVA to VA)
//!   ...
//!   mov reg, [base + idx*scale + disp]  (load from jump table)
//!
//! The jump table address is `disp + imgbase` and each entry is
//! `scale` bytes (typically 4).

use crate::constants::{Architecture, RefType};
use crate::core::workspace::VivWorkspace;
use crate::envi::archs::{X86Disassembler, X86Mode};
use crate::envi::opcode::Opcode;
use crate::envi::operand::{DerefOperand, RegisterOperand};
use crate::error::VivResult;

const MAX_SCAN_INSTRUCTIONS: usize = 32;
const MAX_TABLE_ENTRIES: usize = 512;

#[derive(Debug, Default)]
pub struct NonSymSwitchStats {
    pub switches_found: usize,
    pub total_cases: usize,
    pub cases_wired: usize,
}

struct SwitchContext {
    table_va: u64,
    scale: u8,
}

fn get_image_base(workspace: &VivWorkspace) -> Option<u64> {
    workspace.get_files().first().map(|f| f.base_addr)
}

fn disasm_at(
    disasm: &X86Disassembler,
    workspace: &VivWorkspace,
    va: u64,
) -> Option<Opcode> {
    let bytes = workspace.read_memory(va, 16).ok()?;
    disasm.disassemble(&bytes, va).ok().filter(|op| op.size > 0)
}

fn get_reg_name(op: &Opcode, oper_idx: usize) -> Option<String> {
    let oper = op.opers.get(oper_idx)?;
    let reg = oper.as_any().downcast_ref::<RegisterOperand>()?;
    Some(canonical_name(&reg.reg_name))
}

fn canonical_name(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax".to_string(),
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx".to_string(),
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx".to_string(),
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx".to_string(),
        "sil" | "si" | "esi" | "rsi" => "rsi".to_string(),
        "dil" | "di" | "edi" | "rdi" => "rdi".to_string(),
        "spl" | "sp" | "esp" | "rsp" => "rsp".to_string(),
        "bpl" | "bp" | "ebp" | "rbp" => "rbp".to_string(),
        "r8b" | "r8w" | "r8d" | "r8" => "r8".to_string(),
        "r9b" | "r9w" | "r9d" | "r9" => "r9".to_string(),
        "r10b" | "r10w" | "r10d" | "r10" => "r10".to_string(),
        "r11b" | "r11w" | "r11d" | "r11" => "r11".to_string(),
        "r12b" | "r12w" | "r12d" | "r12" => "r12".to_string(),
        "r13b" | "r13w" | "r13d" | "r13" => "r13".to_string(),
        "r14b" | "r14w" | "r14d" | "r14" => "r14".to_string(),
        "r15b" | "r15w" | "r15d" | "r15" => "r15".to_string(),
        _ => lower,
    }
}

/// Scan backward from `start_va` within the same code block looking for
/// an instruction with mnemonic `mnem` whose first operand is a register
/// matching `target_reg` (canonical name).
fn find_op_backward(
    disasm: &X86Disassembler,
    workspace: &VivWorkspace,
    start_va: u64,
    mnem: &str,
    target_reg: Option<&str>,
) -> Option<Opcode> {
    let cb = workspace.get_codeblock(start_va)?;
    let block_start = cb.va;
    let mut va = start_va;
    let mut steps = 0;

    while steps < MAX_SCAN_INSTRUCTIONS {
        if va == 0 || va <= block_start {
            break;
        }

        // Try decoding at the previous byte — scan backward byte by byte
        // until we get a valid instruction that ends at or before our current va.
        let mut found = false;
        for back in 1..=15u64 {
            let try_va = va.saturating_sub(back);
            if try_va < block_start {
                break;
            }
            if let Some(op) = disasm_at(disasm, workspace, try_va) {
                if try_va + op.size as u64 == va {
                    // Valid instruction ending exactly at our scan point
                    if op.mnem == mnem && !op.opers.is_empty() {
                        if let Some(reg) = target_reg {
                            if let Some(name) = get_reg_name(&op, 0) {
                                if name == reg {
                                    return Some(op);
                                }
                            }
                        } else {
                            return Some(op);
                        }
                    }
                    va = try_va;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            break;
        }
        steps += 1;
    }

    None
}

/// Check if any instruction between `block_start` and `end_va` assigns
/// `imgbase` to register `reg`.
fn scan_for_imgbase_assign(
    disasm: &X86Disassembler,
    workspace: &VivWorkspace,
    end_va: u64,
    reg: &str,
    imgbase: u64,
) -> bool {
    let cb = match workspace.get_codeblock(end_va) {
        Some(cb) => cb.clone(),
        None => return false,
    };
    let block_start = cb.va;
    let mut va = block_start;

    while va < end_va {
        if let Some(op) = disasm_at(disasm, workspace, va) {
            if op.opers.len() >= 2 {
                if let Some(name) = get_reg_name(&op, 0) {
                    if name == reg {
                        if let Some(val) = op.opers[1].get_value(&op) {
                            if val == imgbase {
                                return true;
                            }
                        }
                    }
                }
            }
            va += op.size as u64;
        } else {
            va += 1;
        }
    }

    false
}

/// Try to resolve a switch base from an indirect register jump.
///
/// Scans backward for:
///   add reg, <imgbase>    — rebase from RVA to VA
///   mov reg, [sib]        — load from jump table with SIB addressing
fn get_switch_base(
    disasm: &X86Disassembler,
    workspace: &VivWorkspace,
    jmp_op: &Opcode,
    imgbase: u64,
) -> Option<SwitchContext> {
    if !jmp_op.is_branch() || jmp_op.opers.is_empty() {
        return None;
    }

    // The jump target must be a register
    if !jmp_op.opers[0].is_reg() {
        return None;
    }
    let jmp_reg = get_reg_name(jmp_op, 0)?;

    // Find `add reg, <imgbase>` scanning backward
    let add_op = find_op_backward(disasm, workspace, jmp_op.va, "add", Some(&jmp_reg))?;

    // Check that the second operand of the add is the image base
    let add_val = add_op.opers.get(1)?.get_value(&add_op);

    let reg_for_mov;
    if add_val == Some(imgbase) {
        reg_for_mov = jmp_reg.clone();
    } else {
        // The add might use the register as the base instead of the selector.
        // Check if the image base was assigned to this register earlier.
        if !scan_for_imgbase_assign(disasm, workspace, add_op.va, &jmp_reg, imgbase) {
            tracing::trace!(
                "0x{:x}: add operand != imgbase ({:?} != {:#x})",
                jmp_op.va,
                add_val,
                imgbase
            );
            return None;
        }
        // The other register in the add is the one we need for the mov
        let other_reg = get_reg_name(&add_op, 1)?;
        reg_for_mov = other_reg;
    }

    // Find `mov reg, [base + idx*scale + disp]` scanning backward from the add
    let mov_op = find_op_backward(disasm, workspace, add_op.va, "mov", Some(&reg_for_mov))
        .or_else(|| {
            // Try the other register if the first didn't work
            if reg_for_mov != jmp_reg {
                find_op_backward(disasm, workspace, add_op.va, "mov", Some(&jmp_reg))
            } else {
                None
            }
        })?;

    // The second operand of the mov must be a SIB memory reference
    let deref = mov_op.opers.get(1)?
        .as_any()
        .downcast_ref::<DerefOperand>()?;

    // Must have an index register (SIB pattern)
    if deref.index_reg.is_none() {
        tracing::trace!(
            "0x{:x}: mov operand is not SIB (no index register)",
            jmp_op.va
        );
        return None;
    }

    // Scale must be 4-byte aligned
    if deref.scale == 0 || deref.scale % 4 != 0 {
        tracing::trace!(
            "0x{:x}: bad scale {} (must be multiple of 4)",
            jmp_op.va,
            deref.scale
        );
        return None;
    }

    let table_va = (deref.displacement as u64).wrapping_add(imgbase);

    if !workspace.is_valid_pointer(table_va) {
        tracing::trace!(
            "0x{:x}: table VA {:#x} not valid",
            jmp_op.va,
            table_va
        );
        return None;
    }

    Some(SwitchContext {
        table_va,
        scale: deref.scale,
    })
}

/// Read jump table entries from `table_va`, each `entry_size` bytes,
/// treating them as RVAs rebased by `imgbase`.
fn read_rva_table(
    workspace: &VivWorkspace,
    table_va: u64,
    entry_size: usize,
    imgbase: u64,
    is_little: bool,
) -> Vec<u64> {
    let mut targets = Vec::new();

    for i in 0..MAX_TABLE_ENTRIES {
        let entry_va = match table_va.checked_add((i * entry_size) as u64) {
            Some(v) => v,
            None => break,
        };

        let bytes = match workspace.read_memory(entry_va, entry_size) {
            Ok(b) => b,
            Err(_) => break,
        };

        let rva = match (entry_size, is_little) {
            (4, true) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            (4, false) => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
            _ => break,
        };

        if rva == 0 {
            break;
        }

        let target = rva.wrapping_add(imgbase);

        let in_code = workspace.get_segments().iter().any(|seg| {
            let name = seg.name.to_lowercase();
            (name.contains("text") || name.contains("code"))
                && target >= seg.va
                && target < seg.va + seg.size as u64
        });

        if !in_code {
            break;
        }

        targets.push(target);
    }

    targets
}

/// Run non-symbolic switch case analysis on all functions.
#[must_use]
pub fn analyze_switchcase(workspace: &mut VivWorkspace) -> VivResult<NonSymSwitchStats> {
    let arch = workspace.architecture();
    let mut stats = NonSymSwitchStats::default();

    let mode = match arch {
        Architecture::I386 => X86Mode::Mode32,
        Architecture::Amd64 => X86Mode::Mode64,
        _ => return Ok(stats),
    };

    let imgbase = match get_image_base(workspace) {
        Some(b) => b,
        None => return Ok(stats),
    };

    let is_little = matches!(workspace.endian(), crate::constants::Endian::Little);
    let disasm = X86Disassembler::new(mode);

    let funcs: Vec<u64> = workspace.get_functions();
    let mut switches: Vec<(u64, SwitchContext)> = Vec::new();

    for &func_va in &funcs {
        let blocks = workspace.get_function_blocks(func_va);

        for block in &blocks {
            let block_end = block.va + block.size as u64;
            let mut va = block.va;

            while va < block_end {
                let op = match disasm_at(&disasm, workspace, va) {
                    Some(op) => op,
                    None => { va += 1; continue; }
                };

                if op.is_branch() && !op.is_call() && !op.is_return()
                    && !op.opers.is_empty() && op.opers[0].is_reg()
                {
                    if let Some(ctx) = get_switch_base(&disasm, workspace, &op, imgbase) {
                        switches.push((func_va, ctx));
                    }
                }

                va += op.size as u64;
            }
        }
    }

    // Wire up discovered switches
    for (func_va, ctx) in &switches {
        let targets = read_rva_table(workspace, ctx.table_va, ctx.scale as usize, imgbase, is_little);

        if targets.is_empty() {
            continue;
        }

        stats.switches_found += 1;
        stats.total_cases += targets.len();

        tracing::debug!(
            "[switchcase] switch in func {:#x}: table at {:#x}, {} cases (scale={})",
            func_va, ctx.table_va, targets.len(), ctx.scale
        );

        for (i, &target) in targets.iter().enumerate() {
            workspace.add_xref(ctx.table_va, target, RefType::Code);

            if !workspace.is_function(target) && workspace.get_location(target).is_none() {
                workspace.add_codeblock(target, 0, *func_va);
                workspace.set_name(target, &format!("switch_case_{:x}_{}", func_va, i));
                stats.cases_wired += 1;
            }
        }
    }

    tracing::debug!(
        "[switchcase] found {} switches with {} total cases, {} wired",
        stats.switches_found, stats.total_cases, stats.cases_wired
    );

    Ok(stats)
}
