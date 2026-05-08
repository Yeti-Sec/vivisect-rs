"""
Generate symbolic analysis parity reference vectors from Python vivisect.

Captures reference test vectors for 2 of the 9 parity specs:
  Spec 5: Symbolic reduction (algebraic simplification rules)
  Spec 6: Symbolic translation (x86 instruction -> symbolic effects)

Usage: python generate_symboliks_vectors.py <output_json_path>
"""

import json
import sys
import os

sys.path.insert(0, os.path.expanduser(r"C:\Users\yeti-sec\Desktop\vivisect"))

import vivisect
import envi
from vivisect.symboliks.common import (
    Const, Var, Mem, Arg,
    o_add, o_sub, o_mul, o_div, o_mod,
    o_and, o_or, o_xor,
    o_lshift, o_rshift, o_pow,
    eq, ne, lt, le, gt, ge,
)
from vivisect.symboliks.effects import SetVariable, ReadMemory, WriteMemory


def expr_to_dict(sym):
    """Convert a symbolic expression to a serializable dict."""
    return {
        "repr": str(sym),
        "width": sym.getWidth(),
        "discrete": sym.isDiscrete(),
        "symtype": sym.symtype,
    }


def capture_spec5_reduction():
    """Spec 5: Symbolic reduction — algebraic simplification rules.

    Creates expressions, reduces them, and captures before/after pairs.
    Covers: constant folding, identity, annihilation, self-cancellation,
    associative folding, strength reduction, constraint folding.
    """
    eax = Var("eax", 4)
    ebx = Var("ebx", 4)
    rax = Var("rax", 8)
    rbx = Var("rbx", 8)

    test_cases = []

    def add_case(category, description, expr):
        before_str = str(expr)
        before_discrete = expr.isDiscrete()
        reduced = expr.reduce()
        reduced_str = str(reduced)
        reduced_discrete = reduced.isDiscrete()

        # Try to solve if discrete
        solved = None
        if reduced_discrete:
            try:
                solved = reduced.solve()
            except Exception:
                pass

        test_cases.append({
            "category": category,
            "description": description,
            "before": before_str,
            "after": reduced_str,
            "before_discrete": before_discrete,
            "after_discrete": reduced_discrete,
            "solved_value": solved,
            "width": expr.getWidth(),
        })

    # --- Constant folding ---
    add_case("const_fold", "add two constants",
             o_add(Const(10, 4), Const(20, 4), 4))
    add_case("const_fold", "sub two constants",
             o_sub(Const(100, 4), Const(30, 4), 4))
    add_case("const_fold", "mul two constants",
             o_mul(Const(7, 4), Const(6, 4), 4))
    add_case("const_fold", "div two constants",
             o_div(Const(100, 4), Const(10, 4), 4))
    add_case("const_fold", "mod two constants",
             o_mod(Const(100, 4), Const(7, 4), 4))
    add_case("const_fold", "and two constants",
             o_and(Const(0xFF00, 4), Const(0x0F0F, 4), 4))
    add_case("const_fold", "or two constants",
             o_or(Const(0xFF00, 4), Const(0x00FF, 4), 4))
    add_case("const_fold", "xor two constants",
             o_xor(Const(0xAAAA, 4), Const(0x5555, 4), 4))
    add_case("const_fold", "lshift constant",
             o_lshift(Const(1, 4), Const(8, 4), 4))
    add_case("const_fold", "rshift constant",
             o_rshift(Const(0x100, 4), Const(4, 4), 4))
    add_case("const_fold", "overflow wraps 32-bit",
             o_add(Const(0xFFFFFFFF, 4), Const(1, 4), 4))
    add_case("const_fold", "overflow wraps 8-bit",
             o_add(Const(0xFF, 1), Const(1, 1), 1))

    # --- Identity operations ---
    add_case("identity", "x + 0",
             o_add(eax, Const(0, 4), 4))
    add_case("identity", "0 + x",
             o_add(Const(0, 4), eax, 4))
    add_case("identity", "x - 0",
             o_sub(eax, Const(0, 4), 4))
    add_case("identity", "x * 1",
             o_mul(eax, Const(1, 4), 4))
    add_case("identity", "1 * x",
             o_mul(Const(1, 4), eax, 4))
    add_case("identity", "x / 1",
             o_div(eax, Const(1, 4), 4))
    add_case("identity", "x & 0xFFFFFFFF",
             o_and(eax, Const(0xFFFFFFFF, 4), 4))
    add_case("identity", "x | 0",
             o_or(eax, Const(0, 4), 4))
    add_case("identity", "x ^ 0",
             o_xor(eax, Const(0, 4), 4))
    add_case("identity", "x << 0",
             o_lshift(eax, Const(0, 4), 4))
    add_case("identity", "x >> 0",
             o_rshift(eax, Const(0, 4), 4))

    # --- Annihilation ---
    add_case("annihilation", "x * 0",
             o_mul(eax, Const(0, 4), 4))
    add_case("annihilation", "0 * x",
             o_mul(Const(0, 4), eax, 4))
    add_case("annihilation", "x & 0",
             o_and(eax, Const(0, 4), 4))
    add_case("annihilation", "0 & x",
             o_and(Const(0, 4), eax, 4))
    add_case("annihilation", "x % 1",
             o_mod(eax, Const(1, 4), 4))

    # --- Self-cancellation ---
    add_case("self_cancel", "x - x",
             o_sub(eax, eax, 4))
    add_case("self_cancel", "x ^ x",
             o_xor(eax, eax, 4))

    # --- Idempotent ---
    add_case("idempotent", "x & x",
             o_and(eax, eax, 4))
    add_case("idempotent", "x | x",
             o_or(eax, eax, 4))

    # --- Associative constant folding ---
    add_case("assoc_fold", "(x + 10) + 20",
             o_add(o_add(eax, Const(10, 4), 4), Const(20, 4), 4))
    add_case("assoc_fold", "(x - 10) - 20",
             o_sub(o_sub(eax, Const(10, 4), 4), Const(20, 4), 4))
    add_case("assoc_fold", "(x + 10) + (y + 20)",
             o_add(o_add(eax, Const(10, 4), 4),
                   o_add(ebx, Const(20, 4), 4), 4))
    add_case("assoc_fold", "(x * 3) * 4",
             o_mul(o_mul(eax, Const(3, 4), 4), Const(4, 4), 4))
    add_case("assoc_fold", "(x & 0xFF00) & 0x0F0F",
             o_and(o_and(eax, Const(0xFF00, 4), 4), Const(0x0F0F, 4), 4))
    add_case("assoc_fold", "(x | 0xFF00) | 0x00FF",
             o_or(o_or(eax, Const(0xFF00, 4), 4), Const(0x00FF, 4), 4))

    # --- Strength reduction ---
    add_case("strength", "x * 2 -> x << 1",
             o_mul(eax, Const(2, 4), 4))
    add_case("strength", "x * 4 -> x << 2",
             o_mul(eax, Const(4, 4), 4))
    add_case("strength", "x * 8 -> x << 3",
             o_mul(eax, Const(8, 4), 4))
    add_case("strength", "x * 16 -> x << 4",
             o_mul(eax, Const(16, 4), 4))

    # --- Power operations ---
    add_case("power", "x ** 0",
             o_pow(eax, Const(0, 4), 4))
    add_case("power", "x ** 1",
             o_pow(eax, Const(1, 4), 4))

    # --- Constraint folding ---
    add_case("constraint", "x == x", eq(eax, eax))
    add_case("constraint", "x != x", ne(eax, eax))
    add_case("constraint", "x < x", lt(eax, eax))
    add_case("constraint", "x <= x", le(eax, eax))
    add_case("constraint", "x > x", gt(eax, eax))
    add_case("constraint", "x >= x", ge(eax, eax))
    add_case("constraint", "5 == 5", eq(Const(5, 4), Const(5, 4)))
    add_case("constraint", "5 != 5", ne(Const(5, 4), Const(5, 4)))
    add_case("constraint", "3 < 5", lt(Const(3, 4), Const(5, 4)))
    add_case("constraint", "5 < 3", lt(Const(5, 4), Const(3, 4)))

    # --- Mixed width ---
    add_case("width", "8-byte add constants",
             o_add(Const(0x100000000, 8), Const(0x200000000, 8), 8))
    add_case("width", "8-byte x + 0",
             o_add(rax, Const(0, 8), 8))
    add_case("width", "8-byte x ^ x",
             o_xor(rax, rax, 8))

    # --- Nested expressions ---
    add_case("nested", "(x + 10) + (x + 10)",
             o_add(o_add(eax, Const(10, 4), 4),
                   o_add(eax, Const(10, 4), 4), 4))
    add_case("nested", "((x + 5) + 5) + 5",
             o_add(o_add(o_add(eax, Const(5, 4), 4),
                         Const(5, 4), 4), Const(5, 4), 4))
    add_case("nested", "(x & 0xFF) & 0xFF",
             o_and(o_and(eax, Const(0xFF, 4), 4), Const(0xFF, 4), 4))

    return {
        "test_count": len(test_cases),
        "categories": list(set(c["category"] for c in test_cases)),
        "tests": test_cases,
    }


def capture_spec6_translation():
    """Spec 6: Symbolic translation — x86 instruction to symbolic effects.

    Parses x86 opcodes and translates them to symbolic effects,
    capturing the effect list for each instruction.
    """
    # Create workspace for i386
    vw32 = vivisect.VivWorkspace()
    vw32.verbose = False
    vw32.setMeta("Architecture", "i386")
    vw32.setMeta("Platform", "windows")
    vw32.setMeta("Format", "pe")
    vw32.setMeta("bigend", False)
    vw32.setMeta("psize", 4)

    # We need the arch module initialized
    vw32.addMemoryMap(0x400000, 7, "test", b"\x00" * 0x10000)

    from vivisect.symboliks.archs.i386 import i386SymbolikTranslator

    # i386 test instructions (opcode bytes -> expected mnemonic)
    i386_instructions = [
        # Data movement
        ("89c1",        "mov ecx, eax"),
        ("8b4508",      "mov eax, [ebp+8]"),
        ("894508",      "mov [ebp+8], eax"),
        ("31c0",        "xor eax, eax"),
        ("b801000000",  "mov eax, 1"),
        ("8d4508",      "lea eax, [ebp+8]"),
        ("0fb6c0",      "movzx eax, al"),
        ("0fbec0",      "movsx eax, al"),

        # Arithmetic
        ("01c8",        "add eax, ecx"),
        ("0500010000",  "add eax, 0x100"),
        ("29c8",        "sub eax, ecx"),
        ("2d00010000",  "sub eax, 0x100"),
        ("f7e1",        "mul ecx"),
        ("f7f9",        "idiv ecx"),
        ("40",          "inc eax"),
        ("48",          "dec eax"),
        ("f7d8",        "neg eax"),

        # Logic
        ("21c8",        "and eax, ecx"),
        ("2500ff0000",  "and eax, 0xff00"),
        ("09c8",        "or eax, ecx"),
        ("0d00ff0000",  "or eax, 0xff00"),
        ("31c8",        "xor eax, ecx"),
        ("f7d0",        "not eax"),

        # Shifts
        ("c1e004",      "shl eax, 4"),
        ("c1e804",      "shr eax, 4"),
        ("c1f804",      "sar eax, 4"),

        # Stack
        ("50",          "push eax"),
        ("58",          "pop eax"),

        # Compare/test
        ("39c8",        "cmp eax, ecx"),
        ("3d00010000",  "cmp eax, 0x100"),
        ("85c0",        "test eax, eax"),

        # Control flow
        ("c3",          "ret"),
        ("90",          "nop"),
    ]

    results_i386 = []
    for opcode_hex, description in i386_instructions:
        opbytes = bytes.fromhex(opcode_hex)
        # Write bytes to memory so parseOpcode works
        vw32.writeMemory(0x401000, opbytes)

        try:
            op = vw32.parseOpcode(0x401000)
            mnem = op.mnem

            # Create translator and translate
            xlator = i386SymbolikTranslator(vw32)
            xlator.translateOpcode(op)

            effects = []
            for eff in xlator.getEffects():
                eff_dict = {
                    "type": type(eff).__name__,
                    "repr": str(eff),
                }
                # Extract specific fields based on effect type
                if isinstance(eff, SetVariable):
                    eff_dict["varname"] = eff.varname
                    eff_dict["value_repr"] = str(eff.symobj)
                elif isinstance(eff, ReadMemory):
                    eff_dict["addr_repr"] = str(eff.symaddr)
                elif isinstance(eff, WriteMemory):
                    eff_dict["addr_repr"] = str(eff.symaddr)
                    eff_dict["value_repr"] = str(eff.symval)
                effects.append(eff_dict)

            constraints = []
            for cons in xlator.getConstraints():
                constraints.append(str(cons))

            results_i386.append({
                "opcode_hex": opcode_hex,
                "description": description,
                "mnemonic": mnem,
                "opcode_size": len(op),
                "effect_count": len(effects),
                "effects": effects,
                "constraint_count": len(constraints),
                "constraints": constraints,
            })
        except Exception as e:
            results_i386.append({
                "opcode_hex": opcode_hex,
                "description": description,
                "error": str(e),
            })

    # Now do amd64
    vw64 = vivisect.VivWorkspace()
    vw64.verbose = False
    vw64.setMeta("Architecture", "amd64")
    vw64.setMeta("Platform", "windows")
    vw64.setMeta("Format", "pe")
    vw64.setMeta("bigend", False)
    vw64.setMeta("psize", 8)
    vw64.addMemoryMap(0x140000000, 7, "test", b"\x00" * 0x10000)

    from vivisect.symboliks.archs.amd64 import Amd64SymbolikTranslator

    amd64_instructions = [
        # Data movement
        ("4889c1",          "mov rcx, rax"),
        ("488b4508",        "mov rax, [rbp+8]"),
        ("48894508",        "mov [rbp+8], rax"),
        ("4831c0",          "xor rax, rax"),
        ("48c7c001000000",  "mov rax, 1"),
        ("488d4508",        "lea rax, [rbp+8]"),
        ("0fb6c0",          "movzx eax, al"),
        ("480fbed0",        "movsx rdx, al"),
        ("4863c8",          "movsxd rcx, eax"),

        # Arithmetic
        ("4801c8",          "add rax, rcx"),
        ("480500010000",    "add rax, 0x100"),
        ("4829c8",          "sub rax, rcx"),
        ("482d00010000",    "sub rax, 0x100"),
        ("48ffc0",          "inc rax"),
        ("48ffc8",          "dec rax"),
        ("48f7d8",          "neg rax"),

        # Logic
        ("4821c8",          "and rax, rcx"),
        ("4809c8",          "or rax, rcx"),
        ("4831c8",          "xor rax, rcx"),
        ("48f7d0",          "not rax"),

        # Shifts
        ("48c1e004",        "shl rax, 4"),
        ("48c1e804",        "shr rax, 4"),
        ("48c1f804",        "sar rax, 4"),

        # Stack
        ("50",              "push rax"),
        ("58",              "pop rax"),

        # Compare/test
        ("4839c8",          "cmp rax, rcx"),
        ("4885c0",          "test rax, rax"),

        # Control flow
        ("c3",              "ret"),
        ("90",              "nop"),

        # Sign extension
        ("9948",            "cdq -> cqo"),
        ("98",              "cbw/cwde/cdqe"),

        # Leave
        ("c9",              "leave"),
    ]

    results_amd64 = []
    for opcode_hex, description in amd64_instructions:
        opbytes = bytes.fromhex(opcode_hex)
        vw64.writeMemory(0x140001000, opbytes)

        try:
            op = vw64.parseOpcode(0x140001000)
            mnem = op.mnem

            xlator = Amd64SymbolikTranslator(vw64)
            xlator.translateOpcode(op)

            effects = []
            for eff in xlator.getEffects():
                eff_dict = {
                    "type": type(eff).__name__,
                    "repr": str(eff),
                }
                if isinstance(eff, SetVariable):
                    eff_dict["varname"] = eff.varname
                    eff_dict["value_repr"] = str(eff.symobj)
                elif isinstance(eff, ReadMemory):
                    eff_dict["addr_repr"] = str(eff.symaddr)
                elif isinstance(eff, WriteMemory):
                    eff_dict["addr_repr"] = str(eff.symaddr)
                    eff_dict["value_repr"] = str(eff.symval)
                effects.append(eff_dict)

            constraints = []
            for cons in xlator.getConstraints():
                constraints.append(str(cons))

            results_amd64.append({
                "opcode_hex": opcode_hex,
                "description": description,
                "mnemonic": mnem,
                "opcode_size": len(op),
                "effect_count": len(effects),
                "effects": effects,
                "constraint_count": len(constraints),
                "constraints": constraints,
            })
        except Exception as e:
            results_amd64.append({
                "opcode_hex": opcode_hex,
                "description": description,
                "error": str(e),
            })

    return {
        "i386": {
            "instruction_count": len(results_i386),
            "instructions": results_i386,
        },
        "amd64": {
            "instruction_count": len(results_amd64),
            "instructions": results_amd64,
        },
    }


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_json_path>")
        sys.exit(1)

    output_path = sys.argv[1]

    print("[*] Generating Spec 5: Symbolic reduction vectors...")
    spec5 = capture_spec5_reduction()
    print(f"    {spec5['test_count']} reduction test cases")

    print("[*] Generating Spec 6: Symbolic translation vectors...")
    spec6 = capture_spec6_translation()
    print(f"    i386: {spec6['i386']['instruction_count']} instructions")
    print(f"    amd64: {spec6['amd64']['instruction_count']} instructions")

    result = {
        "source": "python-vivisect",
        "generator": "generate_symboliks_vectors.py",
        "spec5_reduction": spec5,
        "spec6_translation": spec6,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    file_kb = os.path.getsize(output_path) / 1024
    print(f"\n[+] Symboliks vectors written to {output_path} ({file_kb:.1f} KB)")


if __name__ == "__main__":
    main()
