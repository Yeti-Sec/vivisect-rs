"""
Generate algorithm parity reference vectors from Python vivisect.

Captures reference test vectors for 7 of the 9 parity specs:
  Spec 1: PE import parsing (imports with IAT addresses)
  Spec 3: x86 disassembly flags (all functions, full instruction coverage)
  Spec 4: Code flow analysis (per-function block boundaries)
  Spec 7: CFG construction (edge lists per function)
  Spec 8: XRef tracking (full xref set)
  Spec 9: String detection (all strings with encoding)

Specs 2 (ELF), 5 (symbolic reduction), 6 (symbolic translation) require
separate generators.

Usage: python generate_vectors.py <binary_path> <output_json_path>
"""

import json
import sys
import os
import time

sys.path.insert(0, os.path.expanduser(r"C:\Users\yeti-sec\Desktop\vivisect"))

import vivisect
import vivisect.const as v_const
import envi


def capture_spec1_pe_imports(vw):
    """Spec 1: PE import parsing — (dll, name, iat_address) tuples."""
    imports = []
    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_IMPORT):
        name = vw.getName(va) or ""
        # Parse "library.function" format
        parts = name.split(".", 1)
        if len(parts) == 2:
            dll, func = parts
        else:
            dll, func = "", name
        imports.append({
            "iat_address": va,
            "dll": dll,
            "name": func,
            "full_name": name,
        })
    return sorted(imports, key=lambda i: i["iat_address"])


def capture_spec3_disasm_flags(vw):
    """Spec 3: x86 disassembly flags — full instruction coverage.

    Captures flags for every instruction in every function to enable
    comprehensive flag parity testing (is_call, is_branch, is_return, etc.)
    """
    functions = sorted(vw.getFunctions())
    all_disasm = []
    total_instructions = 0

    for fva in functions:
        blocks = vw.getFunctionBlocks(fva)
        if not blocks:
            continue

        func_instructions = []
        for bva, bsize, bfva in sorted(blocks, key=lambda b: b[0]):
            offset = 0
            while offset < bsize:
                try:
                    op = vw.parseOpcode(bva + offset)
                    iflags = op.iflags

                    insn = {
                        "va": op.va,
                        "size": len(op),
                        "mnem": op.mnem,
                        "is_call": op.isCall(),
                        "is_branch": bool(iflags & envi.IF_BRANCH),
                        "is_return": op.isReturn(),
                        "is_cond": bool(iflags & envi.IF_COND),
                        "falls_through": not (
                            op.isReturn()
                            or (
                                bool(iflags & envi.IF_BRANCH)
                                and not bool(iflags & envi.IF_COND)
                            )
                        ),
                        "iflags": iflags,
                    }

                    # Capture branch targets
                    branches = []
                    for brtgt, brflags in op.getBranches():
                        branches.append({"target": brtgt, "flags": brflags})
                    if branches:
                        insn["branches"] = branches

                    func_instructions.append(insn)
                    offset += len(op)
                    total_instructions += 1
                except Exception:
                    break

        if func_instructions:
            all_disasm.append({
                "function_va": fva,
                "instruction_count": len(func_instructions),
                "instructions": func_instructions,
            })

    return {
        "functions_disassembled": len(all_disasm),
        "total_instructions": total_instructions,
        "functions": all_disasm,
    }


def capture_spec4_codeflow(vw):
    """Spec 4: Code flow analysis — per-function block boundaries.

    For each function, captures the ordered list of (block_start, block_end)
    pairs that define its basic blocks.
    """
    functions = sorted(vw.getFunctions())
    results = []

    for fva in functions:
        blocks = vw.getFunctionBlocks(fva)
        if not blocks:
            continue

        block_boundaries = []
        for bva, bsize, bfva in sorted(blocks, key=lambda b: b[0]):
            block_boundaries.append({
                "start": bva,
                "end": bva + bsize,
                "size": bsize,
            })

        fname = vw.getName(fva) or ""
        fsize = vw.getFunctionMeta(fva, "Size", 0)

        results.append({
            "function_va": fva,
            "function_name": fname,
            "function_size": fsize,
            "block_count": len(block_boundaries),
            "blocks": block_boundaries,
        })

    return {
        "function_count": len(results),
        "total_blocks": sum(f["block_count"] for f in results),
        "functions": results,
    }


def capture_spec7_cfg_edges(vw):
    """Spec 7: CFG construction — edge lists per function.

    For each function, captures the directed graph of
    (block_va -> [successor_va]) edges by examining xrefs from
    terminal instructions and fall-through addresses.
    """
    functions = sorted(vw.getFunctions())
    results = []

    for fva in functions:
        blocks = vw.getFunctionBlocks(fva)
        if not blocks:
            continue

        block_set = set()
        block_list = []
        for bva, bsize, bfva in sorted(blocks, key=lambda b: b[0]):
            block_set.add(bva)
            block_list.append((bva, bsize))

        edges = []
        for bva, bsize in block_list:
            successors = []

            # Walk the last few bytes of the block looking for xrefs
            # The terminal instruction is somewhere in the last ~15 bytes
            check_start = max(bva, bva + bsize - 15)
            for addr in range(check_start, bva + bsize):
                for xref in vw.getXrefsFrom(addr):
                    to_va = xref[1]  # (from_va, to_va, rtype, rflags)
                    if to_va in block_set and to_va not in successors:
                        successors.append(to_va)

            # Check fall-through
            fall_va = bva + bsize
            if fall_va in block_set:
                # Check if last instruction falls through
                try:
                    # Find terminal instruction
                    offset = 0
                    last_op = None
                    while offset < bsize:
                        op = vw.parseOpcode(bva + offset)
                        last_op = op
                        offset += len(op)

                    if last_op is not None:
                        is_nofall = last_op.isReturn() or (
                            bool(last_op.iflags & envi.IF_BRANCH)
                            and not bool(last_op.iflags & envi.IF_COND)
                        )
                        if not is_nofall and fall_va not in successors:
                            successors.append(fall_va)
                except Exception:
                    pass

            if successors:
                edges.append({
                    "from_block": bva,
                    "to_blocks": sorted(successors),
                })

        results.append({
            "function_va": fva,
            "block_count": len(block_list),
            "edge_count": len(edges),
            "edges": edges,
        })

    return {
        "function_count": len(results),
        "total_edges": sum(f["edge_count"] for f in results),
        "functions": results,
    }


def capture_spec8_xrefs(vw):
    """Spec 8: XRef tracking — full xref set."""
    xrefs = []
    for xref in vw.getXrefs():
        from_va, to_va, rtype, rflags = xref
        xrefs.append({
            "from_va": from_va,
            "to_va": to_va,
            "ref_type": rtype,
            "ref_flags": rflags,
        })
    return {
        "xref_count": len(xrefs),
        "xrefs": sorted(xrefs, key=lambda x: (x["from_va"], x["to_va"])),
    }


def capture_spec9_strings(vw):
    """Spec 9: String detection — all strings with encoding."""
    strings = []

    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_STRING):
        try:
            s = vw.readMemory(va, min(size, 4096))
            content = s.split(b"\x00")[0].decode("ascii", errors="replace")
            strings.append({
                "va": va,
                "size": size,
                "content": content,
                "encoding": "ascii",
            })
        except Exception:
            pass

    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_UNI):
        try:
            s = vw.readMemory(va, min(size, 8192))
            content = s.decode("utf-16-le", errors="replace").split("\x00")[0]
            strings.append({
                "va": va,
                "size": size,
                "content": content,
                "encoding": "utf-16-le",
            })
        except Exception:
            pass

    return {
        "string_count": len(strings),
        "strings": sorted(strings, key=lambda s: s["va"]),
    }


def capture_metadata(vw, filepath):
    """File metadata and analysis summary."""
    return {
        "architecture": vw.getMeta("Architecture"),
        "platform": vw.getMeta("Platform"),
        "format": vw.getMeta("Format"),
        "bigend": vw.getMeta("bigend", False),
        "entry_points": sorted(vw.getEntryPoints()),
        "base_address": vw.getMeta("imagebase", 0),
        "pointer_size": vw.getMeta("psize", 4),
    }


def generate_vectors(filepath):
    """Generate all reference vectors for a binary."""
    print(f"[*] Loading {filepath}...")
    t0 = time.time()

    vw = vivisect.VivWorkspace()
    vw.verbose = False
    vw.loadFromFile(filepath)

    t_load = time.time() - t0
    print(f"[*] Load complete in {t_load:.1f}s")

    print("[*] Running auto-analysis...")
    t1 = time.time()
    vw.analyze()
    t_analyze = time.time() - t1
    print(f"[*] Analysis complete in {t_analyze:.1f}s")
    print(f"    Functions: {len(vw.getFunctions())}")
    print(f"    Code blocks: {len(vw.getCodeBlocks())}")

    result = {
        "source": "python-vivisect",
        "generator": "generate_vectors.py",
        "file": os.path.basename(filepath),
        "file_size": os.path.getsize(filepath),
    }

    print("[*] Capturing metadata...")
    result["metadata"] = capture_metadata(vw, filepath)

    # Segments
    segments = []
    for va, size, perms, filename in vw.getMemoryMaps():
        segments.append({"va": va, "size": size, "perms": perms, "name": filename})
    result["segments"] = sorted(segments, key=lambda s: s["va"])

    print("[*] Capturing Spec 1: PE import parsing...")
    result["spec1_imports"] = capture_spec1_pe_imports(vw)
    print(f"    {len(result['spec1_imports'])} imports")

    print("[*] Capturing Spec 3: x86 disassembly flags (all functions)...")
    result["spec3_disasm"] = capture_spec3_disasm_flags(vw)
    print(
        f"    {result['spec3_disasm']['functions_disassembled']} functions, "
        f"{result['spec3_disasm']['total_instructions']} instructions"
    )

    print("[*] Capturing Spec 4: Code flow block boundaries...")
    result["spec4_codeflow"] = capture_spec4_codeflow(vw)
    print(
        f"    {result['spec4_codeflow']['function_count']} functions, "
        f"{result['spec4_codeflow']['total_blocks']} blocks"
    )

    print("[*] Capturing Spec 7: CFG edges...")
    result["spec7_cfg"] = capture_spec7_cfg_edges(vw)
    print(
        f"    {result['spec7_cfg']['function_count']} functions, "
        f"{result['spec7_cfg']['total_edges']} edges"
    )

    print("[*] Capturing Spec 8: XRefs...")
    result["spec8_xrefs"] = capture_spec8_xrefs(vw)
    print(f"    {result['spec8_xrefs']['xref_count']} xrefs")

    print("[*] Capturing Spec 9: Strings...")
    result["spec9_strings"] = capture_spec9_strings(vw)
    print(f"    {result['spec9_strings']['string_count']} strings")

    result["timing"] = {
        "load_seconds": round(t_load, 2),
        "analysis_seconds": round(t_analyze, 2),
        "total_seconds": round(time.time() - t0, 2),
    }

    return result


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_path> <output_json_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(binary_path):
        print(f"Error: {binary_path} not found")
        sys.exit(1)

    result = generate_vectors(binary_path)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    file_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"\n[+] Reference vectors written to {output_path} ({file_mb:.1f} MB)")


if __name__ == "__main__":
    main()
