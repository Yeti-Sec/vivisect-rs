"""
Generate golden output from Python vivisect for parity testing against Rust port.

Usage: python generate_golden.py <binary_path> <output_json_path>

Captures:
  - File metadata (format, arch, entry point, image base)
  - Sections (name, va, size, perms)
  - Imports (library, name, address)
  - Exports (name, address)
  - Functions discovered (va, name, size, block count)
  - Code blocks (va, size, function_va)
  - XRefs (from_va, to_va, ref_type)
  - Disassembly sample (first 500 instructions from entry point vicinity)
  - Strings found
"""

import json
import sys
import os
import time

# Add vivisect to path
sys.path.insert(0, os.path.expanduser(r"C:\Users\yeti-sec\Desktop\vivisect"))

import vivisect
import vivisect.const as v_const
import envi


def analyze_binary(filepath):
    """Load and analyze a binary with vivisect, return structured results."""
    result = {
        "source": "python-vivisect",
        "file": os.path.basename(filepath),
        "file_size": os.path.getsize(filepath),
    }

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

    # --- File Metadata ---
    result["metadata"] = {
        "architecture": vw.getMeta("Architecture"),
        "platform": vw.getMeta("Platform"),
        "format": vw.getMeta("Format"),
        "bigend": vw.getMeta("bigend", False),
        "entry_points": sorted(vw.getEntryPoints()),
        "base_address": vw.getMeta("imagebase", 0),
        "pointer_size": vw.getMeta("psize", 4),
    }

    # --- Segments / Memory Maps ---
    segments = []
    for va, size, perms, filename in vw.getMemoryMaps():
        segments.append({
            "va": va,
            "size": size,
            "perms": perms,
            "name": filename,
        })
    result["segments"] = sorted(segments, key=lambda s: s["va"])

    # --- Imports ---
    imports = []
    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_IMPORT):
        name = vw.getName(va) or ""
        imports.append({
            "va": va,
            "name": name,
        })
    result["imports"] = sorted(imports, key=lambda i: i["va"])

    # --- Exports ---
    exports = []
    for va, etype, ename, efilename in vw.getExports():
        exports.append({
            "va": va,
            "type": etype,
            "name": ename,
            "filename": efilename,
        })
    result["exports"] = sorted(exports, key=lambda e: e["va"])

    # --- Functions ---
    functions = []
    for fva in sorted(vw.getFunctions()):
        fname = vw.getName(fva) or ""
        fsize = vw.getFunctionMeta(fva, "Size", 0)
        blocks = vw.getFunctionBlocks(fva)
        block_count = len(blocks) if blocks else 0

        func_info = {
            "va": fva,
            "name": fname,
            "size": fsize,
            "block_count": block_count,
        }

        # Get calling convention if set
        try:
            cc = vw.getFunctionMeta(fva, "CallingConvention", None)
            if cc:
                func_info["calling_convention"] = cc
        except Exception:
            pass

        functions.append(func_info)

    result["functions"] = functions
    result["function_count"] = len(functions)

    # --- Code Blocks ---
    codeblocks = []
    for cb in vw.getCodeBlocks():
        va, size, fva = cb
        codeblocks.append({
            "va": va,
            "size": size,
            "function_va": fva,
        })
    result["codeblocks"] = sorted(codeblocks, key=lambda b: b["va"])
    result["codeblock_count"] = len(codeblocks)

    # --- XRefs ---
    xrefs = []
    for xref in vw.getXrefs():
        from_va, to_va, rtype, rflags = xref
        xrefs.append({
            "from_va": from_va,
            "to_va": to_va,
            "ref_type": rtype,
            "ref_flags": rflags,
        })
    result["xrefs"] = sorted(xrefs, key=lambda x: (x["from_va"], x["to_va"]))
    result["xref_count"] = len(xrefs)

    # --- Strings ---
    strings = []
    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_STRING):
        try:
            s = vw.readMemory(va, min(size, 256))
            content = s.split(b'\x00')[0].decode('ascii', errors='replace')
            strings.append({
                "va": va,
                "size": size,
                "content": content,
            })
        except Exception:
            pass

    for va, size, ltype, tinfo in vw.getLocations(v_const.LOC_UNI):
        try:
            s = vw.readMemory(va, min(size, 512))
            content = s.decode('utf-16-le', errors='replace').split('\x00')[0]
            strings.append({
                "va": va,
                "size": size,
                "content": content,
                "encoding": "utf-16-le",
            })
        except Exception:
            pass

    result["strings"] = sorted(strings, key=lambda s: s["va"])
    result["string_count"] = len(strings)

    # --- Disassembly Sample ---
    # Disassemble first N instructions from each of the first 10 functions
    disasm_sample = []
    sample_functions = sorted(vw.getFunctions())[:10]

    for fva in sample_functions:
        blocks = vw.getFunctionBlocks(fva)
        if not blocks:
            continue

        func_disasm = []
        insn_count = 0
        for bva, bsize, bfva in sorted(blocks, key=lambda b: b[0]):
            offset = 0
            while offset < bsize and insn_count < 50:
                try:
                    op = vw.parseOpcode(bva + offset)
                    insn = {
                        "va": op.va,
                        "size": len(op),
                        "mnem": op.mnem,
                        "opstr": str(op),
                        "is_call": op.isCall(),
                        "is_branch": bool(op.iflags & envi.IF_BRANCH),
                        "is_return": op.isReturn(),
                        "falls_through": not (op.isReturn() or
                                             (bool(op.iflags & envi.IF_BRANCH) and
                                              not bool(op.iflags & envi.IF_COND))),
                        "operand_count": len(op.opers),
                    }

                    # Capture branch targets
                    branches = []
                    for brtgt, brflags in op.getBranches():
                        branches.append({
                            "target": brtgt,
                            "flags": brflags,
                        })
                    if branches:
                        insn["branches"] = branches

                    func_disasm.append(insn)
                    offset += len(op)
                    insn_count += 1
                except Exception:
                    offset += 1
                    break

        if func_disasm:
            disasm_sample.append({
                "function_va": fva,
                "function_name": vw.getName(fva) or "",
                "instructions": func_disasm,
            })

    result["disassembly_sample"] = disasm_sample

    # --- Locations Summary ---
    loc_counts = {}
    loc_type_names = {
        v_const.LOC_UNDEF: "undefined",
        v_const.LOC_NUMBER: "number",
        v_const.LOC_STRING: "string",
        v_const.LOC_UNI: "unicode",
        v_const.LOC_POINTER: "pointer",
        v_const.LOC_OP: "opcode",
        v_const.LOC_STRUCT: "struct",
        v_const.LOC_CLSID: "clsid",
        v_const.LOC_VFTABLE: "vftable",
        v_const.LOC_IMPORT: "import",
        v_const.LOC_PAD: "pad",
    }
    for va, size, ltype, tinfo in vw.getLocations():
        name = loc_type_names.get(ltype, f"type_{ltype}")
        loc_counts[name] = loc_counts.get(name, 0) + 1

    result["location_counts"] = loc_counts

    # --- Timing ---
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

    result = analyze_binary(binary_path)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n[+] Golden output written to {output_path}")
    print(f"    Functions: {result['function_count']}")
    print(f"    Code blocks: {result['codeblock_count']}")
    print(f"    XRefs: {result['xref_count']}")
    print(f"    Strings: {result['string_count']}")
    print(f"    Imports: {len(result['imports'])}")
    print(f"    Exports: {len(result['exports'])}")


if __name__ == "__main__":
    main()
