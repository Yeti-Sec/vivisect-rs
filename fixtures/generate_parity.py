#!/usr/bin/env python3
"""Differential-parity oracle generator (roadmap Phase 11).

Emits a canonical, per-layer JSON snapshot of Python vivisect's analysis of a
sample, for the Rust parity runner (tests/parity_runner_test.rs) to diff against
vivisect-rs. Each layer is a map { "0x<addr>": "<canonical value>" } so the Rust
`compare_layer` can compute exact / missing / extra / mismatch / unsupported per
layer without collapsing to one percentage.

This is the OFFLINE ORACLE CONTRACT. It requires an installed Python `vivisect`
(a documented external blocker in this environment). Run:

    python fixtures/generate_parity.py <sample> fixtures/parity_oracle.json

Layers emitted:
  memory        base -> "perm:size:sha1(bytes)"     (loader/mapped image)
  opcodes       va   -> mnemonic + operand repr      (disasm syntax)
  functions     va   -> function name                (discovery)
  blocks        va   -> "size"                       (basic blocks)
  xrefs         from -> "to:reftype" (joined)        (cross-refs)
  imports       slot -> "lib.name"                   (imports)
  conventions   va   -> calling convention           (ABI)
"""
import hashlib
import json
import sys


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()[:16]


def build_oracle(path: str) -> dict:
    import vivisect  # external: only present where Python vivisect is installed

    vw = vivisect.VivWorkspace()
    vw.loadFromFile(path)
    vw.analyze()

    memory = {}
    for va, size, perms, _fname in vw.getMemoryMaps():
        try:
            data = vw.readMemory(va, size)
        except Exception:
            data = b""
        memory[hex(va)] = f"{perms}:{size}:{_sha1(data)}"

    opcodes, blocks, conventions = {}, {}, {}
    for fva in vw.getFunctions():
        conventions[hex(fva)] = vw.getFunctionMeta(fva, "CallingConvention") or ""
        for bva, bsize, _bfva in vw.getFunctionBlocks(fva):
            blocks[hex(bva)] = str(bsize)
            va = bva
            while va < bva + bsize:
                try:
                    op = vw.parseOpcode(va)
                except Exception:
                    break
                opcodes[hex(va)] = repr(op)
                va += len(op)

    functions = {hex(fva): (vw.getName(fva) or "") for fva in vw.getFunctions()}

    xrefs = {}
    for frm, to, rtype, _flags in vw.getXrefs():
        xrefs.setdefault(hex(frm), []).append(f"{hex(to)}:{rtype}")
    xrefs = {k: ",".join(sorted(v)) for k, v in xrefs.items()}

    imports = {}
    for va, _size, _ltype, tinfo in vw.getImports():
        imports[hex(va)] = str(tinfo)

    return {
        "source": "python-vivisect",
        "file": path,
        "layers": {
            "memory": memory,
            "opcodes": opcodes,
            "functions": functions,
            "blocks": blocks,
            "xrefs": xrefs,
            "imports": imports,
            "conventions": conventions,
        },
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    oracle = build_oracle(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(oracle, f, indent=2, sort_keys=True)
    total = sum(len(v) for v in oracle["layers"].values())
    print(f"wrote {sys.argv[2]}: {total} items across {len(oracle['layers'])} layers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
