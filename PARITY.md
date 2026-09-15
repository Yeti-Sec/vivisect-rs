# Parity with Python vivisect

vivisect-rs aims for behavioral parity with the original Python
[vivisect](https://github.com/vivisect/vivisect) on the subsystems it implements. Parity is
measured per subsystem against an oracle — never collapsed into a single aggregate percentage —
so a passing result states exactly what was compared and against what.

## Oracles

| Oracle | Status | Notes |
|--------|--------|-------|
| Committed golden JSON (captured from Python vivisect) | available | `fixtures/golden_*.json`, `fixtures/impapi.json` |
| Live Python `vivisect` / `viv-utils` | optional | not required to build or test; enables the live differential runner (`fixtures/generate_parity.py`) when installed |
| Hermetic synthetic fixtures | available | hand-built binary headers and hand-assembled opcode bytes, committed alongside their tests |

## Real-sample validation (2026-09-15)

The golden differential suite was also run against the real PE32 sample that
`fixtures/golden_conti_pe32.json` was originally captured from (staged locally via
`VIVISECT_CORPUS_DIR`, not committed — see `fixtures/CORPUS_MANIFEST.json`). Every layer agreed
with the Python-vivisect golden:

| Layer | Result |
|-------|--------|
| format detection | ✅ PE |
| architecture | ✅ i386 |
| entry point | ✅ |
| section count + addresses | ✅ |
| import count + names | ✅ |
| workspace load | ✅ |
| function discovery | ✅ |
| disassembly flags (all functions) | ✅ |

Note: `workspace.analyze()` on a full real-world sample is meaningfully slower in a debug build;
use `--release` when analyzing real binaries from the CLI.

## Differential test coverage

The test suite (`tests/`) exercises, against golden JSON and/or hermetic fixtures:

- **Loader / memory image** — PE section mapping, ELF `PT_LOAD` and relocatable-section mapping
  (including correct zero-fill for `.bss`/virtual-size tails), Mach-O section mapping, and
  persistence round-trips, all through the single `MemoryImage` abstraction (`envi::memory`).
- **Disassembly** — indirect branch retention (register/memory targets), RIP-relative and
  absolute-effective-address data cross-references, and per-function decode-flag agreement with
  the golden oracle.
- **Analysis** — function discovery, calling-convention recognition (including 64-bit ABIs),
  cross-crate ABI/decoder/memory consistency (`vivutils-rs`), and CFG predecessor resolution using
  containing-location semantics.
- **Persistence** — full workspace round-trip (`semantic_digest` equality) through both msgpack
  and JSON backends.
- **Emulation** — icicle-backed CPU emulation memory/permission fidelity against the workspace's
  loaded image.

Run `cargo test` (add `--features icicle` for the emulator tests). The live cross-implementation
runner in `tests/parity_runner_test.rs` is self-skipping when a Python oracle isn't present.
