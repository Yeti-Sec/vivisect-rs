# vivisect-rs

A Rust implementation of the [vivisect](https://github.com/vivisect/vivisect) binary analysis framework. Provides PE/ELF/Mach-O parsing, disassembly, code flow analysis, symbolic analysis, and CPU emulation for malware analysis and reverse engineering.

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Overview

vivisect-rs is a from-scratch Rust port of the Python vivisect framework, focusing on the analysis features most critical for malware tooling: PE/ELF/Mach-O loading, x86/ARM disassembly, 27 analysis modules, symbolic analysis, and [icicle](https://github.com/icicle-emu/icicle-emu)-backed CPU emulation.

Not ported: the interactive debugger/tracer (VDB/vtrace), the Qt GUI, the VStruct definitions library (188K LOC), and niche binary formats (Intel HEX, Motorola S-Record).

### Key Features

- **Binary Parsing** — PE32/PE64, ELF32/ELF64, and Mach-O 32/64/fat via [goblin](https://github.com/m4b/goblin), with import/export/section extraction
- **Disassembly** — x86/x64 via [iced-x86](https://github.com/icedland/iced), ARM/AArch64/MIPS/PowerPC/SPARC/M68K via [capstone](https://github.com/capstone-engine/capstone)
- **Code Flow Analysis** — Function discovery, basic block construction, CFG/call graph generation, data xref tracking from LEA/MOV instructions
- **27 Analysis Modules** — Prologues, calling conventions, thunks, pointers, crypto constant detection, Go pclntab parsing, and more
- **Symbolic Analysis** — Path-sensitive symbolic emulator with expression reduction and bounded constraint solving for switch case resolution
- **9-Architecture CPU Emulation** — x86/x64, ARM/AArch64, MIPS, PowerPC, SPARC, RISC-V, M68K, SuperH via [icicle-emu](https://github.com/icicle-emu/icicle-emu) with [Ghidra](https://github.com/NationalSecurityAgency/ghidra) SLEIGH processor specs
- **Import Emulation** — Workspace-aware emulator with 50+ Windows API stubs
- **Workspace Persistence** — Save/load analysis state via msgpack serialization
- **Thread-Safe Access** — `FrozenWorkspace` for concurrent read-only access after analysis
- **647 Tests** — Unit and integration tests with parity vectors against Python vivisect

## Architecture

```
src/
├── core/           Workspace, FrozenWorkspace, locations, xrefs, symbols, CFG, call graph
├── analysis/       27 analysis modules (orchestrated pipeline)
├── envi/           Disassembly traits, opcodes, operands
│   └── archs/      x86 (iced-x86), ARM/AArch64/MIPS/PPC/SPARC/M68K (capstone), RISC-V/SuperH (icicle)
├── parsers/        PE (goblin), ELF (goblin), Mach-O (goblin), blob
├── emulator/       CpuEmulator trait, IcicleEmulator, MemoryPermissions
├── impemu/         Import emulation: WorkspaceEmulator, API stubs, monitors
├── symboliks/      Symbolic analysis: translator, reducer, bounds solver, effects
├── abstractions/   High-level traits: BinaryAnalyzer, EmulatorDriver
├── remote/         REST API server (axum-based)
├── storage/        Workspace serialization (msgpack)
├── vstruct/        Binary structure primitives
└── utils/          Shared helpers
```

### Analysis Pipeline

```
Binary File
    │
    ▼
VivWorkspace::load_from_file()     PE/ELF detection and parsing
    │
    ▼
workspace.analyze()                 27-module orchestrated pipeline
    ├── Function discovery           Prologues, entry points, exports
    ├── Code flow analysis           Basic blocks, branches, calls
    ├── Cross-references             Code/data xrefs, pointer tables
    ├── Calling conventions          cdecl, stdcall, fastcall, ms64, sysv64
    ├── Import resolution            API name matching, thunk detection
    ├── String detection             ASCII, UTF-16LE, UTF-16BE inline strings
    ├── Switch case analysis         Symbolic path analysis with bounds solving
    ├── Crypto detection             AES S-box, SHA-256, MD5, CRC32, Blowfish constants
    └── Go/ELF-specific              pclntab parsing, PLT resolution
```

## Quick Start

```rust
use vivisect::core::VivWorkspace;

fn main() {
    let mut workspace = VivWorkspace::new();
    workspace.load_from_file(std::path::Path::new("sample.exe"))
        .expect("failed to load binary");

    let result = workspace.analyze();

    println!("Architecture: {:?}", workspace.architecture());
    println!("Functions:    {}", workspace.get_functions().len());

    for &func_va in workspace.get_functions() {
        if let Some(meta) = workspace.get_function(func_va) {
            println!("  {:#010x} {}", func_va, meta.name.as_deref().unwrap_or("???"));
        }
    }
}
```

## CLI Tool (`vivbin`)

The crate also builds a command-line binary called `vivbin` with the following subcommands:

```
vivbin analyze <file>          Analyze a binary and optionally save workspace (--output)
vivbin info <file>             Show binary metadata (format, arch, entry point, sections)
vivbin functions <file>        List discovered functions
vivbin imports <file>          List imports
vivbin exports <file>          List exports
vivbin sections <file>         List sections with virtual addresses, sizes, and permissions
vivbin disasm <file> --address 0x401000   Disassemble at an address (--count for instruction limit)
```

### Workspace Persistence

The `analyze` subcommand can save the analysis state to a msgpack workspace file via `--output`, which can then be loaded by downstream tools without re-analyzing:

```bash
vivbin analyze sample.exe --output sample.viv
vivbin functions sample.viv
```

## Building from Source

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- C compiler (for capstone and icicle native dependencies)

### Icicle Emulation (optional)

The `icicle` feature enables CPU emulation via [icicle-emu](https://github.com/icicle-emu/icicle-emu), which requires [Ghidra](https://github.com/NationalSecurityAgency/ghidra) SLEIGH processor specification files at runtime. The processor specs are located using the following search order:

1. `GHIDRA_SRC` environment variable (Ghidra source checkout)
2. `ICICLE_PROCESSORS` environment variable (direct path to `Ghidra/Processors`)
3. Auto-discovery from bundled specs (when used as a dependency of [floss-rs](https://github.com/Yeti-Sec/floss-rs))

### Build Commands

```bash
# Debug build (no emulation)
cargo build

# Build with icicle emulation support (requires icicle-emu checkout)
cargo build --features icicle

# Build with Unicorn emulation backend
cargo build --features emulation

# Build with REST API server
cargo build --features remote

# Release build
cargo build --release

# Run tests
cargo test
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| default | PE/ELF/Mach-O parsing, x86/ARM disassembly, 27 analysis modules |
| `icicle` | CPU emulation via [icicle-emu](https://github.com/icicle-emu/icicle-emu) + Ghidra SLEIGH specs |
| `emulation` | CPU emulation via [Unicorn Engine](https://github.com/unicorn-engine/unicorn) |
| `remote` | REST API server (axum-based) for remote workspace access |
| `full` | All optional features (`icicle` + `remote`) |

## Supported Architectures

| Architecture | Disassembler | Emulator (icicle) | Sleigh ID |
|---|---|---|---|
| x86 (32-bit) | iced-x86 | ✅ | `x86:LE:32:default` |
| x86-64 | iced-x86 | ✅ | `x86:LE:64:default` |
| ARM (32-bit) | capstone | ✅ | `ARM:LE:32:v7` |
| AArch64 (ARM64) | capstone | ✅ | `AARCH64:LE:64:v8A` |
| MIPS (32/64, BE/LE) | capstone | ✅ | `MIPS:BE/LE:32/64:default` |
| PowerPC (32/64) | capstone | ✅ | `PowerPC:BE:32/64:default` |
| SPARC (32/64) | capstone | ✅ | `Sparc:BE:32/64:default` |
| RISC-V (32/64) | icicle Sleigh | ✅ | `RISCV:LE:32/64:default` |
| M68K (68040) | capstone | ✅ | `68000:BE:32:default` |
| SuperH (SH-4) | icicle Sleigh | ✅ | `SuperH4:BE/LE:32:default` |

All architectures require the `icicle` feature flag for emulation. Disassembly-only analysis works without icicle for capstone-backed architectures.

## Dependencies

| Category | Crates |
|----------|--------|
| Binary Parsing | [`goblin`](https://github.com/m4b/goblin) |
| Disassembly | [`iced-x86`](https://github.com/icedland/iced), [`capstone`](https://github.com/capstone-engine/capstone) |
| Emulation | [`icicle-vm/cpu/mem`](https://github.com/icicle-emu/icicle-emu) (optional) |
| Serialization | `serde`, `rmp-serde` (msgpack) |
| Graphs | `petgraph` |
| Server | `axum`, `tower` (optional) |
| Logging | `tracing` |

## Related Projects

- [vivutils-rs](https://github.com/Yeti-Sec/vivutils-rs) — Vivisect utility library (emulator drivers, FLIRT, CFG analysis)
- [floss-rs](https://github.com/Yeti-Sec/floss-rs) — FLOSS string extraction (uses vivisect-rs + vivutils-rs)
- [capa-rs](https://github.com/Yeti-Sec/capa-rs) — Capability identification for executables

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [vivisect](https://github.com/vivisect/vivisect) by Invisigoth (Atlas/Kenshoto) — the original Python binary analysis framework
- [icicle-emu](https://github.com/icicle-emu/icicle-emu) by mrexodia — SLEIGH-based CPU emulator
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) by NSA — SLEIGH processor specifications
- [goblin](https://github.com/m4b/goblin) — PE/ELF/Mach-O binary parser
- [iced-x86](https://github.com/icedland/iced) — x86/x64 disassembler
- [capstone](https://github.com/capstone-engine/capstone) — multi-architecture disassembly framework
