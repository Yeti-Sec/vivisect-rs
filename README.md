# rust-vivisect

A pure Rust binary analysis framework inspired by [vivisect](https://github.com/vivisect/vivisect). Provides disassembly, control flow analysis, emulation, and symbolic execution for multiple architectures.

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/yeti-sec/rust-vivisect/actions/workflows/ci.yml/badge.svg)](https://github.com/yeti-sec/rust-vivisect/actions)

## Features

- **Multi-format parsing**: PE, ELF, Mach-O via `goblin`
- **Multi-architecture disassembly**: x86/x64 (`capstone`, `iced-x86`), ARM, MIPS, PowerPC
- **Control flow analysis**: CFG construction, call graph, cross-references
- **Emulation**: Icicle VM backend (optional) for dynamic analysis
- **Symbolic execution**: Symbolic value tracking, effect analysis, constraint reduction
- **Workspace persistence**: MessagePack serialization for save/load
- **FLIRT-ready**: Designed for integration with FLIRT signature matching

## Architecture

| Module | Purpose |
|--------|---------|
| `parsers/` | PE, ELF, Mach-O binary format parsers |
| `envi/` | Architecture abstraction (x86, ARM, MIPS opcodes/operands) |
| `core/` | Workspace, CFG, call graph, symbols, locations, xrefs |
| `analysis/` | Code flow analysis, string detection, orchestration |
| `emulator/` | Icicle VM emulation backend (optional) |
| `symboliks/` | Symbolic execution, effect analysis, value reduction |
| `storage/` | MessagePack workspace serialization |
| `abstractions/` | Trait definitions (binary, memory, registers, driver) |
| `vstruct/` | Binary structure parsing primitives |

## Quick Start

```bash
# Build (default features, no emulation)
cargo build --release

# Build with icicle emulation support
cargo build --release --features icicle

# Run the CLI
./target/release/vivbin sample.exe

# Run tests
cargo test
```

## API Usage

```rust
use vivisect::core::workspace::Workspace;

fn main() -> anyhow::Result<()> {
    let mut ws = Workspace::new();
    ws.load_from_file("sample.exe")?;
    ws.analyze()?;

    for func in ws.get_functions() {
        println!("Function at 0x{:x}: {}", func.va, func.name);
    }

    Ok(())
}
```

## Optional Features

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `icicle` | Icicle VM emulation backend | `icicle-vm`, `icicle-cpu`, `icicle-mem` |
| `emulation` | Unicorn emulation backend | `unicorn-engine` |
| `remote` | Async remote capabilities | `tokio` |
| `full` | All features (`icicle` + `remote`) | All above |

## Vendored Dependencies

| Directory | Purpose |
|-----------|---------|
| `deps/rust-icicle-emu` | Icicle CPU emulator (optional, for `icicle` feature) |

## Building from Source

### Prerequisites

- Rust 1.75+
- C compiler (for `capstone` native binding)

```bash
cargo build --release              # Default (no emulation)
cargo build --release --features icicle   # With icicle emulator
cargo test                         # Run all tests
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
