# Vivisect - Dependency Mapping

## Python to Rust Crate Mapping

| Python Package | Rust Crate | Status | Notes |
|----------------|-----------|--------|-------|
| `msgpack` | `rmp-serde` | Ready | MessagePack serialization |
| `pefile` (PE module) | `goblin` | Ready | Multi-format binary parser |
| `pyelftools` (Elf) | `goblin` | Ready | Built into goblin |
| `capstone` (disasm) | `capstone` | Ready | Multi-arch disassembly |
| `unicorn` (emu) | `unicorn-engine` | Optional | CPU emulation |
| `cxxfilt` | `cpp_demangle` | Ready | C++ demangling |
| `pyasn1` | `der-parser` | If needed | ASN.1 parsing |
| `networkx` | `petgraph` | Ready | Graph algorithms |
| `pycparser` | N/A | Custom | C struct parsing |
| `PyQt5` | `egui`/`iced` | Future | GUI framework |

## Internal Dependency Graph

```
error.rs (leaf)
    ^
    |
constants.rs (leaf)
    ^
    |
abstractions/ <-- Core traits used everywhere
    |
    +-- memory.rs
    +-- registers.rs
    +-- emulator.rs
    +-- binary.rs
    ^
    |
envi/ <-- Architecture layer
    |
    +-- opcode.rs (depends: abstractions)
    +-- operand.rs (depends: abstractions)
    +-- memory.rs (depends: abstractions/memory)
    +-- registers.rs (depends: abstractions/registers)
    +-- codeflow.rs (depends: opcode, operand)
    +-- archs/ (depends: all envi)
        ^
        |
vstruct/ <-- Binary structures
    |
    +-- primitives.rs (leaf)
    +-- builder.rs (depends: primitives)
    +-- bitfield.rs (depends: primitives)
        ^
        |
parsers/ <-- Format parsers
    |
    +-- pe.rs (depends: vstruct, envi)
    +-- elf.rs (depends: vstruct, envi)
    +-- blob.rs (depends: envi)
        ^
        |
core/ <-- Vivisect core
    |
    +-- workspace.rs (depends: parsers, envi, abstractions)
    +-- codegraph.rs (depends: workspace)
    +-- analysis.rs (depends: workspace, envi)
```

## Critical Path Analysis

1. **Must Port First**: `error.rs`, `constants.rs`, `abstractions/`
2. **Core Infrastructure**: `envi/opcode.rs`, `envi/operand.rs`
3. **Memory Model**: `envi/memory.rs` with page tables
4. **Parsers**: Can leverage `goblin` heavily
5. **Disassembly**: Use `capstone` or `iced-x86` bindings
6. **Emulation**: Use `unicorn-engine` for Tier 3/4 accuracy

## External Dependencies Strategy

### goblin (PE/ELF/Mach-O Parsing)
- **Use directly**: File format parsing, section enumeration, imports/exports
- **Extend**: Add vivisect-specific analysis on top

### capstone (Disassembly)
- **Use directly**: Multi-architecture disassembly
- **Wrap**: Create vivisect Opcode from capstone instructions

### iced-x86 (x86/x64 Disassembly)
- **Use for**: High-performance x86 disassembly
- **Advantage**: Pure Rust, no FFI overhead

### petgraph (Graphs)
- **Use for**: Call graphs, control flow graphs
- **Advantage**: Native Rust graph algorithms
