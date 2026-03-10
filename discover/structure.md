# Vivisect Rust Port - Module Structure

## Overview

This document maps the Python vivisect project structure to the Rust implementation.

## Python Package Hierarchy

```
vivisect-master/
+-- vivisect/          -> Core disassembler/analysis
+-- envi/              -> Architecture abstraction layer
+-- vtrace/            -> Debugger framework
+-- vdb/               -> Visual debugger GUI
+-- vstruct/           -> Binary structure parsing
+-- PE/                -> PE executable support
+-- Elf/               -> ELF executable support
+-- cobra/             -> RPC/networking (defer)
+-- visgraph/          -> Graph visualization
+-- vqt/               -> Qt utilities (defer - Rust GUI TBD)
```

## Rust Module Mapping

```
rust-vivisect/src/
+-- lib.rs                    <- Library root
+-- main.rs                   <- CLI entry point (vivbin)
+-- error.rs                  <- Error types (thiserror)
+-- constants.rs              <- Global constants
+-- abstractions/             <- Trait definitions
|   +-- mod.rs
|   +-- emulator.rs           <- Emulator trait
|   +-- binary.rs             <- BinaryAnalyzer trait
|   +-- memory.rs             <- Memory abstraction
|   +-- registers.rs          <- Register context trait
+-- envi/                     <- Architecture layer
|   +-- mod.rs
|   +-- opcode.rs             <- Opcode representation
|   +-- operand.rs            <- Operand types
|   +-- memory.rs             <- Memory management
|   +-- registers.rs          <- Register handling
|   +-- codeflow.rs           <- Code flow analysis
|   +-- archs/                <- Architecture implementations
|       +-- mod.rs
|       +-- i386/
|       +-- amd64/
|       +-- arm/
|       +-- aarch64/
|       +-- thumb16/
+-- vstruct/                  <- Binary structure parsing
|   +-- mod.rs
|   +-- primitives.rs         <- Primitive types
|   +-- builder.rs            <- Structure builder
|   +-- bitfield.rs           <- Bitfield support
+-- parsers/                  <- Binary format parsers
|   +-- mod.rs
|   +-- pe.rs                 <- PE format
|   +-- elf.rs                <- ELF format
|   +-- macho.rs              <- Mach-O format
|   +-- blob.rs               <- Raw binary
+-- core/                     <- Vivisect core
|   +-- mod.rs
|   +-- workspace.rs          <- VivWorkspace
|   +-- codegraph.rs          <- Code/call graphs
|   +-- xrefs.rs              <- Cross-references
|   +-- symbols.rs            <- Symbol management
|   +-- analysis.rs           <- Analysis engine
+-- vtrace/                   <- Debugger (future)
|   +-- mod.rs
+-- vdb/                      <- Visual debugger (future)
|   +-- mod.rs
+-- utils/                    <- Utilities
    +-- mod.rs
    +-- graph.rs              <- Graph utilities
```

## Translation Priority (Dependency Order)

### Wave 1 - Leaf Modules (Parallel)
- `error.rs` - Error types
- `constants.rs` - Constants/enums
- `vstruct/primitives.rs` - Primitive types
- `utils/mod.rs` - Basic utilities

### Wave 2 - Core Abstractions (Parallel)
- `abstractions/memory.rs` - Memory traits
- `abstractions/registers.rs` - Register traits
- `abstractions/emulator.rs` - Emulator trait
- `abstractions/binary.rs` - Binary analysis trait
- `envi/opcode.rs` - Opcode representation
- `envi/operand.rs` - Operand types

### Wave 3 - Envi Layer
- `envi/memory.rs` - Memory implementation
- `envi/registers.rs` - Register context
- `envi/codeflow.rs` - Code flow
- `vstruct/builder.rs` - Structure builder

### Wave 4 - Parsers
- `parsers/pe.rs` - PE parser (using goblin)
- `parsers/elf.rs` - ELF parser
- `parsers/blob.rs` - Raw binary

### Wave 5 - Architecture Implementations
- `envi/archs/i386/` - Intel 32-bit
- `envi/archs/amd64/` - Intel/AMD 64-bit
- `envi/archs/arm/` - ARM 32-bit

### Wave 6 - Core Vivisect
- `core/workspace.rs` - Main workspace
- `core/codegraph.rs` - Graph analysis
- `core/analysis.rs` - Analysis modules

### Wave 7 - Integration
- `lib.rs` - Wire everything together
- `main.rs` - CLI implementation
