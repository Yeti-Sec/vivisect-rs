# Vivisect - Complexity Analysis

## Module Complexity Tiers

### Tier 1: Pure Functions, Direct Translation
| Module | Python LOC | Rust Est. | Notes |
|--------|-----------|-----------|-------|
| `vivisect/const.py` | ~200 | ~150 | Constants, enums |
| `envi/const.py` | ~100 | ~80 | Architecture constants |
| `vstruct/primitives.py` | ~300 | ~250 | Primitive types |

### Tier 2: I/O, Standard Library
| Module | Python LOC | Rust Est. | Notes |
|--------|-----------|-----------|-------|
| `vivisect/storage/` | ~400 | ~300 | File I/O with msgpack |
| `vstruct/builder.py` | ~200 | ~250 | Structure building |
| `parsers/blob.py` | ~150 | ~100 | Simple binary loading |

### Tier 3: External Libraries, Complex State
| Module | Python LOC | Rust Est. | Notes |
|--------|-----------|-----------|-------|
| `vivisect/base.py` | ~1600 | ~2000 | Core workspace - complex |
| `envi/__init__.py` | ~1400 | ~1500 | Opcode/Operand system |
| `vtrace/__init__.py` | ~1600 | ~2000 | Debugger - platform deps |
| `parsers/pe.py` | ~800 | ~500 | Use goblin, wrap results |
| `parsers/elf.py` | ~600 | ~400 | Use goblin |

### Tier 4: Dynamic/Metaprogramming, Redesign Needed
| Module | Python LOC | Rust Est. | Notes |
|--------|-----------|-----------|-------|
| `vstruct/cparse.py` | ~400 | ~600 | C parser - complex |
| `cobra/` | ~2000 | TBD | RPC - consider gRPC |
| `vqt/` | ~1500 | TBD | Qt GUI - egui/iced |

## Estimated Total Effort

| Category | Python LOC | Rust Est. | Priority |
|----------|-----------|-----------|----------|
| Core (error, const) | 500 | 400 | P0 |
| Abstractions | - | 800 | P0 |
| Envi base | 2000 | 2000 | P1 |
| Envi archs (x86) | 3000 | 2500 | P1 |
| Vstruct | 1000 | 800 | P1 |
| Parsers | 2000 | 1000 | P2 |
| Core Workspace | 2000 | 2500 | P2 |
| Vtrace | 2000 | 2500 | P3 |
| Analysis modules | 3000 | 3000 | P3 |
| **Total Phase 1** | ~15,500 | ~15,500 | - |

## Risk Assessment

### Low Risk (Tier 1-2)
- Constants translation - straightforward
- Primitive types - well-defined
- Basic utilities - standard patterns

### Medium Risk (Tier 3)
- Binary parsers - goblin covers most, need to wrap
- Opcode system - need careful trait design
- Memory model - ownership considerations

### High Risk (Tier 4)
- C struct parser - may need proc macros
- Debugger platform code - Windows/Linux specific
- GUI layer - completely different ecosystem
