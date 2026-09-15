//! Integration tests for the vivisect library.

use vivisect::constants::{Architecture, Endian, LocationType, RefType};
use vivisect::core::workspace::{FunctionMeta, VivWorkspace};
use vivisect::envi::archs::{X86Disassembler, X86Mode};
use vivisect::envi::ArchitectureModule;
use vivisect::vstruct::VStructType;

// ============================================================================
// Workspace Tests
// ============================================================================

#[test]
fn test_workspace_creation() {
    let workspace = VivWorkspace::new();
    assert_eq!(workspace.architecture(), Architecture::Default);
    assert!(workspace.entry_points().is_empty());
    assert_eq!(workspace.stats().functions, 0);
}

#[test]
fn test_workspace_symbols() {
    let mut workspace = VivWorkspace::new();

    workspace.set_name(0x401000, "main");
    workspace.set_name(0x401100, "helper");
    workspace.set_name(0x401200, "_start");

    assert_eq!(workspace.get_name(0x401000), Some("main"));
    assert_eq!(workspace.get_name(0x401100), Some("helper"));
    assert_eq!(workspace.get_name(0x401200), Some("_start"));
    assert_eq!(workspace.get_name(0x401300), None);

    // Test lookup by name via symbol table
    assert_eq!(workspace.symbols().get_address("main"), Some(0x401000));
    assert_eq!(workspace.symbols().get_address("nonexistent"), None);
}

#[test]
fn test_workspace_locations() {
    let mut workspace = VivWorkspace::new();

    workspace.add_location(0x401000, 5, LocationType::Op, None);
    workspace.add_location(0x401005, 2, LocationType::Op, None);
    workspace.add_location(
        0x402000,
        14,
        LocationType::String,
        Some("Hello, World!".to_string()),
    );

    let loc = workspace.get_location(0x401000);
    assert!(loc.is_some());
    let loc = loc.unwrap();
    assert_eq!(loc.size, 5);
    assert_eq!(loc.ltype, LocationType::Op);
}

#[test]
fn test_workspace_xrefs() {
    let mut workspace = VivWorkspace::new();

    workspace.add_xref(0x401000, 0x402000, RefType::Code);
    workspace.add_xref(0x401010, 0x402000, RefType::Code);
    workspace.add_xref(0x401000, 0x403000, RefType::Data);

    let xrefs_to = workspace.get_xrefs_to(0x402000);
    assert_eq!(xrefs_to.len(), 2);

    let xrefs_from = workspace.get_xrefs_from(0x401000);
    assert_eq!(xrefs_from.len(), 2);
}

#[test]
fn test_workspace_comments() {
    let mut workspace = VivWorkspace::new();

    workspace.set_comment(0x401000, "Entry point");
    workspace.set_comment(0x401010, "Loop start");

    assert_eq!(workspace.get_comment(0x401000), Some("Entry point"));
    assert_eq!(workspace.get_comment(0x401010), Some("Loop start"));
    assert_eq!(workspace.get_comment(0x401020), None);
}

#[test]
fn test_workspace_functions() {
    let mut workspace = VivWorkspace::new();

    let meta1 = FunctionMeta {
        name: Some("main".to_string()),
        calling_convention: Some("cdecl".to_string()),
        ret_type: Some("int".to_string()),
        args: vec![("int".to_string(), "argc".to_string())],
        locals: Vec::new(),
        meta: std::collections::HashMap::new(),
    };

    workspace.add_function(0x401000, meta1);

    let funcs = workspace.get_functions();
    assert_eq!(funcs.len(), 1);
    assert!(funcs.contains(&0x401000));
}

// ============================================================================
// X86 Disassembler Tests
// ============================================================================

#[test]
fn test_x86_32_disassembly() {
    let disasm = X86Disassembler::new(X86Mode::Mode32);

    // NOP
    let op = disasm.disassemble(&[0x90], 0x401000).unwrap();
    assert_eq!(op.mnem, "nop");
    assert_eq!(op.size, 1);

    // push ebp
    let op = disasm.disassemble(&[0x55], 0x401000).unwrap();
    assert_eq!(op.mnem, "push");

    // mov eax, 0x12345678
    let op = disasm
        .disassemble(&[0xB8, 0x78, 0x56, 0x34, 0x12], 0x401000)
        .unwrap();
    assert_eq!(op.mnem, "mov");
    assert_eq!(op.size, 5);

    // ret
    let op = disasm.disassemble(&[0xC3], 0x401000).unwrap();
    assert_eq!(op.mnem, "ret");
    assert!(op.is_return());
    assert!(!op.falls_through());
}

#[test]
fn test_x86_64_disassembly() {
    let disasm = X86Disassembler::new(X86Mode::Mode64);

    // mov rbp, rsp (48 89 e5)
    let op = disasm.disassemble(&[0x48, 0x89, 0xE5], 0x401000).unwrap();
    assert_eq!(op.mnem, "mov");
    assert_eq!(op.size, 3);

    // rex.w prefix instruction
    let op = disasm
        .disassemble(&[0x48, 0x83, 0xEC, 0x20], 0x401000)
        .unwrap();
    assert_eq!(op.mnem, "sub");
}

#[test]
fn test_x86_call_instruction() {
    let disasm = X86Disassembler::new(X86Mode::Mode32);

    // call rel32
    let op = disasm
        .disassemble(&[0xE8, 0xFB, 0xFF, 0xFF, 0xFF], 0x401000)
        .unwrap();
    assert_eq!(op.mnem, "call");
    assert!(op.is_call());
    assert!(op.falls_through()); // calls fall through
}

#[test]
fn test_x86_branch_instructions() {
    let disasm = X86Disassembler::new(X86Mode::Mode32);

    // jmp rel8
    let op = disasm.disassemble(&[0xEB, 0x10], 0x401000).unwrap();
    assert_eq!(op.mnem, "jmp");
    assert!(op.is_branch());
    assert!(!op.falls_through()); // unconditional jump doesn't fall through

    // je rel8 (conditional)
    let op = disasm.disassemble(&[0x74, 0x10], 0x401000).unwrap();
    assert!(op.is_branch());
    assert!(op.is_conditional());
    assert!(op.falls_through()); // conditional branches fall through
}

#[test]
fn test_x86_disassemble_block() {
    let disasm = X86Disassembler::new(X86Mode::Mode32);

    // Simple function prologue + epilogue
    let code = [
        0x55, // push ebp
        0x89, 0xE5, // mov ebp, esp
        0x5D, // pop ebp
        0xC3, // ret
    ];

    let ops = disasm.disassemble_block(&code, 0x401000, 10);
    assert_eq!(ops.len(), 4);
    assert_eq!(ops[0].mnem, "push");
    assert_eq!(ops[1].mnem, "mov");
    assert_eq!(ops[2].mnem, "pop");
    assert_eq!(ops[3].mnem, "ret");
}

// ============================================================================
// Architecture Module Tests
// ============================================================================

#[test]
fn test_architecture_module_trait() {
    let disasm_32 = X86Disassembler::new(X86Mode::Mode32);
    assert_eq!(disasm_32.arch_id(), Architecture::I386);
    assert_eq!(disasm_32.arch_name(), "i386");
    assert_eq!(disasm_32.pointer_size(), 4);
    assert_eq!(disasm_32.endian(), Endian::Little);
    assert_eq!(disasm_32.max_instruction_size(), 15);

    let disasm_64 = X86Disassembler::new(X86Mode::Mode64);
    assert_eq!(disasm_64.arch_id(), Architecture::Amd64);
    assert_eq!(disasm_64.arch_name(), "amd64");
    assert_eq!(disasm_64.pointer_size(), 8);
}

// ============================================================================
// XRef Manager Tests
// ============================================================================

#[test]
fn test_xref_manager() {
    use vivisect::core::xrefs::XRefManager;

    let mut xrefs = XRefManager::new();

    xrefs.add_xref(0x401000, 0x402000, RefType::Code);
    xrefs.add_xref(0x401010, 0x402000, RefType::Code);
    xrefs.add_xref(0x401000, 0x403000, RefType::Data);

    assert_eq!(xrefs.len(), 3);

    let to_refs = xrefs.get_xrefs_to(0x402000);
    assert_eq!(to_refs.len(), 2);

    let from_refs = xrefs.get_xrefs_from(0x401000);
    assert_eq!(from_refs.len(), 2);

    // Test iterator
    let all: Vec<_> = xrefs.iter().collect();
    assert_eq!(all.len(), 3);

    // Test removal
    xrefs.remove_xref(0x401000, 0x402000, RefType::Code);
    assert_eq!(xrefs.len(), 2);
}

// ============================================================================
// Symbol Table Tests
// ============================================================================

#[test]
fn test_symbol_table() {
    use vivisect::core::symbols::SymbolTable;

    let mut symbols = SymbolTable::new();

    symbols.add_symbol(0x401000, "main");
    symbols.add_symbol(0x401100, "helper");
    symbols.add_symbol(0x401200, "_init");

    assert_eq!(symbols.len(), 3);
    assert_eq!(symbols.get_name(0x401000), Some("main"));
    assert_eq!(symbols.get_address("main"), Some(0x401000));

    // Test search
    let matching = symbols.search("_");
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].1, "_init");
}

// ============================================================================
// VStruct Tests
// ============================================================================

#[test]
fn test_vstruct_primitives() {
    use vivisect::vstruct::primitives::{v_uint32, VBytes, VStr};

    // Test uint32 little endian
    let mut num = v_uint32(Endian::Little);
    num.parse(&[0x78, 0x56, 0x34, 0x12], 0).unwrap();
    assert_eq!(num.value, 0x12345678);
    assert_eq!(num.emit(), vec![0x78, 0x56, 0x34, 0x12]);

    // Test uint32 big endian
    let mut num = v_uint32(Endian::Big);
    num.parse(&[0x12, 0x34, 0x56, 0x78], 0).unwrap();
    assert_eq!(num.value, 0x12345678);

    // Test bytes
    let mut bytes = VBytes::new(4);
    bytes.parse(&[0xDE, 0xAD, 0xBE, 0xEF], 0).unwrap();
    assert_eq!(bytes.value, vec![0xDE, 0xAD, 0xBE, 0xEF]);

    // Test string
    let mut s = VStr::new(8);
    s.parse(b"Hello\x00\x00\x00extra", 0).unwrap();
    assert_eq!(s.get_string(), "Hello");
}

#[test]
fn test_vstruct_bitfield() {
    use vivisect::vstruct::bitfield::BitField;

    let mut bf = BitField::new(4, Endian::Little);
    bf.define_field("lower4", 0, 4).unwrap();
    bf.define_field("upper4", 4, 4).unwrap();
    bf.define_field("byte2", 8, 8).unwrap();

    bf.parse(&[0xab, 0xcd, 0x00, 0x00], 0).unwrap();

    assert_eq!(bf.get_field("lower4"), Some(0xb));
    assert_eq!(bf.get_field("upper4"), Some(0xa));
    assert_eq!(bf.get_field("byte2"), Some(0xcd));

    bf.set_field("lower4", 0x5).unwrap();
    assert_eq!(bf.value() & 0xf, 0x5);
}

// ============================================================================
// String Analysis Tests
// ============================================================================

#[test]
fn test_string_detection() {
    use vivisect::analysis::strings::{
        detect_ascii_string, detect_utf16le_string, find_strings, StringAnalysisConfig,
    };

    // ASCII string detection
    let data = b"Hello, World!\x00more data";
    let s = detect_ascii_string(data, 0, 4).unwrap();
    assert_eq!(s.content, "Hello, World!");
    assert_eq!(s.size, 14); // Including null terminator

    // UTF-16 LE string detection
    let data = b"H\x00e\x00l\x00l\x00o\x00\x00\x00";
    let s = detect_utf16le_string(data, 0, 4).unwrap();
    assert_eq!(s.content, "Hello");

    // Find all strings
    let data = b"\x00\x00Hello\x00World\x00\x00\x00";
    let config = StringAnalysisConfig {
        min_length: 4,
        detect_ascii: true,
        detect_utf16: false,
        detect_utf16be: false,
    };
    let strings = find_strings(data, &config);
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].content, "Hello");
    assert_eq!(strings[1].content, "World");
}

#[test]
fn test_string_classification() {
    use vivisect::analysis::strings::{is_path_string, is_registry_string, is_url_string};

    assert!(is_path_string("C:\\Windows\\System32"));
    assert!(is_path_string("/usr/bin/bash"));
    assert!(!is_path_string("just a string"));

    assert!(is_url_string("https://example.com"));
    assert!(is_url_string("http://test.org"));
    assert!(!is_url_string("not a url"));

    assert!(is_registry_string("HKEY_LOCAL_MACHINE\\SOFTWARE"));
    assert!(is_registry_string("HKLM\\SOFTWARE"));
    assert!(!is_registry_string("not a registry key"));
}

// ============================================================================
// Utility Function Tests
// ============================================================================

#[test]
fn test_utils() {
    use vivisect::utils::{align_down, align_up, extract_bits, is_aligned, sign_extend};

    assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    assert_eq!(align_down(0x1001, 0x1000), 0x1000);
    assert!(is_aligned(0x1000, 0x1000));
    assert!(!is_aligned(0x1001, 0x1000));

    // Sign extend 8-bit -1 (0xff) to 64-bit
    assert_eq!(sign_extend(0xff, 8, 64), 0xffffffffffffffff);
    // Sign extend 8-bit 127 (0x7f) to 64-bit
    assert_eq!(sign_extend(0x7f, 8, 64), 0x7f);

    assert_eq!(extract_bits(0xabcd, 4, 8), 0xbc);
    assert_eq!(extract_bits(0xabcd, 0, 4), 0xd);
}

// ============================================================================
// Constants Tests
// ============================================================================

#[test]
fn test_architecture_constants() {
    assert_eq!(Architecture::I386.pointer_size(), 4);
    assert_eq!(Architecture::Amd64.pointer_size(), 8);
    assert_eq!(Architecture::ArmV7.pointer_size(), 4);
    assert_eq!(Architecture::A64.pointer_size(), 8);

    assert_eq!(Architecture::I386.name(), "i386");
    assert_eq!(Architecture::Amd64.name(), "amd64");
}

#[test]
fn test_instruction_flags() {
    use vivisect::constants::InstructionFlags;

    let flags = InstructionFlags::CALL | InstructionFlags::BRANCH;
    assert!(flags.contains(InstructionFlags::CALL));
    assert!(flags.contains(InstructionFlags::BRANCH));
    assert!(!flags.contains(InstructionFlags::RET));

    let branch_cond = InstructionFlags::BRANCH_COND;
    assert!(branch_cond.contains(InstructionFlags::COND));
    assert!(branch_cond.contains(InstructionFlags::BRANCH));
}

// ============================================================================
// Storage Tests
// ============================================================================

#[test]
fn test_workspace_roundtrip() {
    use tempfile::tempdir;

    let mut workspace = VivWorkspace::new();
    workspace.set_name(0x401000, "main");
    workspace.set_name(0x401100, "foo");
    workspace.set_comment(0x401000, "entry point");
    workspace.add_xref(0x401000, 0x401100, RefType::Code);

    // Create temp dir for test file
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.json");

    // Save and load (using JSON for easier testing)
    vivisect::storage::save_workspace(&workspace, &path, vivisect::storage::StorageFormat::Json)
        .unwrap();
    let restored = vivisect::storage::load_workspace(&path).unwrap();

    assert_eq!(restored.get_name(0x401000), Some("main"));
}
