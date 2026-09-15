//! Roadmap Phase 10 / finding #13: the documented workflow
//! `analyze -> save -> reload -> functions` must be a real, tested pipeline,
//! and a saved workspace must reload (with its analyzed function set) without
//! access to the original binary.
//!
//! Both the library pipeline and the `vivbin` CLI are exercised, using a
//! hermetic hand-built ELF64 executable (no external corpus).

use std::process::Command;
use vivisect::core::VivWorkspace;
use vivisect::storage::msgpack::{load_workspace, save_workspace};

/// Minimal ELF64 LSB executable with one PT_LOAD segment containing a couple of
/// tiny functions reachable from the entry point.
fn build_elf() -> Vec<u8> {
    const EHSIZE: usize = 64;
    const PHENTSIZE: usize = 56;
    let seg_off: u64 = (EHSIZE + PHENTSIZE) as u64;
    let vaddr: u64 = 0x400000 + seg_off;
    // entry: call rel32 -> callee; ret.   callee: xor rax,rax; ret.
    // 0: e8 06 00 00 00   call +6  -> (0x5 + 6 = 0xb)
    // 5: c3               ret
    // 6..0xb padding (nop) so call target 0xb is after
    // b: 48 31 c0 c3      xor rax,rax; ret
    let code = [
        0xE8, 0x06, 0x00, 0x00, 0x00, // call +6
        0xC3, // ret
        0x90, 0x90, 0x90, 0x90, 0x90, // padding to 0xb
        0x48, 0x31, 0xC0, 0xC3, // xor rax,rax; ret
    ];
    let filesz = code.len() as u64;
    let memsz = filesz + 0x20; // some zero-filled tail

    let mut b = Vec::new();
    b.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    b.push(2); // ELFCLASS64
    b.push(1); // ELFDATA2LSB
    b.push(1); // version
    b.extend_from_slice(&[0u8; 9]);
    b.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&vaddr.to_le_bytes()); // e_entry (points at code start)
    b.extend_from_slice(&(EHSIZE as u64).to_le_bytes()); // e_phoff
    b.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    b.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    b.extend_from_slice(&(EHSIZE as u16).to_le_bytes());
    b.extend_from_slice(&(PHENTSIZE as u16).to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(b.len(), EHSIZE);

    b.extend_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b.extend_from_slice(&5u32.to_le_bytes()); // R|X
    b.extend_from_slice(&seg_off.to_le_bytes());
    b.extend_from_slice(&vaddr.to_le_bytes());
    b.extend_from_slice(&vaddr.to_le_bytes());
    b.extend_from_slice(&filesz.to_le_bytes());
    b.extend_from_slice(&memsz.to_le_bytes());
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(b.len(), EHSIZE + PHENTSIZE);

    b.extend_from_slice(&code);
    b
}

#[test]
fn library_pipeline_analyze_save_reload_functions() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("mini.elf");
    std::fs::write(&bin, build_elf()).unwrap();

    // analyze
    let mut ws = VivWorkspace::new();
    ws.load_from_file(&bin).unwrap();
    ws.analyze();
    let mut before = ws.get_functions();
    before.sort_unstable();
    assert!(
        !before.is_empty(),
        "analysis discovered no functions in the synthetic ELF"
    );

    // save
    let wsp = dir.path().join("mini.viv");
    save_workspace(&ws, &wsp).unwrap();

    // reload WITHOUT the original binary (delete it first to prove independence)
    std::fs::remove_file(&bin).unwrap();
    let reloaded = load_workspace(&wsp).unwrap();
    let mut after = reloaded.get_functions();
    after.sort_unstable();

    // the listed function set after reload matches the pre-save set
    assert_eq!(before, after);
}

#[test]
fn cli_analyze_save_reload_functions() {
    let exe = env!("CARGO_BIN_EXE_vivbin");
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("mini.elf");
    std::fs::write(&bin, build_elf()).unwrap();
    let wsp = dir.path().join("mini.viv");

    // vivbin analyze <elf> --output <ws>
    let analyze = Command::new(exe)
        .args([
            "analyze",
            bin.to_str().unwrap(),
            "--output",
            wsp.to_str().unwrap(),
        ])
        .output()
        .expect("run vivbin analyze");
    assert!(
        analyze.status.success(),
        "analyze failed: {}",
        String::from_utf8_lossy(&analyze.stderr)
    );
    assert!(wsp.exists(), "analyze did not write the workspace file");
    let a_out = String::from_utf8_lossy(&analyze.stdout);
    assert!(
        a_out.contains("Saved workspace"),
        "analyze did not report save:\n{a_out}"
    );

    // Reload from the workspace WITHOUT the binary present.
    std::fs::remove_file(&bin).unwrap();
    let funcs = Command::new(exe)
        .args(["functions", wsp.to_str().unwrap()])
        .output()
        .expect("run vivbin functions");
    assert!(
        funcs.status.success(),
        "functions failed: {}",
        String::from_utf8_lossy(&funcs.stderr)
    );
    let f_out = String::from_utf8_lossy(&funcs.stdout);
    assert!(
        f_out.contains("Functions ("),
        "functions did not list a reloaded function set:\n{f_out}"
    );
    assert!(
        !f_out.contains("No functions found"),
        "reloaded workspace reported no functions:\n{f_out}"
    );
}
