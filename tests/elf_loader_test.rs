//! Hermetic end-to-end test of ELF PT_LOAD mapping (roadmap Phase 4 / #4):
//! a hand-built ELF64 LSB executable with one PT_LOAD segment where
//! `p_memsz > p_filesz` must map with the file bytes present, the virtual tail
//! zero-filled, permissions from `p_flags`, and endianness propagated.

use vivisect::constants::{Architecture, Endian, MemoryPermissions};
use vivisect::core::VivWorkspace;

fn build_min_elf64() -> Vec<u8> {
    const EHSIZE: usize = 64;
    const PHENTSIZE: usize = 56;
    let seg_off: u64 = (EHSIZE + PHENTSIZE) as u64; // 0x78 = 120
    let vaddr: u64 = 0x400078;
    let code = [0x48u8, 0x31, 0xc0, 0xc3]; // xor rax,rax; ret
    let memsz: u64 = 0x10; // 16 -> 12 bytes zero-filled beyond the 4 file bytes

    let mut b = Vec::new();
    // e_ident
    b.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    b.push(2); // EI_CLASS = ELFCLASS64
    b.push(1); // EI_DATA  = ELFDATA2LSB (little-endian)
    b.push(1); // EI_VERSION
    b.extend_from_slice(&[0u8; 9]); // EI_OSABI, ABIVERSION, pad -> 16 bytes total
                                    // e_type, e_machine, e_version
    b.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b.extend_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    b.extend_from_slice(&1u32.to_le_bytes());
    // e_entry, e_phoff, e_shoff
    b.extend_from_slice(&vaddr.to_le_bytes());
    b.extend_from_slice(&(EHSIZE as u64).to_le_bytes()); // e_phoff = 64
    b.extend_from_slice(&0u64.to_le_bytes()); // e_shoff = 0
                                              // e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&(EHSIZE as u16).to_le_bytes());
    b.extend_from_slice(&(PHENTSIZE as u16).to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    b.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    b.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    b.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    assert_eq!(b.len(), EHSIZE);

    // Program header (PT_LOAD)
    b.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    b.extend_from_slice(&5u32.to_le_bytes()); // p_flags = PF_R | PF_X
    b.extend_from_slice(&seg_off.to_le_bytes()); // p_offset
    b.extend_from_slice(&vaddr.to_le_bytes()); // p_vaddr
    b.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
    b.extend_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz = 4
    b.extend_from_slice(&memsz.to_le_bytes()); // p_memsz = 0x10
    b.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    assert_eq!(b.len(), EHSIZE + PHENTSIZE);

    // Segment bytes
    b.extend_from_slice(&code);
    b
}

#[test]
fn elf_pt_load_maps_with_zero_fill_and_endian() {
    let bytes = build_min_elf64();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mini.elf");
    std::fs::write(&path, &bytes).unwrap();

    let mut ws = VivWorkspace::new();
    ws.load_from_file(&path).expect("ELF must load");

    // Architecture + endianness propagated.
    assert_eq!(ws.architecture(), Architecture::Amd64);
    assert_eq!(ws.endian(), Endian::Little);

    // File bytes are present at the segment's virtual address.
    assert_eq!(
        ws.read_memory(0x400078, 4).unwrap(),
        vec![0x48, 0x31, 0xc0, 0xc3]
    );

    // The virtual tail (p_memsz - p_filesz = 12 bytes) is zero-filled and
    // readable — not left unmapped.
    assert_eq!(ws.read_memory(0x40007c, 12).unwrap(), vec![0u8; 12]);

    // Permissions come from p_flags (PF_R | PF_X), no write.
    let perms = ws.get_permissions(0x400078).unwrap();
    assert!(perms.contains(MemoryPermissions::READ));
    assert!(perms.contains(MemoryPermissions::EXEC));
    assert!(!perms.contains(MemoryPermissions::WRITE));
}

#[test]
fn load_populates_unique_sample_md5() {
    // Loading a binary records its sample MD5 in FileInfo + workspace meta, so
    // function identities are "{md5}:{va}" and never collide across samples
    // (review finding #14). Two distinct binaries must get distinct hashes.
    let dir = tempfile::tempdir().unwrap();
    let hash_of = |last_byte: u8| -> String {
        let mut b = build_min_elf64();
        *b.last_mut().unwrap() = last_byte; // perturb the file content
        let p = dir.path().join(format!("s{last_byte}.elf"));
        std::fs::write(&p, &b).unwrap();
        let mut ws = VivWorkspace::new();
        ws.load_from_file(&p).unwrap();
        let md5 = ws.get_files()[0]
            .md5
            .clone()
            .expect("md5 must be populated");
        assert_eq!(ws.get_meta("md5"), Some(md5.as_str()));
        md5
    };

    let a = hash_of(0xc3);
    let b = hash_of(0x90);
    assert_eq!(a.len(), 32, "md5 must be 32 hex chars");
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, "unknown");
    assert_ne!(
        a, b,
        "distinct samples must have distinct md5 (no id collision)"
    );
}
