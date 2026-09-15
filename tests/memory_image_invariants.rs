//! "One mapped image everywhere" invariants (roadmap Phase 4 §2.1 / unified
//! MemoryImage work order §4). Proves that loader bytes, permissions, zero-fill,
//! SHT_NOBITS/.bss, endianness, workspace reads, and a persistence save→reload
//! all agree on a single mapped image. Uses hand-built ELF fixtures (no corpus).
//!
//! Emulator-read parity (icicle) is asserted in vivutils' emulator_memory_test
//! and vivisect's icicle emucode path; here we cover the loader/workspace/
//! persistence legs that run under default features.

use vivisect::constants::{Architecture, Endian, MemoryPermissions};
use vivisect::core::VivWorkspace;
use vivisect::storage::msgpack::{load_workspace, save_workspace};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn le(v: &mut Vec<u8>, bytes: &[u8]) {
    v.extend_from_slice(bytes);
}

/// ELF64 LSB executable with one PT_LOAD where p_memsz > p_filesz (zero-fill
/// tail) and R+X permissions.
fn elf_pt_load() -> Vec<u8> {
    const EH: usize = 64;
    const PH: usize = 56;
    let seg_off = (EH + PH) as u64; // 0x78
    let vaddr: u64 = 0x400078;
    let code = [0x48u8, 0x31, 0xc0, 0xc3]; // xor rax,rax; ret
    let memsz: u64 = 0x20;

    let mut b = Vec::new();
    le(&mut b, &[0x7f, b'E', b'L', b'F']);
    b.push(2); // ELFCLASS64
    b.push(1); // ELFDATA2LSB
    b.push(1);
    le(&mut b, &[0u8; 9]);
    le(&mut b, &2u16.to_le_bytes()); // ET_EXEC
    le(&mut b, &0x3eu16.to_le_bytes()); // EM_X86_64
    le(&mut b, &1u32.to_le_bytes());
    le(&mut b, &vaddr.to_le_bytes()); // e_entry
    le(&mut b, &(EH as u64).to_le_bytes()); // e_phoff
    le(&mut b, &0u64.to_le_bytes()); // e_shoff
    le(&mut b, &0u32.to_le_bytes());
    le(&mut b, &(EH as u16).to_le_bytes());
    le(&mut b, &(PH as u16).to_le_bytes());
    le(&mut b, &1u16.to_le_bytes()); // e_phnum
    le(&mut b, &0u16.to_le_bytes());
    le(&mut b, &0u16.to_le_bytes());
    le(&mut b, &0u16.to_le_bytes());
    assert_eq!(b.len(), EH);
    // PT_LOAD
    le(&mut b, &1u32.to_le_bytes());
    le(&mut b, &5u32.to_le_bytes()); // R|X
    le(&mut b, &seg_off.to_le_bytes());
    le(&mut b, &vaddr.to_le_bytes());
    le(&mut b, &vaddr.to_le_bytes());
    le(&mut b, &(code.len() as u64).to_le_bytes());
    le(&mut b, &memsz.to_le_bytes());
    le(&mut b, &0x1000u64.to_le_bytes());
    assert_eq!(b.len(), EH + PH);
    le(&mut b, &code);
    b
}

/// Relocatable ELF64 (ET_REL, no program headers) with a PROGBITS `.text` and a
/// `SHT_NOBITS` `.bss` — exercises the section-mapping fallback and SHT_NOBITS
/// zero-fill.
fn elf_relocatable_with_bss() -> Vec<u8> {
    const EH: usize = 64;
    const SH: usize = 64;
    let code = [0x90u8, 0x90, 0xc3]; // nop; nop; ret
                                     // .shstrtab contents
    let mut shstr = Vec::new();
    shstr.push(0); // index 0 = ""
    let name_text = shstr.len() as u32;
    shstr.extend_from_slice(b".text\0");
    let name_bss = shstr.len() as u32;
    shstr.extend_from_slice(b".bss\0");
    let name_shstr = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab\0");

    let text_off = EH as u64; // 64
    let text_size = code.len() as u64;
    let shstr_off = text_off + text_size; // 67
    let shoff = shstr_off + shstr.len() as u64;

    let text_addr: u64 = 0x1000;
    let bss_addr: u64 = 0x2000;
    let bss_size: u64 = 0x10; // 16 zero-filled bytes

    let mut b = Vec::new();
    le(&mut b, &[0x7f, b'E', b'L', b'F']);
    b.push(2); // ELFCLASS64
    b.push(1); // ELFDATA2LSB
    b.push(1);
    le(&mut b, &[0u8; 9]);
    le(&mut b, &1u16.to_le_bytes()); // ET_REL
    le(&mut b, &0x3eu16.to_le_bytes()); // EM_X86_64
    le(&mut b, &1u32.to_le_bytes());
    le(&mut b, &0u64.to_le_bytes()); // e_entry
    le(&mut b, &0u64.to_le_bytes()); // e_phoff (none)
    le(&mut b, &shoff.to_le_bytes()); // e_shoff
    le(&mut b, &0u32.to_le_bytes());
    le(&mut b, &(EH as u16).to_le_bytes());
    le(&mut b, &0u16.to_le_bytes()); // e_phentsize
    le(&mut b, &0u16.to_le_bytes()); // e_phnum
    le(&mut b, &(SH as u16).to_le_bytes()); // e_shentsize
    le(&mut b, &4u16.to_le_bytes()); // e_shnum
    le(&mut b, &3u16.to_le_bytes()); // e_shstrndx
    assert_eq!(b.len(), EH);
    le(&mut b, &code);
    le(&mut b, &shstr);
    assert_eq!(b.len() as u64, shoff);

    // section header helper
    let mut shdr = |name: u32, stype: u32, flags: u64, addr: u64, off: u64, size: u64| {
        le(&mut b, &name.to_le_bytes());
        le(&mut b, &stype.to_le_bytes());
        le(&mut b, &flags.to_le_bytes());
        le(&mut b, &addr.to_le_bytes());
        le(&mut b, &off.to_le_bytes());
        le(&mut b, &size.to_le_bytes());
        le(&mut b, &0u32.to_le_bytes()); // sh_link
        le(&mut b, &0u32.to_le_bytes()); // sh_info
        le(&mut b, &1u64.to_le_bytes()); // sh_addralign
        le(&mut b, &0u64.to_le_bytes()); // sh_entsize
    };
    shdr(0, 0, 0, 0, 0, 0); // NULL
    shdr(name_text, 1, 0x6, text_addr, text_off, text_size); // PROGBITS ALLOC|EXECINSTR
    shdr(name_bss, 8, 0x3, bss_addr, shstr_off, bss_size); // NOBITS ALLOC|WRITE (off irrelevant)
    shdr(name_shstr, 3, 0, 0, shstr_off, shstr.len() as u64); // STRTAB
    b
}

fn load(bytes: &[u8], ext: &str) -> VivWorkspace {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(format!("f.{ext}"));
    std::fs::write(&p, bytes).unwrap();
    let mut ws = VivWorkspace::new();
    ws.load_from_file(&p).unwrap();
    ws
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// I1 + I3: every region's declared size equals its byte length, and
/// workspace.read_memory over the region equals the region bytes with matching
/// permissions (loader bytes == workspace reads).
#[test]
fn i1_i3_region_len_and_reads_agree() {
    for (bytes, ext) in [(elf_pt_load(), "elf"), (elf_relocatable_with_bss(), "o")] {
        let ws = load(&bytes, ext);
        let regions: Vec<_> = ws
            .iter_memory_regions()
            .map(|r| (r.base, r.size, r.permissions, r.data.clone()))
            .collect();
        assert!(!regions.is_empty(), "no regions mapped for .{ext}");
        for (base, size, perms, data) in regions {
            assert_eq!(size, data.len(), "region size != data.len() at {base:#x}");
            assert_eq!(
                ws.read_memory(base, size).unwrap(),
                data,
                "read_memory != region bytes at {base:#x}"
            );
            assert_eq!(
                ws.get_permissions(base),
                Some(perms),
                "perms mismatch at {base:#x}"
            );
            // region_at within the extent resolves to this region.
            assert_eq!(ws.region_at(base).map(|r| r.base), Some(base));
        }
    }
}

/// I2: PT_LOAD virtual tail is zero-filled, and a relocatable SHT_NOBITS `.bss`
/// is mapped and fully zero (not copied file bytes).
#[test]
fn i2_zero_fill_and_bss() {
    // PT_LOAD: 4 file bytes at 0x400078, memsz 0x20 -> tail zero.
    let ws = load(&elf_pt_load(), "elf");
    assert_eq!(
        ws.read_memory(0x400078, 4).unwrap(),
        vec![0x48, 0x31, 0xc0, 0xc3]
    );
    assert_eq!(ws.read_memory(0x40007c, 0x1c).unwrap(), vec![0u8; 0x1c]);

    // Relocatable .bss (SHT_NOBITS) at 0x2000, size 0x10 -> present and all zero.
    let ws = load(&elf_relocatable_with_bss(), "o");
    assert_eq!(ws.read_memory(0x1000, 3).unwrap(), vec![0x90, 0x90, 0xc3]);
    let bss = ws
        .read_memory(0x2000, 0x10)
        .expect(".bss must be mapped (SHT_NOBITS zero-filled)");
    assert_eq!(
        bss,
        vec![0u8; 0x10],
        ".bss must be zero-filled, not file bytes"
    );
    assert!(ws
        .get_permissions(0x2000)
        .unwrap()
        .contains(MemoryPermissions::WRITE));
}

/// I6 + I9: a save → reload round-trip yields an identical memory image
/// (digest, per-region bytes/perms, endian) and identical reads (one image
/// before and after persistence).
#[test]
fn i6_i9_persistence_is_one_image() {
    for (bytes, ext) in [(elf_pt_load(), "elf"), (elf_relocatable_with_bss(), "o")] {
        let ws = load(&bytes, ext);
        let digest_before = ws.memory_image().digest();
        let before: Vec<_> = ws
            .iter_memory_regions()
            .map(|r| (r.base, r.permissions, r.data.clone()))
            .collect();

        let dir = tempfile::tempdir().unwrap();
        let wsp = dir.path().join("ws.viv");
        save_workspace(&ws, &wsp).unwrap();
        let reloaded = load_workspace(&wsp).unwrap();

        assert_eq!(
            digest_before,
            reloaded.memory_image().digest(),
            "memory image digest changed across persistence (.{ext})"
        );
        assert_eq!(ws.endian(), reloaded.endian());
        let after: Vec<_> = reloaded
            .iter_memory_regions()
            .map(|r| (r.base, r.permissions, r.data.clone()))
            .collect();
        assert_eq!(before, after, "regions differ after reload (.{ext})");
        // Reads agree before and after at every region base.
        for (base, _perms, data) in &before {
            assert_eq!(
                reloaded.read_memory(*base, data.len()).unwrap(),
                *data,
                "reloaded read != original at {base:#x}"
            );
        }
    }
}

/// I7: endianness travels with the bytes — a big-endian workspace's typed reads
/// differ from a little-endian one over identical bytes.
#[test]
fn i7_endian_travels_with_image() {
    let mut ws = VivWorkspace::new();
    ws.set_architecture(Architecture::Amd64);
    ws.set_endian(Endian::Big);
    ws.add_memory_region(
        0x1000,
        vec![0x11, 0x22, 0x33, 0x44],
        MemoryPermissions::READ,
        None,
    )
    .unwrap();
    assert_eq!(ws.endian(), Endian::Big);
    assert_eq!(ws.memory_image().read_u32(0x1000).unwrap(), 0x1122_3344);
    // Persisted endianness survives reload.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("be.viv");
    save_workspace(&ws, &p).unwrap();
    let r = load_workspace(&p).unwrap();
    assert_eq!(r.endian(), Endian::Big);
    assert_eq!(r.memory_image().read_u32(0x1000).unwrap(), 0x1122_3344);
}
