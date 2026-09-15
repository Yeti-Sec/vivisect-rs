//! Roadmap Phase 4 / finding #10: the Mach-O parser must be wired into the
//! primary workspace-loading workflow (previously `load_from_file` rejected
//! Mach-O with "Unsupported format").
//!
//! Uses a minimal hand-built Mach-O64 header (no external corpus). Section
//! mapping reuses the same `normalize_mapped_image` zero-fill path that the PE
//! and ELF loaders use (separately tested byte-for-byte).

use vivisect::constants::{Architecture, Endian};
use vivisect::core::VivWorkspace;
use vivisect::parsers::{detect_format_bytes, BinaryFormat};

/// Minimal valid Mach-O 64-bit little-endian executable header (32 bytes).
fn make_macho64_header() -> Vec<u8> {
    let mut d = vec![0u8; 32];
    d[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_MAGIC_64 (LE)
    d[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // CPU_TYPE_X86_64
    d[8..12].copy_from_slice(&3u32.to_le_bytes()); // CPU_SUBTYPE_X86_64_ALL
    d[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
                                                    // ncmds = 0, sizeofcmds = 0, flags = 0, reserved = 0 (already zero)
    d
}

#[test]
fn macho_is_wired_into_the_loader() {
    let bytes = make_macho64_header();

    // Format detection recognizes Mach-O.
    assert_eq!(detect_format_bytes(&bytes).unwrap(), BinaryFormat::MachO);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mini.macho");
    std::fs::write(&path, &bytes).unwrap();

    // The workspace loader dispatches to the Mach-O path instead of returning
    // "Unsupported format" (finding #10).
    let mut ws = VivWorkspace::new();
    ws.load_from_file(&path)
        .expect("Mach-O must load via the workspace loader");

    assert_eq!(ws.architecture(), Architecture::Amd64);
    assert_eq!(ws.endian(), Endian::Little);
    assert_eq!(ws.get_files().len(), 1);
    assert_eq!(ws.get_files()[0].format, BinaryFormat::MachO);
    // Sample identity is populated for Mach-O too (finding #14).
    let md5 = ws.get_files()[0].md5.clone().unwrap();
    assert_eq!(md5.len(), 32);
    assert_eq!(ws.get_meta("md5"), Some(md5.as_str()));
}
