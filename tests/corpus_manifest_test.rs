//! Hermetic verification that every committed parity fixture matches its
//! recorded provenance/size/hash (Phase 0 acceptance: "every parity fixture has
//! provenance/version/hash"). Uses only committed files, so it always runs.

mod common;

#[test]
fn manifest_is_nonempty_and_versioned() {
    let m = common::load_manifest();
    assert!(m.version >= 1, "manifest must be versioned");
    assert!(
        !m.fixtures.is_empty(),
        "manifest must list at least one committed fixture"
    );
    assert!(!m.description.trim().is_empty());
}

#[test]
fn committed_fixtures_match_manifest_hash_and_size() {
    let m = common::load_manifest();
    for entry in &m.fixtures {
        let path = common::required_fixture(&entry.name); // hard-fail if missing
        let bytes = std::fs::read(&path).expect("read committed fixture");
        assert_eq!(
            bytes.len() as u64,
            entry.bytes,
            "size mismatch for {}: manifest {} vs actual {}",
            entry.name,
            entry.bytes,
            bytes.len()
        );
        let got = common::sha256_hex(&bytes);
        assert_eq!(
            got, entry.sha256,
            "sha256 mismatch for {} (fixture changed without updating the manifest?)",
            entry.name
        );
        assert!(
            !entry.provenance.trim().is_empty(),
            "fixture {} lacks provenance",
            entry.name
        );
    }
}
