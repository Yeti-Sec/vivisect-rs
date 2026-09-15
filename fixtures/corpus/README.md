# External raw-binary parity corpus

This directory is the repository-relative home for the raw binary samples used by
the differential parity tests (`parity_test.rs`, `parity_vectors_test.rs`,
`thunks_noret_test.rs`). Override the location with the `VIVISECT_CORPUS_DIR`
environment variable.

The samples themselves are **intentionally not committed** (they are third-party
malware binaries). When they are absent, the parity tests emit an explicit
`[PARITY-SKIP external-corpus] …` line and skip — they never silently pass
(review finding #6). The committed golden/vector JSON in the parent directory is
the offline oracle of record; see `../CORPUS_MANIFEST.json` and
`../../PARITY.md`.

Expected sample file names (as referenced by the tests) include:
`floss_conti`, `floss_badbazzar`, `elf_mirai`, and the Go ELF64
`b02337d82c44ed46e5b186bd54cde717be39da81a29fb332090d10a5c444ccb6`.
