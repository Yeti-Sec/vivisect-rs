//! Verify thunks and noret modules produce meaningful results.

use std::path::Path;
use vivisect::core::workspace::VivWorkspace;

fn sample_path(name: &str) -> std::path::PathBuf {
    Path::new(r"C:\Users\yeti-sec\Desktop\floss_test_samples").join(name)
}

#[test]
fn test_thunks_found_pe32() {
    let path = sample_path("floss_conti");
    if !path.exists() {
        eprintln!("SKIP: floss_conti not found");
        return;
    }

    let mut ws = VivWorkspace::new();
    ws.load_from_file(&path).unwrap();
    ws.analyze();

    let total = ws.function_count();
    let thunks: Vec<u64> = ws.get_functions()
        .into_iter()
        .filter(|&va| ws.is_function_thunk(va))
        .collect();
    let noret: Vec<u64> = ws.get_functions()
        .into_iter()
        .filter(|&va| ws.is_noreturn_va(va))
        .collect();

    println!("\n=== Thunks & NoRet Results (PE32 floss_conti) ===");
    println!("Total functions: {}", total);
    println!("Thunks found: {}", thunks.len());
    println!("No-return functions: {}", noret.len());

    // Show first few thunks
    for &va in thunks.iter().take(5) {
        let meta = ws.get_function(va).unwrap();
        let name = meta.name.as_deref().unwrap_or("?");
        let target = meta.meta.get("Thunk").cloned().unwrap_or_default();
        println!("  thunk {:#010x}: {} -> {}", va, name, target);
    }

    // Show noreturn functions
    for &va in noret.iter().take(5) {
        let name = ws.get_function(va)
            .and_then(|m| m.name.as_deref())
            .unwrap_or("?");
        println!("  noreturn {:#010x}: {}", va, name);
    }

    // We expect at least some thunks in a real PE binary with imports
    assert!(thunks.len() > 0, "Expected at least some thunks in PE32 binary");
    
    // We may or may not find noreturn functions depending on the binary
    println!("Thunks percentage: {:.1}%", thunks.len() as f64 / total as f64 * 100.0);

    // Check impapi annotations — thunks should have API metadata set
    let api_annotated: Vec<u64> = ws.get_functions()
        .into_iter()
        .filter(|&va| {
            ws.get_function(va)
                .map(|m| m.calling_convention.is_some())
                .unwrap_or(false)
        })
        .collect();

    println!("Functions with API metadata: {}", api_annotated.len());
    for &va in api_annotated.iter().take(5) {
        let meta = ws.get_function(va).unwrap();
        let name = meta.name.as_deref().unwrap_or("?");
        let cc = meta.calling_convention.as_deref().unwrap_or("?");
        let ret = meta.ret_type.as_deref().unwrap_or("?");
        println!("  impapi {:#010x}: {} -> {} {} ({} args)", va, name, cc, ret, meta.args.len());
    }

    // Thunks that have Thunk metadata should get API annotations
    assert!(api_annotated.len() > 0, "Expected at least some API-annotated functions");
}
