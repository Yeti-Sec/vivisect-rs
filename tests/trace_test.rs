//! End-to-end tests for the runtime trace layer (roadmap Phase 1 acceptance):
//! - a JSONL trace can reconstruct the high-level path of an analyzed function,
//! - filtering by VA works,
//! - trace disabled vs enabled yields identical semantic results,
//! - the differential comparator finds the first divergent semantic event.
//!
//! Trace state is process-global, so all assertions live in a single test to
//! avoid cross-thread interference with the parallel test runner.

use vivisect::analysis::codeflow::CodeFlowAnalyzer;
use vivisect::constants::{Architecture, MemoryPermissions};
use vivisect::core::VivWorkspace;
use vivisect::trace::{self, EventKind, TraceFilter};

/// A tiny hand-assembled x86-64 function with an internal call:
///
/// ```text
/// 0x1000: 48 83 ec 28        sub  rsp, 0x28
/// 0x1004: e8 07 00 00 00     call 0x1010
/// 0x1009: 48 83 c4 28        add  rsp, 0x28
/// 0x100d: c3                 ret
/// 0x100e: 90 90              nop; nop
/// 0x1010: 48 31 c0           xor  rax, rax   ; callee
/// 0x1013: c3                 ret
/// ```
fn code() -> Vec<u8> {
    vec![
        0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28
        0xE8, 0x07, 0x00, 0x00, 0x00, // call 0x1010
        0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
        0xC3, // ret
        0x90, 0x90, // padding
        0x48, 0x31, 0xC0, // xor rax,rax
        0xC3, // ret
    ]
}

fn build_ws() -> VivWorkspace {
    let mut ws = VivWorkspace::new();
    ws.set_architecture(Architecture::Amd64);
    // Pad the region so the analyzer's fixed 16-byte reads never overrun the
    // callee near the end (0x90 = nop is a harmless filler).
    let mut bytes = code();
    bytes.resize(0x40, 0x90);
    ws.add_memory_region(0x1000, bytes, MemoryPermissions::RX, Some(".text".into()))
        .unwrap();
    ws
}

fn run_codeflow(ws: &mut VivWorkspace) {
    let mut cf = CodeFlowAnalyzer::new();
    cf.add_entry_point(0x1000);
    cf.analyze(ws).unwrap();
}

#[test]
fn trace_layer_end_to_end() {
    // --- 1. Baseline with tracing DISABLED --------------------------------
    trace::clear_session();
    let mut ws_off = build_ws();
    run_codeflow(&mut ws_off);
    let digest_off = ws_off.semantic_digest();

    // --- 2. Same analysis with a collector sink, filtered to one function -
    let collector = trace::collect(TraceFilter::all());
    let mut ws_on = build_ws();
    run_codeflow(&mut ws_on);
    let digest_on = ws_on.semantic_digest();
    trace::clear_session();

    // Tracing must not change analysis semantics.
    assert_eq!(
        digest_off, digest_on,
        "enabling the trace layer changed analysis results"
    );

    let events = collector.events();
    assert!(!events.is_empty(), "no trace events captured");

    // Path reconstruction: we should see the entry instruction decoded, the
    // call's branch emitted, and the code xref to the callee recorded.
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::DecoderDecode && e.va == Some(0x1000)),
        "missing decode of entry instruction"
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::DecoderDecode && e.va == Some(0x1010)),
        "callee was not reached via the call xref"
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::BranchEmit && e.va == Some(0x1004)),
        "call branch not emitted"
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::XrefAdd && e.va == Some(0x1004)),
        "call xref not recorded"
    );
    // Sequence numbers are monotonic and start at 0.
    assert_eq!(events[0].seq, 0);
    assert!(events.windows(2).all(|w| w[1].seq > w[0].seq));

    // --- 3. Filtering by VA -----------------------------------------------
    let only_call = trace::collect(TraceFilter {
        va: Some(0x1004),
        ..TraceFilter::all()
    });
    let mut ws_f = build_ws();
    run_codeflow(&mut ws_f);
    trace::clear_session();
    let filtered = only_call.events();
    assert!(!filtered.is_empty());
    assert!(
        filtered.iter().all(|e| e.va == Some(0x1004)),
        "VA filter leaked other addresses: {:?}",
        filtered
    );

    // --- 4. Differential comparator ---------------------------------------
    // Re-run to get a full stream, then perturb one event and confirm the
    // comparator reports the first divergence.
    let full = trace::collect(TraceFilter::for_kinds([EventKind::DecoderDecode]));
    let mut ws_d = build_ws();
    run_codeflow(&mut ws_d);
    trace::clear_session();
    let stream_a = full.events();
    assert!(stream_a.len() >= 3);

    let mut stream_b = stream_a.clone();
    let idx = 1;
    stream_b[idx].va = Some(0xdead_beef); // perturb the 2nd decode's VA
    let div = trace::first_divergence(&stream_a, &stream_b, trace::semantic_eq)
        .expect("streams must diverge");
    assert_eq!(div.index, idx);
    assert_eq!(div.right.unwrap().va, Some(0xdead_beef));

    // Identical streams do not diverge.
    assert!(trace::first_divergence(&stream_a, &stream_a, trace::semantic_eq).is_none());
}
