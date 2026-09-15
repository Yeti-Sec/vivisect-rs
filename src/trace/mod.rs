//! Runtime code/data-flow tracing (roadmap Phase 1 / §3).
//!
//! A reusable observability layer that emits stable **domain events** across the
//! analysis lifecycle (load → map → decode → analyze → xref/CFG → emulate →
//! persist/reload → differential compare) so parity and regression failures can
//! be localized without ad-hoc print debugging.
//!
//! Design constraints honored here:
//! - **Minimal overhead when disabled**: the fast path is a single relaxed
//!   atomic load; event `detail` strings are built lazily via a closure and are
//!   never constructed while tracing is off.
//! - **Never alters analysis semantics**: emitting is a pure side effect.
//! - **Bounded payloads**: `detail` is truncated; the ring-buffer sink is capped.
//! - **Deterministic**: events carry a monotonic sequence number rather than a
//!   wall-clock timestamp, so captured streams compare deterministically.
//!
//! Tracing is runtime-toggled (via [`set_session`]/[`clear_session`]) rather than
//! `cfg`-gated, which keeps instrumentation call sites uncluttered while still
//! compiling to a cheap disabled check.

use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Maximum length of an event `detail` payload (bounded capture).
pub const MAX_DETAIL_LEN: usize = 256;

static ENABLED: AtomicBool = AtomicBool::new(false);
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether tracing is currently active.
#[inline]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Stable domain event kinds spanning the analysis lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventKind {
    LoaderDetect,
    LoaderMapRegion,
    DecoderDecode,
    OperandResolve,
    BranchEmit,
    AnalysisFunctionAdd,
    AnalysisBlockAdd,
    XrefAdd,
    AbiResolve,
    EmuStep,
    EmuCall,
    WorkspaceSave,
    WorkspaceLoad,
    ParityCompare,
}

/// A single trace event. Carries the correlated context needed to reconstruct
/// and diff an analysis path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Monotonic sequence number (deterministic ordering; not a timestamp).
    pub seq: u64,
    /// Event kind.
    pub kind: EventKind,
    /// Primary address (instruction / region / xref source), if applicable.
    pub va: Option<u64>,
    /// Owning function VA, if applicable.
    pub func_va: Option<u64>,
    /// Optional correlation / parent-span id.
    pub correlation: Option<u64>,
    /// Bounded, human-readable summary.
    pub detail: String,
}

/// A sink that receives emitted events.
pub trait TraceSink: Send + Sync {
    /// Handle one event.
    fn emit(&self, ev: &TraceEvent);
}

/// Discards all events.
pub struct NoopSink;
impl TraceSink for NoopSink {
    fn emit(&self, _ev: &TraceEvent) {}
}

/// Collects all events in order (primarily for tests).
#[derive(Default)]
pub struct CollectorSink {
    events: Mutex<Vec<TraceEvent>>,
}
impl CollectorSink {
    /// Create an empty collector.
    pub fn new() -> Self {
        Self::default()
    }
    /// Snapshot the collected events.
    pub fn events(&self) -> Vec<TraceEvent> {
        self.events.lock().unwrap().clone()
    }
    /// Number of collected events.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }
    /// Whether no events were collected.
    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }
}
impl TraceSink for CollectorSink {
    fn emit(&self, ev: &TraceEvent) {
        self.events.lock().unwrap().push(ev.clone());
    }
}

/// A bounded in-memory ring buffer of the most recent events.
pub struct RingBufferSink {
    cap: usize,
    buf: Mutex<VecDeque<TraceEvent>>,
}
impl RingBufferSink {
    /// Create a ring buffer holding at most `cap` events.
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            buf: Mutex::new(VecDeque::with_capacity(cap.max(1))),
        }
    }
    /// Snapshot the retained events (oldest first).
    pub fn events(&self) -> Vec<TraceEvent> {
        self.buf.lock().unwrap().iter().cloned().collect()
    }
}
impl TraceSink for RingBufferSink {
    fn emit(&self, ev: &TraceEvent) {
        let mut buf = self.buf.lock().unwrap();
        if buf.len() == self.cap {
            buf.pop_front();
        }
        buf.push_back(ev.clone());
    }
}

/// Writes one JSON object per line (JSONL) to an underlying writer.
pub struct JsonlSink {
    writer: Mutex<Box<dyn Write + Send>>,
}
impl JsonlSink {
    /// Create a JSONL sink over any writer (file, buffer, ...).
    pub fn new(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}
impl TraceSink for JsonlSink {
    fn emit(&self, ev: &TraceEvent) {
        if let Ok(mut w) = self.writer.lock() {
            if let Ok(line) = serde_json::to_string(ev) {
                let _ = writeln!(w, "{}", line);
            }
        }
    }
}

/// Filters which events are recorded.
#[derive(Default, Clone)]
pub struct TraceFilter {
    /// If set, only these kinds are recorded.
    pub kinds: Option<HashSet<EventKind>>,
    /// If set, only events for this function VA are recorded.
    pub func_va: Option<u64>,
    /// If set, only events for this VA are recorded.
    pub va: Option<u64>,
}
impl TraceFilter {
    /// Accept everything.
    pub fn all() -> Self {
        Self::default()
    }
    /// Restrict to a single function VA.
    pub fn for_function(func_va: u64) -> Self {
        Self {
            func_va: Some(func_va),
            ..Self::default()
        }
    }
    /// Restrict to a set of event kinds.
    pub fn for_kinds(kinds: impl IntoIterator<Item = EventKind>) -> Self {
        Self {
            kinds: Some(kinds.into_iter().collect()),
            ..Self::default()
        }
    }

    fn accepts(&self, kind: EventKind, va: Option<u64>, func_va: Option<u64>) -> bool {
        if let Some(kinds) = &self.kinds {
            if !kinds.contains(&kind) {
                return false;
            }
        }
        if let Some(want) = self.func_va {
            if func_va != Some(want) {
                return false;
            }
        }
        if let Some(want) = self.va {
            if va != Some(want) {
                return false;
            }
        }
        true
    }
}

/// An active trace session: a sink plus a filter.
pub struct TraceSession {
    sink: Arc<dyn TraceSink>,
    filter: TraceFilter,
}
impl TraceSession {
    /// Create a session from a sink and filter.
    pub fn new(sink: Arc<dyn TraceSink>, filter: TraceFilter) -> Self {
        Self { sink, filter }
    }
}

fn session_cell() -> &'static Mutex<Option<Arc<TraceSession>>> {
    static CELL: OnceLock<Mutex<Option<Arc<TraceSession>>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(None))
}

/// Install a global trace session and enable tracing. Resets the sequence
/// counter so a fresh capture starts at 0 (deterministic streams).
pub fn set_session(session: TraceSession) {
    SEQ.store(0, Ordering::Relaxed);
    *session_cell().lock().unwrap() = Some(Arc::new(session));
    ENABLED.store(true, Ordering::Relaxed);
}

/// Convenience: install a [`CollectorSink`] session and return the collector.
pub fn collect(filter: TraceFilter) -> Arc<CollectorSink> {
    let collector = Arc::new(CollectorSink::new());
    set_session(TraceSession::new(collector.clone(), filter));
    collector
}

/// Disable tracing and drop the global session.
pub fn clear_session() {
    ENABLED.store(false, Ordering::Relaxed);
    *session_cell().lock().unwrap() = None;
}

fn truncate_detail(mut s: String) -> String {
    if s.len() > MAX_DETAIL_LEN {
        s.truncate(MAX_DETAIL_LEN);
        s.push('…');
    }
    s
}

/// Emit a domain event. The `detail` closure is only evaluated when tracing is
/// active and the event passes the session filter, so disabled tracing costs a
/// single atomic load.
#[inline]
pub fn emit(
    kind: EventKind,
    va: Option<u64>,
    func_va: Option<u64>,
    detail: impl FnOnce() -> String,
) {
    if !is_enabled() {
        return;
    }
    let guard = session_cell().lock().unwrap();
    if let Some(session) = guard.as_ref() {
        if !session.filter.accepts(kind, va, func_va) {
            return;
        }
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let ev = TraceEvent {
            seq,
            kind,
            va,
            func_va,
            correlation: None,
            detail: truncate_detail(detail()),
        };
        session.sink.emit(&ev);
    }
}

// ---------------------------------------------------------------------------
// Differential comparator
// ---------------------------------------------------------------------------

/// The first point at which two event streams diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Index of the first differing position.
    pub index: usize,
    /// Event from the left stream at that index, if any.
    pub left: Option<TraceEvent>,
    /// Event from the right stream at that index, if any.
    pub right: Option<TraceEvent>,
}

/// Find the first semantically-divergent event between two streams.
///
/// Events are compared with `eq` (which should ignore incidental fields such as
/// `seq`); the first index where they differ — or where one stream ends before
/// the other — is returned. `None` means the streams are equivalent under `eq`.
pub fn first_divergence(
    left: &[TraceEvent],
    right: &[TraceEvent],
    eq: impl Fn(&TraceEvent, &TraceEvent) -> bool,
) -> Option<Divergence> {
    let n = left.len().max(right.len());
    for i in 0..n {
        match (left.get(i), right.get(i)) {
            (Some(a), Some(b)) if eq(a, b) => continue,
            (a, b) => {
                return Some(Divergence {
                    index: i,
                    left: a.cloned(),
                    right: b.cloned(),
                })
            }
        }
    }
    None
}

/// Semantic event equality that ignores the incidental sequence number and
/// detail text (compares kind + addresses only). Suitable as the default `eq`
/// for [`first_divergence`] when comparing analysis paths.
pub fn semantic_eq(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.va == b.va && a.func_va == b.func_va
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Tracing uses process-global state; serialize the tests that touch it.
    static TEST_LOCK: StdMutex<()> = StdMutex::new(());

    #[test]
    fn disabled_by_default_costs_nothing() {
        let _g = TEST_LOCK.lock().unwrap();
        clear_session();
        assert!(!is_enabled());
        // Emitting while disabled must not panic and must not build detail.
        let mut built = false;
        emit(EventKind::DecoderDecode, Some(0x1000), None, || {
            built = true;
            "x".into()
        });
        assert!(!built, "detail closure must not run while disabled");
    }

    #[test]
    fn collector_captures_and_filters_by_function() {
        let _g = TEST_LOCK.lock().unwrap();
        let c = collect(TraceFilter::for_function(0x401000));
        emit(
            EventKind::AnalysisFunctionAdd,
            Some(0x401000),
            Some(0x401000),
            || "f".into(),
        );
        emit(EventKind::XrefAdd, Some(0x401010), Some(0x401000), || {
            "x".into()
        });
        // Different function → filtered out.
        emit(EventKind::XrefAdd, Some(0x402000), Some(0x402000), || {
            "y".into()
        });
        clear_session();

        let evs = c.events();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].kind, EventKind::AnalysisFunctionAdd);
        assert_eq!(evs[0].seq, 0);
        assert_eq!(evs[1].seq, 1);
        assert!(evs.iter().all(|e| e.func_va == Some(0x401000)));
    }

    #[test]
    fn filter_by_kind() {
        let _g = TEST_LOCK.lock().unwrap();
        let c = collect(TraceFilter::for_kinds([EventKind::XrefAdd]));
        emit(EventKind::AnalysisFunctionAdd, Some(1), None, || "".into());
        emit(EventKind::XrefAdd, Some(2), None, || "".into());
        clear_session();
        let evs = c.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::XrefAdd);
    }

    #[test]
    fn ring_buffer_is_bounded() {
        let _g = TEST_LOCK.lock().unwrap();
        let ring = Arc::new(RingBufferSink::new(3));
        set_session(TraceSession::new(ring.clone(), TraceFilter::all()));
        for i in 0..10u64 {
            emit(EventKind::EmuStep, Some(i), None, || "".into());
        }
        clear_session();
        let evs = ring.events();
        assert_eq!(evs.len(), 3, "ring buffer must cap retained events");
        // Only the most recent 3 survive.
        assert_eq!(
            evs.iter().map(|e| e.va.unwrap()).collect::<Vec<_>>(),
            vec![7, 8, 9]
        );
    }

    #[test]
    fn jsonl_sink_roundtrips() {
        let _g = TEST_LOCK.lock().unwrap();
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        set_session(TraceSession::new(
            Arc::new(JsonlSink::new(Box::new(SharedBuf(buf.clone())))),
            TraceFilter::all(),
        ));
        emit(EventKind::WorkspaceSave, None, None, || "path=x".into());
        emit(EventKind::WorkspaceLoad, Some(0x1000), Some(0x1000), || {
            "ok".into()
        });
        clear_session();

        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let ev0: TraceEvent = serde_json::from_str(lines[0]).unwrap();
        let ev1: TraceEvent = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(ev0.kind, EventKind::WorkspaceSave);
        assert_eq!(ev1.va, Some(0x1000));
    }

    #[test]
    fn comparator_finds_first_divergence() {
        let mk = |seq, kind, va| TraceEvent {
            seq,
            kind,
            va: Some(va),
            func_va: None,
            correlation: None,
            detail: String::new(),
        };
        let a = vec![
            mk(0, EventKind::DecoderDecode, 0x1000),
            mk(1, EventKind::DecoderDecode, 0x1005),
            mk(2, EventKind::BranchEmit, 0x1008),
        ];
        // b diverges at index 1 (different VA), despite different seq numbers.
        let b = vec![
            mk(10, EventKind::DecoderDecode, 0x1000),
            mk(11, EventKind::DecoderDecode, 0x1006),
        ];
        let d = first_divergence(&a, &b, semantic_eq).unwrap();
        assert_eq!(d.index, 1);
        assert_eq!(d.left.unwrap().va, Some(0x1005));
        assert_eq!(d.right.unwrap().va, Some(0x1006));

        // Identical-under-eq streams do not diverge.
        assert!(first_divergence(&a, &a, semantic_eq).is_none());
    }

    #[test]
    fn detail_is_truncated() {
        let _g = TEST_LOCK.lock().unwrap();
        let c = collect(TraceFilter::all());
        emit(EventKind::DecoderDecode, None, None, || "z".repeat(1000));
        clear_session();
        let evs = c.events();
        // Truncated to MAX_DETAIL_LEN plus the ellipsis marker.
        assert!(evs[0].detail.chars().count() <= MAX_DETAIL_LEN + 1);
    }
}
