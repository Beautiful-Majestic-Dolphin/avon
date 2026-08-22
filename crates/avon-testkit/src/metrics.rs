//! A process-wide debugging recorder, so data-plane tests can assert on the
//! reason a packet was dropped rather than only that it never arrived.

use std::sync::OnceLock;

use metrics_util::debugging::{DebuggingRecorder, Snapshotter};

static SNAPSHOTTER: OnceLock<Snapshotter> = OnceLock::new();

/// Install the recorder once per test process. Safe to call repeatedly.
pub fn install() {
    SNAPSHOTTER.get_or_init(|| {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // A second install would mean two test binaries in one process, which
        // cargo does not do; if it ever fails the first recorder still works.
        let _ = metrics::set_global_recorder(recorder);
        snapshotter
    });
}

/// The current value of counter `name` whose labels include every pair in
/// `labels`. Zero when the counter has not been touched.
pub fn counter(name: &str, labels: &[(&str, &str)]) -> u64 {
    let Some(s) = SNAPSHOTTER.get() else {
        return 0;
    };
    s.snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _desc, value)| {
            let key = key.key();
            if key.name() != name {
                return None;
            }
            let present: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_string(), l.value().to_string()))
                .collect();
            let matches = labels
                .iter()
                .all(|(k, v)| present.iter().any(|(pk, pv)| pk == k && pv == v));
            if !matches {
                return None;
            }
            match value {
                metrics_util::debugging::DebugValue::Counter(c) => Some(c),
                _ => None,
            }
        })
        .sum()
}
