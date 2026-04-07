//! In-memory ring buffer of recently-read Message-IDs. Fed by `fetch_message`
//! and `search` result paths (Sprint 5 wires the feeders). Every `tool_end`
//! snapshots the current contents into [`crate::record::Provenance`].
//!
//! Entries older than `window_seconds` are evicted on every push and on every
//! snapshot. This is a pure-Rust in-memory structure — no I/O, no locking
//! beyond what the caller holds.
//!
//! Duplicate Message-IDs are permitted: if the same ID is recorded twice it
//! will appear twice in the snapshot. Deduplication, if desired, is the
//! caller's responsibility.

use std::collections::VecDeque;

use time::OffsetDateTime;

/// Ring buffer of observed Message-IDs with timestamps. Not thread-safe on
/// its own; the caller holds a `Mutex<ProvenanceBuffer>` if needed.
#[derive(Debug, Clone)]
pub struct ProvenanceBuffer {
    window: std::time::Duration,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    message_id: String,
    seen_at: OffsetDateTime,
}

impl ProvenanceBuffer {
    /// Construct an empty buffer with a retention window in seconds.
    #[must_use]
    pub fn new(window_seconds: u32) -> Self {
        Self {
            window: std::time::Duration::from_secs(u64::from(window_seconds)),
            entries: VecDeque::new(),
        }
    }

    /// Record that a Message-ID was read now. Evicts stale entries before
    /// inserting.
    pub fn record(&mut self, message_id: impl Into<String>) {
        let now = OffsetDateTime::now_utc();
        self.evict_before(now);
        self.entries.push_back(Entry {
            message_id: message_id.into(),
            seen_at: now,
        });
    }

    /// Test-only variant taking an explicit clock so eviction can be asserted
    /// deterministically.
    #[doc(hidden)]
    pub fn record_at(&mut self, message_id: impl Into<String>, now: OffsetDateTime) {
        self.evict_before(now);
        self.entries.push_back(Entry {
            message_id: message_id.into(),
            seen_at: now,
        });
    }

    /// Return a `Vec<String>` of current entries, oldest-first. Evicts stale
    /// entries before snapshotting.
    #[must_use]
    pub fn snapshot(&mut self) -> Vec<String> {
        self.evict_before(OffsetDateTime::now_utc());
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Test-only snapshot with explicit clock.
    #[doc(hidden)]
    pub fn snapshot_at(&mut self, now: OffsetDateTime) -> Vec<String> {
        self.evict_before(now);
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Returns the number of entries currently buffered, including any
    /// stale entries that have not yet been evicted. `record*` and
    /// `snapshot*` evict before they act; `len` does not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict entries whose `seen_at` is strictly older than `now - window`.
    /// An entry timestamped exactly at the cutoff is retained.
    fn evict_before(&mut self, now: OffsetDateTime) {
        let cutoff = now - self.window;
        while let Some(front) = self.entries.front() {
            if front.seen_at < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use time::OffsetDateTime;

    use crate::provenance::ProvenanceBuffer;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000 + secs).unwrap()
    }

    #[test]
    fn records_preserve_insertion_order() {
        let mut b = ProvenanceBuffer::new(60);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(1));
        b.record_at("<c@x>", at(2));
        let snap = b.snapshot_at(at(3));
        assert_eq!(snap, vec!["<a@x>", "<b@x>", "<c@x>"]);
    }

    #[test]
    fn entries_older_than_window_are_evicted_on_snapshot() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(5));
        b.record_at("<c@x>", at(15));
        let snap = b.snapshot_at(at(15));
        assert_eq!(snap, vec!["<b@x>", "<c@x>"]);
    }

    #[test]
    fn eviction_runs_before_new_inserts() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(100));
        assert_eq!(b.len(), 1);
        assert_eq!(b.snapshot_at(at(100)), vec!["<b@x>"]);
    }

    #[test]
    fn empty_buffer_snapshots_to_empty_vec() {
        let mut b = ProvenanceBuffer::new(60);
        assert!(b.is_empty());
        let snap = b.snapshot_at(at(0));
        assert!(snap.is_empty());
    }

    #[test]
    fn window_of_zero_drops_everything_immediately() {
        let mut b = ProvenanceBuffer::new(0);
        b.record_at("<a@x>", at(0));
        assert_eq!(b.snapshot_at(at(1)), Vec::<String>::new());
    }
}
