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
//!
//! Callers MUST lossy-decode non-UTF-8 input before calling `record`;
//! `String` cannot represent non-UTF-8 bytes. Per-entry length is capped at
//! `MAX_MESSAGE_ID_LEN` bytes (truncated with a `…[truncated]` suffix);
//! entry count is capped at `MAX_BUFFER_ENTRIES` (oldest evicted).

use std::collections::VecDeque;

use time::OffsetDateTime;

/// Maximum byte length of a Message-ID stored in the buffer. Values longer
/// than this are truncated with a `…[truncated]` suffix. The cap is RFC 5322
/// line length.
const MAX_MESSAGE_ID_LEN: usize = 998;

/// Hard cap on entry count. When the buffer is at capacity, the oldest entry
/// is evicted regardless of the time window.
const MAX_BUFFER_ENTRIES: usize = 1024;

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
    /// inserting. Values longer than `MAX_MESSAGE_ID_LEN` bytes are truncated
    /// with a `…[truncated]` suffix. When the buffer is at `MAX_BUFFER_ENTRIES`
    /// capacity, the oldest entry is evicted regardless of the time window.
    pub fn record(&mut self, message_id: impl Into<String>) {
        self.record_at(message_id, OffsetDateTime::now_utc());
    }

    /// Variant taking an explicit clock so eviction can be asserted
    /// deterministically. Applies the same length cap and count cap as
    /// [`record`](Self::record). Crate-private; tests inside `rimap-audit`
    /// see it via `pub(crate)`.
    pub(crate) fn record_at(&mut self, message_id: impl Into<String>, now: OffsetDateTime) {
        self.evict_before(now);

        let mut message_id = message_id.into();
        if message_id.len() > MAX_MESSAGE_ID_LEN {
            // Truncate at a char boundary, not mid-codepoint.
            let mut end = MAX_MESSAGE_ID_LEN;
            while !message_id.is_char_boundary(end) {
                end -= 1;
            }
            message_id.truncate(end);
            message_id.push_str("\u{2026}[truncated]");
        }

        if self.entries.len() >= MAX_BUFFER_ENTRIES {
            self.entries.pop_front();
        }

        self.entries.push_back(Entry {
            message_id,
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

    /// Test-only snapshot with explicit clock. Crate-private; integration
    /// tests do not need this seam.
    #[cfg(test)]
    pub(crate) fn snapshot_at(&mut self, now: OffsetDateTime) -> Vec<String> {
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

    #[test]
    fn oversize_message_id_is_truncated_with_suffix() {
        let mut b = ProvenanceBuffer::new(60);
        let huge = "x".repeat(2000);
        b.record_at(huge, at(0));
        let snap = b.snapshot_at(at(1));
        assert_eq!(snap.len(), 1);
        let stored = &snap[0];
        assert!(stored.ends_with("\u{2026}[truncated]"));
        assert!(stored.len() < 2000);
    }

    #[test]
    fn count_cap_evicts_oldest_beyond_max_entries() {
        // Window is huge so time eviction isn't in play.
        let mut b = ProvenanceBuffer::new(3600);
        for i in 0..2000_u64 {
            b.record_at(format!("<id-{i}@x>"), at(i64::try_from(i).unwrap()));
        }
        let snap = b.snapshot_at(at(2000));
        // Capped at MAX_BUFFER_ENTRIES = 1024.
        assert_eq!(snap.len(), 1024);
        // Oldest (id-0) is gone; newest (id-1999) is present.
        assert!(!snap.iter().any(|s| s == "<id-0@x>"));
        assert!(snap.iter().any(|s| s == "<id-1999@x>"));
    }
}
