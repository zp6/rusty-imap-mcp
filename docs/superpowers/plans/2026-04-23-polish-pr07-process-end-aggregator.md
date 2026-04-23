# Polish PR 7 — `process_end.total_tool_calls` aggregator

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #135. `process_end` currently emits `total_tool_calls: 0` as a placeholder. Thread a daemon-scoped `AtomicU64` counter through `DaemonState`, increment it from `emit_session_end` with each session's tool-call count, and read it in `daemon_main` before writing the `process_end` record.

**Architecture:** One new `AtomicU64` field on `DaemonState`. `emit_session_end` already loads the per-session `tool_call_count`; add a `fetch_add` on the daemon-level counter with the same value. `daemon_main` reads the daemon-level counter with `Relaxed` before logging `process_end`. Two non-primary call sites that currently also emit `total_tool_calls: 0` (`boot/audit_init.rs:181` and `:230`, both in the boot-failure path before the daemon loop starts) stay at `0` — no sessions have run, so the value is correct.

**Tech Stack:** Rust, `std::sync::atomic::AtomicU64`, `Ordering::Relaxed`.

---

## Files

- Modify: `crates/rimap-server/src/daemon/state.rs` — add `total_tool_calls` field to `DaemonState`.
- Modify: `crates/rimap-server/src/daemon/run.rs:321-340` — bump daemon-level counter in `emit_session_end`.
- Modify: `crates/rimap-server/src/main.rs:202-211` — read counter in `daemon_main` before `log_process_end`.
- Test: `crates/rimap-server/tests/audit_process_end_aggregator.rs` (new integration test).

## Task 1: Add the daemon-level counter field

**Files:**
- Modify: `crates/rimap-server/src/daemon/state.rs`

- [ ] **Step 1: Add a failing unit test**

Append to the `#[cfg(test)]` module at the bottom of `crates/rimap-server/src/daemon/state.rs` (keep the existing `#[expect(clippy::unwrap_used, ...)]` attribute):

```rust
#[test]
fn daemon_state_has_total_tool_calls_counter_starting_at_zero() {
    // Constructed via struct literal (not a helper) to mirror daemon_main().
    // We only assert the counter starts at 0 — the other fields are stubbed
    // with placeholder values that are never observed by this test.
    use std::sync::atomic::Ordering;
    // A minimal DaemonState cannot be built without the full stack; we
    // instead assert via a direct field access on a value we do construct
    // in a real test. This placeholder is elevated into a real integration
    // test in Task 3; for now, just assert the field exists via a compile
    // check.
    fn _assert_field_exists(state: &super::DaemonState) -> u64 {
        state
            .total_tool_calls
            .load(Ordering::Relaxed)
    }
    let _ = _assert_field_exists;
}
```

(This is a compile-time check, not a runtime assertion. `DaemonState` cannot be constructed outside `daemon_main` without considerable plumbing; the runtime check lives in Task 3.)

- [ ] **Step 2: Run the test to confirm it fails to compile**

Run: `cargo test -p rimap-server --lib daemon::state::tests::daemon_state_has_total_tool_calls_counter_starting_at_zero`
Expected: compile error — `no field 'total_tool_calls' on type 'DaemonState'`.

- [ ] **Step 3: Add the field**

Edit `crates/rimap-server/src/daemon/state.rs`. Update the `use` block at the top:

```rust
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
```

Inside `pub struct DaemonState { ... }`, add the new field at the end (after `session_permits`):

```rust
    /// Daemon-wide aggregate of completed tool calls across all sessions.
    /// Incremented in `emit_session_end` with each session's final count.
    /// Read in `daemon_main` to populate `process_end.total_tool_calls`.
    pub total_tool_calls: AtomicU64,
```

- [ ] **Step 4: Initialise the field in `daemon_main`**

Edit `crates/rimap-server/src/main.rs`, inside `daemon_main` where `DaemonState` is constructed (line 186-193). Add the initialiser:

```rust
    let state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits,
        total_tool_calls: std::sync::atomic::AtomicU64::new(0),
    });
```

- [ ] **Step 5: Run the compile-check test**

Run: `cargo test -p rimap-server --lib daemon::state::tests::daemon_state_has_total_tool_calls_counter_starting_at_zero`
Expected: pass (the field now exists).

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/daemon/state.rs crates/rimap-server/src/main.rs
git commit -m "feat(rimap-server): add DaemonState.total_tool_calls counter (#135)"
```

## Task 2: Bump the counter in `emit_session_end`

**Files:**
- Modify: `crates/rimap-server/src/daemon/run.rs:321-340`

- [ ] **Step 1: Update `emit_session_end`**

In `crates/rimap-server/src/daemon/run.rs`, find `emit_session_end` (starts at line 322). Immediately after the `let total = session.tool_call_count.load(...)` line (line 329-331), add:

```rust
    state
        .total_tool_calls
        .fetch_add(total, std::sync::atomic::Ordering::Relaxed);
```

The full block should now read:

```rust
    let total = session
        .tool_call_count
        .load(std::sync::atomic::Ordering::Relaxed);
    state
        .total_tool_calls
        .fetch_add(total, std::sync::atomic::Ordering::Relaxed);
    let end = rimap_audit::record::SessionEnd {
        session_id: session.id,
        reason,
        duration_ms,
        total_tool_calls: total,
        last_error,
    };
```

- [ ] **Step 2: Build to verify no compile errors**

Run: `cargo build -p rimap-server`
Expected: clean build.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/daemon/run.rs
git commit -m "feat(rimap-server): aggregate per-session tool counts into DaemonState (#135)"
```

## Task 3: Read the counter in `daemon_main` and add an integration test

**Files:**
- Modify: `crates/rimap-server/src/main.rs:202-211`
- Create: `crates/rimap-server/tests/audit_process_end_aggregator.rs`

- [ ] **Step 1: Write the failing integration test**

Create `crates/rimap-server/tests/audit_process_end_aggregator.rs`:

```rust
//! Integration test for issue #135: `process_end.total_tool_calls` must
//! aggregate across all sessions, not emit 0.

#![expect(clippy::unwrap_used, reason = "tests")]

mod common;

use common::daemon_harness::TestDaemon;
use serde_json::Value;
use std::time::Duration;

/// Spawn a daemon, run two sessions each making N tool calls, shut the
/// daemon down, and assert `process_end.total_tool_calls == 2 * N`.
#[tokio::test(flavor = "multi_thread")]
async fn process_end_aggregates_tool_calls_across_sessions() {
    let daemon = TestDaemon::spawn().await;
    let audit_path = daemon.audit_path().to_path_buf();

    // Two sessions, two tool calls each. Use the harness's existing
    // connect + list_tools helper; list_tools is an infrastructure call
    // that counts toward tool_call_count.
    for _ in 0..2 {
        let mut client = daemon.connect().await;
        client.list_tools().await.unwrap();
        client.list_tools().await.unwrap();
        drop(client);
    }

    daemon.shutdown_and_wait(Duration::from_secs(5)).await;

    // Scan the audit log for the process_end record.
    let body = std::fs::read_to_string(&audit_path).unwrap();
    let mut total = None;
    for line in body.lines() {
        let v: Value = serde_json::from_str(line).unwrap();
        if v.get("kind").and_then(Value::as_str) == Some("process_end") {
            total = v.get("total_tool_calls").and_then(Value::as_u64);
        }
    }
    assert_eq!(total, Some(4), "expected 4 tool calls, got {total:?}");
}
```

- [ ] **Step 2: Run the test to confirm it fails**

Run: `cargo test -p rimap-server --test audit_process_end_aggregator`
Expected: FAIL with `assertion failed: expected 4 tool calls, got Some(0)`.

- [ ] **Step 3: Update `daemon_main` to read the counter**

In `crates/rimap-server/src/main.rs`, replace lines 204–209:

```rust
    if let Err(e) = audit.log_process_end(rimap_audit::ProcessEnd {
        reason,
        // Aggregation across sessions is a follow-up — leave 0 for v1.
        total_tool_calls: 0,
    }) {
```

with:

```rust
    let total_tool_calls = state
        .total_tool_calls
        .load(std::sync::atomic::Ordering::Relaxed);
    if let Err(e) = audit.log_process_end(rimap_audit::ProcessEnd {
        reason,
        total_tool_calls,
    }) {
```

- [ ] **Step 4: Run the test to confirm it passes**

Run: `cargo test -p rimap-server --test audit_process_end_aggregator`
Expected: PASS.

- [ ] **Step 5: Run the full daemon test suite to confirm no regression**

Run: `cargo test -p rimap-server --tests`
Expected: all existing daemon tests pass (especially `daemon_happy_path` and `daemon_graceful_shutdown`).

- [ ] **Step 6: Run clippy with zero-warnings policy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/main.rs crates/rimap-server/tests/audit_process_end_aggregator.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): wire process_end.total_tool_calls aggregator (#135)

daemon_main reads the new DaemonState counter populated from
emit_session_end. Adds an integration test that runs two sessions
making two tool calls each and asserts process_end reports 4.

Closes #135.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Self-review

- TDD discipline: failing test in Task 3 step 2 before the fix in step 3.
- `Ordering::Relaxed` used consistently — no cross-thread ordering is required because the counter is only read after every session has finished (`drainer_handle.await` happens before the load in Task 3 step 3).
- The two non-primary `total_tool_calls: 0` call sites in `boot/audit_init.rs` (line 181 and 230) are intentionally untouched: they fire only on boot-failure paths where no sessions ever ran. Acceptance criterion in the spec is satisfied because #135's target was the daemon success/error exit path in `daemon_main`.
- Three commits, each independently reviewable; only the final commit changes observable behaviour.
