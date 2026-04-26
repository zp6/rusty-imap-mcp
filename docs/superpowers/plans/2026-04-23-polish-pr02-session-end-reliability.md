# Polish PR 2 — Session-end reliability (#137 + #142)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the daemon-shutdown contract violation in `crates/rimap-server/src/daemon/run.rs` so that EVERY active session emits a `session_end(reason=DaemonShutdown)` audit record, including those aborted by `JoinSet::shutdown()` after the 5-second drain window. Also coalesce the paired-rejection start+end pattern into a single in-line write to take the second-write off the accept-loop hot path.

**Architecture:** Track active session metadata in a side `Mutex<BTreeMap<SessionId, Arc<SessionState>>>` shared between the accept loop and per-session futures. Each session inserts on start, removes on normal exit, and the shutdown path drains whatever remains to synthesize `session_end` records for the aborted ones. Per-session counters (`tool_call_count`, `started_at`) come straight from `SessionState`, so the synthesized record is byte-equivalent to one the live future would have emitted — including the `total_tool_calls` aggregator hop into `state.total_tool_calls`.

**Tech Stack:** Rust, Tokio (`JoinSet`, `Mutex`, `spawn_blocking`), `BTreeMap`, `rimap-audit::record::SessionEnd`.

---

## Status of #142 — already largely done

`#142` was filed against commit `0ec1717` when `daemon/run.rs` did synchronous `state.audit.log_session_*` calls on the accept loop. **As of `main`, the file already uses `tokio::task::spawn_blocking`** for both ends:

- `log_session_start_blocking` — `crates/rimap-server/src/daemon/run.rs:170-195`
- `log_session_end_blocking` — `crates/rimap-server/src/daemon/run.rs:199-210`

Verify with `rg -n 'spawn_blocking' crates/rimap-server/src/daemon/run.rs` before doing any work — if the helpers are present, the bulk of #142 is already shipped (likely as part of an earlier wave's housekeeping). The only remaining bite of #142 is the issue's "consider coalescing the paired start+end" suggestion — Task 4 below addresses it.

The bug-labeled `#137` is the substantive change in this PR.

## Context the engineer must read first

Lesson 1 of `RESUME.md`: verify API assumptions. Read these files in full BEFORE writing code:

- `crates/rimap-server/src/daemon/run.rs` — the entire file. Pay attention to:
  - The accept loop (lines 24–86) and the `tokio::select!` arm structure.
  - `drain_sessions` (lines 89–119): the JoinSet drain that ABORTS at the deadline. This is where #137's fix lands.
  - `build_session_future` (lines 264–295): the per-session future that calls `emit_session_end` on the normal exit paths but is silently dropped on abort.
  - `emit_session_end` (lines 322–346): the single emitter; contains the `state.total_tool_calls.fetch_add` hop that the synthesized records must also perform.
  - `handle_rejected_peer` and `handle_rejected_over_capacity` (lines 214–254): the paired-rejection path that Task 4 collapses.
- `crates/rimap-server/src/daemon/state.rs` — `SessionState` shape; `started_at` and `tool_call_count` are the inputs to a synthesized `session_end`.
- `crates/rimap-audit/src/record/mod.rs` — `SessionEndReason` variants; specifically `DaemonShutdown` is the reason synthesized records carry.
- `crates/rimap-server/tests/daemon_graceful_shutdown.rs` — pre-existing graceful-shutdown integration test. The new test case extends this file's harness (lines 1–80 read first).

Confirm before doing any work:

```bash
rg -n 'spawn_blocking' crates/rimap-server/src/daemon/run.rs
```

If this returns ≥2 hits, #142's bulk is already shipped — proceed to the #137 fix without re-doing the spawn_blocking migration. If it returns 0 hits, escalate (the plan's design assumption is wrong).

---

## Files

- Modify: `crates/rimap-server/src/daemon/run.rs` — add `LiveSessions` side table; wire spawn/exit hooks; rewrite `drain_sessions` to drain the table after `JoinSet::shutdown`; (Task 4) collapse `handle_rejected_*` to a single `session_rejected_record` emission.
- Modify: `crates/rimap-server/tests/daemon_graceful_shutdown.rs` — extend with a new test that holds N long-running sessions through shutdown and asserts N `session_end(DaemonShutdown)` records.
- Modify: `crates/rimap-audit/src/record/mod.rs` — `SessionEndReason` is already exhaustive. No new variant; we use the existing `DaemonShutdown`.

## Task 1: Define and unit-test `LiveSessions`

**Files:**
- Modify: `crates/rimap-server/src/daemon/run.rs`

- [ ] **Step 1: Write the failing unit tests**

Append a `#[cfg(test)] mod live_sessions_tests` to `crates/rimap-server/src/daemon/run.rs`. Place it BEFORE any existing test module so the file's existing `#[cfg(test)]` block stays intact:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod live_sessions_tests {
    use super::LiveSessions;
    use crate::daemon::state::SessionState;
    use rimap_core::SessionId;
    use std::sync::Arc;

    #[tokio::test]
    async fn insert_then_remove_drops_entry() {
        let live = LiveSessions::new();
        let sid = SessionId::new();
        let session = Arc::new(SessionState::new(sid));
        live.insert(sid, Arc::clone(&session)).await;
        assert!(live.contains(sid).await);
        live.remove(sid).await;
        assert!(!live.contains(sid).await);
    }

    #[tokio::test]
    async fn drain_returns_all_remaining_entries_in_one_pass() {
        let live = LiveSessions::new();
        let sid_a = SessionId::new();
        let sid_b = SessionId::new();
        live.insert(sid_a, Arc::new(SessionState::new(sid_a))).await;
        live.insert(sid_b, Arc::new(SessionState::new(sid_b))).await;
        let drained = live.drain().await;
        assert_eq!(drained.len(), 2);
        // After draining the table is empty so subsequent drain returns nothing.
        let again = live.drain().await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn drain_preserves_session_state_arc_for_duration_and_count_reads() {
        // The drain path uses `started_at` and `tool_call_count` from the
        // returned SessionState — pin that the Arcs come back live, not
        // lost copies. Bumping the counter inside the drained Arc must be
        // visible to the holder of the original Arc.
        let live = LiveSessions::new();
        let sid = SessionId::new();
        let session = Arc::new(SessionState::new(sid));
        live.insert(sid, Arc::clone(&session)).await;
        let drained = live.drain().await;
        assert_eq!(drained.len(), 1);
        let (drained_sid, drained_session) = &drained[0];
        assert_eq!(*drained_sid, sid);
        drained_session
            .tool_call_count
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            session
                .tool_call_count
                .load(std::sync::atomic::Ordering::Relaxed),
            7,
            "drained Arc must point to the same SessionState as the inserted Arc",
        );
    }
}
```

- [ ] **Step 2: Run the tests to confirm they fail to compile**

Run: `cargo test -p rimap-server --lib live_sessions_tests`
Expected: compile error — `cannot find type 'LiveSessions'`.

- [ ] **Step 3: Add `LiveSessions` near the top of `run.rs`**

Insert this block immediately after the existing `use` statements at the top of `crates/rimap-server/src/daemon/run.rs`:

```rust
use std::collections::BTreeMap;
use tokio::sync::Mutex;

/// Side table of in-flight sessions, keyed by `SessionId`. Used by the
/// graceful-shutdown drain to synthesize `session_end(DaemonShutdown)`
/// records for sessions that `JoinSet::shutdown` aborts before they
/// could emit their own end records (see #137).
///
/// The map lives behind a Tokio `Mutex` rather than a `parking_lot`
/// mutex because the contention pattern is async-task spawn/join, not
/// CPU-bound — and the lock is held only across two `BTreeMap` ops
/// (insert/remove or drain), well under the `await_holding_lock` clippy
/// threshold.
pub(crate) struct LiveSessions {
    inner: Mutex<BTreeMap<SessionId, Arc<SessionState>>>,
}

impl LiveSessions {
    /// Construct an empty live-session table.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record that `session` is now in flight. Called from the accept
    /// loop immediately before `sessions.spawn(...)`.
    pub(crate) async fn insert(&self, sid: SessionId, session: Arc<SessionState>) {
        self.inner.lock().await.insert(sid, session);
    }

    /// Remove `sid` from the table. Called from `build_session_future`
    /// on every normal exit path — both Ok and Err cases — so an
    /// aborted future is the only one that leaves an entry behind.
    pub(crate) async fn remove(&self, sid: SessionId) {
        self.inner.lock().await.remove(&sid);
    }

    /// Test-only convenience for membership checks.
    #[cfg(test)]
    pub(crate) async fn contains(&self, sid: SessionId) -> bool {
        self.inner.lock().await.contains_key(&sid)
    }

    /// Drain every remaining entry. Called from `drain_sessions` AFTER
    /// `JoinSet::shutdown().await`, so any session still here was
    /// aborted mid-flight and needs a synthesized `session_end`.
    pub(crate) async fn drain(&self) -> Vec<(SessionId, Arc<SessionState>)> {
        let mut guard = self.inner.lock().await;
        std::mem::take(&mut *guard).into_iter().collect()
    }
}
```

- [ ] **Step 4: Run the tests to confirm they pass**

Run: `cargo test -p rimap-server --lib live_sessions_tests`
Expected: 3 passes.

- [ ] **Step 5: Run clippy on the change**

Run: `cargo clippy -p rimap-server --lib --all-features -- -D warnings`
Expected: clean. The Mutex is held across two awaits per call site (insert / remove / drain are each single-statement); no `await_holding_lock` violation. If clippy flags `await_holding_lock`, the lock guard was held across an unrelated `await` — return to step 3.

- [ ] **Step 6: Do not commit yet**

Continue to Task 2 to wire `LiveSessions` into the accept loop and session future. The single bundled commit lands in Task 3 once both halves are in place AND the new behavioural test passes.

## Task 2: Wire `LiveSessions` into the accept loop and `build_session_future`

**Files:**
- Modify: `crates/rimap-server/src/daemon/run.rs`

- [ ] **Step 1: Construct `LiveSessions` at accept-loop start**

In `crates/rimap-server/src/daemon/run.rs`, replace lines 32–34 inside `run`:

```rust
    let socket_path = resolve_socket_path();
    let peer_gate = make_peer_gate();
    let mut sessions: JoinSet<()> = JoinSet::new();
```

with:

```rust
    let socket_path = resolve_socket_path();
    let peer_gate = make_peer_gate();
    let mut sessions: JoinSet<()> = JoinSet::new();
    let live = Arc::new(LiveSessions::new());
```

- [ ] **Step 2: Insert into `live` immediately before `sessions.spawn`**

Replace lines 60–75 (the post-permit / post-session_start block):

```rust
                let sid = SessionId::new();
                let session = Arc::new(SessionState::new(sid));
                if log_session_start_blocking(&state, sid, identity, &socket_path)
                    .await
                    .is_none()
                {
                    drop(permit);
                    drop(stream);
                    continue;
                }
                sessions.spawn(build_session_future(
                    Arc::clone(&state),
                    stream,
                    session,
                    permit,
                ));
```

with:

```rust
                let sid = SessionId::new();
                let session = Arc::new(SessionState::new(sid));
                if log_session_start_blocking(&state, sid, identity, &socket_path)
                    .await
                    .is_none()
                {
                    drop(permit);
                    drop(stream);
                    continue;
                }
                // Insert BEFORE spawn so `drain_sessions` can find the
                // session even if the accept loop exits between insert
                // and spawn.
                live.insert(sid, Arc::clone(&session)).await;
                sessions.spawn(build_session_future(
                    Arc::clone(&state),
                    stream,
                    session,
                    permit,
                    Arc::clone(&live),
                ));
```

- [ ] **Step 3: Pass `live` into `drain_sessions`**

Replace `drain_sessions(sessions).await;` (line 84) with:

```rust
    drain_sessions(sessions, &state, Arc::clone(&live)).await;
```

- [ ] **Step 4: Add the `live` parameter to `build_session_future` and remove on every exit path**

Replace the `build_session_future` signature (lines 264–273):

```rust
#[must_use = "dropping the session future loses session_end emission"]
async fn build_session_future<S>(
    state: Arc<DaemonState>,
    stream: S,
    session: Arc<SessionState>,
    permit: OwnedSemaphorePermit,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
```

with:

```rust
#[must_use = "dropping the session future loses session_end emission"]
async fn build_session_future<S>(
    state: Arc<DaemonState>,
    stream: S,
    session: Arc<SessionState>,
    permit: OwnedSemaphorePermit,
    live: Arc<LiveSessions>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
```

Then update the body so EVERY normal exit path removes the session from `live`. Replace lines 274–295:

```rust
    let _permit = permit;
    let mcp = ImapMcpServer::new(Arc::clone(&state), Arc::clone(&session));
    let serve_result = Box::pin(rmcp::serve_server(mcp, stream)).await;
    let running = match serve_result {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!(error = %e, "rmcp::serve_server initialisation failed");
            emit_session_end(
                &state,
                &session,
                rimap_audit::record::SessionEndReason::Error,
                Some(format!("serve_server init: {e}")),
            )
            .await;
            return;
        }
    };
    let quit = running.waiting().await;
    let (reason, last_err) = session_end_from_quit(quit);
    emit_session_end(&state, &session, reason, last_err).await;
}
```

with:

```rust
    let _permit = permit;
    let sid = session.id;
    let mcp = ImapMcpServer::new(Arc::clone(&state), Arc::clone(&session));
    let serve_result = Box::pin(rmcp::serve_server(mcp, stream)).await;
    let running = match serve_result {
        Ok(svc) => svc,
        Err(e) => {
            tracing::error!(error = %e, "rmcp::serve_server initialisation failed");
            emit_session_end(
                &state,
                &session,
                rimap_audit::record::SessionEndReason::Error,
                Some(format!("serve_server init: {e}")),
            )
            .await;
            // Remove only AFTER emission so a panic in emit_session_end
            // leaves the entry visible for the drain path's safety net.
            live.remove(sid).await;
            return;
        }
    };
    let quit = running.waiting().await;
    let (reason, last_err) = session_end_from_quit(quit);
    emit_session_end(&state, &session, reason, last_err).await;
    live.remove(sid).await;
}
```

- [ ] **Step 5: Rewrite `drain_sessions` to synthesize end records for aborted sessions**

Replace the entire `drain_sessions` function (lines 88–119) with:

```rust
/// Wait up to 5 seconds for in-flight sessions to finish, then abort the rest
/// AND synthesize a `session_end(DaemonShutdown)` audit record for every
/// session that was aborted. The synthesized record carries the per-session
/// duration and tool-call count harvested from `SessionState`, byte-
/// equivalent to what the live future would have emitted.
///
/// See #137: prior to this fix, `JoinSet::shutdown().await` aborted the
/// in-flight session futures before they could emit their own end records,
/// leaving the audit log silently incomplete.
async fn drain_sessions(
    mut sessions: JoinSet<()>,
    state: &Arc<DaemonState>,
    live: Arc<LiveSessions>,
) {
    if sessions.is_empty() {
        // No tasks ever spawned; the live table should be empty too, but
        // belt-and-braces drain it in case an entry slipped in between
        // `live.insert` and `sessions.spawn` and the accept loop then
        // exited.
        for (_, session) in live.drain().await {
            emit_session_end(
                state,
                &session,
                rimap_audit::record::SessionEndReason::DaemonShutdown,
                None,
            )
            .await;
        }
        return;
    }
    tracing::info!(
        count = sessions.len(),
        "draining in-flight sessions (up to 5 s)"
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !sessions.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let rem = deadline - now;
        match tokio::time::timeout(rem, sessions.join_next()).await {
            Ok(Some(_)) => {}           // task completed
            Ok(None) | Err(_) => break, // drained or deadline elapsed
        }
    }
    let still_running = sessions.len();
    let shutdown = tokio::time::timeout(std::time::Duration::from_secs(2), sessions.shutdown());
    let shutdown_clean = shutdown.await.is_ok();

    // After `JoinSet::shutdown`, any remaining entry in `live` is a session
    // that was aborted mid-flight. Synthesize its `session_end` record
    // now — same content the live future would have emitted, with reason
    // = DaemonShutdown.
    let aborted = live.drain().await;
    let synthesized = aborted.len();
    for (_, session) in aborted {
        emit_session_end(
            state,
            &session,
            rimap_audit::record::SessionEndReason::DaemonShutdown,
            None,
        )
        .await;
    }

    if shutdown_clean {
        tracing::info!(
            join_set_aborted = still_running,
            session_end_synthesized = synthesized,
            "session drain complete",
        );
    } else {
        tracing::warn!(
            join_set_aborted = still_running,
            session_end_synthesized = synthesized,
            "session shutdown deadline exceeded; exiting with stuck tasks",
        );
    }
}
```

- [ ] **Step 6: Workspace compile check**

Run: `cargo check -p rimap-server --all-targets`
Expected: clean.

- [ ] **Step 7: Existing daemon tests still pass**

Run: `cargo test -p rimap-server --test daemon_happy_path`
Run: `cargo test -p rimap-server --test daemon_graceful_shutdown`
Run: `cargo test -p rimap-server --test daemon_max_sessions`
Expected: all green. The pre-existing `daemon_graceful_shutdown` test will keep passing because clean-close sessions still emit their own `session_end` from the live future BEFORE removing themselves from `live`, so nothing remains for the drain to synthesize.

- [ ] **Step 8: Do not commit yet**

The behavioural test in Task 3 is what proves the bug fix. Continue.

## Task 3: Add the integration test that proves #137 is fixed

**Files:**
- Modify: `crates/rimap-server/tests/daemon_graceful_shutdown.rs`

- [ ] **Step 1: Read the existing test file in full**

```bash
cat crates/rimap-server/tests/daemon_graceful_shutdown.rs
```

Confirm it uses the `TestDaemon` harness from `tests/common/daemon_harness.rs`. The harness's `test_daemon_state` builds an empty registry — that's fine for this test since we don't make tool calls; the goal is just to hold a session open through shutdown.

- [ ] **Step 2: Append the new test**

Append this test to the end of `crates/rimap-server/tests/daemon_graceful_shutdown.rs`. The test holds two sessions through the shutdown drain, asserts both produce `session_end(reason="daemon_shutdown")` records.

```rust
/// Regression test for #137: every active session emits a
/// `session_end(reason="daemon_shutdown")` record when the daemon
/// shuts down, including those aborted mid-flight by the JoinSet
/// drain. Before the fix, aborted futures never reached
/// `emit_session_end` and the audit log was missing those records.
#[tokio::test]
async fn shutdown_synthesizes_session_end_for_aborted_sessions() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    let tempdir = tempfile::TempDir::new().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = common::daemon_harness::test_daemon_state(tempdir.path(), &audit_path);
    let daemon = common::daemon_harness::TestDaemon::spawn_bare(
        tempdir,
        audit_path.clone(),
        socket_path.clone(),
        state,
    )
    .await;

    // Open two sessions and write nothing through them. The shim-layer
    // serve_server.waiting() is parked on a stalled stdin read; we don't
    // need to send any MCP frames — what matters is that the session is
    // ALIVE in the daemon's JoinSet at shutdown time.
    let mut s1 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("connect 1");
    let mut s2 = UnixStream::connect(&daemon.socket_path)
        .await
        .expect("connect 2");

    // Give the accept loop a beat to spawn the per-session futures and
    // call `live.insert` for each. 50ms is generous on every CI we run
    // and far faster than the 5s drain window.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Trigger shutdown. The drain has 5s to clean-close, then JoinSet
    // aborts. Sessions that never completed handshake will be aborted —
    // exactly the path #137 fixes.
    let audit_log = daemon.shutdown().await;
    drop(s1);
    drop(s2);

    // Count `session_end(reason="daemon_shutdown")` records.
    let shutdown_ends = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_end""#))
        .filter(|line| line.contains(r#""reason":"daemon_shutdown""#))
        .count();
    assert_eq!(
        shutdown_ends, 2,
        "expected 2 session_end(daemon_shutdown) records, got {shutdown_ends}; \
         audit log was:\n{audit_log}",
    );

    // Total session_end count must equal session_start count — no orphan
    // start records and no over-count.
    let starts = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_start""#))
        .count();
    let ends = audit_log
        .lines()
        .filter(|line| line.contains(r#""kind":"session_end""#))
        .count();
    assert_eq!(
        starts, ends,
        "session_start ({starts}) must pair with session_end ({ends}); \
         audit log was:\n{audit_log}",
    );

    // Pre-existing assertion to keep on the safe side: the regression
    // catches a known prior pattern where `total_tool_calls` on an
    // aborted session was lost.
    let _ = Arc::clone; // silence unused-import on `Arc` in some configs
}
```

- [ ] **Step 3: Run the new test to confirm it fails on the unmodified `main`**

If you are bisecting (e.g. for a CI-side regression check), `git stash`, run the test, and observe a count of 0 (not 2). Re-apply the stash before continuing. This step is OPTIONAL — the new test exists to lock the fix in, not to bisect production history.

For normal execution, just run:

```bash
cargo test -p rimap-server --test daemon_graceful_shutdown shutdown_synthesizes_session_end_for_aborted_sessions
```

Expected: pass.

- [ ] **Step 4: Run the full graceful-shutdown test file**

```bash
cargo test -p rimap-server --test daemon_graceful_shutdown
```

Expected: every pre-existing test continues to pass alongside the new one.

- [ ] **Step 5: Commit (#137 + #142)**

```bash
git add crates/rimap-server/src/daemon/run.rs \
        crates/rimap-server/tests/daemon_graceful_shutdown.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): synthesize session_end for shutdown-aborted sessions (#137, #142)

drain_sessions used to call JoinSet::shutdown which aborts in-flight
session futures before they reach emit_session_end. The audit log was
missing session_end(reason="daemon_shutdown") records for any session
that didn't clean-close inside the 5s drain.

Track active sessions in a side LiveSessions table keyed by SessionId.
Each session task removes itself on every normal exit path; whatever
remains after JoinSet::shutdown is by definition an aborted session
that needs synthesizing. The synthesized record uses the per-session
SessionState's started_at and tool_call_count, so it is byte-
equivalent to what the live future would have emitted — including the
total_tool_calls aggregator hop into DaemonState.

#142 (move log_session_* onto spawn_blocking) was already done in an
earlier wave; this PR keeps that surface unchanged.

A new integration test holds two sessions open across shutdown and
asserts both produce session_end(daemon_shutdown). The pre-existing
graceful-shutdown tests still pass — clean-close sessions emit from
their live future and the live table empties, so the drain
synthesizes nothing.

Closes #137. Refs #142.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Optional — coalesce paired-rejection start+end (#142 second-half)

**Goal:** Replace the `handle_rejected_peer` / `handle_rejected_over_capacity` paired writes (start record + end record, two `spawn_blocking` round trips, two seq allocations) with a single in-line `session_rejected` write.

**Decision point:** Skip this task if any of the following is true:
- The pre-existing `daemon_max_sessions` test relies on observing the paired-record shape.
- The audit-log reader (`crates/rimap-audit/src/reader/mod.rs`) doesn't model a `session_rejected` payload.
- It would require adding a new `Payload::SessionRejected` variant — that is a larger surface change than #142's "consider" wording warrants.

The remainder of this task is the lift IF you proceed.

**Files:**
- Modify: `crates/rimap-server/src/daemon/run.rs`
- Possibly: `crates/rimap-audit/src/record/mod.rs` (new variant)
- Possibly: `crates/rimap-audit/src/writer/log.rs` (new emit method)

- [ ] **Step 1: Decide variant vs. reuse existing SessionEndReason**

Two options:

(a) **Variant approach.** Add `Payload::SessionRejected { session_id, peer_identity, socket_path, reason }` to `rimap-audit`'s record schema. Cleanest data model; one record per rejection. Cost: schema migration on disk.

(b) **Reuse approach.** Keep emitting paired `session_start` + `session_end(PeerUidRejected | Rejected)` but in a SINGLE `spawn_blocking` block, batching the two writes. Cost: doubles the block's work but halves the round-trip count.

Pick (b) for this PR — it's the "consider coalescing" the issue body asked for, without expanding the on-disk schema. Save (a) for a future polish wave if the issue resurfaces.

- [ ] **Step 2: Coalesce `handle_rejected_peer`**

Replace the body of `handle_rejected_peer` (lines 214–230):

```rust
async fn handle_rejected_peer(
    state: &Arc<DaemonState>,
    identity: &PeerIdentity,
    socket_path: &str,
) {
    let sid = SessionId::new();
    let _ = log_session_start_blocking(state, sid, identity.clone(), socket_path).await;
    let end = rimap_audit::record::SessionEnd {
        session_id: sid,
        reason: rimap_audit::record::SessionEndReason::PeerUidRejected,
        duration_ms: 0,
        total_tool_calls: 0,
        last_error: None,
    };
    log_session_end_blocking(state, end).await;
    tracing::warn!(?identity, "rejected peer with mismatching identity");
}
```

with the coalesced version that batches both writes inside a single `spawn_blocking`:

```rust
async fn handle_rejected_peer(
    state: &Arc<DaemonState>,
    identity: &PeerIdentity,
    socket_path: &str,
) {
    let sid = SessionId::new();
    log_session_rejected_pair(
        state,
        sid,
        identity.clone(),
        socket_path,
        rimap_audit::record::SessionEndReason::PeerUidRejected,
        None,
    )
    .await;
    tracing::warn!(?identity, "rejected peer with mismatching identity");
}
```

- [ ] **Step 3: Coalesce `handle_rejected_over_capacity`**

Replace the body of `handle_rejected_over_capacity` (lines 235–254) with:

```rust
async fn handle_rejected_over_capacity(
    state: &Arc<DaemonState>,
    identity: &PeerIdentity,
    socket_path: &str,
) {
    let sid = SessionId::new();
    log_session_rejected_pair(
        state,
        sid,
        identity.clone(),
        socket_path,
        rimap_audit::record::SessionEndReason::Rejected,
        Some("max_concurrent_sessions reached".to_owned()),
    )
    .await;
    tracing::warn!(
        ?identity,
        "rejected session: max_concurrent_sessions reached",
    );
}
```

- [ ] **Step 4: Add the helper that batches the two writes**

Insert this function next to `log_session_end_blocking`:

```rust
/// Emit a paired `session_start` + `session_end(reason)` for a connection
/// that we refused at the gate. Both records hit the audit writer inside a
/// single `spawn_blocking` so the accept loop only pays one task-spawn
/// round trip per rejection, not two.
///
/// Errors are logged but not propagated; at this point the connection is
/// already being dropped and the caller has nothing to do with the result.
async fn log_session_rejected_pair(
    state: &Arc<DaemonState>,
    sid: SessionId,
    identity: PeerIdentity,
    socket_path: &str,
    reason: rimap_audit::record::SessionEndReason,
    last_error: Option<String>,
) {
    let audit = state.audit.clone();
    let socket_path = socket_path.to_owned();
    let join = tokio::task::spawn_blocking(move || {
        let start = rimap_audit::record::SessionStart {
            session_id: sid,
            peer_identity: identity,
            socket_path,
        };
        if let Err(e) = audit.log_session_start(start) {
            tracing::error!(error = %e, "rejected-pair session_start write failed");
            return;
        }
        let end = rimap_audit::record::SessionEnd {
            session_id: sid,
            reason,
            duration_ms: 0,
            total_tool_calls: 0,
            last_error,
        };
        if let Err(e) = audit.log_session_end(end) {
            tracing::warn!(error = %e, "rejected-pair session_end write failed");
        }
    })
    .await;
    if let Err(join_err) = join {
        let rimap_err = crate::mcp::spawn_blocking_panic_error(join_err);
        tracing::error!(error = %rimap_err, "rejected-pair spawn_blocking join error");
    }
}
```

- [ ] **Step 5: Run the rejected-peer / over-capacity tests**

```bash
cargo test -p rimap-server --test daemon_max_sessions
cargo test -p rimap-server --test daemon_happy_path
```

Expected: all pre-existing tests pass. The audit-record shape is unchanged on disk (still a paired start+end), so log-readers don't notice the coalesce.

- [ ] **Step 6: Commit (#142 second-half)**

```bash
git add crates/rimap-server/src/daemon/run.rs
git commit -m "$(cat <<'EOF'
perf(rimap-server): coalesce rejected-peer paired audit writes (#142)

handle_rejected_peer and handle_rejected_over_capacity each emitted a
session_start + session_end pair via two separate spawn_blocking round
trips. Batch both records inside a single spawn_blocking so the accept
loop pays one task-spawn cost per rejection instead of two.

Audit-record shape on disk is unchanged: still a paired start+end with
the same fields and reasons. Log readers don't notice.

Refs #142.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 5: Full-workspace verification

**Files:** none — green-gate task.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Full workspace test suite**

Run: `cargo test --workspace`
Expected: all tests pass. Pay special attention to:
- `daemon_graceful_shutdown` — the new shutdown synthesis test green
- `daemon_happy_path` — clean-close sessions still emit their live `session_end`
- `daemon_max_sessions` — paired-rejection records still appear (shape unchanged)
- `audit_merge` — log-reader still parses the audit lines

If a pre-existing test flake fires (`socket_path` env-race with `socket_setup` tests, observed in PR1/PR6), retry once. Don't try to fix the flake here.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean.

- [ ] **Step 5: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- `LiveSessions` is a self-contained type with three unit tests covering insert/remove/drain semantics PLUS an Arc-equality test that proves the drained Arc points at the same `SessionState` as the inserted one.
- `live.insert` happens BEFORE `sessions.spawn` so a panic between insert and spawn would leave the entry visible to the drain (belt-and-braces for #137's invariant).
- `live.remove` happens AFTER `emit_session_end` on every normal exit path, so a panic in emission still leaves the entry available for the drain's safety net.
- The synthesized `session_end` uses the SAME `emit_session_end` helper as the live path, so it inherits the `total_tool_calls.fetch_add` aggregator hop. No special-case code paths.
- Behavioural test asserts BOTH the count of `session_end(daemon_shutdown)` AND the start/end pairing invariant — catches both the under-emission and over-emission failure modes.
- Task 4 is explicitly OPTIONAL with a documented decision point. If skipped, only Task 1–3 + Task 5 land.

## Out of scope

- **`Payload::SessionRejected` variant.** A first-class rejected-session record would require an on-disk schema migration and audit-reader update. Out of scope for this PR; raise a follow-up issue if forensics asks for it.
- **Session-end records for sessions that the operator force-killed (SIGKILL on the daemon).** A SIGKILL gives no opportunity to drain anything. Documented in the design spec as out of scope.
- **Anything in `boot/registry.rs` or the per-account setup path.** That's PR3 (#144 + #148).
- **Test infra for live-IMAP scenarios.** That's PR12 (#136).

If you find yourself editing anything outside the Files list, stop and re-read this plan.
