# Issue #188 — macOS daemon integration test fix (design)

**Date:** 2026-05-01
**Branch:** `fix/issue-188-macos-daemon-tests`
**Issue:** [#188](https://github.com/randomparity/rusty-imap-mcp/issues/188)
**Severity:** LOW (no production impact; macOS-local CI signal only)

## Goal

Identify the macOS-specific cause of audit silence in two daemon integration
tests, land the fix, and remove the `#[cfg_attr(target_os = "macos", ignore =
...)]` annotations they currently carry.

Affected tests:

- `rimap-server::daemon_happy_path::client_connects_and_sees_clean_session_lifecycle`
- `rimap-server::daemon_max_sessions::daemon_releases_permit_on_session_end`

Both panic the same way on macOS:

```
wait_for_audit timed out after 2s; last audit contents:
```

The audit file is empty — not even `session_start` lands.

## Background

PR #189 (`fix/macos-test-flakes`, commit `c34266c`) annotated both tests with
`#[cfg_attr(target_os = "macos", ignore)]` as a workaround so Linux CI stays
green. Issue #188 tracks the root-cause work.

The suspected commit is `1b8a0c4` ("desloppify: replace fixed test sleeps with
audit-log polling"), which rewrote the synchronization in these tests from
`tokio::time::sleep` to predicate-based audit-file polling. The previous
fixed-sleep form may have happened to mask the issue on macOS by waiting long
enough; or the change exposed a real race that sleep had been hiding.

## Two relevant data points

1. `daemon_rejects_session_past_limit` **passes** on macOS. That test connects
   conn1, then explicitly waits for `session_start` to land **before** doing
   anything else. So the daemon does emit `session_start` on macOS — *if* the
   peer is still alive when the daemon's accept loop reaches `peer_cred()`.
2. `daemon_spawns_and_shuts_down_cleanly` passes on macOS. So daemon
   spawn/shutdown plumbing works.

The two failing tests both do `connect → shutdown(write) → drop` on the client
**before** any wait for `session_start`. The strong prior is therefore: on
macOS, the daemon's accept-side syscalls (`accept` and/or `peer_cred`) race
against a peer that has fully closed the connection by the time the daemon
gets there. On Linux this race is benign; on macOS Tahoe (Darwin 25.x =
macOS 26.x), one of those syscalls returns an error and the loop logs `accept
failed` and continues without emitting any audit record.

## Approach

Two phases delivered as **one branch / one PR**.

### Phase 1 — Diagnosis

Capture evidence that names the exact syscall and error before designing the
fix.

#### 1A. Isolated kernel-behavior probe

A new unit test in `crates/rimap-server/src/daemon/transport/unix.rs`:

```rust
#[tokio::test]
async fn accept_and_peer_cred_handle_peer_that_disconnects_immediately() {
    // Bind a listener.
    // tokio::spawn a client that:
    //   - connects via UnixStream::connect
    //   - calls shutdown(SHUT_WR) via tokio's AsyncWriteExt::shutdown
    //   - drops the stream
    // Server task: listener.accept().await, then call peer_cred() on the stream.
    // Record the outcome via eprintln! — accept's Result kind, peer_cred's
    // Result kind, error.kind() if an error.
    //
    // The test does not assert "passes on Linux" or "fails on macOS" — it
    // captures observable kernel behavior so future readers know what the
    // platforms actually do. Phase 2 (after Phase 1's diagnostic run)
    // tightens assertions to whatever the platforms reliably do.
}
```

This test isolates the kernel question from MCP, audit, `spawn_blocking`, and
the rest of the daemon — so its outcome cleanly localizes the bug.

#### 1B. Tracing in the failing tests

Add a `tracing_subscriber::fmt().with_env_filter(...).with_test_writer().try_init()`
call at the top of both failing tests. `try_init()` is idempotent across the
test binary, so adding it twice is fine.

This stays in the test source after Phase 1 — it is zero-cost when `RUST_LOG`
is unset and gives future maintainers a way to flip on tracing without
modifying source.

#### 1C. Diagnostic run on Tahoe

Run on the local machine (Darwin 25.4.0 = macOS 26):

```bash
RUST_LOG=rimap_server=trace,rimap_audit=trace \
    cargo nextest run --package rimap-server \
        --test daemon_happy_path -- --nocapture \
        client_connects_and_sees_clean_session_lifecycle
```

Capture the trace output. Existing tracing in `crates/rimap-server/src/daemon/run.rs`
covers every error edge:

- `tracing::error!(error = %e, "accept failed")` — accept-side failure
- `tracing::warn!(?identity, "rejected peer with mismatching identity")` — gate failure
- `tracing::warn!(..., "rejected session: max_concurrent_sessions reached")` — permit
  exhaustion

If `accept failed` appears, we know the syscall layer is the cause and the
error kind tells us which one. If none of these warn/error lines appear and
`session_start` is still absent, the daemon is not reaching the accept loop
at all (different bug; see decision matrix).

#### 1D. Phase 1 deliverable

Append a paragraph to the implementation plan and a comment to issue #188
naming the root cause: which line, which syscall, which error kind.

### Phase 2 — Fix

Driven by Phase 1 via the decision matrix below.

#### Decision matrix

| Phase 1 finding | Phase 2 action |
|---|---|
| `peer_cred()` errors on already-EOF'd peer (most likely on macOS) | Test-side fix: insert `wait_for_audit(session_start)` barrier between client `connect` and `shutdown+drop` in both failing tests. |
| `accept()` itself errors / never returns when peer EOFs before accept | Same test-side fix — the wait barrier sidesteps the race regardless of which syscall is at fault. |
| Audit `BufWriter` flush delayed on macOS (hypothesis 3 in issue) | Out of scope per the "test-side fix only" decision. The plan pauses; only the diagnosis commits land; a separate plan addresses it. (Already partially ruled out by `daemon_rejects_session_past_limit` passing.) |
| `spawn_blocking` starved on macOS tokio runtime (hypothesis 1 in issue) | Out of scope. Plan pauses. (Issue notes multi_thread didn't help, so probably not this.) |
| `peer_gate` UID mismatch (UID surprise) | Different bug. Plan pauses. |
| Anything else | Plan pauses; re-spec. |

#### Most-likely fix (top two rows)

In `crates/rimap-server/tests/daemon_happy_path.rs::client_connects_and_sees_clean_session_lifecycle`:

```rust
let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

// Wait for session_start to land before closing the client. macOS races
// the daemon's peer_cred() (or accept()) against an already-EOF'd peer;
// see issue #188. The passing daemon_rejects_session_past_limit already
// uses this pattern.
daemon
    .wait_for_audit(Duration::from_secs(2), |c| {
        count_audit_kind(c, "session_start") >= 1
    })
    .await;

stream.shutdown().await.expect("shutdown client write half");
drop(stream);

// existing wait for session_end + existing assertions
```

In `crates/rimap-server/tests/daemon_max_sessions.rs::daemon_releases_permit_on_session_end`:

```rust
// Round 1
let mut c = UnixStream::connect(&socket_path).await.expect("connect 1");
wait_for_audit_at(&audit_path, Duration::from_secs(2), |s| {
    count_audit_kind(s, "session_start") >= 1
})
.await;
c.shutdown().await.expect("shutdown 1");
drop(c);
wait_for_audit_at(&audit_path, Duration::from_secs(2), |s| {
    count_audit_kind(s, "session_end") >= 1
})
.await;

// Round 2 — same shape, with `>= 2` thresholds.
```

Both tests have their `#[cfg_attr(target_os = "macos", ignore = ...)]`
annotations removed.

#### Documentation

Add a comment near `wait_for_audit_at` in
`crates/rimap-server/tests/common/daemon_harness.rs` explaining the macOS
race and the wait-for-session_start pattern, so future tests do not
reintroduce it.

## Acceptance criteria

- Both failing tests pass on macOS locally (`cargo nextest run --package
  rimap-server`) and in CI.
- Both `#[cfg_attr(target_os = "macos", ignore = ...)]` annotations are
  removed.
- The new `accept_and_peer_cred_handle_peer_that_disconnects_immediately`
  unit test is committed in `unix.rs`. Its assertions are tightened to
  whatever Phase 1 finds the platforms reliably do.
- `try_init` calls remain in both failing tests for future tracing-based
  triage.
- A comment in `daemon_harness.rs` documents the wait-for-session_start
  pattern.
- Issue #188 closed with a comment summarizing root cause + fix.

## Out of scope

- Production-side hardening for "real shim crashes mid-handshake." No
  current evidence that scenario occurs in practice. If it surfaces, a
  follow-up plan adds synthesized `session_start` + `session_end(reason =
  ...)` for accept-side failures and a new `SessionEndReason` variant. Not
  this PR.
- Linux behavior. The wait barrier is a no-op on a fast accept loop, so
  Linux runs are unaffected.
- The passing `daemon_rejects_session_past_limit` test. It already uses
  the wait-for-session_start pattern; no changes needed.

## Risks

- **Wrong root cause guessed.** Mitigated by Phase 1 capturing observable
  evidence before Phase 2 changes any production-adjacent behavior. If
  Phase 1 lands in any row of the decision matrix below the top two, the
  PR pauses for a re-spec.
- **Diagnostic only reproducible on macOS Tahoe.** Mitigated: this machine
  is Darwin 25.4.0 = macOS 26 (Tahoe), matching the bug report.
- **Future tests reintroduce the race.** Mitigated by the comment in
  `daemon_harness.rs` documenting the pattern.

## One-PR layout

All commits on `fix/issue-188-macos-daemon-tests`:

1. **Spec doc.** This file.
2. **Phase 1 instrumentation.** `try_init` in the two failing tests + new
   `accept_and_peer_cred_handle_peer_that_disconnects_immediately` probe
   test in `unix.rs`.
3. **Diagnostic findings.** Comment on issue #188 + paragraph appended to
   the plan recording what Phase 1 observed.
4. **Phase 2 fix.** wait-for-session_start barriers, `cfg_attr` removals,
   harness documentation comment, and tightened assertions on the probe
   test.
5. **Final.** Issue close reference.

**Branching condition.** Commits 4 and 5 only land if Phase 1 (commit 3)
lands in one of the top two rows of the decision matrix. If Phase 1 finds
any other cause, the PR stops at commit 3 with the diagnostic findings
documented; a follow-up spec/plan addresses whatever was found.

## Phase 1 findings (recorded 2026-05-01)

**Probe test outcome:** `issue #188 probe: accept Err on macos kind=NotConnected msg=Socket is not connected (os error 57)`.

**Daemon trace from `client_connects_and_sees_clean_session_lifecycle`:**

```
running 1 test
2026-05-01T17:39:27.060125Z ERROR rimap_server::daemon::run: accept failed error=Socket is not connected (os error 57)

thread 'client_connects_and_sees_clean_session_lifecycle' (8061218) panicked at crates/rimap-server/tests/common/daemon_harness.rs:178:9:
wait_for_audit timed out after 2s; last audit contents:
```

The only daemon-side log line emitted before the harness's 2s wait_for_audit
panic is the `accept failed` ERROR with `os error 57` (NotConnected). No
`rejected peer with mismatching identity` log, no
`max_concurrent_sessions reached` log, no `session_start` audit record.

**Daemon trace from `daemon_releases_permit_on_session_end`:**

```
running 1 test
2026-05-01T17:39:32.717404Z ERROR rimap_server::daemon::run: accept failed error=Socket is not connected (os error 57)

thread 'daemon_releases_permit_on_session_end' (8061455) panicked at crates/rimap-server/tests/common/daemon_harness.rs:178:9:
wait_for_audit timed out after 2s; last audit contents:
```

Identical signature: a single `accept failed` ERROR with `os error 57` and
the same harness panic. Consistent with Step 2.

**Root cause:** On macOS, `PlatformListener::accept` (in
`crates/rimap-server/src/daemon/transport/unix.rs`) wraps the kernel
`accept(2)` followed by a `peer_cred()` call. When the client end has
already fully closed the connection by the time the server's
`peer_cred()` runs on the freshly-accepted `UnixStream`, the macOS
kernel returns `ENOTCONN` (errno 57) — surfaced by Rust as
`io::ErrorKind::NotConnected` with message `"Socket is not connected
(os error 57)"`. The wrapper propagates this as `Err(io::Error)`. The
daemon's accept loop in `crates/rimap-server/src/daemon/run.rs:99`
logs it via `tracing::error!(error = %e, "accept failed")` and
`continue`s — the connection is dropped before
`log_session_start_blocking` runs, so no `session_start` audit record
is ever written, and the harness's `wait_for_audit` times out after 2 s.
The probe test in `unix.rs` reproduces exactly this kernel behavior in
isolation. This maps to decision matrix row 1.

**Decision matrix outcome:** Row 1 (peer_cred error on already-EOF'd peer) — proceeding to Phase 2 with test-side wait-for-session_start barrier.
