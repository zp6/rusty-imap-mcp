# Issue #188 — macOS daemon integration test fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the test-side fix for issue #188 (`session_start` never reaches audit log on macOS in two daemon integration tests) on a single PR, gated by a Phase 1 diagnostic that confirms the root cause.

**Architecture:** Two-phased on one branch (`fix/issue-188-macos-daemon-tests`). Phase 1 commits an isolated kernel-behavior probe test in `crates/rimap-server/src/daemon/transport/unix.rs` plus `tracing_subscriber::try_init` calls in the two failing tests, runs both on this Tahoe machine, and records observable evidence. Phase 2, contingent on Phase 1's findings via a decision matrix in the spec, applies a test-side wait-for-`session_start` barrier (mirroring the passing `daemon_rejects_session_past_limit`) and removes the `#[cfg_attr(target_os = "macos", ignore)]` annotations. Production code is out of scope.

**Tech Stack:** Rust 1.94 stable, Tokio (current_thread runtime in `#[tokio::test]`), `tokio::net::UnixListener` / `UnixStream`, `tracing-subscriber` 0.3 (env-filter + fmt features, already a workspace dep on `rimap-server`), `cargo nextest` 0.9.132 with `--run-ignored ignored-only` to bypass the existing macOS ignores during the diagnostic run.

**Spec:** [`docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md`](../specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md)

**Branch:** `fix/issue-188-macos-daemon-tests` (already created).

**Reproducibility:** This machine is Darwin 25.4.0 = macOS 26 (Tahoe), matching the bug report. All Phase 1 commands run locally.

---

## File map

| File | Action | Purpose |
|---|---|---|
| `crates/rimap-server/src/daemon/transport/unix.rs` | Modify (`tests` mod) | Add probe test that records `accept` + `peer_cred` outcome when peer is fully closed. |
| `crates/rimap-server/tests/daemon_happy_path.rs` | Modify | Add `tracing_subscriber::try_init` to `client_connects_and_sees_clean_session_lifecycle`. Phase 2: insert wait-for-`session_start` barrier; remove `cfg_attr`. |
| `crates/rimap-server/tests/daemon_max_sessions.rs` | Modify | Add `tracing_subscriber::try_init` to `daemon_releases_permit_on_session_end`. Phase 2: insert wait-for-`session_start` barriers (both rounds); remove `cfg_attr`. |
| `crates/rimap-server/tests/common/daemon_harness.rs` | Modify (Phase 2) | Add a comment near `wait_for_audit_at` documenting the macOS race and the wait-for-session_start pattern. |
| `docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md` | Modify (Phase 1 step 3) | Append "Phase 1 findings" section recording the observed root cause. |
| GitHub issue #188 | Comment (Phase 1 step 3) and Close (Task 7) | Communicate findings + final fix to readers. |

---

### Task 1: Phase 1 — Add isolated kernel-behavior probe test

**Files:**
- Modify: `crates/rimap-server/src/daemon/transport/unix.rs` (existing `tests` module starts at line 198)

- [ ] **Step 1: Add the probe test to the existing `tests` module**

Append the following test to the existing `mod tests` block in `crates/rimap-server/src/daemon/transport/unix.rs` (after the last existing test, before the closing `}` of the module):

```rust
    /// Issue #188 probe — record what `PlatformListener::accept()` (which
    /// wraps `UnixListener::accept` + `stream.peer_cred()`) does on each
    /// platform when the client has fully disconnected before the server
    /// reaches accept. The output is fact-recording (`eprintln!`) rather
    /// than a hard gate; Phase 2 of the fix tightens assertions to
    /// whatever the platforms reliably do.
    #[tokio::test]
    async fn accept_and_peer_cred_handle_peer_that_disconnects_immediately() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let mut listener = UnixSocketListener::bind(&path).await.unwrap();

        // Spawn a client that connects, shuts down its write half, and
        // drops the stream — i.e., fully disconnects. Wait for that task
        // to complete so the server-side accept() runs *after* the peer
        // has gone.
        let client_path = path.clone();
        let client = tokio::spawn(async move {
            let mut s = UnixStream::connect(&client_path).await.unwrap();
            s.shutdown().await.unwrap();
            drop(s);
        });
        client.await.unwrap();

        // Brief settle so the kernel has had a chance to flag the queued
        // connection as peer-closed, if it does so eagerly.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Wrap accept() in a timeout — if the kernel never delivers the
        // queued connection (or accept hangs), we still terminate.
        let outcome =
            tokio::time::timeout(std::time::Duration::from_secs(2), listener.accept()).await;

        match outcome {
            Ok(Ok(_accepted)) => {
                eprintln!(
                    "issue #188 probe: accept Ok (peer_cred succeeded) on {}",
                    std::env::consts::OS
                );
            }
            Ok(Err(e)) => {
                eprintln!(
                    "issue #188 probe: accept Err on {} kind={:?} msg={}",
                    std::env::consts::OS,
                    e.kind(),
                    e
                );
            }
            Err(_elapsed) => {
                eprintln!(
                    "issue #188 probe: accept did not return within 2 s on {}",
                    std::env::consts::OS
                );
            }
        }
    }
```

- [ ] **Step 2: Verify the test compiles and runs**

Run:

```bash
cargo nextest run --package rimap-server \
    --lib daemon::transport::unix::tests::accept_and_peer_cred_handle_peer_that_disconnects_immediately \
    -- --nocapture
```

Expected: PASS (the test never asserts; it only records). The `eprintln!` line must appear in the output. Note the recorded outcome — this is Phase 1's first datapoint.

If the build fails because `eprintln!` is forbidden, that's a workspace lint. The existing `tests` module is gated by `#[expect(clippy::unwrap_used, reason = "tests")]` and `#[expect(clippy::panic, reason = "tests")]`. If the lint also forbids `eprintln!` in tests, replace `eprintln!` with `println!` (the test module's parent `unix.rs` does not deny `print_stdout` for tests in the workspace lint table — verify by running clippy in step 3 — and if it does, switch to `tracing::info!` and run with `RUST_LOG=info`). Verified by inspection: `print_stdout = "deny"` is in the workspace lint table, but the `tests` module already uses constructs that would otherwise trigger denies (it uses `#[expect]` allowlists), so adding a localized `#[expect(clippy::print_stderr, reason = "issue #188 diagnostic probe")]` on the test function itself is the compatible escape hatch if needed.

- [ ] **Step 3: Run clippy on the modified crate to catch any lint issues**

Run:

```bash
cargo clippy --package rimap-server --all-targets -- -D warnings
```

Expected: PASS. If clippy denies `print_stderr` on the new test, add this attribute on the test function:

```rust
    #[expect(clippy::print_stderr, reason = "issue #188 diagnostic probe — fact-recording test")]
```

Then re-run clippy.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/daemon/transport/unix.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): add issue #188 probe for accept+peer_cred on closed peer

Records what PlatformListener::accept (UnixListener::accept + peer_cred)
does on each platform when the client has fully disconnected before the
server reaches accept. Fact-recording via eprintln!; Phase 2 of the fix
tightens assertions once we have evidence from Phase 1.

Refs: #188

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Expected: pre-commit hooks (clippy, fmt, typos) all pass; commit lands on `fix/issue-188-macos-daemon-tests`.

---

### Task 2: Phase 1 — Add `tracing_subscriber::try_init` to the two failing tests

**Files:**
- Modify: `crates/rimap-server/tests/daemon_happy_path.rs:46` (test body of `client_connects_and_sees_clean_session_lifecycle`)
- Modify: `crates/rimap-server/tests/daemon_max_sessions.rs:139` (test body of `daemon_releases_permit_on_session_end`)

Both tests already carry `#[cfg_attr(target_os = "macos", ignore = "...")]`. We do **not** remove the ignores in this task — Task 5 does that. For the diagnostic run in Task 3, we bypass the ignore with `--run-ignored ignored-only`.

- [ ] **Step 1: Add `try_init` to `client_connects_and_sees_clean_session_lifecycle`**

In `crates/rimap-server/tests/daemon_happy_path.rs`, find the test function body (currently starts at line 46). Insert this block at the very top of the function body, before any other code:

```rust
    // Idempotent across the test binary; zero-cost when RUST_LOG is unset.
    // Set RUST_LOG=rimap_server=trace,rimap_audit=trace and pass --nocapture
    // to surface daemon-side activity. See issue #188 for the diagnostic
    // procedure.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
```

- [ ] **Step 2: Add `try_init` to `daemon_releases_permit_on_session_end`**

In `crates/rimap-server/tests/daemon_max_sessions.rs`, find the test function body (currently starts at line 139). Insert the **same** block at the very top of the function body:

```rust
    // Idempotent across the test binary; zero-cost when RUST_LOG is unset.
    // Set RUST_LOG=rimap_server=trace,rimap_audit=trace and pass --nocapture
    // to surface daemon-side activity. See issue #188 for the diagnostic
    // procedure.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();
```

- [ ] **Step 3: Verify the two tests compile**

Run:

```bash
cargo nextest run --package rimap-server --tests --no-run
```

Expected: build succeeds (no actual test execution — just compilation).

- [ ] **Step 4: Run clippy**

Run:

```bash
cargo clippy --package rimap-server --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/tests/daemon_happy_path.rs crates/rimap-server/tests/daemon_max_sessions.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): init tracing_subscriber in two failing #188 tests

Adds idempotent tracing_subscriber::try_init at the top of
client_connects_and_sees_clean_session_lifecycle and
daemon_releases_permit_on_session_end so RUST_LOG=trace runs surface
daemon-side activity for issue #188 diagnostic. Zero-cost when RUST_LOG
is unset; intended to remain after the fix lands so future maintainers
can flip on tracing without modifying source.

Does not yet remove the macOS cfg_attr ignores — that lands once Phase 1
identifies the root cause.

Refs: #188

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Phase 1 — Diagnostic run on Tahoe + record findings

**Files:**
- Modify: `docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md` (append "Phase 1 findings" section)
- Modify: GitHub issue #188 (add comment via `gh issue comment`)

- [ ] **Step 1: Run the probe test on macOS, capture output**

Run:

```bash
cargo nextest run --package rimap-server \
    --lib daemon::transport::unix::tests::accept_and_peer_cred_handle_peer_that_disconnects_immediately \
    -- --nocapture 2>&1 | tee /tmp/issue-188-probe.log
```

Expected: PASS (the test does not assert). The log contains one `issue #188 probe:` line indicating one of:
- `accept Ok (peer_cred succeeded) on macos` — kernel does not punish closed-peer accept; bug is elsewhere.
- `accept Err on macos kind=<X> msg=<Y>` — kernel returns an error; record the kind.
- `accept did not return within 2 s on macos` — kernel never delivers the connection; record this.

- [ ] **Step 2: Run `client_connects_and_sees_clean_session_lifecycle` with tracing**

The test currently has `#[cfg_attr(target_os = "macos", ignore = ...)]`. Bypass with `--run-ignored only` and capture daemon trace output:

```bash
RUST_LOG=rimap_server=trace,rimap_audit=trace \
    cargo nextest run --package rimap-server \
        --test daemon_happy_path \
        --run-ignored only \
        -- --nocapture 2>&1 | tee /tmp/issue-188-happy-path.log
```

Expected: the test FAILS with `wait_for_audit timed out`. The trace log shows daemon-side activity. Look for one of:
- `accept failed` log line — accept-side syscall errored. Kind is in the message. Maps to decision matrix row 1 or 2.
- `rejected peer with mismatching identity` — peer_gate rejected. Maps to row 5 (UID surprise).
- `rejected session: max_concurrent_sessions reached` — should not appear (limit defaults to 64).
- **None of the above** — daemon never reached the accept-loop branch that handles errors. Maps to row 3, 4, or 6.

- [ ] **Step 3: Run `daemon_releases_permit_on_session_end` with tracing**

```bash
RUST_LOG=rimap_server=trace,rimap_audit=trace \
    cargo nextest run --package rimap-server \
        --test daemon_max_sessions \
        --run-ignored only \
        -- --nocapture 2>&1 | tee /tmp/issue-188-max-sessions.log
```

Expected: the test FAILS the same way `client_connects_and_sees_clean_session_lifecycle` did. Confirm the trace evidence is consistent with step 2's findings.

- [ ] **Step 4: Append "Phase 1 findings" section to the spec**

Edit `docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md`. Append a new top-level section at the end:

```markdown
## Phase 1 findings (recorded YYYY-MM-DD)

**Probe test outcome:** <fill from /tmp/issue-188-probe.log — paste the
exact `issue #188 probe:` line>.

**Daemon trace from `client_connects_and_sees_clean_session_lifecycle`:**
<paste the relevant 5-10 trace lines from /tmp/issue-188-happy-path.log
that named the failure point — typically the last line before the test's
2 s wait_for_audit timeout panic>.

**Daemon trace from `daemon_releases_permit_on_session_end`:** <same as
above for /tmp/issue-188-max-sessions.log>.

**Root cause:** <one-paragraph plain-English explanation: which syscall,
which error, which decision-matrix row this maps to>.

**Decision matrix outcome:** <one of the matrix rows above>. <"Proceeding
to Phase 2 with test-side wait-for-session_start barrier" if rows 1-2,
otherwise "Pausing the PR; opening follow-up spec/plan to handle <X>">.
```

Replace each `<...>` placeholder with the actual content. Do not commit `<...>` strings.

- [ ] **Step 5: Comment on issue #188 with the findings summary**

```bash
gh issue comment 188 --body "$(cat <<'EOF'
## Phase 1 diagnostic results

**Platform:** macOS 26 (Darwin 25.4.0), Apple Silicon.

**Probe (`accept_and_peer_cred_handle_peer_that_disconnects_immediately`):**
<paste the `issue #188 probe:` line from /tmp/issue-188-probe.log>

**Daemon trace from failing tests:** <one-paragraph summary of what the
tracing run showed — which log site was last, which error kind appeared>.

**Root cause:** <plain-English statement>.

**Phase 2 plan:** <"Test-side wait-for-session_start barrier per spec
decision matrix row 1/2" or "Pause; non-test-side cause; will re-spec">.

Spec: docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md
Plan: docs/superpowers/plans/2026-05-01-issue-188-macos-daemon-test-fix.md
EOF
)"
```

Replace each `<...>` placeholder with the actual content before running.

- [ ] **Step 6: Commit the findings appendix**

```bash
git add docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md
git commit -m "$(cat <<'EOF'
docs(spec): record issue #188 Phase 1 diagnostic findings

Captures the probe test output and the daemon trace from the two failing
tests, identifies the root cause, and selects the decision-matrix row
that drives Phase 2.

Refs: #188

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Decision gate — proceed to Phase 2 only on top-two matrix rows

**Files:** none (this is a thinking step).

- [ ] **Step 1: Re-read the "Phase 1 findings" section just committed**

Open `docs/superpowers/specs/2026-05-01-issue-188-macos-daemon-test-fix-design.md`. Read the "Decision matrix outcome" line.

- [ ] **Step 2: If matrix row 1 or 2, continue to Task 5**

Both top rows have the **same** test-side fix (`wait_for_audit(session_start)` barrier). Task 5 implements it.

- [ ] **Step 3: If matrix row 3, 4, 5, or 6, stop here**

Do **not** continue to Task 5. Instead:

```bash
gh issue comment 188 --body "Phase 1 found a non-test-side cause (decision matrix row <N>). Pausing this PR. Opening follow-up spec/plan."
```

Then push the branch as-is for review (it contains commits 1-3, useful for the follow-up):

```bash
git push -u origin fix/issue-188-macos-daemon-tests
gh pr create --title "WIP/diagnostic-only: issue #188 Phase 1 findings" \
    --body "Phase 1 of issue #188 found a non-test-side cause; Phase 2 paused. See spec for details."
```

Mark this plan complete. Brainstorm a follow-up spec (separate session).

---

### Task 5: Phase 2 (top-two outcome) — Apply test-side wait barriers + remove cfg_attr

**Files:**
- Modify: `crates/rimap-server/tests/daemon_happy_path.rs:41-44, 60-71` (cfg_attr block + test body)
- Modify: `crates/rimap-server/tests/daemon_max_sessions.rs:129-137, 152-172` (cfg_attr block + test body, both rounds)
- Modify: `crates/rimap-server/tests/common/daemon_harness.rs` (comment near `wait_for_audit_at`)
- Modify: `crates/rimap-server/src/daemon/transport/unix.rs` (tighten probe assertions)

- [ ] **Step 1: Edit `client_connects_and_sees_clean_session_lifecycle`**

In `crates/rimap-server/tests/daemon_happy_path.rs`:

(a) Remove the `#[cfg_attr(target_os = "macos", ...)]` block — lines that look like:

```rust
// Skipped on macOS: the daemon never emits `session_start` after a client
// connects in this test environment, so `wait_for_audit` panics on timeout
// even at multi-second budgets. Linux CI is unaffected. See issue #188.
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS daemon-on-tokio: session_start never emitted; see issue #188"
)]
#[tokio::test]
```

becomes:

```rust
#[tokio::test]
```

(b) Insert the wait-for-session_start barrier between `UnixStream::connect` and `stream.shutdown`. The patched test body:

```rust
async fn client_connects_and_sees_clean_session_lifecycle() {
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::UnixStream;

    // Idempotent across the test binary; zero-cost when RUST_LOG is unset.
    // Set RUST_LOG=rimap_server=trace,rimap_audit=trace and pass --nocapture
    // to surface daemon-side activity. See issue #188 for the diagnostic
    // procedure.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();

    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state(&audit_path);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Connect as a raw client — we're not speaking MCP, just proving the
    // accept loop works and session_start/session_end get emitted.
    let mut stream = UnixStream::connect(&socket_path).await.expect("connect");

    // Wait for the daemon to record session_start before closing the
    // client. macOS races the daemon's accept-side syscalls against an
    // already-EOF'd peer; without this barrier the daemon never emits
    // session_start. See issue #188 and the comment in
    // tests/common/daemon_harness.rs near `wait_for_audit_at`.
    daemon
        .wait_for_audit(std::time::Duration::from_secs(2), |c| {
            count_audit_kind(c, "session_start") >= 1
        })
        .await;

    // Write nothing. Immediately close the write half so the daemon sees EOF.
    stream.shutdown().await.expect("shutdown client write half");
    drop(stream);

    // Wait for the session_end record to land instead of guessing how
    // long the daemon needs to observe EOF.
    let audit = daemon
        .wait_for_audit(std::time::Duration::from_secs(2), |c| {
            count_audit_kind(c, "session_end") >= 1
        })
        .await;

    // Shut down the daemon (consumes it, tempdir cleaned up here).
    let _audit_after_shutdown = daemon.shutdown().await;

    let session_starts = count_audit_kind(&audit, "session_start");
    let session_ends = count_audit_kind(&audit, "session_end");
    assert!(
        session_starts >= 1,
        "expected at least one session_start, got:\n{audit}"
    );
    assert!(
        session_ends >= 1,
        "expected at least one session_end, got:\n{audit}"
    );
}
```

- [ ] **Step 2: Edit `daemon_releases_permit_on_session_end`**

In `crates/rimap-server/tests/daemon_max_sessions.rs`:

(a) Remove the `#[cfg_attr(target_os = "macos", ...)]` block — same pattern as Step 1(a).

(b) Insert wait-for-session_start barriers in **both** rounds. The patched test body:

```rust
async fn daemon_releases_permit_on_session_end() {
    // Idempotent across the test binary; zero-cost when RUST_LOG is unset.
    // Set RUST_LOG=rimap_server=trace,rimap_audit=trace and pass --nocapture
    // to surface daemon-side activity. See issue #188 for the diagnostic
    // procedure.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_test_writer()
        .try_init();

    // Limit = 1. First connection holds the permit, then closes. A
    // second connection afterwards must succeed (no rejection) because
    // the permit dropped with the first session future.
    let tempdir = tight_tempdir();
    let audit_path = tempdir.path().join("audit.jsonl");
    let socket_path = tempdir.path().join("daemon.sock");
    let state = test_daemon_state_with_limit(&audit_path, 1);

    let daemon =
        TestDaemon::spawn_bare(tempdir, audit_path.clone(), socket_path.clone(), state).await;

    // Round 1: connect, wait for session_start (see issue #188 — macOS
    // races accept-side syscalls against an already-EOF'd peer), close,
    // wait for session_end.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 1");
        wait_for_audit_at(&audit_path, Duration::from_secs(2), |s| {
            count_audit_kind(s, "session_start") >= 1
        })
        .await;
        c.shutdown().await.expect("shutdown 1");
        drop(c);
    }
    wait_for_audit_at(&audit_path, Duration::from_secs(2), |c| {
        count_audit_kind(c, "session_end") >= 1
    })
    .await;

    // Round 2: permit should be back; this connection must not be
    // rejected. Same wait-for-session_start barrier as round 1.
    {
        let mut c = UnixStream::connect(&socket_path).await.expect("connect 2");
        wait_for_audit_at(&audit_path, Duration::from_secs(2), |s| {
            count_audit_kind(s, "session_start") >= 2
        })
        .await;
        c.shutdown().await.expect("shutdown 2");
        drop(c);
    }
    wait_for_audit_at(&audit_path, Duration::from_secs(2), |c| {
        count_audit_kind(c, "session_end") >= 2
    })
    .await;

    let audit = std::fs::read_to_string(&audit_path).expect("read audit");
    let _ = daemon.shutdown().await;

    let rejected_count = count_session_end_reason(&audit, "rejected");
    assert_eq!(
        rejected_count, 0,
        "expected no rejections when permits are released, full audit:\n{audit}"
    );
    let session_start_count = count_audit_kind(&audit, "session_start");
    assert!(
        session_start_count >= 2,
        "expected at least two session_starts, got {session_start_count}:\n{audit}",
    );
}
```

- [ ] **Step 3: Add documentation comment in `daemon_harness.rs`**

In `crates/rimap-server/tests/common/daemon_harness.rs`, find the `pub async fn wait_for_audit_at(...)` definition (around line 163). Insert this paragraph at the end of its existing doc-comment block, just before the `pub async fn` line:

```rust
///
/// ## macOS race note (issue #188)
///
/// Tests that close their client connection immediately after `connect()`
/// must first wait for `session_start` to land in the audit log. On macOS
/// (Tahoe / Darwin 25.x), the daemon's accept-side syscalls race against
/// a peer that has fully closed the connection by the time the daemon
/// reaches them, and no audit record is emitted. The passing
/// `daemon_rejects_session_past_limit` and the post-fix
/// `daemon_releases_permit_on_session_end` /
/// `client_connects_and_sees_clean_session_lifecycle` all use the
/// `wait_for_audit_at(_, _, |c| count_audit_kind(c, "session_start") >= N)`
/// pattern between `connect` and `shutdown+drop` to sidestep this race.
/// See issue #188 for the diagnostic record.
```

- [ ] **Step 4: Tighten the probe test's assertions in `unix.rs`**

In `crates/rimap-server/src/daemon/transport/unix.rs`, the probe test currently only `eprintln!`s its outcome. Now that Phase 1 has named the platform behavior, replace the `match outcome { ... }` block with platform-conditional assertions matching the recorded behavior.

The exact assertions depend on Phase 1's findings. Three concrete scenarios:

(a) **Phase 1 found `accept Ok` on Linux and `accept Err` on macOS:**

```rust
        match outcome {
            Ok(Ok(_accepted)) => {
                #[cfg(target_os = "linux")]
                {
                    // Expected on Linux: kernel delivers the queued
                    // connection and peer_cred succeeds even after peer
                    // disconnect.
                }
                #[cfg(target_os = "macos")]
                panic!("issue #188: macOS accept unexpectedly succeeded");
            }
            Ok(Err(e)) => {
                #[cfg(target_os = "macos")]
                {
                    // Expected on macOS: peer_cred or accept errors after
                    // peer has fully disconnected.
                    eprintln!(
                        "issue #188: macOS accept Err kind={:?} msg={} (expected)",
                        e.kind(),
                        e
                    );
                }
                #[cfg(target_os = "linux")]
                panic!("issue #188: Linux accept unexpectedly errored: {e:?}");
            }
            Err(_elapsed) => panic!("issue #188: accept hung for 2 s on {}", std::env::consts::OS),
        }
```

(b) **Phase 1 found `accept Ok` on both platforms** (the bug is upstream of accept):

The probe test ceases to be diagnostic for issue #188; tighten to `Ok(Ok(_)) => {}` and add a comment that the test confirms accept-after-peer-disconnect is benign at the kernel layer, and the bug must be in audit/spawn_blocking. **In this case the decision matrix sent us to row 3-6, and Task 4 has already paused the PR.** Step 4 of Task 5 should not run.

(c) **Phase 1 found something else** — Task 4 has already paused the PR.

In short: the form of Step 4 depends on Phase 1's row 1 vs. row 2 outcome. Pattern (a) above covers row 1 (peer_cred errors) and row 2 (accept errors) interchangeably because both surface as `Ok(Err(e))` from `PlatformListener::accept` (which returns `io::Result<...>`).

Apply pattern (a). If Phase 1 specifically distinguishes the syscalls and the user wants finer-grained assertions on the error kind, ask before proceeding.

- [ ] **Step 5: Run the four affected tests on macOS to confirm they pass**

```bash
cargo nextest run --package rimap-server \
    --test daemon_happy_path \
    --test daemon_max_sessions \
    -- client_connects_and_sees_clean_session_lifecycle \
       daemon_releases_permit_on_session_end \
       daemon_rejects_session_past_limit \
       daemon_spawns_and_shuts_down_cleanly
```

Expected: 4/4 PASS, including the two previously-ignored tests now running normally (no `--run-ignored` flag needed because the cfg_attr is gone).

Also run the probe test to confirm the tightened assertions hold:

```bash
cargo nextest run --package rimap-server \
    --lib daemon::transport::unix::tests::accept_and_peer_cred_handle_peer_that_disconnects_immediately
```

Expected: PASS.

- [ ] **Step 6: Run clippy**

```bash
cargo clippy --package rimap-server --all-targets -- -D warnings
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/tests/daemon_happy_path.rs \
        crates/rimap-server/tests/daemon_max_sessions.rs \
        crates/rimap-server/tests/common/daemon_harness.rs \
        crates/rimap-server/src/daemon/transport/unix.rs
git commit -m "$(cat <<'EOF'
fix(rimap-server): land #188 — wait for session_start before client EOF

The two failing macOS daemon integration tests raced the daemon's
accept-side syscalls against a fully-closed peer; on macOS Tahoe one of
those syscalls returns an error, so neither session_start nor
session_end was ever emitted and `wait_for_audit` timed out at 2 s.

Insert a `wait_for_audit(session_start)` barrier between
`UnixStream::connect` and `stream.shutdown+drop` in both tests
(matching the pattern the passing daemon_rejects_session_past_limit
already uses), remove the cfg_attr ignores, document the pattern in
daemon_harness.rs, and tighten the issue #188 probe test's assertions
to lock in the observed kernel behavior on each platform.

Closes #188

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Verification — full crate test suite + lints

**Files:** none (verification only).

- [ ] **Step 1: Run the full `rimap-server` test suite on macOS**

```bash
cargo nextest run --package rimap-server
```

Expected: all tests pass. No skipped tests beyond intentional pre-existing skips for non-macOS-related reasons.

- [ ] **Step 2: Run clippy across the workspace**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS.

- [ ] **Step 3: Run formatting check**

```bash
cargo fmt --check
```

Expected: no diffs.

- [ ] **Step 4: Run typos / pre-commit**

```bash
prek run --all-files
```

Expected: PASS.

If any of steps 1-4 fail, fix the issue and create a follow-up commit on the same branch — do **not** amend. Then re-run from step 1.

---

### Task 7: Push branch and open PR

**Files:** none.

- [ ] **Step 1: Verify branch state**

```bash
git status
git log --oneline main..HEAD
```

Expected: `git status` is clean. The log shows 4 commits (5 if Phase 1 found a non-top-two cause and the PR was paused at Task 4 — in that case stop here and follow Task 4 step 3 instead).

- [ ] **Step 2: Push the branch**

```bash
git push -u origin fix/issue-188-macos-daemon-tests
```

- [ ] **Step 3: Open the PR**

```bash
gh pr create --title "fix(rimap-server): #188 macOS daemon tests — wait for session_start before client EOF" --body "$(cat <<'EOF'
## Summary
- Adds an isolated kernel-behavior probe test in `crates/rimap-server/src/daemon/transport/unix.rs` that records what `accept` + `peer_cred` do on each platform when the client has fully disconnected before the server reaches accept.
- Inserts a `wait_for_audit(session_start)` barrier between `UnixStream::connect` and `stream.shutdown+drop` in `client_connects_and_sees_clean_session_lifecycle` and both rounds of `daemon_releases_permit_on_session_end`, mirroring the passing `daemon_rejects_session_past_limit` pattern.
- Removes the `#[cfg_attr(target_os = "macos", ignore = ...)]` annotations from both tests.
- Documents the macOS race in `daemon_harness.rs` near `wait_for_audit_at`.
- Adds idempotent `tracing_subscriber::try_init` in both tests for future tracing-based triage.

## Test plan
- [x] `cargo nextest run --package rimap-server` passes on macOS 26 (Darwin 25.4.0)
- [ ] CI Linux passes
- [ ] CI macOS passes
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [x] `cargo fmt --check` clean
- [x] `prek run --all-files` clean

Closes #188

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR opened. The PR body's `Closes #188` will close the issue when the PR merges.

- [ ] **Step 4: Mark plan complete**

This plan is done. The PR is in review. Subsequent CI runs are tracked on the PR, not this plan.
