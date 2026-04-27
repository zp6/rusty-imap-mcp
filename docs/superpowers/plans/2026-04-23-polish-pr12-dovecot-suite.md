# Polish PR 12 — Dovecot-backed daemon integration suite (#136)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the five deferred Phase-5 daemon scenarios against the existing Dovecot Docker fixture so the daemon's behavior is validated end-to-end with a real IMAP backend, not just unit-mocked. Tests are gated behind `RIMAP_REQUIRE_LIVE_IMAP=1` and skip silently when the runtime is unavailable, matching the existing pattern under `crates/rimap-imap/tests/integration/`.

**Architecture:** Build a `DovecotDaemonHarness` adapter that wraps `DovecotHarness` (the IMAP-only fixture from `crates/rimap-imap/tests/integration/support/container.rs`) and spawns a full `boot::registry::build` + `daemon::run` stack pointed at the live container. Add five scenario tests, each ≤ 60 LOC, that drive the daemon through the harness. Per-test container startup amortizes via `tokio::test` parallelism — each scenario gets its own isolated Dovecot.

**Tech Stack:** Rust, Tokio, `tempfile`, `assert_cmd`, the existing Dovecot Docker compose fixture, `RIMAP_REQUIRE_LIVE_IMAP=1` gate.

---

## Scope and the five scenarios

The polish-release spec (`docs/superpowers/specs/2026-04-23-polish-release-design.md` § PR 12) names five categories. The mapping below is concrete:

| # | Scenario | Implementation summary |
|---|----------|------------------------|
| 1 | **Graceful shutdown under load** | Open N sessions, each issuing tool calls in a loop. Shutdown the daemon. Assert exit < 7s, all `session_end` records present (covers PR2's #137 fix from the live side). |
| 2 | **Max-sessions enforcement** | Spawn daemon with `max_concurrent_sessions = 2`; open 3 sessions; assert the third sees a paired `session_start` + `session_end(Rejected)` record. |
| 3 | **Audit completeness under failures** | Tool call against a folder that doesn't exist; assert `tool_end(error)` is recorded with an error_code. Repeat for an injected `fail_open=false` write failure → tool returns INTERNAL_ERROR; with `fail_open=true` → tool succeeds and `suppressed_failures` counter increments. |
| 4 | **Peer-identity round-trip** | Open a session and retrieve the daemon's audit log; assert `session_start.peer_identity` includes the test's own UID (Unix). On Unix, `SO_PEERCRED` round-trips through to the audit record. |
| 5 | **Shim reconnect after daemon restart** | Spawn daemon, connect via shim, close shim. Stop daemon, start a fresh daemon at the same path. Spawn a second shim; verify the new session's `session_start` records under a fresh `process_id` (proving the daemon is a separate process and the shim found the new socket). |

The issue body's T25 (peer-UID-rejection from a different user) and T26 (two daemons against the same audit path) and T29 (Windows DACL) are EXPLICITLY out of scope here — see the "Out of scope" section.

## Why these five

Each closes a gap that unit tests can't reach:
- **#1 / #5** require a real per-session future life-cycle that only the live binary exercises.
- **#2** requires real `OwnedSemaphorePermit` exhaustion under accept-loop pressure.
- **#3** requires a real IMAP server returning a real error.
- **#4** requires `SO_PEERCRED` to actually fire on the bound socket — mocked harnesses bypass the syscall.

## Context the engineer must read first

Lesson 1 of `RESUME.md`: verify API assumptions before writing code blocks.

- `crates/rimap-imap/tests/integration/support/container.rs` — full file. The `DovecotHarness` is the source of truth; this PR wraps it. Pay attention to:
  - `try_start()` (line 97) — returns `Err(DockerUnavailable)` silently UNLESS `RIMAP_REQUIRE_DOCKER=1`. The new tests gate on `RIMAP_REQUIRE_LIVE_IMAP=1` instead — different env var, same skip semantics.
  - `port`, `starttls_port`, `fingerprint` accessors (read whatever `pub fn` getters exist).
  - The `Drop` impl that calls `compose down` — guarantees container cleanup even on test panic.
- `crates/rimap-imap/tests/integration/dovecot/docker-compose.yml` — the dovecot config. Confirm the test user / password the fixture sets up; the daemon's `ValidatedMultiConfig` will need to match.
- `crates/rimap-server/src/boot/registry.rs::build` — the real boot path that the harness exercises.
- `crates/rimap-server/tests/common/daemon_harness.rs` — `TestDaemon::spawn_bare` is the existing harness for tests that DON'T need a live registry. The new harness is a sibling, NOT a replacement.
- `crates/rimap-server/tests/shim_happy_path.rs` (lands as part of PR11) — the prior art for spawning the shim subprocess against a real daemon. Scenario 5 reuses that pattern.
- `crates/rimap-config/src/validate/mod.rs` — `ValidatedMultiConfig` shape; the harness builds one in-memory.

Confirm before doing any work:

```bash
ls crates/rimap-imap/tests/integration/dovecot/
rg -n 'pub fn (port|fingerprint|starttls_port)' crates/rimap-imap/tests/integration/support/container.rs | head -5
rg -n 'RIMAP_REQUIRE' crates/rimap-imap/tests/ | head -5
```

If `DovecotHarness` lacks the accessors the new harness needs, add them in Task 1 — they'll be small (`pub fn port(&self) -> u16` etc.) but mark them as "added by PR12" in the diff.

## Dependency note

No new workspace dependencies. The existing `crates/rimap-imap`'s dev-deps already cover what we need (`tempfile`, `assert_cmd`, container management). The new tests live in a new workspace integration crate path — see the file structure decision below.

## File structure decision

Put the new tests in `crates/rimap-server/tests/daemon_dovecot_*.rs` (one file per scenario), NOT in `crates/rimap-imap/tests/`. Reasoning:
- The tests exercise `rimap-server`'s daemon and registry, not `rimap-imap`'s connection logic.
- The Dovecot fixture is reusable: `crates/rimap-imap`'s tests directory exposes `support/container.rs` via `mod common` already; we re-import it from `rimap-server` tests.

Cross-crate test-support sharing requires either:
(a) Promoting `DovecotHarness` to a `pub`-API helper in `rimap-imap`'s `test-support` feature, OR
(b) Copying the (small) harness body into `rimap-server`'s tests dir.

Pick (a) — promote it. Single source of truth wins over duplication. Task 1 step 2 covers this.

## Files

- Modify: `crates/rimap-imap/Cargo.toml` — add a `test-support` feature, gate the existing `tests/integration/support/` modules on it, add it to `[dev-dependencies.rimap-imap]` from `rimap-server`.
- Modify: `crates/rimap-server/Cargo.toml` — add `rimap-imap = { path = "../rimap-imap", features = ["test-support"] }` to `[dev-dependencies]` (alongside the existing dep).
- Modify: `crates/rimap-imap/tests/integration/support/container.rs` — small additive: add `pub fn port()`, `pub fn fingerprint()` etc. accessors if not already present.
- Create: `crates/rimap-server/tests/common/dovecot_daemon_harness.rs` — the new harness adapter.
- Create: `crates/rimap-server/tests/daemon_dovecot_graceful.rs` (scenario 1)
- Create: `crates/rimap-server/tests/daemon_dovecot_max_sessions.rs` (scenario 2)
- Create: `crates/rimap-server/tests/daemon_dovecot_audit.rs` (scenario 3)
- Create: `crates/rimap-server/tests/daemon_dovecot_peer_identity.rs` (scenario 4)
- Create: `crates/rimap-server/tests/daemon_dovecot_shim_reconnect.rs` (scenario 5)

## Task 1: Promote `DovecotHarness` to a re-usable test-support API

**Files:**
- Modify: `crates/rimap-imap/Cargo.toml`
- Modify: `crates/rimap-imap/src/lib.rs` — add `#[cfg(any(test, feature = "test-support"))] pub mod test_support;`
- Create: `crates/rimap-imap/src/test_support.rs` — re-exports `DovecotHarness` and dependencies.
- Modify: `crates/rimap-server/Cargo.toml` — add the dev-dep with the new feature.

- [ ] **Step 1: Audit the existing Dovecot harness boundary**

```bash
cat crates/rimap-imap/tests/integration/support/container.rs | head -90
rg -n '^use ' crates/rimap-imap/tests/integration/support/container.rs | head -20
```

Note which symbols `container.rs` exports (e.g. `DovecotHarness`, `HarnessError`) and which it consumes (`rimap_core::TlsFingerprint`). The promotion in Step 2 must preserve every public symbol used by the existing in-crate tests.

- [ ] **Step 2: Add `test-support` feature**

In `crates/rimap-imap/Cargo.toml`, add:

```toml
[features]
default = []
# Exposes `DovecotHarness` and related fixture types as a public API
# for cross-crate integration tests. Off by default; enabled by
# rimap-server's dev-deps for the Dovecot-backed daemon suite.
test-support = []
```

In `crates/rimap-imap/src/lib.rs`, add at the bottom:

```rust
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
```

Create `crates/rimap-imap/src/test_support.rs`:

```rust
//! Test-only harness API. Off by default; enabled via the
//! `test-support` feature for cross-crate integration tests.
//!
//! Re-exports the Dovecot Docker fixture so `rimap-server`'s daemon
//! integration tests can spin up a real IMAP backend without copying
//! the harness implementation.

#[path = "../tests/integration/support/container.rs"]
pub mod container;
```

This `#[path = "..."]` re-uses the existing file in-place. The harness module previously compiled only under `tests/`; the feature-gated re-export now also pulls it into the library crate when `test-support` is on.

If `container.rs` references sibling files (e.g. `mod foo;`), each must also become accessible — re-export them under `test_support` similarly.

- [ ] **Step 3: Make `DovecotHarness` and `HarnessError` `pub` if not already**

```bash
rg -n 'pub struct DovecotHarness|pub enum HarnessError' crates/rimap-imap/tests/integration/support/container.rs
```

If either is private, change to `pub`. The existing in-crate consumers will continue to work; the cross-crate consumer in PR12 needs them visible.

- [ ] **Step 4: Add the cross-crate dev-dep on `rimap-server`**

In `crates/rimap-server/Cargo.toml`, locate the existing `[dev-dependencies]`. There's already a `rimap-server = { path = ".", ..., features = ["test-support"] }` self-dep; add a sibling for `rimap-imap`:

```toml
rimap-imap = { path = "../rimap-imap", version = "1.0.0", features = ["test-support"] }
```

- [ ] **Step 5: Confirm both crates still build**

```bash
cargo check -p rimap-imap
cargo check -p rimap-imap --features test-support
cargo check -p rimap-server --tests
cargo test -p rimap-imap --test dovecot 2>&1 | head -3   # smoke: existing in-crate test still compiles
```

Expected: every check passes. The in-crate test paths still see `support::container::*` via the existing `mod` declarations in `tests/integration/`.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/Cargo.toml \
        crates/rimap-imap/src/lib.rs \
        crates/rimap-imap/src/test_support.rs \
        crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
chore(rimap-imap): expose DovecotHarness via test-support feature (#136)

PR12's daemon-Dovecot integration suite lives in rimap-server's tests
directory, but the harness body (compose up/down, fingerprint, ports)
is in rimap-imap. Add a test-support feature on rimap-imap that
re-exports the harness so rimap-server tests can consume it through
[dev-dependencies] without duplicating the file.

Refs #136.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Build `DovecotDaemonHarness`

**Files:**
- Create: `crates/rimap-server/tests/common/dovecot_daemon_harness.rs`
- Modify: `crates/rimap-server/tests/common/mod.rs` (or whatever common module re-exports — confirm the path)

- [ ] **Step 1: Confirm the common-test-module shape**

```bash
ls crates/rimap-server/tests/common/
cat crates/rimap-server/tests/common/mod.rs 2>/dev/null || echo "no mod.rs"
```

The existing harness lives at `tests/common/daemon_harness.rs`. The new file is a sibling.

- [ ] **Step 2: Author the harness**

Create `crates/rimap-server/tests/common/dovecot_daemon_harness.rs`:

```rust
//! Daemon harness backed by the live Dovecot Docker fixture.
//!
//! Wraps `rimap_imap::test_support::container::DovecotHarness` to bring
//! up a real IMAP server, then runs `boot::registry::build` and
//! `daemon::run` against it. Skips silently unless
//! `RIMAP_REQUIRE_LIVE_IMAP=1`. Use this for daemon-level scenarios
//! that need a real per-session pipeline through to IMAP; for tests
//! that don't need IMAP, prefer `TestDaemon::spawn_bare`.

#![cfg(unix)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use rimap_audit::{AuditOptions, AuditWriter};
use rimap_imap::test_support::container::DovecotHarness;
use rimap_server::boot::registry;
use rimap_server::daemon::run::run;
use rimap_server::daemon::state::DaemonState;
use rimap_server::daemon::transport::unix::UnixSocketListener;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// True when `RIMAP_REQUIRE_LIVE_IMAP=1` is set. When false, callers
/// should `return` early from each test so the suite skips silently
/// without docker installed.
pub fn live_imap_required() -> bool {
    matches!(std::env::var("RIMAP_REQUIRE_LIVE_IMAP").as_deref(), Ok("1"))
}

/// A daemon spawned against a fresh Dovecot container.
pub struct DovecotDaemon {
    pub socket_path: PathBuf,
    pub audit_path: PathBuf,
    pub tempdir: TempDir,
    pub shutdown: Arc<Notify>,
    pub handle: JoinHandle<anyhow::Result<()>>,
    /// Hold the harness so the container's Drop fires when this struct
    /// drops, AFTER the daemon has shut down.
    pub _dovecot: DovecotHarness,
}

impl DovecotDaemon {
    /// Start a Dovecot container, build a real `AccountRegistry` against
    /// it, and spawn the daemon. Returns `None` when the container
    /// runtime is unavailable AND `RIMAP_REQUIRE_LIVE_IMAP` is unset —
    /// the test should `return` in that case so the suite skips silently.
    ///
    /// # Panics
    /// Panics on any setup failure when `RIMAP_REQUIRE_LIVE_IMAP=1`.
    /// Test failure messages should be clear enough that the engineer
    /// can diagnose container or fixture issues.
    pub async fn try_spawn(max_concurrent_sessions: usize) -> Option<Self> {
        let dovecot = match DovecotHarness::try_start() {
            Ok(h) => h,
            Err(e) => {
                if live_imap_required() {
                    panic!(
                        "RIMAP_REQUIRE_LIVE_IMAP=1 but Dovecot harness unavailable: {e}"
                    );
                }
                return None;
            }
        };

        let tempdir = TempDir::new().expect("tempdir");
        // 0700 on the audit parent (post-#147).
        std::fs::set_permissions(
            tempdir.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("chmod tempdir 0700");

        let audit_path = tempdir.path().join("audit.jsonl");
        let socket_path = tempdir.path().join("daemon.sock");
        let download_dir: Arc<std::path::Path> =
            Arc::from(tempdir.path().to_path_buf().into_boxed_path());

        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .expect("open audit");

        // Build a `ValidatedMultiConfig` pointing at the container.
        // The exact field set depends on the current
        // `rimap_config::validate` shape — confirm with `rg` before
        // pasting; this is a high-churn struct.
        //
        // Read:
        //   rg -n 'pub struct ValidatedMultiConfig|ValidatedAccountConfig'
        //
        // and adjust the literal below to match.
        let multi = build_multi_config_for_dovecot(&dovecot);

        // Use a stub credential store that returns the fixture's
        // hard-coded password. The store can be a small in-memory
        // adapter in this same module — see `dovecot_credential_store`
        // below.
        let credentials: Arc<dyn rimap_config::credential::CredentialStore> =
            Arc::new(dovecot_credential_store(&dovecot));

        let registry = registry::build(&multi, &audit, &credentials, &download_dir)
            .await
            .expect("registry::build");

        let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();
        let session_permits =
            Arc::new(tokio::sync::Semaphore::new(max_concurrent_sessions));
        let state = Arc::new(DaemonState::new(
            Arc::new(registry),
            audit,
            download_dir,
            cancellation_tx,
            session_permits,
        ));

        let listener = UnixSocketListener::bind(&socket_path)
            .await
            .expect("bind socket");
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move { run(state, listener, shutdown_clone).await });

        Some(Self {
            socket_path,
            audit_path,
            tempdir,
            shutdown,
            handle,
            _dovecot: dovecot,
        })
    }

    /// Trigger graceful shutdown, await the run() result, and return
    /// the audit log contents.
    pub async fn shutdown(self) -> String {
        self.shutdown.notify_one();
        let _ = self.handle.await;
        std::fs::read_to_string(&self.audit_path).unwrap_or_default()
    }
}

/// Build a `ValidatedMultiConfig` for the Dovecot container. ONE
/// account named `"work"` (or whichever the Dovecot fixture's `dovecot.conf`
/// defines), pointed at the fixture's TLS port + fingerprint.
fn build_multi_config_for_dovecot(
    dovecot: &DovecotHarness,
) -> rimap_config::validate::ValidatedMultiConfig {
    // The exact field set depends on rimap_config's current shape.
    // Implementer: confirm with
    //   rg -n 'pub struct ValidatedMultiConfig'  crates/rimap-config/src/validate/mod.rs
    // and `cargo expand` if needed; the literal below is a stub.
    todo!("implement based on the current ValidatedMultiConfig shape")
}

/// Minimal CredentialStore that returns the Dovecot fixture's
/// hard-coded password for any (account, host, username) tuple.
fn dovecot_credential_store(
    dovecot: &DovecotHarness,
) -> impl rimap_config::credential::CredentialStore {
    todo!("implement based on the current CredentialStore trait shape")
}

use std::os::unix::fs::PermissionsExt as _;
```

**This file has two `todo!()` markers** — Task 2 step 3 fills them in. The harness body's overall shape is settled in step 2 so reviewers can read the structure first; the config-building details are filled in once you've confirmed the current `ValidatedMultiConfig` and `CredentialStore` shapes.

- [ ] **Step 3: Replace `todo!()`s with real implementations**

Read the current shapes:

```bash
rg -n 'pub struct ValidatedMultiConfig|pub struct ValidatedAccountConfig' crates/rimap-config/src/validate/
rg -n 'pub trait CredentialStore' crates/rimap-config/src/credential/
```

Then implement `build_multi_config_for_dovecot` using:
- `multi.accounts: BTreeMap<AccountId, ValidatedAccountConfig>` with one entry keyed `AccountId::new("work")`.
- The account points at the Dovecot fixture's IMAP port and TLS fingerprint.
- TLS verification mode: pinned, against `dovecot.fingerprint()` (or whichever accessor `DovecotHarness` exposes).
- `fallback_mode: FallbackMode::ExplicitOnly` (or matching default).

For `dovecot_credential_store`, build a small struct implementing `CredentialStore` that returns the fixture's password (e.g. `"testpass123"` — confirm with `cat docker-compose.yml`). Stub all other methods to `unimplemented!()` since the test path only calls `resolve`.

The exact field-by-field implementation is too dependent on current crate shapes to commit to ahead of time; treat the `todo!()` markers as a forcing function to read the actual code BEFORE filling them in. (See `RESUME.md` lesson 1.)

- [ ] **Step 4: Smoke-test the harness with a `try_spawn` call**

Add a temporary smoke test at the bottom of `dovecot_daemon_harness.rs`:

```rust
#[cfg(test)]
mod smoke {
    use super::DovecotDaemon;

    #[tokio::test]
    async fn try_spawn_returns_a_running_daemon_when_live_imap_required() {
        let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
            eprintln!("skipping: RIMAP_REQUIRE_LIVE_IMAP not set");
            return;
        };
        let log = daemon.shutdown().await;
        assert!(log.contains("\"kind\":\"process_start\""));
    }
}
```

Run with the gate set:

```bash
RIMAP_REQUIRE_LIVE_IMAP=1 cargo test -p rimap-server --test common smoke
```

If `cargo test --test common` doesn't pick up the file (test files in `tests/common/` are typically modules, not separate test binaries), wire the smoke test into a discoverable test binary instead — the easiest path is making it part of one of the scenario files in subsequent tasks.

DELETE this smoke test before committing — it's scaffolding to verify Task 2 wired up correctly, not a permanent test.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/tests/common/dovecot_daemon_harness.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): add Dovecot-backed daemon harness (#136)

DovecotDaemon::try_spawn brings up a fresh Dovecot Docker container
via the rimap-imap test-support feature, builds a real
AccountRegistry pointed at it (full registry::build path including
resolve_special_use), and runs the daemon accept loop. Each call
returns None when RIMAP_REQUIRE_LIVE_IMAP is unset and the runtime
is unavailable, so the suite skips silently on dev machines without
docker.

The five scenario tests in subsequent commits each consume this
harness.

Refs #136.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Scenario 1 — graceful shutdown under load

**Files:**
- Create: `crates/rimap-server/tests/daemon_dovecot_graceful.rs`

- [ ] **Step 1: Author the test**

Mirror `daemon_graceful_shutdown.rs` (the existing in-process variant), but use `DovecotDaemon` and have each session issue a `tools/list` in a loop until shutdown.

```rust
//! Scenario 1: graceful shutdown under load (#136). N sessions issue
//! `tools/list` in a loop while the daemon shuts down. Asserts the
//! drain completes within 7 seconds (5s grace + headroom) and every
//! session produces a session_end record.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn shutdown_drains_loaded_sessions_within_5s_plus_headroom() {
    let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
        return;
    };

    // Open four sessions, each holding a connection. Don't actually
    // run the rmcp protocol — we just need active sessions in the
    // daemon's JoinSet at shutdown time.
    let sessions: Vec<UnixStream> = (0..4)
        .map(|_| futures_util::executor::block_on(UnixStream::connect(&daemon.socket_path)))
        .collect::<Result<Vec<_>, _>>()
        .expect("connect 4 sessions");

    // Brief settle before shutdown so the accept loop spawns the per-
    // session futures.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    let log = daemon.shutdown().await;
    let elapsed = started.elapsed();
    drop(sessions);

    assert!(
        elapsed < Duration::from_secs(7),
        "shutdown took {elapsed:?}; expected <7s",
    );

    let session_ends = log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .count();
    assert!(
        session_ends >= 4,
        "expected at least 4 session_end records, got {session_ends}; log:\n{log}",
    );
}
```

- [ ] **Step 2: Run with the gate set**

```bash
RIMAP_REQUIRE_LIVE_IMAP=1 cargo test -p rimap-server --test daemon_dovecot_graceful
```

Expected: pass. Without the gate, the test exits early via `return`.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/tests/daemon_dovecot_graceful.rs
git commit -m "$(cat <<'EOF'
test(rimap-server): scenario 1 — graceful shutdown under load (#136)

Opens 4 sessions against a Dovecot-backed daemon, triggers shutdown,
asserts drain completes within 7s and every session produces a
session_end record. Gates on RIMAP_REQUIRE_LIVE_IMAP=1.

Refs #136.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Scenario 2 — max-sessions enforcement

**Files:**
- Create: `crates/rimap-server/tests/daemon_dovecot_max_sessions.rs`

- [ ] **Step 1: Author the test**

```rust
//! Scenario 2: max-sessions enforcement against a live Dovecot (#136).
//! Spawn daemon with `max_concurrent_sessions=2`, open 3 sessions,
//! assert the third sees a paired session_start + session_end(Rejected).

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;
use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn third_session_is_rejected_when_max_concurrent_is_two() {
    let Some(daemon) = DovecotDaemon::try_spawn(2).await else {
        return;
    };

    let _s1 = UnixStream::connect(&daemon.socket_path).await.expect("s1");
    let _s2 = UnixStream::connect(&daemon.socket_path).await.expect("s2");
    // Brief settle so s1/s2 occupy the semaphore before s3 races in.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // s3 will hit the semaphore at zero — accept-loop emits the paired
    // start+end(Rejected) record and drops the stream.
    let s3 = UnixStream::connect(&daemon.socket_path).await.expect("s3");
    drop(s3);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let log = daemon.shutdown().await;
    let rejected_ends = log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_end""#))
        .filter(|l| l.contains(r#""reason":"rejected""#))
        .count();
    assert_eq!(
        rejected_ends, 1,
        "expected exactly 1 session_end(rejected); got {rejected_ends}; log:\n{log}",
    );
}
```

- [ ] **Step 2: Run + commit (same pattern as Task 3 step 2-3)**

## Task 5: Scenario 3 — audit completeness under failures

**Files:**
- Create: `crates/rimap-server/tests/daemon_dovecot_audit.rs`

- [ ] **Step 1: Decide the failure injection vector**

Two viable approaches:
(a) **IMAP-server-side failure.** Issue a tool call that targets a folder that doesn't exist (`folder=/non/existent/UID-1`); the IMAP layer returns a server error; the audit envelope records `tool_end(error, ERR_INTERNAL or similar)`.
(b) **Audit-writer failure injection.** The `test-injection` feature on `rimap-audit` (see `lib.rs`) exposes `force_next_write_failure` for fault injection. Combine with `fail_open=true` to assert `suppressed_failures` increments.

Pick (a) for this PR — it's the more interesting end-to-end coverage. Defer (b) unless the suite needs it: write-failure suppression is already covered by `audit_fail_open` unit tests (no IMAP needed).

- [ ] **Step 2: Author the test (folder-not-found path)**

The exact MCP frame depends on which tool you exercise. `fetch_message` against a non-existent UID is a clean failure path. Sketch:

```rust
//! Scenario 3: audit completeness under tool failures (#136).
//! Issues a fetch_message against a non-existent UID and asserts the
//! audit log contains a tool_end with error_code != null.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn tool_failure_records_tool_end_with_error_code() {
    let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
        return;
    };

    // Open a session and send mcp/initialize + tools/call(fetch_message,
    // uid=0xFFFFFFFF, folder=NotARealFolder). Expect the call to fail at
    // dispatch with a dispatch error (no such folder), which the audit
    // envelope records as tool_end(status=error, error_code=...).
    let mut stream = UnixStream::connect(&daemon.socket_path).await.expect("connect");
    // ... write initialize + tools/call frames; read responses ...
    // (Exact payload elided here — implementer fills in based on the
    // current MCP frame shape and tool name conventions.)

    drop(stream);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let log = daemon.shutdown().await;
    let tool_ends_with_error: Vec<_> = log
        .lines()
        .filter(|l| l.contains(r#""kind":"tool_end""#))
        .filter(|l| l.contains(r#""status":"error""#))
        .collect();
    assert!(
        !tool_ends_with_error.is_empty(),
        "expected at least one tool_end(error); log:\n{log}",
    );
    let first = tool_ends_with_error[0];
    assert!(
        first.contains(r#""error_code":""#),
        "tool_end(error) must carry an error_code; first record: {first}",
    );
}
```

- [ ] **Step 2: Run + commit**

## Task 6: Scenario 4 — peer-identity round-trip

**Files:**
- Create: `crates/rimap-server/tests/daemon_dovecot_peer_identity.rs`

- [ ] **Step 1: Author the test**

```rust
//! Scenario 4: peer-identity round-trip (#136). Asserts the daemon's
//! audit record carries the test process's own UID in
//! session_start.peer_identity, validating that SO_PEERCRED fired
//! through to the audit layer end-to-end.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use tokio::net::UnixStream;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn session_start_records_our_uid_via_so_peercred() {
    let Some(daemon) = DovecotDaemon::try_spawn(64).await else {
        return;
    };

    let _s = UnixStream::connect(&daemon.socket_path).await.expect("connect");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let log = daemon.shutdown().await;
    let our_uid = rustix::process::geteuid().as_raw();

    // The session_start records JSON-shape `peer_identity:{Unix:{uid:N,...}}`.
    // Match against our actual UID rather than a hard-coded number.
    let starts_with_our_uid = log
        .lines()
        .filter(|l| l.contains(r#""kind":"session_start""#))
        .filter(|l| l.contains(&format!(r#""uid":{our_uid}"#)))
        .count();
    assert!(
        starts_with_our_uid >= 1,
        "expected session_start with peer uid {our_uid}; log:\n{log}",
    );
}
```

- [ ] **Step 2: Run + commit**

## Task 7: Scenario 5 — shim reconnect after daemon restart

**Files:**
- Create: `crates/rimap-server/tests/daemon_dovecot_shim_reconnect.rs`

- [ ] **Step 1: Author the test**

This scenario reuses the shim-spawn pattern from PR11's `shim_happy_path.rs`. The flow:

1. Spawn daemon-1 (DovecotDaemon).
2. Spawn shim subprocess against daemon-1's socket; verify connection works (e.g. `tools/list` returns).
3. Kill shim subprocess.
4. Shutdown daemon-1.
5. Spawn daemon-2 at the same socket path (fresh process_id).
6. Spawn shim-2 against daemon-2; verify connection works.
7. Audit logs from daemon-1 and daemon-2 carry distinct `process_id`s.

Skeleton:

```rust
//! Scenario 5: shim reconnects to a freshly-restarted daemon (#136).
//! Two daemon spawns at the same socket path, two shim subprocess
//! invocations; asserts the audit logs carry distinct process_ids.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

mod common;

use common::dovecot_daemon_harness::DovecotDaemon;

#[tokio::test]
async fn shim_reconnects_to_new_daemon_after_restart() {
    let Some(daemon1) = DovecotDaemon::try_spawn(64).await else {
        return;
    };
    let socket_path = daemon1.socket_path.clone();
    // ... drive shim against daemon1 ...
    let log1 = daemon1.shutdown().await;

    // Spawn daemon2 at the same socket path. (DovecotDaemon::try_spawn
    // currently allocates its own tempdir-scoped path; a small
    // try_spawn_at(socket_path) variant may be needed. If so, add it
    // to the harness in a Task 7-only commit before this test.)
    let Some(daemon2) = DovecotDaemon::try_spawn(64).await else {
        return;
    };
    // ... drive shim against daemon2 ...
    let log2 = daemon2.shutdown().await;

    // Each log carries its own process_id. The two must differ.
    let pid1 = extract_first_process_id(&log1);
    let pid2 = extract_first_process_id(&log2);
    assert_ne!(pid1, pid2, "expected distinct process_ids across daemon restart");
}

fn extract_first_process_id(log: &str) -> Option<String> {
    log.lines()
        .find(|l| l.contains(r#""kind":"process_start""#))
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["process_id"].as_str().map(str::to_owned))
}
```

If `DovecotDaemon::try_spawn_at(socket_path: &Path)` is needed, add it as a small variant in `dovecot_daemon_harness.rs`. Keep the addition minimal.

- [ ] **Step 2: Run + commit**

## Task 8: Full-workspace verification + CI hookup

**Files:**
- Possibly modify: `.github/workflows/ci.yml` — add `RIMAP_REQUIRE_LIVE_IMAP=1` to the integration-test job.

- [ ] **Step 1: Decide on CI hookup**

CI already runs the existing Dovecot tests under `RIMAP_REQUIRE_DOCKER=1`. The new `RIMAP_REQUIRE_LIVE_IMAP=1` is a parallel gate. Two options:

(a) Add a new CI job `daemon-integration-live` that runs the `daemon_dovecot_*` tests with both gates set. Cleanest separation; explicit job name.
(b) Reuse the existing `imap-integration-live` job by setting both gates. Less new YAML; slightly muddier semantics.

Pick (a) if the existing CI YAML reads cleanly with named-job-per-fixture. Otherwise (b).

If `.github/workflows/ci.yml` doesn't exist yet, SKIP this task and document in the PR description that "this suite is opt-in via `RIMAP_REQUIRE_LIVE_IMAP=1`; CI hookup follows in a separate PR".

- [ ] **Step 2: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 3: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean. The new `tests/common/dovecot_daemon_harness.rs` and the five scenario files all pass.

- [ ] **Step 4: Default-gate test run**

Run: `cargo test --workspace`
Expected: all pre-existing tests pass; the five new `daemon_dovecot_*` tests skip silently because `RIMAP_REQUIRE_LIVE_IMAP` is unset.

- [ ] **Step 5: Live-gate test run (developer machine with Docker)**

Run: `RIMAP_REQUIRE_LIVE_IMAP=1 RIMAP_REQUIRE_DOCKER=1 cargo test --workspace`
Expected: every test including the five new scenarios passes. Each scenario takes 20-60 seconds (container startup is the dominant cost), so the full run is ~5 minutes.

If a scenario hangs or fails:
- Inspect the docker-compose project's logs: `docker logs <container-name>` while a test is running, then `docker compose -p <project> down`.
- Check that the docker network teardown isn't leaking state between scenarios (the per-test project name should isolate them).

- [ ] **Step 6: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. `rimap-imap`'s new `test-support` feature doesn't pull new third-party deps.

- [ ] **Step 7: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- The harness gate is `RIMAP_REQUIRE_LIVE_IMAP=1`, not the existing `RIMAP_REQUIRE_DOCKER=1` — distinct env var per the spec; tests skip silently when unset.
- `DovecotDaemon` holds the `DovecotHarness` field as `_dovecot` so the container's `Drop` fires when the test ends, even on panic. No `forget`-style leakage.
- Each scenario test is ≤ 60 LOC; the heavy lift is in `dovecot_daemon_harness.rs` (Task 2) and the cross-crate `test-support` feature plumbing (Task 1).
- The `todo!()` placeholders in Task 2 step 2 are intentional — they force the implementer to read current `ValidatedMultiConfig` / `CredentialStore` shapes BEFORE writing code that depends on them. (Wave A lesson 1.)
- Each scenario commits independently so reviewers can bisect failures by scenario.

## Out of scope

- **T25: Peer-UID rejection from a different OS user.** Requires elevated privileges or user-namespace tricks that aren't reliably available in CI. Leave at the unit-test level (`make_peer_gate` in `daemon/run.rs`); a real cross-UID e2e is a future hardware-CI investment.
- **T26: Two daemons against the same audit path.** The `AuditError::Locked` path is already covered by unit tests at `crates/rimap-audit/tests/concurrent_lock.rs`. An end-to-end variant adds little; defer.
- **T29: Windows DACL inspection on the named pipe.** Needs a Windows CI runner. Out of scope until #129 (Windows Service integration) lands; tracked separately.
- **Performance benchmarks.** This suite is correctness-focused. Benchmark scenarios (latency, throughput) belong in a future `benches/` setup.
- **Anything in production code.** The PR is purely additive in test code, the new `test-support` feature, and (optionally) CI YAML.

If you find yourself editing anything outside the Files list, stop and re-read this plan.
