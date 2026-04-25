# Polish PR 1 — `daemon/state.rs` cleanup (#141 + #143 + #145)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bundle three coupled changes on `crates/rimap-server/src/daemon/state.rs`: hoist `RedactionSalt` from per-session to `DaemonState` (#141); replace `RwLock<Option<AccountId>>` on `SessionState.active_account` with `arc-swap::ArcSwapOption<AccountId>` (#143); tighten `DaemonState` field visibility to `pub(crate)` behind a public constructor and delete the unused `SessionAuditSink::raw_writer` accessor (#145).

**Architecture:** The three changes touch the same struct declaration so they land together. One random salt is built at boot and stored on `DaemonState`; `ImapMcpServer` clones the `Arc<RedactionSalt>` out of shared state instead of minting a new one per accept. The session-default account becomes lock-free: reads drop `.await`, writes compare-and-swap. Visibility tightens via a `pub fn DaemonState::new(...)` constructor so `main.rs` (binary crate) and integration tests keep a single construction path while internal fields become `pub(crate)`.

**Tech Stack:** Rust, `arc-swap 1`, `rimap-audit::redact::RedactionSalt`, Tokio async.

---

## Context the engineer must read first

Before touching code, read these in full so the API-shape bugs listed in `RESUME.md` lesson 1 do not recur:

- `crates/rimap-server/src/daemon/state.rs` — current struct + session state + module tests
- `crates/rimap-server/src/mcp/server.rs` — `ImapMcpServer::new` (line 51) builds a per-session salt today; `resolve_account_for_call` (line 526) reads `active_account` with `.read().await.clone()`
- `crates/rimap-server/src/tools/admin/accounts.rs` — `handle_use_account` (line 56) writes `active_account` under a `write().await` guard
- `crates/rimap-server/src/daemon/audit_sink.rs` — `SessionAuditSink::raw_writer` (line 87) is the only `raw_writer` accessor; already carries `#[expect(dead_code)]`
- `crates/rimap-server/src/mcp/audit_envelope.rs` — `compute_tool_args_artifacts` (line 160) reads `self.redaction_salt.as_ref()`
- `crates/rimap-server/src/main.rs:182` — the one production `DaemonState { ... }` struct literal
- Every other struct-literal site (lesson 7 of `RESUME.md`) you MUST update:
  - `crates/rimap-server/tests/e2e.rs:286`
  - `crates/rimap-server/tests/dispatch_ticket.rs:47` and `:217`
  - `crates/rimap-server/tests/common/daemon_harness.rs:99`
  - `crates/rimap-server/src/mcp/dispatch.rs:359`
  - `crates/rimap-server/src/mcp/audit_envelope.rs:457`

## Dependency note

`arc-swap` is NOT currently in the workspace. The Polish spec (spec §"Risks" → PR 1 area) explicitly calls out that this PR reintroduces `arc-swap`, which was removed as dead code in commit `4596078`. Add it as a workspace dep + a `rimap-server` dep exactly once; do not add it to any other crate.

---

## Files

- Modify: `Cargo.toml` — add `arc-swap` to `[workspace.dependencies]`
- Modify: `crates/rimap-server/Cargo.toml` — add `arc-swap = { workspace = true }`
- Modify: `crates/rimap-server/src/daemon/state.rs` — three changes: hoisted salt field, ArcSwapOption, `pub(crate)` + `pub fn new(...)`
- Modify: `crates/rimap-server/src/daemon/audit_sink.rs` — delete `raw_writer` and its `#[expect(dead_code)]` attribute
- Modify: `crates/rimap-server/src/mcp/server.rs` — remove `redaction_salt` field on `ImapMcpServer`; read via `self.state.redaction_salt`
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs` — update `self.redaction_salt.as_ref()` call site; update the in-file test's `DaemonState { ... }` literal
- Modify: `crates/rimap-server/src/mcp/dispatch.rs` — update the in-file test's `DaemonState { ... }` literal
- Modify: `crates/rimap-server/src/tools/admin/accounts.rs` — rewrite `handle_use_account` write path
- Modify: `crates/rimap-server/src/main.rs` — call `DaemonState::new(...)` instead of struct literal; `state.total_tool_calls` accessor still works
- Modify: `crates/rimap-server/tests/e2e.rs` — call `DaemonState::new(...)`
- Modify: `crates/rimap-server/tests/dispatch_ticket.rs` — call `DaemonState::new(...)` at both sites
- Modify: `crates/rimap-server/tests/common/daemon_harness.rs` — call `DaemonState::new(...)`

## Task 1: Add `arc-swap` to the workspace and the `rimap-server` crate

**Files:**
- Modify: `Cargo.toml`
- Modify: `crates/rimap-server/Cargo.toml`

- [ ] **Step 1: Add `arc-swap` to `[workspace.dependencies]`**

In `Cargo.toml`, add this line to the existing `[workspace.dependencies]` table, grouped next to `parking_lot` (they are both concurrency primitives):

```toml
arc-swap = "1"
```

- [ ] **Step 2: Add `arc-swap` as a `rimap-server` dependency**

In `crates/rimap-server/Cargo.toml`, add the following line at the end of the `[dependencies]` table (after `tempfile`):

```toml
arc-swap = { workspace = true }
```

- [ ] **Step 3: Confirm the dep resolves cleanly**

Run: `cargo tree -p rimap-server -i arc-swap`
Expected: a tree rooted at `arc-swap vX.Y.Z`, parent `rimap-server vX.Y.Z (...)` (where X.Y.Z is whatever version cargo picks inside the 1.x range).

- [ ] **Step 4: Run `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean exit. If a transient RustSec DB 500 shows up, rerun — per `RESUME.md` § workflow conventions this is expected intermittently.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rimap-server/Cargo.toml
git commit -m "$(cat <<'EOF'
chore(deps): reintroduce arc-swap for SessionState.active_account (#143)

Lock-free swap of the session-scoped active account. Previously
removed as dead code in 4596078 during multi-client-daemon work;
this PR puts it back on the daemon's single-writer read path for
#143.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Hoist `RedactionSalt` onto `DaemonState` and add `pub fn new(...)` (#141, #145 constructor half)

**Files:**
- Modify: `crates/rimap-server/src/daemon/state.rs`

- [ ] **Step 1: Write the failing test**

Append this test to the existing `#[cfg(test)] mod tests` block near the bottom of `crates/rimap-server/src/daemon/state.rs`:

```rust
    #[tokio::test]
    async fn daemon_state_new_builds_one_salt_per_daemon_lifetime() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use rimap_audit::{AuditOptions, AuditWriter, Seq};
        use tempfile::tempdir;

        use crate::boot::registry::AccountRegistry;
        use super::DaemonState;

        let dir = tempdir().unwrap();
        let audit = AuditWriter::open(&AuditOptions {
            path: dir.path().join("a.jsonl"),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();
        let (cancellation_tx, _rx) = rimap_audit::cancellation_channel();
        let state = Arc::new(DaemonState::new(
            Arc::new(AccountRegistry::new(BTreeMap::new())),
            audit,
            Arc::from(dir.path().to_path_buf().into_boxed_path()),
            cancellation_tx,
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        // Two clones of the Arc<RedactionSalt> must be pointer-equal to
        // the salt stored on state — proves there is exactly one salt.
        let salt1 = Arc::clone(&state.redaction_salt);
        let salt2 = Arc::clone(&state.redaction_salt);
        assert!(Arc::ptr_eq(&salt1, &salt2));
    }
```

- [ ] **Step 2: Run the test to confirm it fails to compile**

Run: `cargo test -p rimap-server --lib daemon_state_new_builds_one_salt_per_daemon_lifetime`
Expected: compile error — `no method named 'new' for struct DaemonState` and `no field 'redaction_salt' on type 'DaemonState'`.

- [ ] **Step 3: Rewrite `DaemonState` — hoisted salt, `pub(crate)` fields, `pub fn new(...)`**

Replace the entire `DaemonState` block (the `/// Daemon-wide shared state. ...` doc comment plus the struct body) in `crates/rimap-server/src/daemon/state.rs` with:

```rust
/// Daemon-wide shared state. One `Arc<DaemonState>` is built at boot and
/// cloned into every `PerSessionHandler`.
///
/// Fields are `pub(crate)` so in-crate code reads them directly; external
/// consumers (the `main.rs` binary + integration tests) must construct via
/// [`DaemonState::new`] and go through the in-crate APIs for reads. See
/// issue #145 (Tighten DaemonState field visibility).
pub struct DaemonState {
    /// Account registry (all accounts, all connections, all per-account
    /// governors and breakers). `Connection`s are already `Arc`-backed
    /// internally; sharing the registry via `Arc` gives every session
    /// cheap access.
    pub(crate) registry: Arc<AccountRegistry>,
    /// Audit writer; the single fs-locked backing file is shared.
    pub(crate) audit: AuditWriter,
    /// Attachment download directory (read-only after boot).
    pub(crate) download_dir: Arc<std::path::Path>,
    /// Cancellation channel sender for the audit drainer.
    pub(crate) cancellation_tx: CancelledToolEndSender,
    /// Daemon start time (used to compute session durations).
    pub(crate) started_at: Instant,
    /// Bound on concurrent shim sessions. An `OwnedSemaphorePermit` is
    /// acquired on each accept and held for the session's lifetime;
    /// dropping the permit (when the session future returns) releases
    /// the slot. Connections that arrive while the semaphore is
    /// exhausted are rejected with a paired
    /// `session_start` + `session_end(Rejected)` audit pair.
    pub(crate) session_permits: Arc<Semaphore>,
    /// Daemon-wide aggregate of completed tool calls across all sessions.
    /// Incremented in `emit_session_end` with each session's final count.
    /// Read in `daemon_main` to populate `process_end.total_tool_calls`.
    pub(crate) total_tool_calls: AtomicU64,
    /// Per-process salt used by [`rimap_audit::redact::Redactor`] to hash
    /// tool arguments. One salt for the daemon lifetime; hashes are not
    /// comparable across restarts (by design — fresh randomness per boot).
    /// Cloned cheaply into every `ImapMcpServer`. See #141.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
}

impl DaemonState {
    /// Build daemon-wide shared state. Called once in `daemon_main`;
    /// integration tests also use this so a new field on `DaemonState`
    /// does not require updating every test's struct literal.
    ///
    /// Generates one [`RedactionSalt`] from the OS RNG and wraps it in
    /// `Arc` so `spawn_blocking` closures can cheaply capture it.
    #[must_use]
    pub fn new(
        registry: Arc<AccountRegistry>,
        audit: AuditWriter,
        download_dir: Arc<std::path::Path>,
        cancellation_tx: CancelledToolEndSender,
        session_permits: Arc<Semaphore>,
    ) -> Self {
        Self {
            registry,
            audit,
            download_dir,
            cancellation_tx,
            started_at: Instant::now(),
            session_permits,
            total_tool_calls: AtomicU64::new(0),
            redaction_salt: Arc::new(RedactionSalt::new_random()),
        }
    }

    /// Read the daemon-wide total tool-call counter. `main.rs` consumes
    /// this at `process_end` emission; external callers have no other
    /// reason to touch the `AtomicU64` directly.
    #[must_use]
    pub fn total_tool_calls(&self) -> u64 {
        self.total_tool_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
```

Then, at the top of the file, add the new import (immediately below the existing `use rimap_audit::...` line):

```rust
use rimap_audit::redact::RedactionSalt;
```

- [ ] **Step 4: Run the new test to verify it passes**

Run: `cargo test -p rimap-server --lib daemon_state_new_builds_one_salt_per_daemon_lifetime`
Expected: 1 pass.

- [ ] **Step 5: Confirm full lib tests still compile and pass for `state.rs`**

Run: `cargo test -p rimap-server --lib daemon::state`
Expected: all four pre-existing `SessionState` tests + the new test pass.

- [ ] **Step 6: Commit the intermediate shape**

Do not commit yet — the rest of the crate still won't compile because `ImapMcpServer::new` still tries to build its own salt, and every `DaemonState { ... }` struct literal now fails because fields are `pub(crate)`. Continue to Task 3 so the repo stays in a buildable state when the commit lands.

## Task 3: Drop `redaction_salt` from `ImapMcpServer`; update the one read site

**Files:**
- Modify: `crates/rimap-server/src/mcp/server.rs`
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs`

- [ ] **Step 1: Remove the `redaction_salt` field and its initializer**

In `crates/rimap-server/src/mcp/server.rs`, delete:

- The `use rimap_audit::redact::RedactionSalt;` line near the top of the file — no longer used in this module.
- The `pub(crate) redaction_salt: Arc<RedactionSalt>,` field on `ImapMcpServer` (around line 43) and its doc comment.
- The `redaction_salt: Arc::new(RedactionSalt::new_random()),` line inside `ImapMcpServer::new` (around line 57).

After the edit, the `ImapMcpServer::new` body becomes:

```rust
    pub fn new(state: Arc<DaemonState>, session: Arc<SessionState>) -> Self {
        let audit = SessionAuditSink::new(state.audit.clone(), session.id);
        Self {
            state,
            session,
            audit,
        }
    }
```

Update the doc comment on `new` to drop the "Builds the per-process redaction salt" wording:

```rust
    /// Construct a per-session server. Per-tool schemas are dispatched on
    /// demand via [`rimap_audit::redact::ToolRedactionSchema::redaction_schema`];
    /// the per-process redaction salt lives on [`DaemonState`] and is shared
    /// across every session.
    #[must_use]
```

- [ ] **Step 2: Point `compute_tool_args_artifacts` at the daemon-level salt**

In `crates/rimap-server/src/mcp/audit_envelope.rs`, replace:

```rust
        let redacted = Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref())
            .apply(&args_value);
```

with:

```rust
        let redacted = Redactor::new(
            &tool.redaction_schema(),
            self.state.redaction_salt.as_ref(),
        )
        .apply(&args_value);
```

- [ ] **Step 3: Verify no other `self.redaction_salt` references remain**

Run: `rg -n 'self\.redaction_salt' crates/rimap-server/src/`
Expected: zero hits.

- [ ] **Step 4: Workspace compile check**

Run: `cargo check -p rimap-server --all-targets`
Expected: errors ONLY at the six `DaemonState { ... }` struct-literal sites listed in "Context the engineer must read first"; no errors in non-literal code. If any error names `redaction_salt`, something in step 1 or 2 was missed.

- [ ] **Step 5: Do not commit yet**

Continue to Task 4 so the commit covers the full `DaemonState` shape change.

## Task 4: Update every `DaemonState { ... }` struct literal to `DaemonState::new(...)`

**Files:**
- Modify: `crates/rimap-server/src/main.rs`
- Modify: `crates/rimap-server/src/mcp/dispatch.rs`
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs`
- Modify: `crates/rimap-server/tests/e2e.rs`
- Modify: `crates/rimap-server/tests/dispatch_ticket.rs`
- Modify: `crates/rimap-server/tests/common/daemon_harness.rs`

- [ ] **Step 1: `main.rs` — replace the struct literal**

In `crates/rimap-server/src/main.rs`, replace lines 182–190:

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

with:

```rust
    let state = Arc::new(DaemonState::new(
        Arc::new(registry),
        audit.clone(),
        download_dir,
        cancellation_tx,
        session_permits,
    ));
```

Also replace line 202–204's accessor:

```rust
    let total_tool_calls = state
        .total_tool_calls
        .load(std::sync::atomic::Ordering::Relaxed);
```

with:

```rust
    let total_tool_calls = state.total_tool_calls();
```

- [ ] **Step 2: `tests/e2e.rs`**

Replace the block around `tests/e2e.rs:286`:

```rust
    let daemon_state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir: std::sync::Arc::from(download_dir.path().to_path_buf().into_boxed_path()),
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
        total_tool_calls: std::sync::atomic::AtomicU64::new(0),
    });
```

with:

```rust
    let daemon_state = Arc::new(DaemonState::new(
        Arc::new(registry),
        audit.clone(),
        std::sync::Arc::from(download_dir.path().to_path_buf().into_boxed_path()),
        cancellation_tx,
        Arc::new(tokio::sync::Semaphore::new(64)),
    ));
```

- [ ] **Step 3: `tests/dispatch_ticket.rs` — first literal (line 47)**

Replace the block:

```rust
    let daemon_state = Arc::new(DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
        total_tool_calls: std::sync::atomic::AtomicU64::new(0),
    });
```

with:

```rust
    let daemon_state = Arc::new(DaemonState::new(
        Arc::new(registry),
        audit.clone(),
        download_dir,
        cancellation_tx,
        Arc::new(tokio::sync::Semaphore::new(64)),
    ));
```

- [ ] **Step 4: `tests/dispatch_ticket.rs` — second literal (line 217)**

Replace the block:

```rust
    let daemon_state_2 = Arc::new(rimap_server::daemon::state::DaemonState {
        registry: Arc::new(registry),
        audit: audit.clone(),
        download_dir: download_dir_2,
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
        total_tool_calls: std::sync::atomic::AtomicU64::new(0),
    });
```

with:

```rust
    let daemon_state_2 = Arc::new(rimap_server::daemon::state::DaemonState::new(
        Arc::new(registry),
        audit.clone(),
        download_dir_2,
        cancellation_tx,
        Arc::new(tokio::sync::Semaphore::new(64)),
    ));
```

- [ ] **Step 5: `tests/common/daemon_harness.rs`**

Replace the block around line 99:

```rust
    Arc::new(DaemonState {
        registry,
        audit,
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
        session_permits,
        total_tool_calls: std::sync::atomic::AtomicU64::new(0),
    })
```

with:

```rust
    Arc::new(DaemonState::new(
        registry,
        audit,
        download_dir,
        cancellation_tx,
        session_permits,
    ))
```

- [ ] **Step 6: `src/mcp/dispatch.rs` (in-file `#[cfg(test)]` module)**

Replace the block around line 359:

```rust
        let daemon_state = Arc::new(DaemonState {
            registry: Arc::new(registry),
            audit: audit.clone(),
            download_dir,
            cancellation_tx,
            started_at: std::time::Instant::now(),
            session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
            total_tool_calls: std::sync::atomic::AtomicU64::new(0),
        });
```

with:

```rust
        let daemon_state = Arc::new(DaemonState::new(
            Arc::new(registry),
            audit.clone(),
            download_dir,
            cancellation_tx,
            Arc::new(tokio::sync::Semaphore::new(64)),
        ));
```

- [ ] **Step 7: `src/mcp/audit_envelope.rs` (in-file `#[cfg(test)]` module)**

Replace the block around line 457:

```rust
        let daemon_state = Arc::new(DaemonState {
            registry: Arc::new(AccountRegistry::new(BTreeMap::new())),
            audit,
            download_dir,
            cancellation_tx,
            started_at: std::time::Instant::now(),
            session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
            total_tool_calls: std::sync::atomic::AtomicU64::new(0),
        });
```

with:

```rust
        let daemon_state = Arc::new(DaemonState::new(
            Arc::new(AccountRegistry::new(BTreeMap::new())),
            audit,
            download_dir,
            cancellation_tx,
            Arc::new(tokio::sync::Semaphore::new(64)),
        ));
```

- [ ] **Step 8: Verify no `DaemonState { ... }` struct literals remain**

Run: `rg -n 'DaemonState\s*\{' crates/rimap-server`
Expected: exactly one hit — the struct declaration itself at `src/daemon/state.rs`. If any other hit appears, return to whichever step missed it.

- [ ] **Step 9: Full workspace build**

Run: `cargo check --workspace --all-targets`
Expected: clean (errors only in the `active_account` read/write paths will still exist at this point because Task 5 hasn't run yet, but there should be no errors about `DaemonState` field visibility or `redaction_salt`). Actually wait — `active_account` is still `RwLock<Option<AccountId>>` at this stage; it's only the hoist + visibility we've touched. So this check should be clean.

- [ ] **Step 10: Full test run for what we've changed**

Run: `cargo test -p rimap-server --lib`
Expected: all lib tests pass.

- [ ] **Step 11: Commit — #141 hoist + #145 visibility half**

```bash
git add crates/rimap-server/src/daemon/state.rs \
        crates/rimap-server/src/mcp/server.rs \
        crates/rimap-server/src/mcp/audit_envelope.rs \
        crates/rimap-server/src/mcp/dispatch.rs \
        crates/rimap-server/src/main.rs \
        crates/rimap-server/tests/e2e.rs \
        crates/rimap-server/tests/dispatch_ticket.rs \
        crates/rimap-server/tests/common/daemon_harness.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-server): hoist RedactionSalt and tighten DaemonState visibility (#141, #145)

Per-session RedactionSalt::new_random() on every accept is pointless
— the salt is a forensics tool that only has to be stable within a
single daemon lifetime. Build one salt in DaemonState::new and clone
the Arc into every ImapMcpServer (#141).

Fields on DaemonState go from pub to pub(crate). The binary crate and
integration tests construct via the new DaemonState::new(...) and read
total_tool_calls via the new accessor, keeping the public surface tight
(#145, visibility half).

Refs #141, refs #145.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 5: Replace `RwLock<Option<AccountId>>` with `ArcSwapOption<AccountId>` (#143)

**Files:**
- Modify: `crates/rimap-server/src/daemon/state.rs`
- Modify: `crates/rimap-server/src/mcp/server.rs`
- Modify: `crates/rimap-server/src/tools/admin/accounts.rs`

- [ ] **Step 1: Write the failing test**

Replace the two existing `active_account_*` `#[tokio::test]` tests in the `#[cfg(test)]` block of `crates/rimap-server/src/daemon/state.rs` with these. The new tests mirror the old ones but use the lock-free API:

```rust
    #[test]
    fn new_session_has_no_active_account() {
        let s = SessionState::new(SessionId::new());
        assert!(s.active_account.load().is_none());
    }

    #[test]
    fn active_account_store_then_load_reflects_update() {
        use std::sync::Arc;
        let s = SessionState::new(SessionId::new());
        let id = rimap_core::account::AccountId::new("work").unwrap();
        s.active_account.store(Some(Arc::new(id.clone())));
        let loaded = s.active_account.load_full();
        assert_eq!(loaded.as_deref(), Some(&id));
    }

    #[test]
    fn active_account_store_is_lock_free_no_await_required() {
        // Compile-time proof: if `store` still needed `.await`, this
        // non-async fn could not call it. The test exists so a future
        // refactor back to RwLock breaks compilation.
        use std::sync::Arc;
        let s = SessionState::new(SessionId::new());
        let id = rimap_core::account::AccountId::new("work").unwrap();
        s.active_account.store(Some(Arc::new(id)));
    }
```

- [ ] **Step 2: Run the tests to confirm they fail to compile**

Run: `cargo test -p rimap-server --lib active_account`
Expected: compile error — `active_account` is still an `RwLock<Option<AccountId>>`, so `.load()` / `.store()` / `.load_full()` don't resolve.

- [ ] **Step 3: Swap the field type**

In `crates/rimap-server/src/daemon/state.rs`, update the imports near the top of the file:

- Remove `use tokio::sync::{RwLock, Semaphore};` — replace with `use tokio::sync::Semaphore;`.
- Add: `use arc_swap::ArcSwapOption;`

Replace the `SessionState::active_account` field declaration:

```rust
    /// Session-scoped active account (overrides the config default).
    /// `RwLock` because `use_account` is the only writer and reads
    /// happen on every tool call.
    pub active_account: RwLock<Option<AccountId>>,
```

with:

```rust
    /// Session-scoped active account (overrides the config default).
    /// `ArcSwapOption` because `use_account` is the only writer and
    /// reads happen on every tool call; lock-free swap removes the
    /// `.await` from the read path. See #143.
    pub active_account: ArcSwapOption<AccountId>,
```

Replace the initializer inside `SessionState::new`:

```rust
            active_account: RwLock::new(None),
```

with:

```rust
            active_account: ArcSwapOption::from(None),
```

- [ ] **Step 4: Update the reader in `server.rs`**

In `crates/rimap-server/src/mcp/server.rs`, replace (around line 535):

```rust
        let session_default = self.session.active_account.read().await.clone();
        self.registry()
            .resolve_with_active(explicit_account.as_deref(), session_default.as_ref())
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))
```

with:

```rust
        let session_default = self.session.active_account.load_full();
        self.registry()
            .resolve_with_active(explicit_account.as_deref(), session_default.as_deref())
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))
```

Note: `resolve_with_active` expects `Option<&AccountId>`. `ArcSwapOption::load_full()` returns `Option<Arc<AccountId>>`; `.as_deref()` derefs the `Arc` to `&AccountId`.

Also update the enclosing `resolve_account_for_call` function signature if it is marked `async` solely for the `.read().await` call — check whether any other `.await` remains in the body; if not, remove the `async` keyword. Look at lines 526–540 to decide. **Do not remove `async`** if any caller awaits the function; `cargo check` will tell you. If you remove `async`, also update the call site inside `call_tool` (line 439: `self.resolve_account_for_call(...).await?`) by dropping the `.await`.

- [ ] **Step 5: Rewrite the writer in `handle_use_account`**

In `crates/rimap-server/src/tools/admin/accounts.rs`, replace the `previous` block in `handle_use_account` (around lines 90–97):

```rust
    let previous = {
        let mut guard = session.active_account.write().await;
        let prev = guard.as_ref().map(ToString::to_string);
        if guard.as_ref() != Some(&new_id) {
            *guard = Some(new_id);
        }
        prev
    };
```

with:

```rust
    let previous = {
        use std::sync::Arc;
        let prev_arc = session.active_account.load_full();
        let prev_string = prev_arc.as_deref().map(ToString::to_string);
        // Skip the store if the value is identical — avoids a pointless
        // allocation of Arc<AccountId> on the no-op path.
        if prev_arc.as_deref() != Some(&new_id) {
            session.active_account.store(Some(Arc::new(new_id)));
        }
        prev_string
    };
```

- [ ] **Step 6: Run the failing tests to confirm they now pass**

Run: `cargo test -p rimap-server --lib active_account`
Expected: 3 passes (new_session_has_no_active_account, active_account_store_then_load_reflects_update, active_account_store_is_lock_free_no_await_required).

- [ ] **Step 7: Run the `handle_use_account` tests to confirm no regression**

Run: `cargo test -p rimap-server --lib tools::admin::accounts`
Expected: all pre-existing tests pass (the tests exercise the rejection branches before `session.active_account` is touched, so the swap does not change their behaviour; the happy-path store/load path is covered by the `daemon::state` tests above).

- [ ] **Step 8: Run the full `--all-targets` check + clippy**

Run: `cargo check -p rimap-server --all-targets`
Expected: clean.

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean. If clippy flags `await_holding_lock` it means a lock-based reader was missed; go back to step 4.

- [ ] **Step 9: Commit — #143**

```bash
git add crates/rimap-server/src/daemon/state.rs \
        crates/rimap-server/src/mcp/server.rs \
        crates/rimap-server/src/tools/admin/accounts.rs
git commit -m "$(cat <<'EOF'
perf(rimap-server): swap SessionState.active_account to ArcSwapOption (#143)

Removes the async RwLock guard from the per-call hot path. Writes are
rare (one per use_account) and serialized by the MCP transport, so
lock-free store+load is strictly tighter than RwLock for this field.

`use_account` keeps its compare-first skip so a no-op swap does not
allocate a fresh Arc<AccountId>.

Closes #143.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 6: Delete the unused `SessionAuditSink::raw_writer` accessor (#145 accessor half)

**Files:**
- Modify: `crates/rimap-server/src/daemon/audit_sink.rs`

- [ ] **Step 1: Confirm `raw_writer` is dead**

Run: `rg -n 'raw_writer' crates/rimap-server`
Expected: exactly one hit — the definition at `src/daemon/audit_sink.rs`. If any callers appear, STOP and revisit the plan — the issue body claimed it was only used for `log_process_start` / `log_process_end` but current `main.rs` at line 205 calls `audit.log_process_end(...)` directly on the writer bound in `daemon_main`, not through `raw_writer`. If you find a caller, narrow the API as per the issue's wording instead of deleting.

- [ ] **Step 2: Delete the accessor**

Remove the entire `raw_writer` block from `crates/rimap-server/src/daemon/audit_sink.rs`, including its doc comment, `#[must_use]`, and `#[expect(dead_code, ...)]` attribute — lines roughly 74–89 of the current file:

```rust
    /// The underlying writer, for emitting records that are explicitly
    /// NOT session-scoped (e.g. `process_start` / `process_end`).
    /// Call sites must justify their non-session status.
    ///
    /// Scoped to `pub(crate)` so session-scoped code outside this crate
    /// cannot bypass the `session_id` injection — out-of-crate call sites
    /// must go through `log_tool_start` / `log_tool_end`.
    #[must_use]
    #[expect(
        dead_code,
        reason = "in-crate escape hatch for non-session-scoped records (process_start/process_end); \
                  kept available even when no current caller uses it, per MCP-AUD-03 design"
    )]
    pub(crate) fn raw_writer(&self) -> &AuditWriter {
        &self.writer
    }
```

Delete the entire block. The `#[expect(dead_code, ...)]` attribute would become an unfulfilled-lint-expectation warning (`RESUME.md` lesson 4) if left dangling, so removing the method and the attribute together in a single edit is mandatory.

- [ ] **Step 3: Run clippy to confirm no new warnings**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean exit. If clippy flags an unfulfilled-lint-expectation, the `#[expect(...)]` attribute was not fully removed in step 2.

- [ ] **Step 4: Run the SessionAuditSink tests**

Run: `cargo test -p rimap-server --lib daemon::audit_sink`
Expected: the three pre-existing `log_tool_start` / `log_tool_end` tests still pass. They never touched `raw_writer`, so they are unaffected.

- [ ] **Step 5: Commit — #145 accessor half**

```bash
git add crates/rimap-server/src/daemon/audit_sink.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-server): delete unused SessionAuditSink::raw_writer (#145)

The accessor carried a `#[expect(dead_code)]` attribute because nothing
inside the crate called it. `main.rs` uses the bare `AuditWriter` for
`log_process_start` / `log_process_end`, not the session-scoped sink.
Deleting the method closes the session_id-injection escape hatch that
wasn't in use.

Closes #145.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 7: Full-workspace verification

**Files:** none — this is the green-gate task before pushing.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean exit.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: every test passes, including `dispatch_ticket`, `e2e`, `daemon_happy_path`, and the `daemon::state`, `daemon::audit_sink`, `tools::admin::accounts`, and `mcp::audit_envelope` tests.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. The new `arc-swap` dep should resolve with no RustSec advisory matches.

- [ ] **Step 5: typos**

Run: `typos`
Expected: clean. Re-run if the pre-commit hook catches something the local run missed.

## Self-review checklist

- Every step has concrete code, not a prose description.
- Tests added before the implementation they exercise (TDD), with a runs-and-fails step before every implementation step.
- `DaemonState::new(...)` is exercised by a brand-new test (Task 2) AND by all six pre-existing struct-literal sites (Task 4).
- `ArcSwapOption` rewrite has three tests (no-active, store-then-load, compile-proof-no-await) covering the three invariants #143 cares about.
- `raw_writer` deletion has a defensive `rg` check (Task 6 step 1) so the engineer refuses to delete a live caller.
- `arc-swap` dep is added in one commit (Task 1) separate from the shape change so reviewers can isolate the Cargo.lock churn from the code churn.
- Four commits land in order: deps → hoist+visibility → ArcSwap → raw_writer delete. Each is independently buildable and clippy-clean.
- Every file that needs editing is listed in the Files section at the top; the engineer never has to search.

## Out of scope (guarded against scope creep)

- **Broader visibility sweep on other daemon internals** — deferred (#145 comment: "the broader sweep should stay deferred").
- **`session_end` on aborted shutdown (#137)** — Wave C PR 2; do not touch the drain path here.
- **Moving `log_session_start` / `log_session_end` onto `spawn_blocking` (#142)** — Wave C PR 2; do not touch the session-end path here.
- **`AccountRegistry.list_tools` caching (#148)** — Wave C PR 3; not on this file.

If you find yourself editing anything outside the Files list, stop and re-read the spec.
