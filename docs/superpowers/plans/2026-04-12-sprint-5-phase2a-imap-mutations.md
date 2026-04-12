# Sprint 5 Phase 2a — IMAP Mutations + `spawn_blocking`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add STORE, MOVE, and APPEND operations to `rimap-imap` and a `spawn_blocking` wrapper for `parse_message` in `rimap-server`.

**Architecture:** Three new ops modules in `rimap-imap` (`store`, `move_msg`, `append`) following the existing pattern of free functions taking `&mut ImapSession`, with public methods on `Connection` providing timeout + reconnect wrapping. New types (`FlagAction`, `MoveResult`, `AppendResult`) in `types.rs`. A thin async wrapper in `rimap-server` for the CPU-bound content parser.

**Tech Stack:** `async-imap 0.11` (STORE, COPY, MOVE, APPEND), `tokio::task::spawn_blocking`, existing Dovecot container harness for integration tests.

**Spec:** [`../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md`](../specs/2026-04-12-sprint-5-phase2-mcp-server-design.md) §2

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/rimap-imap/src/types.rs` | Add `FlagAction`, `MoveResult`, `AppendResult` types |
| `crates/rimap-imap/src/error.rs` | Add `BatchTooLarge` variant |
| `crates/rimap-imap/src/ops/store.rs` | New: UID STORE free function |
| `crates/rimap-imap/src/ops/move_msg.rs` | New: UID MOVE / COPY+DELETE free functions |
| `crates/rimap-imap/src/ops/append.rs` | New: APPEND free function |
| `crates/rimap-imap/src/ops/mod.rs` | Wire new modules |
| `crates/rimap-imap/src/connection.rs` | Add `store_flags`, `move_messages`, `append_message` methods |
| `crates/rimap-imap/src/lib.rs` | Re-export new public types |
| `crates/rimap-imap/tests/integration/dovecot.rs` | Integration tests for STORE, MOVE, APPEND |
| `crates/rimap-server/src/content.rs` | New: `parse_message_async` wrapper |
| `crates/rimap-server/src/main.rs` | Wire `content` module |

---

### Task 1: Add `FlagAction` and `BatchTooLarge` to types/error

**Files:**
- Modify: `crates/rimap-imap/src/types.rs`
- Modify: `crates/rimap-imap/src/error.rs`
- Modify: `crates/rimap-imap/src/connection.rs` (update exhaustive match)

- [ ] **Step 1: Add `FlagAction` enum to `types.rs`**

Add after the `Flag` enum (after line 136):

```rust
/// Whether to add or remove flags in a STORE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction {
    /// `+FLAGS` — add the given flags.
    Add,
    /// `-FLAGS` — remove the given flags.
    Remove,
}
```

- [ ] **Step 2: Add `BatchTooLarge` variant to `error.rs`**

Add a new variant to the `Error` enum (after the `Audit` variant, before the closing `}`):

```rust
    /// Caller passed more UIDs than the per-command batch limit.
    #[error("ERR_BATCH_TOO_LARGE: {count} UIDs exceeds limit of {limit}")]
    BatchTooLarge {
        /// Number of UIDs the caller provided.
        count: usize,
        /// Maximum UIDs allowed per command.
        limit: usize,
    },
```

- [ ] **Step 3: Update the `From<Error> for RimapError` impl in `error.rs`**

Add the new variant to the match in the `From` impl:

```rust
            Error::BatchTooLarge { .. } => ErrorCode::InvalidInput,
```

- [ ] **Step 4: Update the exhaustive match in `connection.rs` `fetch_body`**

In `connection.rs`, the `should_invalidate` match (around line 523) lists every `Error` variant explicitly. Add `Error::BatchTooLarge { .. }` to the false arm alongside `Error::InvalidInput { .. }`:

```rust
            Err(
                Error::Tls { .. }
                | Error::TlsHandshake(_)
                | Error::Connect(_)
                | Error::Timeout { .. }
                | Error::Auth { .. }
                | Error::Protocol(_)
                | Error::InvalidInput { .. }
                | Error::BatchTooLarge { .. }
                | Error::Audit { .. },
            )
            | Ok(_) => false,
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile, no warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/types.rs crates/rimap-imap/src/error.rs crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): add FlagAction enum and BatchTooLarge error variant"
```

---

### Task 2: Implement STORE op

**Files:**
- Create: `crates/rimap-imap/src/ops/store.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`

- [ ] **Step 1: Create `ops/store.rs` with the store function**

```rust
//! UID STORE: add or remove flags on messages by UID.

use futures_util::TryStreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{Flag, FlagAction, Uid};

/// Maximum UIDs per STORE command. Enforced defensively; callers
/// should clamp before calling.
const MAX_BATCH: usize = 100;

/// Add or remove `flags` on `uids` in the currently selected folder.
///
/// Returns the UIDs the server confirmed as updated. The server may
/// silently skip non-existent UIDs, so the returned vec can be shorter
/// than `uids`.
///
/// # Errors
///
/// Returns `Error::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates `Error::Protocol` from async-imap on IMAP failures.
pub async fn store(
    session: &mut ImapSession,
    uids: &[Uid],
    flags: &[Flag],
    action: FlagAction,
) -> Result<Vec<Uid>, Error> {
    if uids.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(Vec::new());
    }

    let uid_set = uid_set_string(uids);
    let flag_str = flags_string(flags);
    let query = match action {
        FlagAction::Add => format!("+FLAGS ({flag_str})"),
        FlagAction::Remove => format!("-FLAGS ({flag_str})"),
    };

    let fetches = session
        .uid_store(&uid_set, &query)
        .await
        .map_err(Error::Protocol)?;

    let items: Vec<_> = fetches
        .try_collect()
        .await
        .map_err(Error::Protocol)?;

    let mut updated = Vec::with_capacity(items.len());
    for item in &items {
        if let Some(uid_val) = item.uid {
            if let Some(uid) = Uid::new(uid_val) {
                updated.push(uid);
            }
        }
    }

    Ok(updated)
}

/// Format UIDs as a comma-separated set for IMAP commands.
fn uid_set_string(uids: &[Uid]) -> String {
    let mut s = String::new();
    for (i, uid) in uids.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&uid.get().to_string());
    }
    s
}

/// Format flags as space-separated IMAP flag atoms.
fn flags_string(flags: &[Flag]) -> String {
    let mut s = String::new();
    for (i, flag) in flags.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        match flag {
            Flag::Seen => s.push_str("\\Seen"),
            Flag::Answered => s.push_str("\\Answered"),
            Flag::Flagged => s.push_str("\\Flagged"),
            Flag::Deleted => s.push_str("\\Deleted"),
            Flag::Draft => s.push_str("\\Draft"),
            Flag::Recent => s.push_str("\\Recent"),
            Flag::Keyword(k) => s.push_str(k),
        }
    }
    s
}
```

- [ ] **Step 2: Wire the module in `ops/mod.rs`**

Add to `crates/rimap-imap/src/ops/mod.rs`:

```rust
pub mod store;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/ops/store.rs crates/rimap-imap/src/ops/mod.rs
git commit -m "feat(imap): implement UID STORE op for flag manipulation"
```

---

### Task 3: Add `store_flags` method to `Connection`

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 1: Add `store_flags` method**

Add after the `fetch_body` method (after line 541), following the existing pattern of timeout + invalidate-on-connection-lost:

```rust
    /// `UID STORE` — add or remove flags on messages.
    ///
    /// Batch limit: ≤100 UIDs. Returns the UIDs the server confirmed.
    ///
    /// # Errors
    /// Returns `Error::BatchTooLarge` if more than 100 UIDs are passed.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn store_flags(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        flags: &[crate::types::Flag],
        action: crate::types::FlagAction,
    ) -> Result<Vec<crate::types::Uid>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("store", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            // SELECT the folder first so STORE targets the right mailbox.
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::store::store(session, uids, flags, action).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): add store_flags method to Connection"
```

---

### Task 4: Implement MOVE op

**Files:**
- Create: `crates/rimap-imap/src/ops/move_msg.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`
- Modify: `crates/rimap-imap/src/types.rs`

- [ ] **Step 1: Add `MoveResult` to `types.rs`**

Add after the `FlagAction` enum:

```rust
/// Result of moving a single message. `new_uid` is `None` when the
/// server lacks UIDPLUS or when using the COPY+DELETE fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveResult {
    /// UID in the source folder (before the move).
    pub old_uid: Uid,
    /// UID in the destination folder (after the move). `None` if the
    /// server does not report it (no UIDPLUS, or COPY+DELETE fallback).
    pub new_uid: Option<Uid>,
}
```

- [ ] **Step 2: Create `ops/move_msg.rs`**

```rust
//! UID MOVE with COPY+DELETE fallback for servers without the MOVE
//! extension (RFC 6851).

use futures_util::TryStreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::ops::store;
use crate::types::{Flag, FlagAction, MoveResult, Uid};

/// Maximum UIDs per MOVE command.
const MAX_BATCH: usize = 100;

/// Move `uids` from the currently selected folder to `dest_folder`.
///
/// Tries the MOVE extension first. If the server lacks MOVE capability,
/// falls back to COPY + STORE \Deleted + EXPUNGE.
///
/// The MOVE extension path is atomic; the fallback is not — if the
/// EXPUNGE fails after COPY+STORE, duplicates may exist. This is
/// documented in the tool response.
///
/// # Errors
///
/// Returns `Error::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates `Error::Protocol` from async-imap on IMAP failures.
pub async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
) -> Result<Vec<MoveResult>, Error> {
    if uids.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(Vec::new());
    }

    let uid_set = store::uid_set_string(uids);

    // Try MOVE first; fall back to COPY+DELETE if the server rejects it.
    let move_result = session
        .uid_mv(&uid_set, dest_folder)
        .await;

    match move_result {
        Ok(()) => {
            // MOVE succeeded. async-imap's uid_mv returns () — no
            // UIDPLUS data is exposed. Report new_uid as None.
            Ok(uids
                .iter()
                .map(|&uid| MoveResult {
                    old_uid: uid,
                    new_uid: None,
                })
                .collect())
        }
        Err(e) => {
            // Check if the error is "unknown command" or similar,
            // indicating MOVE is unsupported. Otherwise propagate.
            let msg = e.to_string();
            if msg.contains("BAD")
                || msg.contains("unknown command")
                || msg.contains("not supported")
            {
                copy_delete_fallback(session, dest_folder, uids)
                    .await
            } else {
                Err(Error::Protocol(e))
            }
        }
    }
}

/// Fallback: COPY + STORE \Deleted + EXPUNGE. Not atomic.
async fn copy_delete_fallback(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
) -> Result<Vec<MoveResult>, Error> {
    let uid_set = store::uid_set_string(uids);

    // Step 1: COPY to destination.
    session
        .uid_copy(&uid_set, dest_folder)
        .await
        .map_err(Error::Protocol)?;

    // Step 2: STORE +FLAGS \Deleted on the originals.
    store::store(
        session,
        uids,
        &[Flag::Deleted],
        FlagAction::Add,
    )
    .await?;

    // Step 3: EXPUNGE to remove deleted messages. The stream yields
    // sequence numbers of expunged messages; we drain it to completion.
    let expunge_stream = session.expunge().await.map_err(Error::Protocol)?;
    let _: Vec<_> = expunge_stream
        .try_collect()
        .await
        .map_err(Error::Protocol)?;

    Ok(uids
        .iter()
        .map(|&uid| MoveResult {
            old_uid: uid,
            new_uid: None,
        })
        .collect())
}
```

- [ ] **Step 3: Make `uid_set_string` pub(crate) in `ops/store.rs`**

In `crates/rimap-imap/src/ops/store.rs`, change:

```rust
fn uid_set_string(uids: &[Uid]) -> String {
```

to:

```rust
pub(crate) fn uid_set_string(uids: &[Uid]) -> String {
```

- [ ] **Step 4: Wire the module in `ops/mod.rs`**

Add to `crates/rimap-imap/src/ops/mod.rs`:

```rust
pub mod move_msg;
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/ops/move_msg.rs crates/rimap-imap/src/ops/mod.rs \
  crates/rimap-imap/src/ops/store.rs crates/rimap-imap/src/types.rs
git commit -m "feat(imap): implement UID MOVE op with COPY+DELETE fallback"
```

---

### Task 5: Add `move_messages` method to `Connection`

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 1: Add `move_messages` method**

Add after the `store_flags` method:

```rust
    /// Move messages from `source_folder` to `dest_folder`.
    ///
    /// Uses the IMAP MOVE extension (RFC 6851) when available; falls
    /// back to COPY + STORE \Deleted + EXPUNGE when the server lacks
    /// MOVE support. The fallback is not atomic.
    ///
    /// Batch limit: ≤100 UIDs.
    ///
    /// # Errors
    /// Returns `Error::BatchTooLarge` if more than 100 UIDs are passed.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn move_messages(
        &self,
        source_folder: &str,
        dest_folder: &str,
        uids: &[crate::types::Uid],
    ) -> Result<Vec<crate::types::MoveResult>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("move", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            // SELECT the source folder so MOVE/COPY targets the right mailbox.
            crate::ops::folders::select(session, source_folder, false).await?;
            crate::ops::move_msg::move_messages(session, dest_folder, uids).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): add move_messages method to Connection"
```

---

### Task 6: Implement APPEND op

**Files:**
- Create: `crates/rimap-imap/src/ops/append.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`
- Modify: `crates/rimap-imap/src/types.rs`

- [ ] **Step 1: Add `AppendResult` to `types.rs`**

Add after the `MoveResult` struct:

```rust
/// Result of appending a message to a mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    /// UID assigned by the server. `None` if the server lacks UIDPLUS.
    /// async-imap 0.11's `append()` does not expose the APPENDUID
    /// response code, so this is always `None` for now.
    pub uid: Option<Uid>,
}
```

- [ ] **Step 2: Create `ops/append.rs`**

```rust
//! IMAP APPEND: upload a message to a mailbox.

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{AppendResult, Flag};

/// Append a raw RFC 5322 message to `folder` with the given flags and
/// keywords.
///
/// Keywords are IMAP keyword atoms (e.g. `"$PendingReview"`). They are
/// appended to the flags string alongside system flags.
///
/// # Errors
///
/// Propagates `Error::Protocol` from async-imap on IMAP failures.
pub async fn append(
    session: &mut ImapSession,
    folder: &str,
    message: &[u8],
    flags: &[Flag],
    keywords: &[&str],
) -> Result<AppendResult, Error> {
    let flag_str = build_flags_string(flags, keywords);
    let flags_arg = if flag_str.is_empty() {
        None
    } else {
        Some(format!("({flag_str})"))
    };

    session
        .append(folder, flags_arg.as_deref(), None, message)
        .await
        .map_err(Error::Protocol)?;

    // async-imap 0.11's append() returns () — it does not parse the
    // APPENDUID response code. UID is always None until upstream
    // support or a post-APPEND STATUS+SEARCH workaround.
    Ok(AppendResult { uid: None })
}

/// Build a space-separated flags + keywords string for the APPEND
/// command.
fn build_flags_string(flags: &[Flag], keywords: &[&str]) -> String {
    use crate::ops::store::flags_string;

    let mut s = flags_string(flags);
    for kw in keywords {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(kw);
    }
    s
}
```

- [ ] **Step 3: Make `flags_string` pub(crate) in `ops/store.rs`**

In `crates/rimap-imap/src/ops/store.rs`, change:

```rust
fn flags_string(flags: &[Flag]) -> String {
```

to:

```rust
pub(crate) fn flags_string(flags: &[Flag]) -> String {
```

- [ ] **Step 4: Wire the module in `ops/mod.rs`**

Add to `crates/rimap-imap/src/ops/mod.rs`:

```rust
pub mod append;
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/ops/append.rs crates/rimap-imap/src/ops/mod.rs \
  crates/rimap-imap/src/ops/store.rs crates/rimap-imap/src/types.rs
git commit -m "feat(imap): implement APPEND op for message upload"
```

---

### Task 7: Add `append_message` method to `Connection`

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 1: Add `append_message` method**

Add after the `move_messages` method:

```rust
    /// `APPEND` a raw RFC 5322 message to `folder` with the given flags
    /// and keywords.
    ///
    /// Does NOT select the folder first — APPEND targets a named mailbox
    /// directly per RFC 3501 §6.3.11.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn append_message(
        &self,
        folder: &str,
        message: &[u8],
        flags: &[crate::types::Flag],
        keywords: &[&str],
    ) -> Result<crate::types::AppendResult, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("append", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::append::append(session, folder, message, flags, keywords).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): add append_message method to Connection"
```

---

### Task 8: Update `lib.rs` exports

**Files:**
- Modify: `crates/rimap-imap/src/lib.rs`

- [ ] **Step 1: Re-export new public types**

The new types (`FlagAction`, `MoveResult`, `AppendResult`) are already public in `types.rs`, which is `pub mod types` in `lib.rs`. Users access them via `rimap_imap::types::FlagAction` etc. No additional re-exports needed at the crate root unless the existing pattern re-exports them.

Check: the existing `lib.rs` only re-exports `Connection`, `ConnectionConfig`, `AuthFailure`, `Error`. The types module is public, so users access types directly. No changes needed.

Run: `cargo check --package rimap-imap`
Expected: clean compile.

- [ ] **Step 2: Commit (skip if no changes)**

No commit needed — this is a verification step.

---

### Task 9: Integration tests for STORE

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`
- Modify: `crates/rimap-imap/tests/integration/support/fixtures.rs`

- [ ] **Step 1: Add a fixture helper to seed a test message**

Read `crates/rimap-imap/tests/integration/support/fixtures.rs` first to understand the existing fixture pattern. Then add a helper that creates a minimal RFC 5322 message for seeding via APPEND:

```rust
/// Minimal RFC 5322 message for test seeding.
pub fn minimal_rfc5322(subject: &str) -> Vec<u8> {
    format!(
        "From: test@example.com\r\n\
         To: recipient@example.com\r\n\
         Subject: {subject}\r\n\
         Date: Sat, 12 Apr 2026 12:00:00 +0000\r\n\
         Message-ID: <test-{subject}@example.com>\r\n\
         \r\n\
         Test body for {subject}.\r\n"
    )
    .into_bytes()
}
```

- [ ] **Step 2: Write STORE integration tests**

Add to `dovecot.rs`:

```rust
#[tokio::test]
async fn case_12_store_add_seen_flag() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message via APPEND.
    let msg = support::fixtures::minimal_rfc5322("store-seen");
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .unwrap();

    // Search for it.
    let uids = h.connection
        .search(
            "INBOX",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("store-seen".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];

    // Add \Seen flag.
    let updated = h.connection
        .store_flags(
            "INBOX",
            &[uid],
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Add,
        )
        .await
        .unwrap();
    assert!(updated.contains(&uid));

    // Verify the flag is set.
    let fetched = h.connection
        .fetch(
            "INBOX",
            &[uid],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(flags.contains(&rimap_imap::types::Flag::Seen));
}

#[tokio::test]
async fn case_13_store_remove_seen_flag() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message with \Seen.
    let msg = support::fixtures::minimal_rfc5322("store-unseen");
    h.connection
        .append_message("INBOX", &msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
        .unwrap();

    let uids = h.connection
        .search(
            "INBOX",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("store-unseen".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(!uids.is_empty());
    let uid = uids[0];

    // Remove \Seen flag.
    let updated = h.connection
        .store_flags(
            "INBOX",
            &[uid],
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Remove,
        )
        .await
        .unwrap();
    assert!(updated.contains(&uid));

    // Verify the flag is removed.
    let fetched = h.connection
        .fetch(
            "INBOX",
            &[uid],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(!flags.contains(&rimap_imap::types::Flag::Seen));
}

#[tokio::test]
async fn case_14_store_batch_too_large() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Create 101 fake UIDs.
    let uids: Vec<rimap_imap::types::Uid> = (1..=101)
        .map(|n| rimap_imap::types::Uid::new(n).unwrap())
        .collect();

    let result = h.connection
        .store_flags(
            "INBOX",
            &uids,
            &[rimap_imap::types::Flag::Seen],
            rimap_imap::types::FlagAction::Add,
        )
        .await;

    match result {
        Err(rimap_imap::error::Error::BatchTooLarge { count: 101, limit: 100 }) => {}
        other => panic!("expected BatchTooLarge, got {other:?}"),
    }
}
```

- [ ] **Step 3: Run tests (skip if no Docker)**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo test --package rimap-imap --test integration -- case_12 case_13 case_14`
Expected: all three pass (with Docker) or skip silently (without).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs \
  crates/rimap-imap/tests/integration/support/fixtures.rs
git commit -m "test(imap): integration tests for STORE flag operations"
```

---

### Task 10: Integration tests for MOVE and APPEND

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`

- [ ] **Step 1: Write APPEND integration test**

```rust
#[tokio::test]
async fn case_15_append_message_to_inbox() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    let msg = support::fixtures::minimal_rfc5322("append-test");
    let result = h.connection
        .append_message(
            "INBOX",
            &msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await
        .unwrap();

    // async-imap doesn't expose APPENDUID, so uid is None.
    assert_eq!(result.uid, None);

    // Verify the message is in INBOX by searching for it.
    let uids = h.connection
        .search(
            "INBOX",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("append-test".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(!uids.is_empty(), "appended message not found");

    // Verify it has the \Draft flag.
    let fetched = h.connection
        .fetch(
            "INBOX",
            &[uids[0]],
            rimap_imap::types::FetchSpec {
                flags: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let flags = fetched[0].flags.as_ref().unwrap();
    assert!(flags.contains(&rimap_imap::types::Flag::Draft));
}
```

- [ ] **Step 2: Write MOVE integration test**

```rust
#[tokio::test]
async fn case_16_move_message_between_folders() {
    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };

    // Seed a message in INBOX.
    let msg = support::fixtures::minimal_rfc5322("move-test");
    h.connection
        .append_message("INBOX", &msg, &[], &[])
        .await
        .unwrap();

    let uids = h.connection
        .search(
            "INBOX",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("move-test".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(!uids.is_empty(), "seeded message not found");
    let uid = uids[0];

    // Move to Archive (seeded in Dovecot entrypoint.sh).
    let results = h.connection
        .move_messages("INBOX", "Archive", &[uid])
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].old_uid, uid);

    // Verify the message is gone from INBOX.
    let after_uids = h.connection
        .search(
            "INBOX",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("move-test".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(
        after_uids.is_empty(),
        "message should be gone from INBOX after move"
    );

    // Verify the message is in Archive.
    let archive_uids = h.connection
        .search(
            "Archive",
            rimap_imap::types::SearchQuery::Structured(
                rimap_imap::types::StructuredQuery {
                    subject: Some("move-test".to_string()),
                    ..Default::default()
                },
            ),
        )
        .await
        .unwrap();
    assert!(
        !archive_uids.is_empty(),
        "message should be in Archive after move"
    );
}
```

- [ ] **Step 3: Run tests**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo test --package rimap-imap --test integration -- case_15 case_16`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "test(imap): integration tests for APPEND and MOVE operations"
```

---

### Task 11: `parse_message_async` wrapper in `rimap-server`

**Files:**
- Create: `crates/rimap-server/src/content.rs`
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Create `content.rs`**

```rust
//! Async wrapper for the synchronous `rimap_content::parse_message`.

use rimap_content::{Content, ContentError, parse_message};

/// Run `parse_message` on the blocking threadpool to avoid starving
/// the tokio runtime. `parse_message` is CPU-bound (~2ms per message).
///
/// # Errors
///
/// Returns `ContentError` from the inner call, or
/// `ContentError::Malformed` if the blocking task panicked.
pub async fn parse_message_async(
    raw: Vec<u8>,
) -> Result<Content, ContentError> {
    tokio::task::spawn_blocking(move || parse_message(&raw))
        .await
        .unwrap_or_else(|e| {
            Err(ContentError::Malformed {
                reason: format!("spawn_blocking panicked: {e}"),
            })
        })
}
```

Note: `ContentError` has three variants: `Malformed`, `LimitExceeded`,
`Decoding`. A `JoinError` (task panicked) maps to `Malformed` since the
message could not be processed. Phase 2b may add an `Internal` variant
if needed for other server-side errors.

- [ ] **Step 3: Wire the module in `main.rs`**

Add to `crates/rimap-server/src/main.rs` (in the module declarations):

```rust
mod content;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check --package rimap-server`
Expected: clean compile. If `ContentError` lacks an `Internal` variant, adjust step 1.

- [ ] **Step 5: Write a unit test**

Add to the bottom of `content.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_message_async_matches_sync() {
        let raw = b"From: test@example.com\r\n\
                     Subject: async test\r\n\
                     \r\n\
                     Body.\r\n"
            .to_vec();

        let sync_result = parse_message(&raw).unwrap();
        let async_result = parse_message_async(raw).await.unwrap();

        assert_eq!(sync_result.meta.subject, async_result.meta.subject);
        assert_eq!(
            sync_result.untrusted.body_text,
            async_result.untrusted.body_text
        );
    }
}
```

- [ ] **Step 6: Run the test**

Run: `cargo test --package rimap-server -- content::tests`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/content.rs crates/rimap-server/src/main.rs
git commit -m "feat(server): add parse_message_async spawn_blocking wrapper"
```

---

### Task 12: Run `just ci` and verify

**Files:** none (verification only)

- [ ] **Step 1: Run the full CI suite**

Run: `just ci`
Expected: all tests pass, no warnings, `cargo deny check` clean.

- [ ] **Step 2: Verify test count increased**

The workspace test count should have increased from 459 (Phase 1 end) by the new unit + integration tests added in this phase.

- [ ] **Step 3: Commit any fixups if needed**

If `just ci` reveals issues (e.g., formatting, clippy warnings), fix and commit with `fix:` prefix.
