# Sprint 2b: v2 Protocol Layer — IMAP Ops + SMTP Crate

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the five new IMAP operations (`delete_message`, `expunge`, `create_folder`, `rename_folder`, `delete_folder`) in `rimap-imap` and scaffold the `rimap-smtp` crate with a `lettre`-based SMTP client.

**Architecture:** New IMAP ops follow the existing pattern: `pub(crate) async fn` in `ops/` modules, wrapped by `pub async fn` on `Connection` with timeout + session lock + invalidation. The SMTP crate is a thin `lettre` wrapper with connection management, TLS via `rustls`, and error mapping. No server-layer changes — Sprint 2c handles tool handlers.

**Tech Stack:** Rust, async-imap, lettre (rustls-tls), tokio, futures-util

**Depends on:** Sprint 2a (core types, config, authz changes must be complete)

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `crates/rimap-imap/src/ops/delete.rs` | `delete_message` op (STORE \Deleted + MOVE to Trash) |
| Create | `crates/rimap-imap/src/ops/expunge.rs` | `expunge` op (EXPUNGE on folder) |
| Create | `crates/rimap-imap/src/ops/folder_mgmt.rs` | `create_folder`, `rename_folder`, `delete_folder` ops |
| Modify | `crates/rimap-imap/src/ops/mod.rs` | Register new modules |
| Modify | `crates/rimap-imap/src/connection.rs` | Add 5 wrapper methods |
| Modify | `crates/rimap-imap/src/lib.rs` | Re-export new types if needed |
| Create | `crates/rimap-smtp/Cargo.toml` | New crate manifest |
| Create | `crates/rimap-smtp/src/lib.rs` | Module root |
| Create | `crates/rimap-smtp/src/client.rs` | `SmtpClient` — lettre wrapper |
| Create | `crates/rimap-smtp/src/error.rs` | `SmtpError` enum |
| Modify | `Cargo.toml` | Add `rimap-smtp` to workspace members, add `lettre` dep |

---

## Task 1: IMAP `delete_message` operation

**Files:**
- Create: `crates/rimap-imap/src/ops/delete.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`

- [ ] **Step 1: Register module**

In `crates/rimap-imap/src/ops/mod.rs`, add:

```rust
pub mod delete;
```

- [ ] **Step 2: Create `delete.rs` with the operation**

Create `crates/rimap-imap/src/ops/delete.rs`:

```rust
//! `delete_message`: STORE +FLAGS (\Deleted) + UID MOVE to Trash.

use crate::connection::ImapSession;
use crate::error::Error;
use crate::ops::store;
use crate::types::{Flag, FlagAction, Uid};

/// Delete a message: flag it as `\Deleted` and move it to Trash.
///
/// If the message is already in the Trash folder (case-insensitive match),
/// only the `\Deleted` flag is applied — no move is attempted.
///
/// Caller must SELECT the `source_folder` before calling this function.
///
/// # Errors
///
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn delete_message(
    session: &mut ImapSession,
    uid: Uid,
    source_folder: &str,
    trash_folder: &str,
    has_move: bool,
) -> Result<DeleteResult, Error> {
    // Step 1: STORE +FLAGS (\Deleted)
    store::store(session, &[uid], &[Flag::Deleted], FlagAction::Add).await?;

    // Step 2: If already in Trash, skip the move
    let in_trash = source_folder.eq_ignore_ascii_case(trash_folder);
    if in_trash {
        return Ok(DeleteResult {
            uid,
            moved_to_trash: false,
        });
    }

    // Step 3: Move to Trash
    let uid_set = store::uid_set_string(&[uid]);
    if has_move {
        session
            .uid_mv(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
    } else {
        // Fallback: COPY + EXPUNGE (same pattern as move_msg.rs)
        session
            .uid_copy(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
        // The \Deleted flag was already set in step 1, so EXPUNGE
        // removes this message from the source folder.
        let stream = session.expunge().await.map_err(super::folders::map_err)?;
        futures_util::pin_mut!(stream);
        while let Some(item) = futures_util::StreamExt::next(&mut stream).await {
            let _seq = item.map_err(super::folders::map_err)?;
        }
    }

    Ok(DeleteResult {
        uid,
        moved_to_trash: true,
    })
}

/// Result of a `delete_message` operation.
#[derive(Debug)]
pub struct DeleteResult {
    /// The UID of the deleted message (in its original folder).
    pub uid: Uid,
    /// `true` if the message was moved to Trash; `false` if it was
    /// already in Trash and only flagged.
    pub moved_to_trash: bool,
}
```

- [ ] **Step 3: Run build**

Run: `cargo build -p rimap-imap 2>&1 | head -20`
Expected: compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/ops/delete.rs crates/rimap-imap/src/ops/mod.rs
git commit -m "feat(imap): add delete_message op (STORE \Deleted + MOVE to Trash)"
```

---

## Task 2: IMAP `expunge` operation

**Files:**
- Create: `crates/rimap-imap/src/ops/expunge.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`

- [ ] **Step 1: Register module**

In `crates/rimap-imap/src/ops/mod.rs`, add:

```rust
pub mod expunge;
```

- [ ] **Step 2: Create `expunge.rs`**

Create `crates/rimap-imap/src/ops/expunge.rs`:

```rust
//! EXPUNGE: permanently remove messages flagged as `\Deleted`.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::Uid;

/// Count of `\Deleted`-flagged messages before expunge, for audit logging.
///
/// Issues `UID SEARCH DELETED` on the currently EXAMINEd folder.
///
/// # Errors
///
/// Propagates connection-lost or protocol errors.
pub(crate) async fn count_deleted(
    session: &mut ImapSession,
    folder: &str,
) -> Result<Vec<Uid>, Error> {
    super::folders::select(session, folder, true).await?;
    let mut stream = session
        .uid_search("DELETED")
        .await
        .map_err(super::folders::map_err)?;
    let mut uids = Vec::new();
    while let Some(uid_val) = stream.next().await {
        let uid_val = uid_val.map_err(super::folders::map_err)?;
        if let Some(uid) = Uid::new(uid_val) {
            uids.push(uid);
        }
    }
    Ok(uids)
}

/// Expunge all `\Deleted` messages from `folder`.
///
/// Caller must SELECT the folder in read-write mode before calling.
///
/// Returns the number of messages expunged (sequence numbers from the
/// server's EXPUNGE responses).
///
/// # Errors
///
/// Propagates connection-lost or protocol errors.
pub(crate) async fn expunge(session: &mut ImapSession) -> Result<u32, Error> {
    let stream = session.expunge().await.map_err(super::folders::map_err)?;
    futures_util::pin_mut!(stream);
    let mut count = 0u32;
    while let Some(item) = stream.next().await {
        let _seq = item.map_err(super::folders::map_err)?;
        count = count.saturating_add(1);
    }
    Ok(count)
}
```

- [ ] **Step 3: Run build**

Run: `cargo build -p rimap-imap 2>&1 | head -20`
Expected: compiles cleanly.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/ops/expunge.rs crates/rimap-imap/src/ops/mod.rs
git commit -m "feat(imap): add expunge op with pre-expunge UID SEARCH DELETED"
```

---

## Task 3: IMAP folder management operations

**Files:**
- Create: `crates/rimap-imap/src/ops/folder_mgmt.rs`
- Modify: `crates/rimap-imap/src/ops/mod.rs`

- [ ] **Step 1: Register module**

In `crates/rimap-imap/src/ops/mod.rs`, add:

```rust
pub mod folder_mgmt;
```

- [ ] **Step 2: Create `folder_mgmt.rs`**

Create `crates/rimap-imap/src/ops/folder_mgmt.rs`:

```rust
//! Folder management: CREATE, RENAME, DELETE.

use crate::connection::ImapSession;
use crate::error::Error;

/// Maximum folder name length in bytes.
const MAX_FOLDER_NAME_BYTES: usize = 255;

/// Validate a folder name for CREATE or RENAME target.
///
/// # Errors
///
/// Returns `Error::InvalidInput` for empty names, names exceeding
/// 255 bytes, names containing null bytes, or path traversal attempts.
pub(crate) fn validate_folder_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidInput {
            field: "folder_name",
            reason: "folder name must not be empty",
        });
    }
    if name.len() > MAX_FOLDER_NAME_BYTES {
        return Err(Error::InvalidInput {
            field: "folder_name",
            reason: "folder name exceeds 255 bytes",
        });
    }
    if name.contains('\0') {
        return Err(Error::InvalidInput {
            field: "folder_name",
            reason: "folder name contains null byte",
        });
    }
    if name.contains("..") {
        return Err(Error::InvalidInput {
            field: "folder_name",
            reason: "folder name contains path traversal",
        });
    }
    Ok(())
}

/// CREATE a new mailbox.
///
/// # Errors
///
/// Returns `Error::InvalidInput` for invalid names.
/// Propagates protocol errors from async-imap.
pub(crate) async fn create_folder(
    session: &mut ImapSession,
    name: &str,
) -> Result<(), Error> {
    validate_folder_name(name)?;
    session.create(name).await.map_err(super::folders::map_err)?;
    Ok(())
}

/// RENAME a mailbox.
///
/// # Errors
///
/// Returns `Error::InvalidInput` for invalid `new_name`.
/// Propagates protocol errors from async-imap.
pub(crate) async fn rename_folder(
    session: &mut ImapSession,
    old_name: &str,
    new_name: &str,
) -> Result<(), Error> {
    validate_folder_name(new_name)?;
    session
        .rename(old_name, new_name)
        .await
        .map_err(super::folders::map_err)?;
    Ok(())
}

/// DELETE a mailbox and all its contents.
///
/// # Errors
///
/// Propagates protocol errors from async-imap.
pub(crate) async fn delete_folder(
    session: &mut ImapSession,
    name: &str,
) -> Result<(), Error> {
    session.delete(name).await.map_err(super::folders::map_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_empty_name_rejected() {
        assert!(validate_folder_name("").is_err());
    }

    #[test]
    fn validate_long_name_rejected() {
        let long = "a".repeat(256);
        assert!(validate_folder_name(&long).is_err());
    }

    #[test]
    fn validate_null_byte_rejected() {
        assert!(validate_folder_name("bad\0name").is_err());
    }

    #[test]
    fn validate_traversal_rejected() {
        assert!(validate_folder_name("../escape").is_err());
        assert!(validate_folder_name("a/../b").is_err());
    }

    #[test]
    fn validate_normal_name_accepted() {
        assert!(validate_folder_name("Archives").is_ok());
        assert!(validate_folder_name("Work/Projects").is_ok());
        assert!(validate_folder_name("a".repeat(255).as_str()).is_ok());
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-imap folder_mgmt -- --nocapture`
Expected: all 5 unit tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/ops/folder_mgmt.rs crates/rimap-imap/src/ops/mod.rs
git commit -m "feat(imap): add create_folder, rename_folder, delete_folder ops"
```

---

## Task 4: Add `Connection` wrapper methods for new ops

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

- [ ] **Step 1: Add `delete_message` wrapper**

Add after the `append_message` method:

```rust
    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
    ) -> Result<crate::ops::delete::DeleteResult, Error> {
        let dur = self.inner.cfg.command_timeout;
        let has_move = self.has_move_capability();
        let result = crate::time::with_timeout("delete_message", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::delete::delete_message(
                session,
                uid,
                folder,
                trash_folder,
                has_move,
            )
            .await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 2: Add `expunge` wrapper**

```rust
    /// Expunge all `\Deleted` messages from `folder`.
    ///
    /// Returns `(deleted_uids, expunged_count)` — the UIDs found by
    /// `UID SEARCH DELETED` before the expunge, and the count from the
    /// EXPUNGE response.
    pub async fn expunge(
        &self,
        folder: &str,
    ) -> Result<(Vec<crate::types::Uid>, u32), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("expunge", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            // Pre-expunge audit: count deleted messages
            let deleted_uids =
                crate::ops::expunge::count_deleted(session, folder).await?;
            // SELECT read-write then EXPUNGE
            crate::ops::folders::select(session, folder, false).await?;
            let count = crate::ops::expunge::expunge(session).await?;
            Ok((deleted_uids, count))
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 3: Add `create_folder` wrapper**

```rust
    /// Create a new IMAP folder.
    pub async fn create_folder(&self, name: &str) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("create_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::create_folder(session, name).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 4: Add `rename_folder` wrapper**

```rust
    /// Rename an IMAP folder.
    pub async fn rename_folder(
        &self,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("rename_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::rename_folder(session, old_name, new_name)
                .await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 5: Add `delete_folder` wrapper**

```rust
    /// Delete an IMAP folder and all its contents.
    pub async fn delete_folder(&self, name: &str) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("delete_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::delete_folder(session, name).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }
```

- [ ] **Step 6: Run build**

Run: `cargo build -p rimap-imap 2>&1 | head -20`
Expected: compiles cleanly.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): add Connection wrappers for delete, expunge, folder ops

All wrappers follow the existing pattern: timeout enforcement,
session lock, invalidation on ConnectionLost/Timeout."
```

---

## Task 5: Scaffold `rimap-smtp` crate

**Files:**
- Create: `crates/rimap-smtp/Cargo.toml`
- Create: `crates/rimap-smtp/src/lib.rs`
- Create: `crates/rimap-smtp/src/error.rs`
- Modify: `Cargo.toml` (workspace root)

- [ ] **Step 1: Add `lettre` to workspace dependencies**

In the root `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
lettre = { version = "0.11", default-features = false, features = ["tokio1-rustls-tls", "smtp-transport", "builder"] }
```

Look up the current stable version of `lettre` before pinning — do not rely on the version above. Use the latest stable release.

- [ ] **Step 2: Add `rimap-smtp` to workspace members**

In the root `Cargo.toml`, add to `[workspace] members`:

```toml
    "crates/rimap-smtp",
```

- [ ] **Step 3: Create `crates/rimap-smtp/Cargo.toml`**

```toml
[package]
name = "rimap-smtp"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
readme.workspace = true
description = "SMTP client for rusty-imap-mcp — lettre wrapper with TLS and error mapping"

[lints]
workspace = true

[dependencies]
rimap-core = { path = "../rimap-core", version = "0.0.0" }
rimap-config = { path = "../rimap-config", version = "0.0.0" }

lettre = { workspace = true }
tokio = { workspace = true }
thiserror = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util", "macros"] }
```

- [ ] **Step 4: Create `crates/rimap-smtp/src/error.rs`**

```rust
//! SMTP error type and conversion to `RimapError`.

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-smtp`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SmtpError {
    /// Cannot reach the SMTP server.
    #[error("SMTP connection failed: {0}")]
    Connection(String),
    /// SMTP authentication failed.
    #[error("SMTP authentication failed")]
    Auth(#[source] lettre::transport::smtp::Error),
    /// TLS handshake failed.
    #[error("SMTP TLS handshake failed")]
    Tls(#[source] lettre::transport::smtp::Error),
    /// Server rejected the message (4xx/5xx).
    #[error("SMTP send rejected: {reason}")]
    Rejected {
        /// Server response reason.
        reason: String,
    },
    /// SMTP command timed out.
    #[error("SMTP operation timed out")]
    Timeout,
    /// Catch-all for other lettre errors.
    #[error("SMTP error: {0}")]
    Transport(#[source] lettre::transport::smtp::Error),
}

impl From<SmtpError> for RimapError {
    fn from(err: SmtpError) -> Self {
        let code = match &err {
            SmtpError::Connection(_) => ErrorCode::ConnectionLost,
            SmtpError::Auth(_) => ErrorCode::Auth,
            SmtpError::Tls(_) => ErrorCode::Tls,
            SmtpError::Rejected { .. } => ErrorCode::ImapProtocol,
            SmtpError::Timeout => ErrorCode::Timeout,
            SmtpError::Transport(_) => ErrorCode::Internal,
        };
        let message = err.to_string();
        RimapError::Imap {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
```

- [ ] **Step 5: Create `crates/rimap-smtp/src/lib.rs`**

```rust
//! SMTP client for rusty-imap-mcp.
//!
//! Thin wrapper around `lettre` providing connection management,
//! TLS via `rustls`, and error mapping. Does not construct messages —
//! message building is handled by the server layer.

#![deny(missing_docs)]

pub mod client;
pub mod error;

pub use crate::client::SmtpClient;
pub use crate::error::SmtpError;
```

- [ ] **Step 6: Create `crates/rimap-smtp/src/client.rs` (initial scaffold)**

```rust
//! `SmtpClient` — one-shot SMTP send via `lettre`.

use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rimap_config::model::{SmtpConfig, SmtpEncryption};

use crate::error::SmtpError;

/// SMTP client built from config. Each `send()` call opens a fresh
/// connection — no persistent session or connection pool.
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpClient {
    /// Build from validated SMTP config and a resolved password.
    ///
    /// # Errors
    ///
    /// Returns `SmtpError::Connection` if the transport cannot be built.
    pub fn new(config: &SmtpConfig, password: &str) -> Result<Self, SmtpError> {
        let creds = Credentials::new(
            config.username.clone(),
            password.to_string(),
        );
        let timeout = Duration::from_secs(u64::from(config.command_timeout_seconds));

        let builder = match config.encryption {
            SmtpEncryption::Tls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                    .map_err(|e| SmtpError::Connection(e.to_string()))?
                    .port(config.port)
            }
            SmtpEncryption::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(|e| SmtpError::Connection(e.to_string()))?
                    .port(config.port)
            }
            SmtpEncryption::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .port(config.port)
            }
        };

        let transport = builder
            .credentials(creds)
            .timeout(Some(timeout))
            .build();

        Ok(Self { transport })
    }

    /// Send a pre-built message via SMTP.
    ///
    /// Returns the SMTP response string on success (typically "250 OK").
    ///
    /// # Errors
    ///
    /// Returns `SmtpError` variants for auth, TLS, rejection, timeout,
    /// or transport failures. SMTP server banners and detailed rejection
    /// reasons are captured in the error but should NOT be forwarded to
    /// MCP clients — log them to audit only.
    pub async fn send(
        &self,
        message: &lettre::Message,
    ) -> Result<String, SmtpError> {
        let response = self
            .transport
            .send(message.clone())
            .await
            .map_err(classify_smtp_error)?;
        Ok(format!("{} {}", response.code(), response.message().collect::<Vec<_>>().join(" ")))
    }
}

/// Classify a lettre SMTP error into our error taxonomy.
fn classify_smtp_error(err: lettre::transport::smtp::Error) -> SmtpError {
    if err.is_response() {
        SmtpError::Rejected {
            reason: err.to_string(),
        }
    } else if err.is_client() {
        SmtpError::Connection(err.to_string())
    } else if err.is_transient() {
        SmtpError::Transport(err)
    } else {
        SmtpError::Transport(err)
    }
}

#[cfg(test)]
mod tests {
    use rimap_config::model::{SmtpConfig, SmtpEncryption};

    use super::SmtpClient;

    fn test_config() -> SmtpConfig {
        SmtpConfig {
            host: "localhost".into(),
            port: 1025,
            encryption: SmtpEncryption::None,
            username: "test@example.com".into(),
            command_timeout_seconds: 5,
            connect_timeout_seconds: 5,
        }
    }

    #[test]
    fn client_builds_with_no_encryption() {
        let client = SmtpClient::new(&test_config(), "password");
        assert!(client.is_ok());
    }
}
```

- [ ] **Step 7: Run build and tests**

Run: `cargo build -p rimap-smtp && cargo test -p rimap-smtp -- --nocapture`
Expected: builds cleanly, unit test passes.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml crates/rimap-smtp/
git commit -m "feat: scaffold rimap-smtp crate with lettre-based SmtpClient

New workspace member wrapping lettre for SMTP sending. Supports
STARTTLS (587), implicit TLS (465), and plaintext (testing).
One-shot connections, no pooling, no retry."
```

---

## Task 6: Add IMAP integration tests for new ops

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`

These tests extend the existing Dovecot integration suite. They run against a real Dovecot instance in Podman and are skipped if Podman is unavailable.

- [ ] **Step 1: Add `delete_message` integration test**

Add a new test case in `crates/rimap-imap/tests/integration/dovecot.rs`:

```rust
/// delete_message: flag + move to Trash, verify UID in Trash.
#[tokio::test]
async fn case_17_delete_message() {
    let Some(h) = boot(PinChoice::None).await else {
        return;
    };
    // Append a test message to INBOX
    let msg = fixtures::simple_message("delete-test@example.com", "Delete me");
    let append = h.conn.append_message("INBOX", &msg, &[], &[]).await.unwrap();
    let uid = append.uid.unwrap();

    // Create Trash folder (Dovecot may not have it by default)
    let _ = h.conn.create_folder("Trash").await;

    // Delete it
    let result = h.conn.delete_message("INBOX", uid, "Trash").await.unwrap();
    assert!(result.moved_to_trash);

    // Verify it's gone from INBOX
    let search = h.conn.search("INBOX", SearchQuery::all()).await.unwrap();
    assert!(!search.contains(&uid));

    // Verify it's in Trash
    let trash_search = h.conn.search("Trash", SearchQuery::all()).await.unwrap();
    assert!(!trash_search.is_empty());
}
```

- [ ] **Step 2: Add `expunge` integration test**

```rust
/// expunge: delete + expunge, verify message is gone.
#[tokio::test]
async fn case_18_expunge() {
    let Some(h) = boot(PinChoice::None).await else {
        return;
    };
    let _ = h.conn.create_folder("Trash").await;

    // Append a message directly to Trash
    let msg = fixtures::simple_message("expunge-test@example.com", "Expunge me");
    let append = h.conn.append_message("Trash", &msg, &[], &[]).await.unwrap();
    let uid = append.uid.unwrap();

    // Flag as \Deleted
    h.conn
        .store_flags("Trash", &[uid], &[Flag::Deleted], FlagAction::Add)
        .await
        .unwrap();

    // Expunge
    let (deleted_uids, count) = h.conn.expunge("Trash").await.unwrap();
    assert!(!deleted_uids.is_empty());
    assert!(count > 0);

    // Verify it's gone
    let search = h.conn.search("Trash", SearchQuery::all()).await.unwrap();
    assert!(!search.contains(&uid));
}
```

- [ ] **Step 3: Add folder management integration test**

```rust
/// create_folder + rename_folder + delete_folder round-trip.
#[tokio::test]
async fn case_19_folder_management() {
    let Some(h) = boot(PinChoice::None).await else {
        return;
    };

    // Create
    h.conn.create_folder("TestFolder").await.unwrap();
    let folders = h.conn.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name == "TestFolder"));

    // Rename
    h.conn.rename_folder("TestFolder", "RenamedFolder").await.unwrap();
    let folders = h.conn.list_folders("*").await.unwrap();
    assert!(folders.iter().any(|f| f.name == "RenamedFolder"));
    assert!(!folders.iter().any(|f| f.name == "TestFolder"));

    // Delete
    h.conn.delete_folder("RenamedFolder").await.unwrap();
    let folders = h.conn.list_folders("*").await.unwrap();
    assert!(!folders.iter().any(|f| f.name == "RenamedFolder"));
}
```

- [ ] **Step 4: Run integration tests**

Run: `cargo test -p rimap-imap --test dovecot -- case_17 case_18 case_19 --nocapture`
Expected: all 3 tests pass (or skip if Podman is unavailable).

Note: these tests may need adjustments based on the exact integration harness helpers available (`boot`, `fixtures`, `SearchQuery::all`, `PinChoice`, `Flag`, `FlagAction`). Read the test imports and adapt the code to match the existing test infrastructure.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "test(imap): add integration tests for delete, expunge, folder ops

Tests run against Dovecot in Podman. Skipped when container
runtime is unavailable."
```

---

## Task 7: Final verification and lint

- [ ] **Step 1: Run full CI locally**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: clean.

- [ ] **Step 2: Run cargo deny**

Run: `cargo deny check 2>&1 | tail -20`
Expected: `lettre` passes advisory, license, and ban checks.

- [ ] **Step 3: Fix any issues and commit**

```bash
git add -u
git commit -m "fix: address lint and deny issues from Sprint 2b"
```
