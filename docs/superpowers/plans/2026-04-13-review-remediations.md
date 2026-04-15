# Sprint 2b Review Remediations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Address all findings from the Sprint 2b security reviews (IMAP security, Rust safety, supply chain, local security). Covers F1–F12 across HIGH, MEDIUM, and LOW severity.

**Architecture:** Seven tasks targeting four crates. Tasks 1–2 fix the high-severity delete_message fallback (UID EXPUNGE + UIDPLUS capability tracking). Task 3 hardens folder name validation. Task 4 fixes the SMTP error taxonomy and message redaction. Task 5 removes the phantom `connect_timeout_seconds` config field. Task 6 replaces `unreachable!()` with fallible error returns. Task 7 adds the `clippy::unreachable` deny lint and runs final verification.

**Tech Stack:** Rust, async-imap (`uid_expunge`), rimap-core (`ErrorCode`/`RimapError`), rimap-smtp (`SmtpError`), rimap-config (`SmtpConfig`)

**Depends on:** Sprint 2b (commit `8c49895`) must be complete.

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-imap/src/connection.rs` | Add `has_uidplus` capability tracking + replace `unreachable!()` |
| Modify | `crates/rimap-imap/src/ops/delete.rs` | Use `uid_expunge` in fallback, validate folder params |
| Modify | `crates/rimap-imap/src/ops/move_msg.rs` | Use `uid_expunge` in fallback |
| Modify | `crates/rimap-imap/src/ops/folder_mgmt.rs` | Reject control chars, validate all params |
| Modify | `crates/rimap-imap/src/ops/expunge.rs` | Validate folder param |
| Modify | `crates/rimap-core/src/error.rs` | Add `SmtpProtocol` error code, `Smtp` variant on `RimapError` |
| Modify | `crates/rimap-smtp/src/error.rs` | Redact server strings in `From<SmtpError>`, use `RimapError::Smtp` |
| Modify | `crates/rimap-config/src/model.rs` | Remove `connect_timeout_seconds` from `SmtpConfig` |
| Modify | `crates/rimap-config/src/validate.rs` | Remove `connect_timeout_seconds` validation |
| Modify | `crates/rimap-smtp/src/client.rs` | Remove `connect_timeout_seconds` from test config |
| Modify | `Cargo.toml` | Add `clippy::unreachable = "deny"` to workspace lints |

---

## Task 1: Add UIDPLUS capability tracking to Connection

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

The `Connection` already tracks `has_move` via `AtomicBool` set during `imap_login`. Add the same pattern for `UIDPLUS` (RFC 4315), which gates `UID EXPUNGE` availability.

- [ ] **Step 1: Add `has_uidplus` field to `ConnectionInner`**

In `crates/rimap-imap/src/connection.rs`, add a new `AtomicBool` field after `has_move` (line 79):

```rust
    /// Server advertised UIDPLUS capability (RFC 4315) after login.
    /// Reset to `false` on `invalidate()`.
    has_uidplus: AtomicBool,
```

Initialize it in `Connection::new` (after `has_move: AtomicBool::new(false)` on line 106):

```rust
                has_uidplus: AtomicBool::new(false),
```

- [ ] **Step 2: Add public accessor**

After `has_move_capability()` (line 134):

```rust
    /// Whether the server advertised the UIDPLUS capability (RFC 4315).
    #[must_use]
    pub fn has_uidplus_capability(&self) -> bool {
        self.inner.has_uidplus.load(Ordering::Relaxed)
    }
```

- [ ] **Step 3: Combine UIDPLUS probe with existing MOVE probe**

In `imap_login`, replace the existing MOVE probe block (lines 317–329) with a combined check that avoids a second round-trip:

```rust
        // Post-login: probe CAPABILITY for MOVE (RFC 6851) and
        // UIDPLUS (RFC 4315).
        let (has_move, has_uidplus) = match session.capabilities().await {
            Ok(caps) => (caps.has_str("MOVE"), caps.has_str("UIDPLUS")),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; \
                     assuming no MOVE/UIDPLUS support",
                );
                (false, false)
            }
        };
        self.inner.has_move.store(has_move, Ordering::Relaxed);
        self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);
```

- [ ] **Step 4: Reset on invalidate**

In `invalidate()` (after `has_move.store(false, ...)` on line 140):

```rust
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
```

- [ ] **Step 5: Pass `has_uidplus` to `delete_message` wrapper**

In the `delete_message` wrapper method (line 677–698), read the flag alongside `has_move`:

```rust
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
```

And pass both to the op:

```rust
            crate::ops::delete::delete_message(
                session,
                uid,
                folder,
                trash_folder,
                has_move,
                has_uidplus,
            )
            .await
```

- [ ] **Step 6: Pass `has_uidplus` to `move_messages` wrapper**

In the `move_messages` wrapper method (line 615–636), read the flag alongside `has_move`:

```rust
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
```

And pass both:

```rust
            crate::ops::move_msg::move_messages(
                session, dest_folder, uids, has_move, has_uidplus,
            )
            .await
```

- [ ] **Step 7: Build (expect errors — ops not updated yet)**

Run: `cargo build -p rimap-imap 2>&1 | head -5`
Expected: compile errors in delete.rs and move_msg.rs about wrong number of arguments. This is correct — Task 2 fixes them.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "feat(imap): track UIDPLUS capability for UID EXPUNGE support

Probes UIDPLUS alongside MOVE during post-login CAPABILITY check.
Passes both flags to delete_message and move_messages ops."
```

---

## Task 2: Use UID EXPUNGE in delete_message and move_msg fallback paths

**Files:**
- Modify: `crates/rimap-imap/src/ops/delete.rs`
- Modify: `crates/rimap-imap/src/ops/move_msg.rs`

This fixes HIGH-severity F1: overbroad `EXPUNGE` nuking all `\Deleted` messages in the folder. When the server supports UIDPLUS (RFC 4315), use `session.uid_expunge()` to scope the expunge to the target UID(s). async-imap 0.11 exposes `uid_expunge(uid_set: &str) -> Stream<Item = Result<Uid>>`.

- [ ] **Step 1: Update `delete_message` signature**

In `crates/rimap-imap/src/ops/delete.rs`, add `has_uidplus: bool` parameter:

```rust
pub(crate) async fn delete_message(
    session: &mut ImapSession,
    uid: Uid,
    source_folder: &str,
    trash_folder: &str,
    has_move: bool,
    has_uidplus: bool,
) -> Result<DeleteResult, Error> {
```

- [ ] **Step 2: Replace overbroad EXPUNGE with UID EXPUNGE when available**

Replace the entire `else` block (current lines 46–58) with:

```rust
    } else {
        // Fallback: COPY + scoped EXPUNGE.
        session
            .uid_copy(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
        // The \Deleted flag was already set in step 1.
        if has_uidplus {
            // UID EXPUNGE (RFC 4315): only expunge this specific UID.
            let stream = session
                .uid_expunge(&uid_set)
                .await
                .map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _uid = item.map_err(super::folders::map_err)?;
            }
        } else {
            // Plain EXPUNGE: removes ALL \Deleted messages in the folder.
            // This is a known data-loss risk when other messages are
            // concurrently flagged \Deleted. Servers without both MOVE
            // and UIDPLUS are rare in practice.
            let stream = session
                .expunge()
                .await
                .map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _seq = item.map_err(super::folders::map_err)?;
            }
        }
    }
```

- [ ] **Step 3: Update `move_messages` signature**

In `crates/rimap-imap/src/ops/move_msg.rs`, add `has_uidplus: bool`:

```rust
pub async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_move: bool,
    has_uidplus: bool,
) -> Result<MoveOutcome, Error> {
```

Pass it to the fallback call:

```rust
    if !has_move {
        let results =
            copy_delete_fallback(session, dest_folder, uids, has_uidplus).await?;
```

- [ ] **Step 4: Update `copy_delete_fallback` to use UID EXPUNGE**

Add `has_uidplus: bool` parameter:

```rust
async fn copy_delete_fallback(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_uidplus: bool,
) -> Result<Vec<MoveResult>, Error> {
```

Replace the EXPUNGE block (current lines 100–107) with:

```rust
    // Step 3: Remove the flagged messages from the source folder.
    if has_uidplus {
        // UID EXPUNGE (RFC 4315): only expunge the UIDs we flagged.
        let uid_set = store::uid_set_string(uids);
        let stream = session
            .uid_expunge(&uid_set)
            .await
            .map_err(super::folders::map_err)?;
        futures_util::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let _uid = item.map_err(super::folders::map_err)?;
        }
    } else {
        // Plain EXPUNGE: removes ALL \Deleted messages. Known data-loss
        // risk with concurrent \Deleted flags. Servers without both MOVE
        // and UIDPLUS are rare in practice.
        let stream = session.expunge().await.map_err(super::folders::map_err)?;
        futures_util::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let _seq = item.map_err(super::folders::map_err)?;
        }
    }
```

- [ ] **Step 5: Build and test**

Run: `cargo build -p rimap-imap 2>&1 | head -20`
Expected: compiles cleanly.

Run: `cargo test -p rimap-imap -- --nocapture 2>&1 | tail -10`
Expected: all unit tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/ops/delete.rs crates/rimap-imap/src/ops/move_msg.rs
git commit -m "fix(imap): use UID EXPUNGE to scope fallback deletion to target UIDs

When the server advertises UIDPLUS (RFC 4315), the COPY+EXPUNGE
fallback in delete_message and move_messages now uses UID EXPUNGE
instead of plain EXPUNGE. This prevents collateral deletion of
other messages flagged as Deleted in the same folder.

Plain EXPUNGE remains as a last-resort fallback when neither MOVE
nor UIDPLUS is available, with a documented data-loss warning."
```

---

## Task 3: Harden folder name validation

**Files:**
- Modify: `crates/rimap-imap/src/ops/folder_mgmt.rs`
- Modify: `crates/rimap-imap/src/ops/delete.rs`
- Modify: `crates/rimap-imap/src/ops/expunge.rs`

Fixes F2 (trash_folder/source_folder not validated), F3 (rename_folder old_name not validated, delete_folder name not validated), F4 (control characters not rejected).

- [ ] **Step 1: Add control character rejection to `validate_folder_name`**

In `crates/rimap-imap/src/ops/folder_mgmt.rs`, replace the null-byte check (lines 27–31) with a broader control character check that subsumes it:

```rust
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(Error::InvalidInput {
            field: "folder_name",
            reason: "folder name contains control characters",
        });
    }
```

- [ ] **Step 2: Add validation to `rename_folder` for `old_name`**

In `rename_folder`, add before the existing `validate_folder_name(new_name)?;`:

```rust
    validate_folder_name(old_name)?;
```

Update the doc comment:

```rust
/// RENAME a mailbox.
///
/// # Errors
///
/// Returns `Error::InvalidInput` for invalid `old_name` or `new_name`.
/// Propagates protocol errors from async-imap.
```

- [ ] **Step 3: Add validation to `delete_folder`**

In `delete_folder`, add before the `session.delete(name)` call:

```rust
    validate_folder_name(name)?;
```

Update the doc comment:

```rust
/// DELETE a mailbox and all its contents.
///
/// # Errors
///
/// Returns `Error::InvalidInput` for invalid names.
/// Propagates protocol errors from async-imap.
```

- [ ] **Step 4: Validate folder params in `delete_message`**

In `crates/rimap-imap/src/ops/delete.rs`, add validation at the top of `delete_message` (before the STORE step):

```rust
    super::folder_mgmt::validate_folder_name(source_folder)?;
    super::folder_mgmt::validate_folder_name(trash_folder)?;
```

- [ ] **Step 5: Validate folder param in `count_deleted`**

In `crates/rimap-imap/src/ops/expunge.rs`, add validation at the top of `count_deleted`:

```rust
    super::folder_mgmt::validate_folder_name(folder)?;
```

- [ ] **Step 6: Update unit tests**

In `crates/rimap-imap/src/ops/folder_mgmt.rs`, replace the `validate_null_byte_rejected` test with a broader test:

```rust
    #[test]
    fn validate_control_characters_rejected() {
        assert!(validate_folder_name("bad\0name").is_err());
        assert!(validate_folder_name("bad\r\nname").is_err());
        assert!(validate_folder_name("bad\x01name").is_err());
        assert!(validate_folder_name("bad\x7fname").is_err());
    }
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p rimap-imap folder_mgmt -- --nocapture`
Expected: all tests pass including the updated control character test.

- [ ] **Step 8: Build workspace**

Run: `cargo build --workspace 2>&1 | tail -5`
Expected: compiles cleanly.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-imap/src/ops/folder_mgmt.rs crates/rimap-imap/src/ops/delete.rs crates/rimap-imap/src/ops/expunge.rs
git commit -m "fix(imap): harden folder name validation

- Reject all control characters (0x00-0x1f, 0x7f), not just null
- Validate old_name in rename_folder and name in delete_folder
- Validate source_folder and trash_folder in delete_message
- Validate folder in count_deleted"
```

---

## Task 4: Fix SMTP error taxonomy and redact server strings

**Files:**
- Modify: `crates/rimap-core/src/error.rs`
- Modify: `crates/rimap-smtp/src/error.rs`

Fixes F5 (server banner leakage in MCP responses), F6 (SMTP errors misclassified as `RimapError::Imap`), F8 (SmtpError::Rejected mapped to `ErrorCode::ImapProtocol`).

- [ ] **Step 1: Add `SmtpProtocol` error code**

In `crates/rimap-core/src/error.rs`, add after `ImapProtocol` (line 23):

```rust
    /// SMTP server rejected message or command.
    SmtpProtocol,
```

Add the wire string in `as_str()` after the `ImapProtocol` arm:

```rust
            Self::SmtpProtocol => "ERR_SMTP_PROTOCOL",
```

- [ ] **Step 2: Add `Smtp` variant to `RimapError`**

In `crates/rimap-core/src/error.rs`, add after the `Imap` variant (after line 98):

```rust
    /// SMTP-layer failure (connection, auth, TLS, rejection, timeout).
    #[error("{code}: {message}")]
    Smtp {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message (redacted — no server banners).
        message: String,
        /// Underlying source error, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    },
```

- [ ] **Step 3: Update `RimapError::code()` accessor**

In the `code()` match, add the `Smtp` variant:

```rust
            Self::Authz { code, .. }
            | Self::Imap { code, .. }
            | Self::Smtp { code, .. }
            | Self::Audit { code, .. } => *code,
```

- [ ] **Step 4: Update `ErrorCode` exhaustive test**

In the `every_error_code_has_stable_string` test, add:

```rust
            (ErrorCode::SmtpProtocol, "ERR_SMTP_PROTOCOL"),
```

- [ ] **Step 5: Run rimap-core tests**

Run: `cargo test -p rimap-core -- --nocapture`
Expected: all tests pass.

- [ ] **Step 6: Update `From<SmtpError> for RimapError` with redaction**

In `crates/rimap-smtp/src/error.rs`, replace the entire `impl From<SmtpError> for RimapError`:

```rust
impl From<SmtpError> for RimapError {
    fn from(err: SmtpError) -> Self {
        let (code, message) = match &err {
            SmtpError::Connection(_) => (
                ErrorCode::ConnectionLost,
                "SMTP connection failed".to_string(),
            ),
            SmtpError::Auth(_) => (
                ErrorCode::Auth,
                "SMTP authentication failed".to_string(),
            ),
            SmtpError::Tls(_) => (
                ErrorCode::Tls,
                "SMTP TLS handshake failed".to_string(),
            ),
            SmtpError::Rejected { .. } => (
                ErrorCode::SmtpProtocol,
                "SMTP server rejected the message".to_string(),
            ),
            SmtpError::Timeout => (
                ErrorCode::Timeout,
                "SMTP operation timed out".to_string(),
            ),
            SmtpError::Transport(_) => (
                ErrorCode::Internal,
                "SMTP transport error".to_string(),
            ),
        };
        RimapError::Smtp {
            code,
            message,
            source: Some(Box::new(err)),
        }
    }
}
```

- [ ] **Step 7: Build and test**

Run: `cargo build -p rimap-smtp && cargo test -p rimap-smtp -- --nocapture`
Expected: compiles cleanly, existing test passes.

Run: `cargo build --workspace 2>&1 | tail -5`
Expected: workspace compiles. If `rimap-server` matches on `RimapError` variants exhaustively, add the `Smtp` arm following the same pattern as `Imap`.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-core/src/error.rs crates/rimap-smtp/src/error.rs
git commit -m "fix(smtp): add Smtp error variant and redact server strings

- Add ErrorCode::SmtpProtocol and RimapError::Smtp variant so SMTP
  failures are not misclassified as IMAP errors in audit logs
- Redact server banners and rejection details in the From<SmtpError>
  conversion — full details preserved in source chain for audit"
```

---

## Task 5: Remove phantom `connect_timeout_seconds` from SmtpConfig

**Files:**
- Modify: `crates/rimap-config/src/model.rs`
- Modify: `crates/rimap-config/src/validate.rs`
- Modify: `crates/rimap-smtp/src/client.rs`

Fixes F7: the `connect_timeout_seconds` field exists in `SmtpConfig` but lettre's builder doesn't support a separate connect timeout. Remove the phantom config field rather than documenting a knob that does nothing.

- [ ] **Step 1: Remove field from `SmtpConfig`**

In `crates/rimap-config/src/model.rs`, remove the `connect_timeout_seconds` field and its `#[serde(default)]` annotation (lines 92–94):

```rust
    /// TCP + TLS handshake deadline.
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u32,
```

Also remove it from the custom `Debug` impl (the `.field("connect_timeout_seconds", ...)` line).

- [ ] **Step 2: Remove from validation**

In `crates/rimap-config/src/validate.rs`, search for any references to `connect_timeout_seconds` in SMTP validation and remove them.

- [ ] **Step 3: Update test config in `client.rs`**

In `crates/rimap-smtp/src/client.rs`, remove `connect_timeout_seconds: 5` from the `test_config()` function (line 98).

- [ ] **Step 4: Fix all compilation errors**

Run: `cargo build --workspace 2>&1 | head -30`

Fix any remaining references to `connect_timeout_seconds` in the SMTP context across the workspace. Check test fixtures, config validation tests, and any config TOML files in tests.

- [ ] **Step 5: Run all tests**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add -u
git commit -m "fix(config): remove phantom connect_timeout_seconds from SmtpConfig

lettre's SmtpTransportBuilder does not support a separate connect
timeout — the single timeout() covers the full session. Remove the
field rather than documenting a knob that does nothing.

This is a breaking config change: existing configs with
connect_timeout_seconds under [smtp] will fail to parse due to
deny_unknown_fields, surfacing the misconfiguration."
```

---

## Task 6: Replace `unreachable!()` with fallible error returns

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`

Fixes F10: 14 sites use `unreachable!()` which bypasses the workspace `panic = "deny"` lint. Replace with typed error returns.

- [ ] **Step 1: Replace all `unwrap_or_else(|| unreachable!(...))` sites**

In `crates/rimap-imap/src/connection.rs`, replace every occurrence of:

```rust
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
```

with:

```rust
            let session = guard.as_mut().ok_or(Error::Protocol(
                async_imap::error::Error::Bad(
                    "session invariant violated: guard is None after session()"
                        .to_string(),
                ),
            ))?;
```

There are 14 sites. Use find-and-replace. The `async_imap::error::Error::Bad` variant wraps a `String` and fits the existing error model. This turns the unreachable panic into a recoverable error.

- [ ] **Step 2: Build**

Run: `cargo build -p rimap-imap 2>&1 | tail -5`
Expected: compiles cleanly.

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-imap -- --nocapture 2>&1 | tail -10`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "fix(imap): replace unreachable!() with fallible error returns

The 14 unwrap_or_else(|| unreachable!(...)) sites in Connection
wrappers bypassed the workspace panic = deny lint. Replace with
Error::Protocol returns so a violated invariant surfaces as a
recoverable error rather than a process crash."
```

---

## Task 7: Add `clippy::unreachable` deny lint + final verification

**Files:**
- Modify: `Cargo.toml` (workspace root)

Closes the lint gap that allowed `unreachable!()` to bypass `panic = "deny"`.

- [ ] **Step 1: Add lint**

In the root `Cargo.toml`, in the `[workspace.lints.clippy]` section, add after the `unimplemented = "deny"` line:

```toml
unreachable = "deny"
```

- [ ] **Step 2: Verify no remaining violations**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings 2>&1 | tail -10`
Expected: no clippy errors. If any `unreachable!()` calls remain elsewhere in the workspace, fix them before proceeding.

- [ ] **Step 3: Run full CI suite**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: all clean.

- [ ] **Step 4: Run cargo deny**

Run: `cargo deny check 2>&1 | tail -5`
Expected: `advisories ok, bans ok, licenses ok, sources ok`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml
git commit -m "fix: deny clippy::unreachable to close panic lint gap

unreachable!() expands to panic!() but is a separate clippy lint
from clippy::panic. Adding the deny catches future occurrences."
```

---

## Findings Deferred (by design)

| Finding | ID | Reason |
|---------|----|--------|
| Password zeroization | F8, F11 | Pre-existing architectural debt (IMAP side has same pattern). Requires `secrecy`/`zeroize` as workspace dep + `CredentialStore` trait change. Track as GitHub issue for a dedicated security sprint. |
| `SmtpError::Transport` Debug leaks | F12 | Low risk — requires Debug format path. Address when SMTP audit logging is wired up in Sprint 2c. |
| `SmtpClient::send` doc comment accuracy | Rust-F7 | Info-only. lettre may pool connections. Fix doc when send_email tool is implemented. |
