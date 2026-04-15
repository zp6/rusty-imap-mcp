# Sprint 2c Review Remediations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all findings from the 6-reviewer security audit of Sprint 2c, from high-severity authorization bypasses down to low-severity information leakage and infrastructure hardening.

**Architecture:** Nine tasks ordered by severity. Tasks 1–5 fix high/medium issues (shippable after Task 5). Tasks 6–8 fix low-severity quality issues. Task 9 is final verification.

**Tech Stack:** Rust, rimap-authz (FolderGuard, FolderName), rimap-smtp, mail-builder, serde, Podman/Docker

**Depends on:** Sprint 2c (commit b995e72)

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-server/src/tools/folder_mgmt.rs` | Fix rename_folder and create_folder authorization |
| Modify | `crates/rimap-server/src/tools/message_builder.rs` | Fix empty cc/bcc panic, validate in_reply_to_folder |
| Modify | `crates/rimap-server/src/tools/send_email.rs` | Remove SMTP response leakage, surface Sent-copy failure, sanitize error |
| Modify | `crates/rimap-imap/tests/integration/smtp/docker-compose.yml` | Pin image by SHA digest |

---

## Task 1: Fix `rename_folder` authorization bypass (high)

**Reviewers:** email-imap #1, mcp #1, code-reviewer

`handle_rename` calls `check_protected` only on `old_name`. A caller can rename any unprotected folder to "INBOX" or "Sent". The existing `FolderGuard::check_rename` method validates both names.

**Files:**
- Modify: `crates/rimap-server/src/tools/folder_mgmt.rs:64-74`

- [ ] **Step 1: Add tests to `folder_mgmt.rs`**

Add a `#[cfg(test)]` module at the bottom of `crates/rimap-server/src/tools/folder_mgmt.rs`:

```rust
#[cfg(test)]
mod tests {
    use rimap_authz::FolderGuard;

    #[test]
    fn rename_to_protected_folder_rejected() {
        let guard = FolderGuard::new(
            &["Sent".to_string(), "Drafts".to_string()],
            &[],
        );
        let err = guard.check_rename("temp", "Sent").unwrap_err();
        assert_eq!(
            err.code(),
            rimap_core::error::ErrorCode::ProtectedFolder,
        );
    }

    #[test]
    fn rename_to_inbox_rejected() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_rename("temp", "INBOX").unwrap_err();
        assert_eq!(
            err.code(),
            rimap_core::error::ErrorCode::ProtectedFolder,
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test -p rimap-server -- folder_mgmt::tests --nocapture`
Expected: both PASS (they test `FolderGuard` which already works).

- [ ] **Step 3: Fix the handler**

In `handle_rename`, replace:

```rust
    server
        .folder_guard
        .check_protected(&input.old_name, "rename")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;
```

With:

```rust
    server
        .folder_guard
        .check_rename(&input.old_name, &input.new_name)
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server -- --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/folder_mgmt.rs
git commit -m "fix(server): validate rename_folder destination via check_rename

check_protected only validated old_name, allowing rename to protected
folder names like INBOX or Sent. check_rename validates both names."
```

---

## Task 2: Fix `create_folder` to use `FolderGuard` (medium)

**Reviewers:** email-imap #2, mcp #2, rust-safety #7

`handle_create` uses inline `eq_ignore_ascii_case` that bypasses Modified UTF-7 normalization and `FolderName::new()` structural validation. `FolderGuard::check_protected` also always blocks INBOX regardless of config.

**Files:**
- Modify: `crates/rimap-server/src/tools/folder_mgmt.rs:32-49`

- [ ] **Step 1: Add test**

Add to the `folder_mgmt::tests` module:

```rust
    #[test]
    fn create_inbox_rejected_even_with_empty_protected_list() {
        let guard = FolderGuard::new(&[], &[]);
        let err = guard.check_protected("INBOX", "create").unwrap_err();
        assert_eq!(
            err.code(),
            rimap_core::error::ErrorCode::ProtectedFolder,
        );
    }
```

- [ ] **Step 2: Run test**

Run: `cargo test -p rimap-server -- folder_mgmt::tests --nocapture`
Expected: PASS.

- [ ] **Step 3: Replace inline check with FolderGuard**

In `handle_create`, replace lines 37–49:

```rust
    let protected = &server.config.config.security.protected_folders;
    if protected
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&input.name))
    {
        return Err(rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: format!(
                "cannot create folder `{}`: name collides with a protected folder",
                input.name
            ),
        });
    }
```

With:

```rust
    server
        .folder_guard
        .check_protected(&input.name, "create")
        .map_err(|e| rimap_core::RimapError::Authz {
            code: e.code(),
            message: e.to_string(),
        })?;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server -- --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/folder_mgmt.rs
git commit -m "fix(server): use FolderGuard for create_folder protected check

Inline eq_ignore_ascii_case bypassed Modified UTF-7 normalization
and FolderName structural validation. FolderGuard also always blocks
INBOX regardless of the protected_folders config list."
```

---

## Task 3: Fix `addresses_to_builder` panic on empty cc/bcc (medium)

**Reviewers:** rust-safety #1

`addresses_to_builder` indexes `addrs[0]` unconditionally. Serde deserializes `"cc": []` as `Some(vec![])`, which reaches this path and panics.

**Files:**
- Modify: `crates/rimap-server/src/tools/message_builder.rs:151-174`

- [ ] **Step 1: Write failing test**

Add to `message_builder::tests`:

```rust
    #[test]
    fn empty_cc_does_not_panic() {
        let input = ComposeInput {
            to: vec![AddressInput {
                name: None,
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![]),
            bcc: Some(vec![]),
            subject: "Test".into(),
            body_text: "body".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };
        validate_compose_input(&input).unwrap();
        let builder = super::build_message_headers("alice@example.com", &input);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();
        assert!(parsed.cc().is_none());
        assert!(parsed.bcc().is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rimap-server -- message_builder::tests::empty_cc_does_not_panic --nocapture`
Expected: FAIL with panic at index operation.

- [ ] **Step 3: Filter empty vecs in `build_message_headers`**

In `build_message_headers`, replace the cc/bcc handling:

```rust
    let builder = if let Some(cc) = &input.cc {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    if let Some(bcc) = &input.bcc {
        builder.bcc(addresses_to_builder(bcc))
    } else {
        builder
    }
```

With:

```rust
    let builder = if let Some(cc) = input.cc.as_ref().filter(|v| !v.is_empty()) {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    if let Some(bcc) = input.bcc.as_ref().filter(|v| !v.is_empty()) {
        builder.bcc(addresses_to_builder(bcc))
    } else {
        builder
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p rimap-server -- message_builder::tests --nocapture`
Expected: all tests pass including `empty_cc_does_not_panic`.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/message_builder.rs
git commit -m "fix(server): prevent panic on empty cc/bcc address lists

addresses_to_builder indexed addrs[0] unconditionally. Serde
deserializes \"cc\": [] as Some(vec![]), reaching this path and
panicking. Filter empty vecs before calling the builder."
```

---

## Task 4: Validate `in_reply_to_folder` before IMAP call (medium)

**Reviewers:** email-imap #3

`apply_threading_headers` passes user-supplied `in_reply_to_folder` directly to `server.imap.fetch_body` without folder name validation. Neither `fetch_body` nor `preflight_fetch_size` validates the folder name.

**Files:**
- Modify: `crates/rimap-server/src/tools/message_builder.rs:48-108`

- [ ] **Step 1: Write failing tests**

Add to `message_builder::tests`:

```rust
    #[test]
    fn in_reply_to_folder_with_crlf_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(1);
        input.in_reply_to_folder = Some("bad\r\nfolder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_with_null_rejected() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(1);
        input.in_reply_to_folder = Some("bad\0folder".into());
        let err = validate_compose_input(&input).unwrap_err();
        assert_eq!(err.code(), rimap_core::error::ErrorCode::InvalidInput);
    }

    #[test]
    fn in_reply_to_folder_valid_accepted() {
        let mut input = make_input(vec![AddressInput {
            name: None,
            address: "ok@example.com".into(),
        }]);
        input.in_reply_to_uid = Some(1);
        input.in_reply_to_folder = Some("INBOX".into());
        validate_compose_input(&input).unwrap();
    }
```

- [ ] **Step 2: Run tests to verify first two fail**

Run: `cargo test -p rimap-server -- message_builder::tests::in_reply_to_folder --nocapture`
Expected: `in_reply_to_folder_with_crlf_rejected` and `in_reply_to_folder_with_null_rejected` FAIL.

- [ ] **Step 3: Add folder validation to `validate_compose_input`**

At the end of `validate_compose_input`, before the final `Ok(())`, add:

```rust
    if let Some(folder) = &input.in_reply_to_folder {
        rimap_authz::folder_name::FolderName::new(folder).map_err(|e| {
            rimap_core::RimapError::Authz {
                code: e.code(),
                message: format!("in_reply_to_folder: {e}"),
            }
        })?;
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rimap-server -- message_builder::tests --nocapture`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/tools/message_builder.rs
git commit -m "fix(server): validate in_reply_to_folder before IMAP call

User-supplied folder name passed directly to fetch_body without
validation. Use FolderName::new() to reject control characters,
NUL bytes, and path traversal at the handler layer."
```

---

## Task 5: Remove SMTP response leakage from `send_email` (medium)

**Reviewers:** email-imap #4, mcp #3

The raw SMTP response (server software, queue IDs, hostname) is forwarded to the MCP client. The rimap-smtp docstring at `client.rs:55-56` explicitly says not to do this.

**Files:**
- Modify: `crates/rimap-server/src/tools/send_email.rs:39-68`

- [ ] **Step 1: Replace SMTP response with generic status**

In `send_email::handle`, after the `send_raw` call, add a log and discard the raw response:

Replace:
```rust
    let smtp_response = client.send_raw(&envelope, &raw_msg).await?;
```

With:
```rust
    let smtp_response = client.send_raw(&envelope, &raw_msg).await?;
    tracing::info!(smtp_response, "send_email: SMTP send succeeded");
```

In the response JSON, replace:
```rust
            "smtp_response": smtp_response,
```

With:
```rust
            "smtp_status": "delivered",
```

- [ ] **Step 2: Run build and tests**

Run: `cargo build -p rimap-server && cargo test -p rimap-server -- --nocapture`
Expected: compiles and all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/tools/send_email.rs
git commit -m "fix(server): stop forwarding SMTP response to MCP client

Raw SMTP server responses leak software version, queue IDs, and
hostname. Log for forensics, return generic status to client.
Per rimap-smtp docstring: 'should NOT be forwarded to MCP clients'."
```

---

## Task 6: Surface Sent-folder APPEND failure to client (low)

**Reviewers:** email-imap #8, mcp #5

When Sent-folder APPEND fails, the client sees `sent_uid: null` with no failure indicator. Cannot distinguish "no UIDPLUS" from "APPEND failed".

**Files:**
- Modify: `crates/rimap-server/src/tools/send_email.rs:47-68`

- [ ] **Step 1: Add failure indicator**

Replace the Sent-copy match and response construction (after the `tracing::info!` line from Task 5):

Replace:
```rust
    let sent_uid = match server
        .imap
        .append_message(sent_folder, &raw_msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
    {
        Ok(result) => result.uid.map(rimap_imap::types::Uid::get),
        Err(e) => {
            tracing::warn!("failed to append to Sent folder: {e}");
            None
        }
    };
```

With:
```rust
    let (sent_uid, sent_copy_failed) = match server
        .imap
        .append_message(sent_folder, &raw_msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
    {
        Ok(result) => (result.uid.map(rimap_imap::types::Uid::get), false),
        Err(e) => {
            tracing::warn!("failed to append to Sent folder: {e}");
            (None, true)
        }
    };
```

And in the response JSON, replace:
```rust
            "sent_copy": {
                "folder": sent_folder,
                "uid": sent_uid,
            },
```

With:
```rust
            "sent_copy": {
                "folder": sent_folder,
                "uid": sent_uid,
                "failed": sent_copy_failed,
            },
```

- [ ] **Step 2: Run build and tests**

Run: `cargo build -p rimap-server && cargo test -p rimap-server -- --nocapture`
Expected: compiles and all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/tools/send_email.rs
git commit -m "fix(server): surface Sent-folder APPEND failure in send_email response

Client previously received sent_uid: null with no way to distinguish
UIDPLUS unsupported from APPEND failure. Add sent_copy.failed field."
```

---

## Task 7: Sanitize address in `parse_lettre_addr` error message (low)

**Reviewers:** rust-safety #4

`parse_lettre_addr` echoes user-supplied address in the error message — minor prompt-injection surface when error is forwarded to LLM context.

**Files:**
- Modify: `crates/rimap-server/src/tools/send_email.rs:104-110`

- [ ] **Step 1: Remove address echo from error**

Replace:
```rust
fn parse_lettre_addr(addr: &str) -> Result<lettre::Address, rimap_core::RimapError> {
    addr.parse::<lettre::Address>()
        .map_err(|e| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: format!("invalid email address `{addr}`: {e}"),
        })
}
```

With:
```rust
fn parse_lettre_addr(addr: &str) -> Result<lettre::Address, rimap_core::RimapError> {
    addr.parse::<lettre::Address>()
        .map_err(|_| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "invalid email address in recipient list".into(),
        })
}
```

- [ ] **Step 2: Run build and tests**

Run: `cargo build -p rimap-server && cargo test -p rimap-server -- --nocapture`
Expected: compiles and all tests pass.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/tools/send_email.rs
git commit -m "fix(server): omit user-supplied address from lettre parse error

Avoids reflecting attacker-controlled content into error messages
that may be forwarded to LLM context."
```

---

## Task 8: Pin Mailpit docker image by SHA digest (low)

**Reviewers:** ci-cd #1

The `mailpit:v1.29.5` tag is mutable. Pin to content-addressable SHA digest.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/smtp/docker-compose.yml:5`

- [ ] **Step 1: Retrieve the digest**

Run: `podman pull docker.io/axllent/mailpit:v1.29.5 && podman inspect --format='{{index .RepoDigests 0}}' docker.io/axllent/mailpit:v1.29.5`

Record the `sha256:...` digest from the output.

- [ ] **Step 2: Update the compose file**

Replace line 5:
```yaml
    image: docker.io/axllent/mailpit:v1.29.5
```

With (using the actual digest from Step 1):
```yaml
    # v1.29.5
    image: docker.io/axllent/mailpit@sha256:<digest>
```

- [ ] **Step 3: Verify the container starts**

Run:
```bash
COMPOSE_PROJECT_NAME=rimap-pin-test \
RIMAP_SMTP_HOST_PORT=11025 \
RIMAP_SMTP_API_PORT=18025 \
podman-compose -f crates/rimap-imap/tests/integration/smtp/docker-compose.yml up -d \
&& sleep 3 \
&& curl -sf http://127.0.0.1:18025/api/v1/info \
&& podman-compose -f crates/rimap-imap/tests/integration/smtp/docker-compose.yml down
```
Expected: Mailpit starts and the API responds with JSON.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/smtp/docker-compose.yml
git commit -m "infra: pin Mailpit docker image by SHA digest

Mutable tags can be repointed by a compromised registry. Pin to
content-addressable digest for reproducible builds."
```

---

## Task 9: Final verification

- [ ] **Step 1: Run full CI locally**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace`
Expected: clean.

- [ ] **Step 2: Run cargo deny**

Run: `cargo deny check`
Expected: advisories ok, bans ok, licenses ok, sources ok.

- [ ] **Step 3: Verify tool matrix and definitions**

Run: `cargo test -p rimap-authz matrix_covers_every_tool -- --nocapture && cargo test -p rimap-server tool_definition -- --nocapture`
Expected: both pass.

- [ ] **Step 4: Fix any issues and commit**

```bash
git add -u
git commit -m "fix: address lint and test issues from 2c review remediations"
```

---

## Findings Deferred (by design)

| Finding | Reviewers | Reason |
|---------|-----------|--------|
| No audit records for 6 new handlers | email-imap #7, mcp #4 | Acknowledged via `#[expect(dead_code)]` on `AuditWriter`. Tracked for dedicated audit sprint — these are destructive ops that need forensic logging before production. |
| Sent/Trash folder names hardcoded | mcp #5, mcp #6 | Requires config schema change + provider-specific folder discovery. Track as feature work for Gmail/provider support. |
| Async cancellation between SMTP send and Sent APPEND | rust-safety #2 | Acceptable given best-effort Sent-copy semantics. Document when audit logging is wired in. |
| Type alias coupling SendEmailInput/CreateDraftInput | rust-safety #3 | Intentional — split to separate struct when fields diverge. |
| Docker Dependabot `docker` ecosystem | ci-cd #1 note | Add when digest pinning is adopted for all integration test images (Dovecot too). |
