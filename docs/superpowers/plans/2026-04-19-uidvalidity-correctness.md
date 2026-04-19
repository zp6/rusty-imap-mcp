# UIDVALIDITY Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three UIDVALIDITY correctness issues as one sweep — stop fabricating `uid_validity = 0` when servers omit it (#97), guard MOVE/COPY against UIDVALIDITY rotation between SELECT and command (#96), and echo + optionally gate on UIDVALIDITY in flag/label/move tool responses (#70).

**Architecture:** Task 1 changes `SelectedFolder.uid_validity` from `u32` (with `.unwrap_or(0)`) to `Option<u32>` and adds `ImapError::UidValidityChanged { folder, expected, actual }` as the shared typed error. Task 2 captures source UIDVALIDITY at SELECT in `move_messages`, compares before `UID MOVE` / `UID COPY`, STATUS-checks the destination after COPY fallback, and adds `used_fallback_reason: Option<String>` to `MoveResult` so the audit layer can surface why `new_uid` is `None` (COPYUID capture is deferred — async-imap does not expose the response code; a follow-up issue is filed in Task 5). Task 3 extends `FlagsMeta`, `LabelsMeta`, `ListLabelsMeta`, and `MoveMessageMeta` with an observed `uid_validity` field populated from the `SelectedFolder` returned by the handler's SELECT/EXAMINE call. Task 4 adds an optional `expected_uidvalidity: Option<u32>` input on each flag/label/move tool; when the caller sets it and the observed UIDVALIDITY differs, the tool returns `ImapError::UidValidityChanged` mapped to an `ERR_*` code that an agent can retry under.

**Tech Stack:** Rust (stable), existing `async-imap` / `imap-proto` types, `rimap-audit::record` (no schema change — `uid_validity` on response meta is serialized through the same path as other meta fields).

---

## Prior-Art Context

`SelectedFolder` at `crates/rimap-imap/src/types.rs:124-137` carries `uid_validity: u32`, populated at `ops/folders.rs:139-158::select` via `mailbox.uid_validity.unwrap_or(0)`. RFC 3501 §2.3.1.1 reserves UIDVALIDITY=0 to indicate the absence of the facility, so the current fabrication collides with that sentinel. Survey confirmed: the field has NO in-tree consumers today — this sweep introduces the first ones (MOVE guard + tool-response echo).

`ops/move_message.rs::move_messages` (lines 40-78) and `copy_delete_fallback` (lines 87-128) neither (a) guard against UIDVALIDITY rotation between the caller's SELECT and the command, nor (b) capture the `[COPYUID uidvalidity src dst]` response code. `MoveResult.new_uid` is always `None` (line 137 in `build_results`, comment at 130-131 documents the async-imap gap).

`ResponseCode::CopyUid(u32, Vec<UidSetMember>, Vec<UidSetMember>)` is defined at `imap-proto 0.16.6 types.rs:139` but unreachable via async-imap 0.11.2's session methods (`uid_copy`, `uid_mv` return `Result<()>` and discard response codes). Wiring COPYUID capture requires raw-command machinery that is too invasive for this sweep.

Flag/label/move tool handlers at `crates/rimap-server/src/tools/mailbox/flags.rs`, `labels.rs`, `move_message.rs` currently return `ToolResponse<FlagsMeta | LabelsMeta | ListLabelsMeta | MoveMessageMeta>` none of which include a UIDVALIDITY field. The labels module already carries an explicit doc comment (lines 4-10) noting the gap.

---

## File Structure

### Modified files

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-imap/src/types.rs` | `SelectedFolder.uid_validity: Option<u32>`. Add `uid_validity: u32` to `MoveResult` (observed source) + `used_fallback_reason: Option<String>`. |
| Modify | `crates/rimap-imap/src/error.rs` | Add `UidValidityChanged { folder: String, expected: u32, actual: u32 }` variant + error-code mapping. |
| Modify | `crates/rimap-core/src/error.rs` | Add `ErrorCode::UidValidityChanged` → `"ERR_UID_VALIDITY_CHANGED"`. Round-trip pairs. |
| Modify | `crates/rimap-imap/src/ops/folders.rs` | `select` populates `Option<u32>` instead of `.unwrap_or(0)`. |
| Modify | `crates/rimap-imap/src/ops/move_message.rs` | `move_messages` accepts `expected_source_uidvalidity: Option<u32>`; compares before UID MOVE / UID COPY. STATUS-check destination UIDVALIDITY after COPY fallback. Populate `used_fallback_reason` on each result. |
| Modify | `crates/rimap-imap/src/connection.rs` | Wrapper `move_messages` signature updated to accept/propagate the new arg. |
| Modify | `crates/rimap-server/src/tools/mailbox/flags.rs` | `FlagsMeta.uid_validity: u32`. Optional `expected_uidvalidity: Option<u32>` input. Guard handler. |
| Modify | `crates/rimap-server/src/tools/mailbox/labels.rs` | Same treatment for `LabelsMeta` / `ListLabelsMeta` (drop the deferred-gap doc comment). |
| Modify | `crates/rimap-server/src/tools/mailbox/move_message.rs` | `MoveMessageMeta.uid_validity: u32`. Optional `expected_source_uidvalidity`. |
| Modify | `crates/rimap-server/src/mcp/error.rs` | Map the new `ImapError::UidValidityChanged` / `ErrorCode::UidValidityChanged` to the right `ErrorData` shape. |

### Unchanged

- `rimap-audit` / on-disk record shapes — no new variants needed. The error code is a new `ErrorCode` variant, handled generically by the audit writer.

---

## Task 1: `SelectedFolder.uid_validity: Option<u32>` + `ErrorCode::UidValidityChanged` (#97)

**Issue:** #97 + foundation for #96 / #70.

**Files:**
- Modify: `crates/rimap-imap/src/types.rs`
- Modify: `crates/rimap-imap/src/ops/folders.rs`
- Modify: `crates/rimap-imap/src/error.rs`
- Modify: `crates/rimap-core/src/error.rs`

### Approach

Change `SelectedFolder.uid_validity` from `u32` to `Option<u32>`. The single populator (`ops/folders.rs::select`) drops `.unwrap_or(0)` and passes `mailbox.uid_validity` through directly.

Add the shared typed error `ImapError::UidValidityChanged { folder: String, expected: u32, actual: u32 }` and the stable `ErrorCode::UidValidityChanged` → `"ERR_UID_VALIDITY_CHANGED"`. Downstream tasks produce and consume this error.

- [ ] **Step 1: Add `ErrorCode::UidValidityChanged` in `rimap-core`**

Follow the pattern landed in the audit-cancellation PR for `ErrorCode::Cancelled`:

- Add `Cancelled` → `UidValidityChanged` with `/// UIDVALIDITY changed between caller-observed value and server observation.`
- `as_str` arm: `Self::UidValidityChanged => "ERR_UID_VALIDITY_CHANGED"`
- `from_str` parse arm
- `round_trip_pairs` list entry
- Downstream exhaustive matches: `crates/rimap-server/src/mcp/dispatch.rs` + `crates/rimap-server/src/mcp/error.rs` (add to whatever arm set the previous new codes landed in — grep for `ErrorCode::Cancelled` to find the pattern).

Write and verify a `uid_validity_changed_round_trips` test.

- [ ] **Step 2: Add `ImapError::UidValidityChanged` variant**

At `crates/rimap-imap/src/error.rs`, add a variant:

```rust
    /// UIDVALIDITY observed by the server differs from the value the
    /// caller expected (recorded at its prior SELECT). The target UID may
    /// now refer to a different message than the caller intended.
    ///
    /// # Fields
    /// - `folder`: affected mailbox name.
    /// - `expected`: UIDVALIDITY the caller observed previously.
    /// - `actual`: UIDVALIDITY the server reports now.
    #[error(
        "UIDVALIDITY changed for `{folder}`: expected {expected}, \
         server reports {actual}"
    )]
    UidValidityChanged {
        /// Mailbox name.
        folder: String,
        /// UIDVALIDITY observed at a prior SELECT.
        expected: u32,
        /// UIDVALIDITY observed now.
        actual: u32,
    },
```

Update the `code()` method (or equivalent mapping) so this variant resolves to `ErrorCode::UidValidityChanged`.

Add a unit test: `uid_validity_changed_display_includes_numbers_and_folder`.

- [ ] **Step 3: Change `SelectedFolder.uid_validity` to `Option<u32>`**

At `crates/rimap-imap/src/types.rs:124-137`:

```rust
pub struct SelectedFolder {
    pub name: String,
    pub exists: u32,
    pub recent: u32,
    /// UIDVALIDITY reported by the server. `None` when the server's
    /// SELECT/EXAMINE response omitted the response code (RFC 3501
    /// §2.3.1.1 reserves UIDVALIDITY=0 for that case — we surface it
    /// as `None` rather than fabricating a sentinel).
    pub uid_validity: Option<u32>,
    pub uid_next: Option<u32>,
    pub read_only: bool,
}
```

At `ops/folders.rs:154`, drop the `.unwrap_or(0)`:

```rust
    Ok(SelectedFolder {
        name: folder.to_string(),
        exists: mailbox.exists,
        recent: mailbox.recent,
        uid_validity: mailbox.uid_validity,
        uid_next: mailbox.uid_next,
        read_only,
    })
```

- [ ] **Step 4: Update sprint-3 design + plan references**

Issue #97 notes that `docs/superpowers/specs/2026-04-07-sprint-3-imap-design.md` (around line 120) and `docs/superpowers/plans/2026-04-07-sprint-3-imap.md` (around lines 1796, 3176) reference the old `u32` shape. Grep and fix those to match `Option<u32>`. These are historical design docs — annotate the change inline (`// #97: changed to Option<u32>`) rather than rewriting the surrounding narrative.

If updating the historical docs feels like scope creep, SKIP this step and note in the commit message that the historical spec references are stale (track via a one-line comment in the commit body).

- [ ] **Step 5: Fix any `SelectedFolder { ... }` struct literals**

Grep: `grep -rn "SelectedFolder {" crates/ tests/`. Every struct-literal construction that reads `uid_validity: <number>` must switch to `uid_validity: Some(<number>)` or `uid_validity: None` as appropriate.

- [ ] **Step 6: Run workspace tests + clippy**

```bash
cd /home/dave/src/rusty-imap-mcp-uidvalidity
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: PASS and clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-core/src/error.rs crates/rimap-imap/src/error.rs \
        crates/rimap-imap/src/types.rs crates/rimap-imap/src/ops/folders.rs \
        crates/rimap-server/src/mcp/dispatch.rs crates/rimap-server/src/mcp/error.rs
# Plus any historical-spec edits + any SelectedFolder literal fixes
git commit -m "imap: SelectedFolder.uid_validity is Option<u32>; typed UidValidityChanged error (#97)

SelectedFolder.uid_validity is now Option<u32>. Drops the
.unwrap_or(0) in ops/folders.rs::select that fabricated the UIDVALIDITY=0
sentinel reserved by RFC 3501 §2.3.1.1. Consumers that need the
value (new this sprint: MOVE guard, flag/label/move response meta)
handle None explicitly.

Adds ImapError::UidValidityChanged { folder, expected, actual } with
stable ErrorCode::UidValidityChanged → ERR_UID_VALIDITY_CHANGED. Used
by the MOVE guard (task 2) and the expected-uidvalidity check in tool
handlers (task 4)."
```

---

## Task 2: MOVE UIDVALIDITY guard + `used_fallback_reason` (#96)

**Issue:** #96.

**Files:**
- Modify: `crates/rimap-imap/src/types.rs` (add `used_fallback_reason` to `MoveResult`)
- Modify: `crates/rimap-imap/src/ops/move_message.rs` (guard logic)
- Modify: `crates/rimap-imap/src/connection.rs` (public wrapper signature)

### Approach

`move_messages` gains an `expected_source_uidvalidity: Option<u32>` argument. When set, the op issues `STATUS <folder> (UIDVALIDITY)` at function entry (cheaper than re-SELECT; does not invalidate current selection) and compares to the expected value. Mismatch → `ImapError::UidValidityChanged`.

For the COPY fallback path, the destination folder is also STATUS-checked for UIDVALIDITY before COPY (captured into the first `MoveResult`). This bounds the "moved into the wrong incarnation" risk.

**COPYUID capture is deferred.** async-imap 0.11.2 does not expose `ResponseCode::CopyUid` through the session API. `new_uid` stays `None` for this PR. A new field `MoveResult.used_fallback_reason: Option<String>` records WHY `new_uid` is `None` (one of: `"async_imap_copyuid_unavailable"` in this sweep; future reasons may be added). A follow-up issue is filed in Task 5.

- [ ] **Step 1: Extend `MoveResult`**

At `crates/rimap-imap/src/types.rs` (around line 167-176), add:

```rust
pub struct MoveResult {
    pub old_uid: Uid,
    pub new_uid: Option<Uid>,
    /// Reason `new_uid` is None. `Some("async_imap_copyuid_unavailable")`
    /// when the UIDPLUS response code was not capturable via async-imap's
    /// session API; see #96 follow-up issue.
    pub used_fallback_reason: Option<String>,
}
```

- [ ] **Step 2: Update `move_messages` signature**

At `crates/rimap-imap/src/ops/move_message.rs:40-78`, change the signature to accept the expected value:

```rust
pub(crate) async fn move_messages(
    session: &mut ImapSession,
    src_folder: &str,
    dest_folder: &str,
    uids: &[Uid],
    expected_source_uidvalidity: Option<u32>,
    has_move: bool,
    has_uidplus: bool,
) -> Result<MoveOutcome, ImapError> {
```

Note the added `src_folder: &str` — the guard needs to know which folder to STATUS-check. If the current implementation doesn't already thread the source folder through, wire it. If the existing `move_messages` relies on the session's SELECTED mailbox, we still need the folder name for error reporting and the STATUS probe (STATUS does not require SELECT).

- [ ] **Step 3: Implement the guard**

Inside `move_messages`, before the UID MOVE / COPY dispatch:

```rust
    // If the caller observed a UIDVALIDITY at SELECT, verify it still
    // holds. We use STATUS rather than a fresh SELECT so the session's
    // current selected mailbox is unaffected.
    if let Some(expected) = expected_source_uidvalidity {
        let status = crate::ops::folders::status(
            session,
            src_folder,
            crate::types::StatusItems { uid_validity: true, ..Default::default() },
        )
        .await?;
        match status.uid_validity {
            Some(actual) if actual != expected => {
                return Err(ImapError::UidValidityChanged {
                    folder: src_folder.to_string(),
                    expected,
                    actual,
                });
            }
            None => {
                // Server omits UIDVALIDITY — cannot compare. Proceed.
                tracing::warn!(
                    folder = src_folder,
                    "STATUS omitted UIDVALIDITY; skipping UIDVALIDITY guard",
                );
            }
            _ => {} // matches expected
        }
    }
```

Adjust `StatusItems` field shape to whatever the existing type defines. If there's no `..Default::default()` shorthand, construct the struct with every field explicit.

- [ ] **Step 4: COPY-path destination guard**

In `copy_delete_fallback` (around lines 87-128), after the COPY but before relying on the implicit destination UIDs, issue `STATUS <dest_folder> (UIDVALIDITY)` and record the observed UIDVALIDITY. If the caller provided an `expected_source_uidvalidity`, the COPY already honors it; the destination STATUS-check closes the narrower gap where destination UIDVALIDITY could have rotated between the lookup-of-dest-name and the copy. Populate the result's `used_fallback_reason` accordingly:

```rust
    // COPYUID is not capturable via async-imap 0.11.2's session API.
    // See follow-up issue for when upstream exposes ResponseCode::CopyUid.
    results.push(MoveResult {
        old_uid,
        new_uid: None,
        used_fallback_reason: Some("async_imap_copyuid_unavailable".to_string()),
    });
```

If the non-fallback (UID MOVE) path also returns `new_uid: None`, apply the same `used_fallback_reason` there.

- [ ] **Step 5: Update callers**

`crates/rimap-imap/src/connection.rs`'s public `move_messages` wrapper must pass through `expected_source_uidvalidity` (and `src_folder`). Every caller of `Connection::move_messages` needs to either supply the expected value (if known) or pass `None`.

Grep: `grep -rn "move_messages\|Connection::move" crates/ tests/ 2>/dev/null`. Update call sites.

- [ ] **Step 6: Integration test**

Add to `crates/rimap-imap/tests/integration/dovecot.rs` (or a new file under `tests/`) a test that:
1. SELECTs INBOX, captures UIDVALIDITY.
2. Deletes and recreates the mailbox (forces UIDVALIDITY rotation — Dovecot increments on CREATE).
3. Calls `move_messages` with the stale UIDVALIDITY.
4. Asserts the error is `ImapError::UidValidityChanged` with the expected/actual values.

If the recreate-to-rotate dance is unreliable across Dovecot versions, an alternative is a MOCKED test that fakes a STATUS response with a different UIDVALIDITY. Use whichever the integration-test harness supports cleanly.

- [ ] **Step 7: Run workspace tests + clippy**

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-imap/src/types.rs crates/rimap-imap/src/ops/move_message.rs \
        crates/rimap-imap/src/connection.rs crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "imap: UIDVALIDITY guard on MOVE + used_fallback_reason (#96)

move_messages accepts expected_source_uidvalidity: Option<u32> and
compares it against a STATUS probe before UID MOVE / UID COPY.
Mismatch returns ImapError::UidValidityChanged. The COPY fallback
path STATUS-checks the destination before falling through.

MoveResult gains used_fallback_reason: Option<String> populated with
'async_imap_copyuid_unavailable' when new_uid is None due to
async-imap 0.11.2 not exposing ResponseCode::CopyUid. Follow-up
issue tracks wiring COPYUID capture once upstream exposes it."
```

---

## Task 3: Echo UIDVALIDITY in flag / label / move tool responses (#70 — response side)

**Issue:** #70 part 1.

**Files:**
- Modify: `crates/rimap-server/src/tools/mailbox/flags.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/labels.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/move_message.rs`

### Approach

Each handler already SELECTs (or EXAMINEs) the target folder during dispatch. Capture the `SelectedFolder.uid_validity: Option<u32>` from that call and populate a new `uid_validity: u32` field on the response meta. When `SelectedFolder.uid_validity` is `None` (server omitted the facility), either:

- (a) Return `ImapError::Protocol` — the server violated the UIDVALIDITY contract and we shouldn't silently succeed.
- (b) Omit the field (`uid_validity: Option<u32>`) and serialize with `skip_serializing_if`.

**Use (b).** Servers that legitimately omit UIDVALIDITY are rare but exist; a hard failure would make the tool unusable on those servers. An omitted field tells the agent "no UIDVALIDITY available, cannot guarantee UID stability."

- [ ] **Step 1: Extend `FlagsMeta`** (flags.rs)

```rust
pub struct FlagsMeta {
    pub folder: String,
    pub uids_updated: Vec<u32>,
    /// UIDVALIDITY observed at the SELECT used for this operation. `None`
    /// when the server's SELECT response omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_validity: Option<u32>,
}
```

Update each handler (`handle_mark_read`, `handle_mark_unread`, `handle_flag`, `handle_unflag`) to capture the `SelectedFolder.uid_validity` from whichever helper calls SELECT (probably `handle_flag_op` per the survey). Populate the new field on the returned meta.

- [ ] **Step 2: Extend `LabelsMeta` and `ListLabelsMeta`** (labels.rs)

Same treatment. Drop the module-level doc comment (lines 4-10 per the survey) that explicitly notes the gap — it's now closed.

- [ ] **Step 3: Extend `MoveMessageMeta`** (move_message.rs)

```rust
pub struct MoveMessageMeta {
    pub folder: String,
    pub destination: String,
    pub moves: Vec<MoveEntry>,
    /// Source-folder UIDVALIDITY observed at the SELECT used for this
    /// operation. `None` when the server omitted the response code. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_uid_validity: Option<u32>,
    /// Destination-folder UIDVALIDITY observed after the COPY (fallback
    /// path) or implied by the UID MOVE command (happy path). `None`
    /// when not observable. (#70)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_uid_validity: Option<u32>,
}
```

The destination value comes from the STATUS-check added in Task 2's fallback path. For the UID MOVE happy path, the destination is in a different selected-mailbox incarnation than the current session — populate from a separate `STATUS <destination> (UIDVALIDITY)` call.

- [ ] **Step 4: Unit tests**

For each meta type, add a serialization test asserting:
- Field is serialized when `Some`.
- Field is omitted when `None` (via `skip_serializing_if`).

- [ ] **Step 5: Run workspace tests + clippy**

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/mailbox/flags.rs \
        crates/rimap-server/src/tools/mailbox/labels.rs \
        crates/rimap-server/src/tools/mailbox/move_message.rs
git commit -m "server: echo UIDVALIDITY in flag/label/move tool responses (#70)

FlagsMeta, LabelsMeta, ListLabelsMeta, and MoveMessageMeta gain an
uid_validity field (source_uid_validity + destination_uid_validity on
move). Populated from the SelectedFolder the handler's SELECT returns.
Option<u32> + #[serde(skip_serializing_if)] so servers that omit
UIDVALIDITY don't cause a hard failure — agents see the field missing
and can reason accordingly.

Labels module loses its 'no UIDVALIDITY tracking' gap comment; the
gap is closed."
```

---

## Task 4: Optional `expected_uidvalidity` on flag/label/move tool inputs (#70 — input side)

**Issue:** #70 part 2.

**Files:**
- Modify: `crates/rimap-server/src/tools/mailbox/flags.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/labels.rs`
- Modify: `crates/rimap-server/src/tools/mailbox/move_message.rs`

### Approach

Each tool's input struct gains an optional `expected_uidvalidity: Option<u32>` field. When the caller supplies it and the observed UIDVALIDITY (from the handler's SELECT) differs, the handler returns `ImapError::UidValidityChanged`, which the dispatch layer maps to `ErrorCode::UidValidityChanged` / `"ERR_UID_VALIDITY_CHANGED"`.

For `move_message`, the input carries `expected_source_uidvalidity: Option<u32>` — passed through to `Connection::move_messages` so the guard from Task 2 does the comparison at the right layer.

- [ ] **Step 1: Extend each input struct**

```rust
pub struct FlagInput {
    pub folder: String,
    pub uids: Vec<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_uidvalidity: Option<u32>,
}
```

Same pattern for `LabelInput`, `ListLabelsInput`, `MoveMessageInput`. The `MoveMessageInput` names the field `expected_source_uidvalidity` to match the wire shape the MOVE guard expects.

- [ ] **Step 2: Handler guard logic (flags + labels)**

For flags/labels, the observed UIDVALIDITY is `SelectedFolder.uid_validity` from the handler's SELECT. Add a guard before the STORE/EXPUNGE:

```rust
    let selected = /* existing SELECT */;
    if let Some(expected) = input.expected_uidvalidity {
        match selected.uid_validity {
            Some(actual) if actual != expected => {
                return Err(rimap_core::RimapError::from(ImapError::UidValidityChanged {
                    folder: input.folder.clone(),
                    expected,
                    actual,
                }));
            }
            None => {
                // Server omits UIDVALIDITY; cannot honor expected-value
                // check. Proceed with a tracing::warn — agent sees the
                // missing uid_validity in the response.
                tracing::warn!(
                    folder = %input.folder,
                    "expected_uidvalidity set but server omitted UIDVALIDITY; proceeding without guard",
                );
            }
            _ => {}
        }
    }
```

- [ ] **Step 3: Move tool — pass through to `Connection`**

For `move_message`, no handler-level guard is needed — `Connection::move_messages` already accepts `expected_source_uidvalidity` (Task 2). Thread the input field through:

```rust
    account
        .imap
        .move_messages(
            &input.folder,
            &input.destination,
            &uid_slice,
            input.expected_source_uidvalidity,
        )
        .await?;
```

Adjust to the actual wrapper signature after Task 2's changes.

- [ ] **Step 4: Redaction schema updates**

`rimap-audit/src/redact/schemas` (or wherever redaction schemas live) may need updating so the new `expected_uidvalidity` field is recognized. If the schemas simply forward all top-level fields without stripping, no change is needed.

- [ ] **Step 5: Unit tests**

For each handler, add tests:
- `expected_uidvalidity: Some(old_value)` + observed differs → returns `UidValidityChanged`.
- `expected_uidvalidity: Some(correct_value)` → tool succeeds normally.
- `expected_uidvalidity: None` → no guard; tool succeeds.

A unit test may need mocking of the SELECT path. If the codebase has a `MockConnection` or similar, use it. Otherwise fall back to an integration test against Dovecot that forces the rotation (same pattern as Task 2's integration test).

- [ ] **Step 6: Run workspace tests + clippy**

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/tools/mailbox/flags.rs \
        crates/rimap-server/src/tools/mailbox/labels.rs \
        crates/rimap-server/src/tools/mailbox/move_message.rs
# Plus any redaction-schema updates
git commit -m "server: expected_uidvalidity input on flag/label/move tools (#70)

Each of the flag, label, and move tools now accepts an optional
expected_uidvalidity (expected_source_uidvalidity for move). When set,
a mismatch between the agent's prior observation and the server's
current UIDVALIDITY returns ImapError::UidValidityChanged → mapped to
ErrorCode::UidValidityChanged → ERR_UID_VALIDITY_CHANGED. Agents that
cached a UID and want to retry safely can now do so without risk of
acting on a different message."
```

---

## Task 5: Final verification + PR + file COPYUID follow-up

- [ ] **Step 1: Run the full verification pipeline**

```bash
cd /home/dave/src/rusty-imap-mcp-uidvalidity
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check advisories bans licenses sources
typos
```

All five must pass.

- [ ] **Step 2: Push + open PR**

Branch: `feat/uidvalidity-correctness`. Target: `main`. PR body references `Closes #70`, `Closes #96`, `Closes #97`.

- [ ] **Step 3: File the COPYUID follow-up issue**

Use the `gh issue create` pattern. Reference:
- The plumbed `MoveResult.used_fallback_reason` and `new_uid: None` (MoveResult location after Task 2)
- async-imap 0.11.2 as the blocker — `ResponseCode::CopyUid` exists in imap-proto but session methods discard it
- Expected follow-up shape: flip the dispatch once async-imap exposes it; populate `new_uid: Some(Uid::new(dst))` and clear `used_fallback_reason`

Title suggestion: `imap: wire COPYUID capture once async-imap exposes ResponseCode::CopyUid`
