# Folder Listing Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four folder-listing issues as one sweep — replace `Vec<String>` folder attributes with a typed enum (#91), validate server-returned mailbox names before they reach STATUS/SELECT/MOVE/COPY (#95), sanitize server-controlled names and flags before they ride under the trusted `meta` envelope (#98), and adopt RFC 5819 LIST-STATUS so `list_folders` no longer issues per-folder STATUS (#92).

**Architecture:** Tasks 1–2 reshape `rimap_imap::types::Folder`: define `FolderAttribute` (typed enum covering RFC 3501 / RFC 5258 attributes the codebase branches on, plus `Other(String)` catch-all), replace `Folder.attributes: Vec<String>` with `Vec<FolderAttribute>`, remove the cached `Folder.selectable: bool` in favor of a derived method. Tasks 3–5 add a server-origin name validator (`validate_server_folder_name`) in `rimap-imap` that rejects NUL and C0/C1/DEL control characters, applied at the LIST boundary (`ops/folders.rs::list`) and at every call site that accepts untrusted folder input (`select`, `status`, `move_messages`). The existing strict `validate_folder_name` used on client CREATE/RENAME/DELETE inputs gains segment-aware traversal detection and bidi/ZWJ handling. Task 6 wires `rimap_content::unicode::sanitize` into `list_folders`'s response path so the `meta.folders[i].name` is the sanitized form, with any warnings surfaced on the response. Tasks 7–8 add a `has_list_status: AtomicBool` capability flag on `Connection` — parallel to the existing `has_move` / `has_uidplus` — and a `list_folders_with_status` operation that issues a single `LIST "" "*" RETURN (STATUS (MESSAGES UIDVALIDITY UNSEEN))` when the capability is advertised, falling back to the existing LIST-then-STATUS loop otherwise.

**Tech Stack:** Rust (stable), `async-imap` (LIST, STATUS, LIST-STATUS extension via `ListOptions`), existing `rimap-content::unicode::sanitize`, existing `rimap-audit::record::WarningCode`.

---

## Prior-Art Context

`crates/rimap-imap/src/types.rs:48-68` defines `Folder` with `attributes: Vec<String>` (built via `format!("{attr:?}")` on `async_imap::types::NameAttribute` at `crates/rimap-imap/src/ops/folders.rs:30`) and a `selectable: bool` derived from those strings via `is_selectable` in the same module (`ops/folders.rs:48`). Consumers in `crates/rimap-server/src/tools/admin/list_folders.rs` read `folder.selectable` and emit `flags: Vec<String>` directly into the `meta` section of the `ToolResponse` (the "trusted" envelope per `crates/rimap-server/src/mcp/response.rs:17`).

`crates/rimap-imap/src/ops/folder_management.rs::validate_folder_name` (lines 14–40) already rejects empty / oversize names, all control characters (`< 0x20` or `== 0x7f`), and any substring `".."`. It is called on CREATE/RENAME/DELETE/EXPUNGE inputs but never on server responses from LIST, SELECT, STATUS, MOVE, or COPY.

`Connection` tracks server capabilities via `AtomicBool` fields: `has_move` for RFC 6851, `has_uidplus` for RFC 4315 (`crates/rimap-imap/src/connection.rs:89-95`). The post-login capability probe (`connection.rs:408-422`) issues `CAPABILITY` and checks for each capability by name. LIST-STATUS (RFC 5819) fits the same pattern.

`rimap_content::unicode::sanitize(bytes, charset, max_bytes, location) -> (String, Vec<SecurityWarning>)` (at `crates/rimap-content/src/unicode.rs:184`) performs charset decode → NFKC → codepoint filtering → grapheme-aware truncation, returning a `Vec<SecurityWarning>` populated via `WarningCode::UnicodeBidiOverrideStripped`, `UnicodeZeroWidthStripped`, `UnicodeC0C1Stripped`. `rimap-server` already depends on `rimap-content`, so no new dep is needed for #98.

`FolderStatus` already exists in `rimap-imap/src/types.rs:103-116` with 5 optional `u32` fields (`messages`, `recent`, `uid_next`, `uid_validity`, `unseen`). Task 7 pairs it with `Folder` in the return of a new `list_folders_with_status` operation.

---

## File Structure

### Modified files

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `crates/rimap-imap/src/types.rs` | New `FolderAttribute` enum; `Folder.attributes: Vec<FolderAttribute>`; drop `Folder.selectable` field; add `Folder::selectable()` method. |
| Modify | `crates/rimap-imap/src/ops/folders.rs` | Map `NameAttribute` → `FolderAttribute` at the LIST boundary. Update `is_selectable` to consume typed attributes. Add `validate_server_folder_name` helper. Apply it to every LIST result and to `select` / `status` inputs. Add `list_with_status` operation (LIST-STATUS path) with capability fallback. |
| Modify | `crates/rimap-imap/src/ops/folder_management.rs` | Tighten `validate_folder_name`: segment-aware traversal check (reject `..` / `.` path segments), bidi/ZWJ warnings. |
| Modify | `crates/rimap-imap/src/ops/move_message.rs` | Validate `dest_folder` via `validate_server_folder_name` before `uid_mv` / `uid_copy`. |
| Modify | `crates/rimap-imap/src/connection.rs` | Add `has_list_status: AtomicBool` + post-login probe. Expose `has_list_status_capability()`. Expose a public `list_folders_with_status` wrapper that dispatches to the new op. |
| Modify | `crates/rimap-server/src/tools/admin/list_folders.rs` | Sanitize each folder's `name` + `flags` via `rimap_content::unicode::sanitize`; surface accumulated `SecurityWarning`s on the response. Adopt `list_folders_with_status` to avoid the N+1 STATUS loop when the capability is present. |
| Modify | `crates/rimap-server/src/mcp/response.rs` (optional) | If the cleanest shape for #98 requires a new response-shape helper, add it here. Expected: minimal change; the existing `ToolResponse<M, U>` generic already accommodates a warnings field under `meta` or `untrusted`. |

### Unchanged

- `crates/rimap-content/src/unicode.rs` — we consume the existing API.
- `crates/rimap-audit/src/record/mod.rs` — reuse existing `WarningCode` variants; no new ones.

---

## Task 1: `FolderAttribute` enum + `NameAttribute` mapping (#91 types)

**Issue:** #91 — typed folder attributes.

**Files:**
- Modify: `crates/rimap-imap/src/types.rs`

### Approach

Define a public `FolderAttribute` enum covering the RFC 3501 / RFC 5258 attributes the codebase branches on:

- `\Noselect`
- `\NoInferiors`
- `\Marked`
- `\Unmarked`
- `\HasChildren`
- `\HasNoChildren`
- `\NonExistent`
- `Other(String)` catch-all for anything `async-imap` reports as `Extension`

This task adds the type only. Task 2 swaps `Folder.attributes`'s type and migrates consumers.

**Real `NameAttribute` shape (imap-proto 0.16.6, re-exported via `async_imap::types::NameAttribute<'a>`):**

```rust
pub enum NameAttribute<'a> {
    NoInferiors,       // RFC 3501
    NoSelect,
    Marked,
    Unmarked,
    All, Archive, Drafts, Flagged, Junk, Sent, Trash,  // RFC 6154 special-use
    Extension(Cow<'a, str>),  // catch-all, used for \HasChildren, \HasNoChildren, \NonExistent
}
```

Important: `HasChildren`, `HasNoChildren`, `NonExistent` are NOT first-class variants — they arrive via `Extension(Cow<'a, str>)` where the string is `"\\HasChildren"` etc. The RFC 6154 special-use variants (`All`, `Archive`, `Drafts`, `Flagged`, `Junk`, `Sent`, `Trash`) ARE first-class, but the codebase already processes them via a separate `Folder.special_use: Option<SpecialUse>` path. To preserve behavior without duplicating information, map those to `Other(spelling)` in `FolderAttribute`.

- [ ] **Step 1: Write failing test for the enum shape**

Add to `crates/rimap-imap/src/types.rs` in a `#[cfg(test)] mod tests` block at the bottom:

```rust
#[cfg(test)]
mod tests {
    use super::FolderAttribute;

    #[test]
    fn folder_attribute_round_trips_rfc_3501_variants() {
        use async_imap::types::NameAttribute;

        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::NoSelect),
            FolderAttribute::Noselect,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::NoInferiors),
            FolderAttribute::NoInferiors,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Marked),
            FolderAttribute::Marked,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Unmarked),
            FolderAttribute::Unmarked,
        );
    }

    #[test]
    fn folder_attribute_extension_decodes_children_and_nonexistent() {
        use async_imap::types::NameAttribute;
        assert_eq!(
            FolderAttribute::from_name_attribute(
                &NameAttribute::Extension("\\HasChildren".into()),
            ),
            FolderAttribute::HasChildren,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(
                &NameAttribute::Extension("\\HasNoChildren".into()),
            ),
            FolderAttribute::HasNoChildren,
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(
                &NameAttribute::Extension("\\NonExistent".into()),
            ),
            FolderAttribute::NonExistent,
        );
    }

    #[test]
    fn folder_attribute_unknown_extension_becomes_other() {
        use async_imap::types::NameAttribute;
        let attr = FolderAttribute::from_name_attribute(
            &NameAttribute::Extension("\\Unknown".into()),
        );
        assert_eq!(attr, FolderAttribute::Other("\\Unknown".to_string()));
    }

    #[test]
    fn folder_attribute_special_use_variants_become_other_preserving_spelling() {
        // RFC 6154 special-use variants are first-class in NameAttribute,
        // but the codebase routes them through Folder.special_use — so the
        // attribute list carries them as Other(spelling) to preserve shape
        // without duplicating information.
        use async_imap::types::NameAttribute;
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Sent),
            FolderAttribute::Other("\\Sent".to_string()),
        );
        assert_eq!(
            FolderAttribute::from_name_attribute(&NameAttribute::Trash),
            FolderAttribute::Other("\\Trash".to_string()),
        );
    }
}
```

`async-imap` is already a regular dep — no Cargo changes needed.

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap --lib types::tests::folder_attribute`
Expected: FAIL — enum undefined.

- [ ] **Step 3: Define `FolderAttribute`**

Add to `crates/rimap-imap/src/types.rs` near the top (before `Folder`):

```rust
/// RFC 3501 / RFC 5258 mailbox name attribute reported by LIST.
///
/// Maps `async_imap::types::NameAttribute` to a stable, match-friendly
/// representation. Extension attributes that the codebase does not branch
/// on land in `Other(String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderAttribute {
    /// `\Noselect` — mailbox cannot be selected.
    Noselect,
    /// `\NoInferiors` — no children may be created under this mailbox.
    NoInferiors,
    /// `\Marked` — server considers this mailbox interesting.
    Marked,
    /// `\Unmarked` — server does not consider this mailbox interesting.
    Unmarked,
    /// `\HasChildren` (RFC 5258).
    HasChildren,
    /// `\HasNoChildren` (RFC 5258).
    HasNoChildren,
    /// `\NonExistent` (RFC 5258) — mailbox name is known but does not exist.
    NonExistent,
    /// Any other attribute the server reported (extension / unknown).
    Other(String),
}

impl FolderAttribute {
    /// Translate an `async_imap::types::NameAttribute` to a typed variant.
    ///
    /// `HasChildren` / `HasNoChildren` / `NonExistent` arrive through
    /// `NameAttribute::Extension(Cow<'_, str>)` — decoded here by matching
    /// the attribute string. RFC 6154 special-use variants (`Sent`,
    /// `Trash`, etc.) are first-class in `NameAttribute` but the codebase
    /// routes them through `Folder.special_use`; here they become
    /// `Other(spelling)` so the attribute list preserves its shape without
    /// duplicating information.
    #[must_use]
    pub fn from_name_attribute(attr: &async_imap::types::NameAttribute<'_>) -> Self {
        use async_imap::types::NameAttribute;
        match attr {
            NameAttribute::NoSelect => Self::Noselect,
            NameAttribute::NoInferiors => Self::NoInferiors,
            NameAttribute::Marked => Self::Marked,
            NameAttribute::Unmarked => Self::Unmarked,
            NameAttribute::All => Self::Other("\\All".to_string()),
            NameAttribute::Archive => Self::Other("\\Archive".to_string()),
            NameAttribute::Drafts => Self::Other("\\Drafts".to_string()),
            NameAttribute::Flagged => Self::Other("\\Flagged".to_string()),
            NameAttribute::Junk => Self::Other("\\Junk".to_string()),
            NameAttribute::Sent => Self::Other("\\Sent".to_string()),
            NameAttribute::Trash => Self::Other("\\Trash".to_string()),
            NameAttribute::Extension(s) => match s.as_ref() {
                "\\HasChildren" => Self::HasChildren,
                "\\HasNoChildren" => Self::HasNoChildren,
                "\\NonExistent" => Self::NonExistent,
                _ => Self::Other(s.to_string()),
            },
            // NameAttribute is #[non_exhaustive] — fall through to preserve
            // future-added variants as `Other(debug-repr)`.
            other => Self::Other(format!("{other:?}")),
        }
    }

    /// Stable wire-safe string form for serialization (matches RFC 3501
    /// attribute spelling, including the leading backslash). Used by
    /// `rimap-server`'s `FolderEntry.flags: Vec<String>` boundary.
    #[must_use]
    pub fn as_wire_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::Noselect => "\\Noselect".into(),
            Self::NoInferiors => "\\NoInferiors".into(),
            Self::Marked => "\\Marked".into(),
            Self::Unmarked => "\\Unmarked".into(),
            Self::HasChildren => "\\HasChildren".into(),
            Self::HasNoChildren => "\\HasNoChildren".into(),
            Self::NonExistent => "\\NonExistent".into(),
            Self::Other(s) => s.as_str().into(),
        }
    }
}
```

The mapping above was verified against `imap-proto 0.16.6` (the version `async-imap` re-exports), which has `#[non_exhaustive]` on the enum. If `cargo update` pulls a newer `imap-proto` with additional variants, the catch-all `other => Self::Other(format!("{other:?}"))` arm absorbs them without a compile break.

- [ ] **Step 4: Run tests — expect PASS**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap --lib types::tests::folder_attribute`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/types.rs
git commit -m "imap: add typed FolderAttribute enum (#91 prep)

Maps async_imap::types::NameAttribute to a stable enum covering the
RFC 3501 / RFC 5258 attributes the codebase branches on. Extension
variants resolve to known names (\\NonExistent) or fall through to
Other(String). No call-site migration yet — task 2 swaps
Folder.attributes' type and updates consumers."
```

---

## Task 2: Migrate `Folder.attributes` + `selectable()` method (#91)

**Issue:** #91.

**Files:**
- Modify: `crates/rimap-imap/src/types.rs`
- Modify: `crates/rimap-imap/src/ops/folders.rs`
- Modify: `crates/rimap-server/src/tools/admin/list_folders.rs`

### Approach

Replace `Folder.attributes: Vec<String>` with `Vec<FolderAttribute>`. Drop `Folder.selectable: bool`. Add `impl Folder { pub fn selectable(&self) -> bool }` derived from the attribute list. Update `ops/folders.rs::list` to map `NameAttribute` via `FolderAttribute::from_name_attribute`. Update `is_selectable` to consume typed attributes. Update `list_folders.rs` to call `folder.selectable()` and map `FolderAttribute` → `String` at the `FolderEntry.flags` boundary.

- [ ] **Step 1: Update the `Folder` struct**

In `crates/rimap-imap/src/types.rs`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Mailbox path reported by the server (Modified UTF-7, not decoded).
    pub name: String,
    /// Attributes reported on this mailbox.
    pub attributes: Vec<FolderAttribute>,
    /// Hierarchy delimiter (`/` for most servers; `None` for namespaces
    /// without a delimiter).
    pub delimiter: Option<char>,
    /// RFC 6154 special-use marker, if present.
    pub special_use: Option<SpecialUse>,
}

impl Folder {
    /// Whether this mailbox can be `SELECT`ed. Derived from the attribute
    /// list — `\Noselect` and `\NonExistent` are non-selectable.
    #[must_use]
    pub fn selectable(&self) -> bool {
        !self
            .attributes
            .iter()
            .any(|a| matches!(a, FolderAttribute::Noselect | FolderAttribute::NonExistent))
    }
}
```

Note: removed `selectable: bool` field. Keep all other fields.

- [ ] **Step 2: Migrate `ops/folders.rs::list`**

At `crates/rimap-imap/src/ops/folders.rs:14-37`, replace the `attributes: attrs.iter().map(...).collect()` line with:

```rust
    attributes: attrs
        .iter()
        .map(crate::types::FolderAttribute::from_name_attribute)
        .collect(),
```

Remove the `selectable:` field population from the `Folder { ... }` struct literal (the struct no longer has it).

- [ ] **Step 3: Migrate `is_selectable` — drop it or retype**

The `is_selectable(&[NameAttribute]) -> bool` helper in `ops/folders.rs:48` is now redundant because `Folder::selectable()` derives the same boolean from the typed list. Two options:

- (a) **Delete `is_selectable`** and its private tests; callers use `folder.selectable()`.
- (b) **Keep `is_selectable` but retype** to `fn is_selectable(attrs: &[FolderAttribute]) -> bool` so it can be called during list construction before the full `Folder` is built.

Choose (a). It's the cleaner cut. Drop any callers of `is_selectable` and its private unit tests (those tests move to `types::tests` coverage of `Folder::selectable`).

- [ ] **Step 4: Migrate `list_folders.rs` consumer**

At `crates/rimap-server/src/tools/admin/list_folders.rs`, update the loop that builds `FolderEntry`:

```rust
    for folder in folders {
        if !folder.selectable() {
            // non-selectable folders skip STATUS
            folder_entries.push(FolderEntry {
                name: folder.name,
                delimiter: folder.delimiter,
                flags: folder
                    .attributes
                    .iter()
                    .map(|a| a.as_wire_str().into_owned())
                    .collect(),
                exists: None,
                unseen: None,
                uid_validity: None,
            });
            continue;
        }
        // existing STATUS fetch path — unchanged; just map attributes here too:
        folder_entries.push(FolderEntry {
            name: folder.name,
            delimiter: folder.delimiter,
            flags: folder
                .attributes
                .iter()
                .map(|a| a.as_wire_str().into_owned())
                .collect(),
            exists: status.messages,
            unseen: status.unseen,
            uid_validity: status.uid_validity,
        });
    }
```

Adapt to the actual control flow — don't change the STATUS-fetching logic; only the attribute mapping. Grep for `folder.selectable` and `folder.attributes` to catch every call site.

- [ ] **Step 5: Write / migrate `Folder::selectable()` test**

Add to the `#[cfg(test)] mod tests` in `types.rs`:

```rust
    #[test]
    fn folder_selectable_when_no_noselect() {
        let f = Folder {
            name: "INBOX".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(f.selectable());
    }

    #[test]
    fn folder_not_selectable_with_noselect() {
        let f = Folder {
            name: "[Gmail]".to_string(),
            attributes: vec![FolderAttribute::Noselect, FolderAttribute::HasChildren],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(!f.selectable());
    }

    #[test]
    fn folder_not_selectable_with_nonexistent() {
        let f = Folder {
            name: "orphan".to_string(),
            attributes: vec![FolderAttribute::NonExistent],
            delimiter: Some('/'),
            special_use: None,
        };
        assert!(!f.selectable());
    }
```

- [ ] **Step 6: Run workspace tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean. The integration tests may reference `Folder { ... }` literals — if so, remove the `selectable:` field from each. Grep: `grep -rn "Folder {" crates/rimap-imap/tests/ crates/rimap-server/tests/`.

- [ ] **Step 7: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/types.rs crates/rimap-imap/src/ops/folders.rs \
        crates/rimap-server/src/tools/admin/list_folders.rs
# plus any integration-test files updated
git commit -m "imap: replace Folder.attributes Vec<String> with typed enum (#91)

Folder.attributes is now Vec<FolderAttribute>. Folder.selectable is
removed in favor of Folder::selectable() derived from the attribute
list. rimap-server's FolderEntry.flags: Vec<String> is built at the
response boundary via FolderAttribute::as_wire_str, so the JSON shape
of the MCP response is unchanged."
```

---

## Task 3: Server-origin name validator (#95 baseline)

**Issue:** #95.

**Files:**
- Modify: `crates/rimap-imap/src/ops/folders.rs`

### Approach

Add `validate_server_folder_name(name: &str) -> Result<(), ImapError>` — permissive baseline: reject NUL, all control chars in `\x01-\x1f` and `\x7f`. No bidi/ZWJ handling here (that belongs to the `rimap-content` sanitization step in Task 6). Apply the validator at the LIST boundary (inside `list`) — names that fail are dropped from the returned `Vec<Folder>`, with a `tracing::warn!` noting the rejection. Also apply the validator inside `select` and `status` on their `folder` input so any caller that passes a server-returned name directly gets the same guard.

- [ ] **Step 1: Write failing test**

Add to `crates/rimap-imap/src/ops/folders.rs` tests:

```rust
    #[test]
    fn validate_server_folder_name_rejects_nul() {
        let err = super::validate_server_folder_name("INBOX\0").unwrap_err();
        assert!(matches!(err, ImapError::Protocol(_)));
    }

    #[test]
    fn validate_server_folder_name_rejects_c0_c1() {
        for bad in ["\x01INBOX", "INBOX\x1f", "INBOX\x7f", "A\x0aB"] {
            let err = super::validate_server_folder_name(bad).unwrap_err();
            assert!(matches!(err, ImapError::Protocol(_)), "bad = {bad:?}");
        }
    }

    #[test]
    fn validate_server_folder_name_accepts_normal() {
        super::validate_server_folder_name("INBOX").unwrap();
        super::validate_server_folder_name("[Gmail]/All Mail").unwrap();
        super::validate_server_folder_name("Folder with spaces").unwrap();
        // Bidi / ZWJ are accepted here (baseline permissive); Task 6 handles
        // them downstream via rimap_content::unicode::sanitize.
        super::validate_server_folder_name("folder\u{202e}txt").unwrap();
    }
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap --lib ops::folders::tests::validate_server_folder_name`
Expected: FAIL — helper undefined.

- [ ] **Step 3: Add the validator**

In `crates/rimap-imap/src/ops/folders.rs` (top of file, before `list`):

```rust
/// Validate a mailbox name returned by the server BEFORE it flows into
/// subsequent IMAP commands or MCP responses.
///
/// Rejects NUL and all C0/C1 control characters (`\x01`–`\x1f`, `\x7f`).
/// Bidi override and zero-width characters are NOT rejected here —
/// `rimap-server` sanitizes them at the response boundary via
/// `rimap_content::unicode::sanitize`, which surfaces them as warnings
/// rather than dropping the folder.
///
/// # Errors
/// Returns `ImapError::Protocol` with a descriptive message if the name
/// contains a disallowed control character.
pub(crate) fn validate_server_folder_name(name: &str) -> Result<(), ImapError> {
    for (i, b) in name.bytes().enumerate() {
        if b == 0 || b < 0x20 || b == 0x7f {
            return Err(ImapError::Protocol(
                async_imap::error::Error::Bad(
                    format!(
                        "server returned mailbox name containing control \
                         byte 0x{b:02x} at offset {i}"
                    ),
                ),
            ));
        }
    }
    Ok(())
}
```

**Verify `ImapError::Protocol`'s inner type.** Look at `crates/rimap-imap/src/error.rs` — if `Protocol` wraps something other than `async_imap::error::Error`, adjust. A plain `ImapError::Protocol(async_imap::error::Error::Bad(message))` pattern is used throughout the codebase; grep for examples: `grep -rn "ImapError::Protocol" crates/rimap-imap/src/ops/`.

- [ ] **Step 4: Apply validator at the LIST boundary**

Update `ops/folders.rs::list` to validate each incoming `folder.name` before constructing the `Folder`:

```rust
pub(crate) async fn list(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<Folder>, ImapError> {
    let mut stream = session.list(Some(""), Some(pattern)).await.map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(mailbox) = stream.next().await {
        let mailbox = mailbox.map_err(map_err)?;
        let name = mailbox.name().to_string();
        // Drop names with control bytes — logged at warn level so operators
        // can see malformed LIST responses without failing the whole call.
        if let Err(e) = validate_server_folder_name(&name) {
            tracing::warn!(
                error = %e,
                "dropping LIST entry with invalid mailbox name",
            );
            continue;
        }
        // ... existing Folder construction
    }
    Ok(out)
}
```

Adapt to the actual structure of the existing function (streaming loop shape may differ slightly).

- [ ] **Step 5: Apply validator to `select` / `status`**

At `ops/folders.rs::select` (around line 94) and `::status` (around line 67), add at the top:

```rust
    validate_server_folder_name(folder)?;
```

These functions currently accept untrusted strings; validating at entry pushes the check to the boundary rather than relying on every caller to pre-validate.

- [ ] **Step 6: Run tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 7: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/ops/folders.rs
git commit -m "imap: validate server-returned mailbox names (#95)

New validate_server_folder_name helper rejects NUL and C0/C1/DEL
control bytes. Applied at three boundaries: the LIST response
stream (invalid names are dropped with tracing::warn!), SELECT, and
STATUS. Bidi/ZWJ are NOT rejected here — task 6 sanitizes those at
the MCP response boundary so operators see a warning rather than
losing a folder entirely."
```

---

## Task 4: Tighten `validate_folder_name` (#95)

**Issue:** #95 (second half).

**Files:**
- Modify: `crates/rimap-imap/src/ops/folder_management.rs`

### Approach

The existing client-input validator uses `name.contains("..")`, which false-matches legitimate names containing `..` as substrings (e.g. `Mail/Receipts..2024`). Replace with delimiter-aware segment iteration: split on `/`, reject any segment that is exactly `.` or `..`. Also reject names containing bidi control characters or zero-width joiners — these CAN be rejected at the client-input boundary because the client created them (no legitimate case).

Keep the existing NUL / control-char check.

- [ ] **Step 1: Write failing tests**

Add to `crates/rimap-imap/src/ops/folder_management.rs` tests:

```rust
    #[test]
    fn validate_folder_name_rejects_dot_segment() {
        assert!(validate_folder_name("a/./b").is_err());
        assert!(validate_folder_name("./a").is_err());
        assert!(validate_folder_name("a/.").is_err());
    }

    #[test]
    fn validate_folder_name_rejects_dotdot_segment() {
        assert!(validate_folder_name("a/../b").is_err());
        assert!(validate_folder_name("../a").is_err());
        assert!(validate_folder_name("a/..").is_err());
    }

    #[test]
    fn validate_folder_name_accepts_legitimate_dots_in_segment() {
        // Legitimate: "Receipts..2024" is a name with dots in the middle,
        // not a path traversal. The old substring check rejected it.
        validate_folder_name("Mail/Receipts..2024").unwrap();
        validate_folder_name("my.folder").unwrap();
    }

    #[test]
    fn validate_folder_name_rejects_bidi_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — common spoofing vector.
        assert!(validate_folder_name("folder\u{202e}txt").is_err());
    }

    #[test]
    fn validate_folder_name_rejects_zero_width_joiner() {
        // U+200D ZERO WIDTH JOINER.
        assert!(validate_folder_name("evil\u{200d}folder").is_err());
    }
```

- [ ] **Step 2: Run tests — expect FAIL** for the new cases (existing `..` test should pass for `a/../b` but fail on the legitimate-substring case).

- [ ] **Step 3: Rewrite `validate_folder_name`**

Replace the body at `crates/rimap-imap/src/ops/folder_management.rs:14-40`:

```rust
pub(crate) fn validate_folder_name(name: &str) -> Result<(), ImapError> {
    if name.is_empty() {
        return Err(ImapError::InvalidInput {
            message: "folder name must not be empty".to_string(),
        });
    }
    if name.len() > MAX_FOLDER_NAME_BYTES {
        return Err(ImapError::InvalidInput {
            message: format!(
                "folder name exceeds {MAX_FOLDER_NAME_BYTES}-byte limit \
                 ({} bytes)",
                name.len()
            ),
        });
    }
    if name.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
        return Err(ImapError::InvalidInput {
            message: "folder name must not contain control characters"
                .to_string(),
        });
    }
    // Delimiter-aware traversal check: split on '/' and reject any
    // path segment that is exactly '.' or '..'. Preserves legitimate
    // names like "Receipts..2024" that merely contain a `..` substring.
    for segment in name.split('/') {
        if segment == "." || segment == ".." {
            return Err(ImapError::InvalidInput {
                message: format!(
                    "folder name contains traversal segment `{segment}`"
                ),
            });
        }
    }
    // Reject bidi control characters and zero-width joiners. These have
    // no legitimate use in client-supplied folder names and are a common
    // spoofing vector (e.g., INBOX\u{202e}txt.exe).
    for c in name.chars() {
        if matches!(
            c,
            '\u{202a}'..='\u{202e}'   // bidi embedding / override
            | '\u{2066}'..='\u{2069}' // isolate
            | '\u{200b}'              // zero-width space
            | '\u{200c}'              // zero-width non-joiner
            | '\u{200d}'              // zero-width joiner
            | '\u{feff}'              // byte-order mark
        ) {
            return Err(ImapError::InvalidInput {
                message: format!(
                    "folder name contains disallowed Unicode control \
                     character U+{:04X}",
                    c as u32,
                ),
            });
        }
    }
    Ok(())
}
```

**Verify `ImapError::InvalidInput` exists.** Look at `crates/rimap-imap/src/error.rs`. If the variant has a different name (e.g. `InvalidFolderName`), adapt. The old validator produced `ImapError::InvalidInput` per `folder_management.rs` — assume it still does.

- [ ] **Step 4: Run tests — expect PASS**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap --lib ops::folder_management::tests`
Expected: all new tests pass. The existing tests for the validator should also pass (the change is strictly stricter in some directions and strictly looser in one).

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/ops/folder_management.rs
git commit -m "imap: tighten validate_folder_name (#95)

Replace name.contains(\"..\") with delimiter-aware segment iteration:
reject path segments equal to \".\" or \"..\" but allow legitimate
names like \"Receipts..2024\". Also reject bidi overrides (U+202A..E,
U+2066..9) and zero-width characters (U+200B..D, U+FEFF) in client-
supplied folder names."
```

---

## Task 5: Apply server-name validator to MOVE/COPY `dest_folder` (#95)

**Issue:** #95 (third boundary).

**Files:**
- Modify: `crates/rimap-imap/src/ops/move_message.rs`

### Approach

`move_messages` and `copy_delete_fallback` accept `dest_folder: &str` and pass it verbatim to `uid_mv` / `uid_copy`. In multi-account / agent-controlled contexts, the destination may originate from untrusted input. Apply `validate_server_folder_name` at the entry of `move_messages` and `copy_delete_fallback`.

- [ ] **Step 1: Write failing test**

Add to `crates/rimap-imap/src/ops/move_message.rs` tests:

```rust
    #[test]
    fn move_messages_rejects_nul_in_dest_folder() {
        // Invoke via whatever helper exists — likely the fn needs a mock
        // ImapSession. If the project doesn't have a mock session, the
        // direct validator call inside move_messages is what's being
        // pinned. A smaller unit test that re-exports
        // crate::ops::folders::validate_server_folder_name and calls it
        // with "INBOX\0" is fine.
        use crate::ops::folders::validate_server_folder_name;
        assert!(validate_server_folder_name("target\0folder").is_err());
    }
```

The test is a light smoke check; the real coverage is the control-flow change below. If the project has a mock session infra, prefer a real end-to-end test.

- [ ] **Step 2: Apply validator**

At `crates/rimap-imap/src/ops/move_message.rs::move_messages` (top of function, line ~40):

```rust
pub(crate) async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_move: bool,
    has_uidplus: bool,
) -> Result<MoveOutcome, ImapError> {
    crate::ops::folders::validate_server_folder_name(dest_folder)?;
    // existing body unchanged
    ...
}
```

Same treatment at the top of `copy_delete_fallback`.

- [ ] **Step 3: Run tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-imap && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 4: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/ops/move_message.rs
git commit -m "imap: validate dest_folder before UID MOVE / UID COPY (#95)

Both move_messages and copy_delete_fallback now run
validate_server_folder_name on dest_folder before issuing the IMAP
command. Prevents control-byte injection via a
destination-folder argument that wasn't routed through the LIST
validator."
```

---

## Task 6: Sanitize `list_folders` response (#98)

**Issue:** #98 — server-controlled bytes under the trusted `meta` envelope.

**Files:**
- Modify: `crates/rimap-server/src/tools/admin/list_folders.rs`

### Approach

For each folder in the response, run the `name` and each element of `flags` through `rimap_content::unicode::sanitize(bytes, None, MAX, location)` with a generous `MAX` (e.g., 1024 bytes — folder names are short, this is just a DoS bound). Accumulate any returned `SecurityWarning`s across all folders. Attach the warnings to the response. Replace the `FolderEntry.name` and `FolderEntry.flags` values with their sanitized forms.

Issue #98 explicitly chose option (B) — sanitize-and-warn — over moving the folders under the `untrusted` envelope. Keeping them in `meta` preserves agent ergonomics; the warning channel tells the operator that something was modified.

- [ ] **Step 1: Write failing test**

Add a test file or inline test in `crates/rimap-server/src/tools/admin/list_folders.rs`:

```rust
    #[test]
    fn list_folders_sanitizes_bidi_in_folder_name() {
        // This is a unit-level test for the sanitization helper introduced
        // below — call it directly with a simulated Folder list rather than
        // spinning up the full MCP dispatch.
        use crate::tools::admin::list_folders::sanitize_folder_entries;
        use rimap_imap::{Folder, FolderAttribute};

        let folders = vec![Folder {
            name: "Inbox\u{202e}gnilleS".to_string(),
            attributes: vec![FolderAttribute::HasNoChildren],
            delimiter: Some('/'),
            special_use: None,
        }];
        let (entries, warnings) = sanitize_folder_entries(folders);
        assert_eq!(entries.len(), 1);
        assert!(
            !entries[0].name.contains('\u{202e}'),
            "sanitized name should not contain U+202E, got: {:?}",
            entries[0].name,
        );
        assert!(
            !warnings.is_empty(),
            "sanitize should have produced a bidi-stripped warning",
        );
    }
```

(The `sanitize_folder_entries` helper is introduced in Step 2. If an alternate shape fits better, adapt — this is a suggested factoring.)

- [ ] **Step 2: Add the sanitization path**

In `crates/rimap-server/src/tools/admin/list_folders.rs`, extract a helper:

```rust
const MAX_FOLDER_NAME_BYTES: usize = 1024;

/// Sanitize a list of `Folder` entries for inclusion in the `list_folders`
/// MCP response. Returns the sanitized `FolderEntry` list and the
/// accumulated security warnings.
///
/// Folder names and flags are run through `rimap_content::unicode::sanitize`
/// so server-controlled bidi overrides, zero-width characters, and C0/C1
/// stripping are surfaced as structured warnings rather than riding
/// unfiltered under the trusted `meta` envelope (#98).
pub(crate) fn sanitize_folder_entries(
    folders: Vec<rimap_imap::Folder>,
) -> (Vec<FolderEntry>, Vec<rimap_audit::record::SecurityWarning>) {
    let mut entries = Vec::with_capacity(folders.len());
    let mut warnings = Vec::new();

    for folder in folders {
        let (clean_name, name_warnings) = rimap_content::unicode::sanitize(
            folder.name.as_bytes(),
            None,
            MAX_FOLDER_NAME_BYTES,
            "folder.name",
        );
        warnings.extend(name_warnings);

        let flags: Vec<String> = folder
            .attributes
            .iter()
            .map(|attr| {
                let raw = attr.as_wire_str();
                let (clean, flag_warnings) = rimap_content::unicode::sanitize(
                    raw.as_bytes(),
                    None,
                    MAX_FOLDER_NAME_BYTES,
                    "folder.flag",
                );
                warnings.extend(flag_warnings);
                clean
            })
            .collect();

        entries.push(FolderEntry {
            name: clean_name,
            delimiter: folder.delimiter,
            flags,
            exists: None,
            unseen: None,
            uid_validity: None,
        });
    }

    (entries, warnings)
}
```

Verify the `SecurityWarning` type's location. Based on the survey, `rimap_content::unicode::sanitize` returns `Vec<SecurityWarning>` where `SecurityWarning` may be re-exported from `rimap-audit`. Grep: `grep -rn "pub struct SecurityWarning\|pub use.*SecurityWarning" crates/rimap-audit/src/ crates/rimap-content/src/`. Adapt the import path.

- [ ] **Step 3: Wire the helper into the tool handler**

Update the existing `handle` function in `list_folders.rs` to call `sanitize_folder_entries` after the LIST (and STATUS) fetches complete, merge its warnings into the final response, and return the sanitized entries in `ListFoldersMeta.folders`.

The STATUS-fetch step still happens per folder — Task 8 switches to LIST-STATUS where possible. For this task, keep the existing fetch loop; just sanitize after the loop ends. Specifically: the existing inner loop builds a temporary `Vec<FolderEntry>` with `exists` / `unseen` / `uid_validity` populated. Keep that, but swap the `name` and `flags` fields to their sanitized forms (either by restructuring the loop to call sanitize during construction, or by sanitizing the `name`/`flags` fields post-hoc).

Add a `warnings` field to the response shape. Preferred placement per the issue (option B): keep folders in `meta`, add `meta.warnings: Vec<SecurityWarning>`. If the `ToolResponse<M, U>` envelope only allows structured data under `meta`, put the warnings inside `ListFoldersMeta` as a new field:

```rust
pub struct ListFoldersMeta {
    pub folders: Vec<FolderEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_warnings: Vec<rimap_audit::record::SecurityWarning>,
}
```

Return shape: `ToolResponse::meta_only(ListFoldersMeta { folders, security_warnings: warnings })`.

- [ ] **Step 4: Run tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test -p rimap-server && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

- [ ] **Step 5: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-server/src/tools/admin/list_folders.rs
git commit -m "server: sanitize folder names + flags in list_folders (#98)

Each folder's name and each flag are run through
rimap_content::unicode::sanitize before being placed under the
trusted meta envelope. Accumulated SecurityWarning records (bidi
overrides stripped, zero-width chars stripped, C0/C1 stripped) are
surfaced on the response so operators and agents can see when a
server returned something the sanitizer had to modify."
```

---

## Task 7: LIST-STATUS capability + `list_folders_with_status` (#92)

**Issue:** #92 — N+1 STATUS loop.

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs`
- Modify: `crates/rimap-imap/src/ops/folders.rs`
- Modify: `crates/rimap-imap/src/types.rs` (optional — may want a typed return shape)

### Approach

Add a `has_list_status: AtomicBool` field to `ConnectionInner`. In the post-login capability probe (`connection.rs:408-422`), also check for `"LIST-STATUS"` and store the result. Expose `has_list_status_capability(&self) -> bool`.

Add an `ops::folders::list_with_status` async fn that, when LIST-STATUS is advertised, issues the extended LIST command `LIST "" <pattern> RETURN (STATUS (MESSAGES UIDVALIDITY UNSEEN))` in ONE round-trip and returns `Vec<(Folder, Option<FolderStatus>)>`. When LIST-STATUS is not advertised, fall back to LIST-then-STATUS-per-folder.

`async-imap` supports LIST-STATUS via `session.list_status(reference, pattern, options)` — check the actual API. If async-imap doesn't expose it directly, the fallback path is the only option for the first cut; document the gap in a TODO and file a follow-up issue.

- [ ] **Step 1: Verify async-imap's LIST-STATUS support**

Before writing any test, run:

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
grep -rn "list_status\|RETURN (STATUS" $(cargo metadata --format-version=1 | \
    jq -r '.packages[] | select(.name == "async-imap") | .manifest_path | rtrimstr("/Cargo.toml")')/src/
```

If the function exists, adapt the plan's code to call it. If not, implement the LIST-STATUS path as a raw command using async-imap's generic command execution (e.g. `session.run_command_and_read_response`), parsing the `STATUS` response-data lines interleaved with the `LIST` response-data lines.

If raw-command parsing is too invasive for this task, take the pragmatic path: **do not implement the extended LIST path at all**; just add the capability probe and the fallback shape. File a follow-up issue to wire the extended LIST once async-imap exposes it. Document the decision in the commit message.

- [ ] **Step 2: Add `has_list_status` capability field**

In `crates/rimap-imap/src/connection.rs`:

```rust
struct ConnectionInner {
    // ... existing fields ...
    /// Server advertised LIST-STATUS capability (RFC 5819) after login.
    has_list_status: AtomicBool,
}
```

Initialize in the constructor with the other `AtomicBool::new(false)` fields.

Update the post-login probe at connection.rs:408-422:

```rust
let (has_move, has_uidplus, has_list_status) = match session.capabilities().await {
    Ok(caps) => (
        caps.has_str("MOVE"),
        caps.has_str("UIDPLUS"),
        caps.has_str("LIST-STATUS"),
    ),
    Err(e) => {
        tracing::warn!(...);
        (false, false, false)
    }
};
self.inner.has_move.store(has_move, Ordering::Relaxed);
self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);
self.inner.has_list_status.store(has_list_status, Ordering::Relaxed);
```

Expose `has_list_status_capability(&self) -> bool` alongside the existing `has_move_capability` / `has_uidplus_capability`.

- [ ] **Step 3: Add `list_with_status` operation**

In `crates/rimap-imap/src/ops/folders.rs`:

```rust
/// LIST + STATUS in a single round-trip via RFC 5819 LIST-STATUS when
/// the server advertises the capability. Falls back to a LIST-then-STATUS
/// loop otherwise (one STATUS per selectable folder).
///
/// Returns (folder, status) pairs. `status` is `None` for non-selectable
/// folders regardless of capability.
///
/// # Errors
/// Propagates `ImapError` from LIST / STATUS.
pub(crate) async fn list_with_status(
    session: &mut ImapSession,
    pattern: &str,
    has_list_status: bool,
) -> Result<Vec<(Folder, Option<FolderStatus>)>, ImapError> {
    if has_list_status {
        // LIST-STATUS path — implement against the actual async-imap API.
        // If async-imap doesn't expose LIST-STATUS, fall through to the
        // legacy path; this function still satisfies the capability
        // contract (has_list_status=true just means the server supports
        // it, not that we'll use it).
        //
        // See Step 1 — if the API isn't there, document and file a follow-up.
        list_with_status_combined(session, pattern).await
    } else {
        list_with_status_legacy(session, pattern).await
    }
}

async fn list_with_status_legacy(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<(Folder, Option<FolderStatus>)>, ImapError> {
    let folders = list(session, pattern).await?;
    let mut out = Vec::with_capacity(folders.len());
    for folder in folders {
        let status = if folder.selectable() {
            Some(
                status(session, &folder.name, StatusItems::basic())
                    .await?,
            )
        } else {
            None
        };
        out.push((folder, status));
    }
    Ok(out)
}
```

Adapt `StatusItems::basic()` to whatever constructor exists — the survey noted STATUS already accepts a `StatusItems` parameter; use the same shape (MESSAGES, UIDVALIDITY, UNSEEN).

- [ ] **Step 4: Expose the operation from `Connection`**

In `crates/rimap-imap/src/connection.rs` add:

```rust
    /// List folders and fetch their STATUS in a single operation,
    /// using RFC 5819 LIST-STATUS when the server advertises the
    /// capability. Falls back to LIST-then-STATUS-per-folder otherwise.
    ///
    /// # Errors
    /// Propagates `ImapError` from the underlying commands.
    pub async fn list_folders_with_status(
        &self,
        pattern: &str,
    ) -> Result<Vec<(Folder, Option<FolderStatus>)>, ImapError> {
        let has_list_status = self.inner.has_list_status.load(Ordering::Relaxed);
        self.with_session("list_folders_with_status", async move |session| {
            ops::folders::list_with_status(session, pattern, has_list_status).await
        })
        .await
    }
```

Adapt the `with_session` helper's shape to the actual codebase — search for how `list_folders` / other ops compose with `with_session`.

- [ ] **Step 5: Run tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean. The legacy-path test may need a mock session — if the codebase doesn't have one, rely on the Dovecot integration test in `crates/rimap-imap/tests/integration/dovecot.rs` to cover the behavioral change at next PR run (dovecot supports LIST-STATUS).

- [ ] **Step 6: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-imap/src/connection.rs crates/rimap-imap/src/ops/folders.rs
git commit -m "imap: add LIST-STATUS capability + list_folders_with_status (#92)

has_list_status: AtomicBool tracks the RFC 5819 capability, probed
post-login alongside MOVE and UIDPLUS. New
Connection::list_folders_with_status dispatches to the extended LIST
when the capability is advertised, otherwise falls back to the
existing LIST-then-STATUS-per-folder loop. Non-selectable folders
skip STATUS regardless of capability."
```

---

## Task 8: `list_folders` adopts LIST-STATUS (#92 wiring)

**Issue:** #92 — wire the N+1 fix into the tool handler.

**Files:**
- Modify: `crates/rimap-server/src/tools/admin/list_folders.rs`

### Approach

Replace the LIST-then-loop-STATUS call chain with a single `connection.list_folders_with_status(pattern)` call. The sanitization path from Task 6 still runs on the returned `Folder` + `Option<FolderStatus>` pairs.

- [ ] **Step 1: Update the handler**

In `crates/rimap-server/src/tools/admin/list_folders.rs::handle`:

```rust
pub async fn handle(
    account: &AccountState,
) -> Result<ToolResponse<ListFoldersMeta>, rimap_core::RimapError> {
    let pairs = account
        .imap
        .list_folders_with_status("*")
        .await
        .map_err(rimap_core::RimapError::from)?;

    let mut entries = Vec::with_capacity(pairs.len());
    let mut warnings = Vec::new();

    for (folder, status) in pairs {
        let (clean_name, name_warnings) = rimap_content::unicode::sanitize(
            folder.name.as_bytes(),
            None,
            MAX_FOLDER_NAME_BYTES,
            "folder.name",
        );
        warnings.extend(name_warnings);

        let flags: Vec<String> = folder
            .attributes
            .iter()
            .map(|attr| {
                let raw = attr.as_wire_str();
                let (clean, w) = rimap_content::unicode::sanitize(
                    raw.as_bytes(),
                    None,
                    MAX_FOLDER_NAME_BYTES,
                    "folder.flag",
                );
                warnings.extend(w);
                clean
            })
            .collect();

        entries.push(FolderEntry {
            name: clean_name,
            delimiter: folder.delimiter,
            flags,
            exists: status.as_ref().and_then(|s| s.messages),
            unseen: status.as_ref().and_then(|s| s.unseen),
            uid_validity: status.as_ref().and_then(|s| s.uid_validity),
        });
    }

    Ok(ToolResponse::meta_only(ListFoldersMeta {
        folders: entries,
        security_warnings: warnings,
    }))
}
```

This absorbs Task 6's `sanitize_folder_entries` inline. If Task 6 left the helper as a reusable function, call it here instead (passing in the paired folders + statuses).

- [ ] **Step 2: Run workspace tests + clippy**

Run: `cd /home/dave/src/rusty-imap-mcp-folder-listing && cargo test --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: PASS and clean.

The Dovecot integration test in `crates/rimap-server/tests/e2e.rs` exercises `list_folders` — if it asserts specific status counts, no change is expected (the LIST-STATUS path returns the same data as the loop path).

- [ ] **Step 3: Commit**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
git add crates/rimap-server/src/tools/admin/list_folders.rs
git commit -m "server: list_folders uses LIST-STATUS when available (#92)

Replaces the per-folder STATUS loop with a single
Connection::list_folders_with_status call. On LIST-STATUS-capable
servers (Dovecot 2.3+, Cyrus, Gmail), this cuts list_folders latency
from O(n) round-trips to O(1). Non-capable servers transparently use
the legacy LIST-then-STATUS fallback."
```

---

## Task 9: Final workspace verification + PR

- [ ] **Step 1: Run the full verification pipeline**

```bash
cd /home/dave/src/rusty-imap-mcp-folder-listing
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny check advisories bans licenses sources
typos
```

All five must pass.

- [ ] **Step 2: Push + open PR**

Branch: `feat/folder-listing-hardening`. Target: `main`. PR body references `Closes #91`, `Closes #92`, `Closes #95`, `Closes #98`.

- [ ] **Step 3: After merge, update the roadmap spec**

Mark sub-group 1 as complete in `docs/superpowers/specs/2026-04-19-open-issues-roadmap-design.md`.
