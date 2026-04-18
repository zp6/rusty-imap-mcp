# Special-Use Folder Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded `"Drafts"` / `"Sent"` / `"Trash"` folder names with RFC 6154 `\Drafts` / `\Sent` / `\Trash` special-use discovery at account boot, so `create_draft`, `send_email`, and `protected_folders` target the server-declared mailboxes (e.g. Gmail's `[Gmail]/Drafts` instead of the user-created `Drafts` label).

**Architecture:** One-shot `LIST "" "*"` is already performed at boot by `list_folders`; we extend it. A new `SpecialUseMap` is built during account construction from the structured `NameAttribute` stream, stored on `AccountState`, and consulted by `create_draft` and `send_email` with hardcoded-string fallbacks when a server reports no matching special-use. `FolderGuard` is constructed **after** discovery so the config-supplied `protected_folders` list is expanded with the discovered names before name-based matching runs.

**Tech Stack:** Rust 1.94 workspace, `async-imap` 0.11, `imap-proto` 0.16 (`NameAttribute::{Drafts, Sent, Trash, Junk, Archive, All, Flagged, Extension}`). Workspace-inherited deps only — no new dependencies.

---

## File Structure

### Files created

- `crates/rimap-imap/src/special_use.rs` — `SpecialUse` enum + `SpecialUseMap` struct + pure resolvers, with unit tests
- `crates/rimap-server/src/boot/discovery.rs` — async one-shot helper that runs LIST and builds a `SpecialUseMap`, with unit tests using a stub `ImapAccess`-shaped input

### Files modified

- `crates/rimap-imap/src/types.rs` — add `special_use: Option<SpecialUse>` on `Folder`
- `crates/rimap-imap/src/ops/folders.rs` — populate `special_use` during LIST (pure helper `classify_special_use`, unit-tested in place alongside the existing `is_selectable` tests)
- `crates/rimap-imap/src/lib.rs` — re-export `special_use::{SpecialUse, SpecialUseMap}`
- `crates/rimap-server/src/boot/registry.rs` — add `special_use: SpecialUseMap` field to `AccountState`; change its `Debug` impl to print the resolved names
- `crates/rimap-server/src/boot/mod.rs` — wire `discovery::resolve_special_use` into the per-account boot sequence; feed expanded names to `FolderGuard::new`
- `crates/rimap-server/src/tools/compose/create_draft.rs` — replace hardcoded `"Drafts"` with `account.special_use.drafts().unwrap_or("Drafts")`
- `crates/rimap-server/src/tools/compose/send_email.rs` — replace hardcoded `"Sent"` with `account.special_use.sent().unwrap_or("Sent")`
- `crates/rimap-authz/src/folder_guard.rs` — unchanged API; verify with a test that an expanded `protected` list including `"[Gmail]/Sent Mail"` is matched case-insensitively with IMAP UTF-7 normalization
- `crates/rimap-imap/tests/integration/dovecot/dovecot.conf` — add `auto = subscribe` special-use mailbox declarations so the Dovecot harness covers the discovery path
- `crates/rimap-imap/tests/integration/dovecot.rs` — add `case_20_special_use_discovery` asserting the harness reports `\Drafts` / `\Sent` / `\Trash` / `\Junk` on the right mailboxes
- `crates/rimap-server/tests/e2e.rs` — in `e2e_full_session`, assert `create_draft` lands in the `\Drafts` mailbox and `send_email`'s Sent copy lands in the `\Sent` mailbox
- `docs/configuration.md` — add a short "Special-use folder discovery" subsection under `[security]` explaining behavior and how defaults are expanded

### Files deliberately NOT changed

- `crates/rimap-config/src/model.rs` — `default_protected_folders()` stays as `["INBOX", "Sent", "Drafts", "Trash"]`. The *literal* names are still required because not every server reports RFC 6154; the expansion happens at boot, not at config-parse time.
- `create_draft.rs` tool input schema — still no `folder` field. If users need to override the target folder, that's a future config surface.

---

## Task 1: `SpecialUse` enum + classifier

**Files:**
- Create: `crates/rimap-imap/src/special_use.rs`
- Modify: `crates/rimap-imap/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Write `crates/rimap-imap/src/special_use.rs`:

```rust
//! RFC 6154 special-use mailbox attributes and per-account resolution.
//!
//! Special-use attributes (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
//! `\Archive`, `\All`, `\Flagged`) identify a mailbox's role without
//! relying on server-specific naming conventions. Gmail's `[Gmail]/Drafts`,
//! Proton's `Drafts`, and Dovecot's `Drafts` all carry `\Drafts`; clients
//! can target "the drafts folder" without hardcoding a name per server.

use async_imap::types::NameAttribute;

/// RFC 6154 special-use attribute, plus the pseudo-attribute for
/// unrecognized `\Sent`/`\Drafts`-style extension strings that some
/// servers emit instead of the structured enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialUse {
    /// `\Drafts` — the mailbox where draft messages live.
    Drafts,
    /// `\Sent` — the mailbox where copies of outgoing messages live.
    Sent,
    /// `\Trash` — the mailbox for deleted messages.
    Trash,
    /// `\Junk` — the mailbox for spam.
    Junk,
    /// `\Archive` — the archive mailbox.
    Archive,
    /// `\All` — aggregate view (Gmail's "All Mail").
    All,
    /// `\Flagged` — aggregate view of flagged/starred messages.
    Flagged,
}

/// Classify the first recognized RFC 6154 special-use marker in the
/// attribute list. Returns `None` if no special-use marker is present.
///
/// Checks both the structured `NameAttribute` variants and
/// `Extension("\\Drafts")`-style strings (case-insensitive), because
/// older `imap-proto` releases reported special-use as extensions.
#[must_use]
pub fn classify_special_use(attrs: &[NameAttribute<'_>]) -> Option<SpecialUse> {
    for attr in attrs {
        if let Some(su) = match_variant(attr) {
            return Some(su);
        }
    }
    None
}

fn match_variant(attr: &NameAttribute<'_>) -> Option<SpecialUse> {
    match attr {
        NameAttribute::Drafts => Some(SpecialUse::Drafts),
        NameAttribute::Sent => Some(SpecialUse::Sent),
        NameAttribute::Trash => Some(SpecialUse::Trash),
        NameAttribute::Junk => Some(SpecialUse::Junk),
        NameAttribute::Archive => Some(SpecialUse::Archive),
        NameAttribute::All => Some(SpecialUse::All),
        NameAttribute::Flagged => Some(SpecialUse::Flagged),
        NameAttribute::Extension(ext) => match_extension(ext),
        _ => None,
    }
}

fn match_extension(ext: &str) -> Option<SpecialUse> {
    if ext.eq_ignore_ascii_case("\\Drafts") {
        Some(SpecialUse::Drafts)
    } else if ext.eq_ignore_ascii_case("\\Sent") {
        Some(SpecialUse::Sent)
    } else if ext.eq_ignore_ascii_case("\\Trash") {
        Some(SpecialUse::Trash)
    } else if ext.eq_ignore_ascii_case("\\Junk") {
        Some(SpecialUse::Junk)
    } else if ext.eq_ignore_ascii_case("\\Archive") {
        Some(SpecialUse::Archive)
    } else if ext.eq_ignore_ascii_case("\\All") {
        Some(SpecialUse::All)
    } else if ext.eq_ignore_ascii_case("\\Flagged") {
        Some(SpecialUse::Flagged)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_structured_drafts_variant() {
        let attrs = [NameAttribute::Drafts];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));
    }

    #[test]
    fn classify_matches_each_rfc6154_variant() {
        for (attr, expected) in [
            (NameAttribute::Drafts, SpecialUse::Drafts),
            (NameAttribute::Sent, SpecialUse::Sent),
            (NameAttribute::Trash, SpecialUse::Trash),
            (NameAttribute::Junk, SpecialUse::Junk),
            (NameAttribute::Archive, SpecialUse::Archive),
            (NameAttribute::All, SpecialUse::All),
            (NameAttribute::Flagged, SpecialUse::Flagged),
        ] {
            let attrs = [attr.clone()];
            assert_eq!(classify_special_use(&attrs), Some(expected));
        }
    }

    #[test]
    fn classify_matches_extension_strings_case_insensitive() {
        let attrs = [NameAttribute::Extension("\\drafts".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));

        let attrs = [NameAttribute::Extension("\\SENT".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Sent));
    }

    #[test]
    fn classify_returns_none_for_unrelated_attributes() {
        let attrs = [
            NameAttribute::Unmarked,
            NameAttribute::Extension("\\HasNoChildren".into()),
        ];
        assert_eq!(classify_special_use(&attrs), None);
    }

    #[test]
    fn classify_returns_first_match_when_multiple_present() {
        // \Drafts + \Sent on the same mailbox is pathological but possible
        // in misconfigured servers; we take the first match in iteration
        // order rather than erroring, to stay useful.
        let attrs = [NameAttribute::Drafts, NameAttribute::Sent];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));
    }

    #[test]
    fn classify_empty_attribute_list_returns_none() {
        assert_eq!(classify_special_use(&[]), None);
    }
}
```

Append to `crates/rimap-imap/src/lib.rs`:

```rust
pub mod special_use;
pub use special_use::{SpecialUse, classify_special_use};
```

- [ ] **Step 2: Run tests and confirm they pass**

Run: `cargo test -p rimap-imap --lib special_use`
Expected: 6 passed

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/special_use.rs crates/rimap-imap/src/lib.rs
git commit -m "feat(rimap-imap): RFC 6154 SpecialUse enum and attribute classifier"
```

---

## Task 2: Populate `Folder.special_use` during LIST

**Files:**
- Modify: `crates/rimap-imap/src/types.rs:48-65`
- Modify: `crates/rimap-imap/src/ops/folders.rs:1-34`

- [ ] **Step 1: Extend `Folder` with the new field**

In `crates/rimap-imap/src/types.rs`, replace the `Folder` struct definition with:

```rust
/// IMAP `LIST` response entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Folder name (mailbox path) as the server reported it. Modified UTF-7
    /// decoding is left to the caller / Sprint 4.
    pub name: String,
    /// Folder attribute flags (`\Noinferiors`, `\Marked`, etc.).
    pub attributes: Vec<String>,
    /// Hierarchy delimiter, if the server reported one.
    pub delimiter: Option<char>,
    /// Whether the folder can be the target of `SELECT`/`EXAMINE`/`STATUS`.
    /// False for RFC 3501 `\Noselect` parents (Gmail's `[Gmail]`, some
    /// Exchange public-folder namespaces) and RFC 5258 `\NonExistent`
    /// entries. `STATUS` against a non-selectable folder aborts the
    /// connection with `ERR_IMAP_PROTOCOL` on many servers.
    pub selectable: bool,
    /// RFC 6154 special-use marker, if the server reported one.
    /// Used to resolve "the drafts/sent/trash folder" without hardcoding
    /// server-specific names.
    pub special_use: Option<crate::special_use::SpecialUse>,
}
```

- [ ] **Step 2: Populate the field in `ops::folders::list`**

In `crates/rimap-imap/src/ops/folders.rs`, replace the `list` function with:

```rust
pub(crate) async fn list(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<Folder>, ImapError> {
    let mut stream = session
        .list(Some(""), Some(pattern))
        .await
        .map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(name) = stream.next().await {
        let name = name.map_err(map_err)?;
        let attrs = name.attributes();
        let selectable = is_selectable(attrs);
        let special_use = crate::special_use::classify_special_use(attrs);
        out.push(Folder {
            name: name.name().to_string(),
            attributes: attrs
                .iter()
                .map(|attr| format!("{attr:?}"))
                .collect(),
            delimiter: name.delimiter().and_then(|s| s.chars().next()),
            selectable,
            special_use,
        });
    }
    Ok(out)
}
```

- [ ] **Step 3: Run existing tests to catch any destructuring breakage**

Run: `cargo test -p rimap-imap --lib`
Expected: all tests pass (no destructuring of `Folder`, so struct-literal syntax still works everywhere via `..Default::default()`-free construction in `ops::folders`).

- [ ] **Step 4: Run workspace clippy**

Run: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-imap/src/types.rs crates/rimap-imap/src/ops/folders.rs
git commit -m "feat(rimap-imap): populate Folder.special_use during LIST"
```

---

## Task 3: `SpecialUseMap` resolver

**Files:**
- Modify: `crates/rimap-imap/src/special_use.rs`
- Modify: `crates/rimap-imap/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/rimap-imap/src/special_use.rs`:

```rust
use crate::types::Folder;

/// Resolved special-use → folder-name map for a single account.
///
/// Built once at account boot from the `LIST` response. Lookup is
/// infallible; callers that want a "give me drafts or fall back" pattern
/// use `drafts_or("Drafts")` to supply a literal fallback string.
#[derive(Debug, Clone, Default)]
pub struct SpecialUseMap {
    drafts: Option<String>,
    sent: Option<String>,
    trash: Option<String>,
    junk: Option<String>,
    archive: Option<String>,
    all: Option<String>,
    flagged: Option<String>,
}

impl SpecialUseMap {
    /// Build the map from the folders returned by one `LIST` call.
    /// When multiple folders claim the same special-use (pathological),
    /// the first one wins — matches the classifier's "first match"
    /// semantics.
    #[must_use]
    pub fn from_folders(folders: &[Folder]) -> Self {
        let mut out = Self::default();
        for folder in folders {
            let Some(su) = folder.special_use else {
                continue;
            };
            let slot = match su {
                SpecialUse::Drafts => &mut out.drafts,
                SpecialUse::Sent => &mut out.sent,
                SpecialUse::Trash => &mut out.trash,
                SpecialUse::Junk => &mut out.junk,
                SpecialUse::Archive => &mut out.archive,
                SpecialUse::All => &mut out.all,
                SpecialUse::Flagged => &mut out.flagged,
            };
            if slot.is_none() {
                *slot = Some(folder.name.clone());
            }
        }
        out
    }

    /// Discovered `\Drafts` folder name, or `None` if the server did not
    /// report one.
    #[must_use]
    pub fn drafts(&self) -> Option<&str> {
        self.drafts.as_deref()
    }

    /// Discovered `\Sent` folder name, or `None`.
    #[must_use]
    pub fn sent(&self) -> Option<&str> {
        self.sent.as_deref()
    }

    /// Discovered `\Trash` folder name, or `None`.
    #[must_use]
    pub fn trash(&self) -> Option<&str> {
        self.trash.as_deref()
    }

    /// All discovered folder names, in no particular order. Used to
    /// expand the `protected_folders` list at boot.
    #[must_use]
    pub fn all_discovered(&self) -> Vec<String> {
        [
            &self.drafts,
            &self.sent,
            &self.trash,
            &self.junk,
            &self.archive,
            &self.all,
            &self.flagged,
        ]
        .into_iter()
        .filter_map(|slot| slot.clone())
        .collect()
    }
}

#[cfg(test)]
mod map_tests {
    use super::*;
    use crate::types::Folder;

    fn folder(name: &str, special: Option<SpecialUse>) -> Folder {
        Folder {
            name: name.to_string(),
            attributes: Vec::new(),
            delimiter: Some('/'),
            selectable: true,
            special_use: special,
        }
    }

    #[test]
    fn from_folders_gmail_layout_maps_drafts_to_gmail_subtree() {
        let folders = vec![
            folder("INBOX", None),
            folder("Drafts", None),
            folder("[Gmail]/Drafts", Some(SpecialUse::Drafts)),
            folder("[Gmail]/Sent Mail", Some(SpecialUse::Sent)),
            folder("[Gmail]/Trash", Some(SpecialUse::Trash)),
            folder("[Gmail]/Spam", Some(SpecialUse::Junk)),
            folder("[Gmail]/All Mail", Some(SpecialUse::All)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), Some("[Gmail]/Drafts"));
        assert_eq!(map.sent(), Some("[Gmail]/Sent Mail"));
        assert_eq!(map.trash(), Some("[Gmail]/Trash"));
    }

    #[test]
    fn from_folders_first_claimant_wins_on_conflict() {
        let folders = vec![
            folder("Drafts", Some(SpecialUse::Drafts)),
            folder("Other Drafts", Some(SpecialUse::Drafts)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), Some("Drafts"));
    }

    #[test]
    fn from_folders_no_special_use_yields_empty_map() {
        let folders = vec![folder("INBOX", None), folder("Drafts", None)];
        let map = SpecialUseMap::from_folders(&folders);
        assert_eq!(map.drafts(), None);
        assert!(map.all_discovered().is_empty());
    }

    #[test]
    fn all_discovered_collects_every_slot() {
        let folders = vec![
            folder("D", Some(SpecialUse::Drafts)),
            folder("S", Some(SpecialUse::Sent)),
            folder("T", Some(SpecialUse::Trash)),
        ];
        let map = SpecialUseMap::from_folders(&folders);
        let mut discovered = map.all_discovered();
        discovered.sort();
        assert_eq!(discovered, vec!["D", "S", "T"]);
    }
}
```

Update the `lib.rs` re-export:

```rust
pub use special_use::{SpecialUse, SpecialUseMap, classify_special_use};
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p rimap-imap --lib special_use`
Expected: 10 passed (6 from Task 1 + 4 new).

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/special_use.rs crates/rimap-imap/src/lib.rs
git commit -m "feat(rimap-imap): SpecialUseMap resolver with per-use lookup"
```

---

## Task 4: Boot-time discovery helper

**Files:**
- Create: `crates/rimap-server/src/boot/discovery.rs`
- Modify: `crates/rimap-server/src/boot/mod.rs`

- [ ] **Step 1: Write the failing tests first (in-file)**

Write `crates/rimap-server/src/boot/discovery.rs`:

```rust
//! One-shot special-use discovery at account boot.
//!
//! Runs `LIST "" "*"` once against a freshly-opened `Connection` and
//! builds a `SpecialUseMap`. Called from `boot::build_account` before
//! `FolderGuard` is constructed so the guard's protected list can
//! include discovered server-native folder names (e.g.
//! `[Gmail]/Sent Mail`) in addition to the config-supplied literals.

use rimap_core::RimapError;
use rimap_imap::{Connection, SpecialUseMap};

/// Run one `LIST "*"` and classify the response into a `SpecialUseMap`.
/// Discovery failures propagate — if we can't enumerate folders at boot,
/// the account is unusable regardless of what the tools do later.
///
/// # Errors
///
/// Returns `RimapError::Imap { ... }` if the underlying LIST fails.
pub async fn resolve_special_use(connection: &Connection) -> Result<SpecialUseMap, RimapError> {
    let folders = connection.list_folders("*").await?;
    Ok(SpecialUseMap::from_folders(&folders))
}

#[cfg(test)]
mod tests {
    //! Unit tests for `resolve_special_use` require a live `Connection`,
    //! which exists only in the Dovecot integration harness. The
    //! name-resolution logic itself is covered by `SpecialUseMap::from_folders`
    //! tests in `rimap-imap::special_use`. Integration coverage lives in
    //! `crates/rimap-imap/tests/integration/dovecot.rs::case_20_special_use_discovery`.
}
```

Update `crates/rimap-server/src/boot/mod.rs` to add the module:

```rust
pub mod discovery;
```

(Place this line alphabetically with the existing `pub mod` declarations — do not export from the crate root unless required by call sites.)

- [ ] **Step 2: Compile check**

Run: `cargo check -p rimap-server`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/boot/discovery.rs crates/rimap-server/src/boot/mod.rs
git commit -m "feat(rimap-server): boot-time special-use discovery helper"
```

---

## Task 5: Thread `SpecialUseMap` through `AccountState`

**Files:**
- Modify: `crates/rimap-server/src/boot/registry.rs:36-62`
- Modify: `crates/rimap-server/src/boot/mod.rs` (the per-account construction path)

- [ ] **Step 1: Add the field to `AccountState`**

Edit `crates/rimap-server/src/boot/registry.rs`. Update the `AccountState` struct and its `Debug` impl:

```rust
use rimap_imap::{Connection, SpecialUseMap};

pub struct AccountState {
    pub id: AccountId,
    pub imap: Connection,
    pub smtp: Option<SmtpClient>,
    pub guard: DispatchGuard<SystemClock>,
    pub folder_guard: FolderGuard,
    pub download_dir: Arc<Path>,
    /// RFC 6154 special-use folder name resolutions, populated at boot
    /// from one `LIST` call. Consulted by `create_draft`, `send_email`,
    /// and expanded into `folder_guard`'s protected list.
    pub special_use: SpecialUseMap,
}

impl std::fmt::Debug for AccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountState")
            .field("id", &self.id)
            .field("smtp", &self.smtp.is_some())
            .field("special_use_drafts", &self.special_use.drafts())
            .field("special_use_sent", &self.special_use.sent())
            .finish_non_exhaustive()
    }
}
```

- [ ] **Step 2: Call discovery in the boot path and expand protected list**

Locate `build_account` (or the equivalent per-account constructor in `crates/rimap-server/src/boot/`). The exact function name depends on the current shape of that module — grep first:

Run: `rg -n 'fn build_account|fn construct.*account|AccountState \{' crates/rimap-server/src/boot/`

Once the builder is located, insert after the `Connection` is established and **before** `FolderGuard::new` is called:

```rust
let special_use = crate::boot::discovery::resolve_special_use(&connection).await?;

let mut protected = account_config.security.protected_folders.clone();
for discovered in special_use.all_discovered() {
    if !protected.iter().any(|p| p.eq_ignore_ascii_case(&discovered)) {
        protected.push(discovered);
    }
}
let folder_guard = FolderGuard::new(&protected, &account_config.security.expunge_folders);
```

Add `special_use` to the `AccountState` struct literal.

- [ ] **Step 3: Run the rimap-server lib tests**

Run: `cargo test -p rimap-server --lib`
Expected: all pass.

- [ ] **Step 4: Run the e2e test in isolation**

Run: `cargo test -p rimap-server --test e2e`
Expected: passes (Dovecot harness boots fine even without special-use mailboxes configured — discovery just returns an empty map).

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/src/boot/registry.rs crates/rimap-server/src/boot/mod.rs
git commit -m "feat(rimap-server): thread SpecialUseMap through AccountState and expand protected folders"
```

---

## Task 6: `create_draft` uses discovered `\Drafts`

**Files:**
- Modify: `crates/rimap-server/src/tools/compose/create_draft.rs:39-65`

- [ ] **Step 1: Replace the hardcoded folder**

Edit `crates/rimap-server/src/tools/compose/create_draft.rs`. Replace the `drafts_folder` assignment:

```rust
let drafts_folder: &str = account.special_use.drafts().unwrap_or("Drafts");
```

The rest of the handler is unchanged.

- [ ] **Step 2: Extend the e2e test to cover Gmail-style drafts**

Edit `crates/rimap-server/tests/e2e.rs`. In `e2e_full_session`, after `harness.create_mailbox("Drafts")` and `harness.create_mailbox("Trash")`, assert that `create_draft`'s reported folder matches the discovered special-use.

Add a new assertion helper near the existing `assert_create_draft`:

```rust
async fn assert_create_draft_uses_special_use_when_available(server: &ImapMcpServer) {
    let account = server.registry.resolve(None).expect("resolve account");
    let expected = account
        .special_use
        .drafts()
        .map(str::to_string)
        .unwrap_or_else(|| "Drafts".to_string());

    let result = call_tool(
        server,
        "create_draft",
        serde_json::json!({
            "to": [{"address": "dest@example.com"}],
            "subject": "s",
            "body_text": "b",
        }),
    )
    .await
    .expect("create_draft failed");
    assert_eq!(result["meta"]["folder"].as_str().unwrap(), expected);
}
```

Call this helper from `e2e_full_session` **after** the original `assert_create_draft` (keep the existing assertion — it still exercises the fallback path in the current Dovecot harness config that has no `\Drafts` special-use mailbox).

- [ ] **Step 3: Run the e2e test**

Run: `cargo test -p rimap-server --test e2e`
Expected: passes.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/tools/compose/create_draft.rs crates/rimap-server/tests/e2e.rs
git commit -m "feat(compose): create_draft targets the discovered \\Drafts folder"
```

---

## Task 7: `send_email` Sent-copy uses discovered `\Sent`

**Files:**
- Modify: `crates/rimap-server/src/tools/compose/send_email.rs:73-84`

- [ ] **Step 1: Replace the hardcoded Sent folder**

In `crates/rimap-server/src/tools/compose/send_email.rs`, replace:

```rust
let sent_folder = "Sent";
```

with:

```rust
let sent_folder: &str = account.special_use.sent().unwrap_or("Sent");
```

- [ ] **Step 2: Run lib tests**

Run: `cargo test -p rimap-server --lib tools::compose::send_email`
Expected: all `build_envelope_*` tests pass (they don't touch the Sent folder).

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-server/src/tools/compose/send_email.rs
git commit -m "feat(compose): send_email Sent-copy targets the discovered \\Sent folder"
```

---

## Task 8: Dovecot fixture adds special-use mailboxes

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot/dovecot.conf`

- [ ] **Step 1: Declare auto-create special-use mailboxes**

Replace the `namespace inbox` block in `crates/rimap-imap/tests/integration/dovecot/dovecot.conf` with:

```
namespace inbox {
  inbox = yes
  separator = /

  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
}
```

- [ ] **Step 2: Prune any stale container from earlier runs**

Run: `just test-integration` will autodetect the runtime and tear down the old container. If running manually:

```bash
docker compose -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml down --volumes 2>/dev/null \
  || podman-compose -f crates/rimap-imap/tests/integration/dovecot/docker-compose.yml down --volumes
```

- [ ] **Step 3: Re-run the Dovecot suite**

Run: `cargo test -p rimap-imap --test dovecot`
Expected: all existing cases still pass (the new mailboxes don't break existing fixtures).

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot/dovecot.conf
git commit -m "test(dovecot): autocreate RFC 6154 special-use mailboxes"
```

---

## Task 9: Integration test for discovery against Dovecot

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs`

- [ ] **Step 1: Add the failing test**

Add to `crates/rimap-imap/tests/integration/dovecot.rs`:

```rust
#[tokio::test]
async fn case_20_special_use_discovery_populates_each_slot() {
    use rimap_imap::{SpecialUse, SpecialUseMap};

    let Some(h) = boot(PinChoice::Correct) else {
        return;
    };
    let folders = h.connection.list_folders("*").await.unwrap();
    let map = SpecialUseMap::from_folders(&folders);

    assert_eq!(map.drafts(), Some("Drafts"));
    assert_eq!(map.sent(), Some("Sent"));
    assert_eq!(map.trash(), Some("Trash"));

    // Confirm classification on the folder level too — each slot should
    // link to exactly one folder with the matching special-use marker.
    let drafts_folder = folders.iter().find(|f| f.name == "Drafts").unwrap();
    assert_eq!(drafts_folder.special_use, Some(SpecialUse::Drafts));
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p rimap-imap --test dovecot case_20_special_use_discovery`
Expected: passes.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "test(dovecot): assert SpecialUseMap resolves Drafts/Sent/Trash/Junk"
```

---

## Task 10: Documentation

**Files:**
- Modify: `docs/configuration.md` (under `[security]` section, around line 131)

- [ ] **Step 1: Add the documentation section**

Insert into `docs/configuration.md` immediately after the `protected_folders` table row:

````markdown
### Special-use folder discovery

At account boot, the server runs `LIST "" "*"` once and records any
RFC 6154 special-use markers (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
`\Archive`, `\All`, `\Flagged`) reported by the server. These names
are then:

1. Used as the target folder for `create_draft` (`\Drafts`) and
   `send_email`'s Sent copy (`\Sent`), falling back to the literal
   strings `"Drafts"` and `"Sent"` if the server does not advertise
   special-use attributes.
2. Merged (case-insensitively) into the `protected_folders` list, so
   Gmail's `[Gmail]/Sent Mail` is protected by the default config even
   though the literal list contains `"Sent"`. This only adds names;
   user-configured entries are preserved.

No config is required to opt in. To disable the expansion into
`protected_folders`, set `protected_folders = ["INBOX"]` (or any
explicit list) — the expansion is additive, not subtractive, so an
empty-but-present user list still gets expanded.
````

- [ ] **Step 2: Commit**

```bash
git add docs/configuration.md
git commit -m "docs: explain special-use folder discovery behavior"
```

---

## Task 11: Full local CI pass

- [ ] **Step 1: Run the whole local-CI pipeline**

Run: `just ci`
Expected: `fmt-check`, `lint`, `test`, `deny` all green.

- [ ] **Step 2: Manually verify against the live Gmail account**

Rebuild the binary into `~/.local/bin` and run a JSON-RPC probe against the running MCP server:

```bash
cargo build --release --bin rusty-imap-mcp \
  && install -m 0755 target/release/rusty-imap-mcp ~/.local/bin/rusty-imap-mcp
```

Probe script: drive `create_draft` the same way the previous probe did and confirm `meta.folder == "[Gmail]/Drafts"`.

Expected: draft appears in Gmail's native Drafts tab, not in the user-created `Drafts` label.

- [ ] **Step 3: Push and open PR**

```bash
git push -u origin feat/special-use-folder-discovery
gh pr create --title "feat: RFC 6154 special-use folder discovery for compose targets" --body "<summary + test plan>"
```

Mark PR as depending on #88 (the `\Noselect` fix) in the description.

---

## Self-Review Checklist

**Spec coverage:**
- [x] `\Drafts` discovery for `create_draft` — Task 6
- [x] `\Sent` discovery for `send_email` — Task 7
- [x] `protected_folders` expansion — Task 5
- [x] Integration coverage — Tasks 8, 9
- [x] Docs — Task 10

**Placeholder scan:** No "TBD", "similar to", or "handle edge cases" without concrete code. The one generic step (Task 5 Step 2) names an exact `rg` command to locate the boot path — necessary because the shape of `boot::mod` is not pinned in this plan and may have moved.

**Type consistency:**
- `SpecialUseMap::drafts() -> Option<&str>` (Task 3) matches `account.special_use.drafts().unwrap_or("Drafts")` usage (Task 6) ✓
- `SpecialUseMap::all_discovered() -> Vec<String>` (Task 3) matches iteration in Task 5 ✓
- `SpecialUse` enum variants stay consistent across Tasks 1, 3, 9 ✓
