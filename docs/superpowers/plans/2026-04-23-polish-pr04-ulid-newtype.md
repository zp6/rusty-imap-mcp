# Polish PR 4 — Shared `ulid_newtype!` macro for `SessionId` + `ProcessId` (#146)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-written ULID newtypes in `rimap_core::SessionId` and `rimap_audit::record::ids::ProcessId` with invocations of a single declarative macro, `rimap_core::ulid_newtype!`, so the third ULID newtype does not accrete a third duplicated impl. Public API, on-disk serialization, and every existing call site stay byte-identical.

**Architecture:** Declarative macro only — no generic type, no trait. The two newtypes' public APIs genuinely diverge (SessionId exposes `::new()`, ProcessId exposes `::new_now()`), so the macro takes the constructor name as a parameter rather than forcing a single spelling. A generic `UlidNewtype<Tag>` would require renaming call sites throughout the workspace and offers no additional safety here.

**Tech Stack:** Rust declarative macros (`macro_rules!`), `ulid = "1.2"`, `serde(transparent)`.

---

## Context the engineer must read first

Reading carefully now prevents the API-assumption bugs `RESUME.md` lesson 1 warns about. The two existing impls are NOT identical — the macro must preserve both surfaces.

- `crates/rimap-core/src/session.rs` — `SessionId` has `new()`, `as_ulid()`, `Default`, `Display`, `FromStr`, `#[serde(transparent)]`, private inner `ulid::Ulid`, derives `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`.
- `crates/rimap-audit/src/record/ids.rs` — `ProcessId` has `new_now()`, `Display`, `#[serde(transparent)]`, **public** inner (`pub Ulid`), derives `Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize`. No `Default`, no `FromStr`, no `as_ulid()`.

**Post-PR invariants:**
- `SessionId::new()` remains callable (many sites: `daemon/state.rs`, `daemon/run.rs`, `tools/admin/accounts.rs`, and tests).
- `ProcessId::new_now()` remains callable (many sites: `boot/audit_init.rs`, `writer/mod.rs`, every `rimap-audit` test, `tests/audit_merge.rs`).
- JSON serialization of both types stays byte-identical (both are `#[serde(transparent)]` wrappers around `ulid::Ulid`, so this falls out automatically — but a round-trip test guards against regression).
- `ProcessId`'s inner field becoming private is fine: `rg 'process_id\.0|ProcessId\(' crates/` returns zero hits outside the definition itself. The public-tuple-inner was never used by any caller.

## Dependency note

No new crates. Both `rimap-core` and `rimap-audit` already have `ulid` and `serde` in their dep graphs.

## Why a macro, not a generic `UlidNewtype<Tag>`

Two reasons:
1. A generic would collapse the constructor name — you'd have to pick either `new()` or `new_now()` for both, forcing an audit-wide rename either way.
2. `#[serde(transparent)]` is an attribute on the struct definition; it does not propagate through a `#[derive]` or a trait impl. A macro is the natural way to generate it; a generic can't.

The spec (PR 4 section) already leaves the door open for a macro — "a declarative macro (`ulid_newtype!`) or a generic `UlidNewtype<T>` type covers both". Picking the macro.

---

## Files

- Modify: `crates/rimap-core/src/lib.rs` — add `pub mod ulid_newtype;` module declaration (or alternatively inline the macro in `lib.rs`); re-export the macro at crate root.
- Create: `crates/rimap-core/src/ulid_newtype.rs` — the macro definition + unit test.
- Modify: `crates/rimap-core/src/session.rs` — replace the hand-written body with a single macro invocation; keep the same public surface.
- Modify: `crates/rimap-audit/src/record/ids.rs` — replace the hand-written `ProcessId` body with a macro invocation; preserve `new_now()`.

## Task 1: Add the `ulid_newtype!` macro in `rimap-core` with a round-trip test

**Files:**
- Create: `crates/rimap-core/src/ulid_newtype.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Write the failing macro-generated-type test**

Create `crates/rimap-core/src/ulid_newtype.rs` with ONLY the test module for now (macro definition comes in step 3 so we see it fail to compile first):

```rust
//! Declarative macro that generates ULID newtypes sharing the same
//! serde/Display/FromStr/Default boilerplate. Each newtype picks its
//! own constructor name so the macro can replace both
//! [`crate::SessionId`] (with `new`) and `rimap_audit::ProcessId`
//! (with `new_now`) without breaking the hundreds of existing call
//! sites.

/// Define a ULID-backed newtype with serde_transparent, Display,
/// FromStr (via `ulid::DecodeError`), Default, and a caller-chosen
/// constructor.
///
/// # Usage
///
/// ```ignore
/// rimap_core::ulid_newtype! {
///     /// Per-connection identifier generated on accept.
///     pub struct SessionId;
///     ctor: new;
/// }
/// ```
///
/// The constructor `$ctor` is a `pub fn $ctor() -> Self` that seeds a
/// fresh [`ulid::Ulid`] from the system clock + RNG. `Default::default`
/// forwards to it.
#[macro_export]
macro_rules! ulid_newtype {
    ($(#[$outer:meta])* $vis:vis struct $name:ident; ctor: $ctor:ident $(;)?) => {
        $(#[$outer])*
        #[derive(
            ::core::fmt::Debug,
            ::core::clone::Clone,
            ::core::marker::Copy,
            ::core::cmp::PartialEq,
            ::core::cmp::Eq,
            ::core::hash::Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        #[serde(transparent)]
        $vis struct $name(::ulid::Ulid);

        impl $name {
            /// Generate a fresh value from the system clock + randomness.
            #[must_use]
            pub fn $ctor() -> Self {
                Self(::ulid::Ulid::new())
            }

            /// Underlying ULID (escape hatch for interop).
            #[must_use]
            pub fn as_ulid(self) -> ::ulid::Ulid {
                self.0
            }
        }

        impl ::core::default::Default for $name {
            fn default() -> Self {
                Self::$ctor()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = ::ulid::DecodeError;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                ::core::str::FromStr::from_str(s).map(Self)
            }
        }
    };
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    // Macro invocation lives inside the test module so the macro's generated
    // type is confined to tests — no production code touches this newtype.
    $crate::ulid_newtype! {
        /// Test-only newtype exercising every trait the macro generates.
        pub(super) struct MacroProbe;
        ctor: new_now;
    }

    use core::str::FromStr;

    #[test]
    fn display_round_trips_via_from_str() {
        let id = MacroProbe::new_now();
        let s = id.to_string();
        assert_eq!(s.len(), 26, "ULID canonical form is 26 chars: {s}");
        let back = MacroProbe::from_str(&s).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn default_is_fresh_value() {
        let a = MacroProbe::default();
        let b = MacroProbe::default();
        assert_ne!(a, b, "default() must mint a fresh ULID each call");
    }

    #[test]
    fn serde_transparent_serializes_as_bare_string() {
        let id = MacroProbe::new_now();
        let json = serde_json::to_string(&id).unwrap();
        // The outer braces of a struct would be `{"0":"..."}` — transparent
        // drops them, leaving a bare JSON string. Any drift from bare-string
        // form is an on-disk schema break.
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner.len(), 26, "serialized form must be a raw ULID: {json}");
    }

    #[test]
    fn serde_round_trip_preserves_value() {
        let id = MacroProbe::new_now();
        let json = serde_json::to_string(&id).unwrap();
        let back: MacroProbe = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn as_ulid_returns_inner_value() {
        let id = MacroProbe::new_now();
        let inner = id.as_ulid();
        assert_eq!(inner.to_string(), id.to_string());
    }
}
```

Note the line `$crate::ulid_newtype! { ... }` inside the test module — this must compile cleanly, so the macro must use `$crate::` paths OR fully-qualified `::ulid::Ulid` paths. The definition above uses fully-qualified paths.

- [ ] **Step 2: Expose the macro at the crate root**

Edit `crates/rimap-core/src/lib.rs` and add the new module declaration. After the existing line:

```rust
pub mod session;
```

add:

```rust
pub mod ulid_newtype;
```

The `#[macro_export]` attribute on the macro definition already re-exports it at the crate root, so callers can write `rimap_core::ulid_newtype! { ... }`. The new `pub mod` line is there so the module's doc and unit tests are visible.

- [ ] **Step 3: Run the tests to confirm they pass**

Run: `cargo test -p rimap-core --lib ulid_newtype`
Expected: all five tests pass.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: clean. If clippy flags a missing-docs on the generated type, confirm the macro's `$(#[$outer:meta])*` capture is correct and the invocation passes a doc comment.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/lib.rs crates/rimap-core/src/ulid_newtype.rs
git commit -m "$(cat <<'EOF'
feat(rimap-core): add ulid_newtype! macro for shared ULID newtypes (#146)

Declarative macro that generates a serde_transparent ULID newtype with
Display, FromStr (via ulid::DecodeError), Default, and a caller-chosen
constructor name. SessionId and ProcessId will migrate to this macro in
follow-up commits; the macro's own unit tests pin the serde byte-
format so the migration is a pure structural refactor.

Refs #146.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Migrate `SessionId` to the macro

**Files:**
- Modify: `crates/rimap-core/src/session.rs`

- [ ] **Step 1: Capture the current serde byte format — regression guard**

Before replacing the implementation, add a byte-stable regression test. Append this to the existing `#[cfg(test)] mod tests` block in `crates/rimap-core/src/session.rs`:

```rust
    #[test]
    fn serde_json_is_a_bare_string_not_a_struct() {
        // On-disk schema pin: SessionId serializes as a bare JSON string,
        // NOT as `{"0":"..."}`. Any future refactor that drops serde
        // transparent would break every recorded audit log. This test is
        // deliberately conservative.
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner.len(), 26, "serialized form must be a raw ULID: {json}");
    }
```

Run: `cargo test -p rimap-core --lib session::tests::serde_json_is_a_bare_string_not_a_struct`
Expected: pass (current impl already has this property; the test locks it in).

- [ ] **Step 2: Replace the hand-written impl with the macro invocation**

Replace the entire contents of `crates/rimap-core/src/session.rs` — above the `#[cfg(test)]` block — with:

```rust
//! Per-connection identifier for daemon sessions.
//!
//! `SessionId` is a ULID (Crockford-base32, 26 chars) so that records
//! sorted by `session_id` land in roughly creation order — a forensic
//! aid when reading the audit log.

crate::ulid_newtype! {
    /// Per-client-connection identifier. Generated on accept.
    pub struct SessionId;
    ctor: new;
}
```

**Leave the entire `#[cfg(test)] mod tests` block in place**, including the new regression guard from step 1. All four pre-existing tests (`new_returns_distinct_values_in_the_same_tick`, `display_round_trips_via_from_str`, `serde_json_round_trip_preserves_value`, `timestamps_order_monotonically_across_newtype`) still apply to the macro-generated type — do not delete them.

- [ ] **Step 3: Run the full `session` test module**

Run: `cargo test -p rimap-core --lib session`
Expected: all five tests (four pre-existing + the new byte-stable guard) pass.

- [ ] **Step 4: Check downstream callers still build**

`SessionId::new()`, `SessionId::from_str()`, `SessionId::default()`, `Display for SessionId`, and `SessionId::as_ulid()` all remain in the public API (the macro generates them). Check that the downstream crates still compile:

Run: `cargo check --workspace --all-targets`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/session.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-core): migrate SessionId to ulid_newtype! macro (#146)

Replaces hand-written Display/FromStr/Default/serde impls with a single
macro invocation. Public API unchanged: SessionId::new(),
SessionId::from_str(), SessionId::default(), Display, and as_ulid() all
still resolve. A new byte-stable serde test pins the on-disk format
against future drift.

Refs #146.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Migrate `ProcessId` to the macro

**Files:**
- Modify: `crates/rimap-audit/src/record/ids.rs`

- [ ] **Step 1: Write the byte-stable regression guard**

Append this test to the existing `#[cfg(test)] mod tests` block in `crates/rimap-audit/src/record/ids.rs` (the module starts around line 123):

```rust
    #[test]
    fn process_id_serde_json_is_a_bare_string_not_a_struct() {
        // On-disk schema pin for ProcessId: serializes as a bare JSON
        // string, NOT as `{"0":"..."}`. Every audit record on disk
        // carries one of these; any drift breaks the reader.
        let id = ProcessId::new_now();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'), "{json}");
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner.len(), 26, "serialized form must be a raw ULID: {json}");
    }

    #[test]
    fn process_id_round_trips_through_serde_json() {
        let id = ProcessId::new_now();
        let json = serde_json::to_string(&id).unwrap();
        let back: ProcessId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }
```

This module already imports `ProcessId` via `use crate::record::ids::{ProcessId, Seq, Timestamp};`, so no new imports are needed. `serde_json` is only a dev-dep on rimap-core, NOT rimap-audit — verify it is available here:

Run: `rg -n '^serde_json' crates/rimap-audit/Cargo.toml`
Expected: a hit under `[dependencies]` (`serde_json = { workspace = true }`). If it is only under `[dev-dependencies]`, adjust the test's `use` accordingly — no change needed, tests can use dev-deps.

Actually verify current state by reading the file — the current `serde_json` entry is under `[dependencies]` at line 21 of `crates/rimap-audit/Cargo.toml`, so tests have free access.

Run the new tests:
```bash
cargo test -p rimap-audit --lib record::ids::tests::process_id_serde_json_is_a_bare_string_not_a_struct record::ids::tests::process_id_round_trips_through_serde_json
```
Expected: both pass (current impl already serializes as bare string; tests lock it in).

- [ ] **Step 2: Replace the hand-written `ProcessId` body with a macro invocation**

In `crates/rimap-audit/src/record/ids.rs`, replace lines 40–58 (the block starting at the doc comment `/// Stable identifier for a single process lifetime.` and ending at the closing `}` of `impl fmt::Display for ProcessId`):

```rust
/// Stable identifier for a single process lifetime. Backed by a ULID so logs
/// from different processes interleave in a meaningful order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessId(pub Ulid);

impl ProcessId {
    /// Generate a fresh process ID from the current system time + randomness.
    #[must_use]
    pub fn new_now() -> Self {
        Self(Ulid::new())
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
```

with:

```rust
rimap_core::ulid_newtype! {
    /// Stable identifier for a single process lifetime. Backed by a ULID so
    /// logs from different processes interleave in a meaningful order.
    pub struct ProcessId;
    ctor: new_now;
}
```

Then remove the now-dead imports at the top of the file. The old block used `serde::{Deserialize, Serialize}`, `ulid::Ulid`, and `core::fmt` — check whether they are still needed by the remaining items (`Seq`, `Timestamp`). Keep the imports that the remaining code still uses; remove only what is now dead.

Inspect: `Seq` uses `serde::{Deserialize, Serialize}` and `core::fmt`; `Timestamp` uses `serde::{...}`, `time::OffsetDateTime`, `time::format_description::well_known::Rfc3339`, and `ulid::Ulid` is no longer referenced outside the macro invocation. Therefore: delete `use ulid::Ulid;` at line 10 — keep the others.

- [ ] **Step 3: Run the file's tests**

Run: `cargo test -p rimap-audit --lib record::ids`
Expected: all tests pass, including the two byte-stable guards from step 1 and the pre-existing `process_id_is_unique_per_call`, `process_id_display_is_ulid_encoded`, etc.

- [ ] **Step 4: Sanity-check every downstream call site — `ProcessId::new_now()` still resolves**

Run: `cargo check --workspace --all-targets`
Expected: clean. If any caller uses `ProcessId(Ulid::new())` (the tuple-struct constructor, which relied on the `pub` inner field), the build breaks here and needs rewriting to `ProcessId::new_now()`. Earlier grep showed no such caller; this step guards against one having been added since.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/record/ids.rs
git commit -m "$(cat <<'EOF'
refactor(rimap-audit): migrate ProcessId to rimap-core's ulid_newtype! (#146)

Replaces hand-written Display/Serialize/Deserialize impls with a single
macro invocation from rimap-core. ProcessId::new_now() and Display are
unchanged; the inner ulid::Ulid is no longer pub (no caller accessed
.0 directly — grep-verified before the swap).

New byte-stable round-trip tests pin the serde format so every audit
record on disk continues to deserialize after the swap.

Closes #146.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 4: Full-workspace verification

**Files:** none — green-gate task.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean exit.

- [ ] **Step 3: Full test suite**

Run: `cargo test --workspace`
Expected: every test passes. Pay special attention to:

- `rimap-audit` `writer` module tests that write records containing `ProcessId`
- `rimap-audit` `reader` module tests that parse those records back
- `rimap-server` `tests/audit_merge.rs` — asserts process-boundary behaviour

If any test fails with a serde-format error (e.g. `invalid type: struct, expected string`), the `#[serde(transparent)]` attribute was dropped by the macro — go back to Task 1 and confirm the attribute is still present on the generated struct.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean.

- [ ] **Step 5: typos + fmt**

Run: `typos && cargo fmt --check`
Expected: clean.

## Self-review checklist

- Macro invocation is the single source of truth; hand-written impls are deleted, not hidden.
- Macro is exercised by its own unit tests (Task 1) AND by the two migrations (Tasks 2–3) in production code.
- Byte-stable serde guards added for BOTH newtypes — this is the core risk (on-disk schema regression) so it gets explicit tests on both sides.
- Commits land in three logical phases: macro + own tests, SessionId migration, ProcessId migration. Reviewers can bisect any step independently.
- `ProcessId`'s inner-field visibility change (`pub Ulid` → private) is grep-verified before the swap (Task 3 step 4) — no caller relied on it.
- `new_now()` and `new()` preserved exactly; no audit-wide rename required.

## Out of scope

- **The "third ULID newtype" the issue hints at** — do not invent one. Ship the shared macro so the next one can use it, but don't add a new ID type here.
- **Renaming `SessionId::new()` to `new_now()` or vice versa** — API compatibility wins over uniformity for now. Revisit only if a concrete caller forces the change.
- **`Seq` or `Timestamp` refactors in `ids.rs`** — those are not ULID newtypes; they stay untouched.

If you find yourself editing outside the Files list, stop and re-read the spec.
