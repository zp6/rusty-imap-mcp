# Sprint 2 — Audit Log Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the append-only JSONL audit log so every process start, auth attempt, and tool call is durably recorded under an OS-level exclusive lock, redaction schemas are declared for every v1 tool, the provenance ring buffer is in place, `--dry-run` acquires the lock (making a second concurrent `--dry-run` fail with `ERR_CONFIG`), and an `audit merge` subcommand can round-trip a synthetic log.

**Architecture:** `rimap-audit` grows from an empty placeholder into the owner of the on-disk log format. The full `AuditRecord` enum and its serde layout move into `rimap-audit::record`, replacing the Sprint-1 shell in `rimap-core::audit` (the shell is deleted outright — nothing outside `rimap-core` matches on the old variants). `AuditWriter` wraps `Arc<Mutex<BufWriter<File>>>` behind a non-blocking exclusive `flock` via `fs4` (maintained successor of `fs2`), writes one record per `write_all`, flushes the buffer after each record, and `fsync`s on `process_*` / `auth` only. Rotation happens under lock by renaming the active file (POSIX `flock` tracks the inode, not the path), locking the new file, then dropping the old fd. Readers take a shared lock. A startup self-check reads the previous last line to populate `previous_last_seq` / `previous_process_id` / `previous_file_inode`. Argument redaction is table-driven per `ToolName` — schemas are declared now, exercised by property tests against synthetic argument blobs, but the tool handlers that feed them stay empty until Sprint 5. The server binary grows an `audit merge` subcommand (shared-lock reader with `--since`/`--until`/`--tool`/`--kind`/`--process` filters, tolerant of a partial trailing line) and wires `AuditWriter::open` into the `--dry-run` path so the concurrent-lock exit criterion is exercised by the existing `--dry-run` mode.

**Tech Stack:** Rust 1.85.1 MSRV / 1.94.0 dev toolchain (unchanged). New runtime deps: `fs4` (drop-in for `fs2`, actively maintained), `serde_json`, `time` (RFC 3339 timestamps with the `serde-well-known` feature), `ulid`, `sha2`, `hex`, `rand`. New dev deps: none (`tempfile`, `proptest`, `assert_cmd`, `predicates` already workspace-level from Sprint 1).

**Spec reference:** `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md` Section 10 (Audit Log — record schema, redaction, provenance, file handling and locking, startup self-check, `audit merge`) and Section 12 "Sprint 2 — Audit log" bullet. Testing targets come from Section 11 "Sprint 1–2: foundations".

---

## Context for the implementing engineer

Sprint 1 is merged to `main`. `rusty-imap-mcp --config x.toml --dry-run` already parses a TOML config, validates it, builds the effective posture matrix, and prints it. `rimap-audit` is an empty placeholder (`lib.rs` has only the crate docstring). `rimap-core::audit` holds a shell enum (`AuditRecord::{Process(ProcessEvent), Auth(AuthOutcome), ToolStart, ToolEnd}`) with no fields. Sprint 2 **deletes** that shell outright and re-establishes the audit types in `rimap-audit::record` with full payloads per spec §10. A workspace-wide `grep` at the start of Sprint 2 confirmed only `rimap-core/src/lib.rs` and `rimap-core/src/audit.rs` reference those identifiers, so the removal is safe.

**Starting branch state:** You start on `main`. Task 1 creates `feat/sprint-2-implementation` off `main`. (Note: this is *not* `feat/sprint-2-plan`, which is the branch carrying this plan document itself. Plan and implementation live on separate branches, matching the Sprint 1 workflow.)

**What "TDD" means here.** For every non-trivial function: write the failing test, run it, see it fail with the exact error you expect, then write the minimal implementation, re-run, commit. Type stubs and `Default` impls don't need a separate failing-test step — but any parsing, serialization round-trip, locking behavior, rotation, recovery path, or redaction transform does. Concurrent locking, rotation-under-lock, partial-trailing-line recovery, and inode-change detection are integration-test territory; write those in `crates/rimap-audit/tests/`.

**Working directory:** `/Users/dave/src/rusty-imap-mcp` throughout.

**Deliberate spec deviation — `fs4` instead of `fs2`:** The spec names `fs2::FileExt::try_lock_exclusive`. We use `fs4` instead because `fs2` is unmaintained (last release 2018) and `fs4` is its drop-in successor with the same `FileExt` trait and method names, actively maintained, pure-Rust (via `rustix`) and cross-platform. API calls are identical — `file.try_lock_exclusive()`, `file.lock_shared()`, `file.unlock()`. `fs4::fs_std::FileExt` is the plain-`std::fs::File` trait; we do **not** use the `tokio`/`async` features. MSRV of `fs4` 0.13 is 1.75, well below our 1.85.1 floor. This is the first and only spec deviation in Sprint 2.

**Important constraints (from global CLAUDE.md and AGENTS.md):**
- Never commit on `main` / `master`. Enforced by the `branch-name` prek hook.
- Never `--no-verify`. If a hook fails, fix the underlying cause.
- 100-char line length.
- No relative `..` imports (Rust: absolute paths from crate root).
- No `unwrap()` / `expect()` / `panic!()` / `unimplemented!()` / `todo!()` in non-test code.
- No `println!` / `eprintln!` / `dbg!` in non-test code. `audit merge` subcommand writes to stdout via `writeln!(std::io::stdout().lock(), …)?` exactly like the Sprint-1 `--dry-run` path does.
- Tests may `#![expect(clippy::unwrap_used, reason = "tests")]` at the `mod tests` level only.
- The audit lock must **never** be held across an `.await`. `AuditWriter` is synchronous; the server calls it from sync paths or from `tokio::task::spawn_blocking` sections only. (Sprint 2 does not yet need `spawn_blocking` — `--dry-run` is synchronous and the `audit merge` reader is synchronous. The discipline lands now so Sprint 3+ inherits it.)
- Audit write failures must surface as `ERR_INTERNAL` per AGENTS.md "Security-sensitive work" guidance. The `audit.fail_open = true` escape hatch from spec §10 is honored but not exercised in Sprint 2.

**Scope guardrails (do NOT do any of this in Sprint 2):**
- No tool handlers. Redaction schemas are declared against `ToolName`, but the handlers that would call them live in Sprint 5.
- No IMAP code in `rimap-imap`. The `auth` record schema is declared; Sprint 3 wires it to actual IMAP connections.
- No content pipeline code in `rimap-content`.
- No `rmcp` wiring. The server still rejects non-`--dry-run` invocations with "not implemented until Sprint 5".
- No automatic provenance interpretation. The ring buffer records evidence; analysis is a v1.x follow-up per spec §10 "Provenance tracking".
- No `AuditRecord::Config` variant. Spec §10 lists `config` as a `kind`, but Sprint 1's `--dry-run` already prints config to stdout and does not write audit records; Sprint 2 does not emit `config` records either. The `kind` variant is declared in the enum with a payload so Sprint 5 can populate it, but no code path writes it yet. Property tests cover its serialization shape.

---

## File structure (end state of Sprint 2)

```
rusty-imap-mcp/
├── Cargo.toml                                         # workspace deps grow
├── deny.toml                                          # skips justified if new dupes appear
├── crates/
│   ├── rimap-core/
│   │   └── src/
│   │       ├── lib.rs                                 # audit module removed, re-exports dropped
│   │       └── audit.rs                               # DELETED
│   ├── rimap-audit/
│   │   ├── Cargo.toml                                 # + rimap-core, thiserror, serde, serde_json,
│   │   │                                              #   time, ulid, sha2, hex, rand, fs4, tracing
│   │   ├── src/
│   │   │   ├── lib.rs                                 # re-exports
│   │   │   ├── error.rs                               # AuditError + ErrorCode mapping
│   │   │   ├── ids.rs                                 # Seq, ProcessId, Timestamp newtypes
│   │   │   ├── record.rs                              # AuditRecord + payload structs + serde
│   │   │   ├── redact.rs                              # RedactionSchema + per-tool schemas + ArgsHasher
│   │   │   ├── provenance.rs                          # ProvenanceBuffer ring buffer
│   │   │   ├── self_check.rs                          # last-line read, inode + previous_* computation
│   │   │   ├── rotation.rs                            # rotate-under-lock
│   │   │   ├── writer.rs                              # AuditWriter (Arc<Mutex<BufWriter<File>>>)
│   │   │   └── reader.rs                              # shared-lock iterator + filter model for `merge`
│   │   └── tests/
│   │       ├── concurrent_lock.rs                     # second open fails with AuditError::Locked
│   │       ├── rotation.rs                            # cross rotate_bytes, verify no record loss
│   │       ├── partial_line.rs                        # reader tolerates truncated trailing line
│   │       └── inode_change.rs                        # delete file between runs → tamper signal
│   └── rimap-server/
│       ├── Cargo.toml                                 # + rimap-audit
│       └── src/
│           ├── cli.rs                                 # + `audit merge` subcommand
│           ├── dry_run.rs                             # open AuditWriter before printing matrix
│           ├── audit_cmd.rs                           # `audit merge` handler
│           └── main.rs                                # dispatch new subcommand
└── docs/superpowers/plans/2026-04-07-sprint-2-audit-log.md  # this file
```

---

## Task 1: Create feature branch

**Files:** none (git state only)

- [ ] **Step 1: Verify you're on `main` and clean**

Run: `git status && git branch --show-current`
Expected: clean working tree, branch `main`. If not, stop and resolve before continuing.

- [ ] **Step 2: Fetch and confirm in sync with origin**

Run: `git fetch origin && git status`
Expected: `Your branch is up to date with 'origin/main'.`

- [ ] **Step 3: Create feature branch**

Run: `git checkout -b feat/sprint-2-implementation`
Expected: `Switched to a new branch 'feat/sprint-2-implementation'`.

No commit for this task.

---

## Task 2: Add Sprint 2 workspace dependencies

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]` section)

These versions are current-stable as of plan authorship. If `cargo update` during compilation pulls a newer patch via semver, that is fine; do not downgrade. If a *major* version has bumped since authorship, stop and ask before adjusting.

- [ ] **Step 1: Add runtime dependencies to `[workspace.dependencies]`**

Modify `Cargo.toml`. After the existing `clap` entry and before the `# Dev dependencies` comment, insert a new `# Audit log` block:

```toml
# Audit log
fs4 = { version = "0.13", default-features = false, features = ["sync"] }
serde_json = "1.0"
time = { version = "0.3", features = ["formatting", "parsing", "macros", "serde", "serde-well-known"] }
ulid = { version = "1.1", features = ["serde"] }
sha2 = "0.10"
hex = "0.4"
rand = "0.8"
```

Also ensure `rimap-core` and `rimap-audit` can be referenced as workspace path deps — if not already declared, add to `[workspace.dependencies]`:

```toml
# Internal crates
rimap-core = { path = "crates/rimap-core" }
rimap-audit = { path = "crates/rimap-audit" }
```

(If those entries already exist from Sprint 1, leave them untouched.)

- [ ] **Step 2: Verify the workspace manifest parses**

Run: `cargo metadata --no-deps --format-version 1 > /dev/null`
Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "chore: add Sprint 2 workspace dependencies"
```

---

## Task 3: Delete the `rimap-core::audit` shell

The Sprint 1 shell is removed outright. Only `rimap-core/src/lib.rs` and `rimap-core/src/audit.rs` reference the old identifiers (verified via `rg 'AuditRecord|ProcessEvent|AuthOutcome' crates/`).

**Files:**
- Delete: `crates/rimap-core/src/audit.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Delete the audit module**

Run: `trash crates/rimap-core/src/audit.rs`
Expected: file moved to macOS Trash.

- [ ] **Step 2: Remove the module declaration and re-exports from `lib.rs`**

Edit `crates/rimap-core/src/lib.rs` to drop the `pub mod audit;` line and the `pub use crate::audit::{AuditRecord, AuthOutcome, ProcessEvent};` line. End state:

```rust
//! Shared core types for rusty-imap-mcp: errors, postures, tool names.

#![deny(missing_docs)]

pub mod error;
pub mod posture;
pub mod tool;

pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::tool::{ParseToolNameError, ToolName};
```

- [ ] **Step 3: Verify the workspace still builds**

Run: `cargo check --workspace --all-targets --all-features`
Expected: clean. If any crate fails to compile because it referenced the old audit types, stop — the Sprint 2 precondition ("nothing outside rimap-core matches on the variants yet") has been violated and the plan needs revision.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-core/src/lib.rs crates/rimap-core/src/audit.rs
git commit -m "refactor(core): remove audit shell in preparation for rimap-audit payloads"
```

---

## Task 4: `rimap-audit` — crate manifest

**Files:**
- Modify: `crates/rimap-audit/Cargo.toml`

- [ ] **Step 1: Replace the empty `[dependencies]` section**

Replace `crates/rimap-audit/Cargo.toml` with:

```toml
[package]
name = "rimap-audit"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp."

[lints]
workspace = true

[dependencies]
rimap-core = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
time = { workspace = true }
ulid = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
rand = { workspace = true }
fs4 = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
proptest = { workspace = true }
```

- [ ] **Step 2: Verify it resolves**

Run: `cargo check -p rimap-audit`
Expected: clean (crate still has only `lib.rs` with the crate docstring, but the new deps are pulled in).

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-audit/Cargo.toml Cargo.lock
git commit -m "chore(audit): add Sprint 2 crate dependencies"
```

---

## Task 5: `rimap-audit` — error type

`AuditError` is the crate-level error. It maps to `ErrorCode::Config` at open time (lock conflict, missing parent, not writable) and to `ErrorCode::Internal` at write/flush/fsync time (spec §10: "audit write failure fails the tool call with `ERR_INTERNAL`"). A `From<AuditError> for RimapError` impl makes the boundary explicit.

**Files:**
- Create: `crates/rimap-audit/src/error.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/error.rs`:

```rust
//! Audit crate error type. Open-time errors map to `ERR_CONFIG`; runtime
//! write/flush/fsync errors map to `ERR_INTERNAL`. See design spec §10.

use std::path::PathBuf;

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-audit`.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The audit file could not be opened for read+write.
    #[error("failed to open audit file `{path}`: {source}")]
    Open {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file's parent directory could not be created.
    #[error("failed to create parent directory for `{path}`: {source}")]
    ParentDir {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file is already locked by another process.
    #[error(
        "audit file `{path}` is already locked by another rusty-imap-mcp process; \
         only one instance may run against a given audit path"
    )]
    Locked {
        /// Path that could not be locked.
        path: PathBuf,
    },
    /// A record could not be serialized to JSON.
    #[error("failed to serialize audit record: {0}")]
    Serialize(#[source] serde_json::Error),
    /// A record could not be written to disk.
    #[error("failed to write audit record to `{path}`: {source}")]
    Write {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `fsync` failed after a flush.
    #[error("failed to fsync audit file `{path}`: {source}")]
    Fsync {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Rotation rename or fresh-file creation failed.
    #[error("failed to rotate audit file `{path}`: {reason}")]
    Rotate {
        /// The active file path that was being rotated.
        path: PathBuf,
        /// Specific reason.
        reason: String,
    },
    /// Reading the audit file for self-check or `audit merge` failed.
    #[error("failed to read audit file `{path}`: {source}")]
    Read {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl AuditError {
    /// The stable [`ErrorCode`] this error maps to at the top-level boundary.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Open { .. } | Self::ParentDir { .. } | Self::Locked { .. } => ErrorCode::Config,
            Self::Serialize(_)
            | Self::Write { .. }
            | Self::Fsync { .. }
            | Self::Rotate { .. }
            | Self::Read { .. } => ErrorCode::Internal,
        }
    }
}

impl From<AuditError> for RimapError {
    fn from(err: AuditError) -> Self {
        match err.code() {
            ErrorCode::Config => Self::Config(err.to_string()),
            _ => Self::Internal(err.to_string()),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::ErrorCode;

    use crate::error::AuditError;

    #[test]
    fn open_time_errors_map_to_config() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        assert_eq!(err.code(), ErrorCode::Config);

        let err = AuditError::Open {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(err.code(), ErrorCode::Config);
    }

    #[test]
    fn runtime_errors_map_to_internal() {
        let err = AuditError::Write {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn locked_message_names_the_path() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/a.jsonl"));
        assert!(msg.contains("another rusty-imap-mcp process"));
    }

    #[test]
    fn rimap_error_conversion_preserves_code() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let rimap: rimap_core::RimapError = err.into();
        assert_eq!(rimap.code(), ErrorCode::Config);
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

Replace `crates/rimap-audit/src/lib.rs` with:

```rust
//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::AuditError;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-audit`
Expected: four tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add AuditError with ErrorCode boundary mapping"
```

---
## Task 6: `rimap-audit` — `ids` module (`Seq`, `ProcessId`, `Timestamp`)

Three tiny newtypes so record fields cannot be accidentally swapped. `Seq` is a monotonically-increasing per-process counter starting at 1. `ProcessId` wraps a ULID. `Timestamp` wraps `time::OffsetDateTime` and serializes as RFC 3339 with millisecond precision in UTC.

**Files:**
- Create: `crates/rimap-audit/src/ids.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/ids.rs`:

```rust
//! Strongly-typed identifiers and timestamp newtype used throughout the
//! audit record schema. Keeping these distinct from raw integers and strings
//! prevents accidental argument-swap bugs when building records by hand.

use core::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

/// Per-process monotonic sequence number. Starts at 1 on `process_start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(pub u64);

impl Seq {
    /// First sequence number every process emits.
    pub const FIRST: Self = Self(1);

    /// Returns the next sequence number. Saturating on `u64::MAX`.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

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

/// Millisecond-precision UTC timestamp, serialized as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(pub OffsetDateTime);

impl Timestamp {
    /// Current wall-clock time in UTC.
    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Format as RFC 3339 with millisecond precision, always ending in `Z`.
    /// Returns `None` if the underlying timestamp cannot be formatted (which,
    /// in practice, cannot happen for a well-formed `OffsetDateTime`).
    #[must_use]
    pub fn to_rfc3339_millis(self) -> Option<String> {
        let truncated = self.0.replace_nanosecond(
            (self.0.nanosecond() / 1_000_000) * 1_000_000,
        ).ok()?;
        truncated.format(&Rfc3339).ok()
    }
}

impl Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = self
            .to_rfc3339_millis()
            .ok_or_else(|| serde::ser::Error::custom("timestamp could not be formatted"))?;
        ser.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <&str as Deserialize>::deserialize(de)?;
        let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(serde::de::Error::custom)?;
        Ok(Self(dt))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::ids::{ProcessId, Seq, Timestamp};

    #[test]
    fn seq_starts_at_one_and_increments() {
        let s = Seq::FIRST;
        assert_eq!(s.get(), 1);
        assert_eq!(s.next().get(), 2);
        assert_eq!(s.next().next().get(), 3);
    }

    #[test]
    fn seq_next_saturates() {
        let s = Seq(u64::MAX);
        assert_eq!(s.next().get(), u64::MAX);
    }

    #[test]
    fn seq_display_uses_integer() {
        assert_eq!(Seq(42).to_string(), "42");
    }

    #[test]
    fn process_id_is_unique_per_call() {
        let a = ProcessId::new_now();
        let b = ProcessId::new_now();
        assert_ne!(a, b);
    }

    #[test]
    fn process_id_display_is_ulid_encoded() {
        let id = ProcessId::new_now();
        let s = id.to_string();
        assert_eq!(s.len(), 26, "ULID canonical form is 26 chars: got {s}");
    }

    #[test]
    fn timestamp_serializes_as_rfc3339_millis() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        // e.g. "\"2026-04-07T14:22:01.234Z\""
        assert!(json.starts_with('"'));
        assert!(json.ends_with("Z\""));
        assert!(
            json.contains('.'),
            "expected milliseconds in serialized form, got {json}",
        );
    }

    #[test]
    fn timestamp_round_trips_through_serde() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        // Milliseconds only — the nanosecond tail is discarded on the way out.
        assert_eq!(back.0.unix_timestamp(), ts.0.unix_timestamp());
        assert_eq!(
            back.0.millisecond(),
            ts.0.millisecond(),
        );
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

Modify `crates/rimap-audit/src/lib.rs`:

```rust
//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod ids;

pub use crate::error::AuditError;
pub use crate::ids::{ProcessId, Seq, Timestamp};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-audit`
Expected: all tests pass (the four from Task 5 plus the seven new ones).

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add Seq, ProcessId, and Timestamp newtypes"
```

---

## Task 7: `rimap-audit` — record schema (part 1: header + process events)

This task lays down the `AuditRecord` enum with `#[serde(tag = "kind", rename_all = "snake_case")]` and the process-lifecycle payloads. Later tasks extend it with auth, tool_start, tool_end, and the `config` kind variant.

**Files:**
- Create: `crates/rimap-audit/src/record.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/record.rs`:

```rust
//! Audit record schema per design spec §10. Every record carries the shared
//! header (`seq`, `ts`, `process_id`, `kind`) plus a kind-specific payload.
//! Serialization uses `#[serde(tag = "kind")]` to produce a flat JSON object
//! per line (JSONL).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ids::{ProcessId, Seq, Timestamp};

/// Why a process exited. Best-effort: only the SIGINT/SIGTERM/EOF paths set
/// this; a hard crash will simply leave the last record as `tool_end` or
/// whatever else was most recently flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEndReason {
    /// SIGINT received (Ctrl-C).
    SignalInt,
    /// SIGTERM received.
    SignalTerm,
    /// Stdin EOF on the MCP transport.
    Eof,
    /// Fatal error path (e.g. config load failure after first record).
    Error,
}

/// Payload of the `process_start` kind. Fields chosen to chain history across
/// restarts (see spec §10 startup self-check).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStart {
    /// Semver of the running binary.
    pub version: String,
    /// Git commit SHA embedded at build (via `vergen` when wired in Sprint 5;
    /// populated as an empty string until then).
    pub git_commit: String,
    /// Effective base posture at startup.
    pub posture: String,
    /// Absolute path of the loaded config file.
    pub config_path: PathBuf,
    /// SHA-256 of the config file contents at load time, hex-encoded.
    pub config_hash_sha256: String,
    /// Sequence number of the last record in the file at startup, if any.
    pub previous_last_seq: Option<Seq>,
    /// Process ID of the previous run, if the file was non-empty.
    pub previous_process_id: Option<ProcessId>,
    /// The inode of the audit file as this process observed it on open.
    /// On Windows this field stores `0` (inode concept does not apply).
    pub previous_file_inode: u64,
    /// Whether the observed inode differs from the inode recorded in the most
    /// recent prior `process_start`. Tamper signal.
    pub audit_file_inode_changed: bool,
}

/// Payload of the `process_end` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEnd {
    /// Why the process exited.
    pub reason: ProcessEndReason,
    /// Number of tool calls dispatched in this process.
    pub total_tool_calls: u64,
}

/// Top-level audit record enum. One variant per `kind` discriminator.
/// Serialized as a flat JSON object per line with `seq`, `ts`, `process_id`,
/// `kind`, and the kind-specific fields merged in via `#[serde(flatten)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Per-process monotonic sequence number.
    pub seq: Seq,
    /// Millisecond-precision UTC timestamp.
    pub ts: Timestamp,
    /// Per-process ULID.
    pub process_id: ProcessId,
    /// The kind-specific payload. `#[serde(flatten)]` + the inner `tag = "kind"`
    /// produces a single flat object with a `kind` discriminator.
    #[serde(flatten)]
    pub payload: Payload,
}

/// Payload enum discriminated by the `kind` field. Additional variants are
/// added in subsequent tasks (`Auth`, `ToolStart`, `ToolEnd`, `Config`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Process startup event — always the first record of a given `process_id`.
    ProcessStart(ProcessStart),
    /// Process shutdown event — best-effort.
    ProcessEnd(ProcessEnd),
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use crate::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{
        AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart,
    };

    fn sample_start() -> AuditRecord {
        AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessStart(ProcessStart {
                version: "0.1.0".to_string(),
                git_commit: String::new(),
                posture: "draft-safe".to_string(),
                config_path: PathBuf::from("/tmp/config.toml"),
                config_hash_sha256: "abcd".repeat(16),
                previous_last_seq: None,
                previous_process_id: None,
                previous_file_inode: 12345,
                audit_file_inode_changed: false,
            }),
        }
    }

    #[test]
    fn process_start_serializes_with_flat_kind_discriminator() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_start");
        assert_eq!(v["seq"], 1);
        assert_eq!(v["posture"], "draft-safe");
        assert!(v["ts"].is_string());
        assert_eq!(v["previous_file_inode"], 12345);
        assert_eq!(v["audit_file_inode_changed"], false);
    }

    #[test]
    fn process_start_round_trips_through_serde() {
        let rec = sample_start();
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_end_round_trips() {
        let rec = AuditRecord {
            seq: Seq(9999),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::SignalInt,
                total_tool_calls: 42,
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert_eq!(v["reason"], "signal_int");
        assert_eq!(v["total_tool_calls"], 42);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn process_end_reason_serializes_snake_case() {
        let json = serde_json::to_string(&ProcessEndReason::SignalTerm).unwrap();
        assert_eq!(json, "\"signal_term\"");
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

Modify `crates/rimap-audit/src/lib.rs`:

```rust
//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod ids;
pub mod record;

pub use crate::error::AuditError;
pub use crate::ids::{ProcessId, Seq, Timestamp};
pub use crate::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason, ProcessStart};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-audit`
Expected: all tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add AuditRecord with process_start/process_end payloads"
```

---

## Task 8: `rimap-audit` — record schema (part 2: auth payload)

**Files:**
- Modify: `crates/rimap-audit/src/record.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Add the `Auth` payload and its tests**

In `crates/rimap-audit/src/record.rs`, add the new types just above the `Payload` enum (keep existing types). Insert:

```rust
/// Outcome of an IMAP authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Credential resolved and server accepted it.
    Success,
    /// Credential resolved but server rejected it.
    Failure,
}

/// Payload of the `auth` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    /// Outcome.
    pub result: AuthResult,
    /// IMAP host attempted.
    pub host: String,
    /// IMAP port attempted.
    pub port: u16,
    /// Username attempted.
    pub username: String,
    /// Observed TLS certificate fingerprint (SHA-256 hex, lowercase, no colons).
    /// `None` if the connection never reached TLS handshake completion.
    pub tls_fingerprint_sha256: Option<String>,
    /// Whether the observed fingerprint matched `imap.tls_fingerprint_sha256`
    /// from the config. `None` means the config did not pin a fingerprint.
    pub fingerprint_match: Option<bool>,
    /// On failure, the stable error code (`ERR_TLS`, `ERR_AUTH`, …); `None`
    /// on success.
    pub error_code: Option<String>,
}
```

In the `Payload` enum, add the `Auth(Auth)` variant after `ProcessEnd`:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Process startup event — always the first record of a given `process_id`.
    ProcessStart(ProcessStart),
    /// Process shutdown event — best-effort.
    ProcessEnd(ProcessEnd),
    /// IMAP authentication attempt.
    Auth(Auth),
}
```

Add this test inside the `mod tests` block:

```rust
    #[test]
    fn auth_record_round_trips_and_uses_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Auth(crate::record::Auth {
                result: crate::record::AuthResult::Success,
                host: "127.0.0.1".to_string(),
                port: 1143,
                username: "alice@example.test".to_string(),
                tls_fingerprint_sha256: Some("ab".repeat(32)),
                fingerprint_match: Some(true),
                error_code: None,
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "auth");
        assert_eq!(v["result"], "success");
        assert_eq!(v["host"], "127.0.0.1");
        assert_eq!(v["port"], 1143);
        assert_eq!(v["fingerprint_match"], true);
        assert!(v["error_code"].is_null());
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn auth_result_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::AuthResult::Failure).unwrap(),
            "\"failure\"",
        );
    }
```

- [ ] **Step 2: Update the `lib.rs` re-exports**

```rust
pub use crate::record::{
    AuditRecord, Auth, AuthResult, Payload, ProcessEnd, ProcessEndReason, ProcessStart,
};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add auth payload to AuditRecord"
```

---

## Task 9: `rimap-audit` — record schema (part 3: tool_start, tool_end, config)

**Files:**
- Modify: `crates/rimap-audit/src/record.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Add the remaining payload types**

In `crates/rimap-audit/src/record.rs`, add (after the `Auth` struct, before the `Payload` enum):

```rust
/// Payload of the `tool_start` kind. Recorded before dispatch begins so a
/// crash mid-call still leaves a breadcrumb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolStart {
    /// The v1 tool name as a string (matches `ToolName::as_str`).
    pub tool: String,
    /// Effective posture at dispatch time (after any config-override merge).
    pub posture_effective: String,
    /// Redacted arguments object produced by `redact::Redactor`.
    pub arguments_redacted: serde_json::Value,
    /// SHA-256 of the canonical JSON serialization of the *unredacted* payload,
    /// hex-encoded. Enables integrity checks without leaking content.
    pub arguments_hash_sha256: String,
}

/// Outcome status for a tool call. `Ok` means a structured result was
/// returned; `Error` means dispatch failed and `error_code` is populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Tool call succeeded.
    Ok,
    /// Tool call failed.
    Error,
}

/// A coarse summary of what a tool returned. Structured so reviewers can
/// reconstruct activity without reading message bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ResultSummary {
    /// RFC 822 `Message-ID` values returned to the caller.
    #[serde(default)]
    pub message_ids_returned: Vec<String>,
    /// Approximate bytes returned to the caller (post-truncation).
    #[serde(default)]
    pub bytes_returned: u64,
    /// Whether the server truncated the result to fit a limit.
    #[serde(default)]
    pub truncated: bool,
    /// Security warning codes emitted alongside the payload (e.g.
    /// `LOOKALIKE_SENDER_MIXED_SCRIPT`). Sprint 4 populates this.
    #[serde(default)]
    pub security_warnings_emitted: Vec<String>,
}

/// Snapshot of the provenance ring buffer at `tool_end` time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Configured window in seconds.
    pub window_seconds: u32,
    /// Message IDs read by this process within the window, oldest to newest.
    pub message_ids_recently_read: Vec<String>,
}

/// Payload of the `tool_end` kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEnd {
    /// `seq` of the paired `tool_start` record.
    pub start_seq: Seq,
    /// Tool name (duplicated from `tool_start` for self-contained log lines).
    pub tool: String,
    /// Outcome.
    pub status: ToolStatus,
    /// On `status = Error`, the stable error code; `None` on success.
    pub error_code: Option<String>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Coarse result summary.
    pub result_summary: ResultSummary,
    /// Provenance snapshot at end-of-call time.
    pub provenance: Provenance,
}

/// Payload of the `config` kind. Declared now so Sprint 5 can emit it; no
/// code path writes it yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigEvent {
    /// Path the config was loaded from.
    pub path: PathBuf,
    /// SHA-256 of the config file contents, hex-encoded.
    pub hash_sha256: String,
}
```

Extend the `Payload` enum to include all four remaining variants:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    /// Process startup event — always the first record of a given `process_id`.
    ProcessStart(ProcessStart),
    /// Process shutdown event — best-effort.
    ProcessEnd(ProcessEnd),
    /// IMAP authentication attempt.
    Auth(Auth),
    /// A tool call has entered the dispatch chain.
    ToolStart(ToolStart),
    /// A tool call has exited the dispatch chain.
    ToolEnd(ToolEnd),
    /// Config-related event (declared for Sprint 5; not emitted in Sprint 2).
    Config(ConfigEvent),
}
```

Add the corresponding tests to `mod tests`:

```rust
    #[test]
    fn tool_start_round_trips_with_snake_case_kind() {
        let rec = AuditRecord {
            seq: Seq(10),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolStart(crate::record::ToolStart {
                tool: "fetch_message".to_string(),
                posture_effective: "draft-safe".to_string(),
                arguments_redacted: serde_json::json!({
                    "folder": "INBOX",
                    "uid": 12345,
                    "include_html": false,
                }),
                arguments_hash_sha256: "de".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_start");
        assert_eq!(v["tool"], "fetch_message");
        assert_eq!(v["arguments_redacted"]["folder"], "INBOX");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_end_round_trips_with_provenance_and_summary() {
        let rec = AuditRecord {
            seq: Seq(11),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolEnd(crate::record::ToolEnd {
                start_seq: Seq(10),
                tool: "fetch_message".to_string(),
                status: crate::record::ToolStatus::Ok,
                error_code: None,
                duration_ms: 47,
                result_summary: crate::record::ResultSummary {
                    message_ids_returned: vec!["<abc@example>".to_string()],
                    bytes_returned: 4821,
                    truncated: false,
                    security_warnings_emitted: vec![],
                },
                provenance: crate::record::Provenance {
                    window_seconds: 60,
                    message_ids_recently_read: vec!["<abc@example>".to_string()],
                },
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "tool_end");
        assert_eq!(v["start_seq"], 10);
        assert_eq!(v["status"], "ok");
        assert_eq!(v["result_summary"]["bytes_returned"], 4821);
        assert_eq!(v["provenance"]["window_seconds"], 60);
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn config_event_serializes_as_config_kind() {
        let rec = AuditRecord {
            seq: Seq(3),
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::Config(crate::record::ConfigEvent {
                path: PathBuf::from("/tmp/config.toml"),
                hash_sha256: "aa".repeat(32),
            }),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "config");
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn tool_status_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&crate::record::ToolStatus::Error).unwrap(),
            "\"error\"",
        );
    }
```

- [ ] **Step 2: Extend `lib.rs` re-exports**

```rust
pub use crate::record::{
    AuditRecord, Auth, AuthResult, ConfigEvent, Payload, ProcessEnd, ProcessEndReason,
    ProcessStart, Provenance, ResultSummary, ToolEnd, ToolStart, ToolStatus,
};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add tool_start/tool_end/config payloads"
```

---
## Task 10: `rimap-audit` — redaction model and argument hasher

The redaction layer is structural: each `ToolName` declares a `RedactionSchema` listing which JSON fields are verbatim, which are replaced with `"<redacted:length>"`, which are hashed with a per-process salt, and which are forbidden (defense-in-depth deny-list). The model is pure data; Task 11 fills in the per-tool schemas.

**Files:**
- Create: `crates/rimap-audit/src/redact.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/redact.rs`:

```rust
//! Structural argument redaction for audit records. Each tool declares a
//! [`RedactionSchema`] that classifies its top-level argument fields:
//!
//! - [`FieldPolicy::Verbatim`] — structural fields copied into the record.
//! - [`FieldPolicy::RedactString`] — replaced with `"<redacted:N>"` where `N`
//!   is the UTF-8 byte length of the original string.
//! - [`FieldPolicy::SaltedHash`] — replaced with the first 16 hex chars of
//!   `sha256(salt || value)`. Unique within a process, unlinkable across
//!   processes.
//! - [`FieldPolicy::Forbidden`] — the field must not appear. Presence is
//!   scrubbed and a `tracing::warn!` emitted.
//!
//! Unknown top-level fields are treated as [`FieldPolicy::RedactString`] by
//! default — conservative.

use std::collections::BTreeMap;

use rand::RngCore;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Per-field policy for the redaction pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldPolicy {
    /// Copy the field's JSON value into the record unchanged.
    Verbatim,
    /// Replace string values with `"<redacted:N>"`. Non-string values are
    /// replaced with `"<redacted:?>"`.
    RedactString,
    /// Replace with `sha256(salt || canonical(value))` truncated to 16 hex
    /// chars. Useful for "same recipient across calls" correlation without
    /// leaking the recipient.
    SaltedHash,
    /// Forbidden field — must not appear in audit output. Presence is logged
    /// via `tracing::warn!` and the field is dropped.
    Forbidden,
}

/// Declarative schema for one tool's arguments. Field names are top-level
/// JSON object keys.
#[derive(Debug, Clone)]
pub struct RedactionSchema {
    /// Tool identifier (matches `ToolName::as_str`). Used in audit record
    /// `tool` field and in tracing output.
    pub tool: &'static str,
    /// Policies keyed by field name.
    pub policies: BTreeMap<&'static str, FieldPolicy>,
}

impl RedactionSchema {
    /// Construct a schema from a static slice of `(name, policy)` pairs.
    #[must_use]
    pub fn new(tool: &'static str, rules: &[(&'static str, FieldPolicy)]) -> Self {
        let mut policies = BTreeMap::new();
        for (name, policy) in rules {
            policies.insert(*name, *policy);
        }
        Self { tool, policies }
    }
}

/// Per-process salt used for [`FieldPolicy::SaltedHash`]. Regenerated on each
/// process start — hashes are not comparable across processes.
#[derive(Debug, Clone)]
pub struct RedactionSalt([u8; 32]);

impl RedactionSalt {
    /// Generate a fresh salt from the OS RNG.
    #[must_use]
    pub fn new_random() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct a salt from explicit bytes. Used by tests.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Applies a [`RedactionSchema`] to an argument JSON value and produces the
/// `arguments_redacted` object recorded in `tool_start`.
#[derive(Debug)]
pub struct Redactor<'a> {
    schema: &'a RedactionSchema,
    salt: &'a RedactionSalt,
}

impl<'a> Redactor<'a> {
    /// Construct a redactor against a schema and a process-lifetime salt.
    #[must_use]
    pub fn new(schema: &'a RedactionSchema, salt: &'a RedactionSalt) -> Self {
        Self { schema, salt }
    }

    /// Apply the schema to `args`, which must be a JSON object.
    ///
    /// Non-object inputs are turned into a one-field object
    /// `{"_non_object": "<redacted:?>"}` so the audit layer always writes a
    /// homogeneous shape.
    #[must_use]
    pub fn apply(&self, args: &Value) -> Value {
        let Value::Object(map) = args else {
            let mut out = Map::new();
            out.insert("_non_object".to_string(), Value::String("<redacted:?>".to_string()));
            return Value::Object(out);
        };
        let mut out = Map::new();
        for (name, value) in map {
            let policy = self
                .schema
                .policies
                .get(name.as_str())
                .copied()
                .unwrap_or(FieldPolicy::RedactString);
            match policy {
                FieldPolicy::Verbatim => {
                    out.insert(name.clone(), value.clone());
                }
                FieldPolicy::RedactString => {
                    out.insert(name.clone(), Self::redact_string(value));
                }
                FieldPolicy::SaltedHash => {
                    out.insert(name.clone(), self.salted_hash(value));
                }
                FieldPolicy::Forbidden => {
                    tracing::warn!(
                        tool = self.schema.tool,
                        field = name.as_str(),
                        "forbidden field present in tool arguments; dropped",
                    );
                }
            }
        }
        Value::Object(out)
    }

    fn redact_string(value: &Value) -> Value {
        if let Value::String(s) = value {
            Value::String(format!("<redacted:{}>", s.len()))
        } else {
            Value::String("<redacted:?>".to_string())
        }
    }

    fn salted_hash(&self, value: &Value) -> Value {
        // Canonicalize via `serde_json::to_vec`; equal values hash to the same
        // bytes within a process because `serde_json` preserves Map insertion
        // order (BTreeMap in our inputs).
        let bytes = serde_json::to_vec(value).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(self.salt.as_bytes());
        hasher.update(&bytes);
        let digest = hasher.finalize();
        let hex_s: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        Value::String(format!("salted:{hex_s}"))
    }
}

/// Computes `sha256(serde_json::to_vec(args))` on the *unredacted* arguments
/// for the `arguments_hash_sha256` audit field.
#[must_use]
pub fn hash_arguments(args: &Value) -> String {
    let bytes = serde_json::to_vec(args).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use serde_json::json;

    use crate::redact::{
        FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments,
    };

    fn schema() -> RedactionSchema {
        RedactionSchema::new(
            "create_draft",
            &[
                ("to", FieldPolicy::SaltedHash),
                ("subject", FieldPolicy::RedactString),
                ("body_text", FieldPolicy::RedactString),
                ("in_reply_to_uid", FieldPolicy::Verbatim),
                ("password", FieldPolicy::Forbidden),
            ],
        )
    }

    fn salt() -> RedactionSalt {
        RedactionSalt::from_bytes([7_u8; 32])
    }

    #[test]
    fn verbatim_fields_pass_through() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"in_reply_to_uid": 12345}));
        assert_eq!(out["in_reply_to_uid"], json!(12345));
    }

    #[test]
    fn strings_are_replaced_with_length_markers() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"subject": "hi there"}));
        assert_eq!(out["subject"], json!("<redacted:8>"));
    }

    #[test]
    fn non_string_redactable_fields_get_question_mark() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"subject": 42}));
        assert_eq!(out["subject"], json!("<redacted:?>"));
    }

    #[test]
    fn salted_hash_is_deterministic_for_same_process() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let a = r.apply(&json!({"to": "alice@example.test"}));
        let b = r.apply(&json!({"to": "alice@example.test"}));
        assert_eq!(a, b);
        let c = r.apply(&json!({"to": "bob@example.test"}));
        assert_ne!(a, c);
        let prefix = a["to"].as_str().unwrap();
        assert!(prefix.starts_with("salted:"));
    }

    #[test]
    fn salted_hash_differs_across_processes() {
        let s = schema();
        let salt_a = RedactionSalt::from_bytes([1_u8; 32]);
        let salt_b = RedactionSalt::from_bytes([2_u8; 32]);
        let ra = Redactor::new(&s, &salt_a);
        let rb = Redactor::new(&s, &salt_b);
        let a = ra.apply(&json!({"to": "alice@example.test"}));
        let b = rb.apply(&json!({"to": "alice@example.test"}));
        assert_ne!(a, b);
    }

    #[test]
    fn forbidden_fields_are_dropped() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"password": "hunter2", "in_reply_to_uid": 1}));
        assert!(!out.as_object().unwrap().contains_key("password"));
        assert_eq!(out["in_reply_to_uid"], json!(1));
    }

    #[test]
    fn unknown_fields_default_to_string_redaction() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!({"mystery": "value"}));
        assert_eq!(out["mystery"], json!("<redacted:5>"));
    }

    #[test]
    fn non_object_input_produces_placeholder() {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&json!("bare string"));
        assert_eq!(out["_non_object"], json!("<redacted:?>"));
    }

    #[test]
    fn hash_arguments_is_stable_and_hex_encoded() {
        let a = hash_arguments(&json!({"uid": 1, "folder": "INBOX"}));
        let b = hash_arguments(&json!({"uid": 1, "folder": "INBOX"}));
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn random_salt_is_not_all_zeros() {
        let salt = RedactionSalt::new_random();
        assert!(salt.as_bytes().iter().any(|&b| b != 0));
    }
}
```

Note: the `rand::rng()` call targets `rand` 0.9. If `cargo` resolves `rand` 0.8 (which exposes `rand::thread_rng()` instead), swap `rand::rng()` for `rand::thread_rng()`. Confirm the active version with `cargo tree -p rimap-audit -i rand` and adjust the call site accordingly before committing.

- [ ] **Step 2: Wire the module into `lib.rs`**

```rust
//! Append-only JSONL audit log with exclusive file locking for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod ids;
pub mod record;
pub mod redact;

pub use crate::error::AuditError;
pub use crate::ids::{ProcessId, Seq, Timestamp};
pub use crate::record::{
    AuditRecord, Auth, AuthResult, ConfigEvent, Payload, ProcessEnd, ProcessEndReason,
    ProcessStart, Provenance, ResultSummary, ToolEnd, ToolStart, ToolStatus,
};
pub use crate::redact::{FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add RedactionSchema, Redactor, and hash_arguments"
```

---

## Task 11: `rimap-audit` — per-tool redaction schemas

Every v1 tool gets a schema registered in a single `schemas()` function keyed by `ToolName`. Sprint 5 will call `schemas().get(&tool).unwrap()` at dispatch time; Sprint 2 only needs the declarations and the tests that every `ToolName::all()` entry resolves to exactly one schema.

**Files:**
- Modify: `crates/rimap-audit/src/redact.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test first**

At the bottom of `mod tests` in `redact.rs`, add:

```rust
    #[test]
    fn every_v1_tool_has_a_schema() {
        use rimap_core::ToolName;
        let table = crate::redact::schemas();
        for tool in ToolName::all() {
            assert!(
                table.iter().any(|s| s.tool == tool.as_str()),
                "missing redaction schema for {}",
                tool.as_str(),
            );
        }
    }

    #[test]
    fn schemas_do_not_have_duplicate_tools() {
        let table = crate::redact::schemas();
        let mut seen = std::collections::BTreeSet::new();
        for schema in table {
            assert!(
                seen.insert(schema.tool),
                "duplicate redaction schema for {}",
                schema.tool,
            );
        }
    }

    #[test]
    fn create_draft_schema_hashes_recipients_and_redacts_body() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == "create_draft")
            .expect("create_draft schema exists");
        assert_eq!(
            schema.policies.get("to").copied(),
            Some(FieldPolicy::SaltedHash),
        );
        assert_eq!(
            schema.policies.get("body_text").copied(),
            Some(FieldPolicy::RedactString),
        );
        assert_eq!(
            schema.policies.get("subject").copied(),
            Some(FieldPolicy::RedactString),
        );
    }

    #[test]
    fn search_schema_keeps_structural_fields_verbatim() {
        let table = crate::redact::schemas();
        let schema = table
            .iter()
            .find(|s| s.tool == "search")
            .expect("search schema exists");
        assert_eq!(
            schema.policies.get("folder").copied(),
            Some(FieldPolicy::Verbatim),
        );
        assert_eq!(
            schema.policies.get("body").copied(),
            Some(FieldPolicy::RedactString),
        );
    }
```

- [ ] **Step 2: Write the implementation**

At the bottom of `crates/rimap-audit/src/redact.rs`, before the `#[cfg(test)] mod tests`, add:

```rust
/// Registry of per-tool redaction schemas. Called once at startup and stored
/// in an `Arc<[RedactionSchema]>` alongside the `RedactionSalt`.
///
/// Schemas cover every v1 `ToolName` variant per design spec §10 "Argument
/// redaction". Field lists mirror the tool argument shapes documented in
/// spec §5 (v1 tool surface). A field not listed here defaults to
/// `FieldPolicy::RedactString` at runtime, so forgetting to list a structural
/// field only produces an overly-conservative log entry, never a leak.
#[must_use]
pub fn schemas() -> Vec<RedactionSchema> {
    use FieldPolicy::{Forbidden, RedactString, SaltedHash, Verbatim};

    vec![
        RedactionSchema::new(
            "list_folders",
            &[("password", Forbidden), ("token", Forbidden)],
        ),
        RedactionSchema::new(
            "search",
            &[
                ("folder", Verbatim),
                ("limit", Verbatim),
                ("include_seen", Verbatim),
                ("since", Verbatim),
                ("until", Verbatim),
                ("from", RedactString),
                ("to", RedactString),
                ("subject", RedactString),
                ("body", RedactString),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "search.advanced_query",
            &[
                ("folder", Verbatim),
                ("limit", Verbatim),
                ("advanced_query", RedactString),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "fetch_message",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("include_html", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "fetch_message.include_html",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("include_html", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "list_attachments",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "download_attachment",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("part", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "mark_read",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "mark_unread",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "flag",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("flag", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "unflag",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("flag", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "move_message",
            &[
                ("folder", Verbatim),
                ("uid", Verbatim),
                ("destination", Verbatim),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
        RedactionSchema::new(
            "create_draft",
            &[
                ("folder", Verbatim),
                ("in_reply_to_uid", Verbatim),
                ("to", SaltedHash),
                ("cc", SaltedHash),
                ("bcc", SaltedHash),
                ("subject", RedactString),
                ("body_text", RedactString),
                ("body_html", RedactString),
                ("password", Forbidden),
                ("token", Forbidden),
            ],
        ),
    ]
}
```

- [ ] **Step 3: Export `schemas` from `lib.rs`**

Add `schemas` to the re-export line:

```rust
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments, schemas,
};
```

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: all green. Every `ToolName::all()` variant must have a matching schema.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): declare redaction schemas for every v1 tool"
```

---

## Task 12: `rimap-audit` — property test for redaction round-trips

`proptest` generates arbitrary JSON object arguments, runs them through a schema + redactor, and asserts that:
- Fields marked `Forbidden` never appear in the output.
- Fields marked `Verbatim` appear unchanged in the output.
- Fields marked `RedactString` produce either `"<redacted:N>"` or `"<redacted:?>"`.
- The output is always a JSON object.
- `hash_arguments` is deterministic and byte-stable.

**Files:**
- Create: `crates/rimap-audit/tests/redact_properties.rs`

- [ ] **Step 1: Write the property test**

Create `crates/rimap-audit/tests/redact_properties.rs`:

```rust
//! Property tests for argument redaction.

#![expect(clippy::unwrap_used, reason = "tests")]

use proptest::prelude::*;
use rimap_audit::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments,
};
use serde_json::{Map, Value};

fn schema() -> RedactionSchema {
    RedactionSchema::new(
        "test_tool",
        &[
            ("folder", FieldPolicy::Verbatim),
            ("uid", FieldPolicy::Verbatim),
            ("subject", FieldPolicy::RedactString),
            ("body", FieldPolicy::RedactString),
            ("to", FieldPolicy::SaltedHash),
            ("password", FieldPolicy::Forbidden),
        ],
    )
}

fn salt() -> RedactionSalt {
    RedactionSalt::from_bytes([0x42_u8; 32])
}

prop_compose! {
    fn arb_input()(
        folder in prop::option::of("[A-Za-z]{1,10}"),
        uid in prop::option::of(any::<u32>()),
        subject in prop::option::of("[^\\n]{0,40}"),
        body in prop::option::of("[^\\n]{0,200}"),
        to in prop::option::of("[a-z]{1,8}@[a-z]{1,8}\\.test"),
        password in prop::option::of("[^\\n]{1,20}"),
        mystery in prop::option::of("[a-z]{1,8}"),
    ) -> Value {
        let mut m = Map::new();
        if let Some(v) = folder { m.insert("folder".into(), Value::String(v)); }
        if let Some(v) = uid { m.insert("uid".into(), Value::from(v)); }
        if let Some(v) = subject { m.insert("subject".into(), Value::String(v)); }
        if let Some(v) = body { m.insert("body".into(), Value::String(v)); }
        if let Some(v) = to { m.insert("to".into(), Value::String(v)); }
        if let Some(v) = password { m.insert("password".into(), Value::String(v)); }
        if let Some(v) = mystery { m.insert("mystery".into(), Value::String(v)); }
        Value::Object(m)
    }
}

proptest! {
    #[test]
    fn forbidden_fields_never_appear(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let obj = out.as_object().unwrap();
        prop_assert!(!obj.contains_key("password"));
    }

    #[test]
    fn verbatim_fields_pass_through_unchanged(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let in_obj = input.as_object().unwrap();
        let out_obj = out.as_object().unwrap();
        if let Some(v) = in_obj.get("folder") {
            prop_assert_eq!(out_obj.get("folder"), Some(v));
        }
        if let Some(v) = in_obj.get("uid") {
            prop_assert_eq!(out_obj.get("uid"), Some(v));
        }
    }

    #[test]
    fn redacted_strings_have_length_marker(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        let in_obj = input.as_object().unwrap();
        let out_obj = out.as_object().unwrap();
        for key in ["subject", "body"] {
            if let Some(Value::String(orig)) = in_obj.get(key) {
                let v = out_obj.get(key).unwrap();
                let s = v.as_str().unwrap();
                let expected = format!("<redacted:{}>", orig.len());
                prop_assert_eq!(s, &expected);
            }
        }
    }

    #[test]
    fn output_is_always_an_object(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let out = r.apply(&input);
        prop_assert!(out.is_object());
    }

    #[test]
    fn hash_arguments_is_deterministic(input in arb_input()) {
        let a = hash_arguments(&input);
        let b = hash_arguments(&input);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn salted_hash_is_deterministic_within_process(input in arb_input()) {
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let a = r.apply(&input);
        let b = r.apply(&input);
        prop_assert_eq!(a, b);
    }
}
```

- [ ] **Step 2: Run the property tests**

Run: `cargo test -p rimap-audit --test redact_properties`
Expected: all six properties pass (default proptest settings: 256 cases each).

- [ ] **Step 3: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/tests/redact_properties.rs
git commit -m "test(audit): property tests for redaction invariants"
```

---

## Task 13: `rimap-audit` — provenance ring buffer

**Files:**
- Create: `crates/rimap-audit/src/provenance.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/provenance.rs`:

```rust
//! In-memory ring buffer of recently-read Message-IDs. Fed by `fetch_message`
//! and `search` result paths (Sprint 5 wires the feeders). Every `tool_end`
//! snapshots the current contents into [`crate::record::Provenance`].
//!
//! Entries older than `window_seconds` are evicted on every push and on every
//! snapshot. This is a pure-Rust in-memory structure — no I/O, no locking
//! beyond what the caller holds.

use std::collections::VecDeque;

use time::OffsetDateTime;

/// Ring buffer of observed Message-IDs with timestamps. Not thread-safe on
/// its own; the caller holds a `Mutex<ProvenanceBuffer>` if needed.
#[derive(Debug, Clone)]
pub struct ProvenanceBuffer {
    window: std::time::Duration,
    entries: VecDeque<Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    message_id: String,
    seen_at: OffsetDateTime,
}

impl ProvenanceBuffer {
    /// Construct an empty buffer with a retention window in seconds.
    #[must_use]
    pub fn new(window_seconds: u32) -> Self {
        Self {
            window: std::time::Duration::from_secs(u64::from(window_seconds)),
            entries: VecDeque::new(),
        }
    }

    /// Record that a Message-ID was read now. Evicts stale entries before
    /// inserting.
    pub fn record(&mut self, message_id: impl Into<String>) {
        let now = OffsetDateTime::now_utc();
        self.evict_before(now);
        self.entries.push_back(Entry {
            message_id: message_id.into(),
            seen_at: now,
        });
    }

    /// Test-only variant taking an explicit clock so eviction can be asserted
    /// deterministically.
    #[doc(hidden)]
    pub fn record_at(&mut self, message_id: impl Into<String>, now: OffsetDateTime) {
        self.evict_before(now);
        self.entries.push_back(Entry {
            message_id: message_id.into(),
            seen_at: now,
        });
    }

    /// Return a `Vec<String>` of current entries, oldest-first. Evicts stale
    /// entries before snapshotting.
    #[must_use]
    pub fn snapshot(&mut self) -> Vec<String> {
        self.evict_before(OffsetDateTime::now_utc());
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Test-only snapshot with explicit clock.
    #[doc(hidden)]
    pub fn snapshot_at(&mut self, now: OffsetDateTime) -> Vec<String> {
        self.evict_before(now);
        self.entries.iter().map(|e| e.message_id.clone()).collect()
    }

    /// Current entry count (after the next eviction, not before).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_before(&mut self, now: OffsetDateTime) {
        let cutoff = now - self.window;
        while let Some(front) = self.entries.front() {
            if front.seen_at < cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use time::OffsetDateTime;

    use crate::provenance::ProvenanceBuffer;

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000 + secs).unwrap()
    }

    #[test]
    fn records_preserve_insertion_order() {
        let mut b = ProvenanceBuffer::new(60);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(1));
        b.record_at("<c@x>", at(2));
        let snap = b.snapshot_at(at(3));
        assert_eq!(snap, vec!["<a@x>", "<b@x>", "<c@x>"]);
    }

    #[test]
    fn entries_older_than_window_are_evicted_on_snapshot() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(5));
        b.record_at("<c@x>", at(15));
        let snap = b.snapshot_at(at(16));
        assert_eq!(snap, vec!["<b@x>", "<c@x>"]);
    }

    #[test]
    fn eviction_runs_before_new_inserts() {
        let mut b = ProvenanceBuffer::new(10);
        b.record_at("<a@x>", at(0));
        b.record_at("<b@x>", at(100));
        assert_eq!(b.len(), 1);
        assert_eq!(b.snapshot_at(at(100)), vec!["<b@x>"]);
    }

    #[test]
    fn empty_buffer_snapshots_to_empty_vec() {
        let mut b = ProvenanceBuffer::new(60);
        assert!(b.is_empty());
        let snap = b.snapshot_at(at(0));
        assert!(snap.is_empty());
    }

    #[test]
    fn window_of_zero_drops_everything_immediately() {
        let mut b = ProvenanceBuffer::new(0);
        b.record_at("<a@x>", at(0));
        assert_eq!(b.snapshot_at(at(1)), Vec::<String>::new());
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

```rust
pub mod error;
pub mod ids;
pub mod provenance;
pub mod record;
pub mod redact;

// …existing re-exports…
pub use crate::provenance::ProvenanceBuffer;
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add ProvenanceBuffer ring buffer"
```

---
## Task 14: `rimap-audit` — startup self-check (last-line read + inode)

Reads the last line of the existing audit file without pulling the whole file into memory, extracts `seq` / `process_id` / `previous_file_inode` (if the last line is a `process_start`), and reports the current file's inode for comparison. This is pure-read logic — no writing, no locking here (the writer will open the file, lock it, then call into this module).

**Files:**
- Create: `crates/rimap-audit/src/self_check.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/self_check.rs`:

```rust
//! Startup self-check: inspect the previous run's trailing state before
//! writing a new `process_start`.
//!
//! The check is read-only and runs *after* the writer has acquired the
//! exclusive lock, so the file is stable for the duration.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use serde::Deserialize;

use crate::error::AuditError;
use crate::ids::{ProcessId, Seq};

/// Result of reading the trailing state of an existing audit file. Every
/// field is `None` when the file is empty or the last line cannot be parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrailingState {
    /// `seq` of the last valid record.
    pub last_seq: Option<Seq>,
    /// `process_id` of the last valid record.
    pub last_process_id: Option<ProcessId>,
    /// Inode reported by the most recent `process_start` record, if any.
    /// Compared against the current file's inode to detect tampering.
    pub last_recorded_inode: Option<u64>,
}

/// Shape we peel off the last line. Unused fields are ignored via `#[serde]`.
#[derive(Debug, Deserialize)]
struct TailEnvelope {
    seq: Seq,
    process_id: ProcessId,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    previous_file_inode: Option<u64>,
}

/// Scan the audit file from the end and return the parsed trailing state.
///
/// A partial trailing line (from a mid-record crash) is silently skipped —
/// the next-to-last newline is treated as "end of valid data". An empty or
/// nonexistent file yields `Ok(TrailingState::default())`.
///
/// # Errors
/// Any I/O error from reading the file.
pub fn read_trailing_state(path: &Path) -> Result<TrailingState, AuditError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(TrailingState::default());
        }
        Err(source) => {
            return Err(AuditError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if meta.len() == 0 {
        return Ok(TrailingState::default());
    }

    let file = File::open(path).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let last_line = read_last_complete_line(&file).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let Some(last_line) = last_line else {
        return Ok(TrailingState::default());
    };
    let Ok(envelope) = serde_json::from_str::<TailEnvelope>(&last_line) else {
        return Ok(TrailingState::default());
    };
    let last_recorded_inode = if envelope.kind == "process_start" {
        envelope.previous_file_inode
    } else {
        None
    };
    Ok(TrailingState {
        last_seq: Some(envelope.seq),
        last_process_id: Some(envelope.process_id),
        last_recorded_inode,
    })
}

/// Returns the current inode of `path`. Returns `0` on non-Unix platforms
/// (Windows inode-equivalent is best-effort and not required for the spec's
/// tamper signal, which specifically says "if a manual `rm` occurred between
/// runs").
///
/// # Errors
/// I/O error reading metadata.
pub fn current_inode(path: &Path) -> Result<u64, AuditError> {
    let meta = std::fs::metadata(path).map_err(|source| AuditError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(inode_of(&meta))
}

#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(not(unix))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}

/// Reads the last line of a newline-terminated file by walking backwards in
/// 4 KiB chunks until a `\n` is found. Tolerates a partial trailing line
/// (no final `\n`) by using that partial line as the result if no earlier
/// newline exists, otherwise returning the *previous* line.
fn read_last_complete_line(file: &File) -> std::io::Result<Option<String>> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    const CHUNK: u64 = 4096;
    let mut pos = len;
    loop {
        let read_from = pos.saturating_sub(CHUNK);
        let to_read = (pos - read_from) as usize;
        reader.seek(SeekFrom::Start(read_from))?;
        let mut chunk = vec![0_u8; to_read];
        std::io::Read::read_exact(&mut reader, &mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
        // Look for the last two newlines in `buf`.
        let trimmed = if buf.ends_with(b"\n") {
            &buf[..buf.len() - 1]
        } else {
            &buf[..]
        };
        if let Some(idx) = trimmed.iter().rposition(|&b| b == b'\n') {
            let line = &trimmed[idx + 1..];
            return Ok(Some(String::from_utf8_lossy(line).into_owned()));
        }
        if read_from == 0 {
            // Entire file is one line, possibly without a trailing newline.
            return Ok(Some(String::from_utf8_lossy(trimmed).into_owned()));
        }
        pos = read_from;
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use crate::self_check::{TrailingState, read_trailing_state};

    fn write_file(dir: &TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body).unwrap();
        path
    }

    #[test]
    fn nonexistent_file_returns_default_state() {
        let dir = TempDir::new().unwrap();
        let state = read_trailing_state(&dir.path().join("nope.jsonl")).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn empty_file_returns_default_state() {
        let dir = TempDir::new().unwrap();
        let path = write_file(&dir, "a.jsonl", b"");
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state, TrailingState::default());
    }

    #[test]
    fn extracts_last_seq_and_process_id_from_trailing_line() {
        let dir = TempDir::new().unwrap();
        let body = concat!(
            "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":1234,\"audit_file_inode_changed\":false}\n",
            "{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_end\",\"reason\":\"eof\",\"total_tool_calls\":0}\n",
        );
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_seq.unwrap().get(), 2);
        assert!(state.last_process_id.is_some());
        // last line is process_end → no recorded inode
        assert_eq!(state.last_recorded_inode, None);
    }

    #[test]
    fn records_inode_when_last_line_is_process_start() {
        let dir = TempDir::new().unwrap();
        let body = "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":9999,\"audit_file_inode_changed\":false}\n";
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_recorded_inode, Some(9999));
    }

    #[test]
    fn partial_trailing_line_is_ignored_in_favor_of_prior_line() {
        let dir = TempDir::new().unwrap();
        let body = concat!(
            "{\"seq\":1,\"ts\":\"2026-04-07T00:00:00.000Z\",\"process_id\":\"01JXAAAAAAAAAAAAAAAAAAAAAA\",\"kind\":\"process_start\",\"version\":\"0.1.0\",\"git_commit\":\"\",\"posture\":\"draft-safe\",\"config_path\":\"/tmp/c.toml\",\"config_hash_sha256\":\"aa\",\"previous_last_seq\":null,\"previous_process_id\":null,\"previous_file_inode\":12345,\"audit_file_inode_changed\":false}\n",
            "{\"seq\":2,\"ts\":\"2026-04-07T00:00:01.000Z\",\"proces", // truncated mid-record
        );
        let path = write_file(&dir, "a.jsonl", body.as_bytes());
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state.last_seq.unwrap().get(), 1);
        assert_eq!(state.last_recorded_inode, Some(12345));
    }

    #[test]
    fn completely_unparseable_trailing_line_returns_default() {
        let dir = TempDir::new().unwrap();
        let path = write_file(&dir, "a.jsonl", b"not json at all\n");
        let state = read_trailing_state(&path).unwrap();
        assert_eq!(state, TrailingState::default());
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

```rust
pub mod self_check;
pub use crate::self_check::{TrailingState, current_inode, read_trailing_state};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add startup self-check (last-line read + inode)"
```

---

## Task 15: `rimap-audit` — `AuditWriter::open` with exclusive lock

The writer holds the file under a non-blocking exclusive lock from the moment it's opened. This task implements `open()` only — `write_record` and `rotate` come in Tasks 16–17.

**Files:**
- Create: `crates/rimap-audit/src/writer.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/writer.rs`:

```rust
//! Exclusively-locked, append-only JSONL writer. See design spec §10 "File
//! handling & locking".
//!
//! ## Invariants
//! - One `AuditWriter` holds `LOCK_EX` on its active file for its entire
//!   lifetime. The lock is released implicitly on drop (OS cleanup — no
//!   explicit `unlock()` call required).
//! - `try_lock_exclusive` is non-blocking; a second writer against the same
//!   path fails immediately with [`AuditError::Locked`].
//! - Per-record writes go through a buffered writer, flushed after each
//!   record. `fsync` is only issued on `process_*` / `auth` records
//!   (Task 16 wires that).

use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs4::fs_std::FileExt;

use crate::error::AuditError;

/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
}

/// Append-only JSONL writer. Construct via [`AuditWriter::open`]. Cheaply
/// cloneable — the underlying `File` and `BufWriter` live behind an
/// `Arc<Mutex<_>>`, so all clones write through the same lock.
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) buf: BufWriter<File>,
    /// Total bytes written to the active file (used by rotation).
    pub(crate) bytes_written: u64,
}

impl AuditWriter {
    /// Open or create the audit file at `opts.path`, acquire an exclusive
    /// non-blocking lock, and return the writer.
    ///
    /// # Errors
    /// - [`AuditError::ParentDir`] if the parent directory cannot be created.
    /// - [`AuditError::Open`] on I/O failure during `OpenOptions::open`.
    /// - [`AuditError::Locked`] if another process already holds the lock.
    pub fn open(opts: AuditOptions) -> Result<Self, AuditError> {
        if let Some(parent) = opts.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|source| AuditError::ParentDir {
                    path: opts.path.clone(),
                    source,
                })?;
                set_parent_mode_0700(parent);
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&opts.path)
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?;
        set_file_mode_0600(&file);

        match FileExt::try_lock_exclusive(&file) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AuditError::Locked {
                    path: opts.path.clone(),
                });
            }
            Err(source) => {
                return Err(AuditError::Open {
                    path: opts.path.clone(),
                    source,
                });
            }
        }

        let bytes_written = file
            .metadata()
            .map_err(|source| AuditError::Open {
                path: opts.path.clone(),
                source,
            })?
            .len();

        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
            })),
        })
    }

    /// The active audit file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rotation threshold in bytes. `0` disables rotation.
    #[must_use]
    pub fn rotate_bytes(&self) -> u64 {
        self.rotate_bytes
    }
}

#[cfg(unix)]
fn set_file_mode_0600(file: &File) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = file.metadata() {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = file.set_permissions(perms);
    }
}

#[cfg(not(unix))]
fn set_file_mode_0600(_file: &File) {}

#[cfg(unix)]
fn set_parent_mode_0700(parent: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(parent) {
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        let _ = std::fs::set_permissions(parent, perms);
    }
}

#[cfg(not(unix))]
fn set_parent_mode_0700(_parent: &Path) {}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use tempfile::TempDir;

    use crate::error::AuditError;
    use crate::writer::{AuditOptions, AuditWriter};

    #[test]
    fn open_creates_file_and_acquires_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        assert_eq!(writer.path(), path);
        assert!(path.exists());
    }

    #[test]
    fn second_open_against_same_path_fails_with_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _first = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let err = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { path: p } => assert_eq!(p, path),
            other => panic!("expected Locked, got {other:?}"),
        }
    }

    #[test]
    fn drop_releases_the_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let _first = AuditWriter::open(AuditOptions {
                path: path.clone(),
                rotate_bytes: 0,
            })
            .unwrap();
        }
        // After drop, a second open succeeds.
        let _second = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
    }

    #[test]
    fn open_creates_missing_parent_directory() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");
        let _writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }
}
```

Note on the `FileExt::try_lock_exclusive` return type: `fs4` 0.13 returns `std::io::Result<bool>` (`Ok(true)` = acquired, `Ok(false)` = would block, `Err(_)` = I/O error). If the local version returns `std::io::Result<()>` (older fs4 API), adjust the match arm accordingly — replace the `Ok(true)/Ok(false)` pair with `Ok(())` → acquired and a `Err(e) if e.kind() == std::io::ErrorKind::WouldBlock` → `AuditError::Locked`. Confirm the actual signature via `cargo doc -p fs4 --open` before Step 3.

- [ ] **Step 2: Wire into `lib.rs`**

```rust
pub mod writer;
pub use crate::writer::{AuditOptions, AuditWriter};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-audit --lib writer`
Expected: four tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add AuditWriter::open with exclusive fs4 lock"
```

---

## Task 16: `rimap-audit` — `write_record` + flush + fsync policy

`write_record` serializes the record to JSON, appends a newline, writes through the `BufWriter`, flushes, and (for `process_*` / `auth`) calls `fsync`.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `crates/rimap-audit/src/writer.rs`:

```rust
    #[test]
    fn write_record_appends_one_jsonl_line() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{
            AuditRecord, Payload, ProcessEnd, ProcessEndReason,
        };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();

        let rec = AuditRecord {
            seq: Seq::FIRST,
            ts: Timestamp::now(),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };
        writer.write_record(&rec).unwrap();
        drop(writer);

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        let line = contents.lines().next().unwrap();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["kind"], "process_end");
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn write_record_tracks_bytes_written() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{
            AuditRecord, Payload, ProcessEnd, ProcessEndReason,
        };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }
        assert_eq!(writer.bytes_written(), writer.on_disk_len().unwrap());
    }
```

- [ ] **Step 2: Implement `write_record` and the helpers**

Add inside `impl AuditWriter`:

```rust
    /// Serialize `record` as one JSONL line, append it to the active file,
    /// flush the buffer, and fsync on `process_*` / `auth` kinds.
    ///
    /// # Errors
    /// - [`AuditError::Serialize`] on JSON failure.
    /// - [`AuditError::Write`] on I/O failure during `write_all` / `flush`.
    /// - [`AuditError::Fsync`] on `fsync` failure.
    pub fn write_record(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        use std::io::Write;

        let mut bytes = serde_json::to_vec(record).map_err(AuditError::Serialize)?;
        bytes.push(b'\n');

        let mut guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "audit mutex poisoned",
            ),
        })?;

        guard.buf.write_all(&bytes).map_err(|source| AuditError::Write {
            path: self.path.clone(),
            source,
        })?;
        guard.buf.flush().map_err(|source| AuditError::Write {
            path: self.path.clone(),
            source,
        })?;
        guard.bytes_written = guard.bytes_written.saturating_add(bytes.len() as u64);

        if needs_fsync(&record.payload) {
            guard
                .buf
                .get_ref()
                .sync_data()
                .map_err(|source| AuditError::Fsync {
                    path: self.path.clone(),
                    source,
                })?;
        }

        Ok(())
    }

    /// Total bytes written through this writer since `open` (including bytes
    /// already present at open time). Used by rotation logic.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.inner
            .lock()
            .map(|g| g.bytes_written)
            .unwrap_or_default()
    }

    /// Returns the current on-disk length of the active file. Used by tests.
    ///
    /// # Errors
    /// I/O error from `metadata()`.
    pub fn on_disk_len(&self) -> Result<u64, AuditError> {
        let guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::Other,
                "audit mutex poisoned",
            ),
        })?;
        let meta = guard
            .buf
            .get_ref()
            .metadata()
            .map_err(|source| AuditError::Write {
                path: self.path.clone(),
                source,
            })?;
        Ok(meta.len())
    }
```

Add the helper below the `impl` block:

```rust
fn needs_fsync(payload: &crate::record::Payload) -> bool {
    use crate::record::Payload;
    matches!(
        payload,
        Payload::ProcessStart(_) | Payload::ProcessEnd(_) | Payload::Auth(_) | Payload::Config(_)
    )
}
```

Note: clippy `matches!` is denied workspace-wide. Replace with an explicit `match`:

```rust
fn needs_fsync(payload: &crate::record::Payload) -> bool {
    use crate::record::Payload;
    match payload {
        Payload::ProcessStart(_) | Payload::ProcessEnd(_) | Payload::Auth(_) | Payload::Config(_) => true,
        Payload::ToolStart(_) | Payload::ToolEnd(_) => false,
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-audit --lib writer`
Expected: all tests including the new ones pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-audit/src/writer.rs
git commit -m "feat(audit): add write_record with flush + selective fsync"
```

---

## Task 17: `rimap-audit` — rotation under lock

Rotation preserves the exclusive lock across the rename: the POSIX `flock` is bound to the inode, so `rename(A, A.1)` leaves the lock intact, we then create a fresh `A`, lock it, swap the `Inner.buf`, and drop the old fd (releasing its lock implicitly). Called from `write_record` when `bytes_written >= rotate_bytes > 0`.

**Files:**
- Create: `crates/rimap-audit/src/rotation.rs`
- Modify: `crates/rimap-audit/src/writer.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `writer.rs`:

```rust
    #[test]
    fn rotation_creates_new_file_and_preserves_contents() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{
            AuditRecord, Payload, ProcessEnd, ProcessEndReason,
        };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Very small rotation threshold: each record is ~180+ bytes.
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        // After rotation, the active file has been renamed and a fresh one
        // created. At least one rotated sibling must exist.
        let mut rotated = 0;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("audit.jsonl.") {
                rotated += 1;
            }
        }
        assert!(rotated >= 1, "expected at least one rotated file, got {rotated}");

        // Concatenate active + rotated contents — every record must be
        // represented exactly once.
        let mut all = String::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if p.file_name().unwrap().to_string_lossy().starts_with("audit.jsonl") {
                all.push_str(&std::fs::read_to_string(&p).unwrap());
            }
        }
        let seqs: std::collections::BTreeSet<u64> = all
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("seq").and_then(|s| s.as_u64()))
            .collect();
        assert_eq!(
            seqs,
            (1_u64..=5).collect::<std::collections::BTreeSet<_>>(),
        );
    }

    #[test]
    fn after_rotation_the_lock_still_blocks_new_writers() {
        use crate::ids::{ProcessId, Seq, Timestamp};
        use crate::record::{
            AuditRecord, Payload, ProcessEnd, ProcessEndReason,
        };

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 200,
        })
        .unwrap();

        for seq in 1_u64..=5 {
            let rec = AuditRecord {
                seq: Seq(seq),
                ts: Timestamp::now(),
                process_id: ProcessId::new_now(),
                payload: Payload::ProcessEnd(ProcessEnd {
                    reason: ProcessEndReason::Eof,
                    total_tool_calls: seq,
                }),
            };
            writer.write_record(&rec).unwrap();
        }

        let err = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap_err();
        match err {
            AuditError::Locked { .. } => {}
            other => panic!("expected Locked after rotation, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Write the rotation module**

Create `crates/rimap-audit/src/rotation.rs`:

```rust
//! Rotation-under-lock logic. See design spec §10 "File handling & locking".

use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use time::OffsetDateTime;

use crate::error::AuditError;

/// Compute the rotation destination path: `<active>.<rfc3339-timestamp>`.
/// Example: `audit.jsonl.2026-04-07T14-22-01.000Z`.
#[must_use]
pub fn rotated_path(active: &Path, now: OffsetDateTime) -> PathBuf {
    let stamp = format!(
        "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}.{:03}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    );
    let mut name = active.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(stamp);
    active.with_file_name(name)
}

/// Perform the rename + new-file dance. Returns the freshly-locked `File`
/// for the new active path (with an empty `BufWriter` wrapping it).
///
/// # Errors
/// Any I/O error during `rename`, `open`, or `try_lock_exclusive` surfaces as
/// [`AuditError::Rotate`] with a descriptive `reason`.
pub fn rotate_file(active: &Path) -> Result<(BufWriter<File>, u64), AuditError> {
    let dst = rotated_path(active, OffsetDateTime::now_utc());
    std::fs::rename(active, &dst).map_err(|source| AuditError::Rotate {
        path: active.to_path_buf(),
        reason: format!("rename to {}: {source}", dst.display()),
    })?;

    let new_file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(active)
        .map_err(|source| AuditError::Rotate {
            path: active.to_path_buf(),
            reason: format!("open fresh file: {source}"),
        })?;

    match FileExt::try_lock_exclusive(&new_file) {
        Ok(true) => {}
        Ok(false) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: "fresh file unexpectedly locked by another process".to_string(),
            });
        }
        Err(e) => {
            return Err(AuditError::Rotate {
                path: active.to_path_buf(),
                reason: format!("lock fresh file: {e}"),
            });
        }
    }

    Ok((BufWriter::new(new_file), 0))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::Path;

    use time::macros::datetime;

    use crate::rotation::rotated_path;

    #[test]
    fn rotated_path_appends_utc_stamp() {
        let active = Path::new("/tmp/audit.jsonl");
        let now = datetime!(2026-04-07 14:22:01.234 UTC);
        let r = rotated_path(active, now);
        assert_eq!(
            r.file_name().unwrap().to_string_lossy(),
            "audit.jsonl.2026-04-07T14-22-01.234Z",
        );
    }
}
```

- [ ] **Step 3: Call rotation from `write_record`**

In `crates/rimap-audit/src/writer.rs`, modify `write_record` to rotate *before* the write when `bytes_written` has crossed `rotate_bytes > 0`. Insert this block at the very top of `write_record`, before the serialization:

```rust
        if self.rotate_bytes > 0 {
            let should_rotate = {
                let guard = self.inner.lock().map_err(|_| AuditError::Write {
                    path: self.path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "audit mutex poisoned",
                    ),
                })?;
                guard.bytes_written >= self.rotate_bytes
            };
            if should_rotate {
                self.rotate()?;
            }
        }
```

Add the `rotate` method to `impl AuditWriter`:

```rust
    /// Rotate the active file: rename it to a timestamped sibling, open a
    /// fresh file at the original path, lock it, and swap it into the
    /// `Inner`. The old fd is dropped at the end of this function, which
    /// releases its lock implicitly.
    fn rotate(&self) -> Result<(), AuditError> {
        let (new_buf, new_len) = crate::rotation::rotate_file(&self.path)?;
        let mut guard = self.inner.lock().map_err(|_| AuditError::Rotate {
            path: self.path.clone(),
            reason: "audit mutex poisoned during rotate".to_string(),
        })?;
        // Swap the new buffered writer in; the old one is dropped at scope
        // exit, which closes the old fd and releases its flock.
        guard.buf = new_buf;
        guard.bytes_written = new_len;
        tracing::info!(path = %self.path.display(), "audit file rotated");
        Ok(())
    }
```

- [ ] **Step 4: Wire the module into `lib.rs`**

```rust
pub mod rotation;
```

(Not re-exporting; rotation is an internal implementation detail.)

- [ ] **Step 5: Run tests**

Run: `cargo test -p rimap-audit --lib writer && cargo test -p rimap-audit --lib rotation`
Expected: all tests pass.

- [ ] **Step 6: Clippy**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): rotate active file under lock when rotate_bytes exceeded"
```

---
## Task 18: `rimap-audit` — shared-lock reader with filter model

The reader is used by the `audit merge` subcommand and by external tools. It opens the file with `try_lock_shared`, streams JSONL through a `BufReader`, skips a malformed trailing line with a `tracing::warn!`, and applies a `Filter` struct. Multiple readers can coexist (shared locks stack), but a reader cannot open a file already held exclusively.

Note: `audit merge` typically runs when no server is live, so a shared lock on a file currently held exclusively by a running server will fail with `AuditError::Locked`. The reader treats that as a documented limitation — the user should stop the server or point `audit merge` at a rotated sibling.

**Files:**
- Create: `crates/rimap-audit/src/reader.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-audit/src/reader.rs`:

```rust
//! Shared-lock JSONL reader for `audit merge` and external tools.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use fs4::fs_std::FileExt;
use time::OffsetDateTime;

use crate::error::AuditError;
use crate::record::{AuditRecord, Payload};

/// Filter predicate for `audit merge`. Empty fields mean "no constraint".
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Inclusive lower bound on `ts`.
    pub since: Option<OffsetDateTime>,
    /// Inclusive upper bound on `ts`.
    pub until: Option<OffsetDateTime>,
    /// Required `tool` field (exact match). Only affects `tool_start` / `tool_end`.
    pub tool: Option<String>,
    /// Required `kind` field (exact match).
    pub kind: Option<String>,
    /// Required `process_id` (canonical ULID string).
    pub process: Option<String>,
}

impl Filter {
    /// Whether `record` passes this filter.
    #[must_use]
    pub fn matches(&self, record: &AuditRecord) -> bool {
        if let Some(since) = self.since {
            if record.ts.0 < since {
                return false;
            }
        }
        if let Some(until) = self.until {
            if record.ts.0 > until {
                return false;
            }
        }
        if let Some(ref want) = self.process {
            if record.process_id.to_string() != *want {
                return false;
            }
        }
        if let Some(ref want) = self.kind {
            if kind_of(&record.payload) != want {
                return false;
            }
        }
        if let Some(ref want) = self.tool {
            let got = match &record.payload {
                Payload::ToolStart(t) => Some(&t.tool),
                Payload::ToolEnd(t) => Some(&t.tool),
                _ => None,
            };
            match got {
                Some(name) if name == want => {}
                _ => return false,
            }
        }
        true
    }
}

fn kind_of(payload: &Payload) -> &'static str {
    match payload {
        Payload::ProcessStart(_) => "process_start",
        Payload::ProcessEnd(_) => "process_end",
        Payload::Auth(_) => "auth",
        Payload::ToolStart(_) => "tool_start",
        Payload::ToolEnd(_) => "tool_end",
        Payload::Config(_) => "config",
    }
}

/// Open the audit file with a shared lock.
///
/// # Errors
/// - [`AuditError::Open`] on I/O failure.
/// - [`AuditError::Locked`] when the file is held exclusively by another
///   process (e.g. a running server).
pub fn open_shared(path: &Path) -> Result<File, AuditError> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|source| AuditError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    match FileExt::try_lock_shared(&file) {
        Ok(true) => Ok(file),
        Ok(false) => Err(AuditError::Locked {
            path: path.to_path_buf(),
        }),
        Err(source) => Err(AuditError::Open {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Stream records from `path` through `filter` into `on_record`. A partial
/// trailing line emits a single `tracing::warn!` and is skipped. Any other
/// parse failure aborts with [`AuditError::Read`] containing the offending
/// line number.
///
/// # Errors
/// I/O error from reading the file, or a JSON parse failure on a
/// non-trailing line.
pub fn stream_records<F>(
    path: &Path,
    filter: &Filter,
    mut on_record: F,
) -> Result<usize, AuditError>
where
    F: FnMut(&AuditRecord) -> Result<(), AuditError>,
{
    let file = open_shared(path)?;
    let reader = BufReader::new(file);
    let mut lines: Vec<String> = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|source| AuditError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        lines.push(line);
    }

    let mut count = 0_usize;
    let total = lines.len();
    for (idx, line) in lines.into_iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let parsed: Result<AuditRecord, _> = serde_json::from_str(&line);
        match parsed {
            Ok(rec) => {
                if filter.matches(&rec) {
                    on_record(&rec)?;
                    count += 1;
                }
            }
            Err(err) if idx + 1 == total => {
                tracing::warn!(
                    path = %path.display(),
                    line = idx + 1,
                    error = %err,
                    "skipping malformed trailing line in audit file",
                );
            }
            Err(err) => {
                return Err(AuditError::Read {
                    path: PathBuf::from(format!("{} (line {})", path.display(), idx + 1)),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
                });
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;
    use time::macros::datetime;

    use crate::ids::{ProcessId, Seq, Timestamp};
    use crate::reader::{Filter, stream_records};
    use crate::record::{
        AuditRecord, Payload, ProcessEnd, ProcessEndReason,
    };

    fn sample(seq: u64, pid: ProcessId) -> AuditRecord {
        AuditRecord {
            seq: Seq(seq),
            ts: Timestamp(datetime!(2026-04-07 14:22:01.000 UTC)),
            process_id: pid,
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: seq,
            }),
        }
    }

    fn write_lines(dir: &TempDir, name: &str, lines: &[String]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        for line in lines {
            f.write_all(line.as_bytes()).unwrap();
            f.write_all(b"\n").unwrap();
        }
        path
    }

    #[test]
    fn streams_all_records_with_empty_filter() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut seen = Vec::new();
        let count = stream_records(&path, &Filter::default(), |rec| {
            seen.push(rec.seq.get());
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(seen, vec![1, 2, 3]);
    }

    #[test]
    fn malformed_trailing_line_is_skipped_with_warning() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let mut lines: Vec<String> = (1_u64..=2)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        lines.push("{\"seq\":3,\"kind\":\"proce".to_string()); // truncated
        let path = write_lines(&dir, "a.jsonl", &lines);

        let mut count = 0;
        stream_records(&path, &Filter::default(), |_rec| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn malformed_non_trailing_line_is_an_error() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let good = serde_json::to_string(&sample(1, pid)).unwrap();
        let good2 = serde_json::to_string(&sample(2, pid)).unwrap();
        let lines = vec!["not json".to_string(), good, good2];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let err = stream_records(&path, &Filter::default(), |_| Ok(())).unwrap_err();
        assert!(format!("{err}").contains("line 1") || format!("{err}").contains("line "));
    }

    #[test]
    fn filter_by_kind_matches_exact_string() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines: Vec<String> = (1_u64..=3)
            .map(|s| serde_json::to_string(&sample(s, pid)).unwrap())
            .collect();
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            kind: Some("process_end".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 3);

        let filter = Filter {
            kind: Some("process_start".to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn filter_by_process_id_matches() {
        let dir = TempDir::new().unwrap();
        let pid_a = ProcessId::new_now();
        let pid_b = ProcessId::new_now();
        let lines = vec![
            serde_json::to_string(&sample(1, pid_a)).unwrap(),
            serde_json::to_string(&sample(2, pid_b)).unwrap(),
            serde_json::to_string(&sample(3, pid_a)).unwrap(),
        ];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            process: Some(pid_a.to_string()),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn filter_by_since_and_until_restricts_range() {
        let dir = TempDir::new().unwrap();
        let pid = ProcessId::new_now();
        let lines = vec![serde_json::to_string(&sample(1, pid)).unwrap()];
        let path = write_lines(&dir, "a.jsonl", &lines);

        let filter = Filter {
            since: Some(datetime!(2027-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            until: Some(datetime!(2020-01-01 00:00:00.000 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 0);

        let filter = Filter {
            since: Some(datetime!(2026-01-01 00:00:00.000 UTC)),
            until: Some(datetime!(2026-12-31 23:59:59.999 UTC)),
            ..Filter::default()
        };
        let count = stream_records(&path, &filter, |_| Ok(())).unwrap();
        assert_eq!(count, 1);
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

```rust
pub mod reader;
pub use crate::reader::{Filter, open_shared, stream_records};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-audit --lib reader && cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-audit/src/
git commit -m "feat(audit): add shared-lock reader with Filter and partial-line tolerance"
```

---

## Task 19: Integration test — concurrent process lock conflict

A dedicated integration test under `crates/rimap-audit/tests/` that opens two `AuditWriter`s against the same path and asserts the second one fails with `AuditError::Locked`. This test exists alongside the unit-test version in `writer.rs` because the exit criterion explicitly names the *integration* behavior and it gives `just ci` a named test binary to report.

**Files:**
- Create: `crates/rimap-audit/tests/concurrent_lock.rs`

- [ ] **Step 1: Write the test**

Create `crates/rimap-audit/tests/concurrent_lock.rs`:

```rust
//! Integration test: a second `AuditWriter` against the same path fails with
//! `AuditError::Locked`, matching the Sprint 2 exit criterion.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use rimap_audit::{AuditError, AuditOptions, AuditWriter};
use tempfile::TempDir;

#[test]
fn concurrent_open_fails_fast_with_locked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let _first = AuditWriter::open(AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
    })
    .unwrap();

    let err = AuditWriter::open(AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
    })
    .unwrap_err();
    match err {
        AuditError::Locked { path: p } => assert_eq!(p, path),
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn lock_released_after_drop_allows_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    {
        let _first = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
    }
    let _second = AuditWriter::open(AuditOptions {
        path,
        rotate_bytes: 0,
    })
    .unwrap();
}
```

- [ ] **Step 2: Run and commit**

Run: `cargo test -p rimap-audit --test concurrent_lock`
Expected: two tests pass.

```bash
git add crates/rimap-audit/tests/concurrent_lock.rs
git commit -m "test(audit): integration test for concurrent lock conflict"
```

---

## Task 20: Integration test — rotation preserves records and lock

**Files:**
- Create: `crates/rimap-audit/tests/rotation.rs`

- [ ] **Step 1: Write the test**

Create `crates/rimap-audit/tests/rotation.rs`:

```rust
//! Integration test for rotation-under-lock. Crosses the rotation boundary
//! multiple times and asserts no record loss, plus that the lock remains
//! held after each rotation.

#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]

use std::collections::BTreeSet;

use rimap_audit::{
    AuditError, AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason,
    ProcessId, Seq, Timestamp,
};
use tempfile::TempDir;

fn record(seq: u64) -> AuditRecord {
    AuditRecord {
        seq: Seq(seq),
        ts: Timestamp::now(),
        process_id: ProcessId::new_now(),
        payload: Payload::ProcessEnd(ProcessEnd {
            reason: ProcessEndReason::Eof,
            total_tool_calls: seq,
        }),
    }
}

#[test]
fn writes_survive_multiple_rotations() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(AuditOptions {
        path: path.clone(),
        rotate_bytes: 300,
    })
    .unwrap();
    const N: u64 = 25;
    for seq in 1..=N {
        writer.write_record(&record(seq)).unwrap();
    }
    drop(writer);

    // Gather every `audit.jsonl*` file in the directory.
    let mut all = String::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.file_name().unwrap().to_string_lossy().starts_with("audit.jsonl") {
            all.push_str(&std::fs::read_to_string(&p).unwrap());
        }
    }

    let seen: BTreeSet<u64> = all
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.get("seq").and_then(|s| s.as_u64()))
        .collect();
    assert_eq!(seen, (1..=N).collect::<BTreeSet<_>>());
}

#[test]
fn lock_persists_across_rotations() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(AuditOptions {
        path: path.clone(),
        rotate_bytes: 300,
    })
    .unwrap();
    for seq in 1_u64..=10 {
        writer.write_record(&record(seq)).unwrap();
    }

    let err = AuditWriter::open(AuditOptions {
        path: path.clone(),
        rotate_bytes: 0,
    })
    .unwrap_err();
    match err {
        AuditError::Locked { .. } => {}
        other => panic!("expected Locked, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run and commit**

Run: `cargo test -p rimap-audit --test rotation`
Expected: two tests pass.

```bash
git add crates/rimap-audit/tests/rotation.rs
git commit -m "test(audit): integration test for rotation under lock"
```

---

## Task 21: Integration test — partial-line recovery

**Files:**
- Create: `crates/rimap-audit/tests/partial_line.rs`

- [ ] **Step 1: Write the test**

Create `crates/rimap-audit/tests/partial_line.rs`:

```rust
//! Integration test for the reader's partial-trailing-line tolerance. The
//! scenario models a crash between `BufWriter::flush` attempts: a well-formed
//! prefix followed by a truncated last record.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::io::Write;

use rimap_audit::{Filter, stream_records};
use tempfile::TempDir;

#[test]
fn partial_trailing_line_is_skipped() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    let good_a = r#"{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_end","reason":"eof","total_tool_calls":0}"#;
    let good_b = r#"{"seq":2,"ts":"2026-04-07T14:22:02.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_end","reason":"eof","total_tool_calls":1}"#;
    let bad = r#"{"seq":3,"ts":"2026-04-07T14:22:03.000Z","proces"#;

    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{good_a}").unwrap();
    writeln!(f, "{good_b}").unwrap();
    // Truncated: no trailing newline.
    write!(f, "{bad}").unwrap();
    drop(f);

    let mut seen = Vec::new();
    let n = stream_records(&path, &Filter::default(), |rec| {
        seen.push(rec.seq.get());
        Ok(())
    })
    .unwrap();
    assert_eq!(n, 2);
    assert_eq!(seen, vec![1, 2]);
}
```

- [ ] **Step 2: Run and commit**

Run: `cargo test -p rimap-audit --test partial_line`
Expected: one test passes.

```bash
git add crates/rimap-audit/tests/partial_line.rs
git commit -m "test(audit): integration test for partial-trailing-line recovery"
```

---

## Task 22: Integration test — inode-change detection

**Files:**
- Create: `crates/rimap-audit/tests/inode_change.rs`

- [ ] **Step 1: Write the test**

Create `crates/rimap-audit/tests/inode_change.rs`:

```rust
//! Integration test for the startup self-check's tamper-signal path.
//!
//! Scenario: first run writes a `process_start` with its current inode in
//! `previous_file_inode`. The file is then removed (simulating `rm`). Second
//! run re-opens the file (a fresh inode), calls `read_trailing_state`, and
//! verifies the comparison would flag a mismatch.
//!
//! On Windows the inode concept does not apply; `current_inode` returns `0`
//! and this test is compiled out.

#![expect(clippy::unwrap_used, reason = "tests")]
#![cfg(unix)]

use std::io::Write;

use rimap_audit::{TrailingState, current_inode, read_trailing_state};
use tempfile::TempDir;

#[test]
fn rm_between_runs_is_detected_as_tamper_signal() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    // Pretend first run: write a process_start line with previous_file_inode = 111.
    let body = r#"{"seq":1,"ts":"2026-04-07T14:22:01.000Z","process_id":"01JXAAAAAAAAAAAAAAAAAAAAAA","kind":"process_start","version":"0.1.0","git_commit":"","posture":"draft-safe","config_path":"/tmp/c.toml","config_hash_sha256":"aa","previous_last_seq":null,"previous_process_id":null,"previous_file_inode":111,"audit_file_inode_changed":false}"#;
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{body}").unwrap();
    drop(f);

    let state_before: TrailingState = read_trailing_state(&path).unwrap();
    assert_eq!(state_before.last_recorded_inode, Some(111));

    // Simulate `rm`: delete and recreate the file.
    std::fs::remove_file(&path).unwrap();
    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "{body}").unwrap();
    drop(f);

    let observed = current_inode(&path).unwrap();
    // 111 is almost certainly not the real inode of the freshly recreated
    // file — we assert they differ (the tamper-signal computation).
    assert_ne!(observed, 111);
}
```

- [ ] **Step 2: Run and commit**

Run: `cargo test -p rimap-audit --test inode_change`
Expected: one test passes on Linux/macOS; skipped on Windows.

```bash
git add crates/rimap-audit/tests/inode_change.rs
git commit -m "test(audit): integration test for inode-change tamper signal"
```

---
## Task 23: `rimap-server` — add `rimap-audit` dependency and `audit` subcommand shell

**Files:**
- Modify: `crates/rimap-server/Cargo.toml`
- Modify: `crates/rimap-server/src/cli.rs`

- [ ] **Step 1: Add the dependency**

Add to `[dependencies]` in `crates/rimap-server/Cargo.toml`:

```toml
rimap-audit = { workspace = true }
time = { workspace = true }
```

- [ ] **Step 2: Extend the `Command` enum**

In `crates/rimap-server/src/cli.rs`, add an `Audit` variant:

```rust
/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Interactively store IMAP credentials in the OS keychain.
    Login {
        /// IMAP host (e.g. `127.0.0.1` for Proton Bridge).
        #[arg(long)]
        host: String,
        /// IMAP username (e.g. `alice@example.com`).
        #[arg(long)]
        username: String,
    },
    /// Audit log inspection utilities.
    Audit {
        /// Audit subcommand.
        #[command(subcommand)]
        action: AuditAction,
    },
}

/// Actions under `rusty-imap-mcp audit <action>`.
#[derive(Debug, Subcommand)]
pub enum AuditAction {
    /// Stream the active (or rotated) audit file as filtered JSONL on stdout.
    Merge {
        /// Path to an audit file.
        #[arg(value_name = "PATH")]
        path: std::path::PathBuf,
        /// Only include records at or after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<String>,
        /// Only include records at or before this RFC 3339 timestamp.
        #[arg(long)]
        until: Option<String>,
        /// Only include records whose `tool` field matches this string.
        #[arg(long)]
        tool: Option<String>,
        /// Only include records whose `kind` field matches this string.
        #[arg(long)]
        kind: Option<String>,
        /// Only include records whose `process_id` matches this ULID.
        #[arg(long)]
        process: Option<String>,
    },
}
```

- [ ] **Step 3: Add tests for the new CLI variants**

Add to the `mod tests` block in `cli.rs`:

```rust
    #[test]
    fn parses_audit_merge_with_all_filters() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "audit",
            "merge",
            "/tmp/audit.jsonl",
            "--since",
            "2026-04-07T00:00:00Z",
            "--until",
            "2026-04-08T00:00:00Z",
            "--tool",
            "search",
            "--kind",
            "tool_end",
            "--process",
            "01JXAAAAAAAAAAAAAAAAAAAAAA",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Audit {
                action:
                    crate::cli::AuditAction::Merge {
                        path,
                        since,
                        until,
                        tool,
                        kind,
                        process,
                    },
            }) => {
                assert_eq!(path, std::path::PathBuf::from("/tmp/audit.jsonl"));
                assert_eq!(since.as_deref(), Some("2026-04-07T00:00:00Z"));
                assert_eq!(until.as_deref(), Some("2026-04-08T00:00:00Z"));
                assert_eq!(tool.as_deref(), Some("search"));
                assert_eq!(kind.as_deref(), Some("tool_end"));
                assert_eq!(
                    process.as_deref(),
                    Some("01JXAAAAAAAAAAAAAAAAAAAAAA"),
                );
            }
            other => panic!("expected Audit::Merge, got {other:?}"),
        }
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-server --lib cli`
Expected: all four CLI tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-server/Cargo.toml crates/rimap-server/src/cli.rs
git commit -m "feat(server): add audit subcommand with merge filters"
```

---

## Task 24: `rimap-server` — `audit merge` handler

**Files:**
- Create: `crates/rimap-server/src/audit_cmd.rs`
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Write the handler**

Create `crates/rimap-server/src/audit_cmd.rs`:

```rust
//! `audit merge` subcommand handler.
//!
//! Streams JSONL from an audit file on stdout, filtered by the CLI flags.
//! Stdout writes go through `std::io::stdout().lock()` directly to dodge the
//! workspace `print_stdout` lint (same pattern as `dry_run`).
//!
//! The audit log is the source of truth; this command re-serializes every
//! record via `serde_json::to_string` so the output is canonical and easily
//! piped into `jq`.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{Filter, stream_records};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Run the `audit merge` subcommand.
///
/// # Errors
/// - Any `AuditError` from opening / locking / reading the file.
/// - Parse errors on `--since` / `--until` arguments.
/// - Stdout I/O errors.
#[allow(clippy::too_many_arguments)] // subcommand signature; splitting hurts readability
pub fn run(
    path: &Path,
    since: Option<&str>,
    until: Option<&str>,
    tool: Option<&str>,
    kind: Option<&str>,
    process: Option<&str>,
) -> anyhow::Result<()> {
    let filter = Filter {
        since: since
            .map(|s| OffsetDateTime::parse(s, &Rfc3339))
            .transpose()
            .with_context(|| format!("parsing --since `{}`", since.unwrap_or("")))?,
        until: until
            .map(|s| OffsetDateTime::parse(s, &Rfc3339))
            .transpose()
            .with_context(|| format!("parsing --until `{}`", until.unwrap_or("")))?,
        tool: tool.map(str::to_string),
        kind: kind.map(str::to_string),
        process: process.map(str::to_string),
    };

    let mut stdout = std::io::stdout().lock();
    stream_records(path, &filter, |record| {
        let line = serde_json::to_string(record).map_err(rimap_audit::AuditError::Serialize)?;
        writeln!(stdout, "{line}").map_err(|source| rimap_audit::AuditError::Write {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    })
    .context("streaming audit records")?;
    Ok(())
}
```

Note on the `#[allow(clippy::too_many_arguments)]`: the workspace denies `allow_attributes`, so use `#[expect(clippy::too_many_arguments, reason = "subcommand signature")]` instead. If that still fires as too-many-args, reduce to five by bundling `since`/`until` into a `(Option<&str>, Option<&str>)` tuple.

- [ ] **Step 2: Dispatch the subcommand from `main.rs`**

Modify `crates/rimap-server/src/main.rs`:

```rust
//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod audit_cmd;
mod cli;
mod dry_run;
mod logging;

use std::io::Write;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rimap_config::credential::KeyringStore;
use rimap_config::loader::resolve_config_path;
use rimap_config::login::{run_login, tty_prompt};

use crate::cli::{AuditAction, Cli, Command};

fn main() -> ExitCode {
    logging::init();
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Some(Command::Login { host, username }) => {
            let store = KeyringStore;
            run_login(&store, &username, &host, tty_prompt)
                .with_context(|| format!("storing credential for {username}@{host}"))?;
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "credential stored for {username}@{host}")?;
            return Ok(());
        }
        Some(Command::Audit {
            action:
                AuditAction::Merge {
                    path,
                    since,
                    until,
                    tool,
                    kind,
                    process,
                },
        }) => {
            return audit_cmd::run(
                &path,
                since.as_deref(),
                until.as_deref(),
                tool.as_deref(),
                kind.as_deref(),
                process.as_deref(),
            );
        }
        None => {}
    }

    if cli.dry_run {
        let path = cli
            .config
            .clone()
            .or_else(|| resolve_config_path(None))
            .ok_or_else(|| {
                anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)")
            })?;
        let mut stdout = std::io::stdout().lock();
        return dry_run::run(&path, &mut stdout);
    }

    // MCP server loop lands in Sprint 5.
    Err(anyhow::anyhow!(
        "MCP server mode is not implemented until Sprint 5; \
         use --dry-run or the `login` subcommand"
    ))
}
```

- [ ] **Step 3: Build and test**

Run: `cargo test -p rimap-server`
Expected: existing tests still pass; new subcommand compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/
git commit -m "feat(server): implement audit merge subcommand"
```

---

## Task 25: `rimap-server` — open `AuditWriter` in `--dry-run` path

Sprint 2's exit criterion requires that a second `--dry-run` instance against the same audit path fails with `ERR_CONFIG`. The cleanest way to honor that is to acquire the audit lock inside `dry_run::run` after validating the config. The writer is opened but no records are written — the drop at the end of `run` releases the lock. This matches the spec: `--dry-run` is supposed to exercise every startup-time check short of the MCP loop.

**Files:**
- Modify: `crates/rimap-server/src/dry_run.rs`

- [ ] **Step 1: Extend the existing `run` function**

In `crates/rimap-server/src/dry_run.rs`, replace the body of `run` with the version below. Keep the module docstring; drop the `insta`-style stable-output claim only if needed — matrix formatting is unchanged.

```rust
use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_audit::{AuditOptions, AuditWriter};
use rimap_authz::matrix::EffectiveMatrix;
use rimap_config::loader::load_from_path;
use rimap_config::validate::validate;

/// Load `path`, validate, acquire the audit lock (exercising the Sprint-2
/// concurrent-lock exit criterion), build the effective matrix, print it
/// to `out`, and return. The audit writer is opened but no records are
/// written — its `Drop` releases the lock.
///
/// # Errors
/// Propagates config load/validate errors, audit open/lock errors, and I/O
/// errors from the writer.
pub fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
    let raw = load_from_path(path).with_context(|| format!("loading config {}", path.display()))?;
    let validated = validate(raw).context("validating config")?;

    let audit_path = validated.audit_path().to_path_buf();
    let rotate_bytes = validated.audit_rotate_bytes();
    let _writer = AuditWriter::open(AuditOptions {
        path: audit_path.clone(),
        rotate_bytes,
    })
    .with_context(|| format!("opening audit log at {}", audit_path.display()))?;

    let matrix = EffectiveMatrix::from_validated(&validated);
    writeln!(out, "Effective matrix (posture = {})", matrix.posture())?;
    for (tool, allowed) in matrix.rows() {
        let tag = if allowed { "[ok ]" } else { "[deny]" };
        writeln!(out, "  {tag} {tool}")?;
    }
    Ok(())
}
```

If `ValidatedConfig` does not currently expose `audit_path()` / `audit_rotate_bytes()` getters, add them to `rimap-config::validate` as thin accessors:

```rust
impl ValidatedConfig {
    pub fn audit_path(&self) -> &std::path::Path {
        &self.audit.path
    }

    pub fn audit_rotate_bytes(&self) -> u64 {
        self.audit.rotate_bytes
    }
}
```

(Check the actual field names in `rimap-config/src/validate.rs` and adjust. If the accessors already exist under different names, use them verbatim and skip the helper additions.)

- [ ] **Step 2: Update existing tests**

Existing `dry_run` tests construct a config with `audit.path = "<tempdir>/audit.jsonl"`, which is now *opened* — that's fine because each test has its own tempdir. Add one new test asserting the concurrent-lock behavior:

```rust
    #[test]
    fn second_dry_run_against_same_audit_fails_with_config_error() {
        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);

        // First dry-run acquires the lock for the duration of the call.
        let mut out1 = Vec::new();
        run(&path, &mut out1).unwrap();

        // Hold the audit file open with a direct writer so the second dry-run
        // collides with us.
        use rimap_audit::{AuditOptions, AuditWriter};
        let audit_path = dir.path().join("audit.jsonl");
        let _held = AuditWriter::open(AuditOptions {
            path: audit_path,
            rotate_bytes: 0,
        })
        .unwrap();

        let err = run(&path, &mut Vec::new()).unwrap_err();
        let chain: String = err.chain().map(|c| format!("{c}")).collect::<Vec<_>>().join("\n");
        assert!(
            chain.contains("already locked") || chain.contains("opening audit log"),
            "unexpected error chain: {chain}",
        );
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-server`
Expected: all pass including the new lock-collision test.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/ crates/rimap-config/src/
git commit -m "feat(server): acquire audit lock in --dry-run path"
```

---

## Task 26: `rimap-server` — end-to-end integration test for `audit merge` round-trip

The Sprint 2 exit criterion says "audit merge subcommand round-trips a synthetic log". This test writes a handful of records directly via `AuditWriter`, then shells out to the compiled binary's `audit merge` subcommand and asserts the JSONL output matches.

**Files:**
- Create: `crates/rimap-server/tests/audit_merge.rs`

- [ ] **Step 1: Write the test**

Create `crates/rimap-server/tests/audit_merge.rs`:

```rust
//! End-to-end test: write a synthetic audit log via `AuditWriter`, invoke
//! the compiled `rusty-imap-mcp audit merge` binary, parse its stdout, and
//! verify every record is present in order.

#![expect(clippy::unwrap_used, reason = "tests")]

use std::collections::BTreeSet;

use assert_cmd::Command;
use rimap_audit::{
    AuditOptions, AuditRecord, AuditWriter, Payload, ProcessEnd, ProcessEndReason, ProcessId,
    Seq, Timestamp,
};
use tempfile::TempDir;

fn record(seq: u64, pid: ProcessId) -> AuditRecord {
    AuditRecord {
        seq: Seq(seq),
        ts: Timestamp::now(),
        process_id: pid,
        payload: Payload::ProcessEnd(ProcessEnd {
            reason: ProcessEndReason::Eof,
            total_tool_calls: seq,
        }),
    }
}

#[test]
fn audit_merge_round_trips_synthetic_log() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    {
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let pid = ProcessId::new_now();
        for seq in 1_u64..=7 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
        // Drop releases the lock so the subcommand can take a shared lock.
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "audit merge failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let seqs: BTreeSet<u64> = stdout
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .map(|v| v["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, (1_u64..=7).collect::<BTreeSet<_>>());
}

#[test]
fn audit_merge_filters_by_kind() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    {
        let writer = AuditWriter::open(AuditOptions {
            path: path.clone(),
            rotate_bytes: 0,
        })
        .unwrap();
        let pid = ProcessId::new_now();
        for seq in 1_u64..=3 {
            writer.write_record(&record(seq, pid)).unwrap();
        }
    }

    let out = Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("audit")
        .arg("merge")
        .arg(&path)
        .arg("--kind")
        .arg("process_start")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.trim().is_empty(), "expected no matches, got {stdout}");
}
```

- [ ] **Step 2: Run and commit**

Run: `cargo test -p rimap-server --test audit_merge`
Expected: two tests pass.

```bash
git add crates/rimap-server/tests/audit_merge.rs
git commit -m "test(server): end-to-end audit merge round-trip"
```

---

## Task 27: Cargo deny sweep and minimal skip justifications

New deps (`fs4`, `serde_json`, `time`, `ulid`, `sha2`, `hex`, `rand`) may pull in duplicate transitive versions of crates already in the graph. Sprint 0's `deny.toml` has narrowly-scoped skips for `hashbrown 0.14` and `windows-sys 0.48/0.52/0.59`. Sprint 2 confirms the existing skips are still minimal and adds new ones only if justified.

**Files:**
- Modify (maybe): `deny.toml`

- [ ] **Step 1: Run cargo deny**

Run: `cargo deny check`
Expected: all four categories (advisories, licenses, bans, sources) pass. If any license is missing, evaluate it carefully — only add MIT-compatible permissive licenses. Never add copyleft without explicit approval.

- [ ] **Step 2: If duplicate-version bans fail**

For each failing crate, run `cargo tree -i <crate>` to identify both sources. Add a skip entry to `deny.toml` only if:
1. Both sources are upstream crates we cannot patch.
2. A `cargo update` does not unify the versions.
3. The skip is scoped to the specific version, not a wildcard.

Add a prose comment above each new skip explaining *why* it exists (the Sprint 0 comments are the gold standard).

Example skeleton:

```toml
# `rand` 0.8 pulled in by `<crate A>`, `rand` 0.9 pulled in by `<crate B>`.
# Neither will budge — tracked upstream in <issue URL>.
{ name = "rand", version = "0.8" },
```

- [ ] **Step 3: Re-run cargo deny**

Run: `cargo deny check`
Expected: clean.

- [ ] **Step 4: Run cargo deny on advisories explicitly**

Run: `cargo deny check advisories`
Expected: clean. Pay special attention to any RUSTSEC notice affecting `fs4`, `time`, `rand`, or `ulid` — Sprint 2's new deps are exactly the ones most likely to carry advisories.

- [ ] **Step 5: Commit if `deny.toml` changed**

```bash
git add deny.toml
git commit -m "chore: justify cargo-deny skips introduced by Sprint 2 deps"
```

Skip this step if `deny.toml` was not modified.

---

## Task 28: Full workspace `just ci` gate

**Files:** none

- [ ] **Step 1: Format**

Run: `just fmt`
Expected: success. If the diff is significant, commit as a separate style commit:

```bash
git diff
git add -u
git commit -m "style: cargo fmt"
```

- [ ] **Step 2: Full local-CI run**

Run: `just ci`
Expected: green across fmt-check, clippy, test, test-msrv, deny, hooks.

- [ ] **Step 3: If `just test-msrv` fails**

MSRV is 1.85.1. Check if any new dep pushed above that floor:
1. `cargo msrv verify` or inspect the dep's `rust-version`.
2. Pin via `cargo update -p <crate> --precise <version>` if an older version works.
3. If pinning is infeasible, stop and ask — MSRV bumps are a spec-level decision.

- [ ] **Step 4: Final prek**

Run: `prek run --all-files`
Expected: all green.

- [ ] **Step 5: Verify clean end state**

Run: `git status`
Expected: clean working tree.

---

## Task 29: Push branch and open PR

**Files:** none

- [ ] **Step 1: Push**

Run: `git push -u origin feat/sprint-2-implementation`

- [ ] **Step 2: Open the PR**

Run:

```bash
gh pr create --base main --title "Sprint 2: audit log, redaction schemas, audit merge" --body "$(cat <<'EOF'
## Summary

- `rimap-audit`: `AuditWriter` with non-blocking exclusive `fs4` lock, per-record write + flush, selective fsync on `process_*`/`auth`, rotation-under-lock preserving the lock across rename, shared-lock reader with partial-trailing-line tolerance.
- Full `AuditRecord` schema per design spec §10: `process_start`, `process_end`, `auth`, `tool_start`, `tool_end`, and declared-but-unemitted `config`. Strongly-typed `Seq`, `ProcessId`, `Timestamp` newtypes. Replaces the Sprint-1 shell in `rimap-core::audit` (deleted).
- Redaction model (`RedactionSchema`, `Redactor`, `RedactionSalt`) with a per-tool schema registry covering every v1 `ToolName` variant. Property tests verify redaction invariants.
- `ProvenanceBuffer` ring buffer with deterministic eviction tests.
- Startup self-check: reads the previous trailing line, extracts `seq` / `process_id` / `previous_file_inode`, and exposes `current_inode` for tamper comparison. Tolerates partial trailing lines.
- `rimap-server`:
  - New `audit merge <path>` subcommand with `--since`/`--until`/`--tool`/`--kind`/`--process` filters, writing canonical JSONL on stdout.
  - `--dry-run` path now opens the audit file under exclusive lock, so a second concurrent `--dry-run` fails with `ERR_CONFIG` (exit criterion).
- Integration tests: concurrent-lock conflict, rotation-under-lock, partial-line recovery, inode-change detection (Unix), end-to-end `audit merge` round-trip against the compiled binary.

## Spec deviation

- Uses `fs4` 0.13 instead of the spec-named `fs2`. `fs4` is the actively-maintained drop-in successor of `fs2` with the same `FileExt` API. Rationale documented in the plan and the commit history.

## Test plan

- [ ] `just ci` green locally
- [ ] `cargo test -p rimap-audit` green (unit + four integration suites)
- [ ] `cargo test -p rimap-server --test audit_merge` green (end-to-end round-trip)
- [ ] All 7 CI status checks green (fmt, clippy, test stable, test MSRV 1.85.1, deny, zizmor, SonarCloud)
- [ ] Manual: two concurrent `./target/debug/rusty-imap-mcp --config <sample> --dry-run` against the same audit path — second instance exits non-zero with an "already locked" message.
EOF
)"
```

Expected: PR URL printed.

- [ ] **Step 3: Wait for CI and verify**

Run: `gh pr checks --watch`
Expected: all 7 checks green.

Known risks:
- Duplicate-version ban failures from `rand` 0.8 vs 0.9, `windows-sys` minor versions — handled in Task 27.
- MSRV regression from a new dep — handled in Task 28 Step 3.
- `test-msrv` may need a `cargo update -p <crate> --precise` pin.

If a check fails, fix the root cause in a new commit on the branch. Do not amend published commits.

- [ ] **Step 4: Sprint 2 done**

Sprint 2 is complete when:
1. PR is open and all 7 CI checks are green.
2. `rusty-imap-mcp --config x.toml --dry-run` still prints the effective matrix and exits clean; a second concurrent `--dry-run` against the same audit path fails with an audit-lock error.
3. `rusty-imap-mcp audit merge <path>` round-trips a synthetic log on stdout.
4. Every `rimap-audit` integration test (`concurrent_lock`, `rotation`, `partial_line`, `inode_change`) passes.
5. Merging the PR is the next human action; **do not merge from the agent.**

---

## Self-review checklist (implementing engineer: do not skip)

Before marking the PR ready:

- [ ] Every file listed in the "File structure" section exists and is committed.
- [ ] `crates/rimap-core/src/audit.rs` has been deleted and `rimap-core/src/lib.rs` no longer declares `pub mod audit`.
- [ ] `git grep -nE 'TBD|FIXME|XXX|todo!\(|unimplemented!\(' -- 'crates/rimap-audit' 'crates/rimap-server'` is empty.
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` is silent.
- [ ] `cargo fmt --all -- --check` is silent.
- [ ] `cargo deny check` is silent.
- [ ] `cargo +1.85.1 check --workspace --all-targets --all-features --locked` is silent.
- [ ] `cargo test --workspace` passes including every `rimap-audit` integration test and the `audit_merge` server test.
- [ ] Two concurrent `./target/debug/rusty-imap-mcp --config <sample> --dry-run` invocations — the second exits non-zero with an "already locked" error.
- [ ] `./target/debug/rusty-imap-mcp audit merge <synthetic>` writes every record on stdout in order.
- [ ] No `println!` / `eprintln!` / `dbg!` in non-test source. `audit merge` uses `writeln!(std::io::stdout().lock(), …)` per Sprint 1 convention.
- [ ] No `AuditWriter` operations held across `.await` (Sprint 2 is synchronous throughout; this check is forward-looking).
- [ ] Every `ToolName::all()` variant has a matching entry in `redact::schemas()`.
- [ ] Property test run count (`proptest` default 256) completed for every property in `redact_properties.rs`.

---

## Dependencies and scope guardrails

- **Do not** add `async-imap`, `rmcp`, `mail-parser`, `ammonia`, or any Sprint 3–5 runtime dep.
- **Do not** implement IMAP code in `rimap-imap`. The `auth` record payload exists; Sprint 3 wires it to a real connection.
- **Do not** implement content-pipeline code in `rimap-content`.
- **Do not** implement tool handlers. Redaction schemas are declared; handlers consume them in Sprint 5.
- **Do not** wire `rmcp`. The server still rejects non-`--dry-run` invocations with a "not implemented until Sprint 5" message.
- **Do not** emit `AuditRecord::Config` from any code path — it is declared but unused until Sprint 5.
- **Do not** autonomously interpret provenance data. The ring buffer records evidence; post-hoc analysis is a v1.x follow-up per spec §10.
- **Do not** hold the audit lock across `.await`. Sprint 2's writer is synchronous; future sprints must keep this discipline (use `tokio::task::spawn_blocking` when calling from async).
- **Do not** add `#[allow(...)]` attributes — use `#[expect(..., reason = "...")]` only when absolutely necessary.
- **Do not** swallow audit write errors. Failures surface via the `AuditError` → `RimapError` boundary and ultimately as `ERR_INTERNAL`.
- **Do not** commit on `main`. All work is on `feat/sprint-2-implementation`.
- **Do not** force-push or amend commits that have been pushed to `origin`.

---

## Spec coverage matrix (self-review cross-check)

| Spec §10 requirement                                       | Task(s)          |
|------------------------------------------------------------|------------------|
| Shared header (`seq`, `ts`, `process_id`, `kind`)          | 6, 7             |
| `process_start` payload + `previous_*` fields              | 7, 14            |
| `process_end` payload                                      | 7                |
| `auth` payload                                             | 8                |
| `tool_start` payload + `arguments_redacted` + hash         | 9, 10, 11        |
| `tool_end` payload + `result_summary` + `provenance`       | 9, 13            |
| `config` payload declared                                  | 9                |
| Structural per-tool redaction (verbatim/redact/hash/deny)  | 10, 11, 12       |
| Process-lifetime salt                                      | 10               |
| Provenance ring buffer with window eviction                | 13               |
| Path creation (`0700` parent, `0600` file)                 | 15               |
| Exclusive non-blocking lock on open                        | 15, 19           |
| Lock held for process lifetime (released on drop)          | 15, 19, 20       |
| Rotation under lock preserving inode-bound flock           | 17, 20           |
| Shared-lock reader                                         | 18, 21, 26       |
| Per-record `write_all` + flush, fsync on `process_*`/`auth`| 16               |
| Audit write failure → `ERR_INTERNAL`                       | 5 (via mapping)  |
| Startup self-check (last-line read, inode comparison)      | 14, 22           |
| `audit merge` subcommand + filters + partial-line tolerance | 23, 24, 26      |
| Concurrent-process conflict exit criterion                 | 19, 25           |
| `audit merge` round-trip exit criterion                    | 26               |
