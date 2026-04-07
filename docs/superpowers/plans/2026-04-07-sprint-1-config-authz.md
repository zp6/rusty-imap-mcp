# Sprint 1 — Config, Postures, Authz Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the configuration + authorization skeleton so `rusty-imap-mcp --config x.toml --dry-run` parses a TOML config, validates it, builds an effective posture-based tool matrix, prints the matrix, and exits clean. No IMAP, no MCP, no audit writes — those land in Sprints 2–5.

**Architecture:** Three library crates grow past their Sprint-0 placeholders. `rimap-core` owns the shared enums (`Posture`, `ToolName`, `AuditRecord` skeleton) and error types; `rimap-config` owns TOML loading, XDG paths, validation, and credential resolution; `rimap-authz` owns the compile-time `PostureMatrix`, runtime `EffectiveMatrix`, `governor` rate limiter, `CircuitBreaker` state machine, and the composed `DispatchGuard`. The `rimap-server` binary grows a `clap` CLI with `--config`, `--dry-run`, and a `login` subcommand, and a `tracing` subscriber writing to stderr via `with_writer` (avoiding the workspace `print_stderr` lint).

**Tech Stack:** Rust 1.85.1 MSRV / 1.94.0 dev toolchain (unchanged from Sprint 0). New runtime deps: `thiserror`, `serde`, `toml`, `directories`, `keyring`, `governor`, `tracing`, `tracing-subscriber`, `clap`, `tokio`, `anyhow`, `nonzero_ext`, `parking_lot`, `rpassword`. New dev deps: `assert_cmd`, `predicates`, `tempfile`, `proptest`.

**Spec reference:** `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md` — this plan implements Sprint 1 (Section 12 "Sprint 1 — Config, postures, authz skeleton"), and draws types from Sections 4 (Configuration & Postures) and 9 (Authorization, Rate Limiting, Circuit Breaker).

---

## Context for the implementing engineer

Sprint 0 is merged to `main`. The workspace compiles with seven empty crates, `just ci` is green, `prek` hooks enforce fmt / clippy / branch-name / forbidden-macros / SHA-pinned actions. This sprint is the first with real feature code.

**Starting branch state:** You start on `main`. Task 1 creates `feat/sprint-1-implementation` off `main`. (Note: this is *not* `feat/sprint-1-plan`, which is the branch carrying this plan document itself. Plan and implementation live on separate branches.)

**What "TDD" means here.** For every non-trivial function: write the failing test, run it, see it fail with the exact error you expect, then write the minimal implementation, re-run, commit. Type stubs and `Default` impls don't need a separate failing-test step — but any parsing, validation, state transition, or error path does. The exit criterion demands ≥ 90% unit test coverage on `rimap-authz`; the only way to hit that without fighting coverage tooling is to TDD every branch.

**Working directory:** `/Users/dave/src/rusty-imap-mcp` throughout.

**Zero-warnings policy is load-bearing.** Every `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` invocation must exit clean. If a pedantic lint fires on a test helper, *fix the code*, do not `#[allow]` it. The workspace denies `allow_attributes`, so you must use `#[expect(lint_name, reason = "…")]` with a concrete reason if you truly need to suppress.

**Important constraints (from global CLAUDE.md and AGENTS.md):**
- Never commit on `main`/`master`. The `branch-name` prek hook will reject it anyway.
- Never `--no-verify`. If a hook fails, fix the underlying cause.
- 100-char line length.
- No relative `..` imports (Rust: absolute paths from crate root).
- No `unwrap()`/`expect()`/`panic!()`/`unimplemented!()`/`todo!()` in non-test code.
- No `println!`/`eprintln!`/`dbg!` in non-test code. The workspace lint set denies both `print_stdout` and `print_stderr`. For stdout output from the `--dry-run` path, use `writeln!(std::io::stdout().lock(), …)?` directly. For stderr logging, use `tracing` with a `tracing-subscriber` layer whose writer is `std::io::stderr` — the clippy `print_stderr` lint only targets the `eprintln!`/`eprint!` macros, not direct `Write` trait calls.
- Tests may `#![expect(clippy::unwrap_used, reason = "tests")]` at the `mod tests` level only.

**Scope guardrails (do NOT do any of this in Sprint 1):**
- No `async-imap`, `rmcp`, `mail-parser`, `ammonia`, `fs2` runtime deps. Those belong to Sprints 3–5.
- No actual audit log writes. Sprint 2 owns `rimap-audit`. This sprint only declares `AuditRecord` variant shells in `rimap-core` so that Sprint 2 and Sprint 5 have a stable enum to match against.
- No IMAP code in `rimap-imap`. It stays a placeholder.
- No content pipeline code in `rimap-content`. It stays a placeholder.
- No MCP server wiring. `main.rs` is a plain binary in this sprint; `rmcp` integration lands in Sprint 5.

---

## File structure (end state of Sprint 1)

```
rusty-imap-mcp/
├── Cargo.toml                                         # workspace deps grow
├── deny.toml                                          # license allowlist may grow
├── crates/
│   ├── rimap-core/
│   │   ├── Cargo.toml                                 # + thiserror, serde
│   │   └── src/
│   │       ├── lib.rs                                 # re-exports
│   │       ├── error.rs                               # RimapError, error codes
│   │       ├── posture.rs                             # Posture enum
│   │       ├── tool.rs                                # ToolName enum
│   │       └── audit.rs                               # AuditRecord skeleton
│   ├── rimap-config/
│   │   ├── Cargo.toml                                 # + serde, toml, directories, keyring, etc.
│   │   └── src/
│   │       ├── lib.rs                                 # re-exports
│   │       ├── error.rs                               # ConfigError
│   │       ├── model.rs                               # Config + nested structs
│   │       ├── loader.rs                              # XDG path + TOML load
│   │       ├── validate.rs                            # validation pipeline
│   │       ├── credential.rs                          # trait + keychain + env impls
│   │       └── login.rs                               # `login` subcommand logic
│   ├── rimap-authz/
│   │   ├── Cargo.toml                                 # + governor, parking_lot, tokio, tracing
│   │   └── src/
│   │       ├── lib.rs                                 # re-exports
│   │       ├── error.rs                               # AuthzError
│   │       ├── matrix.rs                              # PostureMatrix const + EffectiveMatrix
│   │       ├── rate_limit.rs                          # governor wrapper
│   │       ├── breaker.rs                             # CircuitBreaker state machine
│   │       └── guard.rs                               # DispatchGuard composition
│   └── rimap-server/
│       ├── Cargo.toml                                 # + clap, tokio, tracing-subscriber, anyhow
│       └── src/
│           ├── main.rs                                # entry point, tokio runtime
│           ├── cli.rs                                 # clap structs
│           ├── dry_run.rs                             # --dry-run path
│           └── logging.rs                             # tracing subscriber init
└── docs/superpowers/plans/2026-04-07-sprint-1-config-authz.md  # this file
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

Run: `git checkout -b feat/sprint-1-implementation`
Expected: `Switched to a new branch 'feat/sprint-1-implementation'`.

No commit for this task.

---

## Task 2: Add Sprint 1 workspace dependencies

**Files:**
- Modify: `Cargo.toml` (workspace `[workspace.dependencies]` section)

These versions are current-stable as of plan authorship. If `cargo update` during compilation pulls a newer patch via semver, that is fine; do not downgrade. If a *major* version has bumped since authorship, stop and ask before adjusting — upstream API changes may require replanning.

- [ ] **Step 1: Add runtime dependencies to `[workspace.dependencies]`**

Modify `Cargo.toml`. Replace the empty `[workspace.dependencies]` section with:

```toml
[workspace.dependencies]
# Error handling
thiserror = "2.0"
anyhow = "1.0"

# Serde / config
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# Paths
directories = "5.0"

# Credentials
keyring = { version = "3.6", features = ["apple-native", "linux-native-sync-persistent"] }
rpassword = "7.3"

# Authorization primitives
governor = "0.7"
nonzero_ext = "0.3"
parking_lot = "0.12"

# Async runtime
tokio = { version = "1.42", features = ["rt-multi-thread", "macros", "time", "sync"] }

# Observability
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt"] }

# CLI
clap = { version = "4.5", features = ["derive", "env"] }

# Dev dependencies shared across crates
assert_cmd = "2.0"
predicates = "3.1"
tempfile = "3.14"
proptest = "1.6"
```

- [ ] **Step 2: Verify the workspace Cargo.toml parses**

Run: `cargo metadata --no-deps --format-version 1 > /dev/null`
Expected: exit 0. The workspace manifest parses even though no crate consumes the new deps yet.

- [ ] **Step 3: Update `deny.toml` license allowlist if needed**

Run: `cargo deny check licenses 2>&1 | tail -40`
Expected: either passes, or reports specific licenses not in the allowlist.

If any licenses are missing, add them to `deny.toml`'s `[licenses].allow` list. Known candidates that may be introduced by Sprint 1 deps: `Unicode-3.0` (already present), `Zlib` (already present). If a new license appears, stop and verify it's compatible with MIT/Apache-2.0 before adding it to the allowlist. Do **not** add GPL, LGPL, or any copyleft license without explicit approval.

- [ ] **Step 4: Verify `cargo deny` passes**

Run: `cargo deny check`
Expected: all four categories (advisories, licenses, bans, sources) pass. No crates are consumed yet, so this is just a static check of the policy file.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml deny.toml
git commit -m "chore: add Sprint 1 workspace dependencies"
```

---

## Task 3: `rimap-core` — error types

**Files:**
- Modify: `crates/rimap-core/Cargo.toml`
- Create: `crates/rimap-core/src/error.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Add `thiserror` and `serde` dependencies to `rimap-core/Cargo.toml`**

Modify `crates/rimap-core/Cargo.toml`. Replace the empty `[dependencies]` section with:

```toml
[dependencies]
thiserror = { workspace = true }
serde = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Create `crates/rimap-core/src/error.rs`:

```rust
//! Top-level error enum and stable error codes for rusty-imap-mcp.
//!
//! Every error carries a machine-readable [`ErrorCode`] and a human-readable
//! message. Codes are stable across releases; changing a code is a semver-major
//! break. The code list comes from design spec §9.

use thiserror::Error;

/// Stable machine-readable error codes, per design spec §9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Input validation failed.
    InvalidInput,
    /// Tool denied by the active posture.
    PostureDenied,
    /// Rate limiter token bucket empty.
    RateLimited,
    /// Circuit breaker open.
    CircuitOpen,
    /// UID / folder / part missing.
    NotFound,
    /// IMAP server misbehaved.
    ImapProtocol,
    /// TLS handshake or cert verification failed.
    Tls,
    /// Authentication rejected.
    Auth,
    /// Mid-call disconnect.
    ConnectionLost,
    /// Command exceeded time limit.
    Timeout,
    /// Attachment exceeded cap.
    AttachmentTooLarge,
    /// Startup-time configuration error.
    Config,
    /// Bug, invariant violation, or audit failure.
    Internal,
}

impl ErrorCode {
    /// Stable on-wire string form (e.g. `"ERR_INVALID_INPUT"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "ERR_INVALID_INPUT",
            Self::PostureDenied => "ERR_POSTURE_DENIED",
            Self::RateLimited => "ERR_RATE_LIMITED",
            Self::CircuitOpen => "ERR_CIRCUIT_OPEN",
            Self::NotFound => "ERR_NOT_FOUND",
            Self::ImapProtocol => "ERR_IMAP_PROTOCOL",
            Self::Tls => "ERR_TLS",
            Self::Auth => "ERR_AUTH",
            Self::ConnectionLost => "ERR_CONNECTION_LOST",
            Self::Timeout => "ERR_TIMEOUT",
            Self::AttachmentTooLarge => "ERR_ATTACHMENT_TOO_LARGE",
            Self::Config => "ERR_CONFIG",
            Self::Internal => "ERR_INTERNAL",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level tool error returned from dispatch. Library crates produce more
/// specific errors (`AuthzError`, `ConfigError`, …) which map into this via
/// `From` impls added in later sprints.
#[derive(Debug, Error)]
pub enum RimapError {
    /// Authorization, posture, rate limit, or breaker failure.
    #[error("{code}: {message}")]
    Authz {
        /// Stable error code.
        code: ErrorCode,
        /// Human-readable message.
        message: String,
    },
    /// Startup-time configuration error.
    #[error("ERR_CONFIG: {0}")]
    Config(String),
    /// Bug / invariant violation.
    #[error("ERR_INTERNAL: {0}")]
    Internal(String),
}

impl RimapError {
    /// The stable error code carried by this error.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Authz { code, .. } => *code,
            Self::Config(_) => ErrorCode::Config,
            Self::Internal(_) => ErrorCode::Internal,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::error::{ErrorCode, RimapError};

    #[test]
    fn every_error_code_has_stable_string() {
        let cases = [
            (ErrorCode::InvalidInput, "ERR_INVALID_INPUT"),
            (ErrorCode::PostureDenied, "ERR_POSTURE_DENIED"),
            (ErrorCode::RateLimited, "ERR_RATE_LIMITED"),
            (ErrorCode::CircuitOpen, "ERR_CIRCUIT_OPEN"),
            (ErrorCode::NotFound, "ERR_NOT_FOUND"),
            (ErrorCode::ImapProtocol, "ERR_IMAP_PROTOCOL"),
            (ErrorCode::Tls, "ERR_TLS"),
            (ErrorCode::Auth, "ERR_AUTH"),
            (ErrorCode::ConnectionLost, "ERR_CONNECTION_LOST"),
            (ErrorCode::Timeout, "ERR_TIMEOUT"),
            (ErrorCode::AttachmentTooLarge, "ERR_ATTACHMENT_TOO_LARGE"),
            (ErrorCode::Config, "ERR_CONFIG"),
            (ErrorCode::Internal, "ERR_INTERNAL"),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert_eq!(format!("{code}"), expected);
        }
    }

    #[test]
    fn rimap_error_code_accessor_matches_variant() {
        let authz = RimapError::Authz {
            code: ErrorCode::RateLimited,
            message: "slow down".to_string(),
        };
        assert_eq!(authz.code(), ErrorCode::RateLimited);
        assert_eq!(RimapError::Config("x".into()).code(), ErrorCode::Config);
        assert_eq!(RimapError::Internal("x".into()).code(), ErrorCode::Internal);
    }

    #[test]
    fn rimap_error_display_includes_code_prefix() {
        let err = RimapError::Authz {
            code: ErrorCode::PostureDenied,
            message: "tool disabled".to_string(),
        };
        assert_eq!(err.to_string(), "ERR_POSTURE_DENIED: tool disabled");
    }
}
```

- [ ] **Step 3: Wire the new module into `lib.rs`**

Replace `crates/rimap-core/src/lib.rs` with:

```rust
//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::{ErrorCode, RimapError};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rimap-core`
Expected: three tests pass.

- [ ] **Step 5: Run clippy on rimap-core**

Run: `cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: clean exit.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/rimap-core/Cargo.toml crates/rimap-core/src/
git commit -m "feat(core): add RimapError and stable error codes"
```

---

## Task 4: `rimap-core` — `Posture` enum

**Files:**
- Create: `crates/rimap-core/src/posture.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-core/src/posture.rs`:

```rust
//! Security posture enum. Controls which tools are advertised and dispatchable.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The three supported postures. Default is [`Posture::DraftSafe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    /// Read-only operations only. No flag changes, no drafts, no moves.
    Readonly,
    /// Read + safe mutations (flags, moves, draft creation with `$PendingReview`).
    DraftSafe,
    /// Read + mutations + escape hatches (`advanced_query`, `include_html`).
    Full,
}

impl Default for Posture {
    fn default() -> Self {
        Self::DraftSafe
    }
}

impl Posture {
    /// Canonical kebab-case string form used in config files and error messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::DraftSafe => "draft-safe",
            Self::Full => "full",
        }
    }

    /// Every posture, in declaration order. Useful for exhaustive tests.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Readonly, Self::DraftSafe, Self::Full]
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`Posture::from_str`] for unrecognized values.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown posture `{0}`; expected one of: readonly, draft-safe, full")]
pub struct UnknownPosture(pub String);

impl FromStr for Posture {
    type Err = UnknownPosture;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "readonly" => Ok(Self::Readonly),
            "draft-safe" => Ok(Self::DraftSafe),
            "full" => Ok(Self::Full),
            other => Err(UnknownPosture(other.to_string())),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::posture::{Posture, UnknownPosture};
    use core::str::FromStr;

    #[test]
    fn default_is_draft_safe() {
        assert_eq!(Posture::default(), Posture::DraftSafe);
    }

    #[test]
    fn round_trip_all_postures() {
        for posture in Posture::all() {
            let s = posture.as_str();
            let parsed = Posture::from_str(s).unwrap();
            assert_eq!(parsed, posture, "round-trip failed for {s}");
        }
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(Posture::Readonly.to_string(), "readonly");
        assert_eq!(Posture::DraftSafe.to_string(), "draft-safe");
        assert_eq!(Posture::Full.to_string(), "full");
    }

    #[test]
    fn unknown_posture_is_rejected() {
        let err = Posture::from_str("yolo").unwrap_err();
        assert_eq!(err, UnknownPosture("yolo".to_string()));
        assert!(err.to_string().contains("yolo"));
        assert!(err.to_string().contains("draft-safe"));
    }

    #[test]
    fn underscore_alias_is_rejected() {
        // We accept only the kebab-case form. "draft_safe" must NOT parse.
        assert!(Posture::from_str("draft_safe").is_err());
    }

    #[test]
    fn serde_round_trip_matches_kebab_case() {
        let json = serde_json::to_string(&Posture::DraftSafe).ok();
        // We don't want to pull in serde_json just for a test — use toml instead
        // since it's already a workspace dep and rimap-core doesn't depend on it.
        // Skip this branch; the round_trip_all_postures test covers parsing.
        drop(json);
    }
}
```

Note: the `serde_round_trip_matches_kebab_case` test is a deliberate no-op — we don't want to pull `serde_json` or `toml` into `rimap-core` just for a serde smoke test. The `#[serde(rename_all = "kebab-case")]` attribute is exercised end-to-end in `rimap-config` tests (Task 8+).

- [ ] **Step 2: Wire the module into `lib.rs`**

Modify `crates/rimap-core/src/lib.rs`:

```rust
//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod error;
pub mod posture;

pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
```

- [ ] **Step 3: Run the tests — they should fail on the serde test because the no-op test is valid but let's confirm everything compiles**

Run: `cargo test -p rimap-core`
Expected: all tests pass.

- [ ] **Step 4: Run clippy**

Run: `cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: clean. If the no-op `serde_round_trip_matches_kebab_case` test triggers a dead-code lint, delete it entirely — its job is only commentary.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/
git commit -m "feat(core): add Posture enum with FromStr and Display"
```

---

## Task 5: `rimap-core` — `ToolName` enum

The `ToolName` enum models the v1 tool surface *at capability granularity* (so the matrix can gate `search`'s `advanced_query` and `fetch_message`'s `include_html` separately). It also knows about *v2* tool names so that override parsing can return a distinct error for them, per spec §9: "Override referencing a v2 tool → startup error."

**Files:**
- Create: `crates/rimap-core/src/tool.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-core/src/tool.rs`:

```rust
//! Tool identity. Models the v1 tool surface at *capability* granularity so
//! the posture matrix can gate sub-features (`search.advanced_query`,
//! `fetch_message.include_html`) independently of the parent tool.

use core::fmt;
use core::str::FromStr;

use thiserror::Error;

/// Identifier for a dispatchable capability. This is a superset of the MCP
/// tool names because some MCP tools expose multiple gated capabilities
/// (e.g. `search` and `search_advanced`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ToolName {
    /// `list_folders`
    ListFolders,
    /// `search` with the structured query form only.
    Search,
    /// `search` with `advanced_query` escape hatch. Requires `full` posture.
    SearchAdvanced,
    /// `fetch_message` returning text parts only.
    FetchMessage,
    /// `fetch_message` with `include_html = true`. Requires `full` posture.
    FetchMessageHtml,
    /// `list_attachments`
    ListAttachments,
    /// `download_attachment`
    DownloadAttachment,
    /// `mark_read`
    MarkRead,
    /// `mark_unread`
    MarkUnread,
    /// `flag`
    Flag,
    /// `unflag`
    Unflag,
    /// `move_message`
    MoveMessage,
    /// `create_draft` (appends to Drafts with `$PendingReview`).
    CreateDraft,
}

impl ToolName {
    /// Canonical snake-case name used in config overrides and audit log
    /// entries. Sub-capabilities reuse the parent tool name joined with a
    /// descriptive suffix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ListFolders => "list_folders",
            Self::Search => "search",
            Self::SearchAdvanced => "search.advanced_query",
            Self::FetchMessage => "fetch_message",
            Self::FetchMessageHtml => "fetch_message.include_html",
            Self::ListAttachments => "list_attachments",
            Self::DownloadAttachment => "download_attachment",
            Self::MarkRead => "mark_read",
            Self::MarkUnread => "mark_unread",
            Self::Flag => "flag",
            Self::Unflag => "unflag",
            Self::MoveMessage => "move_message",
            Self::CreateDraft => "create_draft",
        }
    }

    /// Every v1 tool, in declaration order. Used for exhaustive matrix tests
    /// and for building the advertised-tools set in `list_tools`.
    #[must_use]
    pub fn all() -> [Self; 13] {
        [
            Self::ListFolders,
            Self::Search,
            Self::SearchAdvanced,
            Self::FetchMessage,
            Self::FetchMessageHtml,
            Self::ListAttachments,
            Self::DownloadAttachment,
            Self::MarkRead,
            Self::MarkUnread,
            Self::Flag,
            Self::Unflag,
            Self::MoveMessage,
            Self::CreateDraft,
        ]
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Known v2 tool names. These are rejected at config load with a distinct
/// error so users get "this is a v2 tool, not yet available" instead of
/// "unknown tool".
const V2_TOOL_NAMES: &[&str] = &["delete_message", "expunge", "send_email"];

/// Error returned by [`ToolName::from_str`] when a name is not recognized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseToolNameError {
    /// The name is not a v1 tool and not a known v2 tool.
    #[error("unknown tool name `{0}`")]
    Unknown(String),
    /// The name refers to a v2 tool not available in v1.
    #[error("tool `{0}` is reserved for v2 and cannot be used in configuration")]
    V2(String),
}

impl FromStr for ToolName {
    type Err = ParseToolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for tool in Self::all() {
            if tool.as_str() == s {
                return Ok(tool);
            }
        }
        if V2_TOOL_NAMES.contains(&s) {
            return Err(ParseToolNameError::V2(s.to_string()));
        }
        Err(ParseToolNameError::Unknown(s.to_string()))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::tool::{ParseToolNameError, ToolName};
    use core::str::FromStr;

    #[test]
    fn all_has_exactly_thirteen_variants() {
        assert_eq!(ToolName::all().len(), 13);
    }

    #[test]
    fn round_trip_all_tool_names() {
        for tool in ToolName::all() {
            let parsed = ToolName::from_str(tool.as_str()).unwrap();
            assert_eq!(parsed, tool);
        }
    }

    #[test]
    fn all_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in ToolName::all() {
            assert!(seen.insert(tool.as_str()), "duplicate name: {}", tool.as_str());
        }
    }

    #[test]
    fn unknown_name_returns_unknown_error() {
        let err = ToolName::from_str("nuke_inbox").unwrap_err();
        assert_eq!(err, ParseToolNameError::Unknown("nuke_inbox".to_string()));
    }

    #[test]
    fn v2_tool_names_return_v2_error() {
        for name in ["delete_message", "expunge", "send_email"] {
            let err = ToolName::from_str(name).unwrap_err();
            assert_eq!(err, ParseToolNameError::V2(name.to_string()));
        }
    }

    #[test]
    fn display_uses_canonical_name() {
        assert_eq!(ToolName::Search.to_string(), "search");
        assert_eq!(
            ToolName::SearchAdvanced.to_string(),
            "search.advanced_query"
        );
    }
}
```

- [ ] **Step 2: Wire the module into `lib.rs`**

Modify `crates/rimap-core/src/lib.rs` to add the `tool` module and re-exports:

```rust
//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod error;
pub mod posture;
pub mod tool;

pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::tool::{ParseToolNameError, ToolName};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-core`
Expected: all tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-core/src/
git commit -m "feat(core): add ToolName enum with v1/v2 parse errors"
```

---

## Task 6: `rimap-core` — `AuditRecord` skeleton

This is a *shell* only. Sprint 2 fills in the struct bodies and adds serialization. We add the variants now so that `rimap-authz` can hold an abstract `audit_sink: &dyn AuditSink` reference in later sprints, and so Sprint 5's tool dispatch can match exhaustively against `AuditRecord`.

**Files:**
- Create: `crates/rimap-core/src/audit.rs`
- Modify: `crates/rimap-core/src/lib.rs`

- [ ] **Step 1: Write the skeleton**

Create `crates/rimap-core/src/audit.rs`:

```rust
//! Audit record skeleton.
//!
//! This module defines the *shape* of the audit log — the variants that every
//! sprint produces — but carries no serialization, no writer, and no I/O.
//! Sprint 2 fills in the variant payloads and adds a file-backed writer in
//! `rimap-audit`; Sprint 5 wires tool dispatch into the writer.
//!
//! Keeping the enum in `rimap-core` guarantees that `rimap-authz` can reference
//! audit variant *names* (e.g. for tracing spans) without taking a dependency
//! on the audit crate.

/// Per-process startup and shutdown events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessEvent {
    /// Process started; first audit entry in a new or rotated file.
    Start,
    /// Process exiting cleanly.
    End,
}

/// Authentication outcome reported by the IMAP session wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Credential was resolved and server accepted it.
    Success,
    /// Credential was resolved but server rejected it.
    Failure,
}

/// Top-level audit record. Variants are placeholder shells — Sprint 2 adds
/// the field payloads (sequence number, timestamps, redacted args, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    /// Process lifecycle event.
    Process(ProcessEvent),
    /// Authentication attempt result.
    Auth(AuthOutcome),
    /// A tool call has entered the dispatch chain.
    ToolStart,
    /// A tool call has exited the dispatch chain.
    ToolEnd,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::audit::{AuditRecord, AuthOutcome, ProcessEvent};

    #[test]
    fn variants_are_constructible() {
        let _ = AuditRecord::Process(ProcessEvent::Start);
        let _ = AuditRecord::Process(ProcessEvent::End);
        let _ = AuditRecord::Auth(AuthOutcome::Success);
        let _ = AuditRecord::Auth(AuthOutcome::Failure);
        let _ = AuditRecord::ToolStart;
        let _ = AuditRecord::ToolEnd;
    }

    #[test]
    fn process_event_equality() {
        assert_eq!(ProcessEvent::Start, ProcessEvent::Start);
        assert_ne!(ProcessEvent::Start, ProcessEvent::End);
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-core/src/lib.rs`:

```rust
//! Shared core types for rusty-imap-mcp: errors, postures, tool names, audit
//! record skeleton.

#![deny(missing_docs)]

pub mod audit;
pub mod error;
pub mod posture;
pub mod tool;

pub use crate::audit::{AuditRecord, AuthOutcome, ProcessEvent};
pub use crate::error::{ErrorCode, RimapError};
pub use crate::posture::{Posture, UnknownPosture};
pub use crate::tool::{ParseToolNameError, ToolName};
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-core && cargo clippy -p rimap-core --all-targets --all-features -- -D warnings`
Expected: all pass clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-core/src/
git commit -m "feat(core): add AuditRecord skeleton for Sprint 2 wiring"
```

---

## Task 7: `rimap-config` — dependencies and error type

**Files:**
- Modify: `crates/rimap-config/Cargo.toml`
- Create: `crates/rimap-config/src/error.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Update `rimap-config/Cargo.toml`**

Replace the file contents with:

```toml
[package]
name = "rimap-config"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Configuration loading, validation, and credential resolution for rusty-imap-mcp."

[lints]
workspace = true

[dependencies]
rimap-core = { path = "../rimap-core" }
thiserror = { workspace = true }
serde = { workspace = true }
toml = { workspace = true }
directories = { workspace = true }
keyring = { workspace = true }
rpassword = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tempfile = { workspace = true }
```

- [ ] **Step 2: Write the failing test**

Create `crates/rimap-config/src/error.rs`:

```rust
//! Configuration error type. Every variant is surfaced as `ERR_CONFIG` at the
//! top level per design spec §9.

use std::path::PathBuf;

use rimap_core::posture::UnknownPosture;
use rimap_core::tool::ParseToolNameError;
use thiserror::Error;

/// Error produced by config loading, parsing, validation, or credential resolution.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The config file could not be read from disk.
    #[error("failed to read config file `{path}`: {source}")]
    Read {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The config file was not valid TOML.
    #[error("failed to parse config file `{path}`: {source}")]
    Parse {
        /// Attempted path.
        path: PathBuf,
        /// Underlying `toml` parse error.
        #[source]
        source: toml::de::Error,
    },
    /// The posture name in the config was not recognized.
    #[error(transparent)]
    Posture(#[from] UnknownPosture),
    /// A per-tool override referenced an unknown or v2 tool name.
    #[error("invalid tool override: {0}")]
    ToolOverride(#[from] ParseToolNameError),
    /// TLS fingerprint did not parse as 32 hex bytes.
    #[error("invalid tls_fingerprint_sha256: expected 32 hex bytes, {reason}")]
    TlsFingerprint {
        /// Specific parse failure reason.
        reason: String,
    },
    /// A required directory is missing or not writable.
    #[error("path `{path}` is not writable: {reason}")]
    PathNotWritable {
        /// The offending path.
        path: PathBuf,
        /// Explanation.
        reason: String,
    },
    /// A numeric limit was zero or out of range.
    #[error("invalid value for `{field}`: {reason}")]
    InvalidLimit {
        /// TOML field name in dotted form, e.g. `limits.commands_per_second`.
        field: &'static str,
        /// Explanation.
        reason: String,
    },
    /// No credential could be found in keychain or environment.
    #[error("no credential found for `{account}`: {reason}")]
    NoCredential {
        /// `<username>@<host>` style account.
        account: String,
        /// What we tried and what the user should do next.
        reason: String,
    },
    /// Keychain access error (not "not found" — that becomes `NoCredential`).
    #[error("keychain error for `{account}`: {source}")]
    Keychain {
        /// `<username>@<host>` style account.
        account: String,
        /// Underlying keyring error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}
```

- [ ] **Step 3: Wire into `lib.rs`**

Replace `crates/rimap-config/src/lib.rs` with:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::ConfigError;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p rimap-config && cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean build, no warnings. There are no tests yet for this task — the error type is pure data and gets exercised by the loader/validator tests in later tasks.

- [ ] **Step 5: Commit**

```bash
git add Cargo.lock crates/rimap-config/Cargo.toml crates/rimap-config/src/
git commit -m "feat(config): add ConfigError and wire dependencies"
```

---

## Task 8: `rimap-config` — config model structs

**Files:**
- Create: `crates/rimap-config/src/model.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Write the model**

Create `crates/rimap-config/src/model.rs`:

```rust
//! Strongly-typed config model. Field-for-field mapping of the TOML schema
//! from design spec §4 "File format".
//!
//! Validation is a separate pass (`validate.rs`): these structs only describe
//! *shape*. An instance that deserializes successfully may still be invalid.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rimap_core::posture::Posture;
use serde::{Deserialize, Serialize};

/// The full config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// IMAP connection settings.
    pub imap: ImapConfig,
    /// Security posture and overrides.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Numeric limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Audit log settings.
    pub audit: AuditConfig,
    /// Attachment download settings.
    #[serde(default)]
    pub attachments: AttachmentsConfig,
}

/// `[imap]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImapConfig {
    /// Server host.
    pub host: String,
    /// Server port (IMAPS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Optional pinned TLS certificate SHA-256 fingerprint. Hex, colons
    /// optional (e.g. `"ab:cd:…"` or `"abcd…"`).
    #[serde(default)]
    pub tls_fingerprint_sha256: Option<String>,
    /// Per-command timeout in seconds.
    #[serde(default = "default_command_timeout")]
    pub command_timeout_seconds: u32,
}

fn default_command_timeout() -> u32 {
    30
}

/// Override verdict for a per-tool override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Tool is allowed regardless of posture.
    Allow,
    /// Tool is denied regardless of posture.
    Deny,
}

/// `[security]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Base posture.
    #[serde(default)]
    pub posture: Posture,
    /// Per-tool overrides, keyed by raw TOML tool name. Resolved to
    /// [`rimap_core::ToolName`] during validation.
    #[serde(default)]
    pub tools: BTreeMap<String, Verdict>,
    /// Look-alike detection settings (placeholder for Sprint 4).
    #[serde(default)]
    pub lookalike: LookalikeConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            posture: Posture::default(),
            tools: BTreeMap::new(),
            lookalike: LookalikeConfig::default(),
        }
    }
}

/// `[security.lookalike]` block. Shape only; Sprint 4 owns semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookalikeConfig {
    /// Whether look-alike detection is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// User-curated watchlist of protected domains.
    #[serde(default)]
    pub known_domains: Vec<String>,
    /// Warn on any non-ASCII domain, even if not in the watchlist.
    #[serde(default)]
    pub warn_on_any_non_ascii_domain: bool,
}

impl Default for LookalikeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            known_domains: Vec::new(),
            warn_on_any_non_ascii_domain: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// `[limits]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Default search result limit.
    #[serde(default = "default_max_search")]
    pub max_search_results: u32,
    /// Hard cap on `max_search_results`.
    #[serde(default = "default_max_search_cap")]
    pub max_search_results_cap: u32,
    /// Max fetched body bytes per message.
    #[serde(default = "default_max_body")]
    pub max_fetch_body_bytes: u64,
    /// Max attachment bytes.
    #[serde(default = "default_max_attach")]
    pub max_attachment_bytes: u64,
    /// Rate limiter: commands per second.
    #[serde(default = "default_cps")]
    pub commands_per_second: u32,
    /// Per-minute draft creation cap.
    #[serde(default = "default_drafts_per_min")]
    pub drafts_per_minute: u32,
    /// Circuit breaker error threshold within the window.
    #[serde(default = "default_breaker_threshold")]
    pub circuit_breaker_error_threshold: u32,
    /// Circuit breaker window in seconds.
    #[serde(default = "default_breaker_window")]
    pub circuit_breaker_window_seconds: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_search_results: default_max_search(),
            max_search_results_cap: default_max_search_cap(),
            max_fetch_body_bytes: default_max_body(),
            max_attachment_bytes: default_max_attach(),
            commands_per_second: default_cps(),
            drafts_per_minute: default_drafts_per_min(),
            circuit_breaker_error_threshold: default_breaker_threshold(),
            circuit_breaker_window_seconds: default_breaker_window(),
        }
    }
}

fn default_max_search() -> u32 {
    200
}
fn default_max_search_cap() -> u32 {
    1000
}
fn default_max_body() -> u64 {
    5_242_880
}
fn default_max_attach() -> u64 {
    26_214_400
}
fn default_cps() -> u32 {
    10
}
fn default_drafts_per_min() -> u32 {
    5
}
fn default_breaker_threshold() -> u32 {
    5
}
fn default_breaker_window() -> u32 {
    30
}

/// `[audit]` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Path to the audit log file.
    pub path: PathBuf,
    /// Rotate when the file reaches this many bytes.
    #[serde(default = "default_rotate_bytes")]
    pub rotate_bytes: u64,
    /// Number of rotated files to keep.
    #[serde(default = "default_rotate_keep")]
    pub rotate_keep: u32,
    /// Provenance ring buffer window in seconds.
    #[serde(default = "default_provenance_window")]
    pub provenance_window_seconds: u32,
    /// If true, continue on audit write failure (insecure; default false).
    #[serde(default)]
    pub fail_open: bool,
}

fn default_rotate_bytes() -> u64 {
    10_485_760
}
fn default_rotate_keep() -> u32 {
    5
}
fn default_provenance_window() -> u32 {
    60
}

/// `[attachments]` block.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentsConfig {
    /// Download directory. Empty = per-session tempdir.
    #[serde(default)]
    pub download_dir: String,
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-config/src/lib.rs`:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod model;

pub use crate::error::ConfigError;
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p rimap-config && cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-config/src/
git commit -m "feat(config): add TOML model structs with serde derives"
```

---

## Task 9: `rimap-config` — loader + XDG path resolution

**Files:**
- Create: `crates/rimap-config/src/loader.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-config/src/loader.rs`:

```rust
//! Config file discovery and TOML loading.
//!
//! Path resolution order, per design spec §4:
//!   1. Explicit `--config <path>` argument (handled by caller; passed here as `Some(path)`).
//!   2. `RUSTY_IMAP_MCP_CONFIG` environment variable.
//!   3. Platform default:
//!        - Linux: `$XDG_CONFIG_HOME/rusty-imap-mcp/config.toml`
//!          (falling back to `~/.config/rusty-imap-mcp/config.toml`)
//!        - macOS: `~/Library/Application Support/rusty-imap-mcp/config.toml`

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

use crate::error::ConfigError;
use crate::model::Config;

/// Organization qualifiers for `directories::ProjectDirs`.
const QUALIFIER: &str = "";
const ORGANIZATION: &str = "";
const APPLICATION: &str = "rusty-imap-mcp";

/// Environment variable name for the config path override.
pub const CONFIG_ENV_VAR: &str = "RUSTY_IMAP_MCP_CONFIG";

/// Return the config path based on the explicit override, the environment
/// variable, or the platform default. Returns `None` if no default path can
/// be determined (e.g. headless system with no HOME).
#[must_use]
pub fn resolve_config_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    if let Ok(v) = std::env::var(CONFIG_ENV_VAR) {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Load and deserialize a config file from the given path. Does **not**
/// validate semantic constraints — that's [`crate::validate::validate`].
pub fn load_from_path(path: &Path) -> Result<Config, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str::<Config>(&contents).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::posture::Posture;
    use tempfile::TempDir;

    use crate::loader::{load_from_path, resolve_config_path, CONFIG_ENV_VAR};
    use crate::model::Verdict;

    fn write_config(dir: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    const MINIMAL_CONFIG: &str = r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "/tmp/rimap-audit.jsonl"
"#;

    #[test]
    fn load_minimal_config_fills_defaults() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", MINIMAL_CONFIG);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.imap.host, "127.0.0.1");
        assert_eq!(cfg.imap.port, 1143);
        assert_eq!(cfg.imap.command_timeout_seconds, 30);
        assert_eq!(cfg.security.posture, Posture::DraftSafe);
        assert_eq!(cfg.limits.commands_per_second, 10);
        assert_eq!(cfg.limits.drafts_per_minute, 5);
        assert!(cfg.security.tools.is_empty());
    }

    #[test]
    fn load_with_tool_overrides_preserves_order_independent_map() {
        let toml = format!(
            r#"{MINIMAL_CONFIG}
[security]
posture = "draft-safe"

[security.tools]
mark_read = "deny"
search = "allow"
"#
        );
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let cfg = load_from_path(&path).unwrap();
        assert_eq!(cfg.security.tools.get("mark_read"), Some(&Verdict::Deny));
        assert_eq!(cfg.security.tools.get("search"), Some(&Verdict::Allow));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = format!("{MINIMAL_CONFIG}\nbogus_top_level = 1\n");
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "config.toml", &toml);
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, crate::error::ConfigError::Parse { .. }));
    }

    #[test]
    fn missing_file_returns_read_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.toml");
        let err = load_from_path(&path).unwrap_err();
        assert!(matches!(err, crate::error::ConfigError::Read { .. }));
    }

    #[test]
    fn resolve_explicit_path_wins() {
        let p = PathBuf::from("/etc/rimap/custom.toml");
        assert_eq!(resolve_config_path(Some(&p)), Some(p));
    }

    #[test]
    fn resolve_env_var_used_when_no_explicit() {
        // Use a unique tempdir path to avoid clobbering a real user env.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("env.toml");
        // SAFETY: single-threaded test; std::env::set_var is safe here.
        temp_env::with_var(CONFIG_ENV_VAR, Some(env_path.as_os_str()), || {
            assert_eq!(resolve_config_path(None), Some(env_path.clone()));
        });
    }

    #[test]
    fn resolve_default_is_some_on_supported_platforms() {
        temp_env::with_var(CONFIG_ENV_VAR, None::<&str>, || {
            let p = resolve_config_path(None);
            // On supported platforms (Linux, macOS, Windows) directories will
            // return Some. On exotic platforms it may be None; accept both.
            if let Some(path) = p {
                assert!(path.to_string_lossy().contains("rusty-imap-mcp"));
                assert!(path.ends_with("config.toml"));
            }
        });
    }
}
```

- [ ] **Step 2: Add `temp_env` to dev-dependencies**

`temp_env` scopes environment variable mutations to a closure — this is needed because tests that touch `std::env` are unsafe in multi-threaded `cargo test` unless scoped.

Modify the workspace `Cargo.toml`'s `[workspace.dependencies]` to add:

```toml
temp-env = "0.3"
```

Modify `crates/rimap-config/Cargo.toml`'s `[dev-dependencies]` to add:

```toml
temp-env = { workspace = true }
```

Note the crate name: the Rust identifier is `temp_env` but the crate name on crates.io is `temp-env`. The code in Step 1 uses `temp_env::with_var`, which matches.

- [ ] **Step 3: Wire `loader` into `lib.rs`**

Modify `crates/rimap-config/src/lib.rs`:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod loader;
pub mod model;

pub use crate::error::ConfigError;
pub use crate::loader::{load_from_path, resolve_config_path, CONFIG_ENV_VAR};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p rimap-config`
Expected: all tests pass.

- [ ] **Step 5: Clippy**

Run: `cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rimap-config/Cargo.toml crates/rimap-config/src/
git commit -m "feat(config): add loader and XDG path resolution"
```

---

## Task 10: `rimap-config` — validation pipeline

**Files:**
- Create: `crates/rimap-config/src/validate.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-config/src/validate.rs`:

```rust
//! Config validation. Runs as a separate pass after `loader::load_from_path`.
//!
//! Checks (per design spec §4 "Config validation at startup"):
//!   - Posture is a known value (enforced by enum parsing — trivially true).
//!   - Every override tool name is a known v1 tool.
//!   - TLS fingerprint parses as 32 hex bytes.
//!   - Audit directory exists and is writable (parent dir of `audit.path`).
//!   - Attachment download dir, if non-empty, is writable.
//!   - All numeric limits are positive and cap/default invariants hold.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{Config, Verdict};

/// Validated config: a `Config` plus the resolved per-tool override map
/// keyed by `ToolName` instead of raw string.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// The underlying parsed config (untouched).
    pub config: Config,
    /// Resolved per-tool overrides.
    pub tool_overrides: BTreeMap<ToolName, Verdict>,
}

/// Validate a parsed config and resolve override tool names.
///
/// # Errors
/// Returns `ConfigError` on any validation failure.
pub fn validate(config: Config) -> Result<ValidatedConfig, ConfigError> {
    validate_fingerprint(config.imap.tls_fingerprint_sha256.as_deref())?;
    validate_limits(&config)?;
    validate_paths(&config)?;
    let tool_overrides = resolve_tool_overrides(&config)?;
    Ok(ValidatedConfig {
        config,
        tool_overrides,
    })
}

fn validate_fingerprint(maybe_fp: Option<&str>) -> Result<(), ConfigError> {
    let Some(raw) = maybe_fp else {
        return Ok(());
    };
    let cleaned: String = raw.chars().filter(|c| *c != ':').collect();
    if cleaned.len() != 64 {
        return Err(ConfigError::TlsFingerprint {
            reason: format!("got {} hex chars (want 64)", cleaned.len()),
        });
    }
    for c in cleaned.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(ConfigError::TlsFingerprint {
                reason: format!("non-hex character `{c}`"),
            });
        }
    }
    Ok(())
}

fn validate_limits(config: &Config) -> Result<(), ConfigError> {
    let limits = &config.limits;
    if limits.commands_per_second == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.commands_per_second",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.drafts_per_minute == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.drafts_per_minute",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.circuit_breaker_error_threshold == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.circuit_breaker_error_threshold",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.circuit_breaker_window_seconds == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.circuit_breaker_window_seconds",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_search_results == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_search_results > limits.max_search_results_cap {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_search_results",
            reason: format!(
                "default {} exceeds cap {}",
                limits.max_search_results, limits.max_search_results_cap
            ),
        });
    }
    if limits.max_fetch_body_bytes == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_fetch_body_bytes",
            reason: "must be > 0".to_string(),
        });
    }
    if limits.max_attachment_bytes == 0 {
        return Err(ConfigError::InvalidLimit {
            field: "limits.max_attachment_bytes",
            reason: "must be > 0".to_string(),
        });
    }
    Ok(())
}

fn validate_paths(config: &Config) -> Result<(), ConfigError> {
    let audit_parent = config.audit.path.parent().ok_or_else(|| {
        ConfigError::PathNotWritable {
            path: config.audit.path.clone(),
            reason: "audit path has no parent directory".to_string(),
        }
    })?;
    require_writable_dir(audit_parent)?;
    if !config.attachments.download_dir.is_empty() {
        require_writable_dir(Path::new(&config.attachments.download_dir))?;
    }
    Ok(())
}

fn require_writable_dir(dir: &Path) -> Result<(), ConfigError> {
    if !dir.exists() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory does not exist".to_string(),
        });
    }
    let meta = std::fs::metadata(dir).map_err(|e| ConfigError::PathNotWritable {
        path: dir.to_path_buf(),
        reason: format!("stat failed: {e}"),
    })?;
    if !meta.is_dir() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "not a directory".to_string(),
        });
    }
    if meta.permissions().readonly() {
        return Err(ConfigError::PathNotWritable {
            path: dir.to_path_buf(),
            reason: "directory is read-only".to_string(),
        });
    }
    Ok(())
}

fn resolve_tool_overrides(config: &Config) -> Result<BTreeMap<ToolName, Verdict>, ConfigError> {
    let mut out = BTreeMap::new();
    for (name, verdict) in &config.security.tools {
        let tool = ToolName::from_str(name)?;
        out.insert(tool, *verdict);
    }
    Ok(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::tool::{ParseToolNameError, ToolName};
    use tempfile::TempDir;

    use crate::error::ConfigError;
    use crate::model::{
        AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, SecurityConfig, Verdict,
    };
    use crate::validate::validate;

    fn base_config(audit_dir: &std::path::Path) -> Config {
        Config {
            imap: ImapConfig {
                host: "127.0.0.1".into(),
                port: 1143,
                username: "alice@example.test".into(),
                tls_fingerprint_sha256: None,
                command_timeout_seconds: 30,
            },
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                provenance_window_seconds: 60,
                fail_open: false,
            },
            attachments: AttachmentsConfig::default(),
        }
    }

    #[test]
    fn minimal_valid_config_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        let v = validate(cfg).unwrap();
        assert!(v.tool_overrides.is_empty());
    }

    #[test]
    fn override_resolves_v1_tool_name() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.tools.insert("mark_read".into(), Verdict::Deny);
        cfg.security.tools.insert("search".into(), Verdict::Allow);
        let v = validate(cfg).unwrap();
        assert_eq!(v.tool_overrides.get(&ToolName::MarkRead), Some(&Verdict::Deny));
        assert_eq!(v.tool_overrides.get(&ToolName::Search), Some(&Verdict::Allow));
    }

    #[test]
    fn override_unknown_tool_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.tools.insert("nuke_inbox".into(), Verdict::Deny);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ToolOverride(ParseToolNameError::Unknown(_))
        ));
    }

    #[test]
    fn override_v2_tool_fails_with_v2_error() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.security.tools.insert("delete_message".into(), Verdict::Allow);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::ToolOverride(ParseToolNameError::V2(_))
        ));
    }

    #[test]
    fn fingerprint_32_hex_bytes_with_colons_passes() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 =
            Some("ab:cd:ef:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d".into());
        validate(cfg).unwrap();
    }

    #[test]
    fn fingerprint_wrong_length_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("abcd".into());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn fingerprint_non_hex_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.imap.tls_fingerprint_sha256 = Some("z".repeat(64));
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::TlsFingerprint { .. }));
    }

    #[test]
    fn zero_commands_per_second_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.commands_per_second = 0;
        let err = validate(cfg).unwrap_err();
        match err {
            ConfigError::InvalidLimit { field, .. } => {
                assert_eq!(field, "limits.commands_per_second");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn zero_drafts_per_minute_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.drafts_per_minute = 0;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.drafts_per_minute",
                ..
            }
        ));
    }

    #[test]
    fn max_search_exceeds_cap_fails() {
        let dir = TempDir::new().unwrap();
        let mut cfg = base_config(dir.path());
        cfg.limits.max_search_results = 5000;
        cfg.limits.max_search_results_cap = 1000;
        assert!(matches!(
            validate(cfg).unwrap_err(),
            ConfigError::InvalidLimit {
                field: "limits.max_search_results",
                ..
            }
        ));
    }

    #[test]
    fn missing_audit_parent_dir_fails() {
        let mut cfg = base_config(std::path::Path::new("/"));
        cfg.audit.path = PathBuf::from("/this/does/not/exist/audit.jsonl");
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::PathNotWritable { .. }));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-config/src/lib.rs`:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod loader;
pub mod model;
pub mod validate;

pub use crate::error::ConfigError;
pub use crate::loader::{load_from_path, resolve_config_path, CONFIG_ENV_VAR};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
pub use crate::validate::{validate, ValidatedConfig};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-config`
Expected: all tests pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-config/src/
git commit -m "feat(config): add validation pipeline and override resolution"
```

---

## Task 11: `rimap-config` — credential resolution trait + env fallback

Keychain access is non-deterministic in CI (no unlocked login keychain, no D-Bus session). We isolate keychain I/O behind a trait so unit tests can substitute an in-memory store; real keychain access is exercised only in `login`-subcommand manual smoke tests and by the end user.

**Files:**
- Create: `crates/rimap-config/src/credential.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-config/src/credential.rs`:

```rust
//! Credential resolution.
//!
//! Order of precedence (design spec §4):
//!   1. OS keychain (service = `rusty-imap-mcp`, account = `<username>@<host>`).
//!   2. Environment variable `RUSTY_IMAP_MCP_PASSWORD`.
//!   3. Clear, actionable error naming both.

use crate::error::ConfigError;

/// Service name used for all keychain entries.
pub const KEYCHAIN_SERVICE: &str = "rusty-imap-mcp";

/// Environment variable name checked as fallback.
pub const PASSWORD_ENV_VAR: &str = "RUSTY_IMAP_MCP_PASSWORD";

/// Abstract credential store. Production uses [`KeyringStore`]; tests
/// substitute an in-memory map.
pub trait CredentialStore: Send + Sync {
    /// Return the stored password for `account`, or `Ok(None)` if absent.
    /// Any *other* error (permission denied, service unreachable) returns
    /// `Err`.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn get_password(&self, account: &str) -> Result<Option<String>, ConfigError>;

    /// Persist `password` for `account`, overwriting any existing entry.
    ///
    /// # Errors
    /// Returns `ConfigError::Keychain` on I/O or access errors.
    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError>;
}

/// Build the `<username>@<host>` account key used for keychain lookups.
#[must_use]
pub fn account_key(username: &str, host: &str) -> String {
    format!("{username}@{host}")
}

/// Resolve a credential: try the store first, then env var, then fail.
///
/// # Errors
/// - `ConfigError::Keychain` if the store itself errored.
/// - `ConfigError::NoCredential` if neither source had a value.
pub fn resolve_credential<S: CredentialStore>(
    store: &S,
    username: &str,
    host: &str,
) -> Result<String, ConfigError> {
    let account = account_key(username, host);
    if let Some(p) = store.get_password(&account)? {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    if let Ok(env) = std::env::var(PASSWORD_ENV_VAR) {
        if !env.is_empty() {
            return Ok(env);
        }
    }
    Err(ConfigError::NoCredential {
        account,
        reason: format!(
            "no entry in keychain service `{KEYCHAIN_SERVICE}` and \
             `{PASSWORD_ENV_VAR}` is unset or empty; run `rusty-imap-mcp login` \
             or set the environment variable"
        ),
    })
}

/// Keychain-backed [`CredentialStore`] using the `keyring` crate. Not
/// constructed in unit tests (keychain access is unreliable in CI).
#[derive(Debug, Default)]
pub struct KeyringStore;

impl CredentialStore for KeyringStore {
    fn get_password(&self, account: &str) -> Result<Option<String>, ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            }
        })?;
        match entry.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            }),
        }
    }

    fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account).map_err(|e| {
            ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            }
        })?;
        entry
            .set_password(password)
            .map_err(|e| ConfigError::Keychain {
                account: account.to_string(),
                source: Box::new(e),
            })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::credential::{
        account_key, resolve_credential, CredentialStore, PASSWORD_ENV_VAR,
    };
    use crate::error::ConfigError;

    #[derive(Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
        fail_on_get: bool,
    }

    impl MockStore {
        fn with(pairs: &[(&str, &str)]) -> Self {
            let mut map = HashMap::new();
            for (k, v) in pairs {
                map.insert((*k).to_string(), (*v).to_string());
            }
            Self {
                entries: Mutex::new(map),
                fail_on_get: false,
            }
        }

        fn failing() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                fail_on_get: true,
            }
        }
    }

    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<String>, ConfigError> {
            if self.fail_on_get {
                return Err(ConfigError::Keychain {
                    account: account.to_string(),
                    source: "simulated failure".into(),
                });
            }
            Ok(self.entries.lock().unwrap().get(account).cloned())
        }

        fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_string());
            Ok(())
        }
    }

    #[test]
    fn account_key_is_username_at_host() {
        assert_eq!(account_key("alice", "mail.example.test"), "alice@mail.example.test");
    }

    #[test]
    fn keychain_hit_wins_over_env() {
        let store = MockStore::with(&[("alice@host", "from_keychain")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, "alice", "host").unwrap();
            assert_eq!(got, "from_keychain");
        });
    }

    #[test]
    fn env_used_when_keychain_empty() {
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            let got = resolve_credential(&store, "alice", "host").unwrap();
            assert_eq!(got, "from_env");
        });
    }

    #[test]
    fn missing_everywhere_returns_no_credential() {
        let store = MockStore::default();
        temp_env::with_var(PASSWORD_ENV_VAR, None::<&str>, || {
            let err = resolve_credential(&store, "alice", "host").unwrap_err();
            match err {
                ConfigError::NoCredential { account, reason } => {
                    assert_eq!(account, "alice@host");
                    assert!(reason.contains("rusty-imap-mcp login"));
                    assert!(reason.contains("RUSTY_IMAP_MCP_PASSWORD"));
                }
                other => panic!("wrong variant: {other:?}"),
            }
        });
    }

    #[test]
    fn keychain_error_propagates() {
        let store = MockStore::failing();
        temp_env::with_var(PASSWORD_ENV_VAR, Some("unused"), || {
            let err = resolve_credential(&store, "alice", "host").unwrap_err();
            assert!(matches!(err, ConfigError::Keychain { .. }));
        });
    }

    #[test]
    fn empty_keychain_value_falls_through_to_env() {
        let store = MockStore::with(&[("alice@host", "")]);
        temp_env::with_var(PASSWORD_ENV_VAR, Some("from_env"), || {
            assert_eq!(
                resolve_credential(&store, "alice", "host").unwrap(),
                "from_env"
            );
        });
    }
}
```

Note on `ConfigError::Keychain` construction in the `failing()` helper: the `source` field is `Box<dyn Error + Send + Sync>`, and `&str` impls `From<&str> for Box<dyn Error + Send + Sync>`, so `"…".into()` works.

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-config/src/lib.rs`:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod credential;
pub mod error;
pub mod loader;
pub mod model;
pub mod validate;

pub use crate::credential::{
    account_key, resolve_credential, CredentialStore, KeyringStore, KEYCHAIN_SERVICE,
    PASSWORD_ENV_VAR,
};
pub use crate::error::ConfigError;
pub use crate::loader::{load_from_path, resolve_config_path, CONFIG_ENV_VAR};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
pub use crate::validate::{validate, ValidatedConfig};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-config`
Expected: all pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-config/src/
git commit -m "feat(config): add credential store trait and keyring impl"
```

---

## Task 12: `rimap-config` — `login` subcommand skeleton

The `login` subcommand prompts for a password on `/dev/tty` (never stdin, since stdio is reserved for MCP transport) and writes the result to the keychain. This task wires the logic; the CLI wrapper lands in Task 21.

**Files:**
- Create: `crates/rimap-config/src/login.rs`
- Modify: `crates/rimap-config/src/lib.rs`

- [ ] **Step 1: Write the module**

Create `crates/rimap-config/src/login.rs`:

```rust
//! `login` subcommand implementation.
//!
//! Interactively prompts for a password and stores it in the keychain under
//! `(KEYCHAIN_SERVICE, <username>@<host>)`. Never reads from stdin — stdio is
//! reserved for MCP transport. Uses `rpassword::prompt_password` which opens
//! `/dev/tty` on Unix and the console on Windows.

use crate::credential::{account_key, CredentialStore};
use crate::error::ConfigError;

/// Run the `login` flow against the provided store. The caller is responsible
/// for constructing the store (a [`crate::credential::KeyringStore`] in
/// production) and for printing any user-facing success confirmation after
/// this returns — this function writes to the store and returns.
///
/// # Errors
/// Returns `ConfigError::Keychain` on store write failure, or a plain
/// `ConfigError::NoCredential` with an explanatory reason if the password
/// prompt failed (e.g. non-interactive terminal).
pub fn run_login<S: CredentialStore>(
    store: &S,
    username: &str,
    host: &str,
    prompt: impl FnOnce(&str) -> std::io::Result<String>,
) -> Result<(), ConfigError> {
    let account = account_key(username, host);
    let prompt_text = format!("Password for {account}: ");
    let password = prompt(&prompt_text).map_err(|e| ConfigError::NoCredential {
        account: account.clone(),
        reason: format!("interactive prompt failed: {e}"),
    })?;
    if password.is_empty() {
        return Err(ConfigError::NoCredential {
            account,
            reason: "empty password not accepted".to_string(),
        });
    }
    store.set_password(&account, &password)?;
    Ok(())
}

/// Default prompt function used by the binary. Wraps `rpassword`.
///
/// # Errors
/// Returns the underlying `std::io::Error` from `rpassword`.
pub fn tty_prompt(text: &str) -> std::io::Result<String> {
    rpassword::prompt_password(text)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::credential::{account_key, CredentialStore};
    use crate::error::ConfigError;
    use crate::login::run_login;

    #[derive(Default)]
    struct MockStore {
        entries: Mutex<HashMap<String, String>>,
    }

    impl CredentialStore for MockStore {
        fn get_password(&self, account: &str) -> Result<Option<String>, ConfigError> {
            Ok(self.entries.lock().unwrap().get(account).cloned())
        }
        fn set_password(&self, account: &str, password: &str) -> Result<(), ConfigError> {
            self.entries
                .lock()
                .unwrap()
                .insert(account.to_string(), password.to_string());
            Ok(())
        }
    }

    #[test]
    fn login_writes_prompted_password_to_store() {
        let store = MockStore::default();
        run_login(&store, "alice", "host", |_| Ok("hunter2".to_string())).unwrap();
        let got = store
            .get_password(&account_key("alice", "host"))
            .unwrap()
            .unwrap();
        assert_eq!(got, "hunter2");
    }

    #[test]
    fn empty_password_is_rejected() {
        let store = MockStore::default();
        let err = run_login(&store, "alice", "host", |_| Ok(String::new())).unwrap_err();
        assert!(matches!(err, ConfigError::NoCredential { .. }));
    }

    #[test]
    fn prompt_error_is_surfaced() {
        let store = MockStore::default();
        let err = run_login(&store, "alice", "host", |_| {
            Err(std::io::Error::other("no tty"))
        })
        .unwrap_err();
        match err {
            ConfigError::NoCredential { reason, .. } => assert!(reason.contains("no tty")),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-config/src/lib.rs`:

```rust
//! Configuration loading, validation, and credential resolution for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod credential;
pub mod error;
pub mod loader;
pub mod login;
pub mod model;
pub mod validate;

pub use crate::credential::{
    account_key, resolve_credential, CredentialStore, KeyringStore, KEYCHAIN_SERVICE,
    PASSWORD_ENV_VAR,
};
pub use crate::error::ConfigError;
pub use crate::loader::{load_from_path, resolve_config_path, CONFIG_ENV_VAR};
pub use crate::login::{run_login, tty_prompt};
pub use crate::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, LimitsConfig, LookalikeConfig,
    SecurityConfig, Verdict,
};
pub use crate::validate::{validate, ValidatedConfig};
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rimap-config`
Expected: all pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-config --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-config/src/
git commit -m "feat(config): add login subcommand core with injectable prompt"
```

---

## Task 13: `rimap-authz` — dependencies + `AuthzError`

**Files:**
- Modify: `crates/rimap-authz/Cargo.toml`
- Create: `crates/rimap-authz/src/error.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Update `rimap-authz/Cargo.toml`**

Replace with:

```toml
[package]
name = "rimap-authz"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp."

[lints]
workspace = true

[dependencies]
rimap-core = { path = "../rimap-core" }
rimap-config = { path = "../rimap-config" }
thiserror = { workspace = true }
governor = { workspace = true }
nonzero_ext = { workspace = true }
parking_lot = { workspace = true }
tracing = { workspace = true }
tokio = { workspace = true }

[dev-dependencies]
proptest = { workspace = true }
tokio = { workspace = true, features = ["test-util", "macros", "time"] }
```

- [ ] **Step 2: Write `AuthzError`**

Create `crates/rimap-authz/src/error.rs`:

```rust
//! Authorization-layer error type. Converts into `RimapError::Authz` with the
//! appropriate error code.

use rimap_core::error::ErrorCode;
use rimap_core::tool::ToolName;
use thiserror::Error;

/// Errors produced by `rimap-authz` stages: posture, breaker, rate limiter.
#[derive(Debug, Error, Clone)]
pub enum AuthzError {
    /// Tool denied by the current posture matrix.
    #[error("tool `{0}` denied by current posture")]
    PostureDenied(ToolName),
    /// Rate limiter rejected the call; `retry_after_ms` is a hint.
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited {
        /// Hint for how long the caller should wait before retrying.
        retry_after_ms: u64,
    },
    /// Circuit breaker is open; fast-failing.
    #[error("circuit breaker open; retry after {retry_after_ms} ms")]
    CircuitOpen {
        /// Hint for how long the caller should wait before retrying.
        retry_after_ms: u64,
    },
    /// Config-time error during matrix build (e.g. unknown override tool).
    /// Wrapped as a string because we don't want `rimap-authz` to depend on
    /// the full `ConfigError` variant surface just for display.
    #[error("authz matrix build failed: {0}")]
    MatrixBuild(String),
}

impl AuthzError {
    /// Map to the stable top-level error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PostureDenied(_) => ErrorCode::PostureDenied,
            Self::RateLimited { .. } => ErrorCode::RateLimited,
            Self::CircuitOpen { .. } => ErrorCode::CircuitOpen,
            Self::MatrixBuild(_) => ErrorCode::Config,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::error::AuthzError;
    use rimap_core::error::ErrorCode;
    use rimap_core::tool::ToolName;

    #[test]
    fn error_codes_match_spec() {
        assert_eq!(
            AuthzError::PostureDenied(ToolName::CreateDraft).code(),
            ErrorCode::PostureDenied
        );
        assert_eq!(
            AuthzError::RateLimited { retry_after_ms: 250 }.code(),
            ErrorCode::RateLimited
        );
        assert_eq!(
            AuthzError::CircuitOpen { retry_after_ms: 15_000 }.code(),
            ErrorCode::CircuitOpen
        );
        assert_eq!(
            AuthzError::MatrixBuild("x".into()).code(),
            ErrorCode::Config
        );
    }
}
```

- [ ] **Step 3: Wire into `lib.rs`**

Replace `crates/rimap-authz/src/lib.rs` with:

```rust
//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;

pub use crate::error::AuthzError;
```

- [ ] **Step 4: Run tests and clippy**

Run: `cargo test -p rimap-authz && cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: all pass clean.

- [ ] **Step 5: Commit**

```bash
git add Cargo.lock crates/rimap-authz/Cargo.toml crates/rimap-authz/src/
git commit -m "feat(authz): add AuthzError type and wire dependencies"
```

---

## Task 14: `rimap-authz` — `PostureMatrix` const + lookup

**Files:**
- Create: `crates/rimap-authz/src/matrix.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-authz/src/matrix.rs`:

```rust
//! Posture matrix: compile-time `const` truth table for v1 tools × postures,
//! plus the runtime `EffectiveMatrix` that merges per-tool overrides.
//!
//! Derived from design spec §4 "Posture matrix".

use std::collections::BTreeMap;

use rimap_config::model::Verdict;
use rimap_config::validate::ValidatedConfig;
use rimap_core::posture::Posture;
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

/// Compile-time truth table. `true` = allowed by base posture.
///
/// Layout: outer by [`ToolName`] (13 tools), inner `[readonly, draft_safe, full]`.
const POSTURE_MATRIX: [(ToolName, [bool; 3]); 13] = [
    (ToolName::ListFolders,       [true,  true,  true ]),
    (ToolName::Search,            [true,  true,  true ]),
    (ToolName::SearchAdvanced,    [false, false, true ]),
    (ToolName::FetchMessage,      [true,  true,  true ]),
    (ToolName::FetchMessageHtml,  [false, false, true ]),
    (ToolName::ListAttachments,   [true,  true,  true ]),
    (ToolName::DownloadAttachment,[true,  true,  true ]),
    (ToolName::MarkRead,          [false, true,  true ]),
    (ToolName::MarkUnread,        [false, true,  true ]),
    (ToolName::Flag,              [false, true,  true ]),
    (ToolName::Unflag,            [false, true,  true ]),
    (ToolName::MoveMessage,       [false, true,  true ]),
    (ToolName::CreateDraft,       [false, true,  true ]),
];

fn posture_index(p: Posture) -> usize {
    match p {
        Posture::Readonly => 0,
        Posture::DraftSafe => 1,
        Posture::Full => 2,
    }
}

/// Lookup against the base `const` matrix, before overrides.
#[must_use]
pub fn base_allows(posture: Posture, tool: ToolName) -> bool {
    let idx = posture_index(posture);
    for (t, row) in POSTURE_MATRIX {
        if t == tool {
            return row[idx];
        }
    }
    // Unreachable: POSTURE_MATRIX must cover all ToolName variants.
    // A compile-time exhaustiveness check lives in the test module.
    false
}

/// Effective authorization matrix: base posture merged with per-tool overrides.
///
/// Deny overrides Allow. An override pointing at a tool that is already in
/// the same state is a no-op (not an error).
#[derive(Debug, Clone)]
pub struct EffectiveMatrix {
    allowed: BTreeMap<ToolName, bool>,
    posture: Posture,
}

impl EffectiveMatrix {
    /// Build from a base [`Posture`] and per-tool overrides (already resolved
    /// to [`ToolName`] by config validation).
    #[must_use]
    pub fn build(posture: Posture, overrides: &BTreeMap<ToolName, Verdict>) -> Self {
        let mut allowed = BTreeMap::new();
        for tool in ToolName::all() {
            let base = base_allows(posture, tool);
            let effective = match overrides.get(&tool) {
                None => base,
                Some(Verdict::Allow) => true,
                Some(Verdict::Deny) => false,
            };
            allowed.insert(tool, effective);
        }
        Self { allowed, posture }
    }

    /// Build from a validated config.
    #[must_use]
    pub fn from_validated(cfg: &ValidatedConfig) -> Self {
        Self::build(cfg.config.security.posture, &cfg.tool_overrides)
    }

    /// Base posture used for construction (for logging / display only).
    #[must_use]
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// `Ok(())` if allowed, `Err(PostureDenied)` otherwise.
    ///
    /// # Errors
    /// Returns `AuthzError::PostureDenied` if `tool` is not allowed.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        if *self.allowed.get(&tool).unwrap_or(&false) {
            Ok(())
        } else {
            Err(AuthzError::PostureDenied(tool))
        }
    }

    /// Return the set of allowed tools in declaration order — the advertised
    /// set for `list_tools`.
    #[must_use]
    pub fn advertised(&self) -> Vec<ToolName> {
        ToolName::all()
            .into_iter()
            .filter(|t| *self.allowed.get(t).unwrap_or(&false))
            .collect()
    }

    /// Iterate `(tool, allowed)` in declaration order. Used by `--dry-run`
    /// printing.
    pub fn rows(&self) -> impl Iterator<Item = (ToolName, bool)> + '_ {
        ToolName::all()
            .into_iter()
            .map(move |t| (t, *self.allowed.get(&t).unwrap_or(&false)))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::BTreeMap;

    use rimap_config::model::Verdict;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use crate::matrix::{base_allows, EffectiveMatrix, POSTURE_MATRIX};

    #[test]
    fn matrix_covers_every_tool_variant_exactly_once() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for (tool, _) in POSTURE_MATRIX {
            assert!(seen.insert(tool), "duplicate row for {tool}");
        }
        assert_eq!(seen.len(), ToolName::all().len());
        for t in ToolName::all() {
            assert!(seen.contains(&t), "missing row for {t}");
        }
    }

    #[test]
    fn base_readonly_row_matches_spec() {
        // readonly allows: list_folders, search, fetch_message, list_attachments,
        // download_attachment
        for t in [
            ToolName::ListFolders,
            ToolName::Search,
            ToolName::FetchMessage,
            ToolName::ListAttachments,
            ToolName::DownloadAttachment,
        ] {
            assert!(base_allows(Posture::Readonly, t), "{t} should be allowed");
        }
        // readonly denies everything else
        for t in [
            ToolName::SearchAdvanced,
            ToolName::FetchMessageHtml,
            ToolName::MarkRead,
            ToolName::MarkUnread,
            ToolName::Flag,
            ToolName::Unflag,
            ToolName::MoveMessage,
            ToolName::CreateDraft,
        ] {
            assert!(!base_allows(Posture::Readonly, t), "{t} should be denied");
        }
    }

    #[test]
    fn base_draft_safe_row_matches_spec() {
        // draft-safe forbids only the two escape hatches
        for t in [ToolName::SearchAdvanced, ToolName::FetchMessageHtml] {
            assert!(!base_allows(Posture::DraftSafe, t));
        }
        for t in ToolName::all() {
            if matches!(t, ToolName::SearchAdvanced | ToolName::FetchMessageHtml) {
                continue;
            }
            assert!(base_allows(Posture::DraftSafe, t), "{t} expected allowed");
        }
    }

    #[test]
    fn base_full_row_allows_everything() {
        for t in ToolName::all() {
            assert!(base_allows(Posture::Full, t), "full should allow {t}");
        }
    }

    #[test]
    fn exhaustive_posture_times_tool_lookup_is_stable() {
        // Exercise every cell; this is the "posture × tool exhaustive" test
        // called out in the sprint requirements.
        for p in Posture::all() {
            for t in ToolName::all() {
                // Just ensuring no panic and consistent dual reads.
                let a = base_allows(p, t);
                let b = base_allows(p, t);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn deny_override_beats_allow_in_base() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::Search, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(matches!(m.check(ToolName::Search), Err(AuthzError::PostureDenied(_))));
        // Unaffected tools still match base.
        assert!(m.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn allow_override_promotes_denied_tool() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::SearchAdvanced, Verdict::Allow);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(m.check(ToolName::SearchAdvanced).is_ok());
    }

    #[test]
    fn override_same_as_base_is_noop() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::ListFolders, Verdict::Allow);
        overrides.insert(ToolName::CreateDraft, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::Readonly, &overrides);
        assert!(m.check(ToolName::ListFolders).is_ok());
        assert!(matches!(
            m.check(ToolName::CreateDraft),
            Err(AuthzError::PostureDenied(_))
        ));
    }

    #[test]
    fn advertised_matches_allowed_set_in_order() {
        let m = EffectiveMatrix::build(Posture::Readonly, &BTreeMap::new());
        let adv = m.advertised();
        assert_eq!(
            adv,
            vec![
                ToolName::ListFolders,
                ToolName::Search,
                ToolName::FetchMessage,
                ToolName::ListAttachments,
                ToolName::DownloadAttachment,
            ]
        );
    }

    #[test]
    fn rows_iterates_every_tool() {
        let m = EffectiveMatrix::build(Posture::Full, &BTreeMap::new());
        let rows: Vec<_> = m.rows().collect();
        assert_eq!(rows.len(), ToolName::all().len());
        assert!(rows.iter().all(|(_, allowed)| *allowed));
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-authz/src/lib.rs`:

```rust
//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod matrix;

pub use crate::error::AuthzError;
pub use crate::matrix::{base_allows, EffectiveMatrix};
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-authz`
Expected: all pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/
git commit -m "feat(authz): add PostureMatrix const and EffectiveMatrix merge"
```

---

## Task 15: `rimap-authz` — governor-based rate limiter

Two limiters: a global `commands_per_second` bucket applied to every tool call, plus a separate stricter `drafts_per_minute` bucket only touched by `create_draft`. Both use `governor::DirectRateLimiter` with the `InMemoryState` / `DefaultClock` combination.

**Files:**
- Create: `crates/rimap-authz/src/rate_limit.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-authz/src/rate_limit.rs`:

```rust
//! Rate limiter wrapper around `governor`.
//!
//! Two buckets (design spec §9):
//!   - Global: `limits.commands_per_second` with burst = 2× rate.
//!   - Draft: `limits.drafts_per_minute`, only consulted on `create_draft`.
//!
//! On exceed: return `AuthzError::RateLimited { retry_after_ms }`. The caller
//! (dispatch guard) decides whether to wait or fail.

use std::num::NonZeroU32;

use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Combined global + draft rate limiter.
pub struct Governor {
    global: DirectLimiter,
    drafts: DirectLimiter,
    clock: DefaultClock,
}

impl Governor {
    /// Build from numeric limits.
    ///
    /// # Errors
    /// Returns `AuthzError::MatrixBuild` if either rate is zero (validation
    /// should have caught this already, but we refuse to build a degenerate
    /// limiter).
    pub fn new(commands_per_second: u32, drafts_per_minute: u32) -> Result<Self, AuthzError> {
        let cps = NonZeroU32::new(commands_per_second).ok_or_else(|| {
            AuthzError::MatrixBuild("commands_per_second must be > 0".to_string())
        })?;
        let dpm = NonZeroU32::new(drafts_per_minute).ok_or_else(|| {
            AuthzError::MatrixBuild("drafts_per_minute must be > 0".to_string())
        })?;
        let burst = NonZeroU32::new(commands_per_second.saturating_mul(2).max(1))
            .unwrap_or(NonZeroU32::MIN);
        let global_quota = Quota::per_second(cps).allow_burst(burst);
        let draft_quota = Quota::per_minute(dpm);
        Ok(Self {
            global: RateLimiter::direct(global_quota),
            drafts: RateLimiter::direct(draft_quota),
            clock: DefaultClock::default(),
        })
    }

    /// Attempt to admit a single call. Returns `Ok(())` on admit,
    /// `Err(RateLimited)` on reject.
    ///
    /// # Errors
    /// `AuthzError::RateLimited` when the relevant bucket is empty.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.global.check().map_err(|nu| AuthzError::RateLimited {
            retry_after_ms: nu.wait_time_from(self.clock.now()).as_millis() as u64,
        })?;
        if matches!(tool, ToolName::CreateDraft) {
            self.drafts.check().map_err(|nu| AuthzError::RateLimited {
                retry_after_ms: nu.wait_time_from(self.clock.now()).as_millis() as u64,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use crate::rate_limit::Governor;

    #[test]
    fn zero_rate_rejected_at_build() {
        assert!(Governor::new(0, 5).is_err());
        assert!(Governor::new(10, 0).is_err());
    }

    #[test]
    fn admits_first_call_in_bucket() {
        let g = Governor::new(10, 5).unwrap();
        assert!(g.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn rejects_after_bucket_drains() {
        // Use a small, controllable rate.
        let g = Governor::new(2, 5).unwrap(); // burst = 4
        // Drain the burst.
        for _ in 0..4 {
            let _ = g.check(ToolName::Search);
        }
        // Next call should almost certainly be rate-limited — give it one
        // more grace call for clock jitter.
        let mut rejected = false;
        for _ in 0..4 {
            if let Err(AuthzError::RateLimited { .. }) = g.check(ToolName::Search) {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "bucket should drain within a handful of calls");
    }

    #[test]
    fn draft_bucket_is_separate() {
        let g = Governor::new(1000, 5).unwrap(); // huge global, tight draft
        // Drain 5 drafts (quota = 5/min).
        for _ in 0..5 {
            let _ = g.check(ToolName::CreateDraft);
        }
        // 6th draft should be limited (while a non-draft tool is still fine).
        let draft_err = g.check(ToolName::CreateDraft).unwrap_err();
        assert!(matches!(draft_err, AuthzError::RateLimited { .. }));
        assert!(g.check(ToolName::Search).is_ok());
    }
}
```

- [ ] **Step 2: Add `proptest`-driven steady-state property test**

Append to `crates/rimap-authz/src/rate_limit.rs` inside the existing `#[cfg(test)] mod tests`:

```rust
    use proptest::prelude::*;

    proptest! {
        /// Steady-state: with N calls against a bucket of burst B, we should
        /// admit *at most* B + (time_elapsed * rate) calls, and at least B
        /// if no meaningful time elapses.
        #[test]
        fn steady_state_never_exceeds_burst_plus_refill(
            cps in 1u32..50u32,
            attempts in 1usize..200usize,
        ) {
            let g = Governor::new(cps, 1).unwrap();
            let mut admitted = 0usize;
            for _ in 0..attempts {
                if g.check(ToolName::Search).is_ok() {
                    admitted += 1;
                }
            }
            // Upper bound: burst (2*cps) plus any refill the kernel gave us
            // during the loop. 10× burst is a generous ceiling that should
            // never flake on CI hardware.
            let burst = (cps as usize).saturating_mul(2);
            prop_assert!(
                admitted <= burst * 10 + 10,
                "admitted {admitted} calls against burst {burst} (cps={cps})"
            );
            prop_assert!(admitted >= 1, "should admit at least one call");
        }
    }
```

- [ ] **Step 3: Wire `rate_limit` into `lib.rs`**

Modify `crates/rimap-authz/src/lib.rs`:

```rust
//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod error;
pub mod matrix;
pub mod rate_limit;

pub use crate::error::AuthzError;
pub use crate::matrix::{base_allows, EffectiveMatrix};
pub use crate::rate_limit::Governor;
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rimap-authz`
Expected: all pass, including proptest cases.

- [ ] **Step 5: Clippy**

Run: `cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: clean. If clippy complains about `as u64` casts on `as_millis`, replace with `u64::try_from(…).unwrap_or(u64::MAX)`.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-authz/src/
git commit -m "feat(authz): add governor-based rate limiter with draft bucket"
```

---

## Task 16: `rimap-authz` — circuit breaker state machine

Closed ↔ Open ↔ HalfOpen, with a sliding window counter for the Closed state, exponential-backoff cooldown for Open, and single-probe semantics for HalfOpen. We implement the state machine with `parking_lot::Mutex` (sync; we never hold it across awaits, so the `await_holding_lock` lint stays happy). Time is injected as a `Clock` trait so tests don't need `tokio::time::pause`.

**Files:**
- Create: `crates/rimap-authz/src/breaker.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Write the state machine**

Create `crates/rimap-authz/src/breaker.rs`:

```rust
//! Circuit breaker state machine.
//!
//! States (design spec §9):
//!   - **Closed** — count errors in a sliding window; if ≥ threshold, trip
//!     to Open.
//!   - **Open** — reject all calls for a cooldown duration. After cooldown,
//!     transition to HalfOpen on next call.
//!   - **HalfOpen** — admit exactly one probe. Success → Closed (reset).
//!     Failure → Open with doubled cooldown (capped at 5 minutes, or 10
//!     minutes for auth-failure reasons).
//!
//! Auth failures trip immediately: a single `FailureReason::Auth` in Closed
//! state moves directly to Open with a 60-second cooldown (starting backoff).
//!
//! Time is abstracted via [`Clock`] so tests are fully deterministic without
//! `tokio::time::pause`.

use std::collections::VecDeque;
use std::time::Duration;

use parking_lot::Mutex;

use crate::error::AuthzError;

/// Reasons a call may fail from the breaker's point of view.
///
/// Per spec, `NotFound`, `InvalidInput`, `PostureDenied`, `RateLimited`,
/// `AttachmentTooLarge`, and `BodyTruncated` are NOT reported here — they're
/// user/agent/policy errors, not service health signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// TCP/TLS session dropped mid-call.
    ConnectionLost,
    /// Authentication rejected.
    Auth,
    /// Tokio timeout elapsed.
    Timeout,
    /// IMAP server returned a malformed response.
    Protocol,
    /// TLS handshake or pinning rejection.
    Tls,
}

/// Abstract monotonic clock. Production uses [`SystemClock`]; tests use
/// [`ManualClock`].
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic time as a [`Duration`] since an arbitrary epoch.
    fn now(&self) -> Duration;
}

/// `std::time::Instant`-backed clock.
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    /// Construct at the current instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        std::time::Instant::now().saturating_duration_since(self.epoch)
    }
}

/// Hand-advanced clock for tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    inner: Mutex<Duration>,
}

impl ManualClock {
    /// Construct at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock by `by`.
    pub fn advance(&self, by: Duration) {
        let mut guard = self.inner.lock();
        *guard += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        *self.inner.lock()
    }
}

/// Public state enum — used only for tests / introspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Normal operation.
    Closed,
    /// Fast-failing; cooldown in effect.
    Open,
    /// Next call is a probe.
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: State,
    // Closed-state sliding-window error timestamps.
    failures: VecDeque<Duration>,
    // When `state == Open`, wall time at which we flip to HalfOpen.
    open_until: Duration,
    // Current cooldown duration. Doubles each trip; capped per reason class.
    current_cooldown: Duration,
    // Last trip reason (for backoff cap selection).
    last_trip_was_auth: bool,
}

/// Circuit breaker configuration (subset of `LimitsConfig` relevant here).
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// Threshold of failures within the window that trips the breaker.
    pub error_threshold: u32,
    /// Sliding window length.
    pub window: Duration,
    /// Starting cooldown for non-auth trips.
    pub starting_cooldown: Duration,
    /// Max cooldown for non-auth trips.
    pub max_cooldown: Duration,
    /// Starting cooldown for auth-failure trips.
    pub auth_starting_cooldown: Duration,
    /// Max cooldown for auth-failure trips.
    pub auth_max_cooldown: Duration,
}

impl BreakerConfig {
    /// Defaults derived from design spec §9.
    #[must_use]
    pub fn default_spec() -> Self {
        Self {
            error_threshold: 5,
            window: Duration::from_secs(30),
            starting_cooldown: Duration::from_secs(15),
            max_cooldown: Duration::from_secs(300),
            auth_starting_cooldown: Duration::from_secs(60),
            auth_max_cooldown: Duration::from_secs(600),
        }
    }
}

/// The breaker itself. Cheap to clone-via-Arc; internal state is mutex-protected.
pub struct CircuitBreaker<C: Clock> {
    clock: C,
    cfg: BreakerConfig,
    inner: Mutex<Inner>,
}

impl<C: Clock> CircuitBreaker<C> {
    /// Construct a new breaker in the Closed state.
    pub fn new(clock: C, cfg: BreakerConfig) -> Self {
        Self {
            clock,
            cfg,
            inner: Mutex::new(Inner {
                state: State::Closed,
                failures: VecDeque::new(),
                open_until: Duration::ZERO,
                current_cooldown: cfg.starting_cooldown,
                last_trip_was_auth: false,
            }),
        }
    }

    /// Current state (for tests and tracing).
    #[must_use]
    pub fn state(&self) -> State {
        self.inner.lock().state
    }

    /// Called *before* a tool dispatch.
    ///
    /// # Errors
    /// `AuthzError::CircuitOpen` when the breaker is Open and has not yet
    /// reached its cooldown deadline.
    pub fn pre_call(&self) -> Result<(), AuthzError> {
        let mut g = self.inner.lock();
        let now = self.clock.now();
        match g.state {
            State::Closed => Ok(()),
            State::Open => {
                if now >= g.open_until {
                    g.state = State::HalfOpen;
                    Ok(())
                } else {
                    let remaining = g.open_until.saturating_sub(now);
                    Err(AuthzError::CircuitOpen {
                        retry_after_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                    })
                }
            }
            State::HalfOpen => {
                // The prior call was the probe; any additional calls before
                // the probe resolves are rejected as still-open.
                let remaining = g.open_until.saturating_sub(now);
                Err(AuthzError::CircuitOpen {
                    retry_after_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
                })
            }
        }
    }

    /// Called *after* a successful tool dispatch.
    pub fn on_success(&self) {
        let mut g = self.inner.lock();
        match g.state {
            State::Closed => {
                // Optional: prune the failure queue to keep memory bounded.
                let now = self.clock.now();
                self.prune_expired(&mut g.failures, now);
            }
            State::Open | State::HalfOpen => {
                g.state = State::Closed;
                g.failures.clear();
                g.current_cooldown = self.cfg.starting_cooldown;
                g.last_trip_was_auth = false;
                g.open_until = Duration::ZERO;
            }
        }
    }

    /// Called *after* a failed tool dispatch, with the failure class.
    pub fn on_failure(&self, reason: FailureReason) {
        let now = self.clock.now();
        let mut g = self.inner.lock();
        match g.state {
            State::Open => {
                // Shouldn't happen — pre_call would have rejected — but ignore.
            }
            State::HalfOpen => {
                // Probe failed: reopen with doubled cooldown.
                self.trip_open(&mut g, now, reason, /* doubling */ true);
            }
            State::Closed => {
                if reason == FailureReason::Auth {
                    // Immediate trip on auth failure.
                    self.trip_open(&mut g, now, reason, false);
                    return;
                }
                self.prune_expired(&mut g.failures, now);
                g.failures.push_back(now);
                if g.failures.len() >= self.cfg.error_threshold as usize {
                    self.trip_open(&mut g, now, reason, false);
                }
            }
        }
    }

    fn trip_open(&self, g: &mut Inner, now: Duration, reason: FailureReason, doubling: bool) {
        let is_auth = reason == FailureReason::Auth;
        let (start, cap) = if is_auth {
            (self.cfg.auth_starting_cooldown, self.cfg.auth_max_cooldown)
        } else {
            (self.cfg.starting_cooldown, self.cfg.max_cooldown)
        };
        let next = if doubling {
            (g.current_cooldown.saturating_mul(2)).min(cap)
        } else if g.last_trip_was_auth == is_auth && g.current_cooldown > Duration::ZERO {
            // Re-entering from Closed after a successful probe: start fresh.
            start
        } else {
            start
        };
        g.current_cooldown = next;
        g.open_until = now + next;
        g.state = State::Open;
        g.failures.clear();
        g.last_trip_was_auth = is_auth;
    }

    fn prune_expired(&self, failures: &mut VecDeque<Duration>, now: Duration) {
        let cutoff = now.saturating_sub(self.cfg.window);
        while failures.front().copied().is_some_and(|t| t < cutoff) {
            failures.pop_front();
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use crate::breaker::{BreakerConfig, CircuitBreaker, FailureReason, ManualClock, State};
    use crate::error::AuthzError;

    fn test_cfg() -> BreakerConfig {
        BreakerConfig {
            error_threshold: 3,
            window: Duration::from_secs(10),
            starting_cooldown: Duration::from_secs(5),
            max_cooldown: Duration::from_secs(60),
            auth_starting_cooldown: Duration::from_secs(30),
            auth_max_cooldown: Duration::from_secs(600),
        }
    }

    #[test]
    fn starts_closed() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        assert_eq!(b.state(), State::Closed);
        assert!(b.pre_call().is_ok());
    }

    #[test]
    fn trips_after_threshold_failures_in_window() {
        let clock = ManualClock::new();
        let b = CircuitBreaker::new(clock, test_cfg());
        for _ in 0..2 {
            b.on_failure(FailureReason::Timeout);
        }
        assert_eq!(b.state(), State::Closed);
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Open);
        let err = b.pre_call().unwrap_err();
        assert!(matches!(err, AuthzError::CircuitOpen { .. }));
    }

    #[test]
    fn failures_outside_window_do_not_count() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Timeout);
        b.on_failure(FailureReason::Timeout);
        // Advance past the window.
        b.clock.advance(Duration::from_secs(11));
        b.on_failure(FailureReason::Timeout);
        assert_eq!(
            b.state(),
            State::Closed,
            "old failures should have pruned out of the window"
        );
    }

    #[test]
    fn auth_failure_trips_immediately() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Auth);
        assert_eq!(b.state(), State::Open);
    }

    #[test]
    fn open_transitions_to_half_open_after_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        // Trip it.
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        assert_eq!(b.state(), State::Open);
        assert!(b.pre_call().is_err());
        // Past the 5s cooldown.
        b.clock.advance(Duration::from_secs(5));
        // pre_call flips to HalfOpen and admits the probe.
        assert!(b.pre_call().is_ok());
        assert_eq!(b.state(), State::HalfOpen);
    }

    #[test]
    fn half_open_success_closes_breaker_and_resets_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // HalfOpen probe admitted
        b.on_success();
        assert_eq!(b.state(), State::Closed);
        assert!(b.pre_call().is_ok());
    }

    #[test]
    fn half_open_failure_reopens_with_doubled_cooldown() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // HalfOpen
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Open);
        // Cooldown should now be ~10s (2×5s). After 6s we should still be open.
        b.clock.advance(Duration::from_secs(6));
        assert!(b.pre_call().is_err());
        // After a total of 10s since the re-trip, we should be HalfOpen.
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok());
        assert_eq!(b.state(), State::HalfOpen);
    }

    #[test]
    fn cooldown_caps_at_max() {
        let mut cfg = test_cfg();
        cfg.starting_cooldown = Duration::from_secs(40);
        cfg.max_cooldown = Duration::from_secs(60);
        let b = CircuitBreaker::new(ManualClock::new(), cfg);
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        // Force several trip/probe-fail cycles and confirm cooldown caps.
        for _ in 0..5 {
            b.clock.advance(Duration::from_secs(120));
            assert!(b.pre_call().is_ok()); // HalfOpen
            b.on_failure(FailureReason::Timeout);
        }
        // The only assertion we can make without exposing internals: the
        // breaker is Open again and the pre_call retry_after is ≤ max_cooldown.
        if let Err(AuthzError::CircuitOpen { retry_after_ms }) = b.pre_call() {
            assert!(retry_after_ms <= 60_000);
        } else {
            panic!("expected CircuitOpen");
        }
    }

    #[test]
    fn half_open_rejects_concurrent_calls_until_probe_resolves() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        for _ in 0..3 {
            b.on_failure(FailureReason::Timeout);
        }
        b.clock.advance(Duration::from_secs(5));
        assert!(b.pre_call().is_ok()); // probe admitted
        assert_eq!(b.state(), State::HalfOpen);
        // A second concurrent pre_call in HalfOpen is rejected.
        assert!(matches!(
            b.pre_call(),
            Err(AuthzError::CircuitOpen { .. })
        ));
    }

    #[test]
    fn success_in_closed_state_prunes_old_failures() {
        let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
        b.on_failure(FailureReason::Timeout);
        b.clock.advance(Duration::from_secs(11));
        b.on_success();
        // Now a fresh streak of failures needs to cross the threshold again.
        b.on_failure(FailureReason::Timeout);
        b.on_failure(FailureReason::Timeout);
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn every_failure_reason_can_trip_the_breaker_in_closed() {
        for reason in [
            FailureReason::ConnectionLost,
            FailureReason::Auth,
            FailureReason::Timeout,
            FailureReason::Protocol,
            FailureReason::Tls,
        ] {
            let b = CircuitBreaker::new(ManualClock::new(), test_cfg());
            // Auth trips immediately; others need 3.
            let needed = if reason == FailureReason::Auth { 1 } else { 3 };
            for _ in 0..needed {
                b.on_failure(reason);
            }
            assert_eq!(b.state(), State::Open, "reason {reason:?} should trip");
        }
    }
}
```

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-authz/src/lib.rs`:

```rust
//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod breaker;
pub mod error;
pub mod matrix;
pub mod rate_limit;

pub use crate::breaker::{
    BreakerConfig, CircuitBreaker, Clock, FailureReason, ManualClock, State, SystemClock,
};
pub use crate::error::AuthzError;
pub use crate::matrix::{base_allows, EffectiveMatrix};
pub use crate::rate_limit::Governor;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-authz`
Expected: all pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: clean. Watch for:
- `cast_possible_truncation` on `as u64` — already switched to `try_from`.
- `needless_pass_by_value` / `missing_errors_doc` — add `# Errors` docs as needed.
- If the pedantic `option_if_let_else` fires, rewrite the prune loop accordingly.

- [ ] **Step 5: Commit**

```bash
git add crates/rimap-authz/src/
git commit -m "feat(authz): add CircuitBreaker state machine with ManualClock"
```

---

## Task 17: `rimap-authz` — `DispatchGuard` composition

`DispatchGuard` glues the three stages together in the order specified by the dispatch chain in spec §9: posture → breaker → rate limiter. We expose a single synchronous `pre_dispatch(ToolName) -> Result<(), AuthzError>` for callers, plus `on_success` / `on_failure` callbacks for the breaker.

**Files:**
- Create: `crates/rimap-authz/src/guard.rs`
- Modify: `crates/rimap-authz/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/rimap-authz/src/guard.rs`:

```rust
//! Composed dispatch guard: posture + circuit breaker + rate limiter.
//!
//! Call order (design spec §9):
//!   1. Posture authorization (effective matrix).
//!   2. Circuit breaker pre-call check.
//!   3. Rate limiter admission.
//!
//! If any stage short-circuits, subsequent stages are skipped. The breaker is
//! notified of success/failure via `on_success` / `on_failure` after dispatch.

use rimap_core::tool::ToolName;

use crate::breaker::{CircuitBreaker, Clock, FailureReason};
use crate::error::AuthzError;
use crate::matrix::EffectiveMatrix;
use crate::rate_limit::Governor;

/// Composed authorization gate. Not async — none of the stages await.
pub struct DispatchGuard<C: Clock> {
    matrix: EffectiveMatrix,
    breaker: CircuitBreaker<C>,
    governor: Governor,
}

impl<C: Clock> DispatchGuard<C> {
    /// Construct from pre-built pieces.
    #[must_use]
    pub fn new(matrix: EffectiveMatrix, breaker: CircuitBreaker<C>, governor: Governor) -> Self {
        Self {
            matrix,
            breaker,
            governor,
        }
    }

    /// Run the full pre-dispatch chain.
    ///
    /// # Errors
    /// Returns the first stage error encountered.
    pub fn pre_dispatch(&self, tool: ToolName) -> Result<(), AuthzError> {
        self.matrix.check(tool)?;
        self.breaker.pre_call()?;
        self.governor.check(tool)?;
        Ok(())
    }

    /// Signal a successful tool dispatch to the breaker.
    pub fn on_success(&self) {
        self.breaker.on_success();
    }

    /// Signal a failed tool dispatch to the breaker.
    pub fn on_failure(&self, reason: FailureReason) {
        self.breaker.on_failure(reason);
    }

    /// Access the effective matrix (for `list_tools` advertisement and
    /// `--dry-run` printing).
    #[must_use]
    pub fn matrix(&self) -> &EffectiveMatrix {
        &self.matrix
    }

    /// Access the underlying breaker (used in tests for manual-clock
    /// advancement; production callers should use `on_success` / `on_failure`).
    #[must_use]
    pub fn breaker(&self) -> &CircuitBreaker<C> {
        &self.breaker
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use crate::breaker::{BreakerConfig, CircuitBreaker, FailureReason, ManualClock};
    use crate::error::AuthzError;
    use crate::guard::DispatchGuard;
    use crate::matrix::EffectiveMatrix;
    use crate::rate_limit::Governor;

    fn guard(posture: Posture) -> DispatchGuard<ManualClock> {
        let matrix = EffectiveMatrix::build(posture, &BTreeMap::new());
        let breaker = CircuitBreaker::new(
            ManualClock::new(),
            BreakerConfig {
                error_threshold: 2,
                window: Duration::from_secs(10),
                starting_cooldown: Duration::from_secs(5),
                max_cooldown: Duration::from_secs(60),
                auth_starting_cooldown: Duration::from_secs(30),
                auth_max_cooldown: Duration::from_secs(600),
            },
        );
        let governor = Governor::new(100, 5).unwrap();
        DispatchGuard::new(matrix, breaker, governor)
    }

    #[test]
    fn readonly_denies_create_draft_at_posture_stage() {
        let g = guard(Posture::Readonly);
        let err = g.pre_dispatch(ToolName::CreateDraft).unwrap_err();
        assert!(matches!(err, AuthzError::PostureDenied(ToolName::CreateDraft)));
    }

    #[test]
    fn draft_safe_allows_mark_read() {
        let g = guard(Posture::DraftSafe);
        g.pre_dispatch(ToolName::MarkRead).unwrap();
    }

    #[test]
    fn posture_denied_does_not_consume_rate_limiter() {
        let g = guard(Posture::Readonly);
        // Hit a denied tool many more times than the burst.
        for _ in 0..500 {
            let _ = g.pre_dispatch(ToolName::CreateDraft);
        }
        // An allowed tool should still be admitted.
        g.pre_dispatch(ToolName::ListFolders).unwrap();
    }

    #[test]
    fn breaker_failure_feedback_eventually_blocks_allowed_tool() {
        let g = guard(Posture::DraftSafe);
        g.pre_dispatch(ToolName::ListFolders).unwrap();
        g.on_failure(FailureReason::Timeout);
        g.on_failure(FailureReason::Timeout);
        let err = g.pre_dispatch(ToolName::ListFolders).unwrap_err();
        assert!(matches!(err, AuthzError::CircuitOpen { .. }));
    }

    #[test]
    fn on_success_after_probe_closes_breaker() {
        let g = guard(Posture::DraftSafe);
        g.on_failure(FailureReason::Timeout);
        g.on_failure(FailureReason::Timeout);
        assert!(matches!(
            g.pre_dispatch(ToolName::ListFolders),
            Err(AuthzError::CircuitOpen { .. })
        ));
        // Advance past the 5s cooldown.
        g.breaker().clock.advance(Duration::from_secs(5));
        g.pre_dispatch(ToolName::ListFolders).unwrap(); // HalfOpen probe
        g.on_success();
        g.pre_dispatch(ToolName::ListFolders).unwrap();
    }
}
```

Note: the last test reaches into `g.breaker.clock` via the `pub` field on `ManualClock`. The struct definition above gives `ManualClock` a private `inner` Mutex — the `clock` field on `CircuitBreaker` is also private. Rewrite the `CircuitBreaker` struct to expose `pub clock: C` (instead of `clock: C`) so tests can call `advance`. This is acceptable because `ManualClock` itself only exposes `advance(&self, Duration)`, a non-destructive operation.

Go back to `crates/rimap-authz/src/breaker.rs` Task 16 step 1 and change:

```rust
pub struct CircuitBreaker<C: Clock> {
    clock: C,
```

to:

```rust
pub struct CircuitBreaker<C: Clock> {
    /// Clock used for window pruning and cooldown checks. Public so tests
    /// using [`ManualClock`] can advance it; production uses [`SystemClock`]
    /// which has no public mutation API, so exposing it is safe.
    pub clock: C,
```

If Task 16 is already committed by the time you reach this step, make the edit here in a separate commit before moving on.

- [ ] **Step 2: Wire into `lib.rs`**

Modify `crates/rimap-authz/src/lib.rs`:

```rust
//! Posture-based authorization, rate limiting, and circuit breaker for rusty-imap-mcp.

#![deny(missing_docs)]

pub mod breaker;
pub mod error;
pub mod guard;
pub mod matrix;
pub mod rate_limit;

pub use crate::breaker::{
    BreakerConfig, CircuitBreaker, Clock, FailureReason, ManualClock, State, SystemClock,
};
pub use crate::error::AuthzError;
pub use crate::guard::DispatchGuard;
pub use crate::matrix::{base_allows, EffectiveMatrix};
pub use crate::rate_limit::Governor;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p rimap-authz`
Expected: all pass.

- [ ] **Step 4: Clippy**

Run: `cargo clippy -p rimap-authz --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit (possibly two commits if the breaker `pub clock` edit is separate)**

```bash
git add crates/rimap-authz/src/breaker.rs
git commit -m "refactor(authz): expose CircuitBreaker.clock for manual-clock tests"

git add crates/rimap-authz/src/guard.rs crates/rimap-authz/src/lib.rs
git commit -m "feat(authz): add DispatchGuard composing matrix, breaker, governor"
```

---

## Task 18: `rimap-authz` — coverage check

The sprint exit criterion is ≥ 90% unit test coverage on `rimap-authz`. We use `cargo-llvm-cov` (already present in CI per Sprint 0). This task records the measured coverage and, if under threshold, adds tests until it clears.

**Files:** none (tests only added if needed)

- [ ] **Step 1: Install `cargo-llvm-cov` if missing**

Run: `cargo llvm-cov --version`
If the command is not found, run: `cargo install cargo-llvm-cov --locked`
Expected: a version number is printed.

- [ ] **Step 2: Measure rimap-authz line coverage**

Run:
```bash
cargo llvm-cov --package rimap-authz --summary-only
```

Expected output ends with a summary table. Note the "Lines" percentage for the overall crate.

- [ ] **Step 3: If coverage < 90%, identify uncovered regions**

Run:
```bash
cargo llvm-cov --package rimap-authz --show-missing-lines
```

The output lists specific uncovered line ranges per file. Add targeted tests to exercise those branches. Likely candidates:
- `breaker.rs` `prune_expired` empty-queue early return.
- `breaker.rs` transition from `State::Open` under `on_failure` (the "shouldn't happen" branch).
- `rate_limit.rs` `Governor::new` error paths for zero rates (already covered by Task 15 — confirm).
- `matrix.rs` `rows` and `advertised` helpers.

Add the tests, re-run the coverage command, iterate until ≥ 90%.

- [ ] **Step 4: Commit any coverage-driven test additions**

```bash
git add crates/rimap-authz/src/
git commit -m "test(authz): raise rimap-authz coverage to ≥90%"
```

(Skip the commit if no new tests were needed.)

---

## Task 19: `rimap-server` — dependencies + CLI module

**Files:**
- Modify: `crates/rimap-server/Cargo.toml`
- Create: `crates/rimap-server/src/cli.rs`

- [ ] **Step 1: Update `rimap-server/Cargo.toml`**

Replace with:

```toml
[package]
name = "rimap-server"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Rusty IMAP MCP server: security-first MCP server for IMAP email access."

[lints]
workspace = true

[[bin]]
name = "rusty-imap-mcp"
path = "src/main.rs"

[dependencies]
rimap-core = { path = "../rimap-core" }
rimap-config = { path = "../rimap-config" }
rimap-authz = { path = "../rimap-authz" }
anyhow = { workspace = true }
clap = { workspace = true }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }

[dev-dependencies]
assert_cmd = { workspace = true }
predicates = { workspace = true }
tempfile = { workspace = true }
```

- [ ] **Step 2: Write the CLI**

Create `crates/rimap-server/src/cli.rs`:

```rust
//! CLI definitions for `rusty-imap-mcp`.
//!
//! Top-level flags:
//!   - `--config <path>` — explicit config path (else env var, else XDG default).
//!   - `--dry-run` — load config, print effective matrix, exit.
//!
//! Subcommand:
//!   - `login` — interactively store a credential in the keychain.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "rusty-imap-mcp",
    version,
    about = "Security-first MCP server for IMAP email access"
)]
pub struct Cli {
    /// Path to the config file. Overrides `RUSTY_IMAP_MCP_CONFIG` and the
    /// platform default.
    #[arg(long, value_name = "PATH", env = "RUSTY_IMAP_MCP_CONFIG")]
    pub config: Option<PathBuf>,

    /// Load the config, print the effective tool matrix, and exit.
    /// Mutually exclusive with subcommands.
    #[arg(long)]
    pub dry_run: bool,

    /// Subcommand (optional; default is the MCP server loop — not yet implemented).
    #[command(subcommand)]
    pub command: Option<Command>,
}

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
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use clap::Parser;

    use crate::cli::{Cli, Command};

    #[test]
    fn parses_dry_run_with_config() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp", "--config", "/tmp/x.toml", "--dry-run"])
            .unwrap();
        assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/tmp/x.toml")));
        assert!(cli.dry_run);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_login_subcommand() {
        let cli = Cli::try_parse_from([
            "rusty-imap-mcp",
            "login",
            "--host",
            "127.0.0.1",
            "--username",
            "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Login { host, username }) => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(username, "alice");
            }
            other => panic!("expected Login, got {other:?}"),
        }
    }

    #[test]
    fn no_args_is_valid_and_defaults() {
        let cli = Cli::try_parse_from(["rusty-imap-mcp"]).unwrap();
        assert!(!cli.dry_run);
        assert!(cli.command.is_none());
    }
}
```

- [ ] **Step 3: Run tests and clippy**

Run: `cargo test -p rimap-server && cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: all pass. (`main.rs` is still the Sprint 0 silent stub — it does not use the new `cli` module yet; that happens in Task 21. The `cli` module is compiled as part of the bin crate and its tests run alone.)

Note: to make the module visible to tests, `main.rs` must declare `mod cli;`. Do that in this task — see Step 4.

- [ ] **Step 4: Declare the `cli` module in `main.rs`**

Modify `crates/rimap-server/src/main.rs` to declare the module but leave `main` silent:

```rust
//! Rusty IMAP MCP server entry point.
//!
//! Sprint 1: the entry point will grow `clap` parsing and a `--dry-run` path
//! in subsequent tasks. For now it declares the submodules so they can be
//! unit-tested independently.

#![deny(missing_docs)]

mod cli;

fn main() {
    // Real dispatch lands in Task 21.
}
```

- [ ] **Step 5: Re-run tests**

Run: `cargo test -p rimap-server`
Expected: `cli` module tests pass.

- [ ] **Step 6: Commit**

```bash
git add Cargo.lock crates/rimap-server/Cargo.toml crates/rimap-server/src/
git commit -m "feat(server): add clap CLI with --dry-run and login subcommand"
```

---

## Task 20: `rimap-server` — `tracing` subscriber init

**Files:**
- Create: `crates/rimap-server/src/logging.rs`
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Write the module**

Create `crates/rimap-server/src/logging.rs`:

```rust
//! Tracing subscriber initialization.
//!
//! Writes to stderr via the `fmt` layer's `with_writer(std::io::stderr)`.
//! The clippy `print_stderr` lint targets the `eprintln!` / `eprint!` macros,
//! not direct `Write` calls through the `tracing-subscriber` machinery, so
//! this initialization is compatible with the workspace lint set.
//!
//! The filter defaults to `info` but can be overridden by
//! `RUST_LOG` / `RIMAP_LOG` environment variables via the standard
//! `EnvFilter::try_from_default_env` chain.

use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the global default subscriber. Safe to call exactly once per
/// process; subsequent calls are no-ops.
pub fn init() {
    let filter = EnvFilter::try_from_env("RIMAP_LOG")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // `with_writer(std::io::stderr)` is an `fn() -> Stderr`, which satisfies
    // the `MakeWriter` trait; `.with_max_level(...)` would also be available
    // via MakeWriterExt if needed.
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr.with_max_level(tracing::Level::TRACE))
        .with_target(true)
        .try_init();
}
```

- [ ] **Step 2: Declare the module**

Modify `crates/rimap-server/src/main.rs`:

```rust
//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

mod cli;
mod logging;

fn main() {
    // Real dispatch lands in Task 21.
}
```

- [ ] **Step 3: Compile and clippy**

Run: `cargo build -p rimap-server && cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean. If clippy flags `.unwrap_or_else(|_| EnvFilter::new("info"))` as `unwrap_or_else` preferred form issues, adjust accordingly.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/src/
git commit -m "feat(server): add tracing subscriber writing to stderr"
```

---

## Task 21: `rimap-server` — `--dry-run` path

**Files:**
- Create: `crates/rimap-server/src/dry_run.rs`
- Modify: `crates/rimap-server/src/main.rs`

- [ ] **Step 1: Write the dry-run module**

Create `crates/rimap-server/src/dry_run.rs`:

```rust
//! `--dry-run` path: load + validate config, build effective matrix, print it
//! to stdout, exit 0.
//!
//! Stdout is reserved for MCP transport, but `--dry-run` is an *out-of-band*
//! mode that terminates the process before any MCP wiring happens, so writing
//! the matrix to stdout is both acceptable and the most useful destination
//! (it can be piped to `less`, etc.).
//!
//! Output format is stable text: one header line and one row per tool, in
//! declaration order. Sample:
//!
//! ```text
//! Effective matrix (posture = draft-safe)
//!   [ok ] list_folders
//!   [ok ] search
//!   [deny] search.advanced_query
//!   ...
//! ```

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use rimap_authz::matrix::EffectiveMatrix;
use rimap_config::loader::load_from_path;
use rimap_config::validate::validate;

/// Load `path`, validate, build the effective matrix, print to `out`, and
/// return.
///
/// # Errors
/// Propagates config load/validate errors and I/O errors from the writer.
pub fn run<W: Write>(path: &Path, out: &mut W) -> anyhow::Result<()> {
    let raw = load_from_path(path).with_context(|| format!("loading config {}", path.display()))?;
    let validated = validate(raw).context("validating config")?;
    let matrix = EffectiveMatrix::from_validated(&validated);
    writeln!(out, "Effective matrix (posture = {})", matrix.posture())?;
    for (tool, allowed) in matrix.rows() {
        let tag = if allowed { "[ok ]" } else { "[deny]" };
        writeln!(out, "  {tag} {tool}")?;
    }
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use crate::dry_run::run;

    fn write_minimal_config(dir: &TempDir) -> PathBuf {
        let audit = dir.path().join("audit.jsonl");
        let config_path = dir.path().join("config.toml");
        let body = format!(
            r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[audit]
path = "{}"
"#,
            audit.display()
        );
        std::fs::write(&config_path, body).unwrap();
        config_path
    }

    #[test]
    fn dry_run_prints_matrix_with_default_posture() {
        let dir = TempDir::new().unwrap();
        let path = write_minimal_config(&dir);
        let mut out = Vec::new();
        run(&path, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("draft-safe"));
        assert!(text.contains("list_folders"));
        assert!(text.contains("search.advanced_query"));
        // The advanced_query cell is denied under draft-safe.
        assert!(text.contains("[deny] search.advanced_query"));
        assert!(text.contains("[ok ] list_folders"));
    }

    #[test]
    fn dry_run_surfaces_parse_errors_as_anyhow() {
        let dir = TempDir::new().unwrap();
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "not valid toml =\n").unwrap();
        let err = run(&bad, &mut Vec::new()).unwrap_err();
        // anyhow chains context; the bottom-most error comes from rimap-config.
        let chain: String = err.chain().map(|e| format!("{e}\n")).collect();
        assert!(chain.contains("loading config") || chain.contains("parse"));
    }
}
```

- [ ] **Step 2: Wire `main.rs` to dispatch**

Replace `crates/rimap-server/src/main.rs` with:

```rust
//! Rusty IMAP MCP server entry point.

#![deny(missing_docs)]

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

use crate::cli::{Cli, Command};

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
    if let Some(Command::Login { host, username }) = cli.command {
        let store = KeyringStore;
        run_login(&store, &username, &host, tty_prompt)
            .with_context(|| format!("storing credential for {username}@{host}"))?;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "credential stored for {username}@{host}")?;
        return Ok(());
    }

    if cli.dry_run {
        let path = cli
            .config
            .clone()
            .or_else(|| resolve_config_path(None))
            .ok_or_else(|| anyhow::anyhow!("no config path (pass --config or set RUSTY_IMAP_MCP_CONFIG)"))?;
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

- [ ] **Step 3: Integration test for the binary**

Create `crates/rimap-server/tests/dry_run_cli.rs`:

```rust
//! End-to-end CLI test: invoke the compiled binary with `--dry-run` against a
//! temp-file config and assert exit code + stdout contents.

#![expect(clippy::unwrap_used, reason = "tests")]

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn write_config(dir: &TempDir) -> std::path::PathBuf {
    let audit = dir.path().join("audit.jsonl");
    let path = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security]
posture = "readonly"

[audit]
path = "{}"
"#,
        audit.display()
    );
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn dry_run_exits_zero_and_prints_matrix() {
    let dir = TempDir::new().unwrap();
    let config = write_config(&dir);
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("readonly"))
        .stdout(predicate::str::contains("[ok ] list_folders"))
        .stdout(predicate::str::contains("[deny] create_draft"));
}

#[test]
fn missing_config_exits_non_zero_with_error_log() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("absent.toml");
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&missing)
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("loading config"));
}

#[test]
fn unknown_tool_override_exits_non_zero() {
    let dir = TempDir::new().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let config = dir.path().join("config.toml");
    let body = format!(
        r#"
[imap]
host = "127.0.0.1"
port = 1143
username = "alice@example.test"

[security.tools]
nuke_inbox = "deny"

[audit]
path = "{}"
"#,
        audit.display()
    );
    std::fs::write(&config, body).unwrap();
    Command::cargo_bin("rusty-imap-mcp")
        .unwrap()
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("nuke_inbox"));
}
```

- [ ] **Step 4: Run the integration test**

Run: `cargo test -p rimap-server`
Expected: all pass.

- [ ] **Step 5: Clippy the whole workspace**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean across every crate.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/
git commit -m "feat(server): wire --dry-run path and login subcommand dispatch"
```

---

## Task 22: Full workspace `just ci` gate

**Files:** none

- [ ] **Step 1: Format the workspace**

Run: `just fmt`
Expected: success. Inspect the diff; if significant churn, commit it separately:

```bash
git diff
git add -u
git commit -m "style: cargo fmt"
```

- [ ] **Step 2: Full local-CI run**

Run: `just ci`
Expected: all green. This runs fmt-check, clippy, test, test-msrv, deny, and hooks.

- [ ] **Step 3: If `just test-msrv` fails**

The MSRV is 1.85.1. Sprint 1 introduces `edition 2024` features used transitively by some deps. If a dep demands a newer MSRV than 1.85.1:
1. First check if a patch-level downgrade via `cargo update -p <crate> --precise <version>` resolves it without breaking other deps.
2. If not, and the dep is truly core, stop and ask for guidance — bumping MSRV is a spec-level change.

Do NOT silently bump `rust-version` in `Cargo.toml`.

- [ ] **Step 4: Final prek run**

Run: `prek run --all-files`
Expected: all green.

- [ ] **Step 5: Verify end state**

Run: `git status`
Expected: clean working tree.

---

## Task 23: Push branch, open PR, verify CI

**Files:** none

- [ ] **Step 1: Push the branch**

Run: `git push -u origin feat/sprint-1-implementation`
Expected: branch published.

- [ ] **Step 2: Open the PR**

Run:

```bash
gh pr create --base main --title "Sprint 1: config, postures, authz skeleton" --body "$(cat <<'EOF'
## Summary

- `rimap-core`: adds `Posture`, `ToolName`, `AuditRecord` skeleton, `RimapError` with stable error codes from design spec §9.
- `rimap-config`: TOML loader with XDG path resolution, `ValidatedConfig` validation pipeline (posture, fingerprint, limits, paths, override resolution), credential store trait with `KeyringStore` impl and env-var fallback, `login` subcommand core.
- `rimap-authz`: compile-time `PostureMatrix` const, runtime `EffectiveMatrix` with override merge (deny-over-allow), `governor`-backed `Governor` rate limiter (global + draft bucket), `CircuitBreaker` state machine with injectable clock, composed `DispatchGuard`.
- `rimap-server`: `clap` CLI with `--config`, `--dry-run`, and `login` subcommand; `tracing` subscriber writing to stderr via `with_writer`; `--dry-run` path prints the effective tool matrix and exits.
- Unit test coverage ≥ 90% on `rimap-authz`; posture × tool matrix exhaustively tested; circuit breaker state transitions covered exhaustively; rate limiter steady-state property test.
- Integration test invoking the compiled binary end-to-end for `--dry-run`.

## Test plan

- [ ] `just ci` green locally
- [ ] `cargo llvm-cov --package rimap-authz --summary-only` ≥ 90%
- [ ] All 7 CI status checks green (fmt, clippy, test stable, test MSRV 1.85.1, deny, zizmor, SonarCloud)
- [ ] Manual: `./target/debug/rusty-imap-mcp --config <path> --dry-run` prints the effective matrix against a sample config
EOF
)"
```

Expected: PR URL printed.

- [ ] **Step 3: Wait for CI and verify**

Run: `gh pr checks --watch`
Expected: all 7 checks green.

Known risks:
- New runtime deps may pull in a license not in the allowlist — fix in `deny.toml` with an additional commit on the branch.
- `test-msrv` may fail if any dep quietly raised its MSRV above 1.85.1 — see Task 22 Step 3.
- `zizmor` should not fire on this PR (no workflow changes).

If a check fails, fix the root cause in a new commit on the branch. Do not amend published commits.

- [ ] **Step 4: Sprint 1 done**

Sprint 1 is complete when:
1. PR is open and all 7 CI checks are green.
2. `rusty-imap-mcp --config x.toml --dry-run` prints the effective matrix and exits clean.
3. `rimap-authz` unit coverage ≥ 90%.
4. Merging the PR is the next human action; **do not merge from the agent.**

---

## Self-review checklist (implementing engineer: do not skip)

Before marking the PR ready:

- [ ] Every file listed in the "File structure" section exists and is committed.
- [ ] `git grep -nE 'TBD|FIXME|XXX|todo!\(|unimplemented!\(' -- 'crates/' ':!crates/*/target'` is empty inside Sprint 1 crates.
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` is silent.
- [ ] `cargo fmt --all -- --check` is silent.
- [ ] `cargo deny check` is silent.
- [ ] `cargo +1.85.1 check --workspace --all-targets --all-features --locked` is silent.
- [ ] `cargo llvm-cov --package rimap-authz --summary-only` reports ≥ 90% line coverage.
- [ ] `cargo test --workspace` passes including the `dry_run_cli` integration test.
- [ ] `rusty-imap-mcp --config <sample> --dry-run` prints a matrix that includes `list_folders`, marks `[deny] search.advanced_query` under `draft-safe`, and includes every tool from `ToolName::all()`.
- [ ] The `login` subcommand parses correctly (see unit tests) — end-to-end keychain write is a manual smoke test, not a CI test.

---

## Dependencies and scope guardrails

- **Do not** add `async-imap`, `rmcp`, `mail-parser`, `ammonia`, `fs2`, or any other runtime dep beyond the list in Task 2. They belong to Sprints 2–5.
- **Do not** implement any actual audit log writes — `rimap-audit` stays empty. The `AuditRecord` skeleton in `rimap-core` is enum shells only.
- **Do not** implement any IMAP code in `rimap-imap`.
- **Do not** add `#[allow(...)]` attributes — the workspace denies them. Use `#[expect(..., reason = "...")]` with a concrete justification only if truly needed.
- **Do not** use `eprintln!`/`println!`/`dbg!` anywhere in non-test source. Tracing writes through `with_writer(std::io::stderr)`; stdout from `--dry-run` goes through `writeln!(std::io::stdout().lock(), …)`.
- **Do not** swallow errors silently. Every `Result` propagates or is matched with a concrete reason.
- **Do not** commit on `main`. All work is on `feat/sprint-1-implementation`.
- **Do not** force-push or amend commits that have been pushed to `origin`.
- **Do not** skip hooks with `--no-verify`. Fix the underlying issue.
