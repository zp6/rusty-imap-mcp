# GitHub Issue Backlog Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve 24 deferred GitHub issues (cleanup carved out of Sprint 1–3 reviews) on a single branch, in nine reviewable batches, with one commit per issue.

**Architecture:** Linear execution on `fix/gh-issue-backlog` off `main`. Each issue is one focused commit referenced by `Closes #N` in the message footer. Batches are checkpoints — after each batch the workspace must pass `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings && cargo test` before moving on. Two issues are confirmed already-resolved on main and only need a `gh issue close` with a justification comment. Five issues are deferred per the answers in the brainstorming session and are documented at the end of this file.

**Tech Stack:** Rust 1.88+, cargo workspace (`rimap-core`, `rimap-config`, `rimap-imap`, `rimap-audit`, `rimap-content`, `rimap-authz`, `rimap-server`), `thiserror`, `tracing`, `tokio`, `async-imap`, `tokio-rustls`, `webpki-roots`, `fs4`, `serde_json`, `time`, `proptest`. Reviewer-agent files are Markdown under `.claude/agents/`.

---

## Scope summary

| Status | Count | Issues |
|---|---|---|
| In-scope (this plan) | 24 | #5, #6, #7, #10, #11, #12, #13, #15, #16, #22, #23, #25, #26, #28, #29, #30, #31, #33, #34, #36, #37, #39, #40, #41 |
| Already resolved on main (close with comment) | 2 | #35, #38 |
| Deferred (out of scope, see end of doc) | 5 | #8, #14, #18, #19, #32 |

## Decisions locked in during brainstorming

| Issue | Decision | Rationale |
|---|---|---|
| #22 SEARCH redaction policy | **A** (keep `RedactString`, doc-only rationale) | Most conservative; reviewer hint agreed. |
| #15 error-taxonomy reviewer | **Block inside `local-security-reviewer`** (not new agent) | Stays under 10 entries. |
| #16 fuzzing coverage tracker | **Option A** (doc + checklist) | Issue text recommends A. |
| #18 SECURITY.md hygiene reviewer | **Split out** (deferred) | Depended on #14 which is also split out. |
| #14 threat-model-reviewer | **Split out** (deferred) | Larger work; deserves its own design. |

## Batch order

| Batch | Issues | Theme | Risk |
|---|---|---|---|
| 1 | #23, #28, #36, #37 | Trivial docs/comments | low |
| 2 | #25, #26, #34 | rimap-core / rimap-audit small fixes | low |
| 3 | #31, #33, #40 | rimap-imap small fixes (TLS, FETCH, deps) | low–med |
| 4 | #5, #6, #7, #29 | Audit subsystem & config containment | med |
| 5 | #39 | rimap-imap error-variant chain (depends on #34 from B2) | med |
| 6 | #41 | Test infrastructure (compose project pruning) | low |
| 7 | #10, #11, #12, #13 | Reviewer-agent doc edits | low |
| 8 | #30, #22 | Supply-chain watchlist + SEARCH redaction rationale | low |
| 9 | #15, #16 | Decision-gated reviewer-agent edits | low |

After Batch 9, two close-as-resolved actions for #35 and #38 (no commits, just `gh issue close`).

---

## Task 0: Branch setup and verification baseline

**Files:** none — git only.

- [ ] **Step 0.1:** Verify clean working tree on `main`.

```bash
git status
git log --oneline -3
```
Expected: working tree clean, HEAD at `638a3e0` (Sprint 3 merge) or later.

- [ ] **Step 0.2:** Create the branch.

```bash
git checkout -b fix/gh-issue-backlog
```

- [ ] **Step 0.3:** Verify the workspace builds clean from the baseline before any change.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```
Expected: all green. If any fail, STOP and report — the baseline is broken and the plan cannot be executed reliably.

---

# Batch 1 — Trivial docs and comments

Four issues, each is a comment or doc-string addition. No tests needed beyond a successful workspace rebuild.

## Task 1: #23 — `Verbatim` folder/destination invariant doc-comment

**Issue:** rimap-audit: doc Verbatim folder/destination invariant for downstream consumers.

**Files:**
- Modify: `crates/rimap-audit/src/redact.rs` (doc-comment on the `Verbatim` enum variant)

- [ ] **Step 1.1:** Open `crates/rimap-audit/src/redact.rs` and locate the `FieldPolicy::Verbatim` variant doc-comment around lines 25–26.

- [ ] **Step 1.2:** Replace that doc-comment with a longer one that documents the upstream invariant.

```rust
    /// Copy the field's JSON value into the record unchanged. This policy
    /// assumes the value has already passed the `rimap-content` mailbox-name
    /// validator (no bare CR/LF, no NUL, no other ASCII control chars). The
    /// invariant matters for downstream consumers of the audit JSONL who
    /// pretty-print or grep the file: smuggled control bytes would surface
    /// as confusing output, and a permissive JSONL re-parser could
    /// re-introduce the bytes into a downstream sink.
    Verbatim,
```

- [ ] **Step 1.3:** Build to confirm the doc-comment compiles.

```bash
cargo build -p rimap-audit
```
Expected: compiles clean.

- [ ] **Step 1.4:** Commit.

```bash
git add crates/rimap-audit/src/redact.rs
git commit -m "$(cat <<'EOF'
docs(audit): document Verbatim control-char invariant

Closes #23
EOF
)"
```

## Task 2: #28 — `audit merge` umask runbook note

**Issue:** docs: audit merge stdout redirect inherits umask, recommend umask 077.

**Files:**
- Modify: `AGENTS.md` (add a note under whichever section discusses `audit merge`, or append a new "Operator notes — audit merge" subsection if no such section exists)

- [ ] **Step 2.1:** Read `AGENTS.md` and search for "audit merge" or "audit.merge" to find the right insertion point.

```bash
grep -n "audit merge" AGENTS.md || echo "(no existing reference — append at the end)"
```

- [ ] **Step 2.2:** Add the following block. If an existing section discusses `audit merge`, place the block immediately under it. Otherwise, append a new subsection at the end of `AGENTS.md` (before the trailing newline).

```markdown
### Operator notes — `audit merge`

`audit merge` re-emits records to stdout. When the output is redirected to a
file, the new file is created with the shell's current umask, which on most
systems is `0022` and produces a world-readable `0644` dump. Operators may
assume "audit log = `0600`" and not realize the merged dump isn't.

Recommended patterns:

```bash
# 1. Set a tight umask before the redirect:
umask 077 && rusty-imap-mcp audit merge … > dump.jsonl

# 2. Or pipe through `install` for an atomic mode-set:
rusty-imap-mcp audit merge … | install -m 0600 /dev/stdin /target/dump.jsonl
```
```

- [ ] **Step 2.3:** Verify the insertion does not break Markdown rendering by skimming the file.

```bash
wc -l AGENTS.md
```

- [ ] **Step 2.4:** Commit.

```bash
git add AGENTS.md
git commit -m "$(cat <<'EOF'
docs(audit): recommend umask 077 for audit merge redirects

Closes #28
EOF
)"
```

## Task 3: #36 — `read_audit_lines` panic on malformed JSON

**Issue:** test(imap): read_audit_lines silently drops malformed JSON records.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs:25-30`

- [ ] **Step 3.1:** Open `crates/rimap-imap/tests/integration/dovecot.rs` and replace the existing `read_audit_lines` helper with a version that surfaces parse errors instead of silently dropping them.

```rust
fn read_audit_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let s = std::fs::read_to_string(path).unwrap_or_default();
    s.lines()
        .enumerate()
        .map(|(idx, l)| {
            serde_json::from_str(l).unwrap_or_else(|e| {
                panic!("audit line {} failed to parse as JSON: {e}\nline: {l}", idx + 1)
            })
        })
        .collect()
}
```

- [ ] **Step 3.2:** Run the dovecot integration test suite to confirm the helper still parses every line in the existing fixture set. The container suite is gated behind `RIMAP_REQUIRE_DOCKER=1`; if no docker runtime is present locally, run with the env var unset and confirm the suite skips cleanly (the helper change is exercised inside the bodies that already require docker).

```bash
cargo test -p rimap-imap --test integration -- --nocapture 2>&1 | tail -40
```
Expected: either every case passes (docker present) or every case is silently skipped (docker absent). The helper change does not affect the skip path.

- [ ] **Step 3.3:** Commit.

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "$(cat <<'EOF'
test(imap): panic with line number when audit JSONL fails to parse

Surfaces "audit line N failed to parse" instead of dropping
malformed records into a silent filter, so future schema
regressions fail loudly.

Closes #36
EOF
)"
```

## Task 4: #37 — Inline comments on shared `audit.clone()` in case_04 / case_10

**Issue:** test(imap): document audit-writer sharing in case_04 and case_10 inline Connection rebuilds.

**Files:**
- Modify: `crates/rimap-imap/tests/integration/dovecot.rs` around `case_04_login_rejected_emits_audit` (~line 129) and `case_10_fetch_body_over_limit_drops_connection` (~line 259)

- [ ] **Step 4.1:** In `case_04_login_rejected_emits_audit`, find the line that constructs the inline `Connection`:

```rust
    let conn = Connection::new(cfg, h.audit.clone(), creds);
```
and prepend a comment immediately above it:

```rust
    // Reuse h.audit so the rejected-auth record lands in the same file
    // the audit assertions below read from. Opening a fresh AuditWriter
    // here would emit the record to a different file and break the test.
    let conn = Connection::new(cfg, h.audit.clone(), creds);
```

- [ ] **Step 4.2:** Repeat the same comment insertion in `case_10_fetch_body_over_limit_drops_connection` (the `Connection::new(cfg, h.audit.clone(), creds);` line near line 259):

```rust
    // Reuse h.audit so the size-limit / connection-loss records land in
    // the file the audit assertions below read from. The override here
    // is `max_fetch_body_bytes`, not the audit writer.
    let conn = Connection::new(cfg, h.audit.clone(), creds);
```

- [ ] **Step 4.3:** Build to confirm comments don't break anything (they shouldn't).

```bash
cargo build -p rimap-imap --tests
```

- [ ] **Step 4.4:** Commit.

```bash
git add crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "$(cat <<'EOF'
test(imap): document audit-writer sharing in case_04 and case_10

Closes #37
EOF
)"
```

## Batch 1 checkpoint

- [ ] **Step B1.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```
Expected: all green. If anything fails, do NOT proceed to Batch 2.

---

# Batch 2 — rimap-core and rimap-audit small fixes

## Task 5: #25 — `ToolName::all()` via `strum::EnumIter`

**Issue:** rimap-core: ToolName::all() compile-time parity via strum::EnumIter.

**Files:**
- Modify: `Cargo.toml` (add `strum` to `[workspace.dependencies]`)
- Modify: `crates/rimap-core/Cargo.toml` (add `strum` to deps)
- Modify: `crates/rimap-core/src/tool.rs` (derive `EnumIter`, replace `all()` body, add parity test)

- [ ] **Step 5.1:** Add `strum` to the workspace dependency block in `Cargo.toml` (currently around line 67–75 in the audit-log section). Insert in alphabetical order under a new "Misc" comment if no obvious home; the simplest spot is after `subtle = "2"`:

```toml
strum = { version = "0.26", features = ["derive"] }
```

- [ ] **Step 5.2:** Add the dep to `crates/rimap-core/Cargo.toml`. Read the file first to find the `[dependencies]` section, then add:

```toml
strum = { workspace = true }
```

- [ ] **Step 5.3:** Edit `crates/rimap-core/src/tool.rs`. Add the import and derive:

```rust
use strum::{EnumIter, IntoEnumIterator};
```
and add `EnumIter` to the existing derive list on `pub enum ToolName`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub enum ToolName {
```

- [ ] **Step 5.4:** Replace the body of `ToolName::all` (currently a hand-maintained `[Self; 13]` literal) with a `Vec<Self>` built from the iterator. The return type changes from `[Self; 13]` to `Vec<Self>`:

```rust
    /// Every v1 tool, in declaration order. Used for exhaustive matrix tests
    /// and for building the advertised-tools set in `list_tools`. Built from
    /// `EnumIter` so adding a new variant cannot silently desynchronize this
    /// list (compile-time parity).
    #[must_use]
    pub fn all() -> Vec<Self> {
        Self::iter().collect()
    }
```

- [ ] **Step 5.5:** Update the existing test `all_has_exactly_thirteen_variants` (line ~133) to use the iterator length, since the array length is gone:

```rust
    #[test]
    fn all_has_exactly_thirteen_variants() {
        assert_eq!(ToolName::all().len(), 13);
        assert_eq!(ToolName::iter().count(), 13);
    }
```

- [ ] **Step 5.6:** Update `FromStr for ToolName` (line ~110) — `for tool in Self::all()` already iterates correctly over the new `Vec<Self>` return type and needs no change. Verify by reading lines 110–124 after the edit.

- [ ] **Step 5.7:** Build and test the crate.

```bash
cargo build -p rimap-core
cargo test -p rimap-core
```
Expected: all green.

- [ ] **Step 5.8:** Confirm the redaction parity test in `rimap-audit` (which depends on `rimap-core::ToolName::all`) still passes:

```bash
cargo test -p rimap-audit redact::tests::every_v1_tool_has_a_schema
```
Expected: passes.

- [ ] **Step 5.9:** Run `cargo deny check` to confirm `strum` does not introduce a duplicate-version conflict.

```bash
cargo deny check 2>&1 | tail -30
```
Expected: no new advisories or duplicate bans.

- [ ] **Step 5.10:** Commit.

```bash
git add Cargo.toml Cargo.lock crates/rimap-core/Cargo.toml crates/rimap-core/src/tool.rs
git commit -m "$(cat <<'EOF'
feat(core): derive ToolName::all() from strum::EnumIter

Hand-maintained [Self; 13] array allowed adding a new variant
without updating all(), which would silently break the
every_v1_tool_has_a_schema parity test in rimap-audit.

Closes #25
EOF
)"
```

## Task 6: #26 — Tighten `ProvenanceBuffer` test seams to `pub(crate)`

**Issue:** rimap-audit: tighten ProvenanceBuffer test seams to pub(crate) + cfg(test) shim.

**Files:**
- Modify: `crates/rimap-audit/src/provenance.rs` (lines 66–67 and 100–101)

- [ ] **Step 6.1:** Open `crates/rimap-audit/src/provenance.rs`. Locate `record_at` (line ~67) and `snapshot_at` (line ~101). Both are currently `#[doc(hidden)] pub fn`.

- [ ] **Step 6.2:** Change both signatures from `pub fn` to `pub(crate) fn`. Drop the `#[doc(hidden)]` attribute since `pub(crate)` items are not part of the public docs anyway.

For `record_at`:

```rust
    /// Variant taking an explicit clock so eviction can be asserted
    /// deterministically. Applies the same length cap and count cap as
    /// [`record`](Self::record). Crate-private; tests inside `rimap-audit`
    /// see it via `pub(crate)`.
    pub(crate) fn record_at(&mut self, message_id: impl Into<String>, now: OffsetDateTime) {
```

For `snapshot_at`:

```rust
    /// Test-only snapshot with explicit clock. Crate-private; integration
    /// tests do not need this seam.
    pub(crate) fn snapshot_at(&mut self, now: OffsetDateTime) -> Vec<String> {
```

- [ ] **Step 6.3:** Run the unit tests in `provenance.rs` to confirm they still compile (they live in the same module and have crate-level access).

```bash
cargo test -p rimap-audit provenance::tests
```
Expected: all eight tests pass.

- [ ] **Step 6.4:** Verify no other crate or integration test references these functions. They are only used in the same module today.

```bash
rg 'record_at|snapshot_at' --type rust
```
Expected: hits only inside `crates/rimap-audit/src/provenance.rs`. If any callers exist elsewhere, STOP and report — the visibility tightening would break them.

- [ ] **Step 6.5:** Commit.

```bash
git add crates/rimap-audit/src/provenance.rs
git commit -m "$(cat <<'EOF'
refactor(audit): downgrade ProvenanceBuffer test seams to pub(crate)

record_at and snapshot_at took an explicit OffsetDateTime so
unit tests could assert eviction deterministically. They were
pub + #[doc(hidden)], which is greppable from production code.
The unit tests live in the same module and only need pub(crate).

Closes #26
EOF
)"
```

## Task 7: #34 — `RimapError::Audit` Display duplication

**Issue:** rimap-core: RimapError::Audit Display duplicates the source message in chain reporters.

**Files:**
- Modify: `crates/rimap-core/src/error.rs:92-104` (the `Audit` variant)

- [ ] **Step 7.1:** Read `crates/rimap-core/src/error.rs` lines 92–124 to confirm the current shape matches the issue description (it does — verified during plan writing).

- [ ] **Step 7.2:** Replace the `Audit` variant in the `RimapError` enum. The change is: format string switches from `{source}` to `{message}`, a new `message: String` field is added, and the `source` field shape is unchanged (still `Box<dyn Error>` with `#[source]`).

Old (lines 92–104):

```rust
    /// Audit log failure. Carries both the stable code (open-time errors
    /// map to `ErrorCode::Config`, runtime errors to `ErrorCode::Internal`)
    /// and the original `AuditError` via the source chain. The Display
    /// form includes the source's message so operators see the audit
    /// path and underlying I/O error.
    #[error("{code}: {source}")]
    Audit {
        /// Stable error code — `Config` for open-time, `Internal` for runtime.
        code: ErrorCode,
        /// The original audit error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
```

New:

```rust
    /// Audit log failure. Carries both the stable code (open-time errors
    /// map to `ErrorCode::Config`, runtime errors to `ErrorCode::Internal`)
    /// and the original `AuditError` via the source chain. `message` is
    /// the source's `to_string()` captured at construction time so the
    /// Display form does not double-print the source when reporters walk
    /// the chain.
    #[error("{code}: {message}")]
    Audit {
        /// Stable error code — `Config` for open-time, `Internal` for runtime.
        code: ErrorCode,
        /// Human-readable message captured from the source at construction.
        message: String,
        /// The original audit error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
```

- [ ] **Step 7.3:** Find every constructor of `RimapError::Audit` in the workspace and update it to populate `message`.

```bash
rg 'RimapError::Audit\s*\{' --type rust -n
```

For each hit, the existing call site looks like:

```rust
RimapError::Audit { code, source: Box::new(err) }
```

and must become:

```rust
let message = err.to_string();
RimapError::Audit { code, message, source: Box::new(err) }
```

If `err` is a value being moved into the box, capture `to_string()` BEFORE moving it.

- [ ] **Step 7.4:** Add a regression test in the existing `mod tests` block at the bottom of `crates/rimap-core/src/error.rs` that asserts `Display` does not duplicate the source message:

```rust
    #[test]
    fn rimap_error_audit_display_does_not_duplicate_source() {
        use std::io;

        let inner: Box<dyn std::error::Error + Send + Sync> =
            Box::new(io::Error::other("disk full"));
        let err = RimapError::Audit {
            code: ErrorCode::Internal,
            message: inner.to_string(),
            source: inner,
        };
        let displayed = err.to_string();
        // The display string should contain "disk full" exactly once.
        assert_eq!(displayed.matches("disk full").count(), 1);
        assert!(displayed.starts_with("ERR_INTERNAL: "));
    }
```

- [ ] **Step 7.5:** Build and test the workspace. Constructor updates may ripple through `rimap-server`, `rimap-imap`, or any other crate that produces `RimapError::Audit`.

```bash
cargo build --workspace
cargo test -p rimap-core
```
Expected: green. If a crate fails to compile because of a constructor that this task missed, fix it and re-test.

- [ ] **Step 7.6:** Commit.

```bash
git add crates/rimap-core/src/error.rs $(git diff --name-only)
git commit -m "$(cat <<'EOF'
fix(core): stop RimapError::Audit Display from duplicating source

Use the {message} pattern that the sibling Imap variant uses,
so reporters that walk the source chain don't print the same
audit-error message twice.

Closes #34
EOF
)"
```

## Batch 2 checkpoint

- [ ] **Step B2.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 3 — rimap-imap small fixes

## Task 8: #31 — `build_tls_config` returns `Result`

**Issue:** rimap-imap: build_tls_config should return Result instead of unreachable!() on WebPkiServerVerifier failures.

**Files:**
- Modify: `crates/rimap-imap/src/tls.rs` (function signature, three `unreachable!()` sites)
- Modify: `crates/rimap-imap/src/connection.rs:131-133` (caller in `connect_inner`)
- Modify: `crates/rimap-imap/src/error.rs` (consider whether `Error::TlsHandshake` already covers — see step 8.2)

- [ ] **Step 8.1:** Read `crates/rimap-imap/src/tls.rs:155-197` and `crates/rimap-imap/src/connection.rs:131-150` to refresh the current shape.

- [ ] **Step 8.2:** Decide on the error variant. `Error::TlsHandshake(rustls::Error)` already exists in `rimap-imap/src/error.rs:20-21` and maps to `ErrorCode::Tls`. Both failure points (`with_safe_default_protocol_versions()` and `WebPkiServerVerifier::builder.build()`) return a `rustls::Error`-shaped failure that is conceptually a TLS configuration error, so reuse `Error::TlsHandshake` rather than adding a new variant.

- [ ] **Step 8.3:** Replace the three `unreachable!()` sites in `tls.rs::build_tls_config`. New signature:

```rust
/// Build a `TlsConfigBundle`. If `pinned.is_some()`, uses `PinningVerifier`
/// (skips chain validation). Otherwise uses webpki-roots with
/// `CapturingVerifier`.
///
/// # Errors
/// - `Error::TlsHandshake` if rustls cannot construct a `ClientConfig` with
///   the workspace's safe default protocol versions (would only fire if a
///   future ring provider drops every cipher suite or kx group).
/// - `Error::TlsHandshake` if `WebPkiServerVerifier::builder.build()` fails
///   (would only fire if `webpki_roots::TLS_SERVER_ROOTS` is somehow empty,
///   e.g. a corrupt webpki-roots release).
pub fn build_tls_config(pinned: Option<TlsFingerprint>) -> Result<TlsConfigBundle, crate::error::Error> {
    let last_observed = Arc::new(OnceLock::new());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());

    let config = if let Some(pin) = pinned {
        let verifier = Arc::new(PinningVerifier {
            pinned: pin,
            last_observed: Arc::clone(&last_observed),
            provider: Arc::clone(&provider),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::Error::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let inner_verifier =
            tokio_rustls::rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|e| crate::error::Error::TlsHandshake(
                tokio_rustls::rustls::Error::General(format!(
                    "WebPkiServerVerifier builder failed: {e}"
                )),
            ))?;
        let capturing = Arc::new(CapturingVerifier {
            inner: inner_verifier,
            last_observed: Arc::clone(&last_observed),
        });
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(crate::error::Error::TlsHandshake)?
            .dangerous()
            .with_custom_certificate_verifier(capturing)
            .with_no_client_auth()
    };

    Ok(TlsConfigBundle {
        config: Arc::new(config),
        last_observed,
    })
}
```

Note: `with_safe_default_protocol_versions()` returns a `Result` whose `Err` is already `rustls::Error`, so `.map_err(Error::TlsHandshake)?` works directly. `WebPkiServerVerifier::builder.build()` returns a `VerifierBuilderError`, which is NOT `rustls::Error`, so it must be wrapped via `rustls::Error::General(format!(...))`.

- [ ] **Step 8.4:** Drop the `#[must_use]` attribute on `build_tls_config` since `Result` is already `must_use`.

- [ ] **Step 8.5:** Update the caller in `crates/rimap-imap/src/connection.rs`. Locate line 133:

```rust
        let bundle = build_tls_config(cfg.pinned_fingerprint);
```

Change to:

```rust
        let bundle = build_tls_config(cfg.pinned_fingerprint)?;
```

The surrounding `connect_inner` already returns `Result<ImapSession, Error>`, so the `?` is type-correct.

- [ ] **Step 8.6:** Build and run the rimap-imap test suite.

```bash
cargo build -p rimap-imap
cargo test -p rimap-imap --lib
```
Expected: green.

- [ ] **Step 8.7:** Commit.

```bash
git add crates/rimap-imap/src/tls.rs crates/rimap-imap/src/connection.rs
git commit -m "$(cat <<'EOF'
fix(imap): build_tls_config returns Result instead of unreachable!()

Both rustls APIs (with_safe_default_protocol_versions and
WebPkiServerVerifier::builder.build) return Err in principle.
The unreachable!() escape hatches were workspace-allowed but
violated the "fail fast with clear, actionable messages" guideline
and would surface as a process crash on a webpki-roots regression.

Closes #31
EOF
)"
```

## Task 9: #33 — Compress UID set to range syntax

**Issue:** rimap-imap: compress UID set to range syntax in ops::fetch::fetch (Dovecot 8KB command-line cap).

**Files:**
- Modify: `crates/rimap-imap/src/ops/fetch.rs:34-41` (replace the comma-join with a call to a new helper)
- Add: helper `compress_uid_set` in the same file
- Add: unit + property tests in the existing `mod tests` block at the bottom

- [ ] **Step 9.1:** Add a `proptest` dev-dep to `crates/rimap-imap/Cargo.toml` if not already present (workspace already declares `proptest = "1.6"`). Read `crates/rimap-imap/Cargo.toml` first to check.

```bash
grep -n proptest crates/rimap-imap/Cargo.toml || echo "(needs adding)"
```

If absent, add to `[dev-dependencies]`:

```toml
proptest = { workspace = true }
```

- [ ] **Step 9.2:** Open `crates/rimap-imap/src/ops/fetch.rs` and add the helper near the top of the file (after the constants block, around line 19):

```rust
/// Compress a slice of UIDs into IMAP `sequence-set` range syntax per
/// RFC 3501 §9. Runs of two or more contiguous UIDs become `start:end`;
/// isolated UIDs stay as bare numbers. Sorts the input first because
/// callers may pass unsorted UIDs.
///
/// Examples:
/// - `[]`              → `""`
/// - `[42]`            → `"42"`
/// - `[1, 3]`          → `"1,3"`
/// - `[1, 2, 3]`       → `"1:3"`
/// - `[1,2,3,5,7,8,9]` → `"1:3,5,7:9"`
fn compress_uid_set(uids: &[Uid]) -> String {
    if uids.is_empty() {
        return String::new();
    }

    let mut sorted: Vec<u32> = uids.iter().map(|u| u.get()).collect();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = String::new();
    let mut run_start = sorted[0];
    let mut run_end = sorted[0];

    for &uid in &sorted[1..] {
        if uid == run_end + 1 {
            run_end = uid;
        } else {
            emit_run(&mut out, run_start, run_end);
            run_start = uid;
            run_end = uid;
        }
    }
    emit_run(&mut out, run_start, run_end);
    out
}

fn emit_run(out: &mut String, start: u32, end: u32) {
    use std::fmt::Write as _;
    if !out.is_empty() {
        out.push(',');
    }
    if start == end {
        let _ = write!(out, "{start}");
    } else {
        let _ = write!(out, "{start}:{end}");
    }
}
```

- [ ] **Step 9.3:** Replace the `// TODO(T15)` block at lines 34–41 with a call to the helper:

```rust
    // Compress to IMAP sequence-set range syntax to stay under Dovecot's
    // ~8KB command-line cap. Plain comma-joined lists exceed the cap
    // around ~2000 UIDs.
    let uid_set = compress_uid_set(uids);
```

- [ ] **Step 9.4:** Add unit tests inside the existing `#[cfg(test)] mod tests` block at the bottom of `fetch.rs`. Find the existing `use super::{...}` line and extend it to include `compress_uid_set`:

```rust
    use super::{MAX_BODYSTRUCTURE_DEPTH, compress_uid_set, convert_bs_inner, project_size};
```

Then add these tests at the end of the module, before the closing `}`:

```rust
    fn uid(n: u32) -> crate::types::Uid {
        crate::types::Uid::new(n).unwrap()
    }

    #[test]
    fn compress_empty_input() {
        assert_eq!(compress_uid_set(&[]), "");
    }

    #[test]
    fn compress_single_uid() {
        assert_eq!(compress_uid_set(&[uid(42)]), "42");
    }

    #[test]
    fn compress_two_non_adjacent() {
        assert_eq!(compress_uid_set(&[uid(1), uid(3)]), "1,3");
    }

    #[test]
    fn compress_three_contiguous() {
        assert_eq!(compress_uid_set(&[uid(1), uid(2), uid(3)]), "1:3");
    }

    #[test]
    fn compress_mixed_runs_and_singletons() {
        let input = [uid(1), uid(2), uid(3), uid(5), uid(7), uid(8), uid(9)];
        assert_eq!(compress_uid_set(&input), "1:3,5,7:9");
    }

    #[test]
    fn compress_unsorted_input_is_sorted_first() {
        let input = [uid(9), uid(7), uid(8), uid(1), uid(2), uid(3), uid(5)];
        assert_eq!(compress_uid_set(&input), "1:3,5,7:9");
    }

    #[test]
    fn compress_duplicates_are_collapsed() {
        let input = [uid(1), uid(1), uid(2), uid(2), uid(3)];
        assert_eq!(compress_uid_set(&input), "1:3");
    }

    proptest::proptest! {
        #[test]
        fn compress_round_trip_via_split(
            mut uids in proptest::collection::vec(1_u32..=10_000_u32, 1..200)
        ) {
            uids.sort_unstable();
            uids.dedup();
            let typed: Vec<crate::types::Uid> =
                uids.iter().map(|n| crate::types::Uid::new(*n).unwrap()).collect();
            let compressed = compress_uid_set(&typed);

            // Parse the compressed form back into a sorted Vec<u32> and
            // assert it equals the input.
            let mut parsed: Vec<u32> = Vec::new();
            for chunk in compressed.split(',') {
                if let Some((lo, hi)) = chunk.split_once(':') {
                    let lo: u32 = lo.parse().unwrap();
                    let hi: u32 = hi.parse().unwrap();
                    for n in lo..=hi {
                        parsed.push(n);
                    }
                } else {
                    parsed.push(chunk.parse().unwrap());
                }
            }
            assert_eq!(parsed, uids);
        }
    }
```

- [ ] **Step 9.5:** Build and test.

```bash
cargo test -p rimap-imap --lib ops::fetch::tests
```
Expected: all unit tests + the proptest pass. The proptest may take a couple of seconds.

- [ ] **Step 9.6:** Run the integration suite if docker is available, to confirm the existing fetch cases still pass with compressed UID sets:

```bash
RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test integration -- case_08 case_09 2>&1 | tail -20
```
Skip this step (and note in the commit) if no docker runtime is available locally.

- [ ] **Step 9.7:** Commit.

```bash
git add crates/rimap-imap/Cargo.toml crates/rimap-imap/src/ops/fetch.rs
git commit -m "$(cat <<'EOF'
feat(imap): compress UID set to IMAP sequence-set range syntax

Plain comma-joined UID lists exceed Dovecot's default 8KB
command-line cap around 2000 UIDs. Compressing contiguous runs
to "start:end" cuts a 5000-UID dense list from ~30KB to ~10
bytes and stays under every reasonable server cap.

Adds compress_uid_set with unit + property-based round-trip
tests against the input sequence.

Closes #33
EOF
)"
```

## Task 10: #40 — Bump `webpki-roots` from `0.26` shim to `1.0`

**Issue:** deps: bump webpki-roots from 0.26 shim to 1.0 and drop the compatibility layer.

**Files:**
- Modify: `Cargo.toml:54` (workspace dep)
- Modify: `crates/rimap-imap/src/tls.rs:173` (the `extend(...)` call may need a constant rename)
- Cargo.lock (regenerated)
- `deny.toml` (only if the duplicate-version exception is no longer needed)

- [ ] **Step 10.1:** Bump the workspace dep in `Cargo.toml` from `webpki-roots = "0.26"` to:

```toml
webpki-roots = "1"
```

- [ ] **Step 10.2:** Run `cargo update -p webpki-roots` to refresh `Cargo.lock`.

```bash
cargo update -p webpki-roots
```

- [ ] **Step 10.3:** Build the workspace and observe whether `tls.rs:173` still compiles. The 1.0 release renamed the constant from `webpki_roots::TLS_SERVER_ROOTS` to `webpki_roots::TLS_SERVER_ROOT_CERTS` in some intermediate releases — verify by reading the upstream changelog or by attempting the build.

```bash
cargo build -p rimap-imap 2>&1 | tail -30
```

- [ ] **Step 10.4:** If the build fails on the `webpki_roots::TLS_SERVER_ROOTS.iter()` line, look up the new name. Fetch the docs:

```bash
# Use the context7 MCP server to look up current webpki-roots 1.x docs
```

Then update the line in `crates/rimap-imap/src/tls.rs` (currently around 173):

```rust
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
```

The most likely 1.0 form is unchanged (`TLS_SERVER_ROOTS` is the canonical export name), but if the type is now `&[TrustAnchor<'static>]` instead of `&[TrustAnchor<'_>]`, the `.cloned()` may need to become `.copied()` or be dropped entirely. Let the compiler guide you.

- [ ] **Step 10.5:** Run `cargo deny check` to confirm the duplicate-version warning for webpki-roots is gone.

```bash
cargo deny check 2>&1 | tail -30
```

- [ ] **Step 10.6:** If `deny.toml` had a skip entry for `webpki-roots` duplicates, remove it. Read the file first:

```bash
grep -n webpki-roots deny.toml || echo "(no entry)"
```

- [ ] **Step 10.7:** Run the TLS pinning test (lives in `crates/rimap-imap/tests/tls_pinning.rs`) and the full rimap-imap suite.

```bash
cargo test -p rimap-imap --test tls_pinning
cargo test -p rimap-imap --lib
```
Expected: green. The pinned-mode path doesn't actually consume the root store, but the unpinned path (CapturingVerifier) does.

- [ ] **Step 10.8:** Commit.

```bash
git add Cargo.toml Cargo.lock crates/rimap-imap/src/tls.rs deny.toml
git commit -m "$(cat <<'EOF'
deps: bump webpki-roots from 0.26 shim to 1.0

The 0.26 release was a compatibility re-export of 1.0; the
binary was carrying two copies of the Mozilla root trust store
plus the migration shim. Cargo-deny tolerated the duplicate
because 1.0's only dependent was the 0.26 shim, but it's wasted
bytes and tech debt.

Closes #40
EOF
)"
```

## Batch 3 checkpoint

- [ ] **Step B3.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 4 — Audit subsystem and config containment

## Task 11: #5 — Implement `rotate_keep` pruning under lock

**Issue:** audit: implement rotate_keep pruning under lock.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs` (add `rotate_keep` to `AuditOptions`, plumb into rotation call site)
- Modify: `crates/rimap-audit/src/rotation.rs` (extend `rotate_file` to take a `keep: usize` parameter and prune after a successful rename)
- Modify: `crates/rimap-server/src/audit_init.rs` (pass `audit_config.rotate_keep` through to `AuditOptions`)
- Modify: `crates/rimap-config/src/model.rs` (doc-comment on `rotate_keep` to call out the `0` semantic — may already have one; check first)
- Add: unit test in `crates/rimap-audit/src/rotation.rs::tests` and an integration assertion in `crates/rimap-audit/tests/rotation.rs`

- [ ] **Step 11.1:** Read `crates/rimap-config/src/model.rs` and find the `AuditConfig` struct. Confirm the `rotate_keep: u32` field exists with a default of 5.

- [ ] **Step 11.2:** Read `crates/rimap-server/src/audit_init.rs` (171 lines per the merge log) to find where it constructs `AuditOptions`. Note the variable name it uses for the loaded config so step 11.6 can reference it correctly.

- [ ] **Step 11.3:** Add `rotate_keep` to `AuditOptions` in `crates/rimap-audit/src/writer.rs:25-34`:

```rust
/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
    /// Number of rotated sibling files to keep on disk after a rotation.
    /// `0` means "keep none — delete every rotated sibling immediately
    /// after rotation". The default at the config layer is 5.
    pub rotate_keep: u32,
    /// First `Seq` value this writer will allocate. Callers compute this from
    /// `read_trailing_state(path).last_seq.map(Seq::next).unwrap_or(Seq::FIRST)`
    /// before calling `open`.
    pub initial_seq: crate::ids::Seq,
}
```

- [ ] **Step 11.4:** Store `rotate_keep` on the `AuditWriter` struct so the rotation call site has access to it. Modify the struct definition (around line 40):

```rust
#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    rotate_keep: u32,
    process_id: crate::ids::ProcessId,
    inner: Arc<Mutex<Inner>>,
}
```

And populate it in `AuditWriter::open` (around line 109):

```rust
        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            rotate_keep: opts.rotate_keep,
            process_id: crate::ids::ProcessId::new_now(),
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
                next_seq: opts.initial_seq,
            })),
        })
```

- [ ] **Step 11.5:** Update the rotation call site inside `write_record` (around line 209). Pass `self.rotate_keep` through:

```rust
        if self.rotate_bytes > 0 && guard.bytes_written >= self.rotate_bytes {
            let (new_buf, new_len) = crate::rotation::rotate_file(&self.path, self.rotate_keep)?;
            guard.buf = new_buf;
            guard.bytes_written = new_len;
            tracing::info!(path = %self.path.display(), "audit file rotated");
        }
```

- [ ] **Step 11.6:** Update `crates/rimap-server/src/audit_init.rs` to pass `rotate_keep` from the loaded config. The exact variable name depends on what step 11.2 found; the change is conceptually:

```rust
let opts = AuditOptions {
    path: audit_cfg.path.clone(),
    rotate_bytes: audit_cfg.rotate_bytes,
    rotate_keep: audit_cfg.rotate_keep,
    initial_seq,
};
```

If `rotate_keep` is `u32` in config and `AuditOptions::rotate_keep` is also `u32`, no conversion is needed.

- [ ] **Step 11.7:** Update every existing test that constructs `AuditOptions` to include the new field. Find them with:

```bash
rg 'AuditOptions\s*\{' --type rust -n
```

Each call site needs `rotate_keep: 0,` (or some other suitable test value) added.

- [ ] **Step 11.8:** Modify `rotate_file` in `crates/rimap-audit/src/rotation.rs:65-104` to accept the keep count and prune after the rename succeeds:

```rust
/// Perform the rename + new-file dance, then prune rotated siblings down to
/// `keep` newest. Returns the freshly-locked `File` for the new active path
/// (with an empty `BufWriter` wrapping it).
///
/// Pruning failures are logged via `tracing::warn!` and never propagated as
/// errors — a stale rotated file is not a write failure.
///
/// # Errors
/// Any I/O error during `rename`, `open`, or `try_lock_exclusive` surfaces as
/// [`AuditError::Rotate`] with a descriptive `reason`.
pub fn rotate_file(active: &Path, keep: u32) -> Result<(BufWriter<File>, u64), AuditError> {
    let dst = unique_rotated_path(active, OffsetDateTime::now_utc());
    std::fs::rename(active, &dst).map_err(|source| AuditError::Rotate {
        path: active.to_path_buf(),
        reason: format!("rename to {}: {source}", dst.display()),
    })?;

    let new_file = crate::fs_ext::writer_open_options()
        .open(active)
        .map_err(|source| AuditError::Rotate {
            path: active.to_path_buf(),
            reason: format!("open fresh file: {source}"),
        })?;

    crate::writer::set_file_mode_0600(&new_file);

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

    // Prune old rotated siblings best-effort. Failures here are logged
    // but never propagated — a stale file is not a write failure.
    prune_rotated_siblings(active, keep);

    Ok((BufWriter::new(new_file), 0))
}

/// Enumerate sibling files matching `<active_filename>.*`, sort by mtime
/// descending, and delete all but the `keep` newest. `keep == 0` deletes
/// every rotated sibling.
fn prune_rotated_siblings(active: &Path, keep: u32) {
    let parent = match active.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return,
    };
    let active_name = match active.file_name().and_then(|s| s.to_str()) {
        Some(n) => n,
        None => return,
    };
    let prefix = format!("{active_name}.");

    let entries = match std::fs::read_dir(parent) {
        Ok(it) => it,
        Err(err) => {
            tracing::warn!(
                parent = %parent.display(),
                error = %err,
                "audit rotate: read_dir failed during prune",
            );
            return;
        }
    };

    let mut siblings: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        // Skip the active file itself if its name happens to start with the
        // prefix (it never does — `active_name.` is strictly longer than
        // `active_name` — but be defensive).
        if path == active {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        siblings.push((mtime, path));
    }

    // Sort newest-first.
    siblings.sort_by(|a, b| b.0.cmp(&a.0));

    let keep_usize = usize::try_from(keep).unwrap_or(usize::MAX);
    for (_, path) in siblings.into_iter().skip(keep_usize) {
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "audit rotate: failed to delete stale rotated sibling",
            );
        }
    }
}
```

- [ ] **Step 11.9:** Add a unit test in the existing `mod tests` block in `rotation.rs`. Place it after `unique_rotated_path_appends_counter_when_base_exists`:

```rust
    use crate::rotation::rotate_file;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn rotate_file_prunes_to_keep_newest_siblings() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");

        // Seed an initial active file.
        std::fs::write(&active, b"first\n").unwrap();

        // Rotate seven times. Each rotation produces one new sibling.
        // Sleep a millisecond between iterations so mtimes are distinct
        // even on filesystems with millisecond resolution.
        for _ in 0..7 {
            // Each rotation moves the current active to a sibling and
            // creates a fresh empty active. Prepopulate with content
            // so the next rotation has something to move.
            std::fs::write(&active, b"x\n").unwrap();
            let (_buf, _len) = rotate_file(&active, 3).unwrap();
            sleep(Duration::from_millis(2));
        }

        // After 7 rotations with keep=3, expect exactly 3 rotated siblings
        // plus the active file = 4 total.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("audit.jsonl"))
                    .unwrap_or(false)
            })
            .collect();
        let rotated = entries
            .iter()
            .filter(|e| e.file_name() != "audit.jsonl")
            .count();
        assert_eq!(rotated, 3, "expected exactly 3 rotated siblings");
        assert!(active.exists(), "active file still present");
    }

    #[test]
    fn rotate_file_with_keep_zero_deletes_all_siblings() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("audit.jsonl");
        std::fs::write(&active, b"x\n").unwrap();
        let (_buf, _len) = rotate_file(&active, 0).unwrap();

        let rotated = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("audit.jsonl.") && n != "audit.jsonl")
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(rotated, 0, "keep=0 should leave no rotated siblings");
    }
```

- [ ] **Step 11.10:** The existing integration test `crates/rimap-audit/tests/rotation.rs` may construct `AuditOptions` directly. Open it and add `rotate_keep: 0` (or a suitable value) to every constructor.

- [ ] **Step 11.11:** Build and run all audit tests.

```bash
cargo build -p rimap-audit
cargo test -p rimap-audit
```
Expected: green.

- [ ] **Step 11.12:** Build the workspace to confirm `rimap-server::audit_init` compiles with the new field.

```bash
cargo build --workspace
```

- [ ] **Step 11.13:** Commit.

```bash
git add Cargo.lock crates/rimap-audit crates/rimap-server/src/audit_init.rs
git commit -m "$(cat <<'EOF'
feat(audit): prune rotated siblings to rotate_keep newest under lock

The rotate_keep field has lived in AuditConfig with default 5
since Sprint 2 but was never plumbed through to the rotation
call site. Long-running servers accumulated rotated siblings
indefinitely. Pruning runs inside the writer lock so concurrent
rotations cannot race; each delete is best-effort and logs a
warn on failure (stale files are not write failures). keep=0
means "delete every rotated sibling immediately".

Closes #5
EOF
)"
```

## Task 12: #6 — Windows parity for inode tamper signal

**Issue:** audit: Windows parity for inode tamper signal.

**Files:**
- Modify: `crates/rimap-audit/src/self_check.rs:175-184` (add a `#[cfg(windows)]` arm to `inode_of`)
- Modify: `crates/rimap-audit/tests/inode_change.rs` (drop the `#[cfg(unix)]` gate)

- [ ] **Step 12.1:** Replace the existing `#[cfg(not(unix))] fn inode_of` stub in `self_check.rs:181-184` with explicit Unix and Windows arms, and a default catch-all stub:

```rust
#[cfg(unix)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.ino()
}

#[cfg(windows)]
fn inode_of(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    // file_index is the NTFS file reference number — stable across
    // OpenOptions re-opens of the same file. Returns Option<u64>; None
    // on filesystems that don't support file indices (ReFS, FAT32, some
    // network filesystems). Treat None as 0 = "unknown", which the
    // tamper-signal logic interprets as "do not flag".
    meta.file_index().unwrap_or(0)
}

#[cfg(not(any(unix, windows)))]
fn inode_of(_meta: &std::fs::Metadata) -> u64 {
    0
}
```

- [ ] **Step 12.2:** Update the doc-comment on `current_inode` (line ~162) to document the Windows behavior and the ReFS/FAT32 caveat:

```rust
/// Returns the current inode of `path`. On Unix, this is the POSIX `ino`
/// from `stat`. On Windows, this is the NTFS file reference number from
/// `MetadataExt::file_index`, which is stable across re-opens of the same
/// file. ReFS, FAT32, and some network filesystems do not provide a stable
/// file index — `file_index` returns `None` and this function returns `0`,
/// which the tamper-signal logic interprets as "unknown, do not flag".
/// Returns `0` on platforms that are neither Unix nor Windows.
///
/// # Errors
/// I/O error reading metadata.
pub fn current_inode(path: &Path) -> Result<u64, AuditError> {
```

- [ ] **Step 12.3:** Open `crates/rimap-audit/tests/inode_change.rs`, find the `#[cfg(unix)]` attribute at the top of the file (or on the test function), and remove it. The test now applies on both Unix and Windows.

```bash
grep -n 'cfg(unix)' crates/rimap-audit/tests/inode_change.rs
```

Edit each match to drop the gate. If the test imports anything Unix-specific (e.g. `std::os::unix::fs::MetadataExt`), wrap those imports in `#[cfg(unix)]` instead, or rewrite the test to use the public `current_inode` API.

- [ ] **Step 12.4:** Build on the local platform (macOS) and run the audit test suite.

```bash
cargo build -p rimap-audit
cargo test -p rimap-audit
```
Expected: green. The Windows arm cannot be exercised locally; CI must verify.

- [ ] **Step 12.5:** Commit.

```bash
git add crates/rimap-audit/src/self_check.rs crates/rimap-audit/tests/inode_change.rs
git commit -m "$(cat <<'EOF'
feat(audit): implement Windows file_index for inode tamper signal

std::os::windows::fs::MetadataExt::file_index returns the NTFS
file reference number, stable across re-opens of the same file.
That is enough for the audit_file_inode_changed tamper signal
to detect "the file was deleted and recreated between runs".
ReFS / FAT32 / network filesystems are documented as a caveat
(file_index returns None there, mapped to 0 = "do not flag").

Drops the #[cfg(unix)] gate from the inode_change integration
test so CI can verify on a Windows runner.

Closes #6
EOF
)"
```

## Task 13: #7 — Honor `audit.fail_open` in writer error paths

**Issue:** audit: honor audit.fail_open escape hatch in writer error paths.

**Files:**
- Modify: `crates/rimap-audit/src/writer.rs` (add `fail_open` to `AuditOptions`, store on `AuditWriter`, gate write/flush/fsync errors, add suppressed counter)
- Modify: `crates/rimap-server/src/audit_init.rs` (pass `fail_open` from config)
- Modify: `crates/rimap-config/src/model.rs` (doc-comment cross-link to security model — only if it's not already there)
- Add: tests in `crates/rimap-audit/src/writer.rs::tests` for both modes

- [ ] **Step 13.1:** Read `crates/rimap-config/src/model.rs` and confirm `AuditConfig::fail_open: bool` already exists with default `false`. (Verified during plan writing — it does, line 196 of validate.rs test fixture.)

- [ ] **Step 13.2:** Add `fail_open` to `AuditOptions` in `crates/rimap-audit/src/writer.rs`:

```rust
/// Options for opening an audit writer.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Path to the active audit file.
    pub path: PathBuf,
    /// Rotate when the file exceeds this many bytes. `0` disables rotation.
    pub rotate_bytes: u64,
    /// Number of rotated sibling files to keep on disk after a rotation.
    pub rotate_keep: u32,
    /// If `true`, write/flush/fsync failures inside `write_record` are
    /// logged via `tracing::error!` and converted to `Ok(())` so the
    /// surrounding tool call still succeeds. The default is `false`
    /// (a write failure fails the tool call). Operators who explicitly
    /// accept losing audit records on storage failures opt in via this
    /// flag — see the audit security model docs for the trade-off.
    pub fail_open: bool,
    /// First `Seq` value this writer will allocate.
    pub initial_seq: crate::ids::Seq,
}
```

- [ ] **Step 13.3:** Add `fail_open` and a suppressed-failures counter to the `AuditWriter` struct:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct AuditWriter {
    path: PathBuf,
    rotate_bytes: u64,
    rotate_keep: u32,
    fail_open: bool,
    process_id: crate::ids::ProcessId,
    suppressed_failures: Arc<AtomicU64>,
    inner: Arc<Mutex<Inner>>,
}
```

(Note: `AtomicU64` already cloneable via `Arc`. The `use std::sync::atomic` line goes near the existing `use std::sync::{Arc, Mutex};` at the top.)

Initialize in `open` (around line 109):

```rust
        Ok(Self {
            path: opts.path.clone(),
            rotate_bytes: opts.rotate_bytes,
            rotate_keep: opts.rotate_keep,
            fail_open: opts.fail_open,
            process_id: crate::ids::ProcessId::new_now(),
            suppressed_failures: Arc::new(AtomicU64::new(0)),
            inner: Arc::new(Mutex::new(Inner {
                buf: BufWriter::new(file),
                bytes_written,
                next_seq: opts.initial_seq,
            })),
        })
```

- [ ] **Step 13.4:** Wrap the body of `write_record` (lines 196–229) in a helper that returns `Result<(), AuditError>` and gate the result on `fail_open`. New shape:

```rust
    /// Serialize `record` as one JSONL line, append it to the active file,
    /// flush the buffer, and fsync on `process_*` / `auth` / `config` kinds.
    ///
    /// If `fail_open` is `true`, write/flush/fsync failures are logged via
    /// `tracing::error!` and converted to `Ok(())`. Suppressed failures are
    /// counted via [`Self::suppressed_failures`] for the next `process_end`
    /// record.
    ///
    /// # Errors
    /// - [`AuditError::Serialize`] on JSON failure (never suppressed —
    ///   serialization errors are bugs, not storage failures).
    /// - [`AuditError::Write`] / [`AuditError::Fsync`] when `fail_open == false`.
    pub fn write_record(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        match self.write_record_inner(record) {
            Ok(()) => Ok(()),
            Err(AuditError::Serialize(e)) => {
                // Serialization failures are programmer errors, not storage
                // failures. Never suppressed regardless of fail_open.
                Err(AuditError::Serialize(e))
            }
            Err(err) if self.fail_open => {
                tracing::error!(
                    path = %self.path.display(),
                    error = %err,
                    "audit write failed; fail_open=true so suppressing and continuing",
                );
                self.suppressed_failures.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    fn write_record_inner(&self, record: &crate::record::AuditRecord) -> Result<(), AuditError> {
        let mut bytes = serde_json::to_vec(record).map_err(AuditError::Serialize)?;
        bytes.push(b'\n');

        let mut guard = self.inner.lock().map_err(|_| AuditError::Write {
            path: self.path.clone(),
            source: std::io::Error::other("audit mutex poisoned"),
        })?;

        if self.rotate_bytes > 0 && guard.bytes_written >= self.rotate_bytes {
            let (new_buf, new_len) = crate::rotation::rotate_file(&self.path, self.rotate_keep)?;
            guard.buf = new_buf;
            guard.bytes_written = new_len;
            tracing::info!(path = %self.path.display(), "audit file rotated");
        }

        do_write_locked(&mut guard, &bytes, &self.path)?;

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

    /// Number of write/flush/fsync failures suppressed by `fail_open = true`
    /// since this writer was opened. Read by `process_end` to populate the
    /// `audit_write_failures_suppressed` field. Always `0` when `fail_open`
    /// is false.
    #[must_use]
    pub fn suppressed_failures(&self) -> u64 {
        self.suppressed_failures.load(Ordering::Relaxed)
    }
```

- [ ] **Step 13.5:** Update `crates/rimap-server/src/audit_init.rs` to pass `fail_open` from config. Same pattern as Task 11 step 11.6:

```rust
let opts = AuditOptions {
    path: audit_cfg.path.clone(),
    rotate_bytes: audit_cfg.rotate_bytes,
    rotate_keep: audit_cfg.rotate_keep,
    fail_open: audit_cfg.fail_open,
    initial_seq,
};
```

- [ ] **Step 13.6:** Add `fail_open: false,` to every existing `AuditOptions` constructor in tests. The same `rg 'AuditOptions\s*\{'` from Task 11 step 11.7 will find them again.

- [ ] **Step 13.7:** Add three tests in the existing `crates/rimap-audit/src/writer.rs::tests` block:

```rust
    #[test]
    fn fail_open_false_returns_write_error_on_storage_failure() {
        // Construct a writer, drop the parent dir's permission to write,
        // then attempt to log. The write should fail.
        // The most portable way to deterministically force a write failure
        // is to truncate the inner File handle externally — but that races
        // with the BufWriter. Instead, hold the writer, then drop it and
        // verify suppressed_failures is 0 (proving the path was Ok up to
        // that point). For the actual error path, see the integration test
        // tests/fail_open.rs (added below in step 13.8).
    }

    #[test]
    fn fail_open_true_increments_suppressed_counter() {
        // Same caveat — see tests/fail_open.rs.
    }
```

The deterministic test seam is hard to wire purely inside `writer.rs::tests` because the failure has to happen inside the BufWriter, which we cannot easily corrupt without `unsafe`. Move the tests to a dedicated integration test file in step 13.8.

- [ ] **Step 13.8:** Create `crates/rimap-audit/tests/fail_open.rs` with deterministic write-failure tests. The technique: open the audit writer in a tempdir, then `chmod 0500` (or platform equivalent) the parent directory and force a rotation by writing past `rotate_bytes`. The rotation rename will fail, surfacing as `AuditError::Rotate` from `write_record`. Verify the gating.

```rust
//! Integration tests for the `fail_open` escape hatch on `AuditWriter`.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::expect_used, reason = "tests")]

use std::os::unix::fs::PermissionsExt;

use rimap_audit::{AuditOptions, AuditWriter};
use rimap_audit::ids::{ProcessId, Seq, Timestamp};
use rimap_audit::record::{AuditRecord, Payload, ProcessEnd, ProcessEndReason};
use tempfile::TempDir;

fn make_record(seq: u64) -> AuditRecord {
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

fn lock_parent_readonly(parent: &std::path::Path) {
    let mut perms = std::fs::metadata(parent).unwrap().permissions();
    perms.set_mode(0o500); // r-x------
    std::fs::set_permissions(parent, perms).unwrap();
}

fn unlock_parent(parent: &std::path::Path) {
    let mut perms = std::fs::metadata(parent).unwrap().permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(parent, perms).unwrap();
}

#[test]
fn fail_open_false_propagates_rotation_failure() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 50,
        rotate_keep: 5,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .unwrap();

    // Lock the parent dir so the rotation rename will fail.
    lock_parent_readonly(dir.path());

    // Write enough bytes to trigger rotation. The first write may succeed
    // (no rotation yet); the second triggers rotation, which fails because
    // the parent dir is read-only.
    let r1 = writer.write_record(&make_record(1));
    let r2 = writer.write_record(&make_record(2));

    // Restore perms before TempDir::drop tries to clean up.
    unlock_parent(dir.path());

    // At least one of r1/r2 must be Err with fail_open=false. Both could
    // succeed if the rotation threshold is not crossed; if so, this test
    // is invalid and the rotate_bytes constant needs lowering.
    assert!(
        r1.is_err() || r2.is_err(),
        "expected at least one write to fail with fail_open=false"
    );
    assert_eq!(writer.suppressed_failures(), 0);
}

#[test]
fn fail_open_true_suppresses_rotation_failure_and_counts_it() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(&AuditOptions {
        path: path.clone(),
        rotate_bytes: 50,
        rotate_keep: 5,
        fail_open: true,
        initial_seq: Seq::FIRST,
    })
    .unwrap();

    lock_parent_readonly(dir.path());

    let r1 = writer.write_record(&make_record(1));
    let r2 = writer.write_record(&make_record(2));

    unlock_parent(dir.path());

    // Both writes return Ok under fail_open=true, even though the
    // rotation failed.
    assert!(r1.is_ok());
    assert!(r2.is_ok());
    // At least one rotation failure was suppressed.
    assert!(
        writer.suppressed_failures() >= 1,
        "expected suppressed_failures >= 1, got {}",
        writer.suppressed_failures()
    );
}
```

- [ ] **Step 13.9:** Build and run the audit suite, including the new integration test.

```bash
cargo test -p rimap-audit --test fail_open
cargo test -p rimap-audit
```
Expected: green.

- [ ] **Step 13.10:** Commit.

```bash
git add crates/rimap-audit crates/rimap-server/src/audit_init.rs Cargo.lock
git commit -m "$(cat <<'EOF'
feat(audit): honor audit.fail_open escape hatch in write_record

When fail_open is true, write/flush/fsync failures are logged
via tracing::error! and converted to Ok(()) so the surrounding
tool call still succeeds. Suppressed failures are counted via
an AtomicU64 for the next process_end record (Sprint 5 wires
the field). Default remains fail_open=false.

Closes #7
EOF
)"
```

## Task 14: #29 — Canonicalize and contain `audit.path`

**Issue:** rimap-config: canonicalize and contain audit.path from config.

**Files:**
- Modify: `crates/rimap-config/src/validate.rs` (canonicalize after permission check, add containment under XDG_STATE_HOME by default with explicit opt-out)
- Modify: `crates/rimap-config/src/model.rs` (add `audit.base_dir` field with default None — see step 14.2 for naming)
- Modify: `crates/rimap-config/src/error.rs` (add `AuditPathOutsideBase` variant)
- Add: tests covering canonicalize and containment

- [ ] **Step 14.1:** Read `crates/rimap-config/src/model.rs::AuditConfig` to confirm the current shape and pick a field name. The rest of this task uses `audit.allowed_base_dir: Option<PathBuf>` (None = use default).

- [ ] **Step 14.2:** Add the field to `AuditConfig` in `model.rs`:

```rust
    /// Optional containment base for `audit.path`. When set, `audit.path`
    /// must canonicalize to a path under this base, or config validation
    /// fails. When None, the default is `$XDG_STATE_HOME/rusty-imap-mcp/`
    /// (or platform equivalent). Set to `audit.allowed_base_dir = "/"`
    /// to opt out of containment entirely (NOT recommended).
    #[serde(default)]
    pub allowed_base_dir: Option<PathBuf>,
```

- [ ] **Step 14.3:** Add a new `ConfigError` variant for the containment failure in `crates/rimap-config/src/error.rs`. Read the file first to find the existing enum and follow its pattern.

```rust
    /// `audit.path` resolved outside the configured `allowed_base_dir`.
    #[error("audit path {path} is not contained in allowed base {base}")]
    AuditPathOutsideBase {
        /// The canonicalized audit path.
        path: PathBuf,
        /// The canonicalized base directory.
        base: PathBuf,
    },
```

- [ ] **Step 14.4:** Add a containment helper in `validate.rs`. Place it near `require_writable_dir`:

```rust
/// Compute the default audit base when `audit.allowed_base_dir` is unset.
/// Returns `$XDG_STATE_HOME/rusty-imap-mcp/` on platforms where
/// `directories::ProjectDirs` resolves; falls back to the current
/// directory otherwise (which is permissive but never panics).
fn default_audit_base() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "rusty-imap-mcp")?;
    Some(dirs.data_local_dir().to_path_buf())
}

/// Canonicalize the audit path and verify it is contained in the allowed
/// base. Called after `require_writable_dir` so the parent dir is known to
/// exist. Canonicalize-then-contain (not contain-then-canonicalize) is
/// chosen because canonicalize-then-check is itself TOCTOU-prone for
/// containment-by-string-prefix.
fn enforce_audit_containment(config: &Config) -> Result<(), ConfigError> {
    let audit_path = &config.audit.path;
    // The parent dir already exists (require_writable_dir ran first).
    // Canonicalize via the parent so the file itself does not need to
    // exist yet.
    let parent = audit_path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    let canon_parent = std::fs::canonicalize(parent).map_err(|e| ConfigError::PathNotWritable {
        path: parent.to_path_buf(),
        reason: format!("canonicalize parent: {e}"),
    })?;
    let file_name = audit_path
        .file_name()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "audit path has no file name".to_string(),
        })?;
    let canon_path = canon_parent.join(file_name);

    let base = config
        .audit
        .allowed_base_dir
        .clone()
        .or_else(default_audit_base)
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: audit_path.clone(),
            reason: "no allowed_base_dir configured and platform default unavailable".to_string(),
        })?;
    let canon_base = std::fs::canonicalize(&base).map_err(|e| ConfigError::PathNotWritable {
        path: base.clone(),
        reason: format!("canonicalize allowed_base_dir: {e}"),
    })?;

    if !canon_path.starts_with(&canon_base) {
        return Err(ConfigError::AuditPathOutsideBase {
            path: canon_path,
            base: canon_base,
        });
    }
    Ok(())
}
```

- [ ] **Step 14.5:** Wire `enforce_audit_containment` into `validate_paths` (line 115 of `validate.rs`):

```rust
fn validate_paths(config: &Config) -> Result<(), ConfigError> {
    let audit_parent = config
        .audit
        .path
        .parent()
        .ok_or_else(|| ConfigError::PathNotWritable {
            path: config.audit.path.clone(),
            reason: "audit path has no parent directory".to_string(),
        })?;
    require_writable_dir(audit_parent)?;
    enforce_audit_containment(config)?;
    if !config.attachments.download_dir.is_empty() {
        require_writable_dir(Path::new(&config.attachments.download_dir))?;
    }
    Ok(())
}
```

- [ ] **Step 14.6:** Add `directories` to `crates/rimap-config/Cargo.toml` if not already there. Read first; if absent:

```toml
directories = { workspace = true }
```

- [ ] **Step 14.7:** Update the existing `base_config` test fixture in `validate.rs::tests` so its audit path is contained inside the tempdir (which is what tests pass) and add `allowed_base_dir: Some(audit_dir.to_path_buf())` to the `AuditConfig`. Existing tests that already use `audit_dir.join("audit.jsonl")` will work as long as the base is set to `audit_dir`.

```rust
    fn base_config(audit_dir: &std::path::Path) -> Config {
        Config {
            // ...
            audit: AuditConfig {
                path: audit_dir.join("audit.jsonl"),
                rotate_bytes: 10_485_760,
                rotate_keep: 5,
                provenance_window_seconds: 60,
                fail_open: false,
                allowed_base_dir: Some(audit_dir.to_path_buf()),
            },
            // ...
        }
    }
```

- [ ] **Step 14.8:** Add three new tests:

```rust
    #[test]
    fn audit_path_inside_allowed_base_passes() {
        let dir = TempDir::new().unwrap();
        let cfg = base_config(dir.path());
        validate(cfg).unwrap();
    }

    #[test]
    fn audit_path_outside_allowed_base_fails() {
        // Two separate tempdirs: base in `base`, audit path in `outside`.
        let base = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let mut cfg = base_config(outside.path());
        // Override the base to point at `base`, not `outside`.
        cfg.audit.allowed_base_dir = Some(base.path().to_path_buf());
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }

    #[test]
    fn audit_path_with_traversal_segments_is_canonicalized_before_containment() {
        // Build an audit path that uses ".." traversal to escape the base.
        let base = TempDir::new().unwrap();
        let nested = base.path().join("inner");
        std::fs::create_dir_all(&nested).unwrap();
        let mut cfg = base_config(&nested);
        // Path with "../../" attempting to escape:
        cfg.audit.path = nested.join("..").join("..").join("escape.jsonl");
        cfg.audit.allowed_base_dir = Some(nested);
        let err = validate(cfg).unwrap_err();
        assert!(matches!(err, ConfigError::AuditPathOutsideBase { .. }));
    }
```

- [ ] **Step 14.9:** Build and test.

```bash
cargo build -p rimap-config
cargo test -p rimap-config
```
Expected: green.

- [ ] **Step 14.10:** Build the workspace to ensure `rimap-server` (which loads config) still compiles.

```bash
cargo build --workspace
cargo test --workspace --no-fail-fast
```

The full workspace test may surface failures in `rimap-server::audit_init` or its tests if they construct `AuditConfig` literals without the new field. Add `allowed_base_dir: None,` (or a tempdir-rooted base) to those call sites.

- [ ] **Step 14.11:** Commit.

```bash
git add crates/rimap-config Cargo.lock $(git diff --name-only)
git commit -m "$(cat <<'EOF'
feat(config): canonicalize and contain audit.path

audit.path is now canonicalized after the writability check and
required to live under audit.allowed_base_dir (default
$XDG_STATE_HOME/rusty-imap-mcp/). Path-traversal attempts that
escape the base via .. segments are rejected with a dedicated
ConfigError::AuditPathOutsideBase variant. Operators with a
genuine non-default location can opt in by setting
allowed_base_dir explicitly.

Closes #29
EOF
)"
```

## Batch 4 checkpoint

- [ ] **Step B4.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 5 — Error-variant chain (depends on #34 from Batch 2)

## Task 15: #39 — Surface `emit_auth` failure as `Error::Audit`

**Issue:** imap: emit_auth failure on success path should surface as a distinct Error::Audit, not discard the session silently.

**Files:**
- Modify: `crates/rimap-imap/src/error.rs` (add `Error::Audit` variant + `From` mapping update)
- Modify: `crates/rimap-imap/src/connection.rs` (update `emit_auth`, the `connect_inner` success arm, and `error_code_for`; update the exhaustive `should_invalidate` match in `fetch_body`)

- [ ] **Step 15.1:** Add a new variant to `rimap_imap::Error` in `crates/rimap-imap/src/error.rs`. Insert between `InvalidInput` and the closing brace:

```rust
    /// Audit-subsystem failure during a tool call. The IMAP transport may
    /// be healthy; this variant exists so audit-write failures stay
    /// distinguishable from network failures in metrics and observability.
    #[error("ERR_AUDIT: {message}")]
    Audit {
        /// Short identifier of the audit operation that failed
        /// (e.g. `"emit_auth"`).
        op: &'static str,
        /// Human-readable failure summary captured at construction.
        message: String,
        /// Underlying error from the audit subsystem.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
```

- [ ] **Step 15.2:** Update the `From<Error> for RimapError` impl at the bottom of `error.rs` to map `Error::Audit` to `ErrorCode::Internal` (not `ConnectionLost`). Add the new arm:

```rust
impl From<Error> for RimapError {
    fn from(err: Error) -> Self {
        let code = match &err {
            Error::Tls { .. } | Error::TlsHandshake(_) => ErrorCode::Tls,
            Error::Connect(_) | Error::ConnectionLost => ErrorCode::ConnectionLost,
            Error::Timeout { .. } => ErrorCode::Timeout,
            Error::Auth { .. } => ErrorCode::Auth,
            Error::SizeLimit { .. } => ErrorCode::AttachmentTooLarge,
            Error::Protocol(_) => ErrorCode::ImapProtocol,
            Error::InvalidInput { .. } => ErrorCode::InvalidInput,
            Error::Audit { .. } => ErrorCode::Internal,
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

(Note: this routes `Error::Audit` through `RimapError::Imap` rather than `RimapError::Audit`. The latter is owned by the audit subsystem proper; this `Error::Audit` is the IMAP-side wrapper. The split keeps the `From` impl flat.)

- [ ] **Step 15.3:** Update `Connection::emit_auth` (`connection.rs:286-301`) to construct `Error::Audit` instead of `Error::Connect(io::Error::other(...))`:

```rust
    /// Emit an `Auth` audit record. Runs `AuditWriter::log_auth` inside
    /// `spawn_blocking` so the `std::sync::Mutex` inside `AuditWriter` is
    /// never held across an `.await` boundary. Audit failures are mapped
    /// to `Error::Audit` (not `Error::Connect`) so observability can tell
    /// audit-storage failures from network failures.
    async fn emit_auth(&self, record: Auth) -> Result<(), Error> {
        let audit = self.inner.audit.clone();
        let join_result = tokio::task::spawn_blocking(move || audit.log_auth(record))
            .await;
        match join_result {
            Err(join_err) => Err(Error::Audit {
                op: "emit_auth",
                message: format!("audit join error: {join_err}"),
                source: Box::new(join_err),
            }),
            Ok(Err(audit_err)) => {
                tracing::error!(
                    error = %audit_err,
                    "audit log_auth failed; converting to Error::Audit",
                );
                let message = audit_err.to_string();
                Err(Error::Audit {
                    op: "emit_auth",
                    message,
                    source: Box::new(audit_err),
                })
            }
            Ok(Ok(_seq)) => Ok(()),
        }
    }
```

- [ ] **Step 15.4:** Update `error_code_for` in `connection.rs:523-533` (the function that maps `Error` variants to short audit-record error-code strings) to add `Error::Audit`:

```rust
fn error_code_for(err: &Error) -> &'static str {
    match err {
        Error::Tls { .. } | Error::TlsHandshake(_) => "ERR_TLS",
        Error::Connect(_) | Error::ConnectionLost => "ERR_NETWORK",
        Error::Timeout { .. } => "ERR_TIMEOUT",
        Error::Auth { .. } => "ERR_AUTH",
        Error::SizeLimit { .. } => "ERR_ATTACHMENT_TOO_LARGE",
        Error::Protocol(_) => "ERR_IMAP_PROTOCOL",
        Error::InvalidInput { .. } => "ERR_INVALID_INPUT",
        Error::Audit { .. } => "ERR_AUDIT",
    }
}
```

- [ ] **Step 15.5:** Update the exhaustive `should_invalidate` match in `fetch_body` (`connection.rs:472-484`). The workspace lints ban wildcard arms, so the new variant must be listed explicitly:

```rust
        let should_invalidate = match &result {
            Err(Error::ConnectionLost | Error::SizeLimit { .. }) => true,
            Err(
                Error::Tls { .. }
                | Error::TlsHandshake(_)
                | Error::Connect(_)
                | Error::Timeout { .. }
                | Error::Auth { .. }
                | Error::Protocol(_)
                | Error::InvalidInput { .. }
                | Error::Audit { .. },
            )
            | Ok(_) => false,
        };
```

- [ ] **Step 15.6:** The success-path call site in `connect_inner` (`connection.rs:162-169`) already propagates `emit_auth` errors via `?`. Now that `emit_auth` returns `Error::Audit` on failure, the propagation does the right thing automatically. Verify by reading those lines and confirming no further change is needed:

```bash
sed -n '160,175p' crates/rimap-imap/src/connection.rs
```

Note: do NOT actually edit this section; the existing `?` is now correct.

- [ ] **Step 15.7:** Search the workspace for any other exhaustive match on `rimap_imap::Error` that needs the new variant added.

```bash
rg 'match .+Error::' crates/rimap-imap --type rust -n
```

Add `Error::Audit { .. }` to any exhaustive match the compiler flags.

- [ ] **Step 15.8:** Add a unit test in `crates/rimap-imap/tests/error_mapping.rs` (the file already exists). Read it first to follow its conventions, then add:

```rust
#[test]
fn audit_variant_maps_to_internal_error_code() {
    use rimap_core::ErrorCode;
    use rimap_imap::error::Error;

    let err = Error::Audit {
        op: "emit_auth",
        message: "disk full".to_string(),
        source: Box::new(std::io::Error::other("disk full")),
    };
    let mapped: rimap_core::RimapError = err.into();
    assert_eq!(mapped.code(), ErrorCode::Internal);
    assert!(mapped.to_string().contains("ERR_INTERNAL"));
}
```

- [ ] **Step 15.9:** Build and test.

```bash
cargo build -p rimap-imap
cargo test -p rimap-imap
```
Expected: green. The compiler will surface any exhaustive matches that need updating.

- [ ] **Step 15.10:** Commit.

```bash
git add crates/rimap-imap/src/error.rs crates/rimap-imap/src/connection.rs crates/rimap-imap/tests/error_mapping.rs
git commit -m "$(cat <<'EOF'
fix(imap): surface emit_auth failure as Error::Audit, not Error::Connect

Audit-write failures on the connect_inner success path were
being stuffed into Error::Connect(io::Error::other(...)), which
made audit-subsystem failures indistinguishable from network
failures in metrics. Adds a dedicated Error::Audit variant
mapping to ErrorCode::Internal and short error-code "ERR_AUDIT"
in the audit log itself.

Closes #39
EOF
)"
```

## Batch 5 checkpoint

- [ ] **Step B5.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 6 — Test infrastructure

## Task 16: #41 — Prune stale `rimap-it-*` compose projects on test-session start

**Issue:** test(imap): prune stale rimap-it-* compose projects on test-session start (Drop doesn't cover SIGKILL).

**Files:**
- Modify: `crates/rimap-imap/tests/integration/support/container.rs:96-185` (`DovecotHarness::try_start`)

- [ ] **Step 16.1:** Add a `prune_stale_projects` helper near `compose_down` in `crates/rimap-imap/tests/integration/support/container.rs`. The helper:
  1. Lists all compose projects whose name matches `rimap-it-*`.
  2. For each project, fetches the compose-internal creation timestamp via `docker compose ls --format json`.
  3. Skips any project younger than 30 minutes (in-flight parallel runs).
  4. Calls `compose_down` on the rest.

```rust
/// Maximum age of a `rimap-it-*` compose project before it is considered
/// stale and pruned at the start of a new test session. Projects younger
/// than this are left alone so parallel test runs do not stomp on each
/// other.
const STALE_PROJECT_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Best-effort cleanup of leaked `rimap-it-*` compose projects from previous
/// runs that died via SIGKILL or power loss (Drop doesn't fire on either).
/// Skips projects younger than `STALE_PROJECT_AGE` to avoid disturbing
/// in-flight parallel runs. All errors are silent — this is opportunistic.
fn prune_stale_projects(compose_dir: &std::path::Path) {
    let output = match Command::new(runtime())
        .arg("compose")
        .arg("ls")
        .arg("--all")
        .arg("--format")
        .arg("json")
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let projects: Vec<serde_json::Value> = match serde_json::from_str(&stdout) {
        Ok(v) => v,
        Err(_) => return,
    };

    let now = std::time::SystemTime::now();
    for project in projects {
        let Some(name) = project.get("Name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !name.starts_with("rimap-it-") {
            continue;
        }
        // Parse the embedded nanosecond timestamp from the project name.
        // Project names look like "rimap-it-<hex-nanos>"; the suffix is
        // hex-encoded `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()`.
        let suffix = &name["rimap-it-".len()..];
        let nanos = match u128::from_str_radix(suffix, 16) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let created = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(
            u64::try_from(nanos / 1_000_000_000 * 1_000_000_000).unwrap_or(0)
        );
        let age = now.duration_since(created).unwrap_or_default();
        if age < STALE_PROJECT_AGE {
            continue;
        }
        // Stale enough to prune. Errors are silent.
        let _ = Command::new(runtime())
            .arg("compose")
            .arg("-p")
            .arg(name)
            .arg("down")
            .arg("-v")
            .arg("--remove-orphans")
            .current_dir(compose_dir)
            .status();
    }
}
```

- [ ] **Step 16.2:** Call `prune_stale_projects` once at the start of `try_start`, after the runtime / arch checks but before allocating the new project name. Locate `try_start` (line ~96) and add:

```rust
        // Best-effort cleanup of stale projects from prior runs killed
        // by SIGKILL / power loss. Drop doesn't fire on either.
        prune_stale_projects(&compose_dir_default());
```

Add a small helper because `compose_dir` isn't available until later in `try_start`:

```rust
fn compose_dir_default() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("integration")
        .join("dovecot")
}
```

And refactor the existing `compose_dir` line in `try_start` to use the helper for consistency:

```rust
        let compose_dir = compose_dir_default();
```

- [ ] **Step 16.3:** Verify `serde_json` is available to the test target. The integration tests already use it (`use serde_json` in `dovecot.rs:25`), so it should be in `crates/rimap-imap/Cargo.toml` `[dev-dependencies]`. If not:

```bash
grep -n serde_json crates/rimap-imap/Cargo.toml
```

If absent, add `serde_json = { workspace = true }` to `[dev-dependencies]`.

- [ ] **Step 16.4:** Build the integration test target to confirm the helper compiles.

```bash
cargo build -p rimap-imap --tests
```

- [ ] **Step 16.5:** If a docker runtime is available, manually verify the prune path by leaving a stale project around and re-running the test. (Skip if no docker available locally — CI exercises it.)

```bash
# Optional manual verification:
# docker compose -p rimap-it-deadbeef up -d   # leave a stale project
# RIMAP_REQUIRE_DOCKER=1 cargo test -p rimap-imap --test integration -- case_01 2>&1 | tail
# docker compose ls --all --format json | grep rimap-it-deadbeef   # should be gone
```

- [ ] **Step 16.6:** Commit.

```bash
git add crates/rimap-imap
git commit -m "$(cat <<'EOF'
test(imap): prune stale rimap-it-* compose projects on session start

DovecotHarness::Drop runs on normal scope exit and on panic
unwinding, but NOT on SIGKILL from cargo nextest --timeout, CI
runner killers, std::process::abort, or power loss. The unique
project name prevents stale containers from breaking subsequent
runs but they still accumulate. Pruning at session start
reclaims them, gated on a 30-minute age threshold so in-flight
parallel runs are not disturbed.

Closes #41
EOF
)"
```

## Batch 6 checkpoint

- [ ] **Step B6.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 7 — Reviewer-agent doc edits

These tasks edit Markdown files under `.claude/agents/`. No build or test cycle is required between commits, but `cargo fmt`/`clippy`/`test` is still run at the batch checkpoint to ensure no accidental drift.

## Task 17: #10 — `email-imap-security-reviewer`: async DoS categories

**Issue:** security-review: add async DoS categories to email-imap-security-reviewer.

**Files:**
- Modify: `.claude/agents/email-imap-security-reviewer.md`

- [ ] **Step 17.1:** Read `.claude/agents/email-imap-security-reviewer.md` and locate the `### Resource / DoS` section (or whatever the existing `MAIL-DOS-*` block is named).

- [ ] **Step 17.2:** Add three new entries at the end of the existing `MAIL-DOS-*` block, preserving the file's existing format:

```markdown
- **MAIL-DOS-06 Slow-loris IMAP reads** — an IMAP server (or MITM) trickling
  response bytes indefinitely pins a task and its connection slot. IDLE is
  the canonical exposure. Requires a read timeout per line AND a
  total-operation timeout, not just a connect timeout.
- **MAIL-DOS-07 Per-connection byte-rate ceiling** — an attacker that
  sustains just enough throughput to avoid the slow-loris timer can still
  exhaust memory by streaming a single large FETCH. Enforce a minimum
  throughput or a maximum byte budget per command.
- **MAIL-DOS-08 Task-per-connection leaks in multi-account** — when the
  server grows to multiple accounts, each account spawning a background
  IDLE task without a `JoinSet` or `TaskTracker` is a task leak.
  Cross-references `[RUST-ASYNC-05]` from `rust-safety-reviewer`.
```

- [ ] **Step 17.3:** Find the agent's red-flag grep section (typically near the end) and extend it to cover IDLE timeout coverage:

```markdown
# IDLE-specific timeout coverage
rg 'tokio::time::timeout.*idle|IDLE.*timeout' crates/rimap-imap/src/
```

- [ ] **Step 17.4:** Find the "Review process" section (typically a numbered list) and add a bullet to step 5 (or wherever the HTML→text walk is) that calls out the IDLE-specific check:

```markdown
- For IDLE paths: confirm a per-line read timeout AND a total-operation
  timeout exist (MAIL-DOS-06). A connect-only timeout is insufficient.
```

- [ ] **Step 17.5:** Commit.

```bash
git add .claude/agents/email-imap-security-reviewer.md
git commit -m "$(cat <<'EOF'
docs(reviewer): add MAIL-DOS-06/07/08 to email-imap-security-reviewer

MAIL-DOS-06 slow-loris reads, MAIL-DOS-07 byte-rate ceiling, and
MAIL-DOS-08 task-per-connection leaks in multi-account. The
review process step is extended to cover IDLE-specific timeout
coverage.

Closes #10
EOF
)"
```

## Task 18: #11 — `local-security-reviewer`: privacy/PII categories

**Issue:** security-review: add privacy/PII retention categories to local-security-reviewer.

**Files:**
- Modify: `.claude/agents/local-security-reviewer.md`

- [ ] **Step 18.1:** Read `.claude/agents/local-security-reviewer.md` to find the existing taxonomy structure.

- [ ] **Step 18.2:** Add a new `### Privacy and retention` block under the existing taxonomy, with these entries:

```markdown
### Privacy and retention

- **LOCAL-PRI-01 Audit log retention cap** — indefinite retention inflates
  blast radius and creates a compliance liability (GDPR, CCPA). Configurable
  retention with a sane default (e.g. 90 days). Links to `LOCAL-UPD-03`.
- **LOCAL-PRI-02 PII-bearing header residue** — beyond `From`/`To`/`Subject`,
  headers like `Received:`, `X-Originating-IP`, `User-Agent`, `X-Mailer`,
  `Message-ID` local part, and DKIM signatures leak recipient/sender
  identity details into the audit log. Redact or hash before persistence.
- **LOCAL-PRI-03 Body snippet retention** — if audit records include body
  snippets for debugging, the snippet itself is PII. Either exclude or cap
  length and hash for correlation only.
- **LOCAL-PRI-04 Consent semantics for posture changes** — if posture ever
  includes "forward message content to a third-party LLM," the consent
  state at the time of the forward must be recorded per-message, not
  per-session.
- **LOCAL-PRI-05 Right-to-delete story** — a user asking "forget account X"
  must have a documented deletion procedure covering audit log, keyring,
  config, and any cache. The absence of such a procedure is a compliance
  finding.
- **LOCAL-PRI-06 Backup and sync exposure** — config and audit paths
  landing in Time Machine, iCloud Drive, or OneDrive by default. Document
  and optionally exclude via platform mechanisms (e.g., the
  `com.apple.metadata:com_apple_backup_excludeItem` xattr on macOS).
```

- [ ] **Step 18.3:** Extend the agent's red-flag grep section with:

```markdown
# PII-bearing headers in audit/content paths
rg 'Received:|X-Originating-IP|User-Agent|X-Mailer' crates/rimap-audit crates/rimap-content
```

- [ ] **Step 18.4:** Add a bullet to the agent's review-process list:

```markdown
- Walk the PII exposure: every email-derived value persisted to disk
  (audit, cache, attachments) must have a documented retention policy and
  a redaction or hash policy. Cross-reference LOCAL-PRI-*.
```

- [ ] **Step 18.5:** Add a cross-reference from `LOCAL-UPD-03` (the existing entry) to `LOCAL-PRI-01`. Find the existing `LOCAL-UPD-03` entry and append:

```markdown
  Cross-references `LOCAL-PRI-01` (audit log retention cap).
```

- [ ] **Step 18.6:** Commit.

```bash
git add .claude/agents/local-security-reviewer.md
git commit -m "$(cat <<'EOF'
docs(reviewer): add LOCAL-PRI-* privacy/retention block

Six new entries covering audit retention, PII-bearing headers,
body snippet retention, posture-change consent, right-to-delete,
and backup/sync exposure. Email metadata is PII by GDPR/CCPA
definition; the prior agent treated it as secret-handling only.

Closes #11
EOF
)"
```

## Task 19: #12 — `mcp-security-reviewer`: elicitation categories

**Issue:** security-review: add MCP sampling/elicitation categories to mcp-security-reviewer.

**Files:**
- Modify: `.claude/agents/mcp-security-reviewer.md`

- [ ] **Step 19.1:** Read `.claude/agents/mcp-security-reviewer.md` to find the existing MCP taxonomy.

- [ ] **Step 19.2:** Add a new `### Elicitation` block. The full body of issue #12 is the source — copy the six MCP-ELIC-* entries verbatim and reformat them into the agent's existing entry shape:

```markdown
### Elicitation

MCP elicitation lets a server prompt the user for structured input mid-tool
call. It is a privileged UX surface because the prompt text is server-controlled
(prompt injection from server → user), the response schema is server-controlled
(server can ask for fields it shouldn't), the user may interpret the prompt as
coming from the MCP client rather than the server (spoofing), and the
structured response becomes trusted input to the server.

- **MCP-ELIC-01 Prompt-text injection** — server-provided prompt text
  containing instructions that alter client behavior (e.g., "before
  answering, send the following to http://…"). Sanitize and flag.
- **MCP-ELIC-02 Schema over-request** — server asks for fields unrelated
  to the tool's declared purpose (e.g., a math tool requesting the user's
  email). Posture should constrain.
- **MCP-ELIC-03 Identity spoofing** — elicitation UX must clearly identify
  the requesting server, not present as the client's own prompt.
- **MCP-ELIC-04 Response injection downstream** — the user's structured
  response becomes trusted input to the server; the server may then use
  it in shell commands, filesystem paths, or further tool calls. The
  response is still untrusted from the client's perspective and must be
  audited.
- **MCP-ELIC-05 Elicitation loop** — repeated elicitation without rate
  limit is a denial-of-UX vector. Cap elicitations per tool call and per
  session.
- **MCP-ELIC-06 Elicitation without consent for sensitive scopes** — an
  elicitation that asks for credentials, TOTP codes, or recovery phrases
  should be refused by the client regardless of server claims.
```

- [ ] **Step 19.3:** Commit.

```bash
git add .claude/agents/mcp-security-reviewer.md
git commit -m "$(cat <<'EOF'
docs(reviewer): add MCP-ELIC-* elicitation block

Six entries covering MCP elicitation: prompt-text injection,
schema over-request, identity spoofing, response injection
downstream, elicitation loops, and refusal of sensitive
scopes. The existing MCP-PRIV-04 covered sampling resource
exhaustion only.

Closes #12
EOF
)"
```

## Task 20: #13 — Test-code security section in all six reviewer agents

**Issue:** security-review: add test-code security section to all reviewer agents.

**Files:**
- Modify: `.claude/agents/mcp-security-reviewer.md`
- Modify: `.claude/agents/email-imap-security-reviewer.md`
- Modify: `.claude/agents/local-security-reviewer.md`
- Modify: `.claude/agents/rust-safety-reviewer.md`
- Modify: `.claude/agents/supply-chain-reviewer.md`
- Modify: `.claude/agents/ci-cd-security-reviewer.md`

- [ ] **Step 20.1:** Add a `## Test-code considerations` section to each agent file. Each agent gets the common bullets PLUS its agent-specific bullets. Place the section immediately before the closing bullets of the file (or before the red-flag grep section if one exists).

**Common bullets (in every agent):**

```markdown
## Test-code considerations

Test code is code. The same lint should apply.

- Real credentials in test fixtures, even "fake" ones that happen to
  validate against the production validator.
- `unwrap()` / `expect()` that hides a panic reachable from a real test
  with different inputs (proptest, fuzz).
- Hard-coded localhost addresses or fixed ports that succeed in CI but
  fail under test isolation.
- Test code that disables a defense (e.g., `danger_accept_invalid_certs(true)`
  in a test that is not specifically about TLS verification).
- Test fixtures under `tests/` with permissive permissions (`0644` on a
  file that contains a credential or a private key fragment).
```

**Per-agent additions (append after the common bullets):**

For `mcp-security-reviewer.md`:

```markdown
- Tests that hit real LLM providers or real MCP clients (network +
  cost + nondeterminism).
```

For `email-imap-security-reviewer.md`:

```markdown
- Tests that use real public IMAP servers (flaky + data-exfil risk if
  the test ever sends a probe with sensitive content).
```

For `local-security-reviewer.md`:

```markdown
- Tests that dump environment variables into log output for debugging.
```

For `rust-safety-reviewer.md`:

```markdown
- Cancellation-safety tests: every new async transaction should have a
  test that drops the future mid-await and asserts state integrity.
```

For `supply-chain-reviewer.md`:

```markdown
- Dev-dependencies that creep into the normal dep graph via cargo
  feature unification (e.g. `dev-dependency = { features = ["foo"] }`
  enables `foo` in the production dep too).
```

For `ci-cd-security-reviewer.md`:

```markdown
- Test-only workflows that don't enforce the same pinning discipline
  as production workflows (`actions/checkout@v4` vs SHA-pinned).
```

- [ ] **Step 20.2:** After all six edits, commit as a single change.

```bash
git add .claude/agents/
git commit -m "$(cat <<'EOF'
docs(reviewer): add Test-code considerations section to all six agents

Common test-code hazards (credentials in fixtures, unwrap that
hides panics, hard-coded localhost, defenses disabled in tests,
permissive fixture perms) plus one agent-specific bullet each.

Closes #13
EOF
)"
```

## Batch 7 checkpoint

- [ ] **Step B7.1:** Run the workspace verification suite. (Doc-only changes shouldn't break anything, but the checkpoint catches accidental edits.)

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 8 — Supply-chain watchlist and SEARCH redaction rationale

## Task 21: #30 — Sprint 2 supply-chain watchlist

**Issue:** Sprint 2 supply-chain watchlist (fs4, ulid pin, internal-dep version, SBOM).

**Files:**
- Add: `docs/security/supply-chain-watchlist.md` (new file)

- [ ] **Step 21.1:** Create `docs/security/supply-chain-watchlist.md` with one section per watchlist item from issue #30. The exact structure mirrors the issue body — four sections.

```markdown
# Supply-chain watchlist

This file tracks supply-chain concerns from the Sprint 2 review (#17) that
do not block merge but need periodic re-evaluation. Each entry has a
trigger condition for promotion to a full-fledged issue or follow-up.

## 1. fs4 single-maintainer status

- **Crate:** `fs4 = "0.13"` (https://github.com/al8n/fs4-rs)
- **Concern:** Single-publisher (Al Liu) in a load-bearing role (audit log
  advisory locking). Bus factor 1.
- **Trigger:** No upstream release in the past 12 months, OR a CVE
  filed against fs4, OR the maintainer announces deprecation.
- **Action on trigger:** Evaluate forking or switching to a maintained
  alternative (`rustix`, `sysinfo` + native APIs, etc.). The lock primitive
  is small enough to vendor.
- **Reference:** supply-chain-reviewer `[SC-DEP-09]` (info)

## 2. ulid = "=1.1.4" exact pin

- **Crate:** `ulid = "=1.1.4"` (in `Cargo.toml`)
- **Concern:** Exact pin blocks any 1.1.x patch release including a
  hypothetical security fix. The pin exists because ulid 1.2+ depends on
  rand 0.9 which conflicts with governor's rand 0.8 transitively.
- **Trigger:** governor releases a version on rand 0.9, OR a CVE is
  filed against ulid 1.1.4.
- **Action on trigger:** Drop the exact pin and unify on rand 0.9
  workspace-wide. The change touches `Cargo.toml`, `deny.toml`, and any
  call site that pinned `rand = "0.8"` for the same reason.
- **Reference:** supply-chain-reviewer `[SC-DEP-01]` (info)

## 3. Internal-crate `version = "0.0.0"` pattern

- **Pattern:** Internal path deps use
  `{ path = "../foo", version = "0.0.0" }` rather than
  `{ workspace = true }`. Documented in commit `27c37dd`.
- **Concern:** At first `cargo publish`, every consumer must be updated
  in lockstep with the workspace version bump. Easy to forget.
- **Trigger:** A pre-publish dry-run (`cargo publish --dry-run`) for any
  workspace member.
- **Action on trigger:** Either (a) move internal crates back into
  `[workspace.dependencies]` and add explicit `bans.skip` entries to
  `deny.toml`, or (b) write a `scripts/release.sh` that grep-replaces
  `version = "0.0.0"` to the new workspace version across every member's
  `Cargo.toml`.
- **Reference:** supply-chain-reviewer (Sprint 2 review)

## 4. SBOM generation at release time

- **Concern:** No SBOM is generated at release time. CycloneDX or SPDX
  via `cargo sbom` or `cargo auditable`, attached as a release asset, is
  the industry expectation for a security-sensitive tool.
- **Trigger:** First binary release (post-v1).
- **Action on trigger:** Add an `sbom` job to the release workflow that
  runs `cargo auditable build --release`, then `cargo sbom` to produce
  CycloneDX JSON, and uploads it as a release asset alongside the binary.
- **Reference:** supply-chain-reviewer (Sprint 2 review). Cross-references
  the deferred `release-integrity-reviewer` (#19).

## Review cadence

This file is reviewed as part of every minor-version bump. Add the entry to
the `CHANGELOG.md` of the bump if any trigger condition has fired.
```

- [ ] **Step 21.2:** Commit.

```bash
git add docs/security/supply-chain-watchlist.md
git commit -m "$(cat <<'EOF'
docs(security): add Sprint 2 supply-chain watchlist

Four entries with trigger conditions: fs4 single-maintainer,
ulid exact pin, internal-crate version pattern, and SBOM
generation at release time.

Closes #30
EOF
)"
```

## Task 22: #22 — Document SEARCH redaction policy rationale (Decision A)

**Issue:** rimap-audit: choose SEARCH criteria redaction policy (RedactString vs SaltedHash).

**Files:**
- Modify: `crates/rimap-audit/src/redact.rs` (add a doc comment to the `search` schema)

- [ ] **Step 22.1:** Open `crates/rimap-audit/src/redact.rs` and locate the `"search"` schema construction (around line 209). The current definition:

```rust
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
```

- [ ] **Step 22.2:** Add a comment immediately above the `RedactionSchema::new("search", ...)` call documenting why `RedactString` was chosen over `SaltedHash`:

```rust
        // SEARCH criteria policy: from/to/subject/body use `RedactString`,
        // not `SaltedHash`. The Sprint 2 review brief recommended SaltedHash
        // so incident responders could answer "did this LLM session search
        // for the same string twice?" — but that adds within-process
        // correlation surface for low-entropy queries (e.g. `{"from":"alice@x"}`)
        // and offers little forensic value beyond what `arguments_hash_sha256`
        // already provides at the record level. RedactString is the more
        // conservative choice (less leakage, no correlation by design) and
        // still records the byte length for unusual-payload detection.
        // Decision recorded in #22.
        RedactionSchema::new(
```

- [ ] **Step 22.3:** Add a corresponding sentence to the `search.advanced_query` schema (around line 224) since the `advanced_query` field has the same trade-off:

```rust
        // SEE search schema above for the RedactString rationale (#22).
        RedactionSchema::new(
            "search.advanced_query",
```

- [ ] **Step 22.4:** Build to confirm the comment compiles.

```bash
cargo build -p rimap-audit
```

- [ ] **Step 22.5:** Commit.

```bash
git add crates/rimap-audit/src/redact.rs
git commit -m "$(cat <<'EOF'
docs(audit): record SEARCH redaction policy as RedactString (not SaltedHash)

The Sprint 2 review brief floated SaltedHash for from/to/subject
/body so within-process search correlation would be possible.
RedactString is more conservative (less leakage, no correlation
surface for low-entropy queries) and still records byte length.
Decision recorded inline at the schema construction site.

Closes #22
EOF
)"
```

## Batch 8 checkpoint

- [ ] **Step B8.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Batch 9 — Decision-gated reviewer-agent edits

## Task 23: #15 — Add error-taxonomy block to `local-security-reviewer`

**Issue:** security-review: create error-taxonomy-reviewer for information disclosure.

**Decision:** Block inside `local-security-reviewer` (not a new agent).

**Files:**
- Modify: `.claude/agents/local-security-reviewer.md`

- [ ] **Step 23.1:** Read `.claude/agents/local-security-reviewer.md` (which already contains the LOCAL-PRI-* block from Task 18).

- [ ] **Step 23.2:** Add a new `### Error-disclosure taxonomy` block after the privacy block. Use the nine `ERR-*` entries from issue #15, but renumber them under the `LOCAL-ERR-*` prefix to fit the agent's namespace:

```markdown
### Error-disclosure taxonomy

Information disclosure via error messages, timing, and error shape
differentials. The taxonomy lives in this agent (rather than a dedicated
`error-taxonomy-reviewer`) per the #15 decision: it is small enough to
fit and the boundary with privacy/PII findings is fuzzy.

- **LOCAL-ERR-01 Username / account enumeration** — `auth failed for user X`
  must not differ in error text, timing, or shape from `user X does not
  exist`. The audit log records both as `ERR_AUTH` for the same reason.
- **LOCAL-ERR-02 Mailbox / resource enumeration** — `list messages in
  folder X` must not produce different errors for "no such folder" vs
  "folder exists but access denied".
- **LOCAL-ERR-03 Non-constant-time string comparison on secrets** — pin
  verification, HMAC verification, and password comparison must use
  constant-time comparison (`subtle::ConstantTimeEq` or similar).
- **LOCAL-ERR-04 Divergent timing across auth success/failure paths** —
  the time spent on a failed login should be indistinguishable from a
  successful one. Pre-emptive credential lookup helps; staged execution
  helps more.
- **LOCAL-ERR-05 Filesystem path in error chain** —
  `format!("{:#}", err)` expanding an `io::Error` with path context
  reveals filesystem layout. Audit-record errors must use the
  `code: ErrorCode` enum, never the raw chain.
- **LOCAL-ERR-06 Internal config value in error chain** — error messages
  that quote a config value (a host name, a fingerprint, a secret) leak
  it to anywhere the error surfaces.
- **LOCAL-ERR-07 Different error shape for existence vs access-denied** —
  the structural variant matters as much as the message. Same
  `ErrorCode` for both, even if the inner message differs in trace logs.
- **LOCAL-ERR-08 Tool error codes too granular** — leaks internal state
  (e.g. `ERR_RATE_LIMITED_BUCKET_3`).
- **LOCAL-ERR-09 Tool error codes too coarse** — `ERR_INTERNAL` for
  everything masks bugs and prevents observability.
```

- [ ] **Step 23.3:** Commit.

```bash
git add .claude/agents/local-security-reviewer.md
git commit -m "$(cat <<'EOF'
docs(reviewer): add LOCAL-ERR-* error-disclosure block

Nine entries: username/mailbox enumeration, constant-time
comparisons, divergent-timing auth paths, filesystem-path
leakage, error-shape differentials, and over/under-granular
error codes. Lives in local-security-reviewer (not a new agent)
per the #15 decision.

Closes #15
EOF
)"
```

## Task 24: #16 — Fuzzing coverage tracker doc

**Issue:** security-review: fuzzing and mutation-testing coverage tracker.

**Decision:** Option A (lightweight doc + reviewer-checklist item).

**Files:**
- Add: `docs/security/fuzzing-coverage.md` (new file)
- Modify: `.claude/agents/rust-safety-reviewer.md` (add a checklist item)

- [ ] **Step 24.1:** Create `docs/security/fuzzing-coverage.md`:

```markdown
# Fuzzing and mutation-testing coverage

Tracks which security-sensitive modules have fuzz targets, which have
proptest strategies, and which have been surveyed by `cargo-mutants`.
Updated as part of every change to a "must fuzz" module.

## "Must fuzz" modules

These modules parse untrusted bytes from network or disk and are
load-bearing for security. A change here without an updated fuzz target
or proptest strategy is a review finding.

| Module | Fuzz target | Proptest strategy | Last cargo-mutants survey |
|---|---|---|---|
| `rimap-content` (MIME, HTML→text) | TBD (Sprint 4) | TBD | — |
| `rimap-imap::ops::fetch::compress_uid_set` | n/a | `crates/rimap-imap/src/ops/fetch.rs::tests::compress_round_trip_via_split` (added in #33) | — |
| `rimap-audit::self_check::read_trailing_state` | TBD | n/a (consumes serde_json which has its own coverage) | — |
| `rimap-audit::redact::Redactor::apply` | TBD | TBD | — |
| `rimap-audit::writer::AuditWriter::write_record` | n/a (no untrusted parser surface) | n/a | — |

## Adding a new "must fuzz" entry

When a new parser-of-untrusted-input lands:

1. Add a row to the table above with `TBD` for fuzz target and proptest.
2. File a `security-review` issue tagged `fuzzing-coverage` linking to the
   module path.
3. Update this file in the same PR that lands the fuzz target.

## Why Option A

A dedicated `fuzzing-coverage-reviewer` agent (Option B from #16) would
duplicate work that the existing `rust-safety-reviewer` already covers
at change-review time. Promoting to Option B is the right move only if
the discipline grows beyond ~10 modules or if the coverage drift becomes
hard to track manually.

## Cargo-mutants survey cadence

Once a quarter, run:

```bash
cargo mutants --in-place --workspace --timeout 60 -- --test-threads 1
```

and update the "Last survey" column for any module whose mutation score
changed by more than 5%.
```

- [ ] **Step 24.2:** Add a checklist item to `.claude/agents/rust-safety-reviewer.md`. Read the file first to find the existing review-process section, then append:

```markdown
- For changes touching parsers of untrusted input, check
  `docs/security/fuzzing-coverage.md`. If the module is on the
  "must fuzz" list and the change does not update a fuzz target or
  proptest, file a finding (`SC-FUZZ-01`) and link to the file.
```

- [ ] **Step 24.3:** Commit.

```bash
git add docs/security/fuzzing-coverage.md .claude/agents/rust-safety-reviewer.md
git commit -m "$(cat <<'EOF'
docs(security): add fuzzing-coverage tracker (Option A from #16)

Lightweight doc listing must-fuzz modules and their current
fuzz/proptest/cargo-mutants coverage. Extends rust-safety-reviewer
with a checklist item that flags untrusted-parser changes
without coverage updates.

Closes #16
EOF
)"
```

## Batch 9 checkpoint

- [ ] **Step B9.1:** Run the workspace verification suite.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

---

# Task 25: Close #35 and #38 as already-resolved

These two issues were filed against pre-merge Sprint 3 code and have already been addressed in the merged Sprint 3 history. They need a closing comment, no commit.

- [ ] **Step 25.1:** Close #35 with a comment.

```bash
gh issue close 35 --comment "$(cat <<'EOF'
Already resolved on main as part of Sprint 3.

`tests/integration/support/container.rs:241-287` now uses
`compose up --force-recreate` (full container rebuild) instead
of the racy `pkill -9 imap`. The harness comment at lines
226-237 explains the bug history. `dovecot.rs:286-301` calls
`h.harness.restart()` which deterministically tears down every
worker fd; the cert is preserved across the rebuild on the
shared named volume.

No further action required.
EOF
)"
```

- [ ] **Step 25.2:** Close #38 with a comment.

```bash
gh issue close 38 --comment "$(cat <<'EOF'
Already resolved on main as part of Sprint 3.

`crates/rimap-imap/src/ops/folders.rs:110-169` walks the error
source chain via \`is_connection_lost\` / \`is_dead_tcp_kind\`
and classifies by \`io::ErrorKind::{ConnectionReset,
ConnectionAborted, BrokenPipe, UnexpectedEof, NotConnected}\`.
The doc-comment at line 109 explicitly references this issue
as the follow-up that landed.

No further action required.
EOF
)"
```

---

# Final verification

- [ ] **Step F.1:** Confirm 24 commits on the branch.

```bash
git log --oneline main..HEAD | wc -l
```
Expected: 24 (one per in-scope issue).

- [ ] **Step F.2:** Confirm every commit references its issue with `Closes #N`.

```bash
git log main..HEAD --format=%B | grep -c '^Closes #'
```
Expected: 24.

- [ ] **Step F.3:** Run the workspace verification suite one final time.

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --no-fail-fast
```

- [ ] **Step F.4:** Confirm `cargo deny check` passes.

```bash
cargo deny check
```

- [ ] **Step F.5:** Verify both close-as-resolved actions ran.

```bash
gh issue view 35 --json state
gh issue view 38 --json state
```
Expected: `"state":"CLOSED"` for both.

- [ ] **Step F.6:** Push and open a PR. Use the body template below.

```bash
git push -u origin fix/gh-issue-backlog
gh pr create --title "fix: resolve 24 deferred backlog issues from Sprint 1-3 reviews" --body "$(cat <<'EOF'
## Summary

Resolves 24 deferred GitHub issues carved out of the Sprint 1, 2, and 3 reviews. One commit per issue, organized into nine reviewable batches. Plan: `docs/superpowers/plans/2026-04-08-gh-issue-backlog.md`.

## Issues closed by this PR

- **Audit subsystem (4):** #5 (rotate_keep pruning), #6 (Windows inode parity), #7 (fail_open escape hatch), #29 (canonicalize audit.path)
- **rimap-core / rimap-audit small (3):** #25 (strum::EnumIter), #26 (pub(crate) test seams), #34 (Audit Display dedup)
- **rimap-imap small (4):** #31 (build_tls_config Result), #33 (UID range compression), #39 (Error::Audit variant), #40 (webpki-roots 1.0)
- **Tests (4):** #36 (panic on malformed audit JSONL), #37 (audit-share comments), #41 (compose project pruning), #23 (Verbatim doc-comment)
- **Reviewer agents (6):** #10, #11, #12, #13, #15 (LOCAL-ERR-* block), #16 (Option A: fuzzing doc)
- **Docs (3):** #28 (umask 077), #30 (supply-chain watchlist), #22 (SEARCH redaction rationale)

## Issues closed separately as already-resolved

- #35 (already fixed by `harness.restart()` in Sprint 3)
- #38 (already fixed by `is_connection_lost`/`io::ErrorKind` in Sprint 3)

## Issues deferred (out of scope, see plan doc)

#8 (audit lifecycle glue — needs own design), #14 (threat-model-reviewer — needs own design), #18 (depends on #14), #19 (post-v1 release work), #32 (fetch_body backpressure — needs async-imap upstream)

## Test plan

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test --workspace --no-fail-fast` passes
- [ ] `cargo deny check` passes
- [ ] CI green on Linux and Windows runners (the #6 Windows file_index path can only be exercised in CI)
- [ ] Optional: run integration suite under `RIMAP_REQUIRE_DOCKER=1` to verify #5 / #7 / #33 / #41 don't regress dovecot tests

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

# Deferred issues (out of scope for this plan)

These five issues are not addressed by this plan and remain open after the branch merges. Each has a documented reason and a recommended next step.

## #8 — audit: server lifecycle glue (write process_start on boot, process_end on shutdown)

**Reason for deferral:** Larger cross-cutting work that ties together `rimap_audit::AuditWriter::open`, `rimap_audit::self_check::read_trailing_state`, the new `process_start` / `process_end` payloads, and signal handling in `rimap-server::main`. Deserves its own brainstorm + plan because it touches the server boot path and the Drop guard semantics.

**Recommended next step:** Open a dedicated brainstorm session for an `audit-lifecycle` design doc, then a focused plan/branch.

## #14 — security-review: create threat-model-reviewer agent for specs and plans

**Reason for deferral:** New agent with non-trivial scope (STRIDE walkthroughs, asset enumeration, trust-boundary mapping). User decision during brainstorming was to split this out.

**Recommended next step:** Brainstorm the agent's scope as its own task, write the agent file, then file a follow-up PR.

## #18 — security-review: SECURITY.md hygiene and disclosure workflow reviewer

**Reason for deferral:** Decided in brainstorming to land as a section of `threat-model-reviewer` (#14). Since #14 is split out, #18 follows it.

**Recommended next step:** Roll into the #14 follow-up.

## #19 — security-review: release and distribution integrity reviewer (post-v1)

**Reason for deferral:** Issue body explicitly says "Create this agent when the project starts landing release automation, not before." There is no release automation yet.

**Recommended next step:** Triggered when the first release-tag workflow lands. The supply-chain watchlist (Task 21, file `docs/security/supply-chain-watchlist.md`) cross-references this issue for the SBOM trigger condition.

## #32 — rimap-imap: fetch_body size cap is accept/reject, not backpressure

**Reason for deferral:** Requires either an upstream contribution to async-imap (chunked body streaming API) or a switch to a lower-level IMAP crate (`imap-proto` + direct tokio-rustls). Neither fits in a single-branch cleanup. The current code at `crates/rimap-imap/src/connection.rs:434-450` already documents the trade-off and points to issue #32.

**Recommended next step:** When async-imap 0.12+ ships chunked streaming, OR when a lower-level rewrite is on the roadmap, plan and execute the switch in a dedicated branch.
