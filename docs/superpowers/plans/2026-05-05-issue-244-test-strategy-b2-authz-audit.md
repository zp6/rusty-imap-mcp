# Sprint B2: rimap-authz + rimap-audit Fuzz + Mutation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Tracking issue:** [#244](https://github.com/randomparity/rusty-imap-mcp/issues/244).

**Goal:** Land the `audit_jsonl` fuzz harness covering `rimap_audit::reader::parse_line` + `rimap_audit::redact::redact`, refresh `cargo-mutants` against current `main` for both `rimap-authz` and `rimap-audit`, kill (or annotate) every survivor in the security-sensitive paths named in spec §5.4, extend `mutation-baseline.md` with the two new sections, and verify ClusterFuzzLite picks up the new target on PR-smoke.

**Architecture:** B1 already shipped the `fuzz/` crate, the `.github/workflows/fuzz.yml` workflow (PR-smoke 600 s, nightly 7200 s, both running every target the build emits), and `docs/superpowers/specs/test-strategy/mutation-baseline.md` (currently `rimap-content` only). B2 reuses all of that. Two thin public helpers (`reader::parse_line`, `redact::redact`) get added to `rimap-audit` so the fuzz harness has named entry points matching the spec; both are also useful as long-lived API surface for downstream tooling. No fuzz target is added for `rimap-authz` — its inputs are typed enums and mutation testing is the right tool. Mutation cleanup proceeds module-by-module after a fresh per-crate baseline run; survivors that change observable behavior get killed by tests, equivalent mutants get inline `// cargo-mutants: known-equivalent` annotations with rationale and a row in `mutation-baseline.md`.

**Tech Stack:** `cargo-fuzz` (nightly-only) and `libfuzzer-sys` 0.4 (already wired up in `fuzz/`), `cargo-mutants` 25.x, ClusterFuzzLite (already pinned in `.github/workflows/fuzz.yml`), `serde_json`, `proptest`, GitHub Actions on `ubuntu-24.04`. Workspace MSRV is 1.88.0; `fuzz/` crate's `rust-version` pin is 1.94.0.

**Spec reference:** [`docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md`](../specs/2026-04-30-test-strategy-improvements-design.md), Sprint B2 — Section 5.

**Branch:** `feat/test-strategy-b2-authz-audit` (cut from current `main` at the start of execution).

**Phase split:** unlike B1 this plan is a single PR. The fuzz harness is small (one target, one helper pair), and bundling baseline-refresh + mutation cleanup keeps the survivor list stable across the PR's lifetime. If the post-refresh survivor counts run hot (>20 in either crate) the executor splits Tasks 6 and 8 into a follow-up PR per the §"Out-of-band split" section at the end of this plan — but the default expectation is one PR.

---

## Pre-flight

Confirm the working branch isn't `main`/`master`, the worktree is clean, and the local toolchain is ready.

- [ ] **Step 0: Verify branch, clean state, and tooling**

Run:
```bash
git branch --show-current
git status --short
which actionlint zizmor cargo-mutants
rustup toolchain list | grep -F nightly
cargo install --list 2>/dev/null | grep -E "cargo-fuzz|cargo-mutants"
```

Expected:
- `git branch --show-current` prints `feat/test-strategy-b2-authz-audit` (NOT `main`). If on `main`, stop and create the branch: `git checkout -b feat/test-strategy-b2-authz-audit`.
- `git status --short` is empty.
- `actionlint`, `zizmor`, `cargo-mutants` are on PATH. Install missing tools per the global `~/.claude/CLAUDE.md` "CLI tools" table or `just setup`.
- A `nightly-*` toolchain is listed. If not, run `rustup toolchain install nightly --component rust-src`.
- `cargo-fuzz` and `cargo-mutants` are listed. If not, run `cargo install --locked cargo-fuzz cargo-mutants`.

- [ ] **Step 1: Sanity-check that B1 infrastructure is live on `main`**

Run:
```bash
test -d fuzz/fuzz_targets && ls fuzz/fuzz_targets/
test -f .github/workflows/fuzz.yml
test -f docs/superpowers/specs/test-strategy/mutation-baseline.md
grep -F "## \`rimap-authz\`" docs/superpowers/specs/test-strategy/mutation-baseline.md || echo "rimap-authz section missing — populate it in Task 9"
grep -F "## \`rimap-audit\`" docs/superpowers/specs/test-strategy/mutation-baseline.md || echo "rimap-audit section missing — populate it in Task 9"
```

Expected: `fuzz/fuzz_targets/` lists the four B1 harnesses; the two grep lines either succeed (sections already exist as scaffolds) or print the "section missing" message (sections will be added in Task 9 with the populated tables). Either is fine.

---

## Task 1: Add `reader::parse_line` to `rimap-audit`

**Why:** The spec names `rimap_audit::reader::parse_line(raw: &[u8])` as the fuzz harness entry point, but only `stream_records` exists today (which assumes a file handle). A thin public wrapper around `serde_json::from_slice::<AuditRecord>` is the smallest helper that matches the spec's named symbol and is independently useful for downstream JSONL-consuming tools (e.g. `audit merge`, future external auditors). Returning `Result<AuditRecord, AuditError>` keeps the error type aligned with `stream_records`'s `AuditError::Read` arm.

**Files:**
- Modify: `crates/rimap-audit/src/reader/mod.rs` (add `pub fn parse_line`)
- Modify: `crates/rimap-audit/src/lib.rs` (re-export `parse_line` alongside `stream_records`)
- Test: new `#[cfg(test)]` block at the bottom of `crates/rimap-audit/src/reader/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests {` block at the bottom of `crates/rimap-audit/src/reader/mod.rs` (just before the closing `}` of `mod tests`):

```rust
    #[test]
    fn parse_line_round_trips_a_valid_record() {
        let pid = ProcessId::new_now();
        let rec = sample(7, pid);
        let bytes = serde_json::to_vec(&rec).unwrap();

        let parsed = super::parse_line(&bytes).expect("valid record must parse");
        assert_eq!(parsed.seq.get(), 7);
    }

    #[test]
    fn parse_line_returns_invalid_data_on_malformed_json() {
        let err = super::parse_line(b"{not json").expect_err("malformed JSON must error");
        match err {
            crate::AuditError::Read { line, source, .. } => {
                assert!(line.is_none(), "parse_line has no line context");
                assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
            }
            other => panic!("unexpected error kind: {other:?}"),
        }
    }

    #[test]
    fn parse_line_does_not_panic_on_empty_input() {
        let _ = super::parse_line(b"");
    }

    #[test]
    fn parse_line_does_not_panic_on_garbage_bytes() {
        // 1 KB of high-entropy bytes — must produce Err, never panic.
        let mut bytes = Vec::with_capacity(1024);
        for i in 0_u16..1024 {
            bytes.push((i & 0xff) as u8);
        }
        let _ = super::parse_line(&bytes);
    }
```

- [ ] **Step 2: Run tests to verify they fail (compile error)**

Run:
```bash
cargo test --package rimap-audit reader::tests::parse_line -- --nocapture
```

Expected: compile error `cannot find function 'parse_line' in module 'super'` (or similar).

- [ ] **Step 3: Implement `parse_line`**

Insert the following function in `crates/rimap-audit/src/reader/mod.rs` immediately above the `pub fn open_shared` declaration (around line 109):

```rust
/// Parse a single JSONL line into an [`AuditRecord`].
///
/// Thin wrapper around `serde_json::from_slice` that maps any decode
/// failure to [`AuditError::Read`] with `line: None` (callers track line
/// numbers when they have them — `parse_line` itself does not). Empty
/// input is treated as malformed and returns `Err`; callers that want
/// the trailing-empty-line tolerance enforced by `stream_records` should
/// use that function instead.
///
/// # Errors
/// [`AuditError::Read`] when the bytes do not deserialize to a valid
/// [`AuditRecord`].
pub fn parse_line(raw: &[u8]) -> Result<AuditRecord, AuditError> {
    serde_json::from_slice::<AuditRecord>(raw).map_err(|err| AuditError::Read {
        path: std::path::PathBuf::new(),
        line: None,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
    })
}
```

- [ ] **Step 4: Re-export from `lib.rs`**

Edit `crates/rimap-audit/src/lib.rs`. Find the line:
```rust
pub use crate::reader::{Filter, open_shared, stream_records};
```

Change to:
```rust
pub use crate::reader::{Filter, open_shared, parse_line, stream_records};
```

- [ ] **Step 5: Run the new tests**

Run:
```bash
cargo test --package rimap-audit reader::tests::parse_line -- --nocapture
```

Expected: all four `parse_line_*` tests pass.

- [ ] **Step 6: Run the full crate suite + clippy**

Run:
```bash
cargo nextest run --package rimap-audit --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: both clean. The new test block must not break any existing reader test, and the new `pub fn` must not trip the `missing_docs` deny in `lib.rs` (the doc comment above is what satisfies it).

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-audit/src/reader/mod.rs crates/rimap-audit/src/lib.rs
git commit -m "test(rimap-audit): add reader::parse_line public helper

Wraps serde_json::from_slice<AuditRecord> with the spec-named entry
point used by the upcoming audit_jsonl fuzz harness. Mapped errors
land in AuditError::Read with line: None so the same arm handles both
stream_records and parse_line callers.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.1"
```

---

## Task 2: Add `redact::redact` to `rimap-audit`

**Why:** The spec names `rimap_audit::redact::redact(record: AuditRecord)` as the second entry point under fuzz. Today `Redactor::apply` redacts a `Value` argument map; there is no top-level "redact this whole record" function. Adding one closes the spec's named symbol and gives the writer a single canonical place to apply per-tool redaction policy at record time. The function is a no-op for non-`tool_start` payloads (those carry no caller-supplied strings) and dispatches via `ToolName::redaction_schema()` for `tool_start`.

**Files:**
- Modify: `crates/rimap-audit/src/redact/mod.rs` (add `pub fn redact`)
- Modify: `crates/rimap-audit/src/lib.rs` (re-export `redact`)
- Test: extend the existing `#[cfg(test)]` block at the bottom of `redact/mod.rs`

- [ ] **Step 1: Write the failing test**

Append the following test module at the end of `crates/rimap-audit/src/redact/mod.rs` (after the existing tests, or — if there is no `#[cfg(test)]` block yet at the end of the file — append a new one). Run `grep -n "^#\[cfg(test)\]" crates/rimap-audit/src/redact/mod.rs` first; if a `mod tests` already exists, add the test inside it.

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod redact_record_tests {
    use rimap_core::{Posture, tool::ToolName};
    use serde_json::json;
    use time::macros::datetime;

    use crate::record::ids::{ProcessId, Seq, Timestamp};
    use crate::record::{
        AuditRecord, Payload, PostureEffective, ToolStart,
    };
    use crate::redact::{RedactionSalt, redact};

    fn salt() -> RedactionSalt {
        RedactionSalt::from_bytes([0x42_u8; 32])
    }

    fn tool_start_record(args_redacted: serde_json::Value) -> AuditRecord {
        AuditRecord {
            seq: Seq(1),
            ts: Timestamp::from_offset(datetime!(2026-05-05 12:00:00.000 UTC)),
            process_id: ProcessId::new_now(),
            payload: Payload::ToolStart(ToolStart {
                account: Some("acct".into()),
                tool: ToolName::Search,
                posture_effective: PostureEffective::Account(Posture::Restricted),
                arguments_redacted: args_redacted,
                arguments_hash_sha256: "0".repeat(64),
            }),
        }
    }

    #[test]
    fn redact_re_redacts_tool_start_arguments() {
        // The record's arguments_redacted contains a literal "secret"
        // string. After re-running redact() that string must not appear
        // in the serialized output for any field whose schema policy is
        // RedactString or SaltedHash.
        let secret = "this-is-a-secret";
        let rec = tool_start_record(json!({
            "subject": secret,
        }));
        let s = salt();
        let redacted = redact(&rec, &s);
        let serialized = serde_json::to_string(&redacted).unwrap();
        assert!(
            !serialized.contains(secret),
            "post-redaction serialized form leaked secret: {serialized}"
        );
    }

    #[test]
    fn redact_passes_through_non_tool_start_records() {
        use crate::record::{ProcessEnd, ProcessEndReason};
        let rec = AuditRecord {
            seq: Seq(2),
            ts: Timestamp::from_offset(datetime!(2026-05-05 12:00:00.000 UTC)),
            process_id: ProcessId::new_now(),
            payload: Payload::ProcessEnd(ProcessEnd {
                reason: ProcessEndReason::Eof,
                total_tool_calls: 0,
            }),
        };
        let redacted = redact(&rec, &salt());
        assert_eq!(rec.seq.get(), redacted.seq.get());
        assert_eq!(rec.process_id.to_string(), redacted.process_id.to_string());
        // ProcessEnd has no string fields to redact, so the serialized
        // forms must match byte-for-byte.
        assert_eq!(
            serde_json::to_string(&rec).unwrap(),
            serde_json::to_string(&redacted).unwrap(),
        );
    }
}
```

- [ ] **Step 2: Run the new tests to verify they fail (compile error)**

Run:
```bash
cargo test --package rimap-audit redact_record_tests -- --nocapture
```

Expected: compile error `cannot find function 'redact' in this scope`.

- [ ] **Step 3: Implement `redact`**

Insert the following function in `crates/rimap-audit/src/redact/mod.rs` immediately after `pub fn hash_arguments` (around line 196):

```rust
/// Re-apply the per-tool [`RedactionSchema`] to an [`AuditRecord`].
///
/// For [`Payload::ToolStart`] this re-runs [`Redactor::apply`] on
/// `arguments_redacted` using the tool's declared schema and the
/// supplied salt. For all other payload variants the record is
/// returned unchanged (no caller-supplied strings to redact).
///
/// This function is intentionally idempotent: applying it twice with
/// the same salt produces the same output as applying it once, because
/// the redaction policies map any surviving string value to either
/// `"<redacted:N>"`, a salted hash, or removal — none of which contain
/// the original bytes.
#[must_use]
pub fn redact(record: &AuditRecord, salt: &RedactionSalt) -> AuditRecord {
    use crate::record::Payload;

    let mut out = record.clone();
    if let Payload::ToolStart(ref mut start) = out.payload {
        let schema = start.tool.redaction_schema();
        let redactor = Redactor::new(&schema, salt);
        start.arguments_redacted = redactor.apply(&start.arguments_redacted);
    }
    out
}
```

You may need to derive or confirm `Clone` on `AuditRecord`; run `grep -nE "derive\(.*Clone" crates/rimap-audit/src/record/mod.rs` — if `AuditRecord` is not `Clone` already, append `Clone` to its derive list. The other inner types (`ToolStart`, `Payload`, etc.) need to be `Clone` transitively; they already are based on the existing `#[derive(Debug, Clone, Serialize, Deserialize)]` patterns in `record/mod.rs`. If the build complains, add `Clone` to the offending derive — this is a non-functional change.

- [ ] **Step 4: Re-export from `lib.rs`**

Edit `crates/rimap-audit/src/lib.rs`. Find the block:
```rust
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, hash_arguments,
    schemas,
};
```

Change to:
```rust
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, hash_arguments,
    redact, schemas,
};
```

- [ ] **Step 5: Run the new tests + the full crate suite**

Run:
```bash
cargo test --package rimap-audit redact_record_tests -- --nocapture
cargo nextest run --package rimap-audit --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
```

Expected: both `redact_record_tests` pass; no regressions; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-audit/src/redact/mod.rs crates/rimap-audit/src/lib.rs crates/rimap-audit/src/record/mod.rs
git commit -m "test(rimap-audit): add redact::redact whole-record helper

Adds the spec-named entry point used by the upcoming audit_jsonl fuzz
harness. ToolStart payloads have arguments_redacted re-redacted via
the tool's per-tool schema; other payloads pass through unchanged.
Idempotent.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.1"
```

---

## Task 3: Wire `rimap-audit` into the `fuzz/` crate

**Why:** B1's `fuzz/Cargo.toml` only depends on `rimap-content`. The `audit_jsonl` harness needs `rimap-audit` available; declare the path dep alongside the existing one.

**Files:**
- Modify: `fuzz/Cargo.toml`

- [ ] **Step 1: Add the path dependency**

Edit `fuzz/Cargo.toml`. Find the existing `[dependencies.rimap-content]` block:

```toml
[dependencies.rimap-content]
path = "../crates/rimap-content"
features = ["test-util"]
```

Append immediately below it:

```toml

[dependencies.rimap-audit]
path = "../crates/rimap-audit"
```

`rimap-audit` does not gate `parse_line` or `redact` behind a feature, so no `features = [...]` clause is needed.

- [ ] **Step 2: Verify the fuzz crate still builds standalone on nightly**

Run:
```bash
cd fuzz && cargo +nightly check && cd ..
```

Expected: clean exit. (The new dep is declared but no target uses it yet — that's fine, the manifest must parse and the dep must resolve.)

- [ ] **Step 3: Commit**

```bash
git add fuzz/Cargo.toml
git commit -m "test(fuzz): declare rimap-audit dependency for upcoming audit_jsonl target

Refs: #244"
```

---

## Task 4: `audit_jsonl` fuzz harness

**Why:** The harness drives the two helpers from Tasks 1 and 2 over arbitrary bytes and asserts the spec's three invariants from §5.1: parse failures are clean errors not panics, redacted output round-trips through serde, and no original input bytes appear as substring inside the redacted serialization (modulo `Verbatim`-policy fields which legitimately pass through).

**Files:**
- Create: `fuzz/fuzz_targets/audit_jsonl.rs`
- Create: `fuzz/corpus/audit_jsonl/` (seeded — see Step 4)
- Modify: `fuzz/Cargo.toml` (register the target)

- [ ] **Step 1: Register the target in `fuzz/Cargo.toml`**

Edit `fuzz/Cargo.toml`. Append at the very end of the file (after the last existing `[[bin]]` block, which is `content_charset`):

```toml

[[bin]]
name = "audit_jsonl"
path = "fuzz_targets/audit_jsonl.rs"
test = false
doc = false
bench = false
```

- [ ] **Step 2: Write the harness**

Create `fuzz/fuzz_targets/audit_jsonl.rs`:

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use rimap_audit::{RedactionSalt, parse_line, redact};

fuzz_target!(|data: &[u8]| {
    // Invariant 1: parse_line never panics on any input. Either it
    // returns Ok(record) or Err(AuditError::Read).
    let Ok(record) = parse_line(data) else {
        return;
    };

    // Invariant 2: redact() on a successfully-parsed record never panics
    // and returns a record that round-trips through serde.
    let salt = RedactionSalt::from_bytes([0x42_u8; 32]);
    let redacted = redact(&record, &salt);
    let serialized = serde_json::to_vec(&redacted)
        .expect("redacted record must serialize via serde_json");
    let _reparsed: rimap_audit::AuditRecord = serde_json::from_slice(&serialized)
        .expect("redacted record must round-trip through serde_json");

    // Invariant 3: for tool_start payloads, no string in the input that
    // mapped to a non-Verbatim policy field appears as a substring of
    // the redacted serialization. We approximate this by checking each
    // top-level string value in the original arguments_redacted.
    if let rimap_audit::Payload::ToolStart(ref start) = record.payload {
        use rimap_audit::ToolRedactionSchema;
        let schema = start.tool.redaction_schema();
        if let serde_json::Value::Object(map) = &start.arguments_redacted {
            for (name, value) in map {
                let policy = schema
                    .policies
                    .get(name.as_str())
                    .copied()
                    .unwrap_or(rimap_audit::FieldPolicy::RedactString);
                if matches!(policy, rimap_audit::FieldPolicy::Verbatim) {
                    continue;
                }
                if let serde_json::Value::String(s) = value {
                    // Empty strings would always be substrings — skip.
                    if s.is_empty() {
                        continue;
                    }
                    // Strings that look like already-redacted markers
                    // would trivially fail this check; skip them.
                    if s.starts_with("<redacted:") || s.starts_with("salted:") {
                        continue;
                    }
                    let s_bytes = s.as_bytes();
                    assert!(
                        !serialized.windows(s_bytes.len()).any(|w| w == s_bytes),
                        "redacted serialization leaked non-Verbatim string {s:?} \
                         from field {name:?} (tool={tool:?})",
                        tool = start.tool,
                    );
                }
            }
        }
    }
});
```

The `assert!` panics are intentional — libfuzzer reports a panic inside `fuzz_target!` as a finding with reproducer bytes attached, which is the exact signal we want for a redaction-leak regression.

- [ ] **Step 3: Verify the harness builds on nightly**

Run:
```bash
cd fuzz && cargo +nightly fuzz build audit_jsonl && cd ..
```

Expected: clean build. If it fails with `unresolved import 'rimap_audit::parse_line'` or `'rimap_audit::redact'`, the re-exports from Tasks 1–2 are wrong — re-check `crates/rimap-audit/src/lib.rs`.

- [ ] **Step 4: Seed the corpus**

Real audit-log lines are not generated outside of integration runs, so the seed corpus is hand-crafted plus a one-time extract from any existing test fixture that produces JSONL. Run:

```bash
mkdir -p fuzz/corpus/audit_jsonl

# Hand-crafted edge cases. Each file is one JSONL line (no trailing
# newline — parse_line takes a single line's bytes).

# Valid records — one per Payload variant.
printf '{"seq":1,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_start","binary_path":"/usr/local/bin/rimap-mcp","binary_sha256":"%s","argv":["rimap-mcp"],"pid":1234,"version":"1.0.0"}' \
    "$(printf '0%.0s' {1..64})" > fuzz/corpus/audit_jsonl/process_start.jsonl
printf '{"seq":2,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"process_end","reason":"eof","total_tool_calls":3}' \
    > fuzz/corpus/audit_jsonl/process_end.jsonl
printf '{"seq":3,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"auth","account":"acct","host":"imap.example.com","port":993,"result":"ok"}' \
    > fuzz/corpus/audit_jsonl/auth_ok.jsonl
printf '{"seq":4,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"tool_start","account":"acct","tool":"search","posture_effective":"restricted","arguments_redacted":{"folder":"INBOX","subject":"<redacted:5>"},"arguments_hash_sha256":"%s"}' \
    "$(printf 'a%.0s' {1..64})" > fuzz/corpus/audit_jsonl/tool_start_search.jsonl
printf '{"seq":5,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"tool_end","account":"acct","tool":"search","status":"ok","duration_ms":42,"result_summary":{"hits":3}}' \
    > fuzz/corpus/audit_jsonl/tool_end_ok.jsonl
printf '{"seq":6,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"config","event":"posture_changed","account":"acct","posture_effective":"restricted"}' \
    > fuzz/corpus/audit_jsonl/config.jsonl

# Edge cases — parse failures the harness must shrug off without panic.
printf '' > fuzz/corpus/audit_jsonl/empty.jsonl
printf '{' > fuzz/corpus/audit_jsonl/truncated.jsonl
printf '{"seq":1}' > fuzz/corpus/audit_jsonl/missing_fields.jsonl
printf '{"kind":"unknown_kind","seq":1,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000"}' \
    > fuzz/corpus/audit_jsonl/unknown_kind.jsonl
printf '\xef\xbb\xbf{"seq":1}' > fuzz/corpus/audit_jsonl/leading_bom.jsonl
printf '\x00\x00\x00\x00' > fuzz/corpus/audit_jsonl/nuls.jsonl
printf '{"seq":1,"ts":"\\nbad"}' > fuzz/corpus/audit_jsonl/embedded_lf.jsonl
printf '{"seq":1,"ts":"%s"}' "$(printf 'A%.0s' {1..2048})" > fuzz/corpus/audit_jsonl/oversized_string.jsonl

# tool_start with sensitive-looking strings — exercises the substring
# leak check in the harness. Each value should be redacted to "<redacted:N>"
# under the Search tool's schema (subject = RedactString).
printf '{"seq":7,"ts":"2026-05-05T12:00:00.000Z","process_id":"01HM0000000000000000000000","kind":"tool_start","account":"acct","tool":"search","posture_effective":"restricted","arguments_redacted":{"subject":"PLAINTEXT-SECRET"},"arguments_hash_sha256":"%s"}' \
    "$(printf 'b%.0s' {1..64})" > fuzz/corpus/audit_jsonl/tool_start_leak_probe.jsonl

ls fuzz/corpus/audit_jsonl | wc -l
```

Expected: at least 14 files. If the count is lower, a `printf` invocation failed silently — re-run interactively. Any of the printf-with-positional-arg lines may need adjustment if your shell escapes `%s` differently (the `0%.0s` and `a%.0s` patterns are bash-specific brace-expansion repetition tricks; for zsh, replace with `printf '%.s0' {1..64}` or pre-build the strings).

- [ ] **Step 5: Run the harness for 60 seconds locally**

Run:
```bash
cd fuzz && cargo +nightly fuzz run audit_jsonl -- -max_total_time=60 && cd ..
```

Expected: clean 60-second run, no crash. The libfuzzer `INITED` line should report `corpus:` ≥ 14 (the seed count). If the harness panics with the `redacted serialization leaked …` assertion, **stop** — you've found a real redaction bug. Triage before proceeding (file an issue and gate this PR on the fix).

- [ ] **Step 6: Commit**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets/audit_jsonl.rs fuzz/corpus/audit_jsonl/
git commit -m "test(fuzz): add audit_jsonl harness for parse_line + redact

Drives rimap_audit::reader::parse_line and rimap_audit::redact::redact
on raw bytes. Asserts: parse_line never panics; redacted records round-
trip via serde_json; for tool_start payloads, no non-Verbatim string
field's value appears as substring of the redacted serialization.

Seed corpus: one valid record per Payload variant, plus eight edge
cases (empty, truncated, missing fields, unknown kind, leading BOM,
NUL bytes, embedded LF, oversized string) and one redaction leak
probe.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.1, §5.3"
```

---

## Task 5: Refresh `cargo-mutants` baseline on `rimap-audit`

**Why:** The 2026-04-08 baseline reports zero survivors in `rimap-audit`, but the codebase has had heavy churn since (BootError introduction, rotation clock seam, daemon transport rollback re-extraction). Per the issue's "reality check" note, refresh first against current `main` before claiming the baseline is current.

**Files:**
- No source files modified in this task — output goes to `mutants.out/` (gitignored) and `/tmp/`.

- [ ] **Step 1: Run the targeted mutation suite**

Run:
```bash
just mutants --package rimap-audit --no-shuffle 2>&1 | tee /tmp/mutants-rimap-audit.log
```

Expected runtime: 20–60 minutes depending on host. The command writes per-mutant outcomes (`caught`, `missed`, `unviable`, `timeout`) to stdout and to `mutants.out/`.

- [ ] **Step 2: Snapshot the survivors**

Run:
```bash
SURVIVORS_TOTAL=$(grep -E "^crates/rimap-audit/src/" mutants.out/missed.txt 2>/dev/null | wc -l | tr -d ' ')
SURVIVORS_HOT=$(grep -E "^crates/rimap-audit/src/(writer/|redact/|reader/)" mutants.out/missed.txt 2>/dev/null | wc -l | tr -d ' ')
echo "rimap-audit total survivors:                  $SURVIVORS_TOTAL"
echo "rimap-audit security-sensitive-path survivors: $SURVIVORS_HOT (writer/, redact/, reader/)"
grep -E "^crates/rimap-audit/src/(writer/|redact/|reader/)" mutants.out/missed.txt > /tmp/rimap-audit-hot-survivors.txt
grep -E "^crates/rimap-audit/src/(cancellation\.rs|fs\.rs|record/)" mutants.out/missed.txt > /tmp/rimap-audit-cold-survivors.txt
wc -l /tmp/rimap-audit-hot-survivors.txt /tmp/rimap-audit-cold-survivors.txt
```

Decision points:
- If `SURVIVORS_HOT` is **> 25**, this is the over-cap signal from the §"Out-of-band split" section: stop, file an issue titled `test(rimap-audit): finish mutation cleanup deferred from Sprint B2`, document the count, and skip Task 6 in this PR. The fuzz harness still ships; the cleanup ships in a follow-up.
- If `SURVIVORS_HOT` is **0–25**, proceed.

- [ ] **Step 3: No commit yet — `mutants.out/` is gitignored**

The output file `/tmp/rimap-audit-hot-survivors.txt` drives Task 6's iteration. Nothing committed in this task.

---

## Task 6: Mutation cleanup — `rimap-audit` security-sensitive paths

**Why:** Per spec §5.4, every survivor in `writer/`, `redact/`, `reader/` must be killed (test added) or annotated with rationale (equivalent mutation). Plumbing modules (`cancellation.rs`, `fs.rs`, `record/`) are best-effort: kill survivors that change observable output, annotate equivalent mutants.

**Files:** iterative — depends on the survivor list from Task 5. Tests land in `crates/rimap-audit/src/<module>/` `#[cfg(test)]` blocks or in `crates/rimap-audit/tests/*.rs`. Annotations land inline above the mutated line. The baseline doc gets a row per annotated mutant in Task 9.

- [ ] **Step 1: Walk the hot-survivor list**

For each line in `/tmp/rimap-audit-hot-survivors.txt`:

  1. **Read the mutation.** Open the named file at the named line. Read enough surrounding code to understand what changes.

  2. **Decide: real gap, or equivalent mutant?** Most mutations are real test gaps. A few are equivalent — the mutated code produces output indistinguishable from the original under the function's contract.

  3. **If real gap, write a failing test.** Pick the test file that exercises this module (in-crate `#[cfg(test)]` for unit-level mutations, or `crates/rimap-audit/tests/*.rs` for integration-level ones). Add a test that asserts the precise behavior the mutation breaks:

     ```bash
     cargo nextest run --package rimap-audit --all-features -- <test_name>
     ```

     The test must pass under unmutated code. Sanity-check by hand-applying the mutation locally and confirming the test fails — then revert the mutation. If the test passes under both, it's not catching the mutation; tighten it.

  4. **If equivalent mutant, annotate.** Add a comment immediately above the mutated line:
     ```rust
     // cargo-mutants: known-equivalent — <one-line rationale>
     ```
     Annotation rationales must explain *why* the mutation is observably indistinguishable, not just "it doesn't matter." Examples to model on are in `crates/rimap-content/src/html/mismatch.rs` (look for `cargo-mutants: known-equivalent`).

  5. **Track the row** for Task 9. Open a scratch file `/tmp/rimap-audit-baseline-rows.md` and append a markdown table row per annotated mutant in this format:
     ```
     | path/to/file.rs:LINE | replace X with Y in fn_name | <rationale> | path/to/file.rs:ANNOTATION_LINE |
     ```

- [ ] **Step 2: Walk the cold-survivor list (best-effort)**

For each line in `/tmp/rimap-audit-cold-survivors.txt`:

  - **Changes observable output / API contract** → kill with a test (Step 1.3 sub-procedure).
  - **Equivalent under documented round-trip** → annotate inline + baseline-doc row.
  - **Pure cosmetic** (e.g., `tracing::debug!` formatting) → annotate inline + baseline-doc row with rationale "diagnostic-only, never observed externally."

The bar is lower here than in Step 1: "internal counter, never read by tests or production" is a complete justification.

- [ ] **Step 3: Re-run mutation tests on the cleaned crate to verify**

Run:
```bash
just mutants --package rimap-audit --no-shuffle
```

Expected: every formerly-missed mutation in the hot paths is either now `caught` (test killed it) or has an inline `// cargo-mutants: known-equivalent` annotation. Cold-path survivors that you chose to annotate must also have the annotation. cargo-mutants does not parse the annotation — the comment is for humans; the source-of-truth that "this survivor is intentional" is the row in `mutation-baseline.md` (Task 9).

If new mutations appeared (e.g. because added tests changed the file), repeat Step 1/Step 2 for the new list.

- [ ] **Step 4: Verify the workspace still builds clean**

Run:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-audit --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit (one commit per module group)**

Group commits by module so the history is readable:

```bash
# Example: writer/ cleanup
git add crates/rimap-audit/src/writer/ crates/rimap-audit/tests/
git commit -m "test(rimap-audit): close mutation gaps in writer/

Adds N tests covering specific cargo-mutants survivors uncovered by
the 2026-05-05 baseline refresh. M known-equivalent mutants annotated
inline with rationale.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.4"
```

Repeat the commit pattern for `redact/` and `reader/`. If you fixed any cold-path survivors, commit them under a single `test(rimap-audit): close mutation gaps in plumbing modules` commit.

---

## Task 7: Refresh `cargo-mutants` baseline on `rimap-authz`

**Why:** Same reality check as Task 5 — the stale 2026-04-08 baseline reported zero survivors but predates several commits. Refresh first.

**Files:** none modified — output is mutants.out/ + /tmp/.

- [ ] **Step 1: Run the targeted mutation suite**

Run:
```bash
just mutants --package rimap-authz --no-shuffle 2>&1 | tee /tmp/mutants-rimap-authz.log
```

Expected runtime: 10–30 minutes (rimap-authz is smaller than rimap-audit).

- [ ] **Step 2: Snapshot the survivors**

Run:
```bash
SURVIVORS_TOTAL=$(grep -E "^crates/rimap-authz/src/" mutants.out/missed.txt 2>/dev/null | wc -l | tr -d ' ')
SURVIVORS_HOT=$(grep -E "^crates/rimap-authz/src/(matrix\.rs|breaker\.rs|rate_limit\.rs|folder_guard\.rs|folder_name\.rs)" mutants.out/missed.txt 2>/dev/null | wc -l | tr -d ' ')
echo "rimap-authz total survivors:                  $SURVIVORS_TOTAL"
echo "rimap-authz security-sensitive-path survivors: $SURVIVORS_HOT"
grep -E "^crates/rimap-authz/src/(matrix\.rs|breaker\.rs|rate_limit\.rs|folder_guard\.rs|folder_name\.rs)" mutants.out/missed.txt > /tmp/rimap-authz-hot-survivors.txt
grep -E "^crates/rimap-authz/src/(error\.rs|guard\.rs)" mutants.out/missed.txt > /tmp/rimap-authz-cold-survivors.txt
wc -l /tmp/rimap-authz-hot-survivors.txt /tmp/rimap-authz-cold-survivors.txt
```

If `SURVIVORS_HOT` > 25, file the over-cap follow-up issue (mirror Task 5 Step 2) and skip Task 8 in this PR.

If `SURVIVORS_HOT` ≤ 25, proceed.

- [ ] **Step 3: No commit — output is in /tmp/**

---

## Task 8: Mutation cleanup — `rimap-authz` security-sensitive paths

**Why:** Spec §5.4 names `matrix.rs`, `breaker.rs`, `rate_limit.rs`, `folder_guard.rs`, `folder_name.rs` as security-critical. Same triage rules as Task 6: kill or annotate.

**Files:** iterative — see Task 6 pattern. Tests land in `crates/rimap-authz/src/<file>.rs` `#[cfg(test)]` blocks (each authz file already has one — see `grep -nE "^#\[cfg\(test\)\]" crates/rimap-authz/src/*.rs`). Annotations inline.

- [ ] **Step 1: Walk the hot-survivor list**

For each line in `/tmp/rimap-authz-hot-survivors.txt`, follow the Task 6 Step 1 sub-procedure (read → decide → write test or annotate → track row).

A note on `breaker.rs`: it uses a `Clock` trait with a `ManualClock` implementation, which makes time-based tests deterministic — there is no excuse for a "can't kill this without sleeping" survivor here. If you find one, the test belongs in `breaker.rs` `#[cfg(test)]` driving `ManualClock::advance(Duration::from_millis(...))`.

A note on `rate_limit.rs`: the `governor` crate's rate limiter uses a clock-based bucket; tests should use `governor::clock::FakeRelativeClock` or the `Clock` abstraction in this file. Survivors that depend on real wall-clock time should be killable with the fake clock.

- [ ] **Step 2: Walk the cold-survivor list**

For each line in `/tmp/rimap-authz-cold-survivors.txt`, decide kill-or-annotate per the Task 6 Step 2 rules.

- [ ] **Step 3: Re-run mutation tests on the cleaned crate**

Run:
```bash
just mutants --package rimap-authz --no-shuffle
```

Expected: zero unannotated survivors in the hot paths.

- [ ] **Step 4: Verify clean build + tests**

Run:
```bash
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run --package rimap-authz --all-features --locked
```

Expected: both clean.

- [ ] **Step 5: Commit (one commit per file group)**

Group by file so the history reads as `breaker`, `matrix`, `rate_limit`, etc.:

```bash
git add crates/rimap-authz/src/breaker.rs
git commit -m "test(rimap-authz): close mutation gaps in breaker.rs

Adds N tests covering specific cargo-mutants survivors uncovered by
the 2026-05-05 baseline refresh. M known-equivalent mutants annotated
inline with rationale.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.4"
```

Repeat for the other four files in the hot-path set.

---

## Task 9: Update `mutation-baseline.md` with B2 sections

**Why:** Spec §5.7 done-criterion 5: "`mutation-baseline.md` updated." The doc already has placeholder sections for `rimap-authz` and `rimap-audit` as scaffolds (or "Populated in Sprint B2." markers); replace those with the populated tables built in Tasks 6 and 8.

**Files:**
- Modify: `docs/superpowers/specs/test-strategy/mutation-baseline.md`

- [ ] **Step 1: Confirm current state**

Run:
```bash
grep -nE "^## \`rimap-(authz|audit)\`" docs/superpowers/specs/test-strategy/mutation-baseline.md
sed -n '/^## `rimap-authz`/,/^## /p' docs/superpowers/specs/test-strategy/mutation-baseline.md | head -20
sed -n '/^## `rimap-audit`/,/^## /p' docs/superpowers/specs/test-strategy/mutation-baseline.md | head -20
```

Expected: two section headers, each followed either by a "_Populated in Sprint B2._" placeholder or by an existing scaffold table. Both will be replaced.

- [ ] **Step 2: Replace the `rimap-audit` section**

Edit `docs/superpowers/specs/test-strategy/mutation-baseline.md`. Find the `## \`rimap-audit\`` heading and replace its body (everything between that heading and the next `## ` heading or EOF) with:

```markdown
## `rimap-audit`

**Last refresh:** 2026-05-05.
**Surviving mutants in hot paths (`writer/`, `redact/`, `reader/`):** N.
**Surviving mutants in plumbing (`cancellation.rs`, `fs.rs`, `record/`):** M (best-effort).

Run summary (Y mutants total, 2026-05-05 full run via `just mutants
--package rimap-audit`): A caught, B missed, C timeout, D unviable
in T minutes wall clock. Every hot-path survivor below is either a
mathematically equivalent mutation (annotated inline with rationale) or
a plumbing-code survivor whose mutation does not change observable
output.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
<!-- Paste the rows you accumulated in /tmp/rimap-audit-baseline-rows.md
     here, one per annotated survivor. If empty (every survivor was
     killed by a test), keep the table empty. -->
```

Replace `N`, `M`, `Y`, `A`, `B`, `C`, `D`, `T` with the actual numbers from your Task 5 run + Task 6 cleanup result. Paste rows from `/tmp/rimap-audit-baseline-rows.md`.

- [ ] **Step 3: Replace the `rimap-authz` section**

Find the `## \`rimap-authz\`` heading and replace its body with the same template, populated for authz:

```markdown
## `rimap-authz`

**Last refresh:** 2026-05-05.
**Surviving mutants in hot paths (`matrix.rs`, `breaker.rs`, `rate_limit.rs`, `folder_guard.rs`, `folder_name.rs`):** N.
**Surviving mutants in plumbing (`error.rs`, `guard.rs`):** M (best-effort).

Run summary (Y mutants total, 2026-05-05 full run via `just mutants
--package rimap-authz`): A caught, B missed, C timeout, D unviable in
T minutes wall clock. Every hot-path survivor below is mathematically
equivalent and annotated inline with rationale.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
<!-- Rows from Task 8 cleanup. -->
```

- [ ] **Step 4: Update the doc-front "Updated:" stamp**

Edit the `**Updated:**` line near the top of `mutation-baseline.md`. Change the date to `2026-05-05`. (If the existing stamp is already 2026-05-05 from a same-day rimap-content refresh, keep it.)

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/test-strategy/mutation-baseline.md
git commit -m "docs(test-strategy): populate mutation-baseline B2 sections

Records the post-cleanup state for rimap-audit and rimap-authz from
the 2026-05-05 baseline refresh. Each row pins a known-equivalent
mutant to an inline annotation in the source.

Refs: #244, docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md §5.7"
```

---

## Task 10: Smoke-test the workflow on a draft PR

**Why:** ClusterFuzzLite picks up every fuzz target the build emits — the `pr-smoke` job in `.github/workflows/fuzz.yml` already shares its 600 s budget across all targets, so adding `audit_jsonl` requires no workflow edit. The draft PR is the cheapest way to confirm the new target builds and runs in CI.

**Files:** none — verification step only.

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin feat/test-strategy-b2-authz-audit
```

- [ ] **Step 2: Open a draft PR**

```bash
gh pr create --draft --title "test: B2 — rimap-authz + rimap-audit fuzz + mutation hardening" \
  --body "$(cat <<'EOF'
## Summary

Sprint B2 of the test-strategy-improvements plan ([#244](https://github.com/randomparity/rusty-imap-mcp/issues/244)).

- Adds `parse_line` + `redact` public helpers to `rimap-audit` matching the spec-named entry points.
- Adds `audit_jsonl` cargo-fuzz harness with 14-file seed corpus.
- Refreshes `cargo-mutants` baseline against current `main` for `rimap-authz` and `rimap-audit`; kills or annotates every survivor in the security-sensitive paths from spec §5.4.
- Updates `docs/superpowers/specs/test-strategy/mutation-baseline.md` with both crates' populated tables.
- ClusterFuzzLite PR-smoke automatically picks up the new target — no workflow edit required.

## Test plan

- [ ] All existing CI checks pass (rustfmt, clippy, check (macOS), test (stable), test (MSRV 1.88.0), cargo-deny, zizmor self-check).
- [ ] `just fuzz audit_jsonl` runs ≥ 5 minutes locally without crash.
- [ ] `cargo mutants --package rimap-audit` reports zero unannotated survivors in `writer/`, `redact/`, `reader/`.
- [ ] `cargo mutants --package rimap-authz` reports zero unannotated survivors in `matrix.rs`, `breaker.rs`, `rate_limit.rs`, `folder_guard.rs`, `folder_name.rs`.
- [ ] The `fuzz / pr-smoke` job appears in this PR's status checks and runs to completion green.
- [ ] `mutation-baseline.md` documents the new state for both crates.

## Spec / issue refs

- Spec: `docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md` §5.
- Tracking issue: #244.
- Plan: `docs/superpowers/plans/2026-05-05-issue-244-test-strategy-b2-authz-audit.md`.

EOF
)"
```

- [ ] **Step 3: Watch CI**

Run:
```bash
gh pr checks --watch
```

Expected: every existing check plus the `fuzz / pr-smoke` job pass. If `pr-smoke` reports a build failure mentioning `audit_jsonl`, the harness or its corpus path resolution is wrong — fix locally, push, watch again. If `pr-smoke` reports a *crash* in `audit_jsonl`, libfuzzer found a real bug (most likely the redaction-leak assertion firing); triage before merging — this PR cannot land until either the bug is fixed or the assertion is intentionally relaxed with rationale.

- [ ] **Step 4: Mark the PR ready for review**

Once CI is green:
```bash
gh pr ready
```

---

## Wrap-up

- [ ] **Step 1: Tick off Sprint B2's spec done-criteria**

Per spec §5.7:

- [ ] `just fuzz audit_jsonl` runs locally for ≥ 5 minutes without crash.
- [ ] `cargo mutants --package rimap-audit` reports 0 unannotated survivors in `writer/`, `redact/`, `reader/`.
- [ ] `cargo mutants --package rimap-authz` reports 0 unannotated survivors in `matrix.rs`, `breaker.rs`, `rate_limit.rs`, `folder_guard.rs`, `folder_name.rs`.
- [ ] CFL PR-smoke is green with the additional target.
- [ ] `mutation-baseline.md` updated.

- [ ] **Step 2: Run the long-form fuzz validation locally before requesting review**

The 60-second smoke from Task 4 Step 5 is not the spec's done-criterion runtime. Run the full 5-minute smoke:

```bash
just fuzz audit_jsonl -- -max_total_time=300
```

Expected: 5-minute clean exit, no crash.

- [ ] **Step 3: Request review**

```bash
gh pr comment --body "Ready for review — Sprint B2 done-criteria verified locally and in CI."
```

- [ ] **Step 4: After merge — open follow-up issues for any deferrals**

Two issues are conditional on Tasks 5/7 hitting the over-cap signal:

1. **`test(rimap-audit): finish mutation cleanup deferred from Sprint B2`** — only if Task 5 reported >25 hot-path survivors and Task 6 was skipped. Body cites this PR and the survivor count.
2. **`test(rimap-authz): finish mutation cleanup deferred from Sprint B2`** — same trigger for Task 7/8.

If neither was triggered, no follow-ups are needed for B2. (Sprint B3 — `rimap-server` + `rimap-imap` — is tracked separately and is not in scope here.)

---

## Out-of-band split

If Task 5 or Task 7 reports more than 25 hot-path survivors, the cleanup is no longer "small and bundleable" and warrants its own PR. The split:

- **This PR:** Tasks 1–4 (helpers + fuzz harness + corpus), Task 5 or 7 (whichever hit the cap, baseline refresh + survivor inventory written to `/tmp/`), Task 9 (mutation-baseline.md update — record the survivor count and explicitly note "cleanup deferred to follow-up issue"), Task 10 (draft PR + CI). The fuzz harness still ships and is the bulk of the spec's value.
- **Follow-up PR (per affected crate):** the corresponding Task 6 or 8 cleanup work, plus a final `mutation-baseline.md` update replacing the "deferred" note with the populated table.

The split is a per-crate decision: if `rimap-audit` is over-cap but `rimap-authz` is not, do `rimap-authz`'s cleanup in this PR and defer only `rimap-audit`'s.

---

## Self-review checklist (writer-side)

- **Spec coverage:** every Sprint B2 sub-section in spec §5 maps to a task — fuzz harness (Tasks 1–4), mutation refresh (Tasks 5, 7), mutation cleanup (Tasks 6, 8), CFL wiring confirmation (Task 10), done-criteria validation (Wrap-up Step 1), `mutation-baseline.md` update (Task 9). The §5.2 carve-out ("no fuzz target for rimap-authz") is honored — no authz fuzz target appears in this plan.
- **B1 infrastructure assumed live:** Pre-flight Step 1 verifies `fuzz/`, the workflow, and `mutation-baseline.md` exist. If any is missing, the executor stops and rebases on a `main` that has B1 merged before running the rest.
- **No placeholders:** every code block has literal text. The two count-substitution placeholders in Task 9's templates (`N`, `M`, `Y`, `A`, `B`, `C`, `D`, `T`) are explicit "replace with the run's actual numbers" — that's by design, not an unfilled slot.
- **Type/name consistency:** `parse_line(raw: &[u8]) -> Result<AuditRecord, AuditError>` is defined in Task 1 and consumed by Task 4's harness via `rimap_audit::parse_line`. `redact(record: &AuditRecord, salt: &RedactionSalt) -> AuditRecord` is defined in Task 2 and consumed similarly. The harness's `ToolRedactionSchema` import matches the existing `pub use` in `lib.rs`.
- **TDD-shape:** Tasks 1 and 2 (the only behavioral changes) are shaped failing-test-first. Task 4 (the fuzz harness) is shaped build-then-run because libfuzzer harnesses don't have a "failing test" framing — the test is the long-running fuzzer. Tasks 6 and 8 (mutation cleanup) embed a kill-or-annotate decision per survivor with a "test must fail under hand-applied mutation" sanity check.
- **One commit per logical change:** Tasks 1, 2, 3, 4, 9 each end in one commit. Tasks 6 and 8 group commits by module/file so history reads cleanly per `writer/`, `redact/`, `reader/`, `matrix.rs`, etc.
- **Out-of-band actions are flagged:** the >25 over-cap signal is called out in Task 5 Step 2 and Task 7 Step 2; the follow-up issues are spelled out in Wrap-up Step 4 and the §"Out-of-band split" section.
- **Cost/value tradeoffs documented:** Task 4's substring-leak assertion logic, the Task 6 hot/cold path bar difference, and the §"Out-of-band split" trigger are all motivated inline.
