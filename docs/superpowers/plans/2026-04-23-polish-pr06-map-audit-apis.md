# Polish PR 6 — `&Map`-taking APIs in the audit envelope (#149)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `rimap_server::mcp::audit_envelope::compute_tool_args_artifacts` pass `&serde_json::Map<String, Value>` to redaction and hashing, instead of wrapping into `Value::Object(args.clone())` just to satisfy the `&Value` signatures. Adds two additive APIs to `rimap-audit` (`Redactor::apply_map` and `hash_arguments_map`), leaves the existing `apply` / `hash_arguments` as thin wrappers, and produces byte-identical output.

**Architecture:** Purely additive public API on `rimap-audit`. The existing `apply(&Value)` and `hash_arguments(&Value)` are preserved so no external caller churns. Internally, the object branch of `apply` delegates to `apply_map`; `hash_arguments(Value::Object(m))` and `hash_arguments_map(&m)` produce byte-identical bytes because `serde_json::to_vec(Value::Object(m))` forwards directly to `Map::serialize` — a serde-transparent property we lock with a regression test.

**Tech Stack:** Rust, `serde_json::{Value, Map}`.

---

## Context the engineer must read first

- `crates/rimap-audit/src/redact/mod.rs`
  - `Redactor::apply(&self, args: &Value) -> Value` — lines 114–152. Non-object branch (lines 116–123) produces a `_non_object` placeholder; object branch iterates the inner `Map` with per-field policy dispatch.
  - `hash_arguments(args: &Value) -> String` — lines 186–196. Canonicalizes via `serde_json::to_vec(value)`, SHA-256, hex.
- `crates/rimap-server/src/mcp/audit_envelope.rs:160-170` — `compute_tool_args_artifacts`:
  ```rust
  let args_value = serde_json::Value::Object(args.clone());
  let redacted = Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref())
      .apply(&args_value);
  let hash = hash_arguments(&args_value);
  (redacted, hash)
  ```
  The `args.clone()` is the exact cost this PR removes.
- `crates/rimap-server/src/mcp/audit_envelope.rs:432-504` — `compute_artifacts_hashes_full_map_including_account_key` test asserts the hash of a specific on-wire map against `hash_arguments(&Value::Object(args.clone()))`. After this PR, the same expected value is derived via `hash_arguments_map(&args)` and the assertion still holds bytewise.
- `crates/rimap-audit/tests/redact_properties.rs` — external user of `hash_arguments(&Value)` and `Redactor::apply(&Value)`. Must continue to compile unchanged (proves the wrappers are still in the public API).
- Serde-transparent property: `Value::serialize` (from the `serde_json::Value` impl) matches on `Value::Object(m)` and calls `m.serialize(serializer)` — there is no outer framing. Therefore `serde_json::to_vec(&Value::Object(m))` and `serde_json::to_vec(&m)` produce byte-identical output. This is the invariant that lets us migrate without changing audit hashes.

## Effort note

This is the smallest of the four Wave B PRs — two additive fns, one call-site rewrite, three new tests. The lift is almost entirely in writing the byte-identity regression tests so the next refactor cannot accidentally break hash stability.

---

## Files

- Modify: `crates/rimap-audit/src/redact/mod.rs` — add `Redactor::apply_map`, refactor `apply` to delegate, add `hash_arguments_map`, keep `hash_arguments` wrapping `serde_json::to_vec(value)`; add byte-identity tests.
- Modify: `crates/rimap-audit/src/lib.rs` — re-export `hash_arguments_map` next to `hash_arguments`.
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs` — swap `compute_tool_args_artifacts` to call `apply_map` + `hash_arguments_map`; drop the `args_value` intermediate; update the import list.

## Task 1: Add `apply_map` and `hash_arguments_map` + byte-identity tests to `rimap-audit`

**Files:**
- Modify: `crates/rimap-audit/src/redact/mod.rs`
- Modify: `crates/rimap-audit/src/lib.rs`

- [ ] **Step 1: Write the failing byte-identity tests**

Append these three tests to the existing `#[cfg(test)] mod tests` block in `crates/rimap-audit/src/redact/mod.rs` (the block starts at line 520-ish):

```rust
    #[test]
    fn apply_and_apply_map_produce_identical_output_for_object_input() {
        // The new apply_map exists so callers with a Map in hand skip the
        // Value::Object wrap+clone. Output MUST be byte-identical to what
        // apply(&Value::Object(map)) returns, otherwise callers migrating
        // from one to the other would break on-disk audit record stability.
        let s = schema();
        let salt = salt();
        let r = Redactor::new(&s, &salt);
        let map: serde_json::Map<String, serde_json::Value> = json!({
            "subject": "hi",
            "body_text": "long body",
            "in_reply_to_uid": 42,
        })
        .as_object()
        .unwrap()
        .clone();
        let via_value = r.apply(&serde_json::Value::Object(map.clone()));
        let via_map = r.apply_map(&map);
        assert_eq!(via_value, via_map);
    }

    #[test]
    fn hash_arguments_and_hash_arguments_map_are_byte_identical_for_object_input() {
        // Same invariant for the hash function: if callers switch from
        // hash_arguments(Value) to hash_arguments_map(Map), the audit
        // record's arguments_hash_sha256 field must not change.
        let map: serde_json::Map<String, serde_json::Value> = json!({
            "folder": "INBOX",
            "uid": 17,
            "subject": "hi",
        })
        .as_object()
        .unwrap()
        .clone();
        let via_value = hash_arguments(&serde_json::Value::Object(map.clone()));
        let via_map = hash_arguments_map(&map);
        assert_eq!(via_value, via_map);
    }

    #[test]
    fn hash_arguments_map_is_deterministic() {
        // Parallel guard to the pre-existing `hash_arguments_is_stable_and_hex_encoded`
        // test, but for the Map variant — ensures the Map path does not
        // accidentally serialize with a different field-ordering policy.
        let map: serde_json::Map<String, serde_json::Value> = json!({
            "uid": 1,
            "folder": "INBOX",
        })
        .as_object()
        .unwrap()
        .clone();
        let a = hash_arguments_map(&map);
        let b = hash_arguments_map(&map);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
```

Update the existing `use` line near the top of the test module (currently `use crate::redact::{FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments};`) to also import `hash_arguments_map`:

```rust
    use crate::redact::{
        FieldPolicy, RedactionSalt, RedactionSchema, Redactor, hash_arguments, hash_arguments_map,
    };
```

- [ ] **Step 2: Run the tests to confirm they fail to compile**

Run: `cargo test -p rimap-audit --lib redact::tests::hash_arguments_map_is_deterministic`
Expected: compile error — `cannot find function hash_arguments_map` and/or `method apply_map not found`.

- [ ] **Step 3: Add `Redactor::apply_map` and refactor `apply`**

In `crates/rimap-audit/src/redact/mod.rs`, replace the existing `apply` method body (lines 114–152):

```rust
    /// Apply the schema to `args`, which must be a JSON object.
    ///
    /// Non-object inputs are turned into a one-field object
    /// `{"_non_object": "<redacted:?>"}` so the audit layer always writes a
    /// homogeneous shape.
    #[must_use]
    pub fn apply(&self, args: &Value) -> Value {
        let Value::Object(map) = args else {
            let mut out = Map::new();
            out.insert(
                "_non_object".to_string(),
                Value::String("<redacted:?>".to_string()),
            );
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
                        tool = self.schema.tool.as_str(),
                        field = name.as_str(),
                        "forbidden field present in tool arguments; dropped",
                    );
                }
            }
        }
        Value::Object(out)
    }
```

with:

```rust
    /// Apply the schema to `args`, which must be a JSON object.
    ///
    /// Non-object inputs are turned into a one-field object
    /// `{"_non_object": "<redacted:?>"}` so the audit layer always writes a
    /// homogeneous shape. Callers that already hold an owned
    /// `Map<String, Value>` should call [`Redactor::apply_map`] directly;
    /// this method exists to preserve the `&Value` public surface.
    #[must_use]
    pub fn apply(&self, args: &Value) -> Value {
        match args {
            Value::Object(map) => self.apply_map(map),
            _ => {
                let mut out = Map::new();
                out.insert(
                    "_non_object".to_string(),
                    Value::String("<redacted:?>".to_string()),
                );
                Value::Object(out)
            }
        }
    }

    /// Apply the schema to an argument map directly, skipping the
    /// `Value::Object(...)` wrap that [`Redactor::apply`] requires. Output
    /// is byte-identical to `apply(&Value::Object(map.clone()))`; used by
    /// `rimap-server::mcp::audit_envelope::compute_tool_args_artifacts` to
    /// avoid a per-tool-call deep-clone of the argument map (#149).
    #[must_use]
    pub fn apply_map(&self, args: &Map<String, Value>) -> Value {
        let mut out = Map::new();
        for (name, value) in args {
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
                        tool = self.schema.tool.as_str(),
                        field = name.as_str(),
                        "forbidden field present in tool arguments; dropped",
                    );
                }
            }
        }
        Value::Object(out)
    }
```

- [ ] **Step 4: Add `hash_arguments_map` next to `hash_arguments`**

Right after the existing `hash_arguments` function in `crates/rimap-audit/src/redact/mod.rs` (after line 196), add:

```rust
/// Computes `sha256(serde_json::to_vec(args))` on the *unredacted* arguments
/// for the `arguments_hash_sha256` audit field. Accepts `&Map<String, Value>`
/// directly so callers with an already-owned map skip the
/// `Value::Object(...)` wrap+clone.
///
/// Output is byte-identical to `hash_arguments(&Value::Object(map.clone()))`
/// because `Value::serialize` delegates to `Map::serialize` for the Object
/// variant — no outer framing is emitted.
#[must_use]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "serde_json::to_vec(Map<String, Value>) is infallible"
)]
pub fn hash_arguments_map(args: &Map<String, Value>) -> String {
    let bytes = serde_json::to_vec(args).expect("serde_json::to_vec of Map is infallible");
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}
```

- [ ] **Step 5: Re-export `hash_arguments_map` from the crate root**

In `crates/rimap-audit/src/lib.rs`, update the existing re-export line:

```rust
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, hash_arguments,
    schemas,
};
```

to include the new name:

```rust
pub use crate::redact::{
    FieldPolicy, RedactionSalt, RedactionSchema, Redactor, ToolRedactionSchema, hash_arguments,
    hash_arguments_map, schemas,
};
```

- [ ] **Step 6: Run the tests to confirm they pass**

Run: `cargo test -p rimap-audit --lib redact`
Expected: every pre-existing redact test passes PLUS the three new byte-identity tests pass.

- [ ] **Step 7: Run the property tests (external caller)**

Run: `cargo test -p rimap-audit --test redact_properties`
Expected: the existing property tests still compile and pass — they use `apply(&Value)` and `hash_arguments(&Value)`, which are unchanged as a public surface.

- [ ] **Step 8: Run clippy on `rimap-audit`**

Run: `cargo clippy -p rimap-audit --all-targets --all-features -- -D warnings`
Expected: clean. The `#[expect(clippy::expect_used, ...)]` on `hash_arguments_map` mirrors the existing annotation on `hash_arguments`; no new lint should fire.

- [ ] **Step 9: Commit**

```bash
git add crates/rimap-audit/src/redact/mod.rs crates/rimap-audit/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(rimap-audit): add Redactor::apply_map and hash_arguments_map (#149)

Additive &Map<String, Value> variants of the redact and hash APIs so
callers with an already-owned argument map skip the Value::Object wrap
and the per-call deep clone it implies. Existing &Value APIs remain as
thin wrappers; `apply(Value::Object(m))` delegates to `apply_map(&m)`.

Three byte-identity regression tests lock the two APIs together so a
future refactor cannot accidentally diverge the on-disk audit hash.

Refs #149.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 2: Cut `compute_tool_args_artifacts` over to the `_map` variants

**Files:**
- Modify: `crates/rimap-server/src/mcp/audit_envelope.rs`

- [ ] **Step 1: Write the failing regression test**

This test asserts that after the refactor, the `args_value` intermediate is gone AND the hash output is unchanged. Append to the `#[cfg(test)] mod tests` block in `crates/rimap-server/src/mcp/audit_envelope.rs` (the block starts at line 300-ish):

```rust
    /// Regression test for #149: `compute_tool_args_artifacts` MUST produce
    /// the same `arguments_hash_sha256` after the refactor to
    /// `hash_arguments_map`. If someone swaps the underlying serialization
    /// path (e.g. sorts Map keys, changes the JSON writer), existing
    /// audit-log consumers break. This test compares the output against an
    /// explicit `hash_arguments(&Value::Object(map))` expected value — the
    /// pre-refactor code path — so the identity is pinned regardless of
    /// which implementation `compute_tool_args_artifacts` chooses internally.
    #[tokio::test]
    async fn compute_artifacts_hash_matches_legacy_value_object_path() {
        use std::collections::BTreeMap;
        use std::sync::Arc;

        use rimap_audit::{
            AuditOptions, AuditWriter, Seq,
            redact::{hash_arguments, hash_arguments_map},
        };

        use crate::boot::registry::AccountRegistry;
        use crate::daemon::state::{DaemonState, SessionState};
        use crate::mcp::server::ImapMcpServer;

        let dir = tempdir().unwrap();
        let audit = AuditWriter::open(&AuditOptions {
            path: dir.path().join("audit.jsonl"),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .unwrap();
        let (cancellation_tx, _rx) = rimap_audit::cancellation_channel();
        let download_dir: Arc<std::path::Path> =
            Arc::from(std::path::Path::new("/tmp/test-downloads"));
        let daemon_state = Arc::new(DaemonState {
            registry: Arc::new(AccountRegistry::new(BTreeMap::new())),
            audit,
            download_dir,
            cancellation_tx,
            started_at: std::time::Instant::now(),
            session_permits: Arc::new(tokio::sync::Semaphore::new(64)),
            total_tool_calls: std::sync::atomic::AtomicU64::new(0),
        });
        let session_state = Arc::new(SessionState::new(rimap_core::SessionId::new()));
        let server = ImapMcpServer::new(daemon_state, session_state);

        let mut args = serde_json::Map::new();
        args.insert(
            "folder".to_string(),
            serde_json::Value::String("INBOX".to_string()),
        );
        args.insert(
            "uid".to_string(),
            serde_json::Value::Number(serde_json::Number::from(17)),
        );

        let (_redacted, computed) = server.compute_tool_args_artifacts(ToolName::Search, &args);

        let legacy = hash_arguments(&serde_json::Value::Object(args.clone()));
        let via_map = hash_arguments_map(&args);
        assert_eq!(computed, legacy, "hash diverged from Value::Object path");
        assert_eq!(computed, via_map, "hash diverged from Map path");
    }
```

Caveat: this test assumes the `DaemonState` struct-literal shape at HEAD of `main`. If PR 1 (daemon/state.rs cleanup, #141+#143+#145) has already landed when this PR is executed, the struct-literal body changes — adjust the test to use `DaemonState::new(...)` per that PR's conventions. Check with `git log --oneline main -- crates/rimap-server/src/daemon/state.rs` before writing the test; if PR 1 has merged, use the new constructor.

- [ ] **Step 2: Run the test to confirm it passes against the pre-refactor code**

Run: `cargo test -p rimap-server --lib mcp::audit_envelope::tests::compute_artifacts_hash_matches_legacy_value_object_path`
Expected: pass — the current implementation wraps into `Value::Object(args.clone())` then calls `hash_arguments`, which is byte-identical to `hash_arguments_map(&args)` because of the `Value::serialize` delegation property. The test exists to catch regressions when the implementation swaps.

- [ ] **Step 3: Rewrite `compute_tool_args_artifacts`**

In `crates/rimap-server/src/mcp/audit_envelope.rs`, first update the import line at the top of the file. Replace:

```rust
use rimap_audit::redact::{Redactor, ToolRedactionSchema, hash_arguments};
```

with:

```rust
use rimap_audit::redact::{Redactor, ToolRedactionSchema, hash_arguments_map};
```

(Drop `hash_arguments` from the top-of-file import; the test module's `use` statements still reference it inside their local scope and will import it independently.)

Then replace the method body (`compute_tool_args_artifacts`, around lines 160–170):

```rust
    pub(super) fn compute_tool_args_artifacts(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> (serde_json::Value, String) {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref())
            .apply(&args_value);
        let hash = hash_arguments(&args_value);
        (redacted, hash)
    }
```

with:

```rust
    pub(super) fn compute_tool_args_artifacts(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> (serde_json::Value, String) {
        let redacted = Redactor::new(&tool.redaction_schema(), self.redaction_salt.as_ref())
            .apply_map(args);
        let hash = hash_arguments_map(args);
        (redacted, hash)
    }
```

If PR 1 has landed and the redaction salt is on `DaemonState`, swap `self.redaction_salt.as_ref()` for `self.state.redaction_salt.as_ref()`. Use `rg -n 'redaction_salt' crates/rimap-server/src/mcp/server.rs` to confirm which revision is live.

- [ ] **Step 4: Run the regression test + the existing `compute_artifacts_hashes_full_map_including_account_key` test**

Run:
```bash
cargo test -p rimap-server --lib mcp::audit_envelope::tests::compute_artifacts_hash_matches_legacy_value_object_path
cargo test -p rimap-server --lib mcp::audit_envelope::tests::compute_artifacts_hashes_full_map_including_account_key
```
Expected: both pass. The legacy-matching test proves byte identity; the pre-existing MCP-INJ-02 test proves the hash continues to cover the full on-wire map including the `"account"` key.

- [ ] **Step 5: Confirm no `Value::Object(args.clone())` or `args_value` remains in `audit_envelope.rs`**

Run: `rg -n 'args_value|Value::Object\(args\.clone' crates/rimap-server/src/mcp/audit_envelope.rs`
Expected: zero hits (the in-file test may still reference `Value::Object(args.clone())` as part of the pre-existing MCP-INJ-02 regression guard — that usage is correct and stays). More narrowly:

Run: `rg -n 'let args_value' crates/rimap-server/src/mcp/audit_envelope.rs`
Expected: zero hits.

- [ ] **Step 6: Full `rimap-server` test + clippy**

Run: `cargo test -p rimap-server`
Expected: all tests pass, including `audit_envelope::tests`, `dispatch_ticket`, and `e2e`.

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/src/mcp/audit_envelope.rs
git commit -m "$(cat <<'EOF'
perf(rimap-server): drop per-tool-call args Map clone in audit envelope (#149)

compute_tool_args_artifacts was building Value::Object(args.clone())
only to hand a &Value to Redactor::apply and hash_arguments, both of
which unwrapped back to &Map internally. Swap to apply_map +
hash_arguments_map so the Map is borrowed directly — one deep clone of
the arg map gone per tool call.

Hash output is byte-identical to the previous path (Value::Object
serde delegates to Map::serialize with no outer framing); regression
tests in both rimap-audit and rimap-server pin the identity.

Closes #149.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

## Task 3: Full-workspace verification

**Files:** none — green-gate task.

- [ ] **Step 1: `cargo fmt --check`**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 2: Full clippy with `-D warnings`**

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Full workspace test suite**

Run: `cargo test --workspace`
Expected: every test passes. The three groups to monitor:

- `rimap-audit::redact::tests` — three new byte-identity tests green.
- `rimap-audit::tests::redact_properties` — unchanged property tests still green (public wrappers preserved).
- `rimap-server::mcp::audit_envelope::tests` — the new legacy-match test and the pre-existing MCP-INJ-02 test both green.

- [ ] **Step 4: `cargo deny check`**

Run: `cargo deny check advisories bans licenses`
Expected: clean. No new dependencies in this PR.

- [ ] **Step 5: typos**

Run: `typos`
Expected: clean.

## Self-review checklist

- Two new public APIs (`apply_map`, `hash_arguments_map`) added; two existing APIs (`apply`, `hash_arguments`) preserved as the `&Value` surface. No caller of the preserved APIs churns.
- Three byte-identity tests pin the new APIs against the old: `apply_and_apply_map_produce_identical_output_for_object_input`, `hash_arguments_and_hash_arguments_map_are_byte_identical_for_object_input`, `compute_artifacts_hash_matches_legacy_value_object_path`. Two in rimap-audit (narrow scope), one in rimap-server (integration across the two crates).
- The refactored `compute_tool_args_artifacts` is three lines, no intermediate allocation beyond what the audit writer itself needs.
- `hash_arguments_map` carries the same `#[expect(clippy::expect_used, ...)]` justification as `hash_arguments`; no lint expansion.
- Two commits land: additive APIs + tests, then call-site cut-over. Each is independently buildable and clippy-clean.

## Out of scope

- **Eliminating `apply`'s non-object fallback** — keeps backwards compatibility for external callers (e.g. `redact_properties.rs` uses `apply(&Value)` with `prop_assume!` guards that could in principle pass a non-object). Don't touch it.
- **Renaming the wrappers or marking them `#[deprecated]`** — the spec explicitly wants both surfaces live. A future release may deprecate if external uptake of `_map` is universal, but that is not this PR.
- **Consolidating the redact + hash helpers into a single `compute_args_artifacts` function inside `rimap-audit`** — attractive, but crosses a crate boundary and couples unrelated concerns (redaction schema vs. raw hash). Revisit only if a second call site needs the same pair.

If you find yourself editing outside the Files list, stop and re-read the spec.
