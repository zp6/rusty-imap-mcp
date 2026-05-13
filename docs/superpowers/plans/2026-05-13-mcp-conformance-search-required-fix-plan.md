# Phase 3 Codex-Findings Fix Plan (round 3)

> **For agentic workers:** Use superpowers:executing-plans or apply inline. Single small task, no review/PR-sized scope.

**Goal:** Address the third `/codex:adversarial-review` finding on branch `test/mcp-behavioral-conformance-spec`: per-tool response schemas mark `SearchResultEntry.from` and `to` as required, but the wire `skip_serializing_if = "Vec::is_empty"` annotations cause those keys to be omitted when empty. The Phase 3 validator can therefore reject legitimate server output.

**Architecture:** One mechanical fix. Tell `schemars` that the two fields are optional (via `#[serde(default)]` — schemars 1.x respects serde's `default` attribute and omits the field from the schema's `required` list). Regenerate the one affected fixture. Add a smoke-test payload that omits both fields to confirm the schema accepts the empty-headers wire shape.

**Parent branch:** continue on `test/mcp-behavioral-conformance-spec`.
**Codex review source:** the third adversarial review pass; comparable to rounds 1 and 2 already addressed in earlier plans.

---

## Scope verification (already performed during plan drafting)

The repo-wide grep is:

```bash
grep -rEn 'skip_serializing_if = "Vec::is_empty"' crates/rimap-server/src crates/rimap-content/src
```

Three sites surface:

| Location | Field | Has `default`? | Schema `required`? | Mismatch? |
|---|---|---|---|---|
| `search.rs:72` | `SearchResultEntry.from: Vec<String>` | no | yes | **YES** |
| `search.rs:75` | `SearchResultEntry.to: Vec<String>` | no | yes | **YES** |
| `list_folders.rs:117` | `ListFoldersMeta.security_warnings: Vec<SecurityWarning>` | **yes** | no | ✓ |
| `mcp/response.rs:24` | `ToolResponse.security_warnings: Vec<SecurityWarning>` | no | n/a (envelope built by hand, not via schema_for!) | ✓ |

So the fix touches exactly two source lines and one regenerated fixture (`search.schema.json`). The envelope-level `ToolResponse.security_warnings` would be a problem only if a future change starts deriving the envelope via `schema_for!(ToolResponse<...>)`. The current `dump_tool_schemas.rs` builds the envelope manually and correctly omits `security_warnings` from `required`, so no fix is needed there. (Flag as a low-priority follow-up if anyone is concerned.)

`Option<T>` fields with `skip_serializing_if = "Option::is_none"` are NOT affected — schemars 1.x already treats `Option<T>` as optional in derived schemas (confirmed by the search fixture: `size`, `flags`, `subject`, `date`, `message_id` are all `Option` and all correctly absent from `SearchResultEntry`'s `required` list).

`FetchMessageUntrusted.date` IS in the `required` list, but the wire emits `"date": null` for None (no `skip_serializing_if`) and the custom `schema_with` accepts `["array", "null"]`. Wire and schema match — not affected.

---

## Task: Mark `from` and `to` optional in the schema

**Files:**
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs:72,75`
- Regenerate: `crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json`
- Modify: `crates/rimap-server/tests/support/wire/schema.rs` (extend `search_fixture_validates_realistic_payload` OR add a sibling test case for the empty-headers shape)

- [ ] **Step 1: Add `#[serde(default)]` to the two fields**

In `crates/rimap-server/src/tools/retrieval/search.rs`, find `SearchResultEntry::from` (line 72) and `SearchResultEntry::to` (line 75). Each currently looks like:

```rust
/// From addresses, sanitized. Omitted when empty.
#[serde(skip_serializing_if = "Vec::is_empty")]
pub from: Vec<String>,
/// To addresses, sanitized. Omitted when empty.
#[serde(skip_serializing_if = "Vec::is_empty")]
pub to: Vec<String>,
```

Change each to:

```rust
/// From addresses, sanitized. Omitted when empty.
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub from: Vec<String>,
/// To addresses, sanitized. Omitted when empty.
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub to: Vec<String>,
```

The `default` attribute makes schemars treat the field as not-required in the generated schema (and gives serde a deserialize path that defaults to `Vec::new()` if the field is absent, which is the right behavior on the consumer side too).

- [ ] **Step 2: Verify the source compiles with the feature on and off**

```bash
cargo check -p rimap-server --locked
cargo check -p rimap-server --features test-support --locked
cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings
```

All exit 0. (No new lints expected — `serde(default)` on an already-`Vec<T>` field is benign.)

- [ ] **Step 3: Regenerate the fixtures**

```bash
just regen-tool-schemas
git diff crates/rimap-server/tests/fixtures/rimap-tool-schemas/ | head -40
```

Expected: only `search.schema.json` changes. The `SearchResultEntry` defn's `required` list drops from `["uid", "from", "to"]` to `["uid"]`.

Spot-check:

```bash
python3 -c "
import json
d = json.load(open('crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json'))
entry = d['\$defs']['SearchResultEntry']
print('required:', entry.get('required'))
"
```

Expected output:
```
required: ['uid']
```

If `from` or `to` still appears in the `required` list, schemars's `serde(default)` handling isn't kicking in. Fallback: try `#[schemars(default)]` directly instead of `#[serde(default)]` (schemars 1.x accepts both). Iterate until the regen produces a schema with only `uid` in the `SearchResultEntry::required` list.

- [ ] **Step 4: Extend the smoke test**

In `crates/rimap-server/tests/support/wire/schema.rs`, find the existing test `search_fixture_validates_realistic_payload` (added in Task B of the previous fix plan). It currently validates a payload that includes non-empty `from` and `to` arrays. ADD a second test case that omits both fields:

```rust
#[test]
fn search_fixture_validates_payload_with_omitted_from_and_to() {
    let search = validator_for_tool_response("search");
    // Wire shape when the parsed message has no From / To headers:
    // both fields are omitted (Vec::is_empty skip_serializing_if).
    // Pre-fix, the schema required them as keys and this payload
    // would have been falsely rejected.
    let payload = serde_json::json!({
        "meta": {
            "total_matched": 1u64,
            "folder": "INBOX",
            "returned": 1u64,
            "truncated": false,
        },
        "untrusted": {
            "messages": [
                {
                    "uid": 42u32,
                    // from and to are omitted, matching the wire when
                    // both vectors are empty.
                }
            ],
        },
        "security_warnings": [],
    });
    if !search.is_valid(&payload) {
        let errors: Vec<String> =
            search.iter_errors(&payload).map(|e| e.to_string()).collect();
        panic!(
            "search schema must accept a result entry with omitted from/to; errors:\n  {}\n\npayload: {payload}",
            errors.join("\n  ")
        );
    }
}
```

If the existing payload test's required `meta` fields don't match what `SearchMeta` actually requires (the plan author hand-checked `folder`, `total_matched`, `returned`, `truncated` based on the fixture's `required` list, but the source struct may have changed since this plan was written), the test will fail with a clear schema diagnostic naming the missing fields. Adjust the payload until it validates.

- [ ] **Step 5: Verify the new test passes and the existing positive case still passes**

```bash
cargo nextest run -p rimap-server --test mcp_wire_conformance --locked
cargo nextest run -p rimap-server --test e2e_wire --locked
cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings
just regen-tool-schemas && git diff --exit-code crates/rimap-server/tests/fixtures/rimap-tool-schemas/
```

Expected:
- `mcp_wire_conformance` runs 12 tests, all pass (was 11; +1 for the new omit-fields case which compiles into this binary via `support/wire/mod.rs`).
- `e2e_wire` runs 5 tests, all pass (was 4; same reason).
- Clippy clean.
- Idempotent regen (no diff).

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/retrieval/search.rs \
        crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json \
        crates/rimap-server/tests/support/wire/schema.rs
git commit -m "fix(test): mark SearchResultEntry.from/to as schema-optional (#265)

Codex round-3 adversarial review caught that SearchResultEntry.from
and SearchResultEntry.to use skip_serializing_if = \"Vec::is_empty\"
on the wire, so the keys are omitted when the parsed message has
no From/To addresses. The generated search.schema.json marked both
as required, so the Phase 3 conformance validator could reject
legitimate server output.

Adding #[serde(default)] makes schemars treat the field as
not-required in the generated schema (and gives serde the matching
deserialize path that defaults to Vec::new() when the field is
absent — relevant for round-trip tests or consumer-side parsing).

Regenerated the one affected fixture; the SearchResultEntry defn
now has required: [\"uid\"] only. Added a smoke-test payload that
omits both fields to lock in the wire-vs-schema parity going
forward.

A repo-wide grep for skip_serializing_if = \"Vec::is_empty\" turned
up exactly two other sites — list_folders.rs:117 and
mcp/response.rs:24 — both of which already pair the skip with
default (ListFoldersMeta.security_warnings) or live on a struct
whose schema is built manually rather than via schema_for!
(ToolResponse.security_warnings). Neither produces a false-required
in any current fixture.
"
```

---

## Acceptance criteria

- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` clean.
- [ ] `SearchResultEntry`'s `required` list in `search.schema.json` is exactly `["uid"]`.
- [ ] `search_fixture_validates_payload_with_omitted_from_and_to` passes.
- [ ] Existing `search_fixture_validates_realistic_payload` (with non-empty `from`/`to`) still passes.
- [ ] `just regen-tool-schemas` is idempotent.
- [ ] Phase 1 (`mcp_wire_conformance`) and Phase 3 (`e2e_wire`) suites pass / silent-skip.

---

## Notes for the reviewer

- The fix is two-character: `default,` added to two existing attributes.
- The fixture diff is one file, one nested `required` array.
- The smoke-test addition is one new `#[test]` function.
- Combined commit is small enough to land without subagent dispatch — single inline edit + regen + commit.

If `#[serde(default)]` turns out NOT to remove the field from schemars's `required` list (i.e. schemars 1.x ignores it for this case), fall back to `#[schemars(default)]` directly on the same fields. Both should work — schemars 1.x documents respect for the serde attribute in derive scenarios.
