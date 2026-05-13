# Phase 3 MCP Behavioral Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a Rust integration test (`e2e_wire`) that drives `rusty-imap-mcp` over its stdio JSON-RPC wire against the existing Dovecot fixture, exercising every draft-safe + read-only posture tool, validating responses against Phase 1's vendored MCP envelope schemas + new per-tool schemas generated from the Rust output structs, and asserting paired audit records with correct account attribution.

**Architecture:** Extract Phase 1's wire harness and `e2e.rs`'s Dovecot harness into a shared `tests/support/` module so both phases share one driver. Add `schemars` derives (already a workspace dep) to existing `<Tool>Meta`/`<Tool>Untrusted` response structs under a `cfg(any(test, feature = "test-support"))` gate. A new `dump-tool-schemas` test-support subcommand emits per-tool composed schemas; `just regen-tool-schemas` writes them to `tests/fixtures/rimap-tool-schemas/`; CI fails on a non-empty diff. The new `e2e_wire.rs` builds a multipart-MIME seed, spawns the production binary with a Dovecot-backed two-account config (`draftsafe` + `readonly`), drives the wire flow, and reads back the audit log to verify pairing and namespace attribution.

**Tech Stack:** Rust 2024 / edition 2024, MSRV 1.88.0. `tokio`, `rmcp` 1.5, `schemars` 1.0, `jsonschema` 0.46, `assert_cmd`, `tempfile`. Reuses existing infrastructure: `cargo-nextest`, the `test-support` feature gate, the Dovecot docker-compose fixture, and Phase 1's vendored MCP spec schema.

**Spec:** `docs/superpowers/specs/2026-05-12-mcp-behavioral-conformance-design.md`
**Branch:** continue on `test/mcp-behavioral-conformance-spec` (already created).

---

## File structure

| Path | Action | Responsibility |
|---|---|---|
| `crates/rimap-server/src/tools/admin/accounts.rs` | Modify | Add `JsonSchema` derives to `UseAccountMeta`, `ListAccountsMeta` (and helpers). |
| `crates/rimap-server/src/tools/admin/list_folders.rs` | Modify | Add `JsonSchema` to `ListFoldersMeta`. |
| `crates/rimap-server/src/tools/mailbox/labels.rs` | Modify | Add `JsonSchema` to `LabelsMeta`, `ListLabelsMeta`. |
| `crates/rimap-server/src/tools/mailbox/flags.rs` | Modify | Add `JsonSchema` to `FlagsMeta`. |
| `crates/rimap-server/src/tools/mailbox/move_message.rs` | Modify | Add `JsonSchema` to `MoveEntry`, `MoveMessageMeta`. |
| `crates/rimap-server/src/tools/compose/create_draft.rs` | Modify | Add `JsonSchema` to `CreateDraftMeta`. |
| `crates/rimap-server/src/tools/retrieval/search.rs` | Modify | Add `JsonSchema` to `SearchResultEntry`, `SearchMeta`, `SearchUntrusted`. |
| `crates/rimap-server/src/tools/retrieval/fetch_message.rs` | Modify | Add `JsonSchema` to `FetchMessageMeta`, `FetchMessageUntrusted`. |
| `crates/rimap-server/src/tools/retrieval/list_attachments.rs` | Modify | Add `JsonSchema` to `AttachmentInfo`, `ListAttachmentsMeta`, `ListAttachmentsUntrusted`. |
| `crates/rimap-server/src/tools/retrieval/download_attachment.rs` | Modify | Add `JsonSchema` to `DownloadAttachmentMeta`, `DownloadAttachmentUntrusted`. |
| `crates/rimap-server/src/cli/dump_tool_schemas.rs` | Create | Test-support subcommand that emits per-tool composed schemas as JSON to stdout. |
| `crates/rimap-server/src/cli/mod.rs` | Modify | Register `DumpToolSchemas` enum variant under `cfg(feature = "test-support")`. |
| `crates/rimap-server/src/main.rs` | Modify | Dispatch the new subcommand in `run_test_support_subcommands`. |
| `justfile` | Modify | Add `regen-tool-schemas` recipe; wire it into `ci` after `mcp-conformance-node`. |
| `crates/rimap-server/tests/fixtures/rimap-tool-schemas/<tool>.schema.json` | Create (14 files) | Generated per-tool combined `{meta, untrusted}` schemas. Checked in. |
| `crates/rimap-server/tests/support/mod.rs` | Create | `pub mod wire; pub mod dovecot;` |
| `crates/rimap-server/tests/support/wire/mod.rs` | Create | Re-exports for harness + schema validators. |
| `crates/rimap-server/tests/support/wire/harness.rs` | Create | `Harness` lifted from `mcp_wire_conformance.rs` + new `spawn_with_config`. |
| `crates/rimap-server/tests/support/wire/schema.rs` | Create | `validator_for`, `assert_envelope_valid`, `validator_for_tool_response`. |
| `crates/rimap-server/tests/support/dovecot/mod.rs` | Create | Re-exports for `DovecotHarness` + fixtures. |
| `crates/rimap-server/tests/support/dovecot/harness.rs` | Create | `DovecotHarness`, `ReservedPort` lifted from `e2e.rs`. |
| `crates/rimap-server/tests/support/dovecot/fixtures.rs` | Create | `multipart_with_attachment()` raw-bytes seed builder + payload constants. |
| `crates/rimap-server/tests/support/wire/config.rs` | Create | `build_dovecot_config(...)` two-account TOML builder. |
| `crates/rimap-server/tests/mcp_wire_conformance.rs` | Modify | Replace inline `Harness` / schema items with `use` imports from `support::wire`. Test bodies unchanged. |
| `crates/rimap-server/tests/e2e.rs` | Modify | Replace inline `DovecotHarness` with `use support::dovecot::DovecotHarness;`. Test bodies unchanged. |
| `crates/rimap-server/tests/e2e_wire.rs` | Create | Two `#[tokio::test]` cases: `wire_e2e_full_session_draft_safe`, `wire_e2e_readonly_posture_denial`. |
| `.github/workflows/ci.yml` | Modify | Add a step running `cargo nextest run -p rimap-server --test e2e_wire --no-tests=fail` and a step running `just regen-tool-schemas && git diff --exit-code`. |
| `AGENTS.md` | Modify | Document Phase 3 wall-time + cross-link the spec. |

---

## Task 1: Add `schemars::JsonSchema` derives to 14 tool response structs

**Files:**
- Modify: `crates/rimap-server/src/tools/admin/accounts.rs:16-44`
- Modify: `crates/rimap-server/src/tools/admin/list_folders.rs:82-130`
- Modify: `crates/rimap-server/src/tools/mailbox/labels.rs:111-140`
- Modify: `crates/rimap-server/src/tools/mailbox/flags.rs:47-65`
- Modify: `crates/rimap-server/src/tools/mailbox/move_message.rs:40-60`
- Modify: `crates/rimap-server/src/tools/compose/create_draft.rs:14-30`
- Modify: `crates/rimap-server/src/tools/retrieval/search.rs:54-100`
- Modify: `crates/rimap-server/src/tools/retrieval/fetch_message.rs:35-60`
- Modify: `crates/rimap-server/src/tools/retrieval/list_attachments.rs:31-70`
- Modify: `crates/rimap-server/src/tools/retrieval/download_attachment.rs:39-80`

- [ ] **Step 1: Verify schemars is already in scope (no Cargo.toml change required)**

Run: `grep -nE "^schemars" /Users/dave/src/rusty-imap-mcp/Cargo.toml /Users/dave/src/rusty-imap-mcp/crates/rimap-server/Cargo.toml`
Expected: `Cargo.toml:194:schemars = "1.0"` and `rimap-server/Cargo.toml:53:schemars = { workspace = true }`. No change needed.

- [ ] **Step 2: Add the derive to every in-scope struct**

For each struct listed in the file table for this task, replace its existing derive line. Example for `crates/rimap-server/src/tools/mailbox/flags.rs:47`:

```rust
// before
#[derive(Debug, Serialize)]

// after
#[derive(Debug, Serialize)]
#[cfg_attr(any(test, feature = "test-support"), derive(schemars::JsonSchema))]
```

Apply the same two-line pattern to each of these structs (every one already has `#[derive(Debug, Serialize)]`):

- `accounts.rs`: `UseAccountMeta`, `AccountEntry`, `ListAccountsMeta`
- `list_folders.rs`: every `#[derive(Debug, Serialize)]` struct in the file (currently `ListFoldersMeta` + 1 helper at line 82)
- `labels.rs`: `LabelsMeta`, `ListLabelsMeta` (+ any helper structs the two reference)
- `flags.rs`: `FlagsMeta`
- `move_message.rs`: `MoveEntry`, `MoveMessageMeta`
- `create_draft.rs`: `CreateDraftMeta`
- `search.rs`: `SearchResultEntry`, `SearchMeta`, `SearchUntrusted`
- `fetch_message.rs`: `FetchMessageMeta`, `FetchMessageUntrusted`
- `list_attachments.rs`: `AttachmentInfo`, `ListAttachmentsMeta`, `ListAttachmentsUntrusted`
- `download_attachment.rs`: `DownloadAttachmentMeta`, `DownloadAttachmentUntrusted`

If a nested type does not implement `JsonSchema` (e.g. a third-party type), apply `#[cfg_attr(any(test, feature = "test-support"), schemars(with = "String"))]` on the offending field as a fallback.

- [ ] **Step 3: Verify the workspace still compiles with the feature off**

Run: `cargo check -p rimap-server --locked`
Expected: clean compile. (Production build does not enable `test-support`, so derives are inert.)

- [ ] **Step 4: Verify the workspace still compiles with the feature on**

Run: `cargo check -p rimap-server --features test-support --locked`
Expected: clean compile.

- [ ] **Step 5: Run clippy with `-D warnings` to catch derive-induced lints**

Run: `cargo clippy -p rimap-server --features test-support --all-targets --locked -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/tools/
git commit -m "feat(server): add schemars derives to tool response structs

Test-support-only derives on every <Tool>Meta and <Tool>Untrusted in
scope for Phase 3 wire conformance (#265). Gated behind
cfg(any(test, feature = \"test-support\")) so production builds do not
pull schemars into their dep graph.
"
```

---

## Task 2: `dump-tool-schemas` test-support subcommand

**Files:**
- Create: `crates/rimap-server/src/cli/dump_tool_schemas.rs`
- Modify: `crates/rimap-server/src/cli/mod.rs:97-100`
- Modify: `crates/rimap-server/src/main.rs:362-370`
- Test: `crates/rimap-server/src/cli/dump_tool_schemas.rs` (inline `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing inline test**

Append to `crates/rimap-server/src/cli/dump_tool_schemas.rs` (file does not exist yet; create with the test first):

```rust
//! `dump-tool-schemas` test-support CLI subcommand. Emits one JSON
//! Schema per in-scope tool, composing `<Tool>Meta` and (where
//! present) `<Tool>Untrusted` into a single `{meta, untrusted}`
//! envelope schema. Used by the Phase 3 wire-conformance harness
//! (issue #265) to validate every wire response against a per-tool
//! schema regenerated from the Rust output structs.

use std::collections::BTreeMap;
use std::io::Write;

use serde_json::Value;

/// Emit `{ "<tool>": <schema>, ... }` as pretty-printed JSON to the
/// given writer. Iteration order is deterministic (BTreeMap).
///
/// # Errors
///
/// Returns the I/O error if the writer fails or the serializer cannot
/// encode an entry. Schemars produces valid JSON for every derive-using
/// struct in scope; failure indicates a bug, not user input.
pub fn dump_tool_schemas<W: Write>(writer: &mut W) -> std::io::Result<()> {
    let schemas = build_schemas();
    serde_json::to_writer_pretty(&mut *writer, &schemas)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn build_schemas() -> BTreeMap<&'static str, Value> {
    use rimap_server::tools::{
        admin::{accounts::{ListAccountsMeta, UseAccountMeta}, list_folders::ListFoldersMeta},
        compose::create_draft::CreateDraftMeta,
        mailbox::{flags::FlagsMeta, labels::{LabelsMeta, ListLabelsMeta}, move_message::MoveMessageMeta},
        retrieval::{
            download_attachment::{DownloadAttachmentMeta, DownloadAttachmentUntrusted},
            fetch_message::{FetchMessageMeta, FetchMessageUntrusted},
            list_attachments::{ListAttachmentsMeta, ListAttachmentsUntrusted},
            search::{SearchMeta, SearchUntrusted},
        },
    };

    let mut out = BTreeMap::<&'static str, Value>::new();

    // meta-only tools (no untrusted payload on the wire)
    out.insert("list_folders",  meta_only::<ListFoldersMeta>());
    out.insert("list_accounts", meta_only::<ListAccountsMeta>());
    out.insert("list_labels",   meta_only::<ListLabelsMeta>());
    out.insert("mark_read",     meta_only::<FlagsMeta>());
    out.insert("mark_unread",   meta_only::<FlagsMeta>());
    out.insert("flag",          meta_only::<FlagsMeta>());
    out.insert("unflag",        meta_only::<FlagsMeta>());
    out.insert("add_label",     meta_only::<LabelsMeta>());
    out.insert("remove_label",  meta_only::<LabelsMeta>());
    out.insert("move_message",  meta_only::<MoveMessageMeta>());
    out.insert("create_draft",  meta_only::<CreateDraftMeta>());
    out.insert("use_account",   meta_only::<UseAccountMeta>());

    // meta + untrusted tools
    out.insert("search",
        meta_and_untrusted::<SearchMeta, SearchUntrusted>());
    out.insert("fetch_message",
        meta_and_untrusted::<FetchMessageMeta, FetchMessageUntrusted>());
    out.insert("list_attachments",
        meta_and_untrusted::<ListAttachmentsMeta, ListAttachmentsUntrusted>());
    out.insert("download_attachment",
        meta_and_untrusted::<DownloadAttachmentMeta, DownloadAttachmentUntrusted>());

    out
}

fn meta_only<M: schemars::JsonSchema>() -> Value {
    let schema = schemars::schema_for!(M);
    serde_json::json!({
        "type": "object",
        "properties": { "meta": schema },
        "required": ["meta"],
        "additionalProperties": true,
    })
}

fn meta_and_untrusted<M: schemars::JsonSchema, U: schemars::JsonSchema>() -> Value {
    let m = schemars::schema_for!(M);
    let u = schemars::schema_for!(U);
    serde_json::json!({
        "type": "object",
        "properties": { "meta": m, "untrusted": u },
        "required": ["meta", "untrusted"],
        "additionalProperties": true,
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn dump_emits_one_key_per_in_scope_tool() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> =
            serde_json::from_slice(&buf).unwrap();

        for name in [
            "list_folders", "list_accounts", "list_labels",
            "list_attachments", "download_attachment", "search",
            "fetch_message", "mark_read", "mark_unread", "flag",
            "unflag", "add_label", "remove_label", "move_message",
            "create_draft", "use_account",
        ] {
            assert!(parsed.contains_key(name), "missing schema for {name}");
            let entry = &parsed[name];
            assert_eq!(entry["type"], "object");
            assert!(entry["properties"]["meta"].is_object(),
                "{name}.meta must be a JSON Schema object");
        }
    }

    #[test]
    fn meta_and_untrusted_tools_include_untrusted_key() {
        let mut buf = Vec::new();
        dump_tool_schemas(&mut buf).unwrap();
        let parsed: serde_json::Map<String, Value> =
            serde_json::from_slice(&buf).unwrap();
        for name in ["search", "fetch_message", "list_attachments", "download_attachment"] {
            assert!(parsed[name]["properties"]["untrusted"].is_object(),
                "{name} must declare an untrusted schema");
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rimap-server --features test-support --lib cli::dump_tool_schemas -- --nocapture`
Expected: FAIL because `pub mod dump_tool_schemas;` is not declared in `cli/mod.rs` yet (compile error: unresolved module).

- [ ] **Step 3: Register the new module**

Edit `crates/rimap-server/src/cli/mod.rs` (insert near line 14 next to `pub(crate) mod dump_tool_catalog;`):

```rust
#[cfg(feature = "test-support")]
pub(crate) mod dump_tool_schemas;
```

Edit the `Command` enum at `crates/rimap-server/src/cli/mod.rs:97-100` to add a sibling variant immediately after `DumpToolCatalog`:

```rust
    /// Emit per-tool JSON Schemas (one entry per in-scope tool,
    /// composing `<Tool>Meta` and `<Tool>Untrusted` into a single
    /// `{meta, untrusted}` envelope) as pretty JSON on stdout. Used
    /// by the Phase 3 wire-conformance harness (#265) and the
    /// `just regen-tool-schemas` recipe. Hidden from `--help` because
    /// it is a test-only utility.
    #[cfg(feature = "test-support")]
    #[command(name = "dump-tool-schemas", hide = true)]
    DumpToolSchemas,
```

- [ ] **Step 4: Wire the subcommand into the test-support dispatcher**

Edit `crates/rimap-server/src/main.rs:362-370`. Replace `run_test_support_subcommands` with:

```rust
#[cfg(feature = "test-support")]
fn run_test_support_subcommands(cli: &Cli) -> Option<anyhow::Result<()>> {
    match cli.command {
        Some(Command::DumpToolCatalog) => {
            let mut stdout = std::io::stdout().lock();
            Some(cli::dump_tool_catalog::dump_tool_catalog(&mut stdout)
                .context("dumping tool catalog"))
        }
        Some(Command::DumpToolSchemas) => {
            let mut stdout = std::io::stdout().lock();
            Some(cli::dump_tool_schemas::dump_tool_schemas(&mut stdout)
                .context("dumping tool schemas"))
        }
        _ => None,
    }
}
```

- [ ] **Step 5: Make the in-scope structs public from `rimap-server` lib**

The `build_schemas` body in Step 1 references each struct via `rimap_server::tools::…`. Verify each is reachable from the library root. Run:

```bash
grep -rEn "pub mod (admin|compose|mailbox|retrieval)" crates/rimap-server/src/tools/mod.rs
```
Expected: each submodule is `pub mod …`. If any is `pub(crate)`, change it to `pub`.

Then verify each leaf struct is `pub struct …` (verified during file-structure mapping — currently true for all 14 in-scope structs). If any is not, change it.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cargo test -p rimap-server --features test-support --lib cli::dump_tool_schemas -- --nocapture`
Expected: 2 tests pass.

- [ ] **Step 7: Smoke-test the subcommand end-to-end**

Run:
```bash
cargo run -p rimap-server --features test-support --bin rusty-imap-mcp -- dump-tool-schemas | head -10
```
Expected: pretty-printed JSON object beginning with `{"add_label": {"type": "object", ...`.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/src/cli/ crates/rimap-server/src/main.rs
git commit -m "feat(server): add dump-tool-schemas test-support subcommand

Emits a per-tool JSON Schema map keyed by tool name; each entry is a
composed {meta, untrusted} envelope schema. Wired under the same
test-support feature gate as dump-tool-catalog (#264). Phase 3
behavioral-conformance plan (#265) consumes the output via the
new just regen-tool-schemas recipe.
"
```

---

## Task 3: `just regen-tool-schemas` recipe + initial schema commit

**Files:**
- Modify: `justfile` (append a new recipe before `ci:`)
- Create: 16 files under `crates/rimap-server/tests/fixtures/rimap-tool-schemas/<tool>.schema.json`

- [ ] **Step 1: Add the recipe to `justfile`**

Insert after the `mcp-conformance-node` recipe (before `ci:`):

```just
# Regenerate per-tool JSON Schemas under
# crates/rimap-server/tests/fixtures/rimap-tool-schemas/. Run after
# changing any tool response struct (<Tool>Meta or <Tool>Untrusted).
# CI fails on a non-empty diff under that directory.
regen-tool-schemas:
    #!/usr/bin/env bash
    set -euo pipefail
    out_dir="crates/rimap-server/tests/fixtures/rimap-tool-schemas"
    mkdir -p "$out_dir"
    cargo build -p rimap-server --bin rusty-imap-mcp \
        --features test-support --locked --quiet
    dump="$(cargo run --quiet -p rimap-server --features test-support \
        --bin rusty-imap-mcp -- dump-tool-schemas)"
    # Split the top-level object into one file per tool. Sort keys
    # so the on-disk byte order is deterministic across runs.
    python3 - "$dump" "$out_dir" <<'PY'
import json, sys, pathlib
dump, out_dir = sys.argv[1], pathlib.Path(sys.argv[2])
data = json.loads(dump)
for tool, schema in sorted(data.items()):
    path = out_dir / f"{tool}.schema.json"
    path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
PY
```

- [ ] **Step 2: Run the recipe to generate the initial fixtures**

Run: `just regen-tool-schemas`
Expected: 16 files appear under `crates/rimap-server/tests/fixtures/rimap-tool-schemas/`. List them:
```bash
ls crates/rimap-server/tests/fixtures/rimap-tool-schemas/
```
Expected names:
```
add_label.schema.json
create_draft.schema.json
download_attachment.schema.json
fetch_message.schema.json
flag.schema.json
list_accounts.schema.json
list_attachments.schema.json
list_folders.schema.json
list_labels.schema.json
mark_read.schema.json
mark_unread.schema.json
move_message.schema.json
remove_label.schema.json
search.schema.json
unflag.schema.json
use_account.schema.json
```

- [ ] **Step 3: Spot-check one generated schema**

Run: `python3 -c "import json; print(json.load(open('crates/rimap-server/tests/fixtures/rimap-tool-schemas/search.schema.json'))['properties'].keys())"`
Expected: `dict_keys(['meta', 'untrusted'])`

- [ ] **Step 4: Verify the recipe is idempotent**

Run: `just regen-tool-schemas && git diff --exit-code crates/rimap-server/tests/fixtures/rimap-tool-schemas/`
Expected: exit 0 (no diff). If a diff appears, the dump output is non-deterministic — fix by sorting in `build_schemas` (already BTreeMap) or in the Python splitter (already `sort_keys=True`).

- [ ] **Step 5: Commit**

```bash
git add justfile crates/rimap-server/tests/fixtures/rimap-tool-schemas/
git commit -m "build: add just regen-tool-schemas recipe + initial fixtures

Generates one JSON Schema file per in-scope tool from the new
dump-tool-schemas subcommand. Schemas are committed; Phase 3 CI step
(separate commit) runs the recipe and fails on non-empty diff.
"
```

---

## Task 4: CI tool-schema drift detector

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Inspect existing job layout to choose the placement**

Run: `grep -nE "^  [a-z-]+:|name:" .github/workflows/ci.yml | head -40`
Expected: a list of jobs including `test (stable)`. Pick a placement after the existing test job and before `mcp-conformance-node` (so build artifacts can be reused if caching is in place; if not, the job is independent).

- [ ] **Step 2: Add the drift job**

Append the following job to `.github/workflows/ci.yml` (adjust indentation to match the existing file):

```yaml
  tool-schema-drift:
    name: tool-schema drift
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@<sha>  # vX.Y.Z   ← match the SHA already used elsewhere in this file
        with:
          persist-credentials: false
      - uses: dtolnay/rust-toolchain@<sha>  # stable
      - uses: Swatinem/rust-cache@<sha>  # vX.Y.Z
      - name: Regenerate tool schemas
        run: just regen-tool-schemas
      - name: Verify no schema drift
        run: |
          git diff --exit-code crates/rimap-server/tests/fixtures/rimap-tool-schemas/ \
            || { echo "::error::Tool response struct changed without rerunning just regen-tool-schemas"; exit 1; }
```

Use the exact SHA + version pins already present in `.github/workflows/ci.yml` for `actions/checkout`, `dtolnay/rust-toolchain`, and `Swatinem/rust-cache`. Run: `grep -nE "uses: (actions/checkout|dtolnay/rust-toolchain|Swatinem/rust-cache)" .github/workflows/ci.yml` to find them.

- [ ] **Step 3: Lint the workflow**

Run: `actionlint .github/workflows/ci.yml && zizmor .github/workflows/ci.yml`
Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add tool-schema drift detector (#265)

Runs just regen-tool-schemas and fails the build if any file under
crates/rimap-server/tests/fixtures/rimap-tool-schemas/ changes.
Mirrors the Phase 1 MCP spec drift detector at
.github/workflows/mcp-spec-drift.yml.
"
```

---

## Task 5: Extract Phase 1 harness into `tests/support/wire/`

**Files:**
- Create: `crates/rimap-server/tests/support/mod.rs`
- Create: `crates/rimap-server/tests/support/wire/mod.rs`
- Create: `crates/rimap-server/tests/support/wire/harness.rs`
- Create: `crates/rimap-server/tests/support/wire/schema.rs`
- Modify: `crates/rimap-server/tests/mcp_wire_conformance.rs`

This task is a refactor — no test behavior changes. Phase 1's nine tests continue to pass byte-for-byte.

- [ ] **Step 1: Create `tests/support/mod.rs`**

```rust
//! Shared support for `rimap-server` integration tests. Re-exports
//! the wire driver (Phase 1 + Phase 3) and the Dovecot harness
//! (Phase 3 + the legacy `e2e_full_session`).
//!
//! Each integration-test file pulls this in with
//! `#[path = "support/mod.rs"] mod support;` at the top.

#![expect(dead_code, reason = "different test files use different subsets")]

pub mod wire;
// `pub mod dovecot;` added in Task 6.
```

- [ ] **Step 2: Create `tests/support/wire/mod.rs`**

```rust
//! Wire driver and MCP spec schema validators shared by Phase 1
//! (`mcp_wire_conformance.rs`) and Phase 3 (`e2e_wire.rs`).

pub mod harness;
pub mod schema;

pub use harness::{Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
pub use schema::{assert_envelope_valid, assert_valid, validator_for};
```

- [ ] **Step 3: Move `Harness` + constants into `tests/support/wire/harness.rs`**

Copy verbatim from `crates/rimap-server/tests/mcp_wire_conformance.rs` lines 30-200 (the `PINNED_PROTOCOL_VERSION`, `MCP_SCHEMA_JSON`, `REQUEST_TIMEOUT`, `SHUTDOWN_TIMEOUT` constants, and the `Harness` struct + `impl Harness`). Adjust the file header so it reads:

```rust
//! Stdio JSON-RPC harness used by both Phase 1 (`mcp_wire_conformance.rs`)
//! and Phase 3 (`e2e_wire.rs`). Spawns the production `rusty-imap-mcp`
//! binary with `--features test-support` and exchanges line-delimited
//! JSON-RPC envelopes over stdin/stdout. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`
//! and the Phase 3 sibling spec for the design context.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]
```

Re-export `MCP_SCHEMA_JSON` as `pub(crate) const`. Make `Harness`, its impl methods, the constants, and `REQUEST_TIMEOUT` / `SHUTDOWN_TIMEOUT` `pub`. Do not move the `validator_for` / `assert_*` helpers yet — those go in `schema.rs` in the next step.

- [ ] **Step 4: Move validator helpers into `tests/support/wire/schema.rs`**

Move `validator_for`, `assert_valid`, `assert_envelope_valid`, and the `MCP_SCHEMA_JSON` import into `schema.rs`:

```rust
//! MCP-spec JSON Schema validators shared by Phase 1 and Phase 3.
//! `validator_for(fragment)` caches per-fragment validators in a
//! process-wide map; the parsed spec document is parsed exactly once.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Value, json};

use super::harness::MCP_SCHEMA_JSON;

pub fn validator_for(fragment: &'static str) -> Arc<jsonschema::Validator> {
    // BODY copied verbatim from mcp_wire_conformance.rs lines 206-257
}

pub fn assert_valid(value: &Value, fragment: &'static str) {
    // BODY copied verbatim from mcp_wire_conformance.rs lines 261-270
}

pub fn assert_envelope_valid(response: &Value) {
    // BODY copied verbatim from mcp_wire_conformance.rs lines 279-298
}
```

- [ ] **Step 5: Replace the inline definitions in `mcp_wire_conformance.rs`**

Replace the moved content in `crates/rimap-server/tests/mcp_wire_conformance.rs` (top of file through line ~298) with:

```rust
//! MCP wire-shape conformance harness (issue #263, Phase 1).
//!
//! Drives the production `rusty-imap-mcp` binary over stdio with a
//! zero-account config and validates every response against the
//! vendored MCP spec schemas. See
//! `docs/superpowers/specs/2026-05-12-mcp-wire-conformance-design.md`.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test assertions render diagnostics")]

#[path = "support/mod.rs"]
mod support;

use std::time::Duration;

use rmcp::model::ProtocolVersion;
use serde_json::json;

use support::wire::{
    Harness, PINNED_PROTOCOL_VERSION, assert_envelope_valid, assert_valid, validator_for,
};
```

Leave the nine `#[tokio::test]` test bodies (currently from line ~300 to end) byte-for-byte unchanged. They reference `Harness`, `PINNED_PROTOCOL_VERSION`, `assert_envelope_valid`, `assert_valid`, and `validator_for` — all now imported.

The `Harness::spawn` body that builds the zero-account TOML stays in `support::wire::harness` for now (Task 7 splits it).

- [ ] **Step 6: Run Phase 1's test suite to verify zero behavior change**

Run: `cargo nextest run -p rimap-server --test mcp_wire_conformance --locked`
Expected: all 9 tests pass.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/tests/support/ crates/rimap-server/tests/mcp_wire_conformance.rs
git commit -m "refactor(test): extract Phase 1 wire harness into tests/support/wire

Pure relocation: tests/support/{mod.rs,wire/{mod.rs,harness.rs,schema.rs}}
own the Harness, constants, and MCP spec schema validators that
mcp_wire_conformance.rs used to declare inline. Test bodies and
assertions are unchanged; the file imports the moved items via
#[path = \"support/mod.rs\"] mod support; use support::wire::…;.

Sets up the shared driver Phase 3 (#265) builds on.
"
```

---

## Task 6: Extract `DovecotHarness` into `tests/support/dovecot/`

**Files:**
- Create: `crates/rimap-server/tests/support/dovecot/mod.rs`
- Create: `crates/rimap-server/tests/support/dovecot/harness.rs`
- Modify: `crates/rimap-server/tests/support/mod.rs`
- Modify: `crates/rimap-server/tests/e2e.rs`

Also a refactor. `e2e_full_session` continues to pass byte-for-byte.

- [ ] **Step 1: Create `tests/support/dovecot/mod.rs`**

```rust
//! Dovecot container harness and seeded-fixture helpers shared by
//! `e2e.rs` (in-process Rust API) and `e2e_wire.rs` (stdio wire).

pub mod harness;
// `pub mod fixtures;` added in Task 9.

pub use harness::DovecotHarness;
```

- [ ] **Step 2: Move `DovecotHarness` into `tests/support/dovecot/harness.rs`**

Move the following items verbatim from `crates/rimap-server/tests/e2e.rs` lines 49-274:

- `runtime()`, `binary_present()`, `runtime_available()`
- `container_name(project)`
- `DovecotHarness` struct + `impl DovecotHarness { try_start, create_mailbox }`
- `wait_for_ready`, `compose_down`, `read_fingerprint`
- `ReservedPort` struct + impl
- `is_port_collision`
- `impl Drop for DovecotHarness`

File header:

```rust
//! Dovecot container harness lifted from the original
//! `crates/rimap-server/tests/e2e.rs`. Honors the same env vars
//! (`RIMAP_CONTAINER_TOOL`, `RIMAP_REQUIRE_DOCKER`) and silently skips
//! on non-x86_64 hosts or when no container runtime is available.
//! See `AGENTS.md` "Container runtime for integration tests".

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use rimap_core::TlsFingerprint;
```

Make `DovecotHarness` and its public methods (`try_start`, `create_mailbox`, `fingerprint()`, `port()`) `pub`. Add small `pub fn` accessors if any test code currently reaches into the struct fields directly (none in `e2e.rs`).

- [ ] **Step 3: Update `tests/support/mod.rs`**

Add `pub mod dovecot;` to the file from Task 5 step 1.

- [ ] **Step 4: Replace the moved content in `e2e.rs`**

In `crates/rimap-server/tests/e2e.rs`, replace lines 49-274 (the harness section) with:

```rust
#[path = "support/mod.rs"]
mod support;

use support::dovecot::DovecotHarness;
```

Leave the `StaticCreds`, `TestEnv`, `build_test_env`, and all the `assert_*` test functions byte-for-byte unchanged. They reference `DovecotHarness` — now imported.

- [ ] **Step 5: Run `e2e_full_session` to verify zero behavior change**

This needs Docker (or Podman). If unavailable locally, document the skip and rely on CI to verify. If available:

Run: `cargo nextest run -p rimap-server --test e2e --locked --no-fail-fast --no-capture`
Expected: `e2e_full_session` passes (or silently returns when no container runtime is present, same as before).

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-server/tests/support/dovecot/ crates/rimap-server/tests/support/mod.rs crates/rimap-server/tests/e2e.rs
git commit -m "refactor(test): extract DovecotHarness into tests/support/dovecot

Pure relocation: tests/support/dovecot/{mod.rs,harness.rs} own the
container lifecycle helpers that e2e.rs declared inline. Test bodies
and assertions are unchanged; the file imports the moved harness via
use support::dovecot::DovecotHarness;.

Sets up shared infrastructure Phase 3 (#265) builds on.
"
```

---

## Task 7: Add `Harness::spawn_with_config` and stderr capture

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/harness.rs`

This split lets Phase 3 reuse the harness with a Dovecot-backed config TOML instead of the inline zero-account TOML. Stderr capture lands in the same task because both changes touch the spawn path.

- [ ] **Step 1: Refactor `Harness::spawn` to delegate to `spawn_with_config`**

In `tests/support/wire/harness.rs`, replace the existing `pub async fn spawn() -> Self` with:

```rust
impl Harness {
    /// Spawn with the legacy zero-account config (Phase 1 default).
    /// Builds a multi-account TOML with `accounts = []`, an audit
    /// path under a fresh tempdir, and calls `spawn_with_config`.
    #[expect(clippy::unused_async, reason = "uniform async surface")]
    pub async fn spawn() -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let config_path = tempdir.path().join("config.toml");
        let audit_path = tempdir.path().join("audit.jsonl");
        let allowed_base = tempdir.path();
        let config = format!(
            r#"
accounts = []

[audit]
path = "{}"
allowed_base_dir = "{}"
"#,
            audit_path.display(),
            allowed_base.display(),
        );
        std::fs::write(&config_path, config).expect("write config");
        Self::spawn_with_config(&config_path, tempdir, &[]).await
    }

    /// Spawn the binary against a caller-supplied config. The
    /// `tempdir` is held by the returned `Harness` so its lifetime
    /// covers the child process's audit path.
    ///
    /// `extra_envs` is forwarded to the child verbatim. Phase 3 uses
    /// this to inject `RUSTY_IMAP_MCP_PASSWORD` (the env-var
    /// fallback for the keyring) without polluting the test
    /// process's env.
    pub async fn spawn_with_config(
        config_path: &std::path::Path,
        tempdir: TempDir,
        extra_envs: &[(&str, &str)],
    ) -> Self {
        let mut cmd = Command::new(cargo_bin("rusty-imap-mcp"));
        cmd.arg("--config")
            .arg(config_path)
            .arg("--allow-empty-accounts")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in extra_envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn rusty-imap-mcp binary");

        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let stderr = child.stderr.take().expect("stderr");

        // Drain stderr into a shared buffer so the binary's tracing
        // output is included in panic messages on assertion failure.
        let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stderr_clone = Arc::clone(&stderr_buf);
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut reader = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut guard) = stderr_clone.lock() {
                            guard.extend_from_slice(&buf[..n]);
                            // Bound the buffer to avoid OOM on a chatty child;
                            // the head is the most useful diagnostic anyway.
                            const CAP: usize = 64 * 1024;
                            if guard.len() > CAP {
                                guard.truncate(CAP);
                            }
                        }
                    }
                }
            }
        });

        Self {
            child,
            stdin,
            stdout,
            stderr_buf,
            next_id: 0,
            _tempdir: tempdir,
        }
    }

    /// Snapshot the captured stderr for diagnostic messages.
    pub fn captured_stderr(&self) -> String {
        self.stderr_buf
            .lock()
            .map(|g| String::from_utf8_lossy(&g).into_owned())
            .unwrap_or_default()
    }
}
```

- [ ] **Step 2: Add the new fields to the struct**

In the same file, update `struct Harness`:

```rust
pub struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Stderr drain buffer, updated by a background task.
    stderr_buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    next_id: u64,
    _tempdir: TempDir,
}
```

- [ ] **Step 3: Surface captured stderr in panic paths**

In the `request` method's existing expect-on-read-line, change:

```rust
let read = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf))
    .await
    .expect("response within timeout")
    .expect("read response");
```

to:

```rust
let read = timeout(REQUEST_TIMEOUT, self.stdout.read_line(&mut buf))
    .await
    .unwrap_or_else(|_| panic!(
        "response within timeout for {method}; child stderr:\n{}",
        self.captured_stderr()
    ))
    .unwrap_or_else(|e| panic!(
        "read response for {method}: {e}; child stderr:\n{}",
        self.captured_stderr()
    ));
```

Use the same pattern in `assert_no_response_within` and `shutdown_and_wait` for their panic branches.

- [ ] **Step 4: Rerun Phase 1's tests**

Run: `cargo nextest run -p rimap-server --test mcp_wire_conformance --locked`
Expected: all 9 tests pass. Stderr capture is invisible to them on the happy path.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/support/wire/harness.rs
git commit -m "feat(test): add Harness::spawn_with_config + stderr capture

spawn_with_config takes a caller-built config path and a list of extra
envs, letting Phase 3 (#265) point the spawned binary at a Dovecot-
backed two-account TOML and inject RUSTY_IMAP_MCP_PASSWORD without
polluting the test process. spawn() becomes a thin wrapper that
builds the zero-account TOML and delegates.

stderr is now piped and drained into a bounded buffer so a wire-call
panic includes the binary's tracing output — the highest-signal
diagnostic when a response is unexpected.
"
```

---

## Task 8: `validator_for_tool_response` helper

**Files:**
- Modify: `crates/rimap-server/tests/support/wire/schema.rs`
- Modify: `crates/rimap-server/tests/support/wire/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/rimap-server/tests/support/wire/schema.rs`:

```rust
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tool_response_tests {
    use super::*;

    #[test]
    fn validates_a_well_formed_list_folders_response() {
        let validator = validator_for_tool_response("list_folders");
        let valid = serde_json::json!({
            "meta": { "folders": [] }
        });
        assert!(validator.is_valid(&valid));
    }

    #[test]
    fn rejects_a_response_missing_meta() {
        let validator = validator_for_tool_response("list_folders");
        let invalid = serde_json::json!({ "something_else": 1 });
        assert!(!validator.is_valid(&invalid));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rimap-server --tests support::wire::schema -- --nocapture`
Expected: FAIL — `validator_for_tool_response` is not defined.

Note: this is an integration-test-only inline test. `cargo test --tests` finds it via the `support` module included from `mcp_wire_conformance.rs` or another integration target. If the inline `mod tool_response_tests` cannot be reached because no integration test pulls it in yet, add a trivial `#[test]` in `mcp_wire_conformance.rs` that imports the helper — and remove that import after Task 10 covers it organically. Simpler alternative: put the test inside `tests/e2e_wire.rs` (created in Task 10) instead.

For this plan, prefer the simpler alternative: hold the test until Task 10, and instead verify the implementation in Step 4 below by adding a `cargo check` step that confirms the new function compiles.

- [ ] **Step 3: Add the helper**

Append to `tests/support/wire/schema.rs`:

```rust
/// Compile (lazily, cached) a validator for the per-tool response
/// schema at `tests/fixtures/rimap-tool-schemas/<tool>.schema.json`.
/// Panics in the test process if the fixture is missing — that's the
/// signal that `just regen-tool-schemas` was not run.
pub fn validator_for_tool_response(tool: &'static str) -> Arc<jsonschema::Validator> {
    type Cache = Mutex<HashMap<&'static str, Arc<jsonschema::Validator>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let guard = cache.lock().expect("tool schema cache mutex poisoned");
        if let Some(v) = guard.get(tool) {
            return Arc::clone(v);
        }
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rimap-tool-schemas")
        .join(format!("{tool}.schema.json"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing tool-response schema fixture for {tool} at {}: {e}\n\
             Run `just regen-tool-schemas` to regenerate.",
            path.display()
        )
    });
    let parsed: Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}", path.display()));
    let compiled = jsonschema::validator_for(&parsed)
        .unwrap_or_else(|e| panic!("invalid JSON Schema in {}: {e}", path.display()));
    let arc = Arc::new(compiled);

    let mut guard = cache.lock().expect("tool schema cache mutex poisoned");
    let entry = guard.entry(tool).or_insert_with(|| Arc::clone(&arc));
    Arc::clone(entry)
}
```

- [ ] **Step 4: Re-export from `support::wire`**

Add to `tests/support/wire/mod.rs`:

```rust
pub use schema::{
    assert_envelope_valid, assert_valid, validator_for, validator_for_tool_response,
};
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p rimap-server --tests --all-features --locked`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/support/wire/
git commit -m "feat(test): add validator_for_tool_response helper

Loads and caches a validator per <tool>.schema.json under
tests/fixtures/rimap-tool-schemas/. Panics with an actionable
diagnostic (\"Run just regen-tool-schemas\") if the fixture is
missing. Phase 3 wire flow uses this to validate every tool/call
result against the schema regenerated from the Rust output structs.
"
```

---

## Task 9: Multipart MIME seed fixture + Dovecot config builder

**Files:**
- Create: `crates/rimap-server/tests/support/dovecot/fixtures.rs`
- Create: `crates/rimap-server/tests/support/wire/config.rs`
- Modify: `crates/rimap-server/tests/support/dovecot/mod.rs`
- Modify: `crates/rimap-server/tests/support/wire/mod.rs`

- [ ] **Step 1: Create `tests/support/dovecot/fixtures.rs`**

```rust
//! Seed fixtures used by the wire-driven e2e tests. Constants and
//! builders live here so the seed bytes and the assertion-side bytes
//! reference the same source — no "what was seeded" / "what to check"
//! duplication.

/// Filename declared in the attachment's `Content-Disposition`.
pub const ATTACHMENT_FILENAME: &str = "attached.bin";

/// Known byte payload of the attachment. 32 deterministic bytes —
/// large enough that an off-by-one in part extraction is visible, small
/// enough to print in test panic messages.
pub const ATTACHMENT_BYTES: &[u8] = &[
    0x52, 0x49, 0x4d, 0x41, 0x50, 0x2d, 0x50, 0x33, 0x2d, 0x41, 0x54, 0x54, 0x41, 0x43, 0x48, 0x45,
    0x44, 0x2d, 0x42, 0x59, 0x54, 0x45, 0x53, 0x2d, 0x32, 0x30, 0x32, 0x36, 0x2d, 0x30, 0x35, 0x12,
];

/// MIME boundary for the multipart container. Fixed so the message
/// bytes are deterministic across runs.
const BOUNDARY: &str = "rimap-p3-boundary-c0ffee";

/// Plain-text body content. Asserted by `fetch_message` in the wire flow.
pub const PLAIN_BODY: &str = "Hello from the Phase 3 wire-driven e2e smoke test.";

/// Returns the raw bytes of a `multipart/mixed` MIME message suitable
/// for `Connection::append_message`. Contains one `text/plain` part
/// with `PLAIN_BODY` and one `application/octet-stream` attachment
/// part with filename `ATTACHMENT_FILENAME` and payload `ATTACHMENT_BYTES`.
///
/// The Content-Transfer-Encoding for the attachment is `base64`. The
/// returned bytes are CRLF-terminated as required by RFC 5322.
pub fn multipart_with_attachment() -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let attachment_b64 = STANDARD.encode(ATTACHMENT_BYTES);
    let mut wrapped = String::new();
    // 76-char lines per RFC 2045.
    for chunk in attachment_b64.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push_str("\r\n");
    }

    let body = format!(
        "From: sender@example.com\r\n\
         To: rimap-test@localhost\r\n\
         Subject: e2e-wire-test-smoke\r\n\
         Date: Sat, 12 May 2026 10:00:00 +0000\r\n\
         Message-ID: <e2e-wire-smoke-001@example.com>\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"{BOUNDARY}\"\r\n\
         \r\n\
         --{BOUNDARY}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         \r\n\
         {PLAIN_BODY}\r\n\
         --{BOUNDARY}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Disposition: attachment; filename=\"{ATTACHMENT_FILENAME}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         \r\n\
         {wrapped}\r\n\
         --{BOUNDARY}--\r\n",
    );

    body.into_bytes()
}
```

Add `base64` to `[dev-dependencies]` in `crates/rimap-server/Cargo.toml` if it's not already present. Check first:

```bash
grep -nE "^base64" Cargo.toml crates/rimap-server/Cargo.toml
```

If missing, append to `crates/rimap-server/Cargo.toml` under `[dev-dependencies]`:

```toml
base64 = { workspace = true }
```

And verify the workspace declares it; if not, add to `Cargo.toml` `[workspace.dependencies]`:

```toml
base64 = "0.22"
```

(Look up the current stable version before committing — never assume.)

- [ ] **Step 2: Re-export from `support::dovecot`**

Update `tests/support/dovecot/mod.rs`:

```rust
pub mod harness;
pub mod fixtures;

pub use harness::DovecotHarness;
```

- [ ] **Step 3: Create `tests/support/wire/config.rs`**

```rust
//! Two-account multi-account TOML builder for Phase 3's wire-driven
//! Dovecot e2e. Both accounts target the same Dovecot user
//! (`rimap-test@dovecot`); the surface under test is the posture
//! matrix on the wire, not authentication isolation.

use std::path::Path;

use crate::support::dovecot::DovecotHarness;

/// Build the multi-account TOML for `e2e_wire.rs`. Caller is
/// responsible for writing the returned string to `config_path` and
/// for placing `audit_path` and `download_dir` inside `allowed_base`.
pub fn build_dovecot_config(
    dovecot: &DovecotHarness,
    audit_path: &Path,
    allowed_base: &Path,
    download_dir: &Path,
) -> String {
    let fingerprint_hex = dovecot.fingerprint().to_hex();
    let port = dovecot.port();
    format!(
        r#"
[audit]
path = "{audit_path}"
allowed_base_dir = "{allowed_base}"

[attachments]
download_dir = "{download_dir}"

[defaults.credentials]
fallback = "keyring-then-env"

[[accounts]]
name = "draftsafe"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "draft-safe"

[[accounts]]
name = "readonly"

[accounts.imap]
host = "127.0.0.1"
port = {port}
username = "rimap-test"
encryption = "tls"
tls_fingerprint_sha256 = "{fingerprint_hex}"

[accounts.security]
posture = "read-only"
"#,
        audit_path = audit_path.display(),
        allowed_base = allowed_base.display(),
        download_dir = download_dir.display(),
        port = port,
        fingerprint_hex = fingerprint_hex,
    )
}
```

If `DovecotHarness::fingerprint()` or `DovecotHarness::port()` do not exist (they were private fields originally), add the accessors in `tests/support/dovecot/harness.rs`:

```rust
impl DovecotHarness {
    pub fn fingerprint(&self) -> &TlsFingerprint { &self.fingerprint }
    pub fn port(&self) -> u16 { self.port }
}
```

`TlsFingerprint::to_hex` already exists (see `crates/rimap-core/src/tls.rs`). Verify with `grep -n "fn to_hex\|fn as_hex" crates/rimap-core/src/tls.rs`. If the method is named differently, adjust the call site to match.

- [ ] **Step 4: Re-export from `support::wire`**

Update `tests/support/wire/mod.rs`:

```rust
pub mod config;
pub mod harness;
pub mod schema;

pub use config::build_dovecot_config;
pub use harness::{Harness, PINNED_PROTOCOL_VERSION, REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
pub use schema::{
    assert_envelope_valid, assert_valid, validator_for, validator_for_tool_response,
};
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check -p rimap-server --tests --all-features --locked`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/tests/support/dovecot/ crates/rimap-server/tests/support/wire/config.rs crates/rimap-server/tests/support/wire/mod.rs crates/rimap-server/Cargo.toml Cargo.toml
git commit -m "feat(test): add multipart seed + Dovecot config builder

multipart_with_attachment() builds the raw bytes of a multipart/mixed
message with a known text/plain body and a 32-byte octet-stream
attachment. build_dovecot_config() composes the two-account TOML
(draftsafe + readonly) Phase 3's wire-driven e2e spawns the binary
against. Both helpers live in tests/support so the new e2e_wire.rs
and any future suite share the same fixtures.

Adds base64 as a dev-dep (already in workspace) to encode the
attachment payload into the MIME part.
"
```

---

## Task 10: `e2e_wire.rs` — full-session draft-safe wire flow

**Files:**
- Create: `crates/rimap-server/tests/e2e_wire.rs`

This is the largest task. Each step adds one slice of the flow and is independently runnable.

- [ ] **Step 1: Scaffold + initialize handshake**

Create `crates/rimap-server/tests/e2e_wire.rs`:

```rust
//! Phase 3 wire-driven Dovecot e2e (#265). Drives `rusty-imap-mcp`
//! over its stdio JSON-RPC wire against the existing Dovecot
//! container fixture, exercising every draft-safe + read-only
//! posture tool category and validating each response against
//! Phase 1's vendored MCP spec schemas + per-tool response schemas
//! under `tests/fixtures/rimap-tool-schemas/`.
//!
//! Silent-skip when no container runtime is available or the host
//! arch is not x86_64; `RIMAP_REQUIRE_DOCKER=1` flips to loud failure.

#![expect(clippy::expect_used, reason = "integration tests")]
#![expect(clippy::panic, reason = "test diagnostics")]
#![expect(clippy::unwrap_used, reason = "integration tests")]

#[path = "support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringCredentialResolver, PASSWORD_ENV_VAR};
use rimap_config::model::FallbackMode;
use rimap_imap::{Connection, ConnectionConfig, ImapEncryption};
use rmcp::model::ProtocolVersion;
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;

use support::dovecot::{DovecotHarness, fixtures};
use support::wire::{
    Harness, assert_envelope_valid, assert_valid, build_dovecot_config,
    validator_for, validator_for_tool_response,
};

/// Dovecot's seeded test password. Matches the value injected via the
/// docker-compose fixture; see e2e.rs StaticCreds for the in-process equivalent.
const DOVECOT_PASSWORD: &str = "testpass";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_full_session_draft_safe() {
    let Some(dovecot) = DovecotHarness::try_start() else {
        return; // silent skip — matches e2e_full_session
    };
    dovecot.create_mailbox("Drafts");
    dovecot.create_mailbox("Trash");

    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    seed_multipart_message(&dovecot).await;

    let config_path = tempdir.path().join("config.toml");
    let config = build_dovecot_config(&dovecot, &audit_path, &allowed_base, &download_dir);
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;

    // Subsequent steps fill in the flow.
    let init = harness.initialize_handshake().await;
    let init_result = &init["result"];
    assert_valid(init_result, "InitializeResult");
    assert!(init_result["capabilities"]["tools"].is_object());
    harness.send_initialized().await;

    let _audit = audit_path; // used in the audit-assertion step below
    let _ = harness.shutdown_and_wait().await;
}

async fn seed_multipart_message(dovecot: &DovecotHarness) {
    // Build a Connection that mirrors e2e.rs's test_connection but
    // sources credentials from a static stub. The seed is in-process
    // so the wire surface remains the surface under test.
    let audit_dir = TempDir::new().expect("seed-audit tempdir");
    let audit = AuditWriter::open(&AuditOptions {
        path: audit_dir.path().join("seed.jsonl"),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: Seq::FIRST,
    })
    .expect("audit open");

    let cfg = ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: "127.0.0.1".into(),
        port: dovecot.port(),
        encryption: ImapEncryption::Tls,
        username: "rimap-test".into(),
        pinned_fingerprint: Some(*dovecot.fingerprint()),
        connect_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(30),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    struct StaticCreds;
    impl CredentialStore for StaticCreds {
        fn get_password(
            &self,
            _: &str,
        ) -> Result<Option<SecretString>, rimap_config::ConfigError> {
            Ok(Some(SecretString::from(DOVECOT_PASSWORD.to_string())))
        }
        #[expect(clippy::panic_in_result_fn, reason = "seed never writes")]
        fn set_password(&self, _: &str, _: &str) -> Result<(), rimap_config::ConfigError> {
            panic!("seed never writes credentials")
        }
    }
    let store: Arc<dyn CredentialStore> = Arc::new(StaticCreds);
    let creds: Arc<dyn rimap_core::CredentialResolver> = Arc::new(
        KeyringCredentialResolver::new(store, FallbackMode::KeyringThenEnv),
    );
    let sink: Arc<dyn rimap_core::auth_sink::AuthEventSink> = Arc::new(audit.clone());
    let conn = Connection::new(cfg, sink, creds);
    conn.append_message("INBOX", &fixtures::multipart_with_attachment(), &[], &[])
        .await
        .expect("APPEND multipart seed");
}
```

- [ ] **Step 2: Run the scaffold to verify it spawns + handshakes**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked --no-capture`
Expected: 1 test (`wire_e2e_full_session_draft_safe`) passes (Docker required). If no Docker available locally, run without `RIMAP_REQUIRE_DOCKER` and confirm it returns silently.

- [ ] **Step 3: Add tools/list assertions + namespace check**

Insert after `harness.send_initialized().await;`:

```rust
    let tools_list = harness.request("tools/list", json!({})).await;
    assert_valid(&tools_list["result"], "ListToolsResult");
    let tools: BTreeMap<String, Value> = tools_list["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| (t["name"].as_str().expect("name").to_string(), t.clone()))
        .collect();

    // Draft-safe namespace advertises mutating tools.
    for required in [
        "draftsafe.list_folders",
        "draftsafe.search",
        "draftsafe.fetch_message",
        "draftsafe.list_attachments",
        "draftsafe.download_attachment",
        "draftsafe.list_labels",
        "draftsafe.mark_read",
        "draftsafe.mark_unread",
        "draftsafe.flag",
        "draftsafe.unflag",
        "draftsafe.add_label",
        "draftsafe.remove_label",
        "draftsafe.move_message",
        "draftsafe.create_draft",
        // Infrastructure tools are NOT namespaced.
        "list_accounts",
        "use_account",
    ] {
        assert!(tools.contains_key(required), "missing tool: {required}");
    }

    // Read-only namespace HIDES mutating tools.
    for forbidden in [
        "readonly.move_message",
        "readonly.create_draft",
        "readonly.mark_read",
        "readonly.mark_unread",
        "readonly.flag",
        "readonly.unflag",
        "readonly.add_label",
        "readonly.remove_label",
    ] {
        assert!(
            !tools.contains_key(forbidden),
            "readonly namespace must not advertise {forbidden}",
        );
    }
```

- [ ] **Step 4: Drive each draft-safe tool through the wire**

Insert a `call_and_validate` helper inside the test function (or above as a free fn) and the per-tool calls. Helper:

```rust
async fn call_tool(harness: &mut Harness, name: &str, args: Value) -> Value {
    let resp = harness.request(
        "tools/call",
        json!({ "name": name, "arguments": args }),
    ).await;
    assert_envelope_valid(&resp);
    assert!(resp["error"].is_null(), "tool {name} failed: {resp}");
    let body = &resp["result"]["structuredContent"];
    // Per-tool schema: name is the bare tool name without the namespace prefix.
    let bare = name.rsplit_once('.').map(|(_, b)| b).unwrap_or(name);
    let validator = validator_for_tool_response(bare);
    if !validator.is_valid(body) {
        let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
        panic!("tool {name} response failed schema:\n  {}\n\nresponse: {body}",
            errors.join("\n  "));
    }
    body.clone()
}
```

Then the call sequence (replace the `let _audit = ...; let _ = harness.shutdown_and_wait()...` placeholder):

```rust
    // 1. list_folders — assert INBOX present
    let folders = call_tool(&mut harness, "draftsafe.list_folders", json!({})).await;
    let folder_names: Vec<&str> = folders["meta"]["folders"]
        .as_array().expect("folders").iter()
        .filter_map(|f| f["name"].as_str()).collect();
    assert!(folder_names.contains(&"INBOX"), "INBOX missing: {folder_names:?}");

    // 2. search — round-trip the seed uid
    let search = call_tool(&mut harness, "draftsafe.search",
        json!({"folder": "INBOX", "subject": "e2e-wire-test-smoke"})).await;
    assert!(search["meta"]["total_matched"].as_u64().unwrap() >= 1);
    let seed_uid = u32::try_from(
        search["untrusted"]["messages"][0]["uid"].as_u64().expect("uid"),
    ).expect("uid fits u32");
    assert!(seed_uid > 0);

    // 3. fetch_message — assert plain body
    let fetched = call_tool(&mut harness, "draftsafe.fetch_message",
        json!({"folder": "INBOX", "uid": seed_uid})).await;
    assert!(
        fetched["untrusted"]["body_text"].as_str().unwrap_or("")
            .contains(fixtures::PLAIN_BODY),
        "fetch_message body missing expected content: {fetched}",
    );

    // 4. list_attachments — must surface the seeded attachment
    let attachments = call_tool(&mut harness, "draftsafe.list_attachments",
        json!({"folder": "INBOX", "uid": seed_uid})).await;
    let parts = attachments["untrusted"]["attachments"]
        .as_array().expect("attachments array");
    assert!(!parts.is_empty(), "attachments must be non-empty");
    let part = &parts[0];
    let part_id = part["part_id"].as_str().expect("part_id");
    assert!(!part_id.is_empty(), "part_id must be non-empty");

    // 5. download_attachment — bytes must equal the seed payload
    let download = call_tool(&mut harness, "draftsafe.download_attachment",
        json!({"folder": "INBOX", "uid": seed_uid, "part_id": part_id})).await;
    let path_str = download["meta"]["path"].as_str().expect("download path");
    let path = std::path::Path::new(path_str);
    assert!(path.starts_with(&download_dir),
        "downloaded path {} must be inside {}", path.display(), download_dir.display());
    let bytes = std::fs::read(path).expect("read downloaded attachment");
    assert_eq!(bytes, fixtures::ATTACHMENT_BYTES, "attachment bytes mismatch");

    // 6. list_labels — empty or pre-seeded, just validate the shape
    let _ = call_tool(&mut harness, "draftsafe.list_labels",
        json!({"folder": "INBOX"})).await;

    // 7. mark_read / mark_unread / flag / unflag — exercise both ToolName variants
    for tool in ["draftsafe.mark_read", "draftsafe.mark_unread",
                 "draftsafe.flag", "draftsafe.unflag"] {
        call_tool(&mut harness, tool,
            json!({"folder": "INBOX", "uid": seed_uid})).await;
    }

    // 8. add_label / remove_label
    call_tool(&mut harness, "draftsafe.add_label",
        json!({"folder": "INBOX", "uid": seed_uid, "label": "phase3-test"})).await;
    call_tool(&mut harness, "draftsafe.remove_label",
        json!({"folder": "INBOX", "uid": seed_uid, "label": "phase3-test"})).await;

    // 9. create_draft × 2 — bare and reply-to
    call_tool(&mut harness, "draftsafe.create_draft", json!({
        "to": [{"address": "dest@example.com"}],
        "subject": "wire-bare-draft",
        "body_text": "bare",
    })).await;
    call_tool(&mut harness, "draftsafe.create_draft", json!({
        "to": [{"address": "reply@example.com"}],
        "subject": "Re: e2e-wire-test-smoke",
        "body_text": "Acknowledged.",
        "in_reply_to_uid": seed_uid,
        "in_reply_to_folder": "INBOX",
    })).await;

    // 10. move_message → re-search to confirm gone from INBOX
    call_tool(&mut harness, "draftsafe.move_message", json!({
        "folder": "INBOX",
        "destination": "Trash",
        "uid": seed_uid,
    })).await;
    let after = call_tool(&mut harness, "draftsafe.search",
        json!({"folder": "INBOX", "subject": "e2e-wire-test-smoke"})).await;
    assert_eq!(after["meta"]["total_matched"].as_u64().unwrap(), 0);

    // 11. use_account → switch to readonly, list_accounts as infrastructure tool
    call_tool(&mut harness, "use_account", json!({"account": "readonly"})).await;
    let accounts = call_tool(&mut harness, "list_accounts", json!({})).await;
    let names: Vec<&str> = accounts["meta"]["accounts"]
        .as_array().expect("accounts").iter()
        .filter_map(|a| a["name"].as_str()).collect();
    assert!(names.contains(&"draftsafe") && names.contains(&"readonly"));
```

Tool input shapes above mirror the existing handlers — verify each against the schemars-generated input schema if a call fails. If a tool name is namespaced differently or an input field name is wrong, follow the failure message back to the corresponding handler under `crates/rimap-server/src/tools/` and adjust the JSON argument.

- [ ] **Step 5: Add audit assertions + clean shutdown**

Replace the trailing `let _ = harness.shutdown_and_wait()...` with:

```rust
    let status = harness.shutdown_and_wait().await;
    assert!(status.success(), "child must exit 0, got {status:?}");

    let records = read_audit_records(&audit_path);

    // Pairing: every tool_start has a tool_end with matching start_seq.
    let starts: Vec<&Value> = records.iter()
        .filter(|r| r["kind"] == "tool_start").collect();
    let ends: Vec<&Value> = records.iter()
        .filter(|r| r["kind"] == "tool_end").collect();
    assert_eq!(starts.len(), ends.len(),
        "tool_start/tool_end mismatch: {} starts, {} ends", starts.len(), ends.len());
    for start in &starts {
        let seq = &start["seq"];
        let paired = ends.iter().find(|e| e["start_seq"] == *seq);
        assert!(paired.is_some(),
            "no tool_end paired with tool_start seq {seq}: {start}");
    }

    // Namespace: every account-scoped tool_* record carries `account = "draftsafe"`.
    let account_scoped_tools: std::collections::HashSet<&str> = [
        "list_folders", "search", "fetch_message", "list_attachments",
        "download_attachment", "list_labels", "mark_read", "mark_unread",
        "flag", "unflag", "add_label", "remove_label", "move_message",
        "create_draft",
    ].into_iter().collect();
    for r in &records {
        let kind = r["kind"].as_str().unwrap_or("");
        if !matches!(kind, "tool_start" | "tool_end") { continue; }
        let tool = r["tool"].as_str().unwrap_or("");
        if account_scoped_tools.contains(tool) {
            assert_eq!(r["account"].as_str(), Some("draftsafe"),
                "account-scoped {kind} for {tool} must record account=\"draftsafe\": {r}");
        }
        if matches!(tool, "use_account" | "list_accounts") {
            assert!(r["account"].is_null(),
                "infrastructure {kind} for {tool} must record account=null: {r}");
        }
    }
```

Add the helper:

```rust
fn read_audit_records(path: &std::path::Path) -> Vec<Value> {
    let contents = std::fs::read_to_string(path).expect("read audit log");
    contents.lines()
        .map(|line| serde_json::from_str(line).expect("parse audit line"))
        .collect()
}
```

- [ ] **Step 6: Run the full test**

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire wire_e2e_full_session_draft_safe --locked --no-capture --no-fail-fast`
Expected: PASS. If individual tool calls fail, the wire harness's stderr capture will include the binary's tracing output in the panic message; adjust the argument JSON or the assertion to match the handler's actual contract.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire.rs
git commit -m "test(server): add Phase 3 wire-driven Dovecot e2e (#265)

wire_e2e_full_session_draft_safe spawns rusty-imap-mcp against a
two-account Dovecot-backed config and exercises every draft-safe
tool over the stdio JSON-RPC wire: list_folders, search,
fetch_message, list_attachments, download_attachment (with byte
equality vs the seeded payload), list_labels, mark_read/unread,
flag/unflag, add_label/remove_label, create_draft × 2, move_message,
use_account, list_accounts.

Every response validates against (a) the vendored MCP envelope/method
schemas and (b) the per-tool response schema under
tests/fixtures/rimap-tool-schemas/.

Audit log assertions verify tool_start/tool_end pairing
(start_seq correlation) and namespace attribution
(account-scoped records carry account=\"draftsafe\";
infrastructure records carry account=None).

The readonly-posture sibling test lands in a follow-up commit.
"
```

---

## Task 11: `e2e_wire.rs` — read-only posture denial

**Files:**
- Modify: `crates/rimap-server/tests/e2e_wire.rs` (append a second test)

- [ ] **Step 1: Append the test scaffold**

At the bottom of `tests/e2e_wire.rs`, before the `read_audit_records` helper:

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_e2e_readonly_posture_denial() {
    let Some(dovecot) = DovecotHarness::try_start() else {
        return;
    };
    let tempdir = TempDir::new().expect("tempdir");
    let audit_path = tempdir.path().join("audit.jsonl");
    let allowed_base = tempdir.path().to_path_buf();
    let download_dir = tempdir.path().join("downloads");
    std::fs::create_dir_all(&download_dir).expect("mkdir download_dir");

    let config_path = tempdir.path().join("config.toml");
    let config = build_dovecot_config(&dovecot, &audit_path, &allowed_base, &download_dir);
    std::fs::write(&config_path, config).expect("write config");

    let envs = [(PASSWORD_ENV_VAR, DOVECOT_PASSWORD)];
    let mut harness = Harness::spawn_with_config(&config_path, tempdir, &envs).await;
    let _ = harness.initialize_handshake().await;
    harness.send_initialized().await;

    // Negative tools/list check: readonly.move_message must NOT appear.
    let tools_list = harness.request("tools/list", json!({})).await;
    let names: Vec<&str> = tools_list["result"]["tools"]
        .as_array().expect("tools").iter()
        .filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"draftsafe.move_message"));
    assert!(!names.contains(&"readonly.move_message"),
        "readonly.move_message must not be advertised; got {names:?}");

    // Posture denial on the wire.
    let resp = harness.request(
        "tools/call",
        json!({
            "name": "readonly.move_message",
            "arguments": {"folder": "INBOX", "destination": "Trash", "uid": 1},
        }),
    ).await;
    assert_envelope_valid(&resp);
    assert!(resp["error"].is_object(), "expected error envelope, got {resp}");

    // Pin the observed posture-denial code. If rmcp's error mapping or
    // the posture-denial bridge changes, update this constant and
    // document why — silent drift in posture wire shape is exactly
    // what this test surfaces. Matches Phase 1's -32602 pin pattern.
    const POSTURE_DENIAL_CODE: i64 = -32602;
    assert_eq!(resp["error"]["code"].as_i64(), Some(POSTURE_DENIAL_CODE),
        "posture-denial wire code drifted; got {resp}");

    let status = harness.shutdown_and_wait().await;
    assert!(status.success(), "child must exit 0, got {status:?}");

    // Audit: exactly one tool_start for readonly.move_message paired
    // with a tool_end, both carrying account="readonly".
    let records = read_audit_records(&audit_path);
    let starts: Vec<&Value> = records.iter()
        .filter(|r| r["kind"] == "tool_start" && r["tool"] == "move_message")
        .collect();
    assert_eq!(starts.len(), 1, "expected exactly one move_message tool_start");
    assert_eq!(starts[0]["account"].as_str(), Some("readonly"),
        "tool_start.account must be \"readonly\" (not collapsed to None): {records:#?}");

    let ends: Vec<&Value> = records.iter()
        .filter(|r| r["kind"] == "tool_end" && r["tool"] == "move_message")
        .collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["account"].as_str(), Some("readonly"));
    assert_eq!(ends[0]["start_seq"], starts[0]["seq"]);
}
```

- [ ] **Step 2: Verify the actual posture-denial wire code**

If `POSTURE_DENIAL_CODE = -32602` is wrong, the assertion fails with the observed value in the panic message. Read the panic, update the constant to match, and add a comment explaining what it is (e.g. `// rmcp INVALID_PARAMS = -32602; posture denials bridge through ErrorData::invalid_params(...)`).

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire wire_e2e_readonly_posture_denial --locked --no-capture`

Expected after pin: PASS.

- [ ] **Step 3: Run clippy + both tests**

Run: `cargo clippy -p rimap-server --tests --all-features --locked -- -D warnings`
Expected: clean.

Run: `RIMAP_REQUIRE_DOCKER=1 cargo nextest run -p rimap-server --test e2e_wire --locked --no-capture`
Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/rimap-server/tests/e2e_wire.rs
git commit -m "test(server): add Phase 3 read-only posture denial test (#265)

wire_e2e_readonly_posture_denial verifies that
1. readonly.move_message is NOT advertised on tools/list,
2. tools/call against readonly.move_message returns the pinned
   posture-denial JSON-RPC error envelope, and
3. the audit log records a tool_start+tool_end pair carrying
   account=\"readonly\" (not collapsed to legacy None) — proving the
   audit boundary is correctly scoped under the read-only namespace
   even though DEFAULT_ACCOUNT_NAME would collapse it.

The wire error code is pinned in a constant with a comment so silent
drift in rmcp's error mapping or the posture-denial bridge surfaces
as an immediate test failure with the observed value in the panic.
"
```

---

## Task 12: CI — Phase 3 target with zero-tests-selected guard

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add a zero-tests guard step to the existing `test (stable)` job**

The workspace nextest run (`cargo nextest run --workspace --locked --no-tests=pass`) already picks up `e2e_wire` because it's an integration test under the `rimap-server` crate. But that flag is `--no-tests=pass`, which would silently green-light a `e2e_wire` file rename. Add an explicit guard step.

Find the existing `test (stable)` job block (around line 66). After its existing `cargo nextest run --workspace ...` step, append:

```yaml
      - name: Phase 3 wire e2e — fail if zero tests selected
        run: |
          cargo nextest run -p rimap-server --test e2e_wire \
            --locked --no-tests=fail \
            --no-capture
        env:
          RIMAP_REQUIRE_DOCKER: "1"
```

`--no-tests=fail` is the nextest flag that exits non-zero when the filter selects zero tests. If a future commit renames or deletes `e2e_wire.rs`, this step fails immediately with `no tests to run`.

If the runner does not have Docker available, drop `RIMAP_REQUIRE_DOCKER` — but every linux GHA runner has Docker; the env var ensures a missing-runtime regression in the GHA image fails loudly.

- [ ] **Step 2: Lint the workflow**

Run: `actionlint .github/workflows/ci.yml && zizmor .github/workflows/ci.yml`
Expected: no warnings.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add Phase 3 wire e2e step with zero-tests guard (#265)

The workspace nextest run already executes e2e_wire because it's an
integration test under rimap-server, but it uses --no-tests=pass which
would silently green-light a future rename. Add an explicit step that
targets `--test e2e_wire` with --no-tests=fail; if the filter ever
matches zero tests the step exits non-zero. RIMAP_REQUIRE_DOCKER=1
upgrades a missing-runtime regression in the GHA image from a silent
skip to a loud failure.
"
```

---

## Task 13: Wall-time measurement + AGENTS.md docs

**Files:**
- Modify: `AGENTS.md`

- [ ] **Step 1: Measure wall time**

Run on a warm machine:
```bash
RIMAP_REQUIRE_DOCKER=1 time cargo nextest run -p rimap-server --test e2e_wire --locked --no-capture
```
Record the elapsed wall time. Expected: 10–25 s (Dovecot bring-up dominates).

- [ ] **Step 2: Decide whether env-flag gating is required**

If wall time ≤ 60 s: no gating change needed.
If wall time > 60 s: add a `RIMAP_RUN_E2E_WIRE` opt-in gate to both tests (early return when not set + `RIMAP_REQUIRE_DOCKER` is also unset). Document the threshold trigger in `AGENTS.md`.

- [ ] **Step 3: Update `AGENTS.md`**

Find the "Container runtime for integration tests" section (around line 64). After it, insert a new subsection:

```markdown
### Wire-driven Dovecot e2e (Phase 3, #265)

`crates/rimap-server/tests/e2e_wire.rs` drives the production binary
over its stdio JSON-RPC wire against the same Dovecot fixture
`e2e_full_session` uses. It exercises every draft-safe and read-only
posture tool, validates every response against the vendored MCP spec
schemas + per-tool schemas under
`crates/rimap-server/tests/fixtures/rimap-tool-schemas/`, and asserts
audit-log pairing + namespace attribution.

- Wall time: ~XX s on a warm developer machine; ~YY s on CI.
  *(Fill in after the measurement step.)*
- Gating: silent-skip when no container runtime is present;
  `RIMAP_REQUIRE_DOCKER=1` flips to loud failure. Same convention
  as the legacy in-process `e2e_full_session`.
- Schema regen: when changing any `<Tool>Meta` or `<Tool>Untrusted`
  struct in `crates/rimap-server/src/tools/`, run
  `just regen-tool-schemas` and commit the diff. CI fails on a
  non-empty diff under `tests/fixtures/rimap-tool-schemas/`.
- Specs: see `docs/superpowers/specs/2026-05-12-mcp-behavioral-conformance-design.md`.
```

Also append the spec to the "Source of truth" paragraph at the top of `AGENTS.md` (around line 22). After `2026-05-12-mcp-conformance-node-design.md`, add:

```
The Phase 3 behavioral-conformance spec
(`2026-05-12-mcp-behavioral-conformance-design.md`) covers the
wire-driven Dovecot e2e harness for tool dispatch + audit-log
attribution.
```

- [ ] **Step 4: Commit**

```bash
git add AGENTS.md
git commit -m "docs: document Phase 3 wire e2e in AGENTS.md (#265)

Add a Wire-driven Dovecot e2e subsection under Container runtime for
integration tests with the measured wall-time, the gating convention,
the schema regen requirement, and a spec cross-link.
"
```

---

## Task 14: Phase 1 + Phase 2 regression smoke

**Files:** (none — verification only)

- [ ] **Step 1: Run Phase 1's full suite**

Run: `cargo nextest run -p rimap-server --test mcp_wire_conformance --locked --no-capture`
Expected: 9 tests pass. If any fail, the Task 5 extraction broke a subtle behavior — bisect against the Task 5 commit.

- [ ] **Step 2: Run Phase 2's Node suite**

Run: `just mcp-conformance-node`
Expected: green. If the new test-support subcommand or feature wiring broke the binary spawn, this surfaces it.

- [ ] **Step 3: Run the full local-CI equivalent**

Run: `just ci`
Expected: green.

- [ ] **Step 4: No code commit — verification only**

If anything fails, return to the offending task and fix forward. Do not commit a "fixup" that masks the regression; trace it back.

---

## Self-review notes

Performed during plan authorship; no separate commit required.

1. **Spec coverage:** Each section of the spec maps to a task — §3.1 layout → Tasks 5/6/9; §3.3 test-support layer → Tasks 1/2/3; §4.1 Harness extraction → Task 5; §4.2 DovecotHarness extraction → Task 6; §4.3 schema validator → Task 8; §4.4 dump-tool-schemas → Tasks 1/2/3; §4.5/§5.1 full-session test → Task 10; §4.6 multi-account config → Task 9; §5.2 posture-denial test → Task 11; §5.3 multipart seed → Task 9; §6 stderr capture → Task 7; §7.1 drift detector → Task 4; §7.3 wall-time + §7.4 CI → Tasks 12/13; §8 acceptance criteria → covered across Tasks 4/10/11/12/13.

2. **Placeholder scan:** Wall-time numbers in Task 13 are deliberately measured at execution time (`XX`, `YY` are placeholders to fill from real output, not "TBD"). The posture-denial code constant in Task 11 has a documented fallback path (read panic message, update constant). The `<sha>` action pins in Task 4 are explicit "look up the SHA already used in this file" instructions, not unfilled blanks.

3. **Type consistency:** `Harness::spawn_with_config(&Path, TempDir, &[(&str, &str)])` is used identically in Tasks 7, 10, 11. `validator_for_tool_response(&'static str)` defined in Task 8, called in Task 10. `DovecotHarness::fingerprint()` / `port()` defined in Task 9 Step 3 (with the "if not already present" guard), called in Tasks 9 and 10. `fixtures::PLAIN_BODY`, `fixtures::ATTACHMENT_BYTES`, `fixtures::ATTACHMENT_FILENAME` defined in Task 9, used in Task 10.

---

## Execution Handoff

Plan complete and saved. Use the writing-plans skill's execution-handoff prompt to pick subagent-driven vs inline.
