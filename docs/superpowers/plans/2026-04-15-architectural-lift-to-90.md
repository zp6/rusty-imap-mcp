# Architectural lift to >90% score

**Author:** Claude · **Date:** 2026-04-15 · **Branch target:** `desloppify/arch-lift`

## Why

Desloppify scoring plateaued at overall **88.8 / strict 88.4** after 17 commits of targeted fixes. The two highest-weighted subjective drags now reflect *structure*, not craft:

| Drag | Current | Root cause | Reviewer note |
|-|-|-|-|
| High elegance | 82.0 | `mcp/server.rs` bundles handler, dispatch, audit envelope, tool catalog, name parsing in **1149 LOC** | "three parallel `ToolName` match tables" |
| API coherence | 78.0 | `download_attachment` breaks the handler arity convention; uid/uids XOR encoded at runtime not type level | "runtime encoding defeats static shape uniformity" |
| Low/Mid elegance | 82.5 / 86.5 | Two `rimap-content` monoliths (`parse.rs` 2026 LOC, `html.rs` 1413 LOC) mix MIME walking, meta extraction, sniffing, sanitisation | "extract_bodies, extract_attachments, enforce_header_count all belong to distinct concerns" |
| Structure nav / package org | 86.0 / 86.0 | `rimap-audit` is a flat 12-file crate root | "flat 12-file root does not reflect internal subsystems" |

Craft-level sweeps have been exhausted. Further gains require moving modules, not editing them.

## Scope — four refactors

Each is its own commit on `desloppify/arch-lift` (split from `desloppify/code-health`). Each refactor ends with `cargo check/test/clippy -D warnings` **and** `cargo doc --no-deps` green.

### R1 — Split `mcp/server.rs` into cohesive modules

**Target:** `crates/rimap-server/src/mcp/server.rs` → `crates/rimap-server/src/mcp/{server.rs, dispatch.rs, tool_catalog.rs, tool_name.rs, audit_envelope.rs}`.

Split map (LOC approximate):

| New module | Moves | Source lines |
|-|-|-|
| `mcp/server.rs` | `ImapMcpServer`, `ServerHandler` impl (MCP method routing only) | 1-292, 64-293 |
| `mcp/dispatch.rs` | `dispatch_tool`, `PostureContext`, `rimap_error_to_breaker_reason` | 293-333, 308-333, body of dispatch in 334-643 |
| `mcp/audit_envelope.rs` | `run_with_audit_envelope`, `emit_tool_start`, `emit_tool_end` | extracted from 334-643 |
| `mcp/tool_name.rs` | `refine_tool_name`, `split_tool_name`, `is_valid_account_prefix`, `is_legacy_single_account` | 683-776 |
| `mcp/tool_catalog.rs` | `tool_spec`, all `ToolSpec` entries, `schema_map`, `ser`, `parse_args` | 644-end |

**Visibility strategy:** each new module gets `pub(super)` items by default; only `ImapMcpServer` stays `pub`. Cross-module helpers (`ser`, `parse_args`) become `pub(super)` in `mcp/mod.rs`.

**Risk:** Module re-split *can* change public surface if `#[doc(hidden)] pub` items get missed. Mitigate by running `cargo public-api --diff-git-checkouts main HEAD` before commit (install: `cargo install cargo-public-api --locked`).

**Gate test:**
- `cargo test -p rimap-server --lib --bins --tests`
- `cargo test --test e2e` — passes or graceful-skips (podman).
- `cargo doc --workspace --no-deps` — zero warnings.

**Estimated effort:** 3 hours. Pure mechanical split; no semantic change.

---

### R2 — Split `rimap-content::parse.rs` (2026 LOC)

**Target:** `crates/rimap-content/src/parse/{mod.rs, meta.rs, headers.rs, bodies.rs, attachments.rs, mime_scrub.rs, filename.rs, sniff.rs}`.

| New file | Moves |
|-|-|
| `parse/mod.rs` | `parse_message` entry point; re-exports; module-level doc |
| `parse/meta.rs` | `extract_meta`, `format_addr`, `address_strings`, `first_address_string`, `convert_datetime`, `sanitize_opt_str` |
| `parse/headers.rs` | `header_value_first_text`, `header_value_all_text`, `collect_header_domains`, `push_domains_from`, `addr_domain`, `enforce_header_count`, `extract_mailing_list`, `sanitize_header_value` |
| `parse/bodies.rs` | `extract_bodies`, `process_text_part`, `process_html_part`, `part_charset`, `check_mime_depth`, `compute_max_depth`, `depth_recursive` |
| `parse/attachments.rs` | `extract_attachments`, `build_attachment_meta`, `part_bytes`, `is_inline`, `content_type_string` |
| `parse/mime_scrub.rs` | `scrub_header_smuggling`, `detect_smuggling_spans`, `locate_encoded_word_end`, `find_header_end`, `split_header_lines` |
| `parse/filename.rs` | `sanitize_attachment_filename`, `sanitize_filename`, `contains_bidi_override`, `DOCUMENT_EXTENSIONS`, `RESERVED_WINDOWS_STEMS`, `EXECUTABLE_EXTENSIONS` |
| `parse/sniff.rs` | `sniff_content_types`, `content_types_compatible` |

**Visibility:** all items `pub(super)` or `pub(crate)`; only `parse_message` + essential types stay `pub` via `parse/mod.rs` re-export.

**Risk:** `tests/snapshots/` uses insta for MIME fixtures. Snapshots MUST be byte-identical post-split. If they drift, the split *changed behaviour*, which is wrong — do not `cargo insta accept`, debug instead.

**Gate test:** `cargo test -p rimap-content` (covers 166+ tests, insta snapshots, proptest).

**Estimated effort:** 2 hours.

---

### R3 — Split `rimap-content::html.rs` (1413 LOC)

**Target:** `crates/rimap-content/src/html/{mod.rs, style_parse.rs, hidden.rs, mismatch.rs, extract.rs, sanitize.rs}`.

| New file | Moves |
|-|-|
| `html/mod.rs` | `process` entry point; re-exports; shared `Html`/`HiddenMethod`/`StyleHints` types |
| `html/style_parse.rs` | `parse_inline_style`, `parse_px`, `opacity_is_zero`, `font_size_is_zero`, `parse_translate_px`, `classify_single_declaration`, `classify_inline_style`, `StyleHints` impl |
| `html/hidden.rs` | `detect_hidden`, `HiddenMethod` enum, `compile_selector`, hidden-method test harness |
| `html/mismatch.rs` | `detect_mismatches`, `MismatchHit`, `extract_registrable_domain`, `count_matching`, `count_img_with_src` |
| `html/extract.rs` | `extract_text`, `walk_children`, `collect_visible_text`, `walk_element`, `push_text`, `normalize_whitespace`, `collect_anchor_hrefs`, `NON_CONTENT_TAGS` |
| `html/sanitize.rs` | `build_ammonia_builder`, `sanitize_body` |

**Gate test:** `cargo test -p rimap-content html` (and full rimap-content tests).

**Estimated effort:** 1.5 hours.

---

### R4 — Reorganise `rimap-audit/src/` into subsystems

**Target:** `crates/rimap-audit/src/` flat 12 files → 4 subsystem directories.

| New dir | Moves |
|-|-|
| `audit/writer/` | `writer.rs` → `writer/mod.rs`, `writer/rotation.rs` (from root `rotation.rs`), `writer/provenance.rs`, `writer/self_check.rs` |
| `audit/record/` | `record.rs` → `record/mod.rs`, `record/ids.rs`, `record/error.rs` |
| `audit/redact/` | `redact.rs` → `redact/mod.rs` |
| `audit/reader/` | `reader.rs` → `reader/mod.rs`, `reader/backup_exclude.rs` |
| `audit/fs.rs` | `fs_ext.rs` (rename — no longer "extension", it's the FS helper module) |

**Visibility:** preserve public API via `lib.rs` re-exports: `pub use writer::AuditWriter; pub use record::{...}`. External callers of `rimap_audit::AuditWriter` keep working.

**Risk:** `rimap-server` imports `rimap_audit::WriterConfig`, `rimap_audit::record::*` — the moves must not break these. Grep `rimap_audit::` across workspace and update imports if needed.

**Gate test:** `cargo test -p rimap-audit -p rimap-server`.

**Estimated effort:** 1 hour.

---

### Not in scope: R5 (deferred) — uid/uids XOR unification

The API coherence finding asks to unify `FlagInput`/`LabelInput`/`MoveMessageInput` (XOR `uid` vs `uids`) into a single typed selector. This is:
- A **breaking JSON schema change** for MCP clients.
- Affects rustdoc, tests, and conformance fixtures.
- Requires user sign-off on the client-facing contract.

Separately: `download_attachment`'s extra `download_dir` arg. The handler signature genuinely differs because it writes to disk — this could be absorbed into the `Input` struct. Smaller change, still a schema update.

**Recommendation:** defer both until architectural split lands; revisit with a dedicated schema-versioning plan and user approval.

## Execution order

Sequential (each depends on clean state of prior):

1. **R4 (audit)** — smallest, lowest risk, unblocks audit-writer testing independence. **Commit `desloppify: split rimap-audit into writer/record/redact/reader subsystems`**.
2. **R2 (parse.rs)** — biggest mechanical win, touches content internals only. **Commit `desloppify: split rimap-content::parse into meta/headers/bodies/attachments/mime_scrub/filename/sniff`**.
3. **R3 (html.rs)** — same pattern as R2 but narrower. **Commit `desloppify: split rimap-content::html into style_parse/hidden/mismatch/extract/sanitize`**.
4. **R1 (server.rs)** — most entangled; leave for last so tests already passing when splitting the dispatch hub. **Commit `desloppify: split mcp/server.rs into dispatch/audit_envelope/tool_name/tool_catalog`**.

Between each step: `cargo check/test/clippy` + `cargo doc --no-deps` green. Do not batch failures.

## Risk register

| Risk | Likelihood | Mitigation |
|-|-|-|
| Snapshot drift in rimap-content | Medium | `cargo insta test` after R2/R3; if drift, debug — never accept blindly |
| Public API accidental expansion/contraction | Medium | `cargo public-api --diff-git-checkouts` gate before each commit |
| `#[cfg(test)]` visibility surprises | Low | Run `cargo test --all-targets` not just `--lib` |
| `rimap-server` test harness broken by audit reorg | Low | R4 first; run full workspace tests |
| Dovecot integration tests fail | Expected | Podman-infra issue, unrelated — note in commit body, don't block |
| Subjective score regression on other dimensions | Medium | Re-review after all 4 land; expect +3-5 on High/Mid/Low elegance + Structure nav; may find new naming/convention items |

## Expected outcome

If R1-R4 land cleanly:

| Dimension | Now | Projected | Weight-impact |
|-|-|-|-|
| High elegance | 82.0 | 90-92 | +1.4-1.8 pts subjective pool |
| Mid elegance | 86.5 | 89-91 | +0.4-0.8 pts |
| Low elegance | 82.5 | 86-88 | +0.4-0.5 pts |
| Structure nav | 86.0 | 91-93 | +0.4-0.5 pts |
| Package org | 86.0 | 91-93 | +0.4-0.5 pts |

**Projected subjective pool:** 87.7 → ~90.5.
**Projected overall:** 0.25 × 95.7 + 0.75 × 90.5 = 91.8.
**Projected strict:** ~91.5.

Above the 90 target with comfortable margin — but dependent on reviewers not finding new blockers. The uid/uids shape will remain a cap at ~78 on API coherence (9.8% weight, so -1.2 pts) even after the structural work, which is why R5 sits as a future ask.

## Checkpoints for user approval

- **Before R1:** confirm monolith split is acceptable (affects diff readability on any in-flight PR touching server.rs).
- **After R1-R4 land:** before running the 20-batch re-review that will regenerate scores.
- **Before R5:** user signs off on schema change to `FlagInput`/`LabelInput`/`MoveMessageInput` and `download_attachment` shape.
