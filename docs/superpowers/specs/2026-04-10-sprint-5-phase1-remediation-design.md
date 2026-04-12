# Sprint 5 Phase 1 — Content Pipeline Remediation Design

**Status:** Approved 2026-04-10
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](2026-04-07-rusty-imap-mcp-design.md) §Sprint 5
**Sprint 4b handoff:** [`../plans/2026-04-08-sprint-4b-to-5-handoff.md`](../plans/2026-04-08-sprint-4b-to-5-handoff.md)
**Branch:** `feat/sprint-5`

## 1. Scope and Strategy

Sprint 5 is a two-phase sprint:

- **Phase 1** (this spec): Close out high-priority Sprint 4b remediation
  items against `rimap-content`. Fixes warning semantics, bypass classes,
  Reply-To gaps, ammonia hardening, and supply-chain comment hygiene.
- **Phase 2** (separate spec): MCP server wiring (`rimap-server` tool
  handlers, IMAP STORE/MOVE/APPEND, `spawn_blocking`, end-to-end tests).

### Issues addressed

| Issue | Items included | Items deferred |
|-------|---------------|----------------|
| #49 (posture + warning semantics) | All 4 items | — |
| #50 (Reply-To + Auth-Results gaps) | Items 1, 3 (Reply-To, addr consistency) | Item 2 (Authentication-Results parser) |
| #51 (bypass classes) | Items 2–5 (CDATA, double-ext, PSL skip, off-screen) | Item 1 (rfc822 recursion) |
| #52 (ammonia + charset hardening) | All 3 items | — |
| #53 (operational readiness) | Items 3, 4 (build.rs, mutants rerun) | Items 1, 2 (spawn_blocking, epvme tests → Phase 2) |
| #54 (supply-chain comment hygiene) | All items | — |

### Deferred to Phase 2 or later

- **Authentication-Results parser** (#50 item 2) — New module, new config
  surface, not load-bearing for Phase 2 tool handlers.
- **`message/rfc822` recursion** (#51 item 1) — Largest single item,
  deferred since Sprint 4a. High value but high complexity; requires its
  own design spec.
- **`spawn_blocking` for `parse_message`** (#53 item 1) — Needed in
  `rimap-server`, lands naturally in Phase 2.
- **`epvme_runner` integration tests** (#53 item 2) — Phase 2 cleanup.

### Approach

Bottom-up by file to minimize merge conflicts:

1. Warning semantics layer (`output.rs`)
2. Ammonia hardening (`html.rs` — defensive)
3. Bypass fixes (`html.rs` + `parse.rs`)
4. Reply-To + address extraction (`parse.rs` + `lookalike.rs`)
5. Hardening & verification (build.rs, proptest, mutants, comments)

## 2. Warning Semantics Layer

File: `crates/rimap-content/src/output.rs`

### 2.1 Rename `HtmlHiddenContentStripped` → `HtmlHiddenContentDetected`

The current name implies the payload is removed everywhere. In reality,
hidden content is stripped from `body_text` but remains in `body_html`
(by design — posture rules decide exposure). Rename the variant to
reflect detection, not removal.

Update the `severity()` match arm. All 22 insta snapshots regenerate.

### 2.2 Add `HtmlAnchorUnparsableHref` variant

New variant with severity `Informational`. Fires when
`extract_registrable_domain()` returns `None` for an anchor href whose
visible text looks like a URL/domain. Distinguishes "we checked and
it's fine" from "we couldn't check."

### 2.3 Document `HtmlLinkTextHrefMismatch` raw-DOM semantics

Add doc comment on the variant:

> Reflects the original message content, not the sanitized `body_html`.
> An anchor stripped by ammonia may still produce this warning. This is
> intentional — the warning is a signal about the message's intent,
> not about the sanitized output.

No code change beyond the comment. Detection stays pre-ammonia.

### 2.4 Pin `detail` as opaque

Add doc comment on `SecurityWarning::detail`:

> Human-readable context string. Consumers MUST NOT parse this field
> programmatically — use `code` and other typed fields for dispatch.
> Format may change without notice.

No structural change. If Phase 2 tool handlers need structured warning
data, add typed fields to `SecurityWarning` incrementally.

## 3. Ammonia Hardening

File: `crates/rimap-content/src/html.rs`

### 3.1 Explicit tag denial list

In `build_ammonia_builder()`, call `Builder::rm_tags()` with: `script`,
`style`, `iframe`, `object`, `embed`, `meta`, `base`, `link`, `form`,
`input`, `button`, `textarea`, `svg`, `math`, `frame`, `frameset`,
`noframes`, `applet`, `details`, `summary`.

This pins behavior against ammonia default drift. The `details`/`summary`
removal is new — collapsed content is invisible to humans glancing at
rendered output but visible to LLMs reading HTML tokens.

Test: `sanitize_drops_iframe_and_details` — pass each tag through
`build_ammonia_builder().clean()`, assert stripped output.

### 3.2 Explicit `strip_comments(true)`

Call `.strip_comments(true)` in `build_ammonia_builder()`.

Test: `body_html_has_no_html_comments` — verify `<!-- comment -->`
is removed from sanitized output.

## 4. Bypass Fixes

### 4.1 CDATA text leak

Files: `crates/rimap-content/src/html.rs` (`collect_visible_text` /
`walk_element`)

Sprint 4b's `html-tokenizer-divergence` fixture discovered that
scraper/html5ever leaks JS source from CDATA sections into `body_text`
as text nodes. The inner `<script>` tags are stripped but literal JS
source survives.

Fix: in `walk_element()`, skip text content that leaked through CDATA
parsing. The exact mechanism depends on scraper's representation —
validate in the worktree before implementing. The handoff characterizes
this as a one-liner.

Re-add CDATA payload to `html-tokenizer-divergence` fixture with
`must_not_contain: ["alert(", "cdata-bypass"]`.

### 4.2 PSL silent-skip → `HtmlAnchorUnparsableHref`

File: `crates/rimap-content/src/html.rs` (`detect_mismatches`)

In `detect_mismatches()`, when `extract_registrable_domain(href)`
returns `None` but the existing `linkify` scan finds a URL in the
anchor's visible text (i.e., the text looks like a clickable domain),
emit `HtmlAnchorUnparsableHref` instead of silently skipping the
anchor. This covers the case where an attacker crafts an href the PSL
cannot resolve, paired with visible text pointing at a brand.

Warning fields:
- `code`: `HtmlAnchorUnparsableHref`
- `detail`: `"href=<unparsable_url>,text=<visible_text>"`
- `location`: `"body_html:anchor"`

Corpus fixture: `html-anchor-unparsable-href` with an anchor whose
href has an unresolvable PSL domain paired with brand-like visible text.

### 4.3 Off-screen threshold loosening

File: `crates/rimap-content/src/html.rs` (`detect_hidden`)

Current: fires on `left <= -1000px` or `top <= -1000px` with
`position: absolute|fixed`.

Change to: fire on `left < -100px` or `top < -100px` (same position
requirement). This catches `-999px` evasion while leaving small
negative values (legitimate border tricks) alone.

Add `transform: translate` pattern: parse inline `style` for
`transform:` values matching `translate[XY]?\s*\(\s*-(\d+)` where the
captured pixel value exceeds 100. Catches `translateX(-9999px)` and
`translate(-500px, 0)`.

Corpus fixture: `html-offscreen-evasion` with `left: -999px` and
`transform: translateX(-9999px)` payloads, asserting
`HtmlHiddenContentDetected`.

### 4.4 Double-extension filename heuristic

File: `crates/rimap-content/src/parse.rs` (`build_attachment_meta`)

After the existing bidi-override check and before `sanitize_filename()`,
add a double-extension check:

1. Split filename on `.`
2. If 3+ segments, extract penultimate and final extensions (lowercased)
3. If penultimate is a document type AND final is an executable type,
   emit `LookalikeFilenameExtensionSpoof`

Document types: `pdf`, `doc`, `docx`, `xls`, `xlsx`, `png`, `jpg`,
`jpeg`, `gif`, `txt`, `csv`, `rtf`.

Executable types: `exe`, `dll`, `bat`, `cmd`, `ps1`, `vbs`, `js`,
`scr`, `msi`, `app`, `dmg`, `sh`, `com`, `pif`, `jar`, `lnk`.

Warning fields:
- `code`: `LookalikeFilenameExtensionSpoof`
- `detail`: `"reason=double_extension,visible=.<penultimate>,declared=.<penultimate>.<final>"`
- `location`: `"attachment[<idx>]:filename"`

The gap-pinning fixture at
`tests/injection-corpus/attachment-double-extension/` currently asserts
detector-absent behavior. When this detector lands, the snapshot diffs
— that diff is the verification.

## 5. Reply-To + Address Extraction

### 5.1 Add `reply_to` to `ContentMeta`

File: `crates/rimap-content/src/output.rs`

Add `pub reply_to: Option<String>` to `ContentMeta`.

### 5.2 Populate Reply-To in `extract_meta`

File: `crates/rimap-content/src/parse.rs`

In `extract_meta()`, populate `reply_to` via `first_address_string()`
on `message.reply_to()`, matching the existing `from` pattern.

### 5.3 Thread Reply-To through bidi audit

File: `crates/rimap-content/src/parse.rs`

In `parse_message()`, after the existing from/to/cc bidi audit calls,
add a call for Reply-To: extract the first `Addr` from
`message.reply_to()`, pass to `audit_addr_domain_bidi()` with
`location = "header:reply_to"`.

### 5.4 Add Reply-To pass in lookalike `scan_header_domains`

File: `crates/rimap-content/src/lookalike.rs`

Add a fourth block in `scan_header_domains()` after cc: extract domain
from `meta.reply_to`, pass to `emit_classification()` with
`location = "header:reply_to"`.

### 5.5 Address extraction consistency

Files: `crates/rimap-content/src/lookalike.rs`,
`crates/rimap-content/src/parse.rs`

Currently `extract_domain_from_address()` uses `rfind('@')` on the
rendered string from `ContentMeta`. This can disagree with
mail-parser's structured `Addr.address` on adversarial display-name
attacks like `"Name <fake@x>" <real@y>`.

Fix: add a field `header_domains: Vec<(String, String)>` to
`LookalikeInput` — each entry is `(domain, location)`, pre-extracted
at the `parse_message()` boundary using `addr.address` directly.
`scan_header_domains()` iterates this vec instead of re-parsing
`meta.from`/`to`/`cc`/`reply_to`.

`extract_domain_from_address()` remains available for anchor-href and
body-url passes in passes 2 and 3 of `audit()`.

### 5.6 Corpus fixture

Add `lookalike-reply-to-mismatch` with a Reply-To domain that triggers
`LookalikeMixedScript` or `LookalikeIdnPunycode`.

## 6. Hardening & Verification

### 6.1 `build.rs` strictness

File: `crates/rimap-content/build.rs`

Two changes:

1. **Fail on malformed rows.** Replace `eprintln!` + `continue` with
   `panic!` on parse failure. Any skipped row becomes a build failure.
   Add comment: "Bump EXPECTED_MIN and re-audit when regenerating from
   a new Unicode version."
2. **Tighten floor.** Change `assert!(seen.len() > 5000)` to
   `assert!(seen.len() >= 6200)`. Unicode 16.0 produces ~6355 MA rows;
   this catches silent format drift dropping more than ~2.5% of entries.

### 6.2 Charset proptest

File: new `crates/rimap-content/tests/proptest_charset.rs` (or appended
to `proptest_html_lookalike.rs`)

Property: generate arbitrary `Content-Type` charset parameter strings,
construct a minimal `.eml` with that charset declaration, pass to
`parse_message()`, assert the result is either
`Err(ContentError::...)` or `Ok(Content)` where `body_text` is valid
UTF-8. Run at 10k cases.

### 6.3 Mutants rerun

Run `cargo mutants --package rimap-content --timeout 120` early in the
sprint. Confirm library kill rate >= 85%. Update
`docs/superpowers/mutants-survivors.md` with measured numbers and new
survivor list. If survivors reveal easy kills, add targeted tests.

### 6.4 Supply-chain comment hygiene (#54)

All items from issue #54. Zero code impact beyond comments, config
annotations, and one shell script regex fix:

- **M1:** Add 4 missing proc-macros (`yoke-derive`, `zerofrom-derive`,
  `zerovec-derive`, `displaydoc`) to R10 provenance block in
  `Cargo.toml`, identifying trust anchor as "unicode-org via ICU4X,
  pulled through idna_adapter."
- **M2:** Rewrite `idna` line comment: first `url`/`idna` entry in the
  workspace, `idna 1.x` replaced in-crate Unicode tables with ICU4X
  provider stack pulling ~20 new transitive crates. Accepted because
  ICU4X is the unicode-org canonical path; re-audit on any minor bump.
- **M3:** Rewrite `phf` default-features comment: our direct `phf`
  declaration disables defaults; `phf_macros` still enters the graph
  transitively via `cssparser`.
- **L1:** Add comment to `deny.toml` skip-tree entries documenting
  caret-range semantics.
- **L2:** Add TODO comment in `crates/rimap-content/Cargo.toml` about
  Unicode-DFS-2016 license for vendored `data/confusables.txt`.
- **L3:** Create `crates/rimap-content/data/NOTICE` with Unicode
  attribution matching root `NOTICE`.
- **L4:** Add informational comment about `psl` version pattern
  (patch tracks PSL snapshot date) in `deny.toml`.
- **L5:** Tighten `scripts/check-forbidden-macros.sh` regex from
  `(^|/)build\.rs$` to `(^|/)crates/[^/]+/build\.rs$`.

## 7. Test Impact Summary

### New corpus fixtures (4)

| Fixture | Asserts |
|---------|---------|
| `html-anchor-unparsable-href` | `HtmlAnchorUnparsableHref` emitted |
| `html-offscreen-evasion` | `HtmlHiddenContentDetected` on -999px and translateX |
| `lookalike-reply-to-mismatch` | `LookalikeMixedScript` or `LookalikeIdnPunycode` on Reply-To |
| (CDATA re-add to `html-tokenizer-divergence`) | `must_not_contain` for JS source |

### Snapshot changes

All 22 existing snapshots regenerate due to the
`HtmlHiddenContentStripped` → `HtmlHiddenContentDetected` rename.
The `attachment-double-extension` gap-pinning fixture snapshot diffs
when the detector lands.

### New unit tests

| Test | File |
|------|------|
| `sanitize_drops_iframe_and_details` | `html.rs` |
| `body_html_has_no_html_comments` | `html.rs` |

### New proptest

| Property | Cases | File |
|----------|-------|------|
| charset parameter → valid UTF-8 or error | 10,000 | `proptest_charset.rs` |

## 8. Files Changed

| File | Changes |
|------|---------|
| `crates/rimap-content/src/output.rs` | Rename variant, add variant, add `reply_to` field, doc comments |
| `crates/rimap-content/src/html.rs` | Ammonia hardening, CDATA fix, PSL→warning, off-screen threshold, tests |
| `crates/rimap-content/src/parse.rs` | Reply-To extraction, bidi audit, double-extension, header_domains for lookalike |
| `crates/rimap-content/src/lookalike.rs` | Reply-To pass, `header_domains` on `LookalikeInput`, `scan_header_domains` rewrite |
| `crates/rimap-content/build.rs` | Malformed-row panic, floor tightening |
| `crates/rimap-content/tests/proptest_charset.rs` | New charset proptest |
| `Cargo.toml` | Comment fixes (M1, M2, M3) |
| `deny.toml` | Comment fixes (L1, L4) |
| `crates/rimap-content/Cargo.toml` | Comment fix (L2) |
| `crates/rimap-content/data/NOTICE` | New file (L3) |
| `scripts/check-forbidden-macros.sh` | Regex tighten (L5) |
| `docs/superpowers/mutants-survivors.md` | Updated numbers |
| `tests/injection-corpus/` | 3 new fixtures + 1 fixture update |
| `crates/rimap-content/tests/snapshots/` | 22+ snapshot regenerations |

## 9. Out of Scope

- Authentication-Results parser (#50 item 2)
- `message/rfc822` recursion (#51 item 1)
- `spawn_blocking` wiring (#53 item 1)
- `epvme_runner` tests (#53 item 2)
- `<style>` block class/id resolution (deferred since 4b)
- Runtime-configurable limits (deferred since 4b)
- Differential HTML oracle
- cargo-fuzz harnesses
- Phase 2 MCP server work
