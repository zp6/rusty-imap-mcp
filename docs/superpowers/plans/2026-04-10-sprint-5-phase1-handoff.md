# Sprint 5 Phase 1 → Phase 2 Handoff — Content Pipeline Remediation

**Status:** Sprint 5 Phase 1 is complete on branch `feat/sprint-5`.
**Parent spec:** [`2026-04-10-sprint-5-phase1-remediation-design.md`](../specs/2026-04-10-sprint-5-phase1-remediation-design.md)
**Phase 1 plan:** [`2026-04-10-sprint-5-phase1.md`](./2026-04-10-sprint-5-phase1.md)
**Sprint 4b → Sprint 5 handoff (prior):** [`2026-04-08-sprint-4b-to-5-handoff.md`](./2026-04-08-sprint-4b-to-5-handoff.md)
**Mutants survivors:** [`../mutants-survivors.md`](../mutants-survivors.md)

## What Phase 1 shipped

Phase 1 closed 14 commits on `feat/sprint-5`, addressing warning semantics,
Reply-To coverage, bypass fixes, ammonia hardening, build strictness, and
supply-chain comment hygiene.

### Warning semantics (#49)

- **Renamed `HtmlHiddenContentStripped` → `HtmlHiddenContentDetected`.** The old
  name implied hidden content was removed everywhere. In reality, hidden content
  is stripped from `body_text` but may remain in `body_html` when the posture
  allows HTML exposure. The new name reflects detection, not removal.
- **Added `HtmlAnchorUnparsableHref` variant** (Informational severity). Fires
  when an anchor's `href` can't be resolved via the Public Suffix List but the
  anchor's visible text contains a URL-looking token (detected by `linkify`).
  This makes "we checked and it's fine" distinguishable from "we couldn't
  check." Phase 2 posture policy can filter on this variant.
- **Pinned `HtmlLinkTextHrefMismatch` as raw-DOM (pre-ammonia) semantics** via
  doc comment. An anchor stripped by ammonia may still produce this warning —
  the warning signals the message's intent, not the sanitized output.
- **Pinned `SecurityWarning::detail` as opaque/human-readable** via doc comment.
  Consumers must not parse this field programmatically; use `code` and other
  typed fields for dispatch.

### Reply-To + address extraction (#50 items 1 and 3)

- **`reply_to: Option<String>` added to `ContentMeta`.** Populated via
  `first_address_string(message.reply_to(), ...)` in `extract_meta()`, which
  includes the bidi-prestrip audit. Reply-To domains with bidi override
  characters now emit `LookalikeHomographDomain` with `location = "header:reply_to"`.
- **`header_domains: Vec<(String, String)>` added to `LookalikeInput`.** Built
  at the `parse_message` boundary using structured `Addr.address` data rather
  than rfind-based re-parsing of rendered display strings.
- **`scan_header_domains()` rewritten** to iterate pre-extracted domains
  (covers `from`, `to`, `cc`, and `reply_to`). Eliminates the Sprint 4b
  finding 9 gap where Reply-To was invisible to the lookalike header pass.
- **`collect_header_domains()` + `addr_domain()` helpers added** in `parse.rs`
  at the structured-data boundary.

### Bypass fixes (#51 items 2–5)

- **CDATA text leak (#51.2).** html5ever/scraper parses `<![CDATA[` in HTML5
  non-SVG context as a bogus comment. Inner content can leak as text nodes via
  two paths: closed CDATA (text includes `]]>`) and unclosed CDATA (text node
  follows the bogus comment with no `]]>` marker). Fixed with an `after_cdata`
  flag in text extraction that suppresses text nodes following CDATA sections.
  Both paths covered and tested.
- **Double-extension filename heuristic (#51.3).** `detect_double_extension()`
  checks for patterns like `invoice.pdf.exe` — penultimate extension is a
  document type, final extension is an executable type. Emits
  `LookalikeFilenameExtensionSpoof` with `reason=double_extension`. Two
  constant slices (`DOCUMENT_EXTENSIONS`, `EXECUTABLE_EXTENSIONS`) define the
  type sets.
- **PSL silent-skip (#51.4).** `detect_mismatches()` now emits
  `HtmlAnchorUnparsableHref` when an href can't be PSL-resolved but anchor
  text contains a URL token. Return type changed from `(hits, overflow)` to
  `(hits, overflow, unparsable_hrefs)`.
- **Off-screen threshold (#51.5).** Lowered from -1000px to -100px (catches
  evasion via `left: -999px`). Added `transform: translate` pattern detection
  via `parse_translate_px()`. `StyleHints` gains `transform_offset_px: Option<f64>`.

### Ammonia hardening (#52 items 1–2)

- **Explicit `rm_tags()` call** with 20 tags including `details` and `summary`
  (new removals — collapsed `<details>` content is invisible to humans but
  visible to LLMs reading HTML tokens). Other tags pinned: `iframe`, `object`,
  `embed`, `meta`, `base`, `link`, `form`, `input`, `button`, `textarea`,
  `svg`, `math`, `frame`, `frameset`, `noframes`, `applet`.
- **Explicit `strip_comments(true)`** to pin comment-stripping behavior against
  upstream ammonia drift.

### Charset proptest (#52 item 3)

- **New `proptest_charset.rs`** — 10,000 cases of arbitrary charset parameter
  strings in `Content-Type` headers, asserting that `parse_message` always
  produces valid UTF-8 output or a structured `ContentError`, never a panic.

### `build.rs` strictness (#53 item 3)

- **Malformed target rows now `panic!`** instead of `eprintln!` + `continue`.
  A malformed row is a build-time data integrity failure, not a warning.
- **Floor raised from >5000 to >=6200.** Unicode 16.0 produces ~6355 entries;
  the tighter floor catches silent format drift that drops more than ~2.5% of
  entries.

### Supply-chain comment hygiene (#54)

- **M1:** 4 missing ICU4X proc-macros added to R10 provenance block in root
  `Cargo.toml` (`yoke-derive`, `zerofrom-derive`, `zerovec-derive`,
  `displaydoc`).
- **M2:** `idna` comment rewritten to document the actual ICU4X baseline and
  the ~20 transitive crates it introduces.
- **M3:** `phf` default-features comment clarified — our direct declaration
  disables defaults; `phf_macros` still enters the graph transitively via
  `cssparser`.
- **L1:** Caret-range semantics documented in `deny.toml` `skip-tree` entries.
- **L2:** Unicode-DFS-2016 license TODO added to `crates/rimap-content/Cargo.toml`
  for the vendored `confusables.txt`.
- **L3:** `NOTICE` file created at `crates/rimap-content/data/NOTICE` with
  Unicode attribution.
- **L4:** PSL version pattern (patch-as-snapshot-date) documented in `deny.toml`.
- **L5:** `check-forbidden-macros.sh` regex tightened to
  `(^|/)crates/[^/]+/build\.rs$` so only workspace crate build scripts are
  exempted.

## Test totals

- `just ci` green: **459 tests, 0 failures**
- Wall-clock: **~10.7s test execution** (total `just ci` ~2m 20s with linters)
- **25 corpus fixtures** (up from 22), **25 insta snapshots**
- **9 proptest properties** at 10,000 cases each (up from 8):
  - `proptest_charset.rs`: 1 new property
  - `proptest_html_lookalike.rs`: 3 from Sprint 4b
  - `properties.rs`: 5 from Sprint 4a
- **New unit tests:** ammonia tag denial (18 tags), HTML comments, off-screen
  threshold variants (−999px, −50px, translateX, small translateX), CDATA both
  closed and unclosed, double-extension positive and negative, Reply-To
  extraction, Reply-To bidi prestrip, Reply-To lookalike (mixed script), PSL
  unparsable href

## Deferred items

- **Mutants rerun (#53 item 4).** The ~76-minute `cargo mutants --package rimap-content`
  run should be done before the Phase 1 PR merges to verify the library kill
  rate reached ≥85% after Phase 1's test additions. The Sprint 4b number was
  83.9% (library-only) / 77.5% (whole-crate including `epvme_runner`).
- **Authentication-Results parser (#50 item 2).** New module for parsing
  `Authentication-Results:` headers (DKIM, SPF, DMARC pass/fail). Deferred to
  Phase 2 or later. No partial scaffolding was added.
- **rfc822 recursion (#51.1).** Deferred since Sprint 4a. Nested HTML bodies
  inside `message/rfc822` attachments are not processed. `MAX_MIME_DEPTH` only
  applies to the outer walk.
- **`spawn_blocking` (#53 item 1).** `parse_message` is CPU-bound (~2ms per
  message on warm cache). The async wrapper belongs in `rimap-server`, which
  lands in Phase 2. No change to the synchronous `rimap-content` API.
- **`epvme_runner` integration tests (#53 item 2).** 44 of the Sprint 4b
  surviving mutants were in `src/bin/epvme_runner.rs`. Phase 2 should add
  integration tests for `collect_eml_files` and `run_dataset` over a small
  fixture directory.

## API findings

- **`mail_parser::Message::reply_to()`** returns `Option<&Address<'_>>`, the
  same shape as `from()`. `first_address_string` works directly without
  special-casing.
- **html5ever CDATA in HTML5 non-SVG context.** The parser treats `<![CDATA[`
  as a bogus comment that terminates at the first `>`. Inner content leaks as
  text nodes via two distinct paths: (1) closed CDATA — the text includes the
  `]]>` literal; (2) unclosed CDATA — a text node follows the bogus comment
  with no `]]>` marker. Both paths are now suppressed by the `after_cdata`
  flag.
- **`ammonia::Builder::rm_tags` is a no-op for tags ammonia already strips.**
  The explicit call is intentional — it pins behavior against upstream
  allowlist changes. A future ammonia version that adds `details` to its
  allowlist would silently expose content without our explicit removal.

## Phase 2 prerequisites

1. **`ContentMeta.reply_to` is populated.** Phase 2 tool handlers can expose it
   in `fetch_message` and `search_messages` responses without any further
   `rimap-content` changes.
2. **`HtmlAnchorUnparsableHref` is wired.** Phase 2 posture policy can filter
   on it. The Informational severity means it does not block message delivery
   by default.
3. **`body_html` sanitization is hardened** (ammonia explicit tag list + CDATA
   suppression + off-screen threshold + comment stripping). Phase 2
   `fetch_message` with `include_html=true` builds on a solid foundation.
4. **Address extraction uses structured data.** Phase 2 can trust that lookalike
   warnings reflect actual `Addr.address` values at every header domain, not
   re-parsed display strings. Reply-To is now a first-class source.
5. **`spawn_blocking` wrapper.** Phase 2 adds the async shim in `rimap-server`
   wrapping the synchronous `rimap_content::parse_message`. The `rimap-content`
   API remains `fn parse_message(raw: &[u8]) -> Result<Content, ContentError>`
   — no change required.

## Gotchas and non-obvious constraints

- **`after_cdata` flag is stateful across the text-node walk.** The flag is set
  when a bogus-comment node whose data starts with `[CDATA[` is encountered, and
  cleared after the following text node is suppressed. This is load-bearing for
  the unclosed CDATA path — do not refactor it into a stateless predicate.
- **`detect_double_extension` requires ≥3 dot-separated segments.** A filename
  like `invoice.exe` has only 2 segments and does not fire. This is intentional:
  the heuristic targets the specific `visible.doc.exe` camouflage pattern.
- **`rm_tags` order in `build_ammonia_builder` does not matter.** ammonia applies
  the removal set regardless of declaration order. The 20-entry list is for
  documentation — future maintainers should not infer semantic ordering.
- **Off-screen transform detection parses the minimum (most negative) pixel
  value found.** `translate(-500px, 0)` extracts −500 from the first argument
  only; `0` (no `px` suffix) is not parsed as a pixel value. This is the
  conservative safe direction: false positives are harmless, false negatives
  (missed detections) are the risk.
- **`just ci` wall-clock is ~2m 20s** (including `cargo deny check`, `typos`,
  and linters). The proptest at 10,000 × 9 properties dominates test time. The
  `[profile.dev.package."*"] opt-level = 3` workspace setting from Sprint 4b
  Task 18 is load-bearing — do not remove it.
