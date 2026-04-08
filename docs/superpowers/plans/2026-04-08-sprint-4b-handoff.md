# Sprint 4b Handoff — HTML, Look-alike, Full-crate Mutation Gate

**Status:** Planned. Sprint 4a is complete and merged.
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](../specs/2026-04-07-rusty-imap-mcp-design.md) §Sprint 4 (lines 1228–1249) and §Sprint 4 adversarial corpus (lines 1097–1128)
**Sprint 4a design spec:** [`2026-04-08-sprint-4a-content-pipeline-design.md`](../specs/2026-04-08-sprint-4a-content-pipeline-design.md)
**Sprint 4a plan:** [`2026-04-08-sprint-4a-content-pipeline.md`](./2026-04-08-sprint-4a-content-pipeline.md)
**mail-parser 0.11 API reference (reused in 4b):** [`2026-04-08-sprint-4a-mail-parser-0.11-api.md`](./2026-04-08-sprint-4a-mail-parser-0.11-api.md)

## What Sprint 4a shipped

- **`rimap-content::output`** — `Content`, `ContentMeta`, `Untrusted`, `AttachmentMeta`, `MailingListInfo`, `SecurityWarning`, `WarningCode` (9 variants, all `#[non_exhaustive]`).
- **`rimap-content::error`** — `ContentError` via `thiserror` with `Malformed` / `LimitExceeded` / `Decoding` variants.
- **`rimap-content::unicode`** — pure `decode` (encoding_rs), `normalize_nfkc`, `filter_codepoints` + `FilterResult`, `normalize_line_endings`, `truncate_graphemes`, and `sanitize` composer.
- **`rimap-content::parse`** — `parse_message` entrypoint, pre-parse CRLF-header-smuggling scrub (span-aware detector across logical headers), `mail-parser 0.11` header extraction via `format_addr` / `Address::iter`, MIME walk with depth and part-count limits, text-body selection via `message.text_body`, attachment metadata with magic-byte sniffing for PNG/JPEG/GIF/PDF/ZIP/MZ-exe, inline detection via `PartType::InlineBinary`, `List-*` extraction via dedicated mail-parser accessors.
- **10 adversarial corpus fixtures** under repo-root `tests/injection-corpus/`: prompt-injection-plaintext, zero-width-poisoning, trojan-source-bidi, rfc2047-crlf-smuggling, mime-type-spoofing, oversized-body, multipart-bomb, nested-rfc822, mailing-list, multilingual-negative.
- **Insta snapshots** for all 10 fixtures committed under `crates/rimap-content/tests/snapshots/`.
- **5 proptest properties** on the unicode pipeline at 10,000 cases each: `nfkc_stable`, `no_stripped_codepoints_in_output`, `no_c0_c1_controls_except_tab_newline`, `utf8_preserved`, `grapheme_truncation_bounds`.
- **IDN baseline tests** — two unit tests pinning U-label and A-label IDN passthrough behavior for 4b's homograph work to diff against.
- **75 `rimap-content` tests** total (26 unicode + 26 parse including IDN baseline + 4 output/error + 5 proptest + 10 snapshots + 1 corpus harness + misc unit), 338 workspace tests.
- **`just ci` wall-clock ~21 s** (pre-4a baseline ~11 s; proptest at 10k cases adds ~10 s).

## Sprint 4b scope

### `rimap-content::html` module

Per parent spec §6:

- `html5ever` parser + `scraper` DOM traversal.
- Plain-text extraction that routes every text node through `unicode::sanitize`.
- Hidden-element detection: `display:none`, `visibility:hidden`, `opacity:0`, off-screen positioning, white-on-white, zero-font-size.
- Text/href mismatch detection: anchor text that looks like one URL while the `href` points elsewhere.
- Optional `ammonia` pipeline to produce an allowlist-sanitized HTML variant for tools that opt in.
- Integrate with `parse::extract_bodies` so `text/html` parts (currently surfaced via `message.html_body`) route through the HTML pipeline before being added to `Untrusted` (possibly as a new `body_html` field on `Untrusted`).

New `WarningCode` variants (minimum):
- `HtmlHiddenContentStripped`
- `HtmlLinkTextHrefMismatch`
- `HtmlScriptStripped`
- `HtmlStyleStripped`

### `rimap-content::lookalike` module

Per parent spec:

- Mixed-script detection (Latin + Cyrillic in the same label → homograph signature).
- TR39 skeleton generation (vendored `confusables.txt` compiled to a `phf` map at build time via `build.rs`).
- Punycode / IDN handling via `idna` — compare U-label and A-label forms, surface ambiguity.
- Bidi / invisible pre-strip audit: if `unicode::filter_codepoints` stripped characters from a domain, emit a dedicated lookalike warning (not just the generic unicode warning).
- Filename extension-after-bidi-strip check: detect cases where a filename's visible extension differs from the extension after removing bidi overrides.

New `WarningCode` variants (minimum):
- `LookalikeMixedScript`
- `LookalikeHomographDomain`
- `LookalikeIdnPunycode`
- `LookalikeFilenameExtensionSpoof`

### Remaining corpus fixtures (5+)

To land under `tests/injection-corpus/` alongside the 4a set:

1. `white-on-white/` — HTML with hidden instructions.
2. `css-display-none/` — HTML with `display:none` injection.
3. `homograph-domain/` — anchor href with Cyrillic `а` in `paypal.com`.
4. `text-href-mismatch/` — anchor text shows `bank.example.com`, href goes to `attacker.example`.
5. `idn-passthrough-positive/` — legitimate U-label IDN email (complements the Sprint 4a IDN unit tests).
6. One fixture per new `LookalikeMixedScript` / `LookalikeHomographDomain` / `LookalikeIdnPunycode` / `LookalikeFilenameExtensionSpoof` variant asserting the exact code fires.

Each fixture needs matching insta snapshots.

### Full-crate `cargo-mutants ≥ 80%`

Sprint 4a deferred `cargo-mutants` to end of 4b. Run it once against the complete `rimap-content` crate after the html and lookalike modules land, document surviving mutants under `docs/superpowers/mutants-survivors.md` with reasons each is acceptable.

## 4a TODOs and gotchas surfaced during implementation

### Correctness findings

- **`unicode::sanitize` pipeline ordering bug (fixed in Task 10)** — originally `filter_codepoints` ran BEFORE `normalize_line_endings`, which meant the raw `\r` in every CRLF pair in a mail-parser body was stripped as a disallowed C0 control before the pair could be collapsed into `\n`. Every multi-line body in production would have emitted spurious `UnicodeC0C1Stripped` warnings. Fixed by swapping the order. The bug was caught by the `multilingual-negative` corpus fixture (which asserts zero warnings on clean multilingual content).
- **RFC 2047 CRLF header smuggling must operate on logical headers, not physical lines** — the plan's original `line_has_encoded_word_with_crlf` per-line helper couldn't catch the realistic attack where `=?...` and `?=...` land in different logical headers because `Bcc:` etc. don't start with whitespace, so standard folding doesn't glue them. The scrub was rewritten in Task 5 as a span-aware detector (`detect_smuggling_spans` + `locate_encoded_word_end` + `EncodedWordEnd` enum) that drops the full span from originating `=?` through terminating `?=` inclusive, or just the originating header when the terminator is missing (dangling case).

### mail-parser 0.11 API differences vs. the plan's original 0.9 assumptions

The plan was written against `mail-parser 0.9.x` and the workspace pinned `0.11.2`. A dedicated API reference doc was added during execution: [`2026-04-08-sprint-4a-mail-parser-0.11-api.md`](./2026-04-08-sprint-4a-mail-parser-0.11-api.md). Key differences that bit us:

- `message.from()` / `.to()` / `.cc()` return `Option<&Address>` (typed), NOT a matchable `HeaderValue::Address` variant. Use `Address::iter()` to flatten list+group addresses uniformly.
- `message.in_reply_to()` / `.references()` / `.list_*()` return `&HeaderValue` (not `Option`) — always handle `HeaderValue::Empty` as absent.
- `MessagePartId` is `u32` in 0.11.2 (not `usize` as the reference doc initially stated — corrected mid-sprint). Cast with `as usize` when indexing into `message.parts`.
- **`List-ID` / `List-Unsubscribe` / `List-Post` come back as `HeaderValue::Address`**, not `Text` / `TextList`. mail-parser 0.11 routes them through `parse_address()`. The `sanitize_header_value` helper needs an `Address` arm that flattens through `format_addr`.
- `MessagePart` has no `contents()` or `is_inline()` method — use a `PartType` match for raw bytes (`Text`/`Html` → `as_bytes()`, `Binary`/`InlineBinary` → `as_ref()`) and check `matches!(part.body, PartType::InlineBinary(_))` or the `Content-Disposition` fallback for inline detection.
- `MimeHeaders` is a trait — import it with `use mail_parser::MimeHeaders as _;` in any helper that calls `content_type()`, `content_disposition()`, `content_id()`, or `attachment_name()`.
- `DateTime::to_timestamp() -> i64` exists and is the right entrypoint for `time::OffsetDateTime::from_unix_timestamp`. Guard with `dt.is_valid()` first.

All of the above is documented in the API reference doc — 4b should keep it current.

### Fixture / toolchain gotchas

- **`.eml` fixtures must use CRLF line endings.** Pre-commit hooks (`end-of-file-fixer`, `mixed-line-ending`) will silently rewrite them to LF and corrupt the fixtures. Task 10 added `^tests/injection-corpus/` and `crates/rimap-content/tests/snapshots/` to the exclude lists in `.pre-commit-config.yaml`. 4b's new fixtures (white-on-white, CSS display:none, etc.) will benefit from the same exclusion — no new config needed.
- **`check-added-large-files` pre-commit hook** was extended to exclude `crates/rimap-content/tests/snapshots/` because the `oversized-body` fixture's snapshot is ~1 MiB. Future large snapshots inherit the exclusion.
- **`typos.toml`** excludes `tests/injection-corpus/` because zero-width and bidi fixture content triggers false positives (e.g., `hel` substrings inside `\u{200B}` escapes).
- **multipart-bomb fixture generator in the plan was missing blank lines** between multipart headers and children — mail-parser flattened the whole blob into a single text body rather than rejecting it. Task 10's fix: emit `\r\n\r\n` after every `Content-Type` header in the generator.

### Test-ordering / pipeline observations

- Proptest at 10k cases × 5 properties adds ~10 s to `just ci` wall-clock (pre-4a ~11 s → post-4a ~21 s). No `just test-slow` split was needed. 4b's proptest additions will compound — if the total exceeds ~60 s, introduce a `PROPTEST_CASES=1000`-gated `just test` vs full-cases `just test-slow` split as described in the Sprint 4a plan's Task 12.
- The corpus harness runs as a single `#[test] fn all_corpus_fixtures_pass()` that accumulates per-fixture failures into one panic. 4b can add new fixtures by just dropping them into `tests/injection-corpus/<name>/` — no harness changes required.

### Deliberately deferred

- **Recursive `message/rfc822` sanitization.** 4a extracts nested rfc822 metadata as an attachment and deliberately does NOT recurse into the nested body. The `nested-rfc822` fixture asserts `must_not_contain: ["This is the original body"]` which passes because `extract_bodies` skips `PartType::Message` parts. 4b or Sprint 5 should decide whether nested messages get a recursive parse pass.
- **Runtime-configurable limits.** `MAX_MESSAGE_BYTES`, `MAX_BODY_BYTES`, `MAX_HEADER_BYTES`, `MAX_MIME_DEPTH`, `MAX_MIME_PARTS`, `MAX_HEADER_COUNT` are all compile-time `const` in 4a. If Sprint 5's MCP server needs posture-dependent limits, promote them to runtime config there.
- **`unicode-properties` crate is declared but unused** in 4a. Task 4 left it in `crates/rimap-content/Cargo.toml` anticipating 4b's lookalike module will use it for Unicode category checks. If 4b doesn't need it after all, drop it from the crate's dependencies.

## Dependencies 4b will add

To workspace root `[workspace.dependencies]`:

- `html5ever` — HTML parsing.
- `markup5ever_rcdom` OR `scraper` — DOM traversal (pick one based on how Task 4b's design shakes out).
- `ammonia` — HTML sanitization (allowlist-based).
- `idna` — punycode / IDN handling.
- `phf` + `phf_codegen` — perfect-hash map for the confusables table.

All new deps need a `cargo deny` license review at 4b's first commit. A vendored copy of the Unicode `confusables.txt` file must live under the repo (not pulled at build time) and be compiled into a `phf::Map` via a `build.rs`.

## Blockers / prerequisites for 4b

None. Sprint 4a is self-contained and 4b can start as soon as 4a merges.

## Suggested 4b task order

1. Workspace deps + license review.
2. `WarningCode` variant additions (output.rs).
3. `rimap-content::html` skeleton + unit tests on small HTML fragments.
4. `rimap-content::html` integration into `parse::extract_bodies`.
5. HTML corpus fixtures (white-on-white, CSS display:none, text/href mismatch) + snapshots.
6. `rimap-content::lookalike` skeleton + mixed-script + TR39 skeleton.
7. `lookalike` IDN integration via `idna`.
8. Look-alike corpus fixtures + snapshots.
9. IDN passthrough fixture (positive, complements the 4a unit tests).
10. Full-crate `cargo-mutants` run + survivor documentation.
11. 4b handoff doc → Sprint 5.
