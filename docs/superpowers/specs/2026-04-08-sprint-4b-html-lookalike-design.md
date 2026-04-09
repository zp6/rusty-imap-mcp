# Sprint 4b Design — `rimap-content::html` + `rimap-content::lookalike`

**Status:** Approved during brainstorming. Ready for plan-writing.
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](./2026-04-07-rusty-imap-mcp-design.md) §Sprint 4 (lines 1228–1249).
**Sprint 4a design:** [`2026-04-08-sprint-4a-content-pipeline-design.md`](./2026-04-08-sprint-4a-content-pipeline-design.md).
**Sprint 4b handoff doc:** [`../plans/2026-04-08-sprint-4b-handoff.md`](../plans/2026-04-08-sprint-4b-handoff.md).
**mail-parser 0.11 reference:** [`../plans/2026-04-08-sprint-4a-mail-parser-0.11-api.md`](../plans/2026-04-08-sprint-4a-mail-parser-0.11-api.md).

---

## 1. Goal

Extend the Sprint 4a `rimap-content` crate with two new modules, replacing the temporary `HtmlBodyUnsanitized` refusal landed in 4a R3:

- **`html`** — parse `text/html` bodies, extract sanitized plain text, detect hidden-content and anchor/href phishing signals, and produce a separate ammonia-sanitized HTML rendering with remote content removed.
- **`lookalike`** — audit domains (from headers, anchor hrefs, and plain-text URLs) and attachment filenames for TR39 mixed-script violations, homograph confusables, punycode/IDN round-trips, and bidi-strip ordering attacks.

Sprint 4b also lands a full-crate `cargo-mutants` ≥ 80% quality gate as the terminal task, with a written survivor-rationale document.

Sprint 4b is self-contained: no runtime-configurable limits, no Sprint 5 posture logic, no recursive `message/rfc822` parsing (all still deferred per the handoff doc).

## 2. Scope decisions locked during brainstorming

| # | Decision | Rationale |
|---|---|---|
| Q1 | **`Untrusted.body_html: Option<String>`** as an additive field. `body_text` remains the primary. | Sanitized HTML is a real Sprint 5 deliverable; adding the field now costs one field and ~12 snapshot regenerations, avoiding a bigger retrofit mid-Sprint-5. |
| Q2 | **Inline-style-only hidden-element detection.** `<style>` blocks are stripped with `HtmlStyleStripped`; class/id resolution deferred to a future sprint. | Keeps 4b's dep graph and complexity ceiling low; strip-and-warn is a safe default; the detection visitor is structured so class-lookup can layer on later without rewriting the consumer. |
| Q3 | **ammonia default minus remote content.** `<img>` tag preserved with `alt` only (`src`/`srcset` stripped), URL schemes restricted to `http`/`https`/`mailto`/`tel`. New `HtmlRemoteImageStripped` warning. | Tracking-pixel hazard is real; Sprint 5 LLM consumers need a clean signal that a message wanted to phone home; tables survive so newsletters remain readable. |
| Q4 | **Href-mismatch rule: text-URL ≠ registrable-href-domain.** Uses `linkify` for URL extraction over anchor text (text nodes only, no `title`/`aria-label`); `addr` for PSL-aware registrable-domain comparison; punycode-normalized case-insensitive compare. | Sweet-spot precision/recall; newsletter "click here" anchors do not fire; `login.bank.example.com` text in `bank.example.com` href does not fire. |
| Q5a | **Lookalike scans headers + anchor hrefs + linkified body_text URLs.** | Closes the text/plain phishing gap cheaply; linkify is already pulled in for Q4. |
| Q5b | **Vendored Unicode 16.0 `confusables.txt` + `build.rs` + `phf_codegen`.** | Matches handoff's explicit "vendored + compile-time map" requirement; avoids the unmaintained `unicode-security` crate flagged as a supply-chain yellow flag. |
| Q5c | **TR39 Highly Restrictive mixed-script profile** via `unicode-script`. | Standard TR39 answer; permits legitimate Japanese/Chinese multilingual domains while catching Latin+Cyrillic and Latin+Greek spoofing. |
| Approach | **Pure layered free-function modules**, no `ContentPipeline` struct. | Consistency with 4a's `unicode.rs` pattern; no speculative state optimization; cleaner mutation-testing surface. |
| R3 | **`HtmlBodyUnsanitized` variant is deleted** from `WarningCode` entirely. | "Replace, don't deprecate." The variant existed only as a 4a safety valve; with real sanitization landing, a defined-but-unemitted variant would be dead code. Snapshot for the `html-only-hidden-instructions` 4a corpus fixture regenerates with real extracted text + warnings. |

## 3. Architecture

### 3.1 Crate layout

```text
crates/rimap-content/src/
├─ lib.rs                  (re-exports unchanged + `html` + `lookalike`)
├─ output.rs               (WarningCode: +9, −1; severity() updated)
├─ error.rs                (unchanged)
├─ unicode.rs              (unchanged)
├─ parse.rs                (extract_bodies: R3 refusal → html::process call;
│                           parse_message: lookalike::audit at the bottom)
├─ html.rs                 (NEW)
├─ lookalike.rs            (NEW)
└─ data/
   └─ confusables.txt      (NEW — vendored Unicode 16.0, Unicode-DFS-2016)
build.rs                   (NEW — phf_codegen for confusables)
tests/
├─ snapshots/              (existing + 9 new .snap files)
└─ (corpus harness unchanged)
```

### 3.2 Module boundaries

- `html` is the only consumer of `scraper`, `ammonia`, `linkify`. Nothing else in the workspace imports them.
- `lookalike` is the only consumer of `idna`, `addr`, `unicode-script`, `unicode-properties`, `phf`, and the compiled confusables map.
- `parse::extract_bodies` is the only caller of `html::process`.
- `parse::parse_message` is the only caller of `lookalike::audit`.
- No circular imports. `html` and `lookalike` do not reference each other; they communicate indirectly via a struct returned from `html::process` that `parse::extract_bodies` partially forwards into the `lookalike::audit` input.

### 3.3 Dependency delta

Added to `[workspace.dependencies]` in the repo-root `Cargo.toml`:

| Crate | Version | Purpose | License |
|---|---|---|---|
| `scraper` | `0.26.0` | HTML parsing + CSS-selector DOM queries (pulls `html5ever` transitively) | ISC |
| `ammonia` | `4.1.2` | Allowlist HTML sanitization | MIT OR Apache-2.0 |
| `linkify` | `0.10.0` | URL extraction from anchor text and body text | MIT OR Apache-2.0 |
| `idna` | `1.1.0` | Punycode / IDN conversion | MIT OR Apache-2.0 |
| `addr` | `0.15.6` | Registrable-domain (PSL-aware) parsing | MIT OR Apache-2.0 |
| `unicode-script` | `0.5.8` | UAX #24 Script / Script_Extension lookup | MIT OR Apache-2.0 |
| `unicode-properties` | `0.1.4` | UAX #44 category lookups (re-added — 4a R9 removed as unused) | MIT OR Apache-2.0 |
| `phf` | `0.13.1` | Runtime side of the confusables map | MIT |
| `phf_codegen` | `0.13.1` | `build.rs`-only codegen for the confusables map | MIT |

Every new dep gets a `cargo deny check` pass at Sprint 4b's first commit with the deps added. Proc-macro deps pulled transitively (e.g. from `scraper` or `phf_codegen`) get a provenance comment in the workspace `Cargo.toml` matching the R10 `hashify` / `mail-parser` pattern. `data/confusables.txt` requires a Unicode-DFS-2016 entry in the repo's `NOTICE` file.

`html5ever` is NOT added as a direct workspace dep — it comes in transitively through `scraper`.

### 3.4 WarningCode variant delta

| Added (9) | Severity | Removed (1) |
|---|---|---|
| `HtmlHiddenContentStripped` | Adversarial | `HtmlBodyUnsanitized` |
| `HtmlLinkTextHrefMismatch` | Adversarial | |
| `HtmlScriptStripped` | Adversarial | |
| `HtmlStyleStripped` | Informational | |
| `HtmlRemoteImageStripped` | Informational | |
| `LookalikeMixedScript` | Adversarial | |
| `LookalikeHomographDomain` | Adversarial | |
| `LookalikeIdnPunycode` | Informational | |
| `LookalikeFilenameExtensionSpoof` | Adversarial | |

`WarningCode::severity()` is non-wildcarded inside `rimap-content` (per 4a R8), so omitting any of the nine fails compilation.

### 3.5 Build-time shape

`build.rs` parses `data/confusables.txt` (TR39 "MA" rows → skeleton mappings), constructs a `phf_codegen::Map<char, &'static str>`, and writes to `$OUT_DIR/confusables.rs`. `lookalike.rs` `include!`s it. `build.rs` stays under ~100 lines; the workspace `panic!` lint is disabled for `build.rs` only via a crate-level attribute, so IO failure surfaces as a build error rather than swallowed. A unit test in `lookalike` spot-checks the map (e.g. Cyrillic `а` (U+0430) → Latin `a`) to ensure the build.rs output is non-empty and correct.

## 4. `html` module

### 4.1 Public surface

```rust
// crates/rimap-content/src/html.rs

pub(crate) struct HtmlResult {
    /// Plain text extracted from the HTML, already run through `unicode::sanitize`.
    pub body_text: String,
    /// Ammonia-sanitized HTML (default allowlist minus remote content).
    pub body_html: String,
    /// Anchor hrefs surviving sanitization, as owned strings. Consumed by `lookalike::audit`.
    pub anchor_hrefs: Vec<String>,
    /// Warnings produced during parse, detection, and sanitization.
    pub warnings: Vec<SecurityWarning>,
}

pub(crate) fn process(raw: &[u8]) -> Result<HtmlResult, ContentError>;
```

`process` is the only entrypoint. Everything else is module-private.

### 4.2 Pipeline stages

```text
process(raw)
  1. size gate                        → LimitExceeded if raw.len() > MAX_HTML_BYTES
  2. unicode::decode(raw)              → String (charset detection, lossy on invalid)
  3. scraper::Html::parse_document     → Html
  4. detect_hidden(&html)              → Vec<HiddenHit>  → HtmlHiddenContentStripped
  5. detect_mismatches(&html)          → Vec<MismatchHit> → HtmlLinkTextHrefMismatch
  6. extract_text(&html, &hidden)      → String → unicode::sanitize → body_text
  7. ammonia_clean(&decoded)           → body_html (via LazyLock<Builder>)
                                        + HtmlRemoteImageStripped, HtmlScriptStripped,
                                          HtmlStyleStripped (detected via pre-scan count delta)
  8. re-parse body_html → collect <a href> → anchor_hrefs
  9. assemble HtmlResult
```

### 4.3 Hidden-element detection (step 4)

Inline-style only. Scans every descendant of `<body>` (or the document root if no body) and checks the element's `style=""` attribute value for:

- `display: none`
- `visibility: hidden`
- `opacity: 0` or `opacity: 0.0`
- `position: absolute|fixed` combined with `left|top` < `-1000px`
- `font-size: 0` (with any unit)
- `color` and `background-color` that parse to the same CSS color

Each hit contributes one `HiddenHit`. After `MAX_HIDDEN_HITS = 64` hits, further hits increment a counter only; the warning is summarized with `detail = "method=mixed,additional_hits=N"`.

Substring/regex matching over the `style` value is acceptable — we do not need a full CSS parser for inline styles. The parser is a small hand-rolled `split(';')` loop that normalizes whitespace and lowercases property names.

Elements with any hit are recorded in a `HashSet<ElementId>` that `extract_text` (step 6) consults so hidden text is excluded from `body_text`.

### 4.4 Href-mismatch detection (step 5)

For every `a[href]` element:

1. Collect anchor text via `element.text().collect::<String>()`, truncated to `MAX_ANCHOR_TEXT_SCAN = 4 KiB`.
2. Run the text through `linkify::LinkFinder::new().links(&text).next()` to get the first URL-ish token.
3. If no URL token, no warning.
4. Parse both the href and the extracted URL with `addr::parse_domain_name`. If either fails, no warning (silent skip).
5. Compare registrable domains, case-insensitive, after `idna::Uts46::to_ascii` on both.
6. If they differ, emit `HtmlLinkTextHrefMismatch` with `detail = "text_domain=<ascii>,href_domain=<ascii>"`.

Never emits for:
- Empty href.
- Relative href (no scheme).
- `mailto:` or `tel:` href.
- Anchor text with no URL-like token ("click here", "read more", button labels).

### 4.5 Text extraction (step 6)

Tree-order walk of the document:

- Skip `<script>`, `<style>`, `<head>` and their descendants.
- Skip any element in the hidden set from step 4.
- Collect text nodes, normalize whitespace (collapse runs of space/tab/newline to single space), join, and pass the final string through `unicode::sanitize`.

### 4.6 Ammonia sanitization (step 7)

`AMMONIA_BUILDER: LazyLock<ammonia::Builder<'static>>` constructed once at module load via a private `build_ammonia_builder()` helper (~30 lines, independently unit-testable).

Builder config:

- `url_schemes`: `{"http", "https", "mailto", "tel"}` (drops `javascript:`, `data:`, `file:`, etc.)
- `tag_attributes` for `img`: `{"alt", "width", "height"}` only (strips `src`, `srcset`, `data-*`, `loading`, `decoding`)
- Relies on ammonia's default tag allowlist (which includes `img`) and default attribute-stripping of event handlers (`on*`), scripts, styles, and frame elements. The exact set of tags stripped by default is pinned against ammonia 4.1.2's documented defaults at plan-writing time, not assumed here.

Warning emission after sanitize:

- **`HtmlScriptStripped` / `HtmlStyleStripped`**: count `<script>` / `<style>` elements in the pre-sanitize document (already parsed in step 3). Non-zero → emit with `detail = "count=N"`.
- **`HtmlRemoteImageStripped`**: count `<img>` elements with a non-empty `src` in the pre-sanitize document. Non-zero → emit with `detail = "count=N"`.

### 4.7 Compiled state

```rust
static SEL_ANCHOR: LazyLock<Selector> = LazyLock::new(|| compile_selector("a[href]"));
static SEL_IMG: LazyLock<Selector>    = LazyLock::new(|| compile_selector("img"));
static SEL_SCRIPT: LazyLock<Selector> = LazyLock::new(|| compile_selector("script"));
static SEL_STYLE: LazyLock<Selector>  = LazyLock::new(|| compile_selector("style"));
static AMMONIA_BUILDER: LazyLock<Builder<'static>> = LazyLock::new(build_ammonia_builder);
```

`compile_selector` is a tiny private helper wrapping `Selector::parse(...).expect(...)` with a single `#[expect(clippy::expect_used, reason = "const CSS selector, cannot fail at runtime")]`, avoiding per-site lint suppressions.

### 4.8 Constants

```rust
const MAX_HTML_BYTES: usize       = 1 * 1024 * 1024;  // 1 MiB, matches MAX_BODY_BYTES
const MAX_ANCHOR_TEXT_SCAN: usize = 4 * 1024;
const MAX_HIDDEN_HITS: usize      = 64;
const MAX_MISMATCH_HITS: usize    = 32;
```

## 5. `lookalike` module

### 5.1 Public surface

```rust
// crates/rimap-content/src/lookalike.rs

pub(crate) struct LookalikeInput<'a> {
    pub meta: &'a ContentMeta,
    pub body_text: &'a str,
    pub anchor_hrefs: &'a [String],
    pub attachments: &'a [AttachmentMeta],
}

pub(crate) fn audit(input: LookalikeInput<'_>) -> Vec<SecurityWarning>;
```

### 5.2 Passes

`audit` runs three independent, individually testable passes that each consume a shared `classify_domain` helper. A fourth concern (bidi-pre-strip) lives outside `lookalike` entirely.

1. **`scan_header_domains`** — iterate `meta.from/to/cc/reply_to` addresses, extract each domain, run through `classify_domain`. Location: `"header:<name>"`.
2. **`scan_anchor_hrefs`** — run `classify_domain` over each href's domain. Location: `"html:anchor"`.
3. **`scan_body_urls`** — linkify `body_text` (capped at `MAX_LINKIFY_SCAN_BYTES = 64 KiB`) for URL tokens, extract domains, classify. Location: `"body_text"`.

**`classify_domain`** — private helper, not a top-level pass. Signature: `&str` → `DomainClassification`. Runs `idna::Uts46::to_ascii` / `to_unicode`, computes the TR39 skeleton via the compiled `phf` map, and runs a TR39 Highly Restrictive mixed-script check via `unicode-script`. Silent skip on invalid-domain input. The only place that touches `idna`, `addr`, `unicode-script`, and the confusables map.

**Bidi-pre-strip detection lives outside `lookalike`.** By the time `audit` runs, bidi characters have already been removed by `unicode::sanitize`. The only clean place to detect them is at the sanitize call site, so emission of `LookalikeFilenameExtensionSpoof` and `LookalikeHomographDomain{reason=bidi_pre_strip}` lives in `parse.rs`: `parse::sanitize_filename` (already exists from 4a R2) gains the filename-extension check, and a new helper emits the domain-strip warning when header domain strings lose bidi characters during sanitize. The variants are still defined in `output.rs`; only their emission site is outside `lookalike`.

### 5.3 Detail format

Domains in `detail` strings are always punycode (ASCII) to prevent bidi/homograph characters from leaking into log output and spoofing the log line itself. U-labels appear only in explicit `ulabel=<unicode>` keys.

| Variant | `detail` format |
|---|---|
| `HtmlHiddenContentStripped` | `"method=<reason>"` + optional `count=N` |
| `HtmlLinkTextHrefMismatch` | `"text_domain=<ascii>,href_domain=<ascii>"` |
| `HtmlScriptStripped` | `"count=N"` |
| `HtmlStyleStripped` | `"count=N"` |
| `HtmlRemoteImageStripped` | `"count=N"` |
| `LookalikeMixedScript` | `"domain=<punycode>,scripts=<S1+S2>"` |
| `LookalikeHomographDomain` | `"domain=<punycode>,skeleton_match=<other_punycode>"` or `"domain=<punycode>,reason=bidi_pre_strip"` |
| `LookalikeIdnPunycode` | `"domain=<punycode>,ulabel=<unicode>"` |
| `LookalikeFilenameExtensionSpoof` | `"visible=<after_strip>,declared=<original>"` |

## 6. `parse` integration

### 6.1 `extract_bodies` changes

The `PartType::Html(_) => HtmlBodyUnsanitized` arm is replaced with a call to `html::process`. Only the `message.html_body`-designated first HTML part is processed; alternate HTML parts flow to `alternate_parts` metadata (same shape as alternate text). `ContentError::LimitExceeded` is converted to a `ParseBodyTruncated` warning with `location = "body:html"` (new string constant, matching 4a's existing `location` shape). `ContentError::Malformed` and `ContentError::Decoding` bubble up to the `parse_message` caller.

If `body_text` from the text parts is empty, the HTML-derived text becomes the primary `body_text`. If both are present, the HTML-derived text goes to `alternate_parts` and the plain-text stays primary.

`body_html` is NOT counted against `MAX_TOTAL_BODY_BYTES`. The R4 aggregate cap defends `body_text + alternate_parts` against multipart bombs; counting `body_html` would double-charge the same source bytes and effectively halve the html budget.

### 6.2 `parse_message` changes

`extract_bodies` threads an internal-only `html_anchor_hrefs: Option<Vec<String>>` return field (not part of `Untrusted`'s public shape). After `Untrusted` is assembled but before returning, `parse_message` calls:

```rust
let lookalike_warnings = lookalike::audit(LookalikeInput {
    meta: &content.meta,
    body_text: &content.body_text,
    anchor_hrefs: html_anchor_hrefs.as_deref().unwrap_or(&[]),
    attachments: &content.attachments,
});
warnings.extend(lookalike_warnings);
```

### 6.3 `Untrusted` public shape change

One additive field: `pub body_html: Option<String>`. All existing `insta` snapshots regenerate because adding a serialized field changes every snapshot's byte output (messages with no HTML part gain a `body_html: None` line; messages with an HTML part gain the sanitized HTML string). This is a mechanical `cargo insta accept` pass run once after the field lands, not manual edits.

## 7. Error handling

Error model unchanged from 4a: `ContentError` stays `Malformed | LimitExceeded | Decoding`. Sprint 4b behaviors:

| Failure | Outcome |
|---|---|
| HTML body > `MAX_HTML_BYTES` | `LimitExceeded` → `ParseBodyTruncated` warning at `"body:html"` (non-fatal) |
| Charset decoding rejects html bytes | `Decoding` → bubbles up (fatal) |
| scraper parses to empty tree | `HtmlResult` with empty fields, no warning, no error |
| `Selector::parse` on const string | Impossible; wrapped in `compile_selector` helper with single scoped `expect` |
| `ammonia::clean` | Cannot panic on valid UTF-8 (ammonia guarantees); no `catch_unwind` |
| `idna::Uts46::to_ascii` on malformed domain | `Err` → silent skip; no warning |
| `addr::parse_domain_name` failure | Silent skip; no warning |
| Confusables map miss | Silent fallback (char maps to itself) |
| `build.rs` cannot read `confusables.txt` | Build fails loudly via `panic!` (build.rs is exempt from workspace panic lint) |

## 8. Testing strategy

Target delta: ~55 new tests, ~430 workspace total.

### 8.1 Unit tests

- **`html`**: 18 tests covering empty input, each hidden-detection method, href-mismatch fires and no-fires, img src stripping with alt preservation, `javascript:` URL stripping, size limit, hidden-hit cap summarization, empty-body document.
- **`lookalike`**: 14 tests covering pure Latin, pure Cyrillic (single-script OK), Latin+Cyrillic mixed-script, TR39 Highly Restrictive Latin+Han / Latin+Hiragana allowed, homograph skeleton match, IDN punycode informational, per-pass scans (headers, anchors, body URLs), `MAX_LINKIFY_SCAN_BYTES` enforcement, clean multilingual zero-warning regression, invalid-domain silent skip, confusables-map spot check.
- **`parse` wiring**: 3 tests covering HTML-only message populates both `body_text` and `body_html`, HTML-limit-exceeded emits truncated warning, alternate HTML part does not double-process.

### 8.2 Corpus fixtures and snapshots

9 new fixtures under `tests/injection-corpus/` (CRLF-encoded via `python3 -c ... .encode('utf-8')`, never heredoc), each with an accompanying `insta` snapshot:

| # | Fixture | Primary warning(s) |
|---|---|---|
| 1 | `html-white-on-white/` | `HtmlHiddenContentStripped{method=color_match}` |
| 2 | `html-display-none/` | `HtmlHiddenContentStripped{method=display_none}` |
| 3 | `html-text-href-mismatch/` | `HtmlLinkTextHrefMismatch` |
| 4 | `html-remote-image-tracker/` | `HtmlRemoteImageStripped` |
| 5 | `html-script-payload/` | `HtmlScriptStripped` |
| 6 | `lookalike-homograph-paypal/` | `LookalikeHomographDomain` + `LookalikeMixedScript` (co-occur on the classic Cyrillic-`а` attack) |
| 7 | `lookalike-idn-positive/` | zero warnings (`münchen.de` sender, negative-case regression) |
| 8 | `lookalike-idn-punycode/` | `LookalikeIdnPunycode` (informational) |
| 9 | `lookalike-filename-rlo-bidi/` | `LookalikeFilenameExtensionSpoof` |

Existing fixtures inherit the pre-commit exclude rules landed in 4a — no `.pre-commit-config.yaml` changes. The `html-only-hidden-instructions` 4a corpus fixture's snapshot regenerates with real extracted text and warnings (replacing the R3 `HtmlBodyUnsanitized`-only snapshot).

### 8.3 Proptest properties

3 new properties at 10,000 cases each (projected `just ci` wall-clock ~27s, still under the 60s test-split threshold):

1. **`html_process_terminates_on_arbitrary_utf8`** — arbitrary UTF-8 input capped at `MAX_HTML_BYTES`; asserts `process` returns `Ok` or `Err(LimitExceeded)`, never panics, never hangs.
2. **`sanitized_body_html_re_parses_cleanly`** — feed `body_html` output back through `Html::parse_document`; assert no `<script>`, `<style>`, `javascript:`, or `data:` href survives the round-trip.
3. **`classify_domain_no_panic_on_arbitrary_unicode`** — arbitrary printable Unicode ≤ 253 bytes; assert `classify_domain` returns without panicking.

### 8.4 `cargo-mutants` full-crate gate

Terminal Sprint 4b task. Runs after all other work is green:

```bash
cargo mutants --package rimap-content --timeout 120
```

Target: ≥ 80% mutant kill rate. Surviving mutants are documented in `docs/superpowers/mutants-survivors.md` with rationale. Expected acceptable survivor categories:

- Log message / detail string content mutations (tests rarely assert on exact text format).
- Hit-cap boundary off-by-ones where the test only exercises the cap value itself.

Unacceptable survivor categories (must be fixed):

- Severity classification flips (Adversarial ↔ Informational).
- Warning variant emission flips (emit ↔ no-emit for a documented attack).
- Silent-skip vs. warn decisions in `classify_domain`.

## 9. Out of scope

Explicitly deferred from Sprint 4b:

- `<style>` block class/id resolution (Q2 deferred; module designed for layering).
- Runtime-configurable limits (still compile-time `const`).
- Recursive `message/rfc822` parsing (still deferred from 4a).
- `criterion` benchmarks.
- Differential HTML parser oracles.
- `cargo-fuzz` runs.
- Sprint 5 posture rules that consume `WarningCode::severity()`.
- Sprint 5 tool-handler prompt templating (header-newline escaping is a Sprint 5 concern; the post-merge handoff note stays in the 4b-handoff doc verbatim).

## 10. Suggested task order (mirrors handoff, refined)

1. Branch `feat/sprint-4b-content` + workspace deps + `cargo deny` license review.
2. Vendor `data/confusables.txt` + `build.rs` + `phf_codegen` scaffolding + map-size sanity test.
3. `WarningCode` variant additions (9) + deletion (1) + `severity()` classification.
4. `html` module skeleton: `process` stub, `HtmlResult`, constants, `LazyLock` statics, `compile_selector` helper.
5. `html` module stage 1–3 (size gate, decode, scraper parse) + unit tests for empty / oversize / basic parse.
6. `html` module stage 4 (hidden detection) + unit tests per detection method.
7. `html` module stage 5 (href mismatch) + unit tests for fires / no-fires.
8. `html` module stage 6 (text extraction) + unit tests.
9. `html` module stage 7 (ammonia sanitize) + `build_ammonia_builder` unit tests + stripped-warning detection.
10. `html` module stage 8 (anchor-href re-parse collection) + assembly + wiring unit tests.
11. `parse::extract_bodies` integration: delete `HtmlBodyUnsanitized` arm, call `html::process`, handle `LimitExceeded` → `ParseBodyTruncated`, `body_html` field plumbing. Regenerate existing snapshots.
12. `Untrusted.body_html` public field + output.rs snapshot regen.
13. `lookalike` module skeleton: `LookalikeInput`, `audit`, `classify_domain` stub.
14. `lookalike::classify_domain`: idna, mixed-script, skeleton, IDN punycode logic + unit tests.
15. `lookalike` passes 1–3 (headers, anchors, body URLs) + unit tests.
16. `parse::parse_message` wiring: call `lookalike::audit`, thread anchor hrefs through.
17. Bidi-pre-strip detection moved into `parse::sanitize_filename` and a new domain-prestrip helper; emit `LookalikeFilenameExtensionSpoof` / `LookalikeHomographDomain{reason=bidi_pre_strip}`.
18. 9 corpus fixtures + insta snapshots.
19. 3 proptest properties at 10k cases each.
20. Full-crate `cargo-mutants` run + survivor documentation.
21. Sprint 4b → Sprint 5 handoff doc.

## 11. Ground rules (inherited from 4a)

- Never commit on `main`. All work on `feat/sprint-4b-content`.
- `just ci` must pass locally before each push. Inner loop: `just check` / `just test` / `just lint`.
- Workspace lints deny `unwrap_used`, `panic`, `print_stdout`/`stderr`, `dbg`, `todo`, `unimplemented`. Test modules opt out with `#[expect(clippy::unwrap_used, reason = "...")]` only where they actually call `.unwrap()`.
- `#![deny(missing_docs)]` — every public item needs a Google-style doc comment.
- Functions ≤100 lines, cyclomatic complexity ≤8, 100-char lines, absolute imports only.
- `.eml` corpus fixtures use CRLF line endings; write via `python3 -c` + `.encode('utf-8')`.
- Dependencies declared once in workspace root `[workspace.dependencies]`; members inherit with `{ workspace = true }`.
- Commit messages end with `Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>`.
- Never rewrite pushed commits.
