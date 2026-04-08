# Sprint 4a — Content pipeline foundation (parse + unicode + output)

**Status:** Design approved 2026-04-08
**Branch:** `feat/sprint-4a-content`
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](./2026-04-07-rusty-imap-mcp-design.md) §Sprint 4 (lines 1228–1249) and §Sprint 4 adversarial corpus (lines 1097–1128)
**Scope:** First half of the parent spec's Sprint 4. HTML sanitization and look-alike detection are deferred to Sprint 4b.

## Goal

Land the foundation of `rimap-content`: MIME parsing, Unicode-safe sanitization, a `Content` output type, and an adversarial fixture harness — sufficient that Sprint 5 `rimap-server` tool handlers could call `rimap-content::parse(&raw_rfc822)` and receive a `Content` struct with `meta`, `untrusted`, and `security_warnings` populated for every non-HTML attack class in the seeded corpus.

Sprint 4b extends this with `html` sanitization, `lookalike` detection, remaining corpus fixtures, and the `cargo-mutants ≥ 80%` gate against the completed crate.

## Non-goals

- HTML-to-text conversion, `ammonia` sanitization, hidden-element detection (4b).
- Mixed-script / TR39 skeleton / punycode / IDN / confusables (4b).
- Any integration with `rimap-imap`, `rimap-server`, or network I/O. The crate MUST build and test with zero network/IMAP dependencies.
- Tool handlers or MCP wiring (Sprint 5).
- Mutation testing gate (4b runs once against the full crate).

## Architecture

### Crate layout

```
crates/rimap-content/
├── Cargo.toml
├── src/
│   ├── lib.rs       -- crate docs, public re-exports
│   ├── output.rs    -- Content, SecurityWarning, WarningCode
│   ├── unicode.rs   -- pure decode → NFKC → filter → bound pipeline
│   ├── parse.rs     -- mail-parser wrapper, MIME walk, limits
│   └── error.rs     -- ContentError via thiserror
└── tests/
    ├── corpus.rs       -- fixture loader + assertion runner
    └── properties.rs   -- proptest properties
```

### Module boundaries

- **`unicode`** is pure. No I/O, no `mail-parser` types, no `Content`. Inputs are `&[u8]` or `&str`; outputs are owned `String`. Every public function is synchronous and deterministic. This is the load-bearing module — every other consumer of untrusted text routes through it.
- **`parse`** owns all `mail-parser` contact. No other module imports `mail-parser` types. It calls into `unicode` to sanitize every header value and body text part it extracts.
- **`output`** declares `Content`, `SecurityWarning`, and `WarningCode`. `WarningCode` is `#[non_exhaustive]` so Sprint 4b can add HTML and look-alike variants without breaking callers.
- **`error`** declares `ContentError` via `thiserror`. Variants cover parse failure, limit exceeded, and decoding failure. Callers receive `Result<Content, ContentError>` from the crate's single top-level entrypoint.

Per the parent spec's hard limit (100 lines/function, cyclomatic complexity ≤ 8), `parse` in particular will need helper functions for the MIME walk — budget for 4–6 private helpers rather than one monolithic walker.

### Public API surface (Sprint 4a)

```rust
// lib.rs re-exports
pub use output::{Content, SecurityWarning, WarningCode, ContentMeta, Untrusted};
pub use error::ContentError;

// Top-level entrypoint
pub fn parse_message(raw: &[u8]) -> Result<Content, ContentError>;
```

Sprint 4b will add `parse_message_with_html` (or an options struct) when the HTML pipeline lands. Sprint 4a deliberately does not expose options — the default limits are `const` and callers have no knobs yet.

### The `Content` type

```rust
#[non_exhaustive]
pub struct Content {
    pub meta: ContentMeta,
    pub untrusted: Untrusted,
    pub security_warnings: Vec<SecurityWarning>,
}

#[non_exhaustive]
pub struct ContentMeta {
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: Option<String>,
    pub date: Option<time::OffsetDateTime>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub mailing_list: Option<MailingListInfo>,
    pub attachments: Vec<AttachmentMeta>,
    pub original_size_bytes: u64,
    pub body_truncated: bool,
}

#[non_exhaustive]
pub struct Untrusted {
    pub body_text: String,       // the primary text/plain part, post-unicode-sanitization
    pub alternate_parts: Vec<String>, // other text/* parts, also sanitized
}

#[non_exhaustive]
pub struct SecurityWarning {
    pub code: WarningCode,
    pub detail: Option<String>,  // short human-readable context
    pub location: Option<String>, // e.g., "header:subject", "body:part[2]"
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningCode {
    // Sprint 4a
    UnicodeZeroWidthStripped,
    UnicodeBidiOverrideStripped,
    UnicodeC0C1Stripped,
    ParseHeaderSmugglingBlocked,
    ParseMimeTypeMismatch,
    ParseBodyTruncated,
    ParseMimeDepthExceeded,
    ParseMimePartCountExceeded,
    ParseHeaderCountExceeded,
    // Sprint 4b will add: HtmlHiddenContentStripped, HtmlLinkTextHrefMismatch,
    // LookalikeMixedScript, LookalikeHomographDomain, LookalikeIdnPunycode, ...
}
```

Field and variant names are proposals — reviewers can bikeshed during commit 2. The shape (three top-level regions: `meta` / `untrusted` / `security_warnings`) is from the parent spec and is non-negotiable.

### The `unicode` pipeline

Pure functions, composable, each independently testable:

1. **`decode(bytes, charset)`** — `encoding_rs` decode to `String`. Unknown/missing charset falls back to UTF-8 with replacement characters.
2. **`normalize_nfkc(s)`** — `unicode_normalization::UnicodeNormalization::nfkc(s)`.
3. **`filter_codepoints(s)`** — strips disallowed codepoints. Strip set:
   - Zero-width: U+200B, U+200C, U+200D, U+FEFF, U+2060
   - Bidi overrides: U+202A–U+202E, U+2066–U+2069
   - C0 controls except `\t` (U+0009) and `\n` (U+000A)
   - C1 controls (U+0080–U+009F)
   - Other format characters in Unicode category `Cf` except those explicitly allowed
   Each stripped codepoint class produces a distinct `WarningCode`.
4. **`normalize_line_endings(s)`** — `\r\n` → `\n`, bare `\r` → `\n`.
5. **`truncate_graphemes(s, max_bytes)`** — truncate at a grapheme-cluster boundary ≤ `max_bytes`. Uses `unicode-segmentation`.

A single public `sanitize(bytes, charset, max_bytes) -> (String, Vec<SecurityWarning>)` composes the pipeline and returns the sanitized string plus the warnings accumulated along the way.

### The `parse` pipeline

`parse_message(raw)` flow:

1. Record `original_size_bytes = raw.len()`.
2. Enforce `raw.len() ≤ MAX_MESSAGE_BYTES`; if exceeded, truncate and emit `ParseBodyTruncated`.
3. Pre-parse header scan: detect any raw CRLF inside an RFC 2047 encoded-word. The offending header line is dropped from the byte stream before the rest is handed to `mail-parser`, and `ParseHeaderSmugglingBlocked` is recorded to surface on the returned `Content`. This runs BEFORE `mail-parser` because `mail-parser` may transparently reassemble headers and hide the smuggling attempt. Risk flagged in Section "Risks" below.
4. `mail-parser::MessageParser::default().parse(raw)` → `Message`.
5. Extract headers into `ContentMeta`. Every header string is run through `unicode::sanitize` with a header-appropriate byte cap. RFC 2047 decoding is handled by `mail-parser`; we still NFKC-normalize the output.
6. Walk the MIME tree depth-first, enforcing `MAX_MIME_DEPTH` and `MAX_MIME_PARTS`. Emit `ParseMimeDepthExceeded` / `ParseMimePartCountExceeded` on violation and reject (return `Err`).
7. Select the primary `text/plain` part (per RFC 2046 multipart/alternative rules) → `untrusted.body_text`. Sanitize via `unicode::sanitize` with `MAX_BODY_BYTES`. Other `text/*` parts → `alternate_parts`, same treatment.
8. Walk attachments: capture `AttachmentMeta` (filename, content-type, size, content-id, is-inline). If the declared content-type doesn't match the magic-byte sniff of the first N bytes, emit `ParseMimeTypeMismatch`. (Magic-byte sniff uses a small hand-rolled table for common types — image/png, image/jpeg, image/gif, application/pdf, application/zip, MZ-exe. No new dep; extends in 4b if needed.)
9. `message/rfc822` attachments surface as `AttachmentMeta` but their inner body is NOT recursively parsed in 4a — the metadata records `content_type = "message/rfc822"` and `size = <inner bytes>`. A nested parse pass is deferred (noted in the handoff doc).
10. Extract `List-*` headers into `MailingListInfo` if present.
11. Return `Content`.

### Hard limits (compile-time `const`)

```rust
const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;   // 25 MiB
const MAX_BODY_BYTES: usize = 1 * 1024 * 1024;       // 1 MiB per text part post-sanitize
const MAX_HEADER_BYTES: usize = 8 * 1024;            // 8 KiB per header value post-sanitize
const MAX_MIME_DEPTH: usize = 8;
const MAX_MIME_PARTS: usize = 100;
const MAX_HEADER_COUNT: usize = 256;
```

Values are starting points informed by industry norms (Gmail rejects >25 MiB; most mail fits under 1 MiB of text). Reviewers can tune during implementation. Promotion to runtime config is deferred to Sprint 5 if the MCP server needs posture-dependent limits.

### Dependencies

Added to workspace root `[workspace.dependencies]`, inherited by `crates/rimap-content/Cargo.toml`:

| crate | purpose | license check |
|---|---|---|
| `mail-parser` | MIME/RFC 5322 parsing | to verify in commit 1 |
| `encoding_rs` | charset decoding | Apache-2.0 OR MIT (already in deny allowlist) |
| `unicode-normalization` | NFKC | Apache-2.0 OR MIT |
| `unicode-segmentation` | grapheme clusters | Apache-2.0 OR MIT |
| `unicode-properties` | codepoint category lookup for strip filter | Apache-2.0 OR MIT |

Dev-deps on `rimap-content`:

| crate | purpose |
|---|---|
| `proptest` | property tests (already workspace dep) |
| `insta` | snapshot tests (new dev-dep, workspace-shared) |
| `serde_json` | fixture `expected.json` loader (already workspace dep) |

The `cargo deny` license delta is reviewed in commit 1; any additions to `deny.toml` carry an inline justification.

## Testing

### Adversarial corpus

Location: **repo-root** `tests/injection-corpus/` (deviation from per-crate convention, spec'd in parent doc line 1099; allows Sprint 5 `rimap-server` tests to replay the same fixtures without path gymnastics).

Each fixture is a directory:

```
tests/injection-corpus/
└── <fixture-name>/
    ├── input.eml
    └── expected.json
```

`expected.json` schema (enforced by the fixture loader in `crates/rimap-content/tests/corpus.rs`):

```json
{
  "description": "human-readable purpose of the fixture",
  "expect": "ok",
  "must_contain": ["substrings required in Content.untrusted.body_text"],
  "must_not_contain": ["substrings forbidden in Content.untrusted.body_text"],
  "warning_codes": ["codes that MUST appear in Content.security_warnings"],
  "forbidden_warning_codes": ["codes that MUST NOT appear"],
  "meta": {
    "mailing_list_present": false,
    "attachment_count": 0,
    "body_truncated": false
  }
}
```

Or for fixtures that must be rejected outright:

```json
{
  "description": "human-readable purpose of the fixture",
  "expect": "error",
  "error_kind": "LimitExceeded"
}
```

The `expect` field is required and is either `"ok"` (all other assertion fields apply to the returned `Content`) or `"error"` (only `error_kind` applies, matched against the `ContentError` variant name). Unknown top-level keys in `expected.json` are rejected (fail the test) to prevent silent typos.

**Sprint 4a fixtures seeded (10 total):**

| # | Fixture | Asserts |
|---|---|---|
| 1 | `prompt-injection-plaintext/` | "ignore previous instructions" body passes through to `untrusted.body_text` intact, zero security warnings (content, not an attack on the pipeline) |
| 2 | `zero-width-poisoning/` | U+200B/200C/200D/FEFF in subject and body stripped; `UnicodeZeroWidthStripped` emitted (at least twice, one per location) |
| 3 | `trojan-source-bidi/` | RLO/LRO/PDI stripped; `UnicodeBidiOverrideStripped` emitted |
| 4 | `rfc2047-crlf-smuggling/` | Encoded-word containing raw CRLF: the smuggled header is dropped, `ParseHeaderSmugglingBlocked` emitted, parse returns `Ok(Content)` with the surviving message intact so downstream tools can still see legitimate headers |
| 5 | `mime-type-spoofing/` | MZ-exe bytes declared `image/png`; `ParseMimeTypeMismatch` emitted with attachment location |
| 6 | `oversized-body/` | Body > `MAX_BODY_BYTES`; `ParseBodyTruncated` emitted; `Content.meta.body_truncated == true`; `original_size_bytes` preserves pre-truncation length |
| 7 | `multipart-bomb/` | MIME depth > `MAX_MIME_DEPTH`; parse returns `Err(ContentError::LimitExceeded { .. })`; fixture uses `"expect": "error"` with `"error_kind": "LimitExceeded"` |
| 8 | `nested-rfc822/` | `message/rfc822` attachment surfaces in `meta.attachments` with correct content-type and size; inner body NOT parsed recursively |
| 9 | `mailing-list/` | `List-ID` / `List-Unsubscribe` populate `ContentMeta.mailing_list`; zero spurious warnings |
| 10 | `multilingual-negative/` | Japanese + Hebrew + Arabic + German-umlaut content in separate sub-fixtures or one combined fixture; **zero** warnings; body round-trips byte-for-byte after NFKC |

Fixture #10 may expand to 4 separate fixtures if one combined fixture becomes unreadable.

### Proptest properties (≥10,000 cases each)

In `crates/rimap-content/tests/properties.rs` with `ProptestConfig::with_cases(10_000)`:

1. **`nfkc_stable`** — for any `String s`, `unicode::normalize_nfkc(unicode::normalize_nfkc(&s)) == unicode::normalize_nfkc(&s)`.
2. **`no_stripped_codepoints_in_output`** — for any input, the output of `unicode::filter_codepoints` contains no codepoint in the strip set.
3. **`no_c0_c1_controls_except_tab_newline`** — for any input, the output contains no byte in C0 (0x00–0x1F) except `\t` (0x09) and `\n` (0x0A), and no byte in C1 (0x80–0x9F).
4. **`utf8_preserved`** — for any `Vec<u8>` input to `unicode::decode`, the output is valid UTF-8.
5. **`grapheme_truncation_preserves_cluster_boundary`** — for any `String s` and `max_bytes`, `unicode::truncate_graphemes(&s, max_bytes)` returns a prefix whose byte length ≤ `max_bytes` and whose final grapheme cluster is not split.

Shrinking enabled on all properties so failures report minimal counterexamples.

### Insta snapshots

`cargo insta` captures the full `Content` struct serialized as JSON for each corpus fixture. Committed under `crates/rimap-content/tests/snapshots/`. Any sanitizer behavior change produces a visible snapshot diff that must be reviewed before merge.

### Unit tests

Colocated `#[cfg(test)]` blocks per module cover narrow edges not worth a fixture: empty input, single-byte input, exactly-at-limit inputs, boundary codepoints. Not a substitute for corpus/proptest — a supplement.

### CI impact

Proptest at 10,000 cases × 5 properties will add measurable wall-clock to `just test`. Plan:

1. Measure on first full run (commit 7).
2. If `just ci` exceeds a tolerable bar, split: `just test` runs proptest at 1,000 cases (fast inner loop), `just test-slow` runs at 10,000 cases, `just ci` invokes `test-slow`.
3. If CI still balloons unacceptably, escalate to the user before merging.

## Commit sequence

Branch: `feat/sprint-4a-content` off `main`. One PR at the end. Each commit leaves `just ci` green and is independently reviewable.

| # | Commit subject | Deliverable |
|---|---|---|
| 1 | `chore(deps): add mail-parser, encoding_rs, unicode-* to workspace` | Workspace dep entries, `rimap-content/Cargo.toml` inheritance, `cargo deny check` delta reviewed, license additions to `deny.toml` documented |
| 2 | `feat(content): output types (Content, SecurityWarning, WarningCode)` | `output.rs`, `error.rs`, `lib.rs` re-exports, Google-style docstrings, `#[non_exhaustive]` everywhere, unit tests for construction |
| 3 | `feat(content): unicode pipeline (decode → NFKC → filter → bounds)` | `unicode.rs` pure functions, inline unit tests for edge cases, `nfkc_stable` proptest at 1,000 cases as a smoke test (full 10k lands in commit 7) |
| 4 | `feat(content): mail-parser wrapper with MIME walk and limits` | `parse.rs`, pre-parse CRLF header scan, RFC 2047 header decoding routed through `unicode::sanitize`, MIME walk with limits, attachment metadata with magic-byte sniff, `parse_message` public entrypoint |
| 5 | `test(content): seed adversarial corpus fixtures (10 non-HTML)` | `tests/injection-corpus/` with all 10 fixtures, `crates/rimap-content/tests/corpus.rs` loader + assertion runner, unknown-key rejection in `expected.json` |
| 6 | `test(content): insta snapshots for corpus fixtures` | `insta` added to workspace dev-deps, one snapshot per fixture committed under `crates/rimap-content/tests/snapshots/` |
| 7 | `test(content): proptest properties at 10,000 cases` | `crates/rimap-content/tests/properties.rs` with all 5 properties, `ProptestConfig::with_cases(10_000)`, `just test-slow` target introduced if wall-clock demands |
| 8 | `docs(content): sprint 4a exit notes + sprint 4b handoff` | Handoff doc under `docs/superpowers/plans/` listing: 4b scope (`html`, `lookalike`), remaining 5+ fixtures, full-crate `cargo-mutants` target, any TODOs surfaced during 4a |

## Exit criteria

- `rimap-content` builds with zero warnings; workspace lints (`unwrap_used`, `print_*`, `panic`, etc.) clean.
- `cargo clippy --all-targets --all-features -- -D warnings` green.
- `cargo fmt --check` green.
- All 10 corpus fixtures pass `must_contain` / `must_not_contain` / `warning_codes` / `forbidden_warning_codes` / `meta` assertions.
- All 5 proptest properties pass at ≥10,000 cases each.
- `insta` snapshots committed and reviewed.
- `just ci` green locally and on Ubuntu CI (macOS and Fedora follow-up per Sprint 3 pattern).
- Crate has zero network/IMAP transitive deps, verified by `cargo tree -p rimap-content` containing no `tokio`, `rustls`, `async-imap`, or `hyper`.
- 4b handoff doc committed.

## Out of scope (explicitly deferred)

- **HTML sanitization** — `html5ever`, `scraper`, `ammonia`, hidden-element detection, link-warning extraction, text/href mismatch. Sprint 4b.
- **Look-alike detection** — mixed-script, TR39 skeleton, confusables, `idna`, bidi-strip filename check. Sprint 4b.
- **Remaining corpus fixtures** — white-on-white, CSS `display:none`, homograph domains, text/href mismatch phishing, per-lookalike-code fixtures. Sprint 4b.
- **`cargo-mutants ≥ 80%`** — runs once against the full crate at end of 4b.
- **Recursive `message/rfc822` parsing** — metadata only in 4a; nested parse pass deferred (possibly Sprint 5).
- **Runtime-configurable limits** — hard-coded `const` in 4a; promoted to config if Sprint 5 needs posture-dependent limits.
- **Integration with `rimap-imap` or `rimap-server`** — crate is standalone in 4a.

## Risks

### Risk 1: `mail-parser` may hide header-smuggling attempts

`mail-parser` may transparently reassemble or decode headers in ways that obscure a raw-CRLF injection inside an RFC 2047 encoded-word. If the CRLF is stripped during parsing, we can't detect it post-parse.

**Mitigation:** run a pre-parse raw-byte header scan (a small hand-rolled header tokenizer that walks up to the first empty line) before handing bytes to `mail-parser`. Reject on CRLF inside an encoded-word. This is committed in commit 4. Coverage validated by fixture #4 (`rfc2047-crlf-smuggling/`).

### Risk 2: Proptest wall-clock

5 properties × 10,000 cases could push `just ci` past a tolerable CI budget.

**Mitigation:** measure in commit 7 and introduce `just test-slow` split if needed. If CI still balloons, escalate to the user before merging — do not silently lower the proptest count.

### Risk 3: License delta on new Unicode crates

New `unicode-*` dependencies may bring licenses not yet in the `deny.toml` allowlist.

**Mitigation:** commit 1 runs `cargo deny check` and documents any license additions inline. Block the commit if a license is not acceptable.

### Risk 4: `mail-parser` API surface may not expose what we need

`parse.rs` assumes `mail-parser` exposes per-part raw bytes, per-header raw bytes, and MIME depth traversal. If the API forces an owned/allocated intermediate form that breaks our limit enforcement, commit 4 may need to fall back to a different crate or a hand-rolled walker.

**Mitigation:** spike `mail-parser` API surface early in commit 4 before investing in the full MIME walk. If blocked, flag immediately and reassess — do not paper over with `.unwrap()` or silent fallbacks.

## References

- Parent design spec: `docs/superpowers/specs/2026-04-07-rusty-imap-mcp-design.md`
- Sprint 3 as implementation-shape reference: `docs/superpowers/plans/2026-04-07-sprint-3-imap.md`
- Workspace conventions: `AGENTS.md`
- Global Rust standards: `~/.claude/CLAUDE.md`
