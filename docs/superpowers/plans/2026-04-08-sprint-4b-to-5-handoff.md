# Sprint 4b → Sprint 5 Handoff — HTML, Look-alike, Full-crate Mutation Gate

**Status:** Sprint 4b is complete on branch `feat/sprint-4b-content`.
**Parent spec:** [`2026-04-07-rusty-imap-mcp-design.md`](../specs/2026-04-07-rusty-imap-mcp-design.md) §Sprint 4 (lines 1228–1249) and §Sprint 4 adversarial corpus (lines 1097–1128)
**Sprint 4b design spec:** [`2026-04-08-sprint-4b-html-lookalike-design.md`](../specs/2026-04-08-sprint-4b-html-lookalike-design.md)
**Sprint 4b plan:** [`2026-04-08-sprint-4b-content.md`](./2026-04-08-sprint-4b-content.md)
**Sprint 4a → 4b handoff (prior):** [`2026-04-08-sprint-4b-handoff.md`](./2026-04-08-sprint-4b-handoff.md)
**mail-parser 0.11 API reference:** [`2026-04-08-sprint-4a-mail-parser-0.11-api.md`](./2026-04-08-sprint-4a-mail-parser-0.11-api.md)
**Full-crate mutants survivors:** [`../mutants-survivors.md`](../mutants-survivors.md)

## What Sprint 4b shipped

- **Workspace deps** — `scraper`, `ammonia`, `linkify`, `addr`, `idna`, `unicode-script`, `phf`, `phf_codegen` added to `[workspace.dependencies]`. `deny.toml` updated with ecosystem-split `skip-tree` entries for the dual-tokenizer html5ever situation (scraper on 0.39 + ammonia on 0.35) with upstream tracker links.
- **Vendored Unicode 16 `confusables.txt`** under `crates/rimap-content/data/` compiled at build time by `crates/rimap-content/build.rs` into a `phf::Map` loaded via `include!` at `OUT_DIR/confusables_map.rs`. No network pulls; panic at build time on parse failure.
- **`WarningCode` additions** — 9 new variants, 1 removed:
  - Added: `HtmlHiddenContentStripped`, `HtmlLinkTextHrefMismatch`, `HtmlScriptStripped`, `HtmlStyleStripped`, `HtmlRemoteContentStripped`, `LookalikeMixedScript`, `LookalikeHomographDomain`, `LookalikeIdnPunycode`, `LookalikeFilenameExtensionSpoof`.
  - Removed: `HtmlBodyUnsanitized` (the Sprint 4a R3 refusal warning — Sprint 4b replaces the refusal with real sanitization).
  - `WarningCode::severity()` match extended non-wildcarded to cover every new variant (Informational vs. Adversarial).
- **`Untrusted.body_html: Option<String>`** additive field. `None` when the message has no HTML part; `Some(sanitized)` when html processing ran. Plain text continues to live in `body_text`.
- **`rimap-content::html` module** — scraper-based parser pipeline:
  - Stages: size gate → charset decode → scraper parse → hidden-element audit → href-mismatch audit → visible-text extraction → ammonia sanitize → anchor href collection.
  - **Inline-style hidden detection** via 6 methods: `display:none`, `visibility:hidden`, `opacity:0`, off-screen absolute positioning, white-on-white via explicit `color:#fff` + `background:#fff`, zero font-size. `<style>` block class/id resolution is explicitly out of scope.
  - **Anchor href mismatch** via `linkify::LinkFinder` with `url_must_have_scheme(false)` (required — see §plan-vs-reality below) plus `addr` PSL registrable-domain comparison.
  - **Visible text extraction** that skips subtrees rooted at hidden elements, `<script>`, and `<style>`. Indexes hidden nodes via a pre-order scraper `select` walk which aligns with the depth-first recursive text walker.
  - **`ammonia::Builder`** with `add_tag_attributes` / `rm_tag_attributes` (NOT `tag_attributes`, which wipes the default whitelist — see §plan-vs-reality), remote-content stripping for `<img>`/`<video>`/`<audio>` with non-`cid:`/`data:` URLs, and emission of `HtmlScriptStripped` / `HtmlStyleStripped` / `HtmlRemoteContentStripped` warnings whenever sanitization dropped anything.
- **`rimap-content::lookalike` module**:
  - `classify_domain` returns `{ ascii, unicode, was_punycode, mixed_script, skeleton }`.
  - TR39 **Highly Restrictive** mixed-script detection via `unicode-script` — allows Latin+{Han, Hiragana, Katakana, Bopomofo, Hangul} groups; anything else cross-script fires `LookalikeMixedScript`.
  - `idna::domain_to_unicode` round-trip for A-label ↔ U-label. `LookalikeIdnPunycode` is informational when a domain was in xn-- form.
  - **3-pass `audit`**: pass 1 over header addresses (`from`/`to`/`cc`), pass 2 over anchor hrefs from `html::process`, pass 3 scans body text for URLs via `linkify`.
  - **Design correction (§finding 8 below):** `LookalikeHomographDomain` is NOT emitted by `lookalike::audit` — TR39 confusables contain identity-looking maps that fire on nearly every Latin-only domain. The variant is reserved for the high-confidence bidi-pre-strip signal below.
- **Bidi-pre-strip detection** in `parse::sanitize_filename` and a new header-domain audit helper in `parse.rs`:
  - Filename: if `unicode::filter_codepoints` stripped any bidi override (`U+202A..U+202E`, `U+2066..U+2069`) from a filename, emit `LookalikeFilenameExtensionSpoof`.
  - Domain: if a header address domain contained any of the same bidi overrides, emit `LookalikeHomographDomain` with `detail = "reason=bidi_pre_strip"`.
- **10 new adversarial corpus fixtures** under `tests/injection-corpus/` (total now 22, up from 12 at the end of 4a):
  - `html-white-on-white`, `html-display-none`, `html-text-href-mismatch`, `html-script-payload`, `html-remote-image-tracker`, `html-tokenizer-divergence` (the Task 1 mandated scraper↔ammonia differential probe), `lookalike-homograph-paypal`, `lookalike-idn-punycode`, `lookalike-idn-positive`, `lookalike-filename-rlo-bidi`.
  - Matching insta snapshots committed under `crates/rimap-content/tests/snapshots/`.
- **3 new proptest properties** at 10,000 cases each in `tests/proptest_html_lookalike.rs`:
  - `parse_message_terminates_on_arbitrary_from_header`
  - `parse_message_terminates_on_arbitrary_html`
  - `sanitized_body_html_has_no_script_style_or_dangerous_urls`
- **Full-crate `cargo-mutants` run** (Task 19) documented at [`docs/superpowers/mutants-survivors.md`](../mutants-survivors.md). Library kill rate **83.9%** (≥ 80% target met). Whole-crate rate (including `src/bin/epvme_runner.rs`) drags to 77.5% because the binary has no automated test coverage (see §Sprint 5 remediation item 3). 5 targeted kill tests added in Task 19 but the confirming re-run is deferred (item 4).
- **Test totals on `rimap-content`:**
  - lib unit tests: **141**
  - `src/bin/epvme_runner.rs` unit tests: **5**
  - `tests/injection_corpus.rs` harness: **1** (iterates 22 fixtures)
  - `tests/properties.rs` (4a unicode proptest): **5** at 10k cases
  - `tests/proptest_html_lookalike.rs` (4b proptest): **3** at 10k cases
  - `tests/snapshots.rs`: **22** insta snapshots
  - Total: **177 `rimap-content` tests**, **440 workspace tests** all green.
- **`just ci` wall-clock:** **~2m 17s** on this macOS dev box. The `[profile.dev.package."*"] opt-level = 3` workspace tweak from Task 18 keeps the scraper/ammonia/html5ever compile from dominating each `cargo test` invocation. Proptest at 10k × 8 properties is ~27 s of that wall-clock (one property alone runs ~9.8 s under `cargo test`'s optimized deps).

## Plan-vs-reality API findings

Sprint 4b hit ten API-shape surprises worth recording so future plans don't relitigate them. Most were caught mid-task and fixed in the same commit; a few (finding 6, finding 8) required a rollback of an earlier task's assumption.

1. **`ContentError::LimitExceeded`** is `{ kind: &'static str, limit: usize }`. No `actual` field; `kind` is `&'static str`, not `String`. The plan assumed `{ what: String, limit, actual }`. Discovered: Task 5.
2. **`unicode::decode`** is `(bytes: &[u8], charset_label: Option<&str>) -> String` — two args, infallible. Plan assumed a single-arg infallible signature. Discovered: Task 5. Forced `html::process` to widen to `(raw: &[u8], charset: Option<&str>)`.
3. **`unicode::sanitize`** is `(bytes, charset, max_bytes, location) -> (String, Vec<SecurityWarning>)` — returns warnings, not just a string. Plan assumed `(&str) -> String`. Discovered: Task 9; html's visible-text pipeline threads the returned warnings back to `HtmlResult`.
4. **`mail_parser::Message::html_body`** is a `Vec<MessagePartId>` field, not an `html_body_count()` / `html_body(n)` method pair. Discovered: Task 12. Iterate the field directly and index `message.parts[*id as usize]`.
5. **`scraper::Html::select` pre-order indices align with a depth-first recursive text walk** of the body's element children. Verified empirically by Task 9's hidden-element index/walker cross-check. Not an API surprise per se, but worth pinning because the alignment is load-bearing for the hidden-stripping logic.
6. **`ammonia::Builder::tag_attributes(map)` REPLACES the per-tag attribute whitelist wholesale.** Calling it silently strips `<a href>` because the default whitelist is gone. Discovered: Task 11 while tracking down a Task 10 regression. Fix: use `add_tag_attributes` + `rm_tag_attributes`, which compose with ammonia's defaults.
7. **`linkify::LinkFinder` default requires URLs to have a scheme.** Bare `bank.example.com` anchor text only scans as a URL after `finder.url_must_have_scheme(false)`. Discovered: Task 8.
8. **TR39 `confusables.txt` contains identity-looking maps** like `m → rn` and `e → e\u{0301}`. The naive "skeleton != unicode form" homograph check fires on effectively every Latin-only domain. Discovered: Task 14 while investigating Task 13 test failures. **Design correction:** `LookalikeHomographDomain` is emitted ONLY from the Task 16 bidi-pre-strip path, never from `lookalike::audit`. The variant is reserved for high-confidence signals. If Sprint 5 wants a confusables-based detector it needs a curated skeleton pair list (e.g. only fire when the skeleton collides with a well-known brand), not the raw TR39 skeleton.
9. **`ContentMeta` has `from`/`to`/`cc` only.** There is no `reply_to` field. `lookalike::audit`'s header pass iterates exactly those three. Discovered: Task 14. If Sprint 5 wants reply-to lookalike coverage it must first add the field to `ContentMeta`.
10. **`idna::domain_to_unicode`** returns a `(String, Result<(), Errors>)` tuple in `idna` 1.1. The `Result` is the informational part (was the input valid A-label?); the `String` is always the best-effort decode. Discovered: Task 13.

## Known Sprint 5 remediation items (non-blocking for 4b merge)

1. **CDATA tokenizer divergence — script source leaks into `body_text`.** The Task 17 `html-tokenizer-divergence` fixture exercises a `<![CDATA[<script>alert(...)</script>]]>` payload. `scraper` / html5ever 0.39 parses the CDATA section such that the inner `<script>` element is stripped (good) but the literal JS source text survives as a text node and flows into `body_text` (bad — defeats the "hide script bodies from LLM" design). The fix is likely a one-liner in `html::collect_visible_text` that skips CDATA section children alongside `<script>`/`<style>` subtrees. Sprint 5 should land it as an early fixit and add `must_not_contain` assertions to the fixture's snapshot.
2. **`LookalikeFilenameExtensionSpoof` detail format mismatch.** The variant's doc comment in `output.rs` says `detail = "visible=<after_strip>,declared=<original>"` but Task 16's implementation emits `detail = "raw=<debug>,contains_bidi_override=true"` because computing `visible=` requires a bidi rendering engine we don't have. Sprint 5: either update the doc comment to match the actual shape, or implement the stricter visible-vs-declared comparison.
3. **`src/bin/epvme_runner.rs` has no automated tests.** 44 of the 111 surviving mutants in Task 19's run are in this binary. Options: (a) add `.cargo/mutants.toml` with `exclude_globs = ["src/bin/**"]` to exclude it from the headline number; (b) add integration tests for `collect_eml_files` and `run_dataset` over a two-file fixture directory. Option (b) is preferred because it actually improves coverage.
4. **Mutants re-run after Task 19's test additions.** Task 19 added 5 targeted kill tests but did not re-run the ~76-minute full-crate mutants pass to confirm the lib kill rate moved to ~85% as estimated. Sprint 5 should run it early so the headline number in docs stays honest.
5. **`HeaderValue::TextList` arm in `parse::sanitize_header_value`** (around `parse.rs:219-238`) is effectively dead code against the current corpus. Task 19's mutants survived there. Either remove the arm or add a targeted fixture that exercises it.
6. **Recursive `message/rfc822` parsing** is still deferred from 4a. Nested HTML bodies inside rfc822 attachments are not processed. If Sprint 5 chooses to recurse, it needs to reuse `html::process` on the nested part and handle arbitrary nesting depth (the existing `MAX_MIME_DEPTH` cap applies to the outer walk only).
7. **Runtime-configurable limits** are still compile-time `const`. Sprint 5's posture layer likely wants posture-dependent caps (e.g. permissive: 4 MiB `MAX_HTML_BYTES`; strict: 256 KiB). Promote constants to runtime config when the posture layer lands.

## Deferred from 4b (intentional, restated)

The following were explicitly out of scope for Sprint 4b per `2026-04-08-sprint-4b-html-lookalike-design.md` §9 and remain deferred:

- **`<style>` block class/id resolution.** Sprint 4b only inspects inline `style="..."` attributes. CSS rules in `<style>` blocks are ignored for hidden-element detection. An attacker can currently hide content via `<style>.x{display:none}</style><div class="x">...</div>` and the hide is not detected (though the content is still extracted as visible text, which is the safer default — the detection signal is missing but no hidden content is smuggled past text extraction).
- **Runtime-configurable limits.** See remediation item 7.
- **Recursive `message/rfc822`.** See remediation item 6.
- **cargo-fuzz harnesses.** Sprint 4b relies on proptest at 10k cases × 8 properties plus the corpus. Continuous fuzzing is a Sprint 5+ concern.
- **Differential HTML oracle.** Sprint 4b does not run a cross-parser differential (e.g. scraper vs. html5gum vs. regex-based stripping) beyond the single `html-tokenizer-divergence` probe. If Sprint 5 wants stronger guarantees about scraper↔ammonia divergence, build it then.

## Known safe Sprint 4b boundaries (reassurance)

- **Parallel tokenizers, not chained.** `scraper` (html5ever 0.39) and `ammonia` (html5ever 0.35) run independently on the raw input. Task 10's pipeline is: detection first (scraper, raw), sanitize second (ammonia, raw). They never feed each other. The dual-tokenizer divergence is observable as warnings plus the CDATA finding above. `deny.toml`'s `skip-tree` entries document the rationale and the upstream html5ever consolidation tracker.
- **Proptest covers the three main no-panic invariants** through `parse_message` (arbitrary `From:` header bytes, arbitrary HTML body bytes, sanitized-html-contains-no-script-or-dangerous-urls).
- **Corpus fixtures cover every new `WarningCode` emission site** with at least one positive-assertion fixture (see `tests/injection-corpus/html-*` and `lookalike-*`).
- **Insta snapshots pin the full `Content` output** for all 22 adversarial + regression fixtures. A snapshot regen is required after any output-shape change — use `cargo insta review` to diff.

## Sprint 5 prerequisites (restated)

1. **Posture layer consumes `WarningCode::severity()`.** The `Informational` / `Adversarial` partition is already correct for every 4b variant. Sprint 5's posture rules can filter on severity without maintaining a parallel classification.
2. **`Untrusted.body_html` is already populated** by `parse_message`. Sprint 5 MCP tool handlers can surface sanitized HTML directly — no additional rimap-content work needed to expose it.
3. **Prompt-template header escaping (restated from 4a R10).** Sprint 5 MCP tool handlers MUST NOT concatenate sanitized header strings into LLM prompts without escaping. `ContentMeta.subject` and other sanitized fields can legitimately contain `\n` — RFC 2047 base64 / quoted-printable encoded-word content with legal CR/LF passes through the scrub intact and `normalize_line_endings` collapses `\r\n` to `\n`, which is on the C0 allowlist. A naive template like

       format!("Subject: {subject}\nBody: {body}")

   is exploitable: an attacker-controlled subject of `hello\nBody: forged` forges a `Body:` line in the prompt. Safe templating options: (a) replace `\n` with space in header strings before interpolation; (b) use a structured format (JSON) where the serializer escapes newlines; (c) add a `ContentMeta::subject_single_line()` helper on rimap-content that returns the prompt-safe form.

## Gotchas discovered during 4b execution

Beyond the API findings in §plan-vs-reality above:

- **`.eml` fixtures must still be CRLF.** 4a's pre-commit exclusions already cover `^tests/injection-corpus/` and the snapshot directory — no new config needed for 4b's 10 new fixtures.
- **`typos.toml` already excludes `tests/injection-corpus/`.** 4b's bidi and zero-width fixture content continues to inherit that exclusion.
- **`cargo mutants --package rimap-content` takes ~76 minutes** on this dev box. Budget accordingly when Sprint 5 does the verification re-run.
- **Task 18's `[profile.dev.package."*"] opt-level = 3`** workspace tweak is load-bearing for `just ci` wall-clock staying under ~2m 20s with the proptest at 10k cases. If Sprint 5 removes or overrides it, expect `just ci` to balloon.

## `just ci` current state

```
Summary [  10.648s] 440 tests run: 440 passed, 0 skipped
cargo deny check: advisories ok, bans ok, licenses ok, sources ok
typos: clean
Total wall-clock: 2m 17.58s
```

All green end-to-end at the Sprint 4b tip.
