# Sprint 5 Phase 1 — Content Pipeline Remediation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close out Sprint 4b remediation items against `rimap-content` — warning semantics, ammonia hardening, bypass fixes, Reply-To gaps, address extraction consistency, build.rs strictness, and supply-chain comment hygiene.

**Architecture:** Bottom-up by file. Warning types land first (output.rs), then ammonia hardening + bypass fixes (html.rs), then parse-layer changes (parse.rs), then lookalike changes (lookalike.rs), then verification and comment hygiene. Each task produces a compilable, testable commit.

**Tech Stack:** Rust 2024 edition, MSRV 1.88. `scraper`, `ammonia`, `linkify`, `addr`, `idna`, `unicode-script`, `phf`, `mail-parser`, `proptest`, `insta`. Workspace clippy with `unwrap_used = deny`, `panic = deny`.

**Spec:** [`docs/superpowers/specs/2026-04-10-sprint-5-phase1-remediation-design.md`](../specs/2026-04-10-sprint-5-phase1-remediation-design.md)

**Worktree:** `/Users/dave/src/rusty-imap-mcp-sprint5` on branch `feat/sprint-5`

---

### Task 1: Rename `HtmlHiddenContentStripped` → `HtmlHiddenContentDetected`

**Files:**
- Modify: `crates/rimap-content/src/output.rs`
- Modify: `crates/rimap-content/src/html.rs`
- Modify: `crates/rimap-content/tests/injection_corpus.rs`
- Modify: `crates/rimap-content/tests/snapshots.rs` (snapshot regen only)
- Modify: all `tests/injection-corpus/*/expected.json` that reference `html_hidden_content_stripped`

- [ ] **Step 1: Rename the variant in `output.rs`**

In `crates/rimap-content/src/output.rs`, rename the variant and update its doc comment:

```rust
    /// HTML content contained hidden elements (e.g. `display:none`,
    /// `visibility:hidden`, `opacity:0`, off-screen positioning,
    /// zero font size, or background-color-matching text). Hidden
    /// content is stripped from `body_text` but may remain in
    /// `body_html` when the posture allows HTML exposure.
    HtmlHiddenContentDetected,
```

Update the `severity()` match arm: change `WarningCode::HtmlHiddenContentStripped` → `WarningCode::HtmlHiddenContentDetected` in the Adversarial arm.

Update every test in the `mod tests` block that references `HtmlHiddenContentStripped` to use `HtmlHiddenContentDetected`. There are four occurrences:
- `severity_classifies_known_variants` (line 331)
- `new_warning_variants_serialize_snake_case` (lines 372-374)

- [ ] **Step 2: Update `html.rs` emission sites**

In `crates/rimap-content/src/html.rs`, replace all `WarningCode::HtmlHiddenContentStripped` with `WarningCode::HtmlHiddenContentDetected`. There are two emission sites:
- `process()` line 557 (per-hit warnings)
- `process()` line 564 (overflow summary warning)

Update all tests in `html.rs` that reference the old variant. Search for `HtmlHiddenContentStripped`:
- `process_detects_display_none_in_body` (line 858)
- `process_hidden_hit_cap_summarizes_overflow` (line 879)

- [ ] **Step 3: Update corpus harness**

In `crates/rimap-content/tests/injection_corpus.rs`, update `warning_code_to_label`:
```rust
        WarningCode::HtmlHiddenContentDetected => "html_hidden_content_detected",
```

Update every `expected.json` that references `html_hidden_content_stripped`. Check:
```bash
rg -l 'html_hidden_content_stripped' tests/injection-corpus/
```
Change each `"html_hidden_content_stripped"` to `"html_hidden_content_detected"`.

- [ ] **Step 4: Regenerate snapshots**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --test snapshots -- --ignored 2>/dev/null; cargo insta review --accept
```

Or if `insta` is not installed as a CLI:
```bash
INSTA_UPDATE=always cargo test --package rimap-content --test snapshots
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all tests pass. The snapshot test will show diffs for every fixture that emits `html_hidden_content_detected` (the old `_stripped` label).

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/output.rs crates/rimap-content/src/html.rs \
  crates/rimap-content/tests/injection_corpus.rs \
  crates/rimap-content/tests/snapshots/ \
  tests/injection-corpus/
git commit -m "refactor(content): rename HtmlHiddenContentStripped → HtmlHiddenContentDetected

The old name implied hidden content was removed everywhere. In reality
it is stripped from body_text but may remain in body_html. The new name
reflects detection, not removal.

Closes part of #49 item 1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add `HtmlAnchorUnparsableHref` variant + doc comments

**Files:**
- Modify: `crates/rimap-content/src/output.rs`
- Modify: `crates/rimap-content/tests/injection_corpus.rs`

- [ ] **Step 1: Add the variant to `WarningCode`**

In `crates/rimap-content/src/output.rs`, add after `HtmlRemoteImageStripped`:

```rust
    /// An HTML anchor's `href` could not be resolved to a registrable
    /// domain via the Public Suffix List, but the anchor's visible text
    /// contained a URL-looking token (detected by `linkify`). This
    /// distinguishes "we checked and it's fine" from "we couldn't
    /// check." Consumers should treat the anchor with suspicion.
    HtmlAnchorUnparsableHref,
```

Add it to the `severity()` match in the `Informational` arm:

```rust
            WarningCode::ParseBodyTruncated
            | WarningCode::HtmlStyleStripped
            | WarningCode::HtmlRemoteImageStripped
            | WarningCode::HtmlAnchorUnparsableHref
            | WarningCode::LookalikeIdnPunycode => WarningSeverity::Informational,
```

- [ ] **Step 2: Add doc comments for semantic pinning**

On `HtmlLinkTextHrefMismatch`, update the doc comment:

```rust
    /// An HTML anchor's visible text contained a URL-looking token
    /// whose registrable domain differs from the anchor's `href`
    /// registrable domain.
    ///
    /// Reflects the original message content (pre-ammonia), not the
    /// sanitized `body_html`. An anchor stripped by ammonia may still
    /// produce this warning — the warning signals the message's
    /// intent, not the sanitized output.
    HtmlLinkTextHrefMismatch,
```

On `SecurityWarning::detail`, update the doc comment:

```rust
    /// Human-readable context string. Consumers MUST NOT parse this
    /// field programmatically — use `code` and other typed fields for
    /// dispatch. Format may change without notice.
    ///
    /// `None` when no additional detail is available.
    pub detail: Option<String>,
```

- [ ] **Step 3: Add test for new variant serialization**

In the `mod tests` block at the bottom of `output.rs`, add to the `new_warning_variants_serialize_snake_case` test array:

```rust
            (
                WarningCode::HtmlAnchorUnparsableHref,
                "html_anchor_unparsable_href",
            ),
```

Add to `severity_classifies_known_variants`:

```rust
        assert_eq!(
            WarningCode::HtmlAnchorUnparsableHref.severity(),
            WarningSeverity::Informational
        );
```

- [ ] **Step 4: Update corpus harness**

In `crates/rimap-content/tests/injection_corpus.rs`, add to `warning_code_to_label`:

```rust
        WarningCode::HtmlAnchorUnparsableHref => "html_anchor_unparsable_href",
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/output.rs crates/rimap-content/tests/injection_corpus.rs
git commit -m "feat(content): add HtmlAnchorUnparsableHref variant + semantic doc comments

New Informational variant for anchors whose href can't be resolved via
PSL but whose visible text looks like a URL. Also pins
HtmlLinkTextHrefMismatch as raw-DOM semantics and detail as opaque.

Closes #49 items 2-4.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Add `reply_to` to `ContentMeta`

**Files:**
- Modify: `crates/rimap-content/src/output.rs`

- [ ] **Step 1: Write failing test**

In `crates/rimap-content/src/output.rs` `mod tests`, add:

```rust
    #[test]
    fn content_meta_has_reply_to_field() {
        let meta = ContentMeta {
            reply_to: Some("reply@example.com".to_string()),
            ..ContentMeta::default()
        };
        assert_eq!(meta.reply_to.as_deref(), Some("reply@example.com"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- output::tests::content_meta_has_reply_to_field
```

Expected: FAIL — `reply_to` field does not exist.

- [ ] **Step 3: Add the field**

In `ContentMeta`, after `cc`:

```rust
    /// Parsed `Reply-To:` header, sanitized. `None` if absent.
    pub reply_to: Option<String>,
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- output::tests::content_meta_has_reply_to_field
```

Expected: PASS.

- [ ] **Step 5: Regenerate snapshots (reply_to will appear as null in JSON)**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
INSTA_UPDATE=always cargo test --package rimap-content --test snapshots
```

- [ ] **Step 6: Run full test suite**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/output.rs crates/rimap-content/tests/snapshots/
git commit -m "feat(content): add reply_to field to ContentMeta

Preparation for Reply-To lookalike and bidi-prestrip audit coverage.

Part of #50 item 1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Ammonia hardening — explicit tag denial + strip_comments

**Files:**
- Modify: `crates/rimap-content/src/html.rs`

- [ ] **Step 1: Write failing tests**

In `crates/rimap-content/src/html.rs` `mod tests`, add:

```rust
    #[test]
    fn sanitize_drops_iframe_and_details() {
        let tags = [
            "iframe", "object", "embed", "meta", "base", "link",
            "form", "input", "button", "textarea", "svg", "math",
            "frame", "frameset", "noframes", "applet",
            "details", "summary",
        ];
        for tag in tags {
            let input = format!(
                "<html><body><{tag}>hidden content</{tag}></body></html>"
            );
            let result = process(input.as_bytes(), None)
                .expect("process should succeed");
            assert!(
                !result.body_html.contains(&format!("<{tag}")),
                "tag <{tag}> should be stripped from body_html, got: {}",
                result.body_html
            );
        }
    }

    #[test]
    fn body_html_has_no_html_comments() {
        let input = b"<html><body><!-- secret comment --><p>visible</p></body></html>";
        let result = process(input, None).expect("process should succeed");
        assert!(
            !result.body_html.contains("<!--"),
            "HTML comments should be stripped, got: {}",
            result.body_html
        );
        assert!(
            !result.body_html.contains("secret comment"),
            "comment content should be stripped, got: {}",
            result.body_html
        );
    }
```

- [ ] **Step 2: Run tests to verify the `details`/`summary` test fails**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::sanitize_drops_iframe_and_details
```

Expected: FAIL on `details` or `summary` (ammonia allows them by default). The `strip_comments` test likely passes already (ammonia defaults to stripping comments) but we want to pin it.

- [ ] **Step 3: Update `build_ammonia_builder`**

In `crates/rimap-content/src/html.rs`, replace `build_ammonia_builder`:

```rust
fn build_ammonia_builder() -> Builder<'static> {
    let mut builder = Builder::default();
    let schemes: HashSet<&'static str> =
        ["http", "https", "mailto", "tel"].into_iter().collect();
    builder.url_schemes(schemes);
    builder.rm_tag_attributes("img", &["src", "srcset"]);
    builder.add_tag_attributes("img", &["alt", "width", "height"]);
    // Pin tag removals against ammonia default drift. details/summary
    // are explicitly removed: collapsed content is invisible to humans
    // but visible to LLMs reading HTML tokens.
    builder.rm_tags(&[
        "script", "style", "iframe", "object", "embed", "meta",
        "base", "link", "form", "input", "button", "textarea",
        "svg", "math", "frame", "frameset", "noframes", "applet",
        "details", "summary",
    ]);
    builder.strip_comments(true);
    builder
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::sanitize_drops_iframe_and_details
cargo test --package rimap-content --lib -- html::tests::body_html_has_no_html_comments
```

Expected: both PASS.

- [ ] **Step 5: Run full rimap-content tests + regenerate snapshots**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
INSTA_UPDATE=always cargo test --package rimap-content
```

Expected: all pass. Some snapshots may change if `<details>` appeared in any corpus fixture's body_html output.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/html.rs crates/rimap-content/tests/snapshots/
git commit -m "fix(content): explicit ammonia tag denial list + strip_comments

Pin script/style/iframe/object/embed/meta/base/link/form/input/button/
textarea/svg/math/frame/frameset/noframes/applet/details/summary removal
against ammonia default drift. Explicitly set strip_comments(true).

Closes #52 items 1-2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Off-screen threshold loosening + transform detection

**Files:**
- Modify: `crates/rimap-content/src/html.rs`

- [ ] **Step 1: Write failing test**

In `crates/rimap-content/src/html.rs` `mod tests`, add:

```rust
    #[test]
    fn classify_offscreen_minus_999_fires() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -999px"),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_offscreen_minus_50_does_not_fire() {
        assert_eq!(
            classify_inline_style("position: absolute; left: -50px"),
            None
        );
    }

    #[test]
    fn classify_offscreen_transform_translate() {
        assert_eq!(
            classify_inline_style(
                "position: absolute; transform: translateX(-9999px)"
            ),
            Some(HiddenMethod::OffScreen)
        );
        assert_eq!(
            classify_inline_style(
                "position: fixed; transform: translate(-500px, 0)"
            ),
            Some(HiddenMethod::OffScreen)
        );
    }

    #[test]
    fn classify_offscreen_transform_small_value_no_fire() {
        assert_eq!(
            classify_inline_style(
                "position: absolute; transform: translateX(-50px)"
            ),
            None
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::classify_offscreen_minus_999_fires
```

Expected: FAIL (current threshold is -1000).

- [ ] **Step 3: Update `StyleHints` and `is_offscreen`**

In `crates/rimap-content/src/html.rs`, update `StyleHints` to add a `transform` field:

```rust
struct StyleHints {
    position: Option<String>,
    left_px: Option<f64>,
    top_px: Option<f64>,
    color: Option<String>,
    bg_color: Option<String>,
    transform_offset_px: Option<f64>,
}
```

Update `StyleHints::record` to parse `transform`:

```rust
    fn record(&mut self, prop: &str, val: &str) {
        match prop {
            "position" => self.position = Some(val.to_string()),
            "left" => self.left_px = parse_px(val),
            "top" => self.top_px = parse_px(val),
            "color" => self.color = Some(val.to_string()),
            "background-color" => self.bg_color = Some(val.to_string()),
            "transform" => self.transform_offset_px = parse_translate_px(val),
            _ => {}
        }
    }
```

Update `is_offscreen` to use the new threshold and transform:

```rust
    fn is_offscreen(&self) -> bool {
        let positioned = matches!(
            self.position.as_deref(),
            Some("absolute" | "fixed")
        );
        if !positioned {
            return false;
        }
        let off_left = self.left_px.is_some_and(|v| v < -100.0);
        let off_top = self.top_px.is_some_and(|v| v < -100.0);
        let off_transform = self
            .transform_offset_px
            .is_some_and(|v| v < -100.0);
        off_left || off_top || off_transform
    }
```

Add a `parse_translate_px` function near `parse_px`:

```rust
/// Parse a `transform: translate*(-Npx)` value and return the most
/// negative pixel offset found, or `None` if no translate pattern
/// matches. Handles `translateX(-9999px)`, `translateY(-500px)`,
/// and `translate(-500px, 0)`.
fn parse_translate_px(val: &str) -> Option<f64> {
    let mut min: Option<f64> = None;
    // Match patterns: translateX(-Npx), translateY(-Npx),
    // translate(-Npx ...).
    for part in val.split(|c: char| c == '(' || c == ',' || c == ')') {
        let trimmed = part.trim();
        if let Some(px_val) = parse_px(trimmed) {
            match min {
                Some(current) if px_val < current => min = Some(px_val),
                None => min = Some(px_val),
                _ => {}
            }
        }
    }
    min
}
```

- [ ] **Step 4: Update the existing off-screen test threshold**

The existing test `classify_offscreen_absolute` asserts `-9999px` and `-5000px` — both still pass with the new threshold. No change needed. Verify:

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::classify_offscreen
```

Expected: all offscreen tests pass.

- [ ] **Step 5: Run full rimap-content tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/html.rs
git commit -m "fix(content): loosen off-screen threshold to -100px + transform detection

Catches evasion via left:-999px and transform:translateX(-9999px).
Small negative values (legitimate border tricks) are not flagged.

Part of #51 item 5.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: PSL silent-skip → `HtmlAnchorUnparsableHref` emission

**Files:**
- Modify: `crates/rimap-content/src/html.rs`

- [ ] **Step 1: Write failing test**

In `crates/rimap-content/src/html.rs` `mod tests`, add:

```rust
    #[test]
    fn mismatch_emits_unparsable_href_for_psl_failure() {
        // href uses a single-label host (no dot) that PSL can't resolve,
        // but the visible text looks like a domain (has a dot, linkify
        // picks it up).
        let input = br#"<html><body>
            <a href="https://evilserver/phish">Visit paypal.com now</a>
        </body></html>"#;
        let result = process(input, None).expect("ok");
        assert!(
            result
                .warnings
                .iter()
                .any(|w| matches!(
                    w.code,
                    crate::output::WarningCode::HtmlAnchorUnparsableHref
                )),
            "expected HtmlAnchorUnparsableHref, got {:?}",
            result.warnings
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::mismatch_emits_unparsable_href_for_psl_failure
```

Expected: FAIL — currently the anchor is silently skipped.

- [ ] **Step 3: Update `detect_mismatches` to emit the warning**

In `detect_mismatches()` (around line 338-371), change the `extract_registrable_domain(href)` None case. Currently when `href_domain` is `None`, the loop does `continue`. Instead, check if the anchor text contains a URL:

Replace the current block:
```rust
        let Some(href_domain) = extract_registrable_domain(href) else {
            continue;
        };
```

With:
```rust
        let href_domain = match extract_registrable_domain(href) {
            Some(d) => d,
            None => {
                // href couldn't be resolved via PSL. If the anchor text
                // looks like a URL, emit an informational warning so
                // the absence of HtmlLinkTextHrefMismatch is
                // distinguishable from "we couldn't check."
                let mut text: String =
                    anchor.text().collect::<Vec<&str>>().join(" ");
                if text.len() > MAX_ANCHOR_TEXT_SCAN {
                    text.truncate(MAX_ANCHOR_TEXT_SCAN);
                }
                let has_url_text = finder
                    .links(&text)
                    .any(|l| l.kind() == &linkify::LinkKind::Url);
                if has_url_text && hits.len() < MAX_MISMATCH_HITS {
                    unparsable_hrefs.push((
                        href.to_string(),
                        text.trim().to_string(),
                    ));
                }
                continue;
            }
        };
```

This requires adding a `unparsable_hrefs` accumulator. Change the function signature to return it:

Actually, to keep the return type stable, add the unparsable hrefs to a separate return. Change the function:

```rust
fn detect_mismatches(
    document: &Html,
) -> (Vec<MismatchHit>, usize, Vec<(String, String)>) {
```

Add `let mut unparsable_hrefs: Vec<(String, String)> = Vec::new();` at the top, and return `(hits, overflow, unparsable_hrefs)`.

Update the call site in `process()` to destructure and emit warnings:

```rust
    let (mismatches, mismatch_overflow, unparsable_hrefs) =
        detect_mismatches(&document);
    // ... existing mismatch warning emission ...
    for (href, text) in &unparsable_hrefs {
        warnings.push(SecurityWarning {
            code: crate::output::WarningCode::HtmlAnchorUnparsableHref,
            detail: Some(format!("href={href},text={text}")),
            location: Some("body_html:anchor".to_string()),
        });
    }
```

- [ ] **Step 4: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests::mismatch_emits_unparsable_href
```

Expected: PASS.

- [ ] **Step 5: Run full tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/html.rs
git commit -m "fix(content): emit HtmlAnchorUnparsableHref for PSL-unresolvable hrefs

When an anchor's href can't be resolved via the Public Suffix List but
the visible text contains a URL token, emit an Informational warning
instead of silently skipping. Distinguishes 'checked, fine' from
'couldn't check.'

Closes #51 item 4.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: CDATA text leak fix

**Files:**
- Modify: `crates/rimap-content/src/html.rs`
- Modify: `tests/injection-corpus/html-tokenizer-divergence/expected.json`

- [ ] **Step 1: Investigate the CDATA behavior**

Before writing the fix, validate what scraper does with CDATA. Run:

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- html::tests 2>&1 | head -30
```

Read the existing `html-tokenizer-divergence/input.eml` to understand the current fixture content. The handoff says CDATA was intentionally omitted from the fixture. We need to understand scraper's behavior to craft the right fix.

Write a diagnostic test (temporary) to see what scraper does:

```rust
    #[test]
    fn debug_cdata_scraper_behavior() {
        let html = r#"<html><body><![CDATA[<script>alert("cdata-bypass")</script>]]></body></html>"#;
        let result = process(html.as_bytes(), None).expect("ok");
        eprintln!("body_text: {:?}", result.body_text);
        eprintln!("body_html: {:?}", result.body_html);
        // This test is diagnostic — check stderr output to determine
        // whether the JS source leaks into body_text.
    }
```

Run it with `-- --nocapture` to see output. Based on the output, determine the fix approach.

- [ ] **Step 2: Implement the fix**

Per the handoff, the JS source text survives as a text node in `body_text`. The fix in `collect_visible_text` / `walk_element` depends on how scraper represents the CDATA content. If it appears as a text child of an element that scraper treats as a comment or special node, the fix may be to check for script-like content in text nodes.

The most robust approach: in `push_text`, or in the text-node handler in `collect_visible_text`, skip text content that looks like it leaked from a CDATA section. Alternatively, check if the parent element or sibling context indicates CDATA provenance.

**Note to implementer:** the exact fix depends on the diagnostic test output from Step 1. The handoff says "one-liner" — likely the scraper parse turns CDATA into a comment node that the text walker incorrectly treats as text, or the walker needs to skip a specific node type.

- [ ] **Step 3: Update the corpus fixture**

In `tests/injection-corpus/html-tokenizer-divergence/input.eml`, add a CDATA section to the HTML body. If the input.eml already has one that was commented out, uncomment it. If not, add it to the HTML body part:

```
<![CDATA[<script>alert("cdata-bypass")</script>]]>
```

Update `tests/injection-corpus/html-tokenizer-divergence/expected.json` — the `must_not_contain` already includes `alert("cdata-bypass")`, so no change needed there.

- [ ] **Step 4: Run tests + regenerate snapshots**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
INSTA_UPDATE=always cargo test --package rimap-content
```

Expected: all pass, including the tokenizer-divergence fixture.

- [ ] **Step 5: Remove the diagnostic test**

Delete the `debug_cdata_scraper_behavior` test added in Step 1.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/html.rs \
  tests/injection-corpus/html-tokenizer-divergence/ \
  crates/rimap-content/tests/snapshots/
git commit -m "fix(content): prevent CDATA JS source from leaking into body_text

Scraper/html5ever parses CDATA sections such that inner script content
survives as text nodes. Skip these during visible-text extraction.

Closes #51 item 2.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Double-extension filename heuristic

**Files:**
- Modify: `crates/rimap-content/src/parse.rs`

- [ ] **Step 1: Write failing test**

In `crates/rimap-content/src/parse.rs` `mod tests`, add:

```rust
    #[test]
    fn double_extension_pdf_exe_fires_spoof_warning() {
        let eml = b"From: test@example.com\r\n\
            Subject: invoice\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).expect("should parse");
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "expected LookalikeFilenameExtensionSpoof with double_extension, \
             got {:?}",
            content.security_warnings
        );
    }

    #[test]
    fn single_extension_does_not_fire_double_extension() {
        let eml = b"From: test@example.com\r\n\
            Subject: file\r\n\
            MIME-Version: 1.0\r\n\
            Content-Type: multipart/mixed; boundary=\"bound\"\r\n\
            \r\n\
            --bound\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            See attached.\r\n\
            --bound\r\n\
            Content-Type: application/pdf\r\n\
            Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
            Content-Transfer-Encoding: base64\r\n\
            \r\n\
            AAAA\r\n\
            --bound--\r\n";
        let content = parse_message(eml).expect("should parse");
        assert!(
            !content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeFilenameExtensionSpoof
                    && w.detail
                        .as_deref()
                        .is_some_and(|d| d.contains("double_extension"))
            }),
            "single extension should not fire double_extension spoof"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- parse::tests::double_extension_pdf_exe_fires
```

Expected: FAIL — double extension check doesn't exist yet.

- [ ] **Step 3: Implement `detect_double_extension`**

Add a helper function in `parse.rs` near `contains_bidi_override`:

```rust
/// Document-type extensions that commonly appear as the penultimate
/// extension in a double-extension spoof (e.g. `invoice.pdf.exe`).
const DOCUMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "png", "jpg", "jpeg",
    "gif", "txt", "csv", "rtf",
];

/// Executable-type extensions that commonly appear as the final
/// extension in a double-extension spoof.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "scr", "msi",
    "app", "dmg", "sh", "com", "pif", "jar", "lnk",
];

/// Check for a double-extension spoof pattern like `file.pdf.exe`.
/// Returns `Some((penultimate, final))` if the filename has 3+
/// dot-separated segments where the penultimate is a document type
/// and the final is an executable type.
fn detect_double_extension(name: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 3 {
        return None;
    }
    let penultimate = segments[segments.len() - 2].to_ascii_lowercase();
    let final_ext = segments[segments.len() - 1].to_ascii_lowercase();
    if DOCUMENT_EXTENSIONS.contains(&penultimate.as_str())
        && EXECUTABLE_EXTENSIONS.contains(&final_ext.as_str())
    {
        Some((penultimate, final_ext))
    } else {
        None
    }
}
```

- [ ] **Step 4: Wire into `build_attachment_meta`**

In `build_attachment_meta`, after the existing bidi-override check (line ~734) and before the `unicode::sanitize` call, add the double-extension check:

```rust
        if let Some((penult, final_ext)) = detect_double_extension(name) {
            warnings.push(SecurityWarning {
                code: WarningCode::LookalikeFilenameExtensionSpoof,
                detail: Some(format!(
                    "reason=double_extension,visible=.{penult},\
                     declared=.{penult}.{final_ext}"
                )),
                location: Some(format!("attachment[{idx}]:filename")),
            });
        }
```

- [ ] **Step 5: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- parse::tests::double_extension
```

Expected: both tests PASS.

- [ ] **Step 6: Run full tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/parse.rs
git commit -m "feat(content): detect double-extension filename spoofs

Detect patterns like invoice.pdf.exe where the penultimate extension
is a document type and the final extension is an executable type.
Emits LookalikeFilenameExtensionSpoof with reason=double_extension.

Closes #51 item 3.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Populate Reply-To in `extract_meta` + bidi audit

**Files:**
- Modify: `crates/rimap-content/src/parse.rs`

- [ ] **Step 1: Write failing test**

In `crates/rimap-content/src/parse.rs` `mod tests`, add:

```rust
    #[test]
    fn reply_to_extracted_into_meta() {
        let eml = b"From: sender@example.com\r\n\
            Reply-To: reply@different.com\r\n\
            To: recipient@example.com\r\n\
            Subject: test\r\n\
            \r\n\
            body\r\n";
        let content = parse_message(eml).expect("should parse");
        assert_eq!(
            content.meta.reply_to.as_deref(),
            Some("reply@different.com")
        );
    }

    #[test]
    fn reply_to_bidi_override_emits_warning() {
        // Reply-To domain with a bidi override character.
        let eml = format!(
            "From: sender@example.com\r\n\
             Reply-To: attacker@evil\u{202E}.com\r\n\
             To: recipient@example.com\r\n\
             Subject: test\r\n\
             \r\n\
             body\r\n"
        );
        let content = parse_message(eml.as_bytes()).expect("should parse");
        assert!(
            content.security_warnings.iter().any(|w| {
                w.code == WarningCode::LookalikeHomographDomain
                    && w.location.as_deref() == Some("header:reply_to")
            }),
            "expected LookalikeHomographDomain on reply_to, got {:?}",
            content.security_warnings
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- parse::tests::reply_to_extracted
```

Expected: FAIL — `reply_to` is not populated.

- [ ] **Step 3: Populate Reply-To in `extract_meta`**

In `extract_meta()`, add after the `cc` line (around line 125):

```rust
    let reply_to = first_address_string(
        message.reply_to(),
        "header:reply_to",
        warnings,
    );
```

Add to the `ContentMeta` struct literal (around line 138):

```rust
        reply_to,
```

Note: `first_address_string` already calls `audit_addr_domain_bidi` internally (line 194), so the bidi audit for Reply-To is automatically wired by using this function.

- [ ] **Step 4: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- parse::tests::reply_to
```

Expected: both PASS.

- [ ] **Step 5: Regenerate snapshots + run full tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
INSTA_UPDATE=always cargo test --package rimap-content
```

Expected: all pass. Snapshots may change to include `reply_to` values.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/parse.rs crates/rimap-content/tests/snapshots/
git commit -m "feat(content): populate Reply-To in ContentMeta with bidi audit

Extract Reply-To via first_address_string, which includes the
addr-domain bidi-prestrip audit. Reply-To domains with bidi overrides
now emit LookalikeHomographDomain.

Closes #50 item 1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: Address extraction consistency + Reply-To lookalike pass

**Files:**
- Modify: `crates/rimap-content/src/lookalike.rs`
- Modify: `crates/rimap-content/src/parse.rs`

- [ ] **Step 1: Write failing test for Reply-To lookalike**

In `crates/rimap-content/src/lookalike.rs` `mod tests`, add:

```rust
    #[test]
    fn audit_flags_mixed_script_reply_to_domain() {
        let mut meta = empty_meta();
        meta.from = Some("legit@example.com".to_string());
        meta.reply_to =
            Some("support@p\u{0430}ypal.com".to_string());
        let warnings = run_audit(&meta, "", &[]);
        let reply_to_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| {
                w.code == WarningCode::LookalikeMixedScript
                    && w.location.as_deref() == Some("header:reply_to")
            })
            .collect();
        assert_eq!(
            reply_to_warnings.len(),
            1,
            "expected one mixed-script hit on reply_to, got {warnings:?}"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --lib -- lookalike::tests::audit_flags_mixed_script_reply_to
```

Expected: FAIL — `scan_header_domains` doesn't check `reply_to`.

- [ ] **Step 3: Add `header_domains` to `LookalikeInput`**

In `crates/rimap-content/src/lookalike.rs`, update `LookalikeInput`:

```rust
pub(crate) struct LookalikeInput<'a> {
    /// Header-derived metadata (from, subject, list-id, …).
    pub meta: &'a ContentMeta,
    /// Sanitized plain-text body, used for body-URL scanning.
    pub body_text: &'a str,
    /// Anchor hrefs collected from the sanitized HTML body.
    pub anchor_hrefs: &'a [String],
    /// Pre-extracted header address domains with their locations.
    /// Built at the `parse_message` boundary using structured
    /// `Addr.address` data rather than re-parsing rendered strings.
    pub header_domains: Vec<(String, String)>,
}
```

- [ ] **Step 4: Rewrite `scan_header_domains` to use `header_domains`**

```rust
fn scan_header_domains(
    input: &LookalikeInput<'_>,
    out: &mut Vec<SecurityWarning>,
) {
    for (domain, location) in &input.header_domains {
        emit_classification(domain, location, out);
    }
}
```

Update the call in `audit()`:
```rust
    scan_header_domains(input, &mut out);
```

- [ ] **Step 5: Build `header_domains` in `parse_message`**

In `crates/rimap-content/src/parse.rs`, add a helper to extract domains from structured addresses:

```rust
/// Extract domains from structured `Addr` values for lookalike
/// scanning. Uses `addr.address` directly rather than re-parsing
/// rendered display strings.
fn collect_header_domains(
    message: &Message<'_>,
) -> Vec<(String, String)> {
    let mut domains = Vec::new();
    if let Some(address) = message.from() {
        for addr in address.iter() {
            if let Some(domain) = addr_domain(addr) {
                domains.push((domain, "header:from".to_string()));
            }
        }
    }
    if let Some(address) = message.to() {
        for addr in address.iter() {
            if let Some(domain) = addr_domain(addr) {
                domains.push((domain, "header:to".to_string()));
            }
        }
    }
    if let Some(address) = message.cc() {
        for addr in address.iter() {
            if let Some(domain) = addr_domain(addr) {
                domains.push((domain, "header:cc".to_string()));
            }
        }
    }
    if let Some(address) = message.reply_to() {
        for addr in address.iter() {
            if let Some(domain) = addr_domain(addr) {
                domains.push((
                    domain,
                    "header:reply_to".to_string(),
                ));
            }
        }
    }
    domains
}

/// Extract the domain from a structured `Addr` via `addr.address`.
fn addr_domain(addr: &mail_parser::Addr<'_>) -> Option<String> {
    let email = addr.address.as_deref()?;
    let (_local, domain) = email.rsplit_once('@')?;
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}
```

Update the `lookalike::audit` call in `parse_message`:

```rust
    let header_domains = collect_header_domains(&message);
    let lookalike_warnings = lookalike::audit(&lookalike::LookalikeInput {
        meta: &content.meta,
        body_text: &content.untrusted.body_text,
        anchor_hrefs: &html_anchor_hrefs,
        header_domains,
    });
```

- [ ] **Step 6: Update test helpers in `lookalike.rs`**

Update the `run_audit` helper in `lookalike::tests`:

```rust
    fn run_audit(
        meta: &ContentMeta,
        body_text: &str,
        anchor_hrefs: &[String],
    ) -> Vec<SecurityWarning> {
        // For tests, build header_domains from meta fields to keep
        // existing test patterns working.
        let mut header_domains = Vec::new();
        if let Some(from) = meta.from.as_deref() {
            if let Some(domain) = extract_domain_from_address(from) {
                header_domains.push((domain, "header:from".to_string()));
            }
        }
        for addr in &meta.to {
            if let Some(domain) = extract_domain_from_address(addr) {
                header_domains.push((domain, "header:to".to_string()));
            }
        }
        for addr in &meta.cc {
            if let Some(domain) = extract_domain_from_address(addr) {
                header_domains.push((domain, "header:cc".to_string()));
            }
        }
        if let Some(reply_to) = meta.reply_to.as_deref() {
            if let Some(domain) = extract_domain_from_address(reply_to) {
                header_domains.push((
                    domain,
                    "header:reply_to".to_string(),
                ));
            }
        }
        audit(&LookalikeInput {
            meta,
            body_text,
            anchor_hrefs,
            header_domains,
        })
    }
```

- [ ] **Step 7: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass including the new Reply-To test.

- [ ] **Step 8: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/src/lookalike.rs crates/rimap-content/src/parse.rs
git commit -m "feat(content): address extraction consistency + Reply-To lookalike pass

Replace rfind-based domain extraction in scan_header_domains with
pre-extracted domains from structured Addr.address at the parse
boundary. Adds Reply-To as a fourth header domain source.

Closes #50 item 3.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: Corpus fixtures — offscreen evasion, unparsable href, Reply-To

**Files:**
- Create: `tests/injection-corpus/html-offscreen-evasion/input.eml`
- Create: `tests/injection-corpus/html-offscreen-evasion/expected.json`
- Create: `tests/injection-corpus/html-anchor-unparsable-href/input.eml`
- Create: `tests/injection-corpus/html-anchor-unparsable-href/expected.json`
- Create: `tests/injection-corpus/lookalike-reply-to-mismatch/input.eml`
- Create: `tests/injection-corpus/lookalike-reply-to-mismatch/expected.json`
- Modify: `crates/rimap-content/tests/snapshots.rs`

- [ ] **Step 1: Create `html-offscreen-evasion` fixture**

Create `tests/injection-corpus/html-offscreen-evasion/input.eml` (CRLF line endings):

```
From: attacker@evil.example
To: victim@example.com
Subject: Offscreen evasion test
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Please review the attached document.</p>
<div style="position: absolute; left: -999px">HIDDEN BY LEFT OFFSET</div>
<div style="position: fixed; transform: translateX(-9999px)">HIDDEN BY TRANSFORM</div>
</body></html>
```

Create `tests/injection-corpus/html-offscreen-evasion/expected.json`:

```json
{
  "description": "Off-screen evasion via left:-999px (below old -1000px threshold) and transform:translateX(-9999px). Both must trigger HtmlHiddenContentDetected.",
  "expect": "ok",
  "must_contain": [
    "Please review the attached document."
  ],
  "must_not_contain": [
    "HIDDEN BY LEFT OFFSET",
    "HIDDEN BY TRANSFORM"
  ],
  "warning_codes": [
    "html_hidden_content_detected"
  ],
  "forbidden_warning_codes": []
}
```

- [ ] **Step 2: Create `html-anchor-unparsable-href` fixture**

Create `tests/injection-corpus/html-anchor-unparsable-href/input.eml` (CRLF line endings):

```
From: phisher@evil.example
To: victim@example.com
Subject: Unparsable href test
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Click to verify your account:</p>
<a href="https://evilserver/phishing-page">Visit paypal.com to verify</a>
</body></html>
```

Create `tests/injection-corpus/html-anchor-unparsable-href/expected.json`:

```json
{
  "description": "Anchor href uses a single-label host (no dot, PSL fails) but visible text contains paypal.com. HtmlAnchorUnparsableHref must fire.",
  "expect": "ok",
  "must_contain": [
    "Click to verify your account:"
  ],
  "must_not_contain": [],
  "warning_codes": [
    "html_anchor_unparsable_href"
  ],
  "forbidden_warning_codes": []
}
```

- [ ] **Step 3: Create `lookalike-reply-to-mismatch` fixture**

Create `tests/injection-corpus/lookalike-reply-to-mismatch/input.eml` (CRLF line endings). Uses a Cyrillic 'а' (U+0430) in the Reply-To domain:

```
From: support@paypal.com
Reply-To: =?utf-8?B?c3VwcG9ydEBw0LB5cGFsLmNvbQ==?=
To: victim@example.com
Subject: Account verification required
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Please verify your account by replying to this email.
```

Note: the base64 `c3VwcG9ydEBw0LB5cGFsLmNvbQ==` decodes to `support@pаypal.com` (with Cyrillic а).

**Important:** Verify the base64 encoding is correct before committing. Generate it:
```bash
echo -n 'support@p\xd0\xb0ypal.com' | base64
```

Create `tests/injection-corpus/lookalike-reply-to-mismatch/expected.json`:

```json
{
  "description": "Reply-To uses a Cyrillic homograph of paypal.com (Latin+Cyrillic mixed script). LookalikeMixedScript must fire on header:reply_to.",
  "expect": "ok",
  "must_contain": [
    "Please verify your account"
  ],
  "must_not_contain": [],
  "warning_codes": [
    "lookalike_mixed_script"
  ],
  "forbidden_warning_codes": []
}
```

- [ ] **Step 4: Add snapshot test functions**

In `crates/rimap-content/tests/snapshots.rs`, add:

```rust
#[test]
fn snapshot_html_offscreen_evasion() {
    snapshot_one("html-offscreen-evasion");
}

#[test]
fn snapshot_html_anchor_unparsable_href() {
    snapshot_one("html-anchor-unparsable-href");
}

#[test]
fn snapshot_lookalike_reply_to_mismatch() {
    snapshot_one("lookalike-reply-to-mismatch");
}
```

Also update the `warning_code_to_label` in `snapshots.rs` if it has a matching function (check — it may use serde instead).

- [ ] **Step 5: Run tests + generate initial snapshots**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
INSTA_UPDATE=always cargo test --package rimap-content
```

Expected: all pass. New snapshots created for the three fixtures.

- [ ] **Step 6: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add tests/injection-corpus/html-offscreen-evasion/ \
  tests/injection-corpus/html-anchor-unparsable-href/ \
  tests/injection-corpus/lookalike-reply-to-mismatch/ \
  crates/rimap-content/tests/snapshots.rs \
  crates/rimap-content/tests/snapshots/
git commit -m "test(content): add corpus fixtures for offscreen evasion, unparsable href, Reply-To

Three new adversarial corpus fixtures with insta snapshots:
- html-offscreen-evasion: left:-999px + translateX(-9999px)
- html-anchor-unparsable-href: PSL-unresolvable href with brand text
- lookalike-reply-to-mismatch: Cyrillic homograph in Reply-To domain

Part of #51 items 4-5 and #50 item 1.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: `build.rs` strictness

**Files:**
- Modify: `crates/rimap-content/build.rs`

- [ ] **Step 1: Tighten the floor and fail on malformed rows**

In `crates/rimap-content/build.rs`, replace the `eprintln!` + `continue` for malformed targets (around line 60-65):

```rust
        let Some(target_string) = parse_codepoint_sequence(tgt) else {
            panic!(
                "build: malformed target at line {}: {raw_line}\n\
                 Bump EXPECTED_MIN and re-audit when regenerating \
                 from a new Unicode version.",
                lineno + 1
            );
        };
```

Replace the floor assertion at the bottom (around line 98-103):

```rust
    // Unicode 16.0 produces ~6355 MA rows. This floor catches silent
    // format drift that drops more than ~2.5% of entries. Bump this
    // value and re-audit when regenerating from a new Unicode version.
    assert!(
        seen.len() >= 6200,
        "build: suspiciously small confusables map ({} entries, \
         expected >= 6200) — is data/confusables.txt the right file?",
        seen.len()
    );
```

- [ ] **Step 2: Verify build succeeds**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo build --package rimap-content
```

Expected: builds successfully, `eprintln` output shows ~6355 entries.

- [ ] **Step 3: Run tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/build.rs
git commit -m "fix(content): tighten build.rs confusables row floor to 6200 + fail on malformed

Any malformed target row now panics the build instead of silently
skipping. Floor raised from >5000 to >=6200 (Unicode 16.0 has ~6355).

Closes #53 item 3.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: Charset proptest

**Files:**
- Create: `crates/rimap-content/tests/proptest_charset.rs`

- [ ] **Step 1: Write the proptest**

Create `crates/rimap-content/tests/proptest_charset.rs`:

```rust
//! Proptest property: arbitrary charset parameter strings passed to
//! `parse_message` always produce either a valid `Content` with UTF-8
//! `body_text` or a structured `ContentError` — never a panic.
//!
//! Runs at 10,000 cases.

use proptest::prelude::*;
use rimap_content::parse_message;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 10_000,
        max_shrink_iters: 10_000,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn charset_parameter_produces_valid_utf8_or_error(
        charset in "[a-zA-Z0-9_:. -]{0,40}"
    ) {
        let eml = format!(
            "From: test@example.com\r\n\
             Subject: charset test\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=\"{charset}\"\r\n\
             \r\n\
             Hello world\r\n"
        );
        match parse_message(eml.as_bytes()) {
            Ok(content) => {
                // body_text must be valid UTF-8 (it's a String, so
                // this is guaranteed by construction, but we verify
                // the content is non-panicking and reasonable).
                let _ = content.untrusted.body_text.len();
            }
            Err(_) => {
                // Structured error is acceptable.
            }
        }
    }
}
```

- [ ] **Step 2: Run the proptest**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content --test proptest_charset -- --nocapture
```

Expected: 10,000 cases pass.

- [ ] **Step 3: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add crates/rimap-content/tests/proptest_charset.rs
git commit -m "test(content): add charset parameter proptest (10k cases)

Arbitrary charset strings in Content-Type must produce valid UTF-8
output or a structured error, never a panic.

Closes #52 item 3.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: Supply-chain comment hygiene (#54)

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `deny.toml`
- Modify: `crates/rimap-content/Cargo.toml`
- Create: `crates/rimap-content/data/NOTICE`
- Modify: `scripts/check-forbidden-macros.sh`

- [ ] **Step 1: M1 — Add missing proc-macros to R10 provenance block**

In the root `Cargo.toml`, find the R10 provenance comment block (around the proc-macro enumeration, search for `phf_macros` or `derive_more-impl`). After the existing list, add:

```
# - yoke-derive 0.8.2 (unicode-org via ICU4X, pulled through idna_adapter)
# - zerofrom-derive 0.1.7 (unicode-org via ICU4X, pulled through idna_adapter)
# - zerovec-derive 0.11.3 (unicode-org via ICU4X, pulled through idna_adapter)
# - displaydoc 0.2.5 (unicode-org via ICU4X, pulled through idna_adapter)
```

- [ ] **Step 2: M2 — Rewrite `idna` line comment**

Find the `idna = "1.1.0"` line (line 118) and replace its comment block:

```toml
# First url/idna entry in the workspace. idna 1.x replaced in-crate
# Unicode tables with the ICU4X provider stack, pulling ~20 new
# transitive crates (icu_collections, icu_locale_core, icu_normalizer,
# icu_normalizer_data, icu_properties, icu_properties_data,
# icu_provider, idna_adapter, litemap, potential_utf, tinystr,
# writeable, yoke*, zerofrom*, zerotrie, zerovec*, utf8_iter,
# displaydoc). Accepted because ICU4X is the unicode-org canonical
# path; re-audit on any minor bump of the idna or icu_* family.
idna = "1.1.0"
```

- [ ] **Step 3: M3 — Rewrite `phf` default-features comment**

Find the `phf` line (line 152) and update the nearby comment to note:

```toml
# Our direct phf declaration disables defaults; phf_macros still
# enters the graph transitively via cssparser, which is acknowledged
# in the proc-macro enumeration above.
phf = { version = "0.13.1", default-features = false }
```

- [ ] **Step 4: L1 — Add caret-range comment to deny.toml skip-tree**

In `deny.toml`, before the `html5ever` skip-tree entry (around line 111), add:

```toml
    # NOTE: cargo-deny interprets bare version strings as caret ranges
    # (e.g., "0.35" matches ">=0.35.0, <0.36.0"). This is intentional
    # here — ammonia floats its own transitive html5ever pin.
```

- [ ] **Step 5: L2 — Add Unicode-DFS-2016 TODO to rimap-content Cargo.toml**

In `crates/rimap-content/Cargo.toml`, near the `license.workspace = true` line, add a comment:

```toml
# TODO: data/confusables.txt is licensed under Unicode-DFS-2016. If
# this crate is ever published to crates.io, update the license field
# to reflect the vendored data and add "Unicode-DFS-2016" to the
# workspace deny.toml allow list.
```

- [ ] **Step 6: L3 — Create NOTICE file**

Check the root NOTICE for the attribution text, then create `crates/rimap-content/data/NOTICE`:

```
Unicode Character Database — confusables.txt
Copyright (c) 1991-2024 Unicode, Inc. All rights reserved.

Licensed under the Unicode License v3 (Unicode-DFS-2016).
Full text: https://www.unicode.org/license.txt

Vendored from Unicode TR39 (Unicode 16.0).
```

- [ ] **Step 7: L4 — Add psl version pattern note**

In `deny.toml`, add a comment near the bottom or in the `[bans]` section:

```toml
# psl (via addr) uses a versioning scheme where the patch number
# tracks the Public Suffix List snapshot date (e.g. 2.1.200). This
# is legitimate but looks like a massive version bump to naive
# pattern matching.
```

- [ ] **Step 8: L5 — Tighten check-forbidden-macros.sh regex**

In `scripts/check-forbidden-macros.sh`, change line ~14:

From:
```bash
    grep -vE '(^|/)build\.rs$' ||
```

To:
```bash
    grep -vE '(^|/)crates/[^/]+/build\.rs$' ||
```

- [ ] **Step 9: Verify build + tests**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo test --package rimap-content
cargo deny check
```

Expected: all pass.

- [ ] **Step 10: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add Cargo.toml deny.toml crates/rimap-content/Cargo.toml \
  crates/rimap-content/data/NOTICE scripts/check-forbidden-macros.sh
git commit -m "chore: supply-chain comment hygiene from Sprint 4b review

M1: add 4 missing ICU4X proc-macros to R10 provenance block
M2: rewrite idna line comment to reflect actual baseline
M3: clarify phf_macros transitive entry via cssparser
L1: document caret-range semantics in deny.toml skip-tree
L2: add Unicode-DFS-2016 license TODO for vendored confusables.txt
L3: create rimap-content/data/NOTICE with Unicode attribution
L4: document psl version pattern
L5: tighten check-forbidden-macros.sh build.rs exemption regex

Closes #54.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: Mutants rerun + verification pass

**Files:**
- Modify: `docs/superpowers/mutants-survivors.md`

- [ ] **Step 1: Run just ci to verify everything is green**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
just ci
```

Expected: all green in ~2m 20s.

- [ ] **Step 2: Run mutants (long — ~76 min)**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
cargo mutants --package rimap-content --timeout 120
```

Expected: library kill rate >= 85%. Record the exact numbers.

- [ ] **Step 3: Update mutants-survivors.md**

Update `docs/superpowers/mutants-survivors.md` with:
- Sprint 5 Phase 1 run date
- Library kill rate
- Whole-crate kill rate
- New survivor list (if any new easy kills, add targeted tests in a follow-up)

- [ ] **Step 4: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add docs/superpowers/mutants-survivors.md
git commit -m "docs(content): update mutants-survivors.md with Sprint 5 Phase 1 numbers

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: Sprint 5 Phase 1 handoff doc

**Files:**
- Create: `docs/superpowers/plans/2026-04-10-sprint-5-phase1-handoff.md`

- [ ] **Step 1: Write handoff document**

Summarize what Phase 1 shipped: warning renames, new variants, ammonia hardening, bypass fixes (CDATA, double-extension, PSL skip, off-screen threshold), Reply-To plumbing, address extraction consistency, build.rs strictness, supply-chain comments, mutants verification. List test totals. Note any API findings or gotchas. State Phase 2 prerequisites.

- [ ] **Step 2: Commit**

```bash
cd /Users/dave/src/rusty-imap-mcp-sprint5
git add docs/superpowers/plans/2026-04-10-sprint-5-phase1-handoff.md
git commit -m "docs(sprint-5): Phase 1 handoff to Phase 2

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```
