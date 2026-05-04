# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-05-04
**Tool:** `cargo-mutants` (run via `just mutants --package <name>`)
**Scope:** Five trust-boundary crates — `rimap-content`, `rimap-authz`,
`rimap-audit`, `rimap-server`, `rimap-imap`. Other workspace crates are
out of scope per spec
[`archive: 2026-04-30-test-strategy-improvements-design.md`](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/specs/2026-04-30-test-strategy-improvements-design.md).

A survivor is recorded here when it is *not* a true bug in the test suite —
either because the mutation is mathematically equivalent to the original
code, or because it falls in a code path the spec explicitly classifies as
"plumbing, best-effort." Survivors that *are* test-suite gaps are killed by
adding a test, not annotated.

---

## `rimap-content`

**Last refresh:** 2026-05-04.
**Surviving mutants in non-`bin/` code:** 14.

Run summary (652 mutants total, 2026-05-04 full single-threaded run
via `just mutants --package rimap-content`): 566 caught, 16 missed, 6
timeout, 64 unviable in 40 minutes wall clock. Three of the 19
known-equivalent rows below report "caught" in this run only because
a flaky callsite-cache interaction in
`parse::safe_parser::tests::log_parser_panic_emits_structured_tracing_event`
([#239](https://github.com/randomparity/rusty-imap-mcp/issues/239))
fails the per-mutant runs for `lookalike.rs:220` (`< with <=`),
`lookalike.rs:228` (`+ with *`), and `bin/epvme_runner.rs:189`
(`"xyzzy".into()`); the mutations themselves remain genuinely
mathematically equivalent. Counting all 19 the deterministic
survivor floor is 14 outside `src/bin/` and 5 inside. Every
non-`bin/` survivor is a mathematically equivalent mutation
documented in the table below; the 5 `src/bin/epvme_runner.rs`
survivors are documented in the `### bin/epvme_runner.rs` subsection
below (issue #193 took the original 16 to 5 by killing 11 with tests
and annotating the rest). Issue #236 killed three post-archive
survivors in `testutil.rs` and `parse/mime_scrub.rs` and added two
new known-equivalent rows for the `> with >=` mutations on the
`MAX_ANCHOR_TEXT_SCAN` truncation guards in `html/mismatch.rs`.

The follow-up plan
[`archive: 2026-04-30-rimap-content-mutation-cleanup-followup.md`](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/plans/2026-04-30-rimap-content-mutation-cleanup-followup.md)
drove the non-`bin/` list to zero. The table below records every
survivor whose mutation is mathematically equivalent to the original
code — those are kept behind a `// cargo-mutants: known-equivalent —
<rationale>` comment at the annotation site. Survivors that are real
test-suite gaps are killed by adding a test, not annotated, and so do
not appear here.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `parse/mime_scrub.rs:130` | `replace < with <= in locate_encoded_word_end` (`if start_offset < first.len()`) | At `start_offset == first.len()`, the empty `&first[start_offset..]` produces no `windows(2)` element, so the `let Some(rel)` guard short-circuits and the function falls through to the outer scan — identical to the `<` branch. | `parse/mime_scrub.rs:124` |
| `parse/mime_scrub.rs:187` | `replace < with > in split_header_lines` (`if line_start < headers.len()`) | The inner loop's only exit invariant is `line_start == headers.len()` — the `None` branch of the `\n` search sets `line_end = headers.len()` and the subsequent push sets `line_start = line_end`. On exit, the predicate is false under both `<` and `>`; the trailing push is defensive dead code in current usage. | `parse/mime_scrub.rs:180` |
| `html/style_parse.rs:74` | `replace < with <= in parse_translate_px` (`if px_val < current`) | The `<` and `<=` predicates differ only when `px_val == current`; in that case both arms set `min = Some(px_val)` to a value already equal to `current`, leaving the running minimum unchanged. Distinct values pick the same minimum under either operator. | `html/style_parse.rs:68` |
| `html/mismatch.rs:51` | `replace || with && in extract_registrable_domain` (`if host.is_empty() || !host.contains('.')`) | The `||` and `&&` predicates differ only when `host.is_empty()=false && !host.contains('.')=true` — a non-empty single-label host. Both branches then route control through the idna+addr lookup, which returns `None` for any single-label host (no registrable domain exists above a TLD). The opposite case (`is_empty=true && !contains('.')=false`) is unreachable: an empty string contains no `.`. | `html/mismatch.rs:43` |
| `html/mismatch.rs:107` | `replace > with >= in detect_mismatches` (unparsable-href branch `if text.len() > MAX_ANCHOR_TEXT_SCAN`) | `>` and `>=` differ only at `text.len() == MAX_ANCHOR_TEXT_SCAN`. In that case, `String::truncate(MAX_ANCHOR_TEXT_SCAN)` is a documented no-op (does nothing when `new_len >= len`), so the predicate flip produces no observable change in `text` or in the downstream linkify scan. | `html/mismatch.rs:101` |
| `html/mismatch.rs:123` | `replace > with >= in detect_mismatches` (parsable-href branch `if text.len() > MAX_ANCHOR_TEXT_SCAN`) | Same reasoning as the unparsable-branch row above: `truncate(MAX_ANCHOR_TEXT_SCAN)` is a no-op at the boundary value, so the operator flip is observably equivalent. | `html/mismatch.rs:119` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the first `||` between `is_ascii_digit()` and `c == '-'`) | Each char that the original `continue`s past — ASCII digits, `-`, `_` — has `Script::Common`, which the match below treats as a no-op. Whether the loop short-circuits via `continue` or runs through to the match, the `scripts` set membership is unchanged. | `lookalike.rs:103` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the second `||` between `c == '-'` and `c == '_'`) | Same reasoning as the first `||` mutation: the chars that the guard short-circuits on all classify as `Script::Common`, ignored by the match arm. | `lookalike.rs:103` |
| `lookalike.rs:220` | `replace < with <= in extract_domain_from_address` (`lt < gt`) | `lt == gt` is unreachable when both `rfind` results are `Some`: a single byte cannot be both `<` and `>`. Distinct positions exercise the same arm under either operator. | `lookalike.rs:214` |
| `lookalike.rs:228` | `replace + with * in extract_domain_from_address` (`&trimmed[lt + 1..gt]`) | `lt * 1 == lt` shifts the slice start by one byte to include the `<` delimiter; `rsplit_once('@')` then yields the same `(local, domain)` split because the leading `<` lands in the discarded local part, not the domain on the right of `@`. | `lookalike.rs:222` |
| `lookalike.rs:268` | `replace || with && in extract_domain_from_url` (`if host.is_empty() || !host.contains('.')`) | Same equivalence as `html/mismatch.rs:51`: the only difference between `||` and `&&` is on non-empty single-label hosts, which `classify_domain` filters out anyway because no registrable PSL match exists above a TLD. | `lookalike.rs:260` |
| `raw_parts.rs:71` | `replace > with == in walk` (`if depth > MAX_MIME_DEPTH`) | `parse_message` already rejects messages whose MIME depth exceeds 8 (`MAX_MIME_DEPTH`) before any caller of `walk_attachment_parts` sees them. The 64-level defensive cap here therefore can never fire in production; `==` only differs from `>` at exactly `depth == 64`, which is unreachable. | `raw_parts.rs:62` |
| `raw_parts.rs:71` | `replace > with >= in walk` (same site) | Same reasoning as the `==` mutation: `>=` differs from `>` only on the unreachable range `depth in [64, max-tree-depth]`, which is gated out upstream by `parse_message`'s 8-level depth limit. | `raw_parts.rs:62` |
| `raw_parts.rs:96` | `replace + with * in walk` (`walk(msg, child_idx, &child_id, out, depth + 1)?`) | `depth * 1 == depth` keeps the recursion depth at 0 forever, but mail_parser-reachable trees are bounded by `parse_message`'s 8-level depth limit, so both `+ 1` and `* 1` walk to the same set of leaves before recursion bottoms out on `sub_parts() == None`. | `raw_parts.rs:89` |

### `bin/epvme_runner.rs`

**Last refresh:** 2026-05-01.
**Surviving mutants:** 5 (all annotated as `known-equivalent`; 11 of
the 16 mutations recorded in the 2026-04-30 baseline were killed by
tests added under issue #193).

Issue [#193](https://github.com/randomparity/rusty-imap-mcp/issues/193)
drove this list to its current state. Triage bar: a mutation that
affects the dataset's pass/fail signal (counts in `RunSummary`,
`is_success`, the process exit code) or the JSON summary schema was
killed by adding a test; everything else (stdout phrasing, log-style
summary lines, diagnostic-only counter ordering) is annotated as
`known-equivalent` with a one-line rationale.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `bin/epvme_runner.rs:189` | `replace usage -> String with String::new()` | usage() output is consumed only as stderr text; no test or production caller asserts its content. Mutation leaves exit codes and JSON schema unchanged. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:189` | `replace usage -> String with "xyzzy".into()` | Same rationale as the String::new mutation — stderr-only diagnostic text. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:381` | `delete ! in print_summary` (`if !summary.parse_error_counts.is_empty()` guard) | Guard inversion would print "Parse error kinds:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:377` |
| `bin/epvme_runner.rs:392` | `delete ! in print_summary` (`if !summary.warning_counts.is_empty()` guard) | Guard inversion would print "Warning counts:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:388` |
| `bin/epvme_runner.rs:403` | `delete ! in print_summary` (`if !summary.recorded_failures.is_empty()` guard) | Guard inversion would print "Recorded failures (showing up to 50):" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:399` |

The other four trust-boundary crates (`rimap-authz`, `rimap-audit`,
`rimap-server`, `rimap-imap`) get their own sections here when Sprints
B2–B3 land.
