# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-05-01
**Tool:** `cargo-mutants` (run via `just mutants-crate <name>`)
**Scope:** Five trust-boundary crates — `rimap-content`, `rimap-authz`,
`rimap-audit`, `rimap-server`, `rimap-imap`. Other workspace crates are
out of scope per spec
[`2026-04-30-test-strategy-improvements-design.md`](../2026-04-30-test-strategy-improvements-design.md).

A survivor is recorded here when it is *not* a true bug in the test suite —
either because the mutation is mathematically equivalent to the original
code, or because it falls in a code path the spec explicitly classifies as
"plumbing, best-effort." Survivors that *are* test-suite gaps are killed by
adding a test, not annotated.

---

## `rimap-content`

**Last refresh:** 2026-05-01.
**Surviving mutants in non-`bin/` code:** 15.

Run summary (646 mutants total): 540 caught, 31 missed (15 outside
`src/bin/`, 16 inside), 11 timeout, 64 unviable. Every survivor
outside `src/bin/` is a mathematically equivalent mutation
documented in the table below; the 16 `src/bin/epvme_runner.rs`
survivors are out of scope for this work.

The follow-up plan
[`2026-04-30-rimap-content-mutation-cleanup-followup.md`](../../plans/2026-04-30-rimap-content-mutation-cleanup-followup.md)
drives this list to zero. The table below records every survivor whose
mutation is mathematically equivalent to the original code — those are kept
behind a `// cargo-mutants: known-equivalent — <rationale>` comment at the
annotation site. Survivors that are real test-suite gaps are killed by
adding a test, not annotated, and so do not appear here.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `parse/mime_scrub.rs:105` | `replace + with * in detect_smuggling_spans` (`scan_from = end_rel_to_header + 1`) | The `+ 1` and `* 1` versions point the next `=?` search at adjacent bytes; both find the same next encoded-word at the same absolute position because `windows(2).position` shifts the relative offset by 1 to compensate. | `parse/mime_scrub.rs:96` |
| `parse/mime_scrub.rs:149` | `replace < with <= in locate_encoded_word_end` (`if start_offset < first.len()`) | At `start_offset == first.len()`, the empty `&first[start_offset..]` produces no `windows(2)` element, so the `let Some(rel)` guard short-circuits and the function falls through to the outer scan — identical to the `<` branch. | `parse/mime_scrub.rs:143` |
| `parse/mime_scrub.rs:213` | `replace < with > in split_header_lines` (`if line_start < headers.len()`) | The inner loop's only exit invariant is `line_start == headers.len()` — the `None` branch of the `\n` search sets `line_end = headers.len()` and the subsequent push sets `line_start = line_end`. On exit, the predicate is false under both `<` and `>`; the trailing push is defensive dead code in current usage. | `parse/mime_scrub.rs:206` |
| `html/style_parse.rs:74` | `replace < with <= in parse_translate_px` (`if px_val < current`) | The `<` and `<=` predicates differ only when `px_val == current`; in that case both arms set `min = Some(px_val)` to a value already equal to `current`, leaving the running minimum unchanged. Distinct values pick the same minimum under either operator. | `html/style_parse.rs:67` |
| `html/mismatch.rs:65` | `replace || with && in extract_registrable_domain` (`if host.is_empty() || !host.contains('.')`) | The `||` and `&&` predicates differ only when `host.is_empty()=false && !host.contains('.')=true` — a non-empty single-label host. Both branches then route control through the idna+addr lookup, which returns `None` for any single-label host (no registrable domain exists above a TLD). The opposite case (`is_empty=true && !contains('.')=false`) is unreachable: an empty string contains no `.`. | `html/mismatch.rs:56` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the first `||` between `is_ascii_digit()` and `c == '-'`) | Each char that the original `continue`s past — ASCII digits, `-`, `_` — has `Script::Common`, which the match below treats as a no-op. Whether the loop short-circuits via `continue` or runs through to the match, the `scripts` set membership is unchanged. | `lookalike.rs:103` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the second `||` between `c == '-'` and `c == '_'`) | Same reasoning as the first `||` mutation: the chars that the guard short-circuits on all classify as `Script::Common`, ignored by the match arm. | `lookalike.rs:103` |
| `lookalike.rs:195` | `replace > with >= in scan_body_urls` (`while end > 0 && !is_char_boundary(end)`) | The loop also exits via `!is_char_boundary(end)=false` when `end` reaches a boundary, and `is_char_boundary(0)=true` always. The `>` and `>=` predicates therefore produce the same exit point in every reachable trajectory. | `lookalike.rs:190` |
| `lookalike.rs:205` | `replace -= with += in scan_body_urls` (`end -= 1` inside the char-boundary back-off loop) | The backward walk lands on the previous boundary; the forward walk lands on the next boundary. The window between those two boundaries spans exactly one UTF-8 multi-byte codepoint (max 4 bytes), too small to fit any URL token. linkify's verdict on the resulting slice is therefore identical: any URL is either fully inside both slices or fully outside both. | `lookalike.rs:196` |
| `lookalike.rs:237` | `replace < with <= in extract_domain_from_address` (`lt < gt`) | `lt == gt` is unreachable when both `rfind` results are `Some`: a single byte cannot be both `<` and `>`. Distinct positions exercise the same arm under either operator. | `lookalike.rs:231` |
| `lookalike.rs:245` | `replace + with * in extract_domain_from_address` (`&trimmed[lt + 1..gt]`) | `lt * 1 == lt` shifts the slice start by one byte to include the `<` delimiter; `rsplit_once('@')` then yields the same `(local, domain)` split because the leading `<` lands in the discarded local part, not the domain on the right of `@`. | `lookalike.rs:239` |
| `lookalike.rs:285` | `replace || with && in extract_domain_from_url` (`if host.is_empty() || !host.contains('.')`) | Same equivalence as `html/mismatch.rs:65`: the only difference between `||` and `&&` is on non-empty single-label hosts, which `classify_domain` filters out anyway because no registrable PSL match exists above a TLD. | `lookalike.rs:277` |
| `raw_parts.rs:71` | `replace > with == in walk` (`if depth > MAX_MIME_DEPTH`) | `parse_message` already rejects messages whose MIME depth exceeds 8 (`MAX_MIME_DEPTH`) before any caller of `walk_attachment_parts` sees them. The 64-level defensive cap here therefore can never fire in production; `==` only differs from `>` at exactly `depth == 64`, which is unreachable. | `raw_parts.rs:62` |
| `raw_parts.rs:71` | `replace > with >= in walk` (same site) | Same reasoning as the `==` mutation: `>=` differs from `>` only on the unreachable range `depth in [64, max-tree-depth]`, which is gated out upstream by `parse_message`'s 8-level depth limit. | `raw_parts.rs:62` |
| `raw_parts.rs:96` | `replace + with * in walk` (`walk(msg, child_idx, &child_id, out, depth + 1)?`) | `depth * 1 == depth` keeps the recursion depth at 0 forever, but mail_parser-reachable trees are bounded by `parse_message`'s 8-level depth limit, so both `+ 1` and `* 1` walk to the same set of leaves before recursion bottoms out on `sub_parts() == None`. | `raw_parts.rs:84` |

### `bin/epvme_runner.rs`

**Last refresh:** YYYY-MM-DD (replace with today's date when committing Task 9).
**Surviving mutants:** N (replace with the line count of
`/tmp/mutation-cleanup-193/bin-survivors.txt` from Task 1 — every
surviving mutant either has a row in the table below (annotated as
`known-equivalent`) or has been killed by a test added in Tasks 4–8).

Issue [#193](https://github.com/randomparity/rusty-imap-mcp/issues/193)
drives this list to zero. Triage bar: a mutation that affects the
dataset's pass/fail signal (counts in `RunSummary`, `is_success`, the
process exit code) or the JSON summary schema is killed by adding a
test; everything else (stdout phrasing, log-style summary lines,
diagnostic-only counter ordering) is annotated as `known-equivalent`
with a one-line rationale.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `bin/epvme_runner.rs:186` | `replace usage -> String with String::new()` | usage() output is consumed only as stderr text; no test or production caller asserts its content. Mutation leaves exit codes and JSON schema unchanged. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:186` | `replace usage -> String with "xyzzy".into()` | Same rationale as the String::new mutation — stderr-only diagnostic text. | `bin/epvme_runner.rs:185` |
| `bin/epvme_runner.rs:381` | `delete ! in print_summary` (`if !summary.parse_error_counts.is_empty()` guard) | Guard inversion would print "Parse error kinds:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:377` |
| `bin/epvme_runner.rs:392` | `delete ! in print_summary` (`if !summary.warning_counts.is_empty()` guard) | Guard inversion would print "Warning counts:" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:388` |
| `bin/epvme_runner.rs:403` | `delete ! in print_summary` (`if !summary.recorded_failures.is_empty()` guard) | Guard inversion would print "Recorded failures (showing up to 50):" header with zero rows; stdout phrasing only, JSON schema unaffected. | `bin/epvme_runner.rs:399` |

The other four trust-boundary crates (`rimap-authz`, `rimap-audit`,
`rimap-server`, `rimap-imap`) get their own sections here when Sprints
B2–B3 land.
