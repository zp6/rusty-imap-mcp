# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-05-01
**Tool:** `cargo-mutants` (run via `just mutants-crate <name>`)
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

**Last refresh:** 2026-05-01.
**Surviving mutants in non-`bin/` code:** 15.

Run summary (646 mutants total): 540 caught, 31 missed (15 outside
`src/bin/`, 16 inside), 11 timeout, 64 unviable. Every survivor
outside `src/bin/` is a mathematically equivalent mutation
documented in the table below; the 16 `src/bin/epvme_runner.rs`
survivors are out of scope for this work.

The follow-up plan
[`archive: 2026-04-30-rimap-content-mutation-cleanup-followup.md`](https://github.com/randomparity/rusty-imap-mcp/blob/archive/daemon-experiment/docs/superpowers/plans/2026-04-30-rimap-content-mutation-cleanup-followup.md) (superseded by docs/superpowers/plans/2026-05-03-issue-225-rimap-content-mutation-waves-rextract.md)
drives this list to zero. The table below records every survivor whose
mutation is mathematically equivalent to the original code — those are kept
behind a `// cargo-mutants: known-equivalent — <rationale>` comment at the
annotation site. Survivors that are real test-suite gaps are killed by
adding a test, not annotated, and so do not appear here.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| `parse/mime_scrub.rs:130` | `replace < with <= in locate_encoded_word_end` (`if start_offset < first.len()`) | At `start_offset == first.len()`, the empty `&first[start_offset..]` produces no `windows(2)` element, so the `let Some(rel)` guard short-circuits and the function falls through to the outer scan — identical to the `<` branch. | `parse/mime_scrub.rs:124` |
| `parse/mime_scrub.rs:187` | `replace < with > in split_header_lines` (`if line_start < headers.len()`) | The inner loop's only exit invariant is `line_start == headers.len()` — the `None` branch of the `\n` search sets `line_end = headers.len()` and the subsequent push sets `line_start = line_end`. On exit, the predicate is false under both `<` and `>`; the trailing push is defensive dead code in current usage. | `parse/mime_scrub.rs:180` |
| `html/style_parse.rs:74` | `replace < with <= in parse_translate_px` (`if px_val < current`) | The `<` and `<=` predicates differ only when `px_val == current`; in that case both arms set `min = Some(px_val)` to a value already equal to `current`, leaving the running minimum unchanged. Distinct values pick the same minimum under either operator. | `html/style_parse.rs:68` |
| `html/mismatch.rs:51` | `replace || with && in extract_registrable_domain` (`if host.is_empty() || !host.contains('.')`) | The `||` and `&&` predicates differ only when `host.is_empty()=false && !host.contains('.')=true` — a non-empty single-label host. Both branches then route control through the idna+addr lookup, which returns `None` for any single-label host (no registrable domain exists above a TLD). The opposite case (`is_empty=true && !contains('.')=false`) is unreachable: an empty string contains no `.`. | `html/mismatch.rs:43` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the first `||` between `is_ascii_digit()` and `c == '-'`) | Each char that the original `continue`s past — ASCII digits, `-`, `_` — has `Script::Common`, which the match below treats as a no-op. Whether the loop short-circuits via `continue` or runs through to the match, the `scripts` set membership is unchanged. | `lookalike.rs:103` |
| `lookalike.rs:110` | `replace || with && in label_mixes_scripts` (the second `||` between `c == '-'` and `c == '_'`) | Same reasoning as the first `||` mutation: the chars that the guard short-circuits on all classify as `Script::Common`, ignored by the match arm. | `lookalike.rs:103` |
| `lookalike.rs:220` | `replace < with <= in extract_domain_from_address` (`lt < gt`) | `lt == gt` is unreachable when both `rfind` results are `Some`: a single byte cannot be both `<` and `>`. Distinct positions exercise the same arm under either operator. | `lookalike.rs:214` |
| `lookalike.rs:228` | `replace + with * in extract_domain_from_address` (`&trimmed[lt + 1..gt]`) | `lt * 1 == lt` shifts the slice start by one byte to include the `<` delimiter; `rsplit_once('@')` then yields the same `(local, domain)` split because the leading `<` lands in the discarded local part, not the domain on the right of `@`. | `lookalike.rs:222` |
| `lookalike.rs:268` | `replace || with && in extract_domain_from_url` (`if host.is_empty() || !host.contains('.')`) | Same equivalence as `html/mismatch.rs:51`: the only difference between `||` and `&&` is on non-empty single-label hosts, which `classify_domain` filters out anyway because no registrable PSL match exists above a TLD. | `lookalike.rs:260` |
| `raw_parts.rs:71` | `replace > with == in walk` (`if depth > MAX_MIME_DEPTH`) | `parse_message` already rejects messages whose MIME depth exceeds 8 (`MAX_MIME_DEPTH`) before any caller of `walk_attachment_parts` sees them. The 64-level defensive cap here therefore can never fire in production; `==` only differs from `>` at exactly `depth == 64`, which is unreachable. | `raw_parts.rs:62` |
| `raw_parts.rs:71` | `replace > with >= in walk` (same site) | Same reasoning as the `==` mutation: `>=` differs from `>` only on the unreachable range `depth in [64, max-tree-depth]`, which is gated out upstream by `parse_message`'s 8-level depth limit. | `raw_parts.rs:62` |
| `raw_parts.rs:96` | `replace + with * in walk` (`walk(msg, child_idx, &child_id, out, depth + 1)?`) | `depth * 1 == depth` keeps the recursion depth at 0 forever, but mail_parser-reachable trees are bounded by `parse_message`'s 8-level depth limit, so both `+ 1` and `* 1` walk to the same set of leaves before recursion bottoms out on `sub_parts() == None`. | `raw_parts.rs:89` |

The `bin/epvme_runner.rs` survivors are out of scope — that crate is
diagnostic tooling, not production. Re-evaluate post-B4.

The other four trust-boundary crates (`rimap-authz`, `rimap-audit`,
`rimap-server`, `rimap-imap`) get their own sections here when Sprints
B2–B3 land.
