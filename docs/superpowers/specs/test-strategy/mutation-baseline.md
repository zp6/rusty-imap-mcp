# Mutation-baseline — Targeted-trust-boundary survivor inventory

**Updated:** 2026-04-30
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

**Last refresh:** 2026-04-30.
**Surviving mutants in non-`bin/` code:** 80.

> **Cap exceeded.** B1's mutation cleanup is scoped to "manageable inline
> cleanup," with a 30-survivor cap defined in the plan. The refreshed run
> recorded 80 survivors outside `src/bin/`, well above that threshold, so
> Tasks 8 and 9 are deferred to a follow-up plan. The full survivor list
> for this run is preserved at `/tmp/rimap-content-survivors.txt` on the
> author's machine and in `mutants.out/missed.txt` for this commit; per-file
> breakdown is summarised in the table below. Fuzz harnesses (Task 6,
> already shipped in PR #190) and ClusterFuzzLite wiring (Task 10) still
> ship in this sprint.

| File:line | Mutation | Reason kept | Annotation site |
|---|---|---|---|
| _populated by Task 8/9_ |  |  |  |

Per-file survivor counts at 2026-04-30 refresh (for sizing the follow-up
plan):

| File | Survivors |
|---|---:|
| `src/lookalike.rs` | 14 |
| `src/parse/filename.rs` | 10 |
| `src/parse/bodies.rs` | 9 |
| `src/html/style_parse.rs` | 8 |
| `src/parse/headers.rs` | 7 |
| `src/html/mismatch.rs` | 7 |
| `src/parse/mime_scrub.rs` | 6 |
| `src/threading.rs` | 4 |
| `src/raw_parts.rs` | 3 |
| `src/lib.rs` | 3 |
| `src/html/mod.rs` | 3 |
| `src/parse/mod.rs` | 2 |
| `src/unicode.rs` | 1 |
| `src/parse/meta.rs` | 1 |
| `src/parse/attachments.rs` | 1 |
| `src/html/extract.rs` | 1 |
| **Total** | **80** |

Run summary (646 mutants total): 479 caught, 96 missed (80 outside
`src/bin/`, 16 inside), 8 timeout, 63 unviable.

The `bin/epvme_runner.rs` survivors are out of scope for B1 — that crate is
diagnostic tooling, not production. Re-evaluate post-B4.

## `rimap-authz`

_Populated in Sprint B2._

## `rimap-audit`

_Populated in Sprint B2._

## `rimap-server`

_Populated in Sprint B3._

## `rimap-imap`

_Populated in Sprint B3._
