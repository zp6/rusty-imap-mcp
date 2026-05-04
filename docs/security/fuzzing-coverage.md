# Fuzzing and mutation-testing coverage

Tracks which security-sensitive modules have fuzz targets, which have
proptest strategies, and which have been surveyed by `cargo-mutants`.
Updated as part of every change to a "must fuzz" module.

## "Must fuzz" modules

These modules parse untrusted bytes from network or disk and are
load-bearing for security. A change here without an updated fuzz target
or proptest strategy is a review finding.

| Module | Fuzz target | Proptest strategy | Last cargo-mutants survey |
|---|---|---|---|
| `rimap-content` (MIME, HTML→text) | TBD (Sprint 4) | TBD | — |
| `rimap-imap::ops::fetch::compress_uid_set` | n/a | `crates/rimap-imap/src/ops/fetch.rs::tests::compress_round_trip_via_split` (added in #33) | — |
| `rimap-audit::self_check::read_trailing_state` | TBD | n/a (consumes serde_json which has its own coverage) | — |
| `rimap-audit::redact::Redactor::apply` | TBD | TBD | — |
| `rimap-audit::writer::AuditWriter::write_record` | n/a (no untrusted parser surface) | n/a | — |

## Adding a new "must fuzz" entry

When a new parser-of-untrusted-input lands:

1. Add a row to the table above with `TBD` for fuzz target and proptest.
2. File a `security-review` issue tagged `fuzzing-coverage` linking to the
   module path.
3. Update this file in the same PR that lands the fuzz target.

## Why Option A

A dedicated `fuzzing-coverage-reviewer` agent (Option B from #16) would
duplicate work that the existing `rust-safety-reviewer` already covers
at change-review time. Promoting to Option B is the right move only if
the discipline grows beyond ~10 modules or if the coverage drift becomes
hard to track manually.

## Cargo-mutants survey cadence

Once a quarter, run:

    just mutants --workspace --timeout 60 -- --test-threads 1

and update the "Last survey" column for any module whose mutation score
changed by more than 5%.

### Known issue (cargo-mutants 27.0.0)

Worker-tree corruption causes `<file> is not a file` mid-run on
macOS when the temp-copy mode is used (macOS `dirhelper` unlinks the
reflink copies introduced in cargo-mutants 26.0.0). The `--in-place`
flag baked into `just mutants` is required, not optional, until
upstream fix lands. See the
[cargo-mutants runbook](cargo-mutants-runbook.md). Tracking issues:
[#235](https://github.com/randomparity/rusty-imap-mcp/issues/235),
upstream [`sourcefrog/cargo-mutants#611`](https://github.com/sourcefrog/cargo-mutants/issues/611).
