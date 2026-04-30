# Test Strategy Improvements — April 2026

**Status:** Draft 2026-04-30
**Scope:** Three test-strategy gaps in `rusty-imap-mcp` v1.x — fuzzing
infrastructure (`cargo-fuzz` + OSS-Fuzz), targeted mutation hardening on
trust-boundary crates, and macOS-Apple-Silicon Dovecot-integration enablement.
This spec drives a family of four sprint-shaped implementation plans, not a
single monolithic plan.

## Table of Contents

1. [Goals & Non-Goals](#1-goals--non-goals)
2. [Current State](#2-current-state)
3. [Architecture & Cross-Cutting Infrastructure](#3-architecture--cross-cutting-infrastructure)
4. [Sprint B1 — `rimap-content` Fuzz + Mutation](#4-sprint-b1--rimap-content-fuzz--mutation)
5. [Sprint B2 — `rimap-authz` + `rimap-audit`](#5-sprint-b2--rimap-authz--rimap-audit)
6. [Sprint B3 — `rimap-server` + `rimap-imap`](#6-sprint-b3--rimap-server--rimap-imap)
7. [Sprint B4 — OSS-Fuzz Upstream + macOS Integration](#7-sprint-b4--oss-fuzz-upstream--macos-integration)
8. [Cross-Cutting Concerns](#8-cross-cutting-concerns)
9. [Next Steps](#9-next-steps)

---

## 1. Goals & Non-Goals

### Goals

- Add coverage-guided fuzzing to every untrusted-input boundary the codebase
  owns, with continuous fuzzing infrastructure in CI.
- Refresh the `cargo-mutants` baseline (last run 2026-04-08, 3+ weeks stale)
  and kill every surviving mutant in security-critical paths of the five
  trust-boundary crates (`rimap-content`, `rimap-authz`, `rimap-audit`,
  `rimap-server`, `rimap-imap`).
- Enable Dovecot integration tests on macOS Apple Silicon developer hosts and
  in CI, eliminating the silent-skip path that today hides regressions from
  Apple-Silicon developers until they reach the Linux CI runner.
- Sequence the work as four small, independently mergeable sprints keyed to
  trust boundaries, mirroring the pattern from
  `2026-04-19-open-issues-roadmap-design.md`.

### Non-Goals

- Mutation-score CI gate. Targeted hardening (per-crate cleanup) is the
  scope; promotion to a CI gate requires at least one quarter of stable
  baseline data and is out of scope here.
- Criterion benchmarks. Listed as deferred in
  `2026-04-08-sprint-4b-html-lookalike-design.md`; no consumer signals it as
  a current need.
- Differential HTML-sanitizer oracle. Genuinely valuable but warrants its
  own spec; not bundled here.
- Property tests beyond the existing five harnesses in `rimap-content`.
  Lower-value than fuzzing for the other crates; revisit if mutation
  cleanup surfaces a bug class better caught by proptest.
- Dovecot 2.4 config migration unless the B4 spike requires it (Path A is
  reactive, not speculative).
- Public corpus persistence outside OSS-Fuzz's own infrastructure.

---

## 2. Current State

**Test surface today.** 42 integration test files across the eight member
crates (~6,142 LOC of tests vs. 157 source files). Layers:

- **Unit + integration:** in-crate `#[cfg(test)]` modules plus `tests/` per
  crate.
- **Property tests** via `proptest` — 10,000 cases on the
  `rimap-content` Unicode and HTML pipelines, plus charset and lookalike
  properties.
- **Snapshot tests** via `insta` for sanitizer output.
- **Adversarial corpus** at `tests/injection-corpus/` — 24+ `.eml` fixtures
  with `expected.json` declaring required security warnings and forbidden
  content. Corpus only grows.
- **Container integration** via a docker-or-podman autodetect harness in
  `crates/rimap-imap/tests/integration/dovecot/`. Skips silently on
  non-x86_64 hosts because the pinned `dovecot/dovecot:2.3.21` image is
  amd64-only.
- **Proton Bridge integration** behind `PROTON_BRIDGE_TEST=1` (local-only).
- **`cargo-mutants`** has been run once (2026-04-08); `mutants.out/missed.txt`
  records 111 surviving mutants. 67 of those are in non-binary
  `rimap-content` code; the remainder are in the `epvme_runner` diagnostic
  binary.
- **Coverage** via `cargo-llvm-cov` in the SonarQube CI job.

**Gaps targeted by this spec.**

- **Fuzzing.** `cargo-fuzz` is referenced as deferred in three earlier specs
  (Sprint 4b, Sprint 5 phase 1, Sprint 5 phase 2) but no harnesses, `fuzz/`
  directory, or fuzz CI job exist.
- **Mutation.** The 2026-04-08 snapshot is stale; main has had heavy churn
  since (`desloppify` review batches, BootError introduction, daemon
  transport, rotation clock seam). A targeted refresh on trust-boundary
  crates will surface real survivors today.
- **macOS integration.** `DovecotHarness::check_prerequisites` returns
  `DockerUnavailable` on any host where `std::env::consts::ARCH != "x86_64"`,
  so Apple Silicon developers and `macos-latest` CI both silently skip the
  Dovecot suite. The pinned dovecot 2.3.21 image is amd64-only; the current
  multi-arch `dovecot/dovecot:2.4.x` line ships both `linux/amd64` and
  `linux/arm64`.

---

## 3. Architecture & Cross-Cutting Infrastructure

### 3.1 Workspace layout addition

A new top-level `fuzz/` directory holds the `cargo-fuzz` crate. It is
deliberately **not** a workspace member — `cargo-fuzz` is nightly-only and
does not need to compile under stable.

```
fuzz/
├── Cargo.toml          # standalone, links libfuzzer-sys and the crates under test
├── fuzz_targets/
│   ├── content_mime.rs
│   ├── content_html.rs
│   ├── content_rfc2047.rs
│   ├── content_charset.rs
│   ├── audit_jsonl.rs
│   └── server_jsonrpc.rs
└── corpus/
    └── <target>/       # seed corpora, version-controlled
```

The workspace root `Cargo.toml` gets `exclude = ["fuzz"]` so
`cargo build --workspace` does not pull `libfuzzer-sys`.

### 3.2 Mutation testing layout

`cargo-mutants` runs are per-crate (`cargo mutants --package <crate>`) rather
than workspace-wide. Per-crate baseline survivor lists are documented at
`docs/superpowers/specs/test-strategy/mutation-baseline.md`. The runtime
scratch directory `mutants.out/` stays gitignored (already configured); only
the curated baseline doc is committed.

### 3.3 CI changes (cumulative across sprints)

- **`.github/workflows/fuzz.yml`** — new file. `cfl-build` and `cfl-fuzz`
  jobs from ClusterFuzzLite. Triggered on `pull_request` (10-min smoke
  per target subset) and `schedule` (60-min nightly on `main`). All
  pinned to ClusterFuzzLite SHAs per existing zizmor policy. Corpus
  persisted to a private GitHub Actions cache, not pushed back to the
  repo.
- **`.github/workflows/mutants.yml`** — new file. `cargo-mutants` targeted,
  `workflow_dispatch` only initially. Promotion to scheduled or required
  is explicitly out of scope (see Section 8).
- **`.github/workflows/ci.yml`** — unchanged in B1–B3. Sprint B4 adds
  `test (macOS, integration)` to the existing matrix.

### 3.4 Justfile additions

```
fuzz TARGET *ARGS:                    # cargo +nightly fuzz run TARGET ARGS
    cd fuzz && cargo +nightly fuzz run {{TARGET}} -- -max_total_time=30 {{ARGS}}

fuzz-list:                             # enumerate harnesses
    cd fuzz && cargo +nightly fuzz list

mutants-crate CRATE:                   # targeted mutation run
    cargo mutants --package {{CRATE}} --no-shuffle
```

### 3.5 OSS-Fuzz prerequisites

- Maintainer email plus GPG key for vulnerability disclosures.
- Project description for `project.yaml` `homepage` and `main_repo`.
- License confirmation: project is dual-licensed Apache-2.0/MIT; both are
  OSS-Fuzz-acceptable.

The upstream PR happens in Sprint B4; B1–B3 build the prerequisites.

### 3.6 Trust-boundary mapping

Each fuzz target maps to exactly one crate's untrusted-input boundary so a
crash report fingerprint immediately identifies the responsible owner.

| Target | Crate | Boundary |
| --- | --- | --- |
| `content_mime` | rimap-content | `mail-parser` feed of raw bytes |
| `content_html` | rimap-content | HTML→text sanitizer entry |
| `content_rfc2047` | rimap-content | encoded-word header decoder |
| `content_charset` | rimap-content | charset label + bytes → UTF-8 |
| `audit_jsonl` | rimap-audit | JSONL line parser + redactor |
| `server_jsonrpc` | rimap-server | JSON-RPC envelope + dispatch |

`rimap-authz` and `rimap-imap` intentionally have no fuzz targets — their
input surfaces are typed enums or already-fuzzed upstream wire formats. See
Sprints B2 and B3 for the rationale.

---

## 4. Sprint B1 — `rimap-content` Fuzz + Mutation

**Goal.** Land four `cargo-fuzz` harnesses for the trust boundary that
consumes adversarial email content, refresh `cargo-mutants` on this crate,
and kill every surviving mutant in non-binary code.

### 4.1 Fuzz harnesses

| Target | Entry point | Asserted invariants |
| --- | --- | --- |
| `content_mime` | `rimap_content::parse::parse_message(raw: &[u8])` | No panic; respects existing depth/size caps in `parse::limits`; no unbounded allocation. |
| `content_html` | `rimap_content::html::sanitize_html(input: &str)` | Already proptested; libfuzzer's coverage-guided exploration finds different bugs. Output never re-introduces a stripped tag. |
| `content_rfc2047` | `rimap_content::parse::header::decode_encoded_word(raw: &[u8])` | The CRLF-smuggling fixture in `tests/injection-corpus/` proves this is a real attack class — output never contains an unescaped CRLF. |
| `content_charset` | `rimap_content::parse::charset::decode(label: &str, bytes: &[u8])` | Drives label parsing and decoding side-by-side. No panic on garbage labels. |

### 4.2 Seed corpora

- `content_mime`: every `.eml` from `tests/injection-corpus/` and
  `crates/rimap-imap/tests/integration/dovecot/fixtures/` (24+ + 3 files).
- `content_html`: HTML bodies extracted from the corpus, plus a small
  one-time pull of W3C HTML5 conformance edge cases.
- `content_rfc2047`: header lines extracted from the same corpus plus
  RFC 2047 examples.
- `content_charset`: 50–100 short `(label, bytes)` pairs covering every
  charset in `encoding_rs`'s named set plus a handful of garbage labels.

The `epvme_runner` 200-message dataset is **not** copied into seed corpora —
fuzz seeds need to be small (libfuzzer prefers <4 KB) and minimized.

### 4.3 Mutation cleanup

67 of the 111 stale survivors live in `crates/rimap-content/src/` outside
`bin/`. Refresh against current `main` first (the snapshot is
false-positive-prone), then triage:

- **`parse/`, `html/`, `unicode.rs`, `lookalike.rs`** — kill all surviving
  mutants.
- **`output.rs`, `error.rs`, `raw_parts.rs`, `testutil.rs`** — kill if the
  surviving mutant changes observable behavior; document equivalent mutants
  with `// cargo-mutants: known-equivalent` comments and a one-line
  rationale.
- **`bin/epvme_runner.rs`** — survivors stay open. Diagnostic tooling, not
  production.

### 4.4 ClusterFuzzLite wiring

The PR-smoke job runs `content_mime` plus `content_html` for 5 minutes each
on every PR. The other two `content_*` targets stay nightly-only — their
input space is largely subsumed by `content_mime`'s deeper code paths, so
adding them to PR-smoke costs runner minutes without buying meaningful new
coverage. Nightly job runs all four targets at 30 minutes each. Crashes
upload to GHA artifacts; reproducer files persist 90 days.

### 4.5 Done criteria

1. `just fuzz content_mime` runs locally for ≥ 5 minutes without finding a
   new crash.
2. Same for the other three targets.
3. `cargo mutants --package rimap-content` reports 0 surviving mutants in
   non-`bin/` code, or every survivor has a `known-equivalent` annotation
   with rationale.
4. ClusterFuzzLite smoke job is green on the PR.
5. `mutation-baseline.md` documents the new state.

### 4.6 Rough size

~7–10 PR-sized commits on one focused branch: 4 fuzz-harness commits (one
per target with seed corpus), 1 ClusterFuzzLite-config commit, 1
mutation-baseline-refresh commit, ~3 mutation-fix commits batched by module.

---

## 5. Sprint B2 — `rimap-authz` + `rimap-audit`

**Goal.** Land the audit-log JSONL fuzz harness, refresh `cargo-mutants` on
both crates, kill survivors. Lighter than B1 — the input surfaces are
narrower.

### 5.1 Fuzz harness

| Target | Entry point | Asserted invariants |
| --- | --- | --- |
| `audit_jsonl` | `rimap_audit::reader::parse_line(raw: &[u8])` plus `rimap_audit::redact::redact(record: AuditRecord)` | Parse failures are clean errors, not panics; redacted output round-trips through serde without losing the redaction marker; no original-secret bytes appear in redacted output (substring check against the input). |

### 5.2 No fuzz target for `rimap-authz`

The crate's input boundary is already-typed values (`Posture`, `ToolName`,
`RateLimiterClock`). The matrix lookup is a pure function of two enums.
Fuzzing typed enum inputs is enumeration, which `cargo-mutants` already
exercises better. If a textual config form of the matrix is added, that
becomes a future fuzz target.

### 5.3 Seed corpus for `audit_jsonl`

- Real audit-log lines captured during the existing daemon-Dovecot
  integration tests (one-time extract, sanitized, ~50 lines).
- Hand-crafted edge cases: truncated JSON, unknown `kind`, missing required
  fields, oversized strings, NUL bytes, BOMs, mixed line endings, embedded
  newlines inside strings.

### 5.4 Mutation cleanup

The stale snapshot reports zero survivors in either crate, but predates
several commits (desloppify review batches, BootError, rotation clock seam).
Refresh will likely surface new survivors.

1. **Refresh first.** `cargo mutants --package rimap-authz` and
   `cargo mutants --package rimap-audit` against current `main`.
2. **Kill all survivors in security-sensitive paths:**
   - `rimap-authz`: `matrix.rs`, `breaker.rs`, `rate_limit.rs`,
     `folder_guard.rs`, `folder_name.rs`.
   - `rimap-audit`: `writer/`, `redact/`, `reader/`.
3. **Best-effort on plumbing:** `cancellation.rs`, `fs.rs`, `record/`. Kill
   survivors that change observable output; annotate equivalent mutants with
   rationale.

### 5.5 ClusterFuzzLite wiring

`audit_jsonl` joins the PR-smoke set (now 3 targets at 5 min each = ~15 min
PR-smoke; under the CFL budget). Nightly run includes it at 30 min.

### 5.6 Why these two crates together

Both are pure-Rust with no IMAP/network dependencies, and both feed the same
audit-record type. A change in `rimap-audit::record` shapes affects what
`rimap-authz` decisions get logged; bundling them surfaces that coupling in
one review. They're also the smallest two trust-boundary crates — keeping
B2 small leaves headroom for B3, which is the heaviest sprint.

### 5.7 Done criteria

1. `just fuzz audit_jsonl` runs ≥ 5 minutes locally without crash.
2. `cargo mutants --package rimap-audit` reports 0 unannotated survivors.
3. `cargo mutants --package rimap-authz` reports 0 unannotated survivors.
4. CFL PR-smoke is green with all 3 targets.
5. `mutation-baseline.md` updated.

### 5.8 Rough size

~5 commits: 1 fuzz harness + corpus, 1 baseline refresh, 2 mutation-fix
commits (one per crate), 1 CFL-config bump.

---

## 6. Sprint B3 — `rimap-server` + `rimap-imap`

**Goal.** Land the JSON-RPC envelope fuzz harness, refresh `cargo-mutants`
on both crates, kill survivors in security-sensitive paths.

### 6.1 Fuzz harness

| Target | Entry point | Asserted invariants |
| --- | --- | --- |
| `server_jsonrpc` | `rimap_server::mcp::dispatch::handle_request(raw: &[u8])` (or the lowest-level public bytes-to-response shim — wrap if necessary) | No panic; every accepted request produces a serializable `Response`; rejected requests return a structured error code; the stub `ToolCallSink` never receives a tool name absent from the active posture. |

If `handle_request` is not currently a public entry point, B3's first commit
refactors the dispatch entry point to expose a `pub(crate)` byte-buffer shim
usable from the fuzz crate via the `test-util` feature pattern that
`rimap-content` already uses. The harness runs synchronously with a stub
`ToolCallSink`, never a live IMAP connection.

### 6.2 No fuzz target for `rimap-imap`

The crate is pure transport — its inputs are typed `ConnectionConfig` values
and the wire bytes are consumed by upstream `async-imap`. Fuzzing the IMAP
wire side fuzzes async-imap, not this crate. The TLS verifier's input is
structured (`&[CertificateDer]`) and rustls itself is heavily fuzzed
upstream. Mutation testing covers the surface adequately.

### 6.3 Seed corpus for `server_jsonrpc`

- Captured request/response pairs from the existing `dispatch_ticket.rs`
  and `e2e.rs` integration tests (one-time extract, ~30–50 envelopes
  covering each of the 24 `ToolName` variants).
- Hand-crafted edge cases: oversized fields, deeply nested JSON, unknown
  method names, malformed `id` field, batch requests, requests with extra
  fields.

### 6.4 Mutation cleanup

The stale snapshot reports zero survivors in either crate, but `rimap-server`
has had heavy churn (the entire daemon transport landed after April 8). The
refresh will surface real work.

**`rimap-server` security-critical paths — kill all unannotated survivors:**

- `mcp/dispatch.rs` (request routing, posture enforcement).
- `mcp/posture_context.rs` (active-posture decision).
- `mcp/audit_envelope.rs` (audit-record construction).
- `mcp/tool_catalog.rs`, `mcp/tool_name.rs` (tool advertisement,
  posture-gated visibility).
- `daemon/transport*.rs` (wire framing).
- `daemon/audit_sink.rs` (cross-process audit forwarding).
- `boot/`, `daemon/run.rs` (startup paths that touch credentials).
- `shim.rs` (process boundary).

**`rimap-server` plumbing — best-effort:** `cli/`, `daemon/state.rs`,
`daemon/shutdown.rs`. Survivors there change observable behavior but not
security posture; kill the easy ones, annotate the rest.

**`rimap-imap` security-critical paths — kill all unannotated survivors:**

- `tls.rs` (custom `ServerCertVerifier`).
- `auth.rs`.
- `connection.rs` (state machine for IDLE / reconnect).
- `ops/` (FETCH / SEARCH / APPEND wrappers — UID arithmetic and literal-size
  handling).
- `preflight.rs`.

**`rimap-imap` plumbing — best-effort:** `error.rs`, `types.rs`, `time.rs`,
`special_use.rs`, `test_support.rs`.

### 6.5 ClusterFuzzLite wiring

`server_jsonrpc` joins the PR-smoke set. PR-smoke now exercises 4 of 6
targets — the remaining two are the `content_*` targets from B1 that stay on
nightly to keep PR-smoke under 30 min. By end of B3, the full 6-target
nightly is live.

### 6.6 Done criteria

1. `just fuzz server_jsonrpc` runs ≥ 5 minutes locally without crash.
2. `cargo mutants --package rimap-server` reports 0 unannotated survivors in
   the security-critical paths above.
3. Same for `cargo mutants --package rimap-imap`.
4. CFL nightly is green and exercises all 6 targets.
5. `mutation-baseline.md` updated; the document now covers all four
   trust-boundary crates.

### 6.7 Rough size

~10 commits — heaviest sprint. 1 dispatch-entry-point refactor (if needed),
1 fuzz harness + corpus, 1 baseline refresh, ~5 mutation-fix commits split
by module (dispatch+posture, transport, TLS, ops, plumbing), 1 CFL-config
bump, 1 doc update.

---

## 7. Sprint B4 — OSS-Fuzz Upstream + macOS Integration

**Goal.** Land the OSS-Fuzz upstream submission and unblock the
macOS-Apple-Silicon integration test path. Pairing them is deliberate —
both are external-facing and lower-risk to land late: the value of every
prior sprint is captured even if B4 slips.

### 7.1 OSS-Fuzz upstream submission

#### Prerequisite check

Before the upstream PR opens, B1–B3 must be complete: 6 fuzz targets exist,
ClusterFuzzLite has been running ≥ 1 full nightly cycle on `main` without
crashes, and the mutation baseline doc is current. OSS-Fuzz reviewers ask
"is the project actively fuzzed and the harnesses maintained?" — those are
the answer.

#### Upstream PR contents

A new `projects/rusty-imap-mcp/` directory in `google/oss-fuzz`:

```
projects/rusty-imap-mcp/
├── project.yaml      # language: rust; sanitizers: address; fuzzing_engines: libfuzzer
├── Dockerfile        # FROM gcr.io/oss-fuzz-base/base-builder-rust; clones our repo
└── build.sh          # cd fuzz && cargo +nightly fuzz build --release
```

`project.yaml` declares:

- `homepage`: this repo's URL.
- `main_repo`: same.
- `auto_ccs`: maintainer email(s) for crash notifications.
- `vendor_ccs`: empty (no downstream vendor).
- `language: rust`, `sanitizers: [address]`,
  `fuzzing_engines: [libfuzzer]` (the only engine `cargo-fuzz` supports).

#### Local-side support

A new `oss-fuzz/` directory in this repo mirrors what the upstream PR will
reference. Two files: `oss-fuzz-build.sh` and `oss-fuzz-Dockerfile.fragment`.
Keeping these in-tree gives maintainers a single place to edit when a fuzz
target is added/renamed and prevents drift between the OSS-Fuzz upstream and
this project.

#### `SECURITY.md` update

Add a "Reporting fuzz-discovered crashes" subsection: OSS-Fuzz crashes are
reported to the `auto_ccs` list with a 90-day disclosure clock; the existing
vuln-disclosure policy already covers that timeline, but the source of the
bug needs to be unambiguous.

#### Acceptance handling

OSS-Fuzz acceptance is upstream's call. The plan includes opening the PR,
responding to reviewer feedback for one round, and accepting the outcome.
If acceptance is deferred, the done criterion is "PR is open and awaiting
upstream review" — not "PR is merged."

### 7.2 macOS-Apple-Silicon integration

#### Step 1 — spike

A 30–60 minute test:

1. Set `RIMAP_REQUIRE_DOCKER=1` and remove the `ARCH != "x86_64"` guard
   locally (do not commit).
2. Run `just test-integration` (or the rimap-imap dovecot integration suite
   directly).
3. Observe: does the existing `dovecot/dovecot:2.3.21` image run under
   Docker Desktop's Rosetta-for-Linux on this host? If yes, are dovecot's
   worker processes stable across the full suite?

#### Step 2 — fork

- **Path B (Rosetta works):** single PR. Remove the `ARCH != "x86_64"`
  guard. Add a `RIMAP_DOVECOT_PLATFORM` env var that defaults to host arch
  but can be set to `linux/amd64` to force Rosetta. Add a small CI matrix
  entry — `test (macOS, integration)` on `macos-latest` with the Dovecot
  suite enabled. Document the requirement (Docker Desktop ≥ 4.16,
  Rosetta-for-Linux enabled) in the `AGENTS.md` "Container runtime for
  integration tests" section.
- **Path A (Rosetta still crashes):** two-PR sequence. PR-1 bumps the image
  to `dovecot/dovecot:2.4.x` (multi-arch native), migrates `dovecot.conf` to
  2.4 syntax, validates that the existing Linux integration suite stays
  green. PR-2 (after PR-1 merges) removes the arch guard and adds the
  `test (macOS, integration)` CI job.

The decision between Path A and Path B is recorded inline in the spike
commit message; it's a one-test-run question, not a planning question.

#### CI runner cost

Adding `test (macOS, integration)` is a real cost — macOS minutes are ~10×
the Linux rate. Mitigations:

- Run on `pull_request` only when files in `crates/rimap-imap/` change
  (`paths:` filter), plus a nightly cron.
- Single concurrency group so two PRs do not both pin a macOS runner.
- Job is non-blocking initially (`continue-on-error: true`). Promote to
  required only after two consecutive weeks of green runs. Acceptable here
  because the Linux integration suite already provides the load-bearing
  signal — the macOS run is incremental hardening.

### 7.3 Done criteria

1. OSS-Fuzz upstream PR open with all three files; reviewer engagement
   begun.
2. `oss-fuzz-build.sh` and `oss-fuzz-Dockerfile.fragment` committed in-tree.
3. `SECURITY.md` updated with fuzz-disclosure subsection.
4. Spike result documented; chosen path (A or B) implemented.
5. `test (macOS, integration)` CI job exists and ran green at least once.
6. `AGENTS.md` "Container runtime for integration tests" section updated.

### 7.4 Rough size

~6 commits: 1 oss-fuzz/ directory commit, 1 SECURITY.md update, 1
spike-result documentation commit, 1 macOS CI job commit, 1 docs sync
commit, 1 (Path A only) image-bump commit.

---

## 8. Cross-Cutting Concerns

### 8.1 Out of scope (explicit deferrals)

- **Criterion benchmarks.** Mentioned as deferred in
  `2026-04-08-sprint-4b-html-lookalike-design.md`. Performance regressions
  are detectable today via Sonar's coverage delta and `cargo nextest`
  runtime; criterion adds a maintenance burden without a clear consumer.
  Re-evaluate post-B4 if a real perf bug ships.
- **Differential HTML oracle.** Comparing `ammonia`/`scraper` output against
  a second sanitizer (e.g., `html5ever` raw). Genuinely valuable, but
  defining "equivalent sanitization" between two engines is a sprint of its
  own.
- **Mutation-score CI gate.** Targeted hardening was the chosen scope.
  Promotion to a CI gate requires at least one quarter of stable
  baseline data to set a non-flaky threshold.
- **Property tests beyond `rimap-content`.** Adding proptest harnesses to
  `rimap-authz`, `rimap-audit`, `rimap-imap` is reasonable but lower-value
  than fuzzing for those crates. Revisit if mutation cleanup surfaces a bug
  class better caught by proptest.
- **Dovecot 2.4 config migration unless the B4 spike requires it.** Path A
  is reactive, not speculative.
- **Public corpus persistence outside OSS-Fuzz's own infrastructure.**
  OSS-Fuzz manages its own corpus per accepted project; the project does
  not run a parallel public corpus.

### 8.2 Success metrics

1. **Fuzzing.** All 6 targets pass a 30-min nightly run on `main` for two
   consecutive weeks. OSS-Fuzz PR open. ClusterFuzzLite green on every PR
   for one full sprint cycle.
2. **Mutation.** `cargo mutants --package <crate>` reports 0 unannotated
   survivors in security-critical paths of all five trust-boundary crates
   (`rimap-content`, `rimap-authz`, `rimap-audit`, `rimap-server`,
   `rimap-imap`). `mutation-baseline.md` is current as of the latest tagged
   release.
3. **macOS integration.** `test (macOS, integration)` exists and runs green
   nightly. Local Apple-Silicon developers can run `just test-integration`
   without setting bypass env vars.
4. **No regressions.** `just ci` runtime grows by less than 20% across the
   full plan. PR-smoke fuzz time stays under 30 min total.

### 8.3 Risks and mitigations

- **OSS-Fuzz acceptance is upstream's decision.** Mitigation: the
  done-criterion is "PR open + reviewer engaged," not "merged."
  ClusterFuzzLite captures the runtime value independently.
- **macOS CI minutes cost overrun.** Mitigation: `paths:` filter + nightly
  cron + initial `continue-on-error: true`; promote to required only after
  two clean weeks.
- **Mutation refresh discovers many survivors in B2/B3.** Likely — the
  snapshot is 3+ weeks stale. Mitigation: each sprint's done-criterion is
  "0 survivors *in named security-critical paths*", not "0 survivors
  anywhere." Plumbing-code survivors get annotated, not fixed.
- **Nightly runner exhaustion at peak GHA load.** Mitigation: nightly fuzz
  job is a single concurrency group with retry-once-on-runner-pickup-timeout.
- **Adding a fuzz target later requires editing both `fuzz/` and
  `oss-fuzz/`.** Mitigation: short `oss-fuzz/README.md` with "when adding
  a target, also add it to..." checklist.

### 8.4 Why this ordering

B1 first because `rimap-content` is the largest attacker-surface crate and
has the largest backlog of stale mutants. B2 second because it is the
smallest sprint — landing it after B1 keeps momentum without burning the
budget needed for B3. B3 third because the dispatch-entry-point refactor it
may need is the only structural change in the plan and benefits from the
mutation-cleanup discipline practiced in B1/B2 first. B4 last because
OSS-Fuzz acceptance benefits from a non-empty fuzzing track record on
`main`, and macOS integration is the only piece that touches CI runner cost
materially — landing it last minimizes blast radius.

---

## 9. Next Steps

1. Land this spec on `main` via the standard feature-branch + PR workflow.
2. Generate per-sprint implementation plans on demand via the
   `superpowers:writing-plans` skill, one per sprint (B1, B2, B3, B4).
   Each plan is independently mergeable; sprints sequence by dependency
   (B3 may depend on B2's audit-record refactor work, B4 depends on B1–B3
   being live).
3. Open tracking issues for the deferrals listed in Section 8.1 so they
   are visible in the issues list rather than buried in this spec.
