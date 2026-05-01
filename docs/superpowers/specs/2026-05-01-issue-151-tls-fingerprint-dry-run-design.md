# Issue #151 — Display TLS cert fingerprint during `--dry-run` (design)

**Date:** 2026-05-01
**Branch:** `feat/issue-151-tls-fingerprint-dry-run`
**Issue:** [#151](https://github.com/randomparity/rusty-imap-mcp/issues/151)
**Severity:** LOW (UX / onboarding)

## Goal

Extend `--dry-run` to print the observed leaf-cert SHA-256 fingerprint per
account so operators can copy the value into `tls_fingerprint_sha256` in
`config.toml` without reaching for `openssl s_client`. Output adapts to three
cases: unpinned (onboarding), pinned-and-matched (confirmation), and
pinned-and-mismatched (diagnostic).

## Background

TLS pinning is wired end-to-end:

- `ConnectionConfig.pinned_fingerprint: Option<TlsFingerprint>` —
  `crates/rimap-imap/src/connection.rs:77`.
- `build_tls_config` returns a `TlsConfigBundle` whose `last_observed: Arc<OnceLock<TlsFingerprint>>`
  slot is populated by both `PinningVerifier` and `CapturingVerifier` on every
  cert verification — `crates/rimap-imap/src/tls.rs`.
- `connect_inner` enriches a TLS handshake error into
  `ImapError::Tls { observed, expected }` when both sides are known —
  `crates/rimap-imap/src/connection.rs:232-239`.

`#117` landed the TCP+TLS+CAPABILITY preflight at `--dry-run` time
(`crates/rimap-imap/src/preflight.rs`, invoked from
`crates/rimap-server/src/cli/dry_run.rs:80-99`). The remaining gap: the
fingerprint observed during that preflight is currently discarded — it lives
on the `TlsConfigBundle` constructed inside `probe_preflight` and goes out of
scope on return. Operators have no documented way to surface the value short
of running `openssl x509 -fingerprint -sha256` against the server cert.

The issue body's claim that mismatch already produces
`ImapError::Tls { observed, expected }` is true on the auth path (`connect_inner`)
but **not** the preflight path: `probe_preflight` propagates the raw rustls
error as `ImapError::TlsHandshake`. Closing the gap requires extending the
enrichment to both call sites.

Note: the issue body uses the TOML key `tls_fingerprint`. The actual config
key (per `docs/configuration.md:30`, `docs/quickstart-proton-bridge.md:72`,
`docs/multi-account.md:24`) is **`tls_fingerprint_sha256`**. All printed
strings and docs use the real key.

## Architecture

Three changes, in dependency order:

### 1. Extract a shared TLS-error enrichment helper

`connect_inner` in `crates/rimap-imap/src/connection.rs:232-239` currently
inlines the logic for converting a `rustls::Error` into `ImapError::Tls`
when the verifier captured a fingerprint and the caller had a pin. Extract
into a `pub(crate) fn`:

```rust
pub(crate) fn enrich_tls_handshake_error(
    err: ImapError,
    bundle: &TlsConfigBundle,
    pinned: Option<TlsFingerprint>,
) -> ImapError {
    let ImapError::TlsHandshake(_) = &err else { return err; };
    match (bundle.last_observed.get().copied(), pinned) {
        (Some(observed), Some(expected)) if observed != expected => {
            ImapError::Tls { observed, expected }
        }
        _ => err,
    }
}
```

Call from both `connect_inner` and `probe_preflight`. The existing
`connect_inner` mismatch test at `connection.rs:1140-1147` is the
regression gate — its expectations do not change.

### Unpinned-mode capture (TOFU)

`probe_preflight` uses two TLS-verifier modes:

- **Pinned**: when `cfg.pinned_fingerprint.is_some()`, build via
  `build_tls_config(...)`. The `PinningVerifier` bypasses chain
  validation and accepts only the configured fingerprint.
- **Unpinned + capture-only**: when `cfg.pinned_fingerprint.is_none()`,
  build via `build_tls_config_capture_only()`. The `CaptureOnlyVerifier`
  records the leaf-cert fingerprint and **always accepts** the cert.

The capture-only path is required so a self-signed cert (e.g., Proton
Bridge) does not abort the probe before the fingerprint can be surfaced
to the operator. The auth path (`Connection::connect_inner`) is
unaffected — it continues to use `build_tls_config(None)` with
webpki-roots in unpinned mode.

**Trust posture**: `--dry-run` against an unpinned config has the same
TOFU guarantee as running `openssl s_client` over the same network. A
network attacker's cert would be captured and reported as if it were
the server's. Quickstart docs already advise extracting the fingerprint
in a trusted environment; that guidance applies whether the operator
uses `--dry-run` or the openssl recipe.

### 2. Extend `PreflightInfo` and capture in `probe_preflight`

`PreflightInfo` is `#[non_exhaustive]`, so adding a field is non-breaking:

```rust
#[non_exhaustive]
pub struct PreflightInfo {
    pub capabilities: Vec<String>,
    pub tls_fingerprint: TlsFingerprint,  // new
}
```

In `probe_preflight`:

- After a successful CAPABILITY round-trip, read
  `bundle.last_observed.get().copied()`. The verifier runs before any
  `Ok` path, so the slot must be populated. If it is not (programming
  error), return `ImapError::TlsHandshake(rustls::Error::General(
  "verifier did not capture fingerprint"))` rather than panicking.
- On any error path that produced an `ImapError::TlsHandshake`, route
  through `enrich_tls_handshake_error` so a mismatch surfaces as
  `ImapError::Tls { observed, expected }`. The handshake-failure paths
  on lines 54-67 (`Tls`) and 62-67 (`Starttls`) need the enrichment;
  errors after handshake (greeting, CAPABILITY) do not.

### 3. Print three-case fingerprint section in dry-run

`crates/rimap-server/src/cli/dry_run.rs` currently prints `Capabilities`
on `Ok(info)` and `Capabilities ... unavailable (...)` on `Err(e)`.
Add a `TLS fingerprint (sha256):` section.

**Unpinned + ok** (operator is onboarding):

```text
TLS fingerprint (sha256):
  ab:cd:...:ef
  (add `tls_fingerprint_sha256 = "ab:cd:...:ef"` under [imap] in config.toml to pin)
```

**Pinned + match** (confirmation):

```text
TLS fingerprint (sha256):
  ab:cd:...:ef  (matches configured pin)
```

**Pinned + mismatch** (diagnostic — error path):

```text
TLS fingerprint (sha256):
  observed: ef:01:...:23
  expected: ab:cd:...:ef  (configured pin)
  hint: re-run the openssl command from the quickstart and update tls_fingerprint_sha256
```

The mismatch branch matches on `Err(ImapError::Tls { observed, expected })`.
Other error variants (`Connect`, `Timeout`, `TlsHandshake` for non-mismatch
reasons, `Protocol`) keep the existing `Capabilities (...): unavailable (e)`
line and **omit** the fingerprint section — there is no fingerprint to
print when the verifier never ran.

## Testing

The only real-handshake test infrastructure in the repo is the
Dovecot container harness in `crates/rimap-imap/tests/integration/`
(`ConnectedHarness::new(PinChoice)` in `support/connect.rs`,
`DovecotHarness` in `support/container.rs`). `tls_pinning.rs` uses
synthetic DER bytes only; there is no in-process rustls listener.
The issue's acceptance criterion ("integration test against the
project's Dovecot / Mailpit fixture") maps directly to the existing
harness. Tests split as follows:

### API contract — `crates/rimap-imap/tests/integration/dovecot.rs`

Two new tests using `ConnectedHarness`:

- `case_NN_probe_preflight_returns_observed_fingerprint`: build a
  `ConnectionConfig` from the harness with `pinned_fingerprint = None`,
  call `probe_preflight`, assert `info.tls_fingerprint ==
  harness.expected_fingerprint()` (the harness exposes the cert's
  SHA-256 via the `/shared/fingerprint.hex` file the container
  publishes).
- `case_NN_probe_preflight_mismatch_returns_typed_error`: pin a
  deliberately wrong fingerprint, assert the error is
  `ImapError::Tls { observed, expected }` with `observed ==
  harness.expected_fingerprint()` and `expected == wrong_hash`.

These run only when Docker/Podman is available (silent skip otherwise),
matching the rest of the Dovecot suite.

### Printer contract — unit tests in `crates/rimap-server/src/cli/dry_run.rs`

Extract the fingerprint-printing logic into a small pure function:

```rust
fn write_fingerprint_section<W: Write>(
    out: &mut W,
    result: &Result<PreflightInfo, ImapError>,
    pinned: Option<TlsFingerprint>,
) -> io::Result<()>
```

This function takes synthesized inputs and writes the three-case
output. Three new unit tests cover each branch:

- `write_fingerprint_section_unpinned_prints_paste_hint`: `pinned =
  None`, `Ok(info)` with a synthesized fingerprint; assert output
  contains `TLS fingerprint (sha256):`, the hex string, and
  `tls_fingerprint_sha256 =`.
- `write_fingerprint_section_pinned_match_prints_confirmation`:
  `pinned = Some(fp)`, `Ok(info)` with the same fingerprint; assert
  output contains `(matches configured pin)`.
- `write_fingerprint_section_pinned_mismatch_prints_diagnostic`:
  `pinned = Some(a)`, `Err(ImapError::Tls { observed: b, expected: a })`;
  assert output contains `observed:`, `expected:`, both hex values,
  and the `hint:` line.

The existing `dry_run_cli.rs` integration test gets a one-line
addition: assert that `TLS fingerprint (sha256):` appears in stdout
(or that the `unavailable` variant fires, since the test points at
an unreachable port). This is a smoke-level check, not the contract.

### Mutation testing

Run `cargo mutants --jobs 2` over the touched files (`preflight.rs`,
`connection.rs`, `dry_run.rs`) after the change lands and kill any
escaped mutants per the project's standing practice.

### Mutation testing

Run `cargo mutants --jobs 2` over the touched files (`preflight.rs`,
`connection.rs`, `dry_run.rs`) after the change lands and kill any
escaped mutants per the project's standing practice.

## Documentation

- `docs/quickstart-proton-bridge.md`: in the pinning step, add a
  primary path that says "run `rusty-imap-mcp --config config.toml
  --dry-run` and copy the value under `TLS fingerprint (sha256):`
  into `tls_fingerprint_sha256`". Keep the `openssl s_client | openssl
  x509 -fingerprint -sha256` recipe as a secondary fallback paragraph.
- `docs/quickstart-gmail.md`: parallel update if the file has a
  pinning step (Gmail uses CA-signed certs, so pinning is optional —
  documented but not required).
- `docs/configuration.md`: under the `tls_fingerprint_sha256` table
  row, add one sentence pointing to `--dry-run` as the canonical
  onboarding path.
- `crates/rimap-imap/src/preflight.rs` module doc: update the
  high-level summary to mention fingerprint capture.
- `crates/rimap-server/src/cli/dry_run.rs` module doc: add the
  `TLS fingerprint (sha256):` section to the sample output block.

## Out of scope

- `--pin-fingerprint` CLI flag. Pinning stays config-file-only,
  consistent with existing posture surface.
- Cert chain / issuer / subject / validity-date introspection. The
  fingerprint alone covers the immediate onboarding need.
- Fixing the report-and-continue exit-code gap noted in #117's
  acceptance criteria. The current `dry_run.rs` exits 0 even on
  preflight failure; #117's acceptance said non-zero on any account
  failure. This is an adjacent gap, separate PR.

## Risks

- **Auth-path regression from extracting `enrich_tls_handshake_error`.**
  The helper is a mechanical extraction of existing logic. The
  existing `connect_inner` mismatch test at `connection.rs:1140-1147`
  exercises the auth path and is the regression gate. Run
  `cargo test -p rimap-imap` before and after to confirm parity.
- **`bundle.last_observed.get()` returning `None` after a successful
  handshake** would indicate a rustls/verifier bug. Treat as a typed
  error (`ImapError::TlsHandshake(General(...))`), not a panic.
- **Public API change to `PreflightInfo`.** The struct is
  `#[non_exhaustive]`, so adding a field is source-compatible.
  Downstream callers that destructure with `..` (the only allowed
  pattern for `non_exhaustive` external structs) keep compiling.

## Acceptance criteria (from #151)

- [ ] `--dry-run` output contains a `TLS fingerprint (sha256):` section
  per account.
- [ ] The printed value matches what the server actually presented at
  handshake time (asserted by both `tls_pinning.rs` API test and
  `dry_run_cli.rs` CLI test).
- [ ] Docs updated — quickstart instructions reference `--dry-run` as
  the onboarding path.
