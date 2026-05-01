# Issue #151 — TLS Fingerprint Dry-Run Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Print the observed leaf-cert SHA-256 fingerprint per account during `--dry-run` so operators can pin TLS without running `openssl s_client`.

**Architecture:** Extract a shared `enrich_tls_handshake_error` helper in `rimap-imap` (used by both the auth path and the preflight path) so a fingerprint mismatch produces `ImapError::Tls { observed, expected }` everywhere. Extend `PreflightInfo` with a `tls_fingerprint: TlsFingerprint` field captured from `bundle.last_observed`. Add a `write_fingerprint_section` printer to `dry_run.rs` with three branches (unpinned-onboard, pinned-match, pinned-mismatch).

**Tech Stack:** Rust 1.x stable, `tokio_rustls`, `async-imap`, `tracing`, `assert_cmd` for CLI tests, the existing Dovecot container harness for integration tests.

**Spec:** `docs/superpowers/specs/2026-05-01-issue-151-tls-fingerprint-dry-run-design.md`

---

## File Map

**Modified — production code:**
- `crates/rimap-imap/src/connection.rs` — extract `enrich_tls_handshake_error` helper from `connect_inner`'s inline match
- `crates/rimap-imap/src/preflight.rs` — extend `PreflightInfo` with `tls_fingerprint`; capture from bundle after handshake; route handshake errors through the enrichment helper
- `crates/rimap-server/src/cli/dry_run.rs` — add `write_fingerprint_section` printer; call from `run`

**Modified — tests:**
- `crates/rimap-imap/tests/integration/dovecot.rs` — two new test cases exercising preflight against the real Dovecot cert

**Modified — docs:**
- `docs/quickstart-proton-bridge.md` — promote `--dry-run` as the primary onboarding path; keep `openssl` recipe as fallback
- `docs/quickstart-gmail.md` — parallel update if it covers pinning
- `docs/configuration.md` — point to `--dry-run` under `tls_fingerprint_sha256`

---

## Task 1: Extract `enrich_tls_handshake_error` helper (refactor, no behavior change)

**Files:**
- Modify: `crates/rimap-imap/src/connection.rs:230-242`

**Why:** `connect_inner` and `probe_preflight` need the same logic for converting a generic `ImapError::TlsHandshake` into the typed `ImapError::Tls { observed, expected }` when both pin and observed fingerprint are known. Extract once, reuse twice.

- [ ] **Step 1: Read the current inline enrichment**

Run: `sed -n '220,245p' crates/rimap-imap/src/connection.rs`
Confirm the match arm at lines 230-242 reads as expected before refactoring.

- [ ] **Step 2: Add the helper function above `connect_inner`**

Locate the start of `impl Connection { ... async fn connect_inner ...` and add a free function (not a method) just before it, inside the same module. Free function — `probe_preflight` is in a different module and needs to call it without a `Connection` instance.

```rust
/// If `err` is `ImapError::TlsHandshake` and the bundle observed a fingerprint
/// that disagrees with `pinned`, rewrite into `ImapError::Tls { observed,
/// expected }`. Other error variants and matching observations pass through
/// unchanged. Used by both `connect_inner` and `probe_preflight` so the typed
/// mismatch error surfaces on every TLS-failing path.
pub(crate) fn enrich_tls_handshake_error(
    err: ImapError,
    bundle: &crate::tls::TlsConfigBundle,
    pinned: Option<rimap_core::TlsFingerprint>,
) -> ImapError {
    match err {
        ImapError::TlsHandshake(inner) => match (pinned, bundle.last_observed.get().copied()) {
            (Some(expected), Some(observed)) if expected != observed => {
                ImapError::Tls { observed, expected }
            }
            _ => ImapError::TlsHandshake(inner),
        },
        other => other,
    }
}
```

- [ ] **Step 3: Replace the inline match in `connect_inner`**

Replace lines 230-242 (the `let (outcome, credential_source) = match raw_outcome { ... };` block) with:

```rust
        let (outcome, credential_source) = match raw_outcome {
            Ok((session, src)) => (Ok(session), Some(src)),
            Err((err, src)) => (
                Err(enrich_tls_handshake_error(err, &bundle, cfg.pinned_fingerprint)),
                src,
            ),
        };
```

The behavior is identical: `enrich_tls_handshake_error` only rewrites `TlsHandshake` variants, so non-handshake errors pass through.

- [ ] **Step 4: Run the rimap-imap test suite — refactor must be a no-op**

Run: `cargo test -p rimap-imap --lib --tests`
Expected: all tests pass. Pay particular attention to the existing mismatch test at `connection.rs:1140-1147` — it must still produce `ImapError::Tls`.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-imap/src/connection.rs
git commit -m "refactor(rimap-imap): extract enrich_tls_handshake_error helper

Lifts the inline TlsHandshake → Tls { observed, expected } match out
of connect_inner into a free function so probe_preflight can reuse it.
No behavior change.

Refs: #151"
```

---

## Task 2: Add `tls_fingerprint` to `PreflightInfo` and capture in `probe_preflight`

**Files:**
- Modify: `crates/rimap-imap/src/preflight.rs:20-27` (struct), `crates/rimap-imap/src/preflight.rs:34-124` (function body)
- Test: `crates/rimap-imap/tests/integration/dovecot.rs` (new test case)

- [ ] **Step 1: Find the right test-case-number prefix**

Run: `rg -n "^async fn case_" crates/rimap-imap/tests/integration/dovecot.rs | tail -3`
Note the highest existing `case_NN_*` number; the new tests use the next two.

- [ ] **Step 2: Write the failing integration test**

Append to `crates/rimap-imap/tests/integration/dovecot.rs`. Substitute `NN` with the chosen number from Step 1.

```rust
#[tokio::test]
async fn case_NN_probe_preflight_returns_observed_fingerprint() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let cfg = rimap_imap::ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: support::container::DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: support::container::DovecotHarness::username().to_string(),
        pinned_fingerprint: None,
        connect_timeout: std::time::Duration::from_secs(10),
        command_timeout: std::time::Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let info = rimap_imap::preflight::probe_preflight(&cfg)
        .await
        .expect("preflight should succeed against the live harness");
    assert_eq!(info.tls_fingerprint, h.harness.pinned_fingerprint());
    assert!(!info.capabilities.is_empty());
}
```

- [ ] **Step 3: Run the test — expect compile error**

Run: `cargo test -p rimap-imap --test dovecot case_NN_probe_preflight_returns_observed_fingerprint`
Expected: compile error — `tls_fingerprint` is not a field of `PreflightInfo`.

(If Docker is unavailable, the test silently skips at runtime, but this step is checking compile-time. The compile error will fire regardless of Docker.)

- [ ] **Step 4: Add the `tls_fingerprint` field to `PreflightInfo`**

In `crates/rimap-imap/src/preflight.rs`, modify the struct (line ~20-27):

```rust
/// Result of a successful preflight probe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PreflightInfo {
    /// Capability atoms returned by the server's pre-auth `CAPABILITY`
    /// response, upper-cased, de-duplicated, order preserved as received.
    pub capabilities: Vec<String>,
    /// Leaf-cert SHA-256 fingerprint observed during the TLS handshake.
    /// Captured from the verifier's `last_observed` slot before any IMAP
    /// traffic flows.
    pub tls_fingerprint: rimap_core::TlsFingerprint,
}
```

- [ ] **Step 5: Capture the fingerprint in `probe_preflight`'s success path**

In `crates/rimap-imap/src/preflight.rs`, modify the final `Ok(...)` at line ~123. Read the slot from the bundle after the CAPABILITY round-trip succeeds. The verifier writes the slot during handshake — by the time CAPABILITY succeeds the slot is guaranteed populated, but treat `None` as a typed error instead of panicking.

Replace the function-final return:

```rust
    Ok(PreflightInfo { capabilities: caps })
```

with:

```rust
    let tls_fingerprint = bundle.last_observed.get().copied().ok_or_else(|| {
        ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(
            "verifier did not capture fingerprint".into(),
        ))
    })?;
    Ok(PreflightInfo {
        capabilities: caps,
        tls_fingerprint,
    })
```

- [ ] **Step 6: Run the test — expect pass (or silent skip without Docker)**

Run: `cargo test -p rimap-imap --test dovecot case_NN_probe_preflight_returns_observed_fingerprint`
Expected with Docker: PASS.
Expected without Docker: silent skip (no failure).

If you have neither Docker nor Podman, run a final compile check:
Run: `cargo build -p rimap-imap --tests`
Expected: clean compile.

- [ ] **Step 7: Run clippy**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add crates/rimap-imap/src/preflight.rs crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "feat(rimap-imap): expose observed TLS fingerprint via PreflightInfo

Adds PreflightInfo.tls_fingerprint, populated from the bundle's
last_observed slot after a successful handshake. New Dovecot
integration case asserts the captured value matches the harness's
known cert fingerprint.

Refs: #151"
```

---

## Task 3: Route `probe_preflight` errors through `enrich_tls_handshake_error`

**Files:**
- Modify: `crates/rimap-imap/src/preflight.rs:52-69` (the two handshake arms)
- Test: `crates/rimap-imap/tests/integration/dovecot.rs` (new test case)

**Why:** Today `probe_preflight` returns `ImapError::TlsHandshake(...)` on a fingerprint mismatch — the enrichment lives only in `connect_inner`. Route through the helper so callers see the typed `ImapError::Tls { observed, expected }` on the preflight path too.

- [ ] **Step 1: Write the failing integration test**

Append to `crates/rimap-imap/tests/integration/dovecot.rs` (use the next `case_NN+1` number):

```rust
#[tokio::test]
async fn case_NN_probe_preflight_mismatch_returns_typed_tls_error() {
    let Some(h) = boot(PinChoice::None) else {
        return;
    };
    let wrong = rimap_core::TlsFingerprint::from_cert_der(b"deliberately-wrong");
    let cfg = rimap_imap::ConnectionConfig {
        account: None,
        account_id: rimap_core::account::AccountId::default_account(),
        host: support::container::DovecotHarness::host().to_string(),
        port: h.harness.port(),
        encryption: rimap_imap::ImapEncryption::Tls,
        username: support::container::DovecotHarness::username().to_string(),
        pinned_fingerprint: Some(wrong),
        connect_timeout: std::time::Duration::from_secs(10),
        command_timeout: std::time::Duration::from_secs(10),
        max_fetch_body_bytes: 5_242_880,
        max_append_bytes: 10_485_760,
    };
    let err = rimap_imap::preflight::probe_preflight(&cfg)
        .await
        .expect_err("mismatched pin must produce an error");
    match err {
        ImapError::Tls { observed, expected } => {
            assert_eq!(observed, h.harness.pinned_fingerprint());
            assert_eq!(expected, wrong);
        }
        other => panic!("expected ImapError::Tls, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run the test — expect failure (with Docker) or skip-pass (without)**

Run: `cargo test -p rimap-imap --test dovecot case_NN_probe_preflight_mismatch_returns_typed_tls_error`
Expected with Docker: FAIL with `expected ImapError::Tls, got TlsHandshake(...)`.
Expected without Docker: silent skip.

- [ ] **Step 3: Wire enrichment into `probe_preflight`'s handshake error paths**

In `crates/rimap-imap/src/preflight.rs`, modify the two handshake match arms (around lines 52-69). The `tls_handshake` and `starttls_upgrade` calls return `ImapError::TlsHandshake(...)` on fingerprint mismatch; route through the helper.

Replace the existing match block:

```rust
    let (tls_stream, already_greeted) = match cfg.encryption {
        ImapEncryption::Tls => {
            let s = timeout(remaining, tls_handshake(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout {
                    op: "tls_handshake",
                })??;
            (s, false)
        }
        ImapEncryption::Starttls => {
            let s = timeout(remaining, starttls_upgrade(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout {
                    op: "starttls_upgrade",
                })??;
            (s, true)
        }
    };
```

with the enriched form:

```rust
    let (tls_stream, already_greeted) = match cfg.encryption {
        ImapEncryption::Tls => {
            let s = timeout(remaining, tls_handshake(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout {
                    op: "tls_handshake",
                })?
                .map_err(|e| {
                    crate::connection::enrich_tls_handshake_error(
                        e,
                        &bundle,
                        cfg.pinned_fingerprint,
                    )
                })?;
            (s, false)
        }
        ImapEncryption::Starttls => {
            let s = timeout(remaining, starttls_upgrade(tcp, &bundle, &cfg.host))
                .await
                .map_err(|_| ImapError::Timeout {
                    op: "starttls_upgrade",
                })?
                .map_err(|e| {
                    crate::connection::enrich_tls_handshake_error(
                        e,
                        &bundle,
                        cfg.pinned_fingerprint,
                    )
                })?;
            (s, true)
        }
    };
```

- [ ] **Step 4: Run the test — expect pass**

Run: `cargo test -p rimap-imap --test dovecot case_NN_probe_preflight_mismatch_returns_typed_tls_error`
Expected with Docker: PASS.
Expected without Docker: silent skip.

- [ ] **Step 5: Verify no regression in `case_NN` (the success case from Task 2)**

Run: `cargo test -p rimap-imap --test dovecot probe_preflight`
Expected: both new cases pass (or silent skip without Docker).

- [ ] **Step 6: Run clippy**

Run: `cargo clippy -p rimap-imap --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add crates/rimap-imap/src/preflight.rs crates/rimap-imap/tests/integration/dovecot.rs
git commit -m "feat(rimap-imap): enrich probe_preflight TLS errors with observed fingerprint

Routes both Tls and Starttls handshake error paths in probe_preflight
through enrich_tls_handshake_error so a fingerprint mismatch surfaces
as ImapError::Tls { observed, expected } — same shape as connect_inner.
New Dovecot integration case pins the typed-error contract.

Refs: #151"
```

---

## Task 4: Add `write_fingerprint_section` printer with three branches

**Files:**
- Modify: `crates/rimap-server/src/cli/dry_run.rs` (add helper + tests; not yet wired into `run`)

**Why:** Isolate the three-case output formatter into a pure function with synthesized inputs so each branch is unit-tested without standing up a real server.

- [ ] **Step 1: Write three failing unit tests**

In `crates/rimap-server/src/cli/dry_run.rs`, inside the existing `mod tests` block, add:

```rust
    use rimap_core::TlsFingerprint;
    use rimap_imap::error::ImapError;
    use rimap_imap::preflight::PreflightInfo;

    fn synth_fp(seed: &[u8]) -> TlsFingerprint {
        TlsFingerprint::from_cert_der(seed)
    }

    #[test]
    fn write_fingerprint_section_unpinned_prints_paste_hint() {
        let fp = synth_fp(b"unpinned-test");
        let info = PreflightInfo {
            capabilities: vec!["IMAP4REV1".into()],
            tls_fingerprint: fp,
        };
        let result: Result<PreflightInfo, ImapError> = Ok(info);
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("TLS fingerprint (sha256):"),
            "header missing:\n{text}"
        );
        assert!(text.contains(&fp.to_string()), "fingerprint missing:\n{text}");
        assert!(
            text.contains("tls_fingerprint_sha256 ="),
            "paste hint missing:\n{text}"
        );
    }

    #[test]
    fn write_fingerprint_section_pinned_match_prints_confirmation() {
        let fp = synth_fp(b"matched-pin");
        let info = PreflightInfo {
            capabilities: vec!["IMAP4REV1".into()],
            tls_fingerprint: fp,
        };
        let result: Result<PreflightInfo, ImapError> = Ok(info);
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, Some(fp)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("matches configured pin"),
            "match confirmation missing:\n{text}"
        );
        // Paste hint must NOT appear when already pinned-and-matched.
        assert!(
            !text.contains("tls_fingerprint_sha256 ="),
            "paste hint should not appear on match:\n{text}"
        );
    }

    #[test]
    fn write_fingerprint_section_pinned_mismatch_prints_diagnostic() {
        let observed = synth_fp(b"observed-cert");
        let expected = synth_fp(b"expected-pin");
        let result: Result<PreflightInfo, ImapError> = Err(ImapError::Tls { observed, expected });
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, Some(expected)).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("observed:"), "observed: missing:\n{text}");
        assert!(text.contains("expected:"), "expected: missing:\n{text}");
        assert!(
            text.contains(&observed.to_string()),
            "observed hex missing:\n{text}"
        );
        assert!(
            text.contains(&expected.to_string()),
            "expected hex missing:\n{text}"
        );
        assert!(text.contains("hint:"), "hint line missing:\n{text}");
    }

    #[test]
    fn write_fingerprint_section_other_error_prints_nothing() {
        let result: Result<PreflightInfo, ImapError> = Err(ImapError::Timeout { op: "tcp_connect" });
        let mut out = Vec::new();
        super::write_fingerprint_section(&mut out, &result, None).unwrap();
        assert!(out.is_empty(), "fingerprint section must be silent on non-TLS error");
    }
```

- [ ] **Step 2: Run the tests — expect compile error (function not yet defined)**

Run: `cargo test -p rimap-server --lib write_fingerprint_section`
Expected: compile error — `write_fingerprint_section` not found.

- [ ] **Step 3: Implement `write_fingerprint_section`**

In `crates/rimap-server/src/cli/dry_run.rs`, add the helper above `pub async fn run`:

```rust
/// Print the `TLS fingerprint (sha256):` section for one account, given the
/// preflight outcome and the (optional) pinned fingerprint from config. Three
/// branches:
///
/// - `Ok(info)` + no pin: print observed fingerprint with a paste-into-config
///   hint (onboarding path).
/// - `Ok(info)` + matching pin: print observed fingerprint with `(matches
///   configured pin)` confirmation.
/// - `Err(ImapError::Tls { observed, expected })`: print both values plus a
///   diagnostic hint pointing at the quickstart.
///
/// All other error variants (`Connect`, `Timeout`, `TlsHandshake` for
/// non-mismatch reasons, `Protocol`) silently print nothing — there is no
/// fingerprint to surface when the verifier never ran or the value is not
/// meaningfully informative.
fn write_fingerprint_section<W: std::io::Write>(
    out: &mut W,
    result: &Result<rimap_imap::preflight::PreflightInfo, rimap_imap::error::ImapError>,
    pinned: Option<rimap_core::TlsFingerprint>,
) -> std::io::Result<()> {
    match (result, pinned) {
        (Ok(info), None) => {
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  {}", info.tls_fingerprint)?;
            writeln!(
                out,
                "  (add `tls_fingerprint_sha256 = \"{}\"` under [imap] in config.toml to pin)",
                info.tls_fingerprint
            )?;
        }
        (Ok(info), Some(pin)) if info.tls_fingerprint == pin => {
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  {}  (matches configured pin)", info.tls_fingerprint)?;
        }
        (Ok(info), Some(_pin_mismatch_unreachable)) => {
            // A live mismatch should never reach here because `probe_preflight`
            // returns `Err(ImapError::Tls)` instead. Defensive branch: print
            // observed only.
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  {}", info.tls_fingerprint)?;
        }
        (Err(rimap_imap::error::ImapError::Tls { observed, expected }), _) => {
            writeln!(out, "TLS fingerprint (sha256):")?;
            writeln!(out, "  observed: {observed}")?;
            writeln!(out, "  expected: {expected}  (configured pin)")?;
            writeln!(
                out,
                "  hint: re-run the openssl command from the quickstart and update tls_fingerprint_sha256"
            )?;
        }
        (Err(_), _) => {
            // Connect / Timeout / TlsHandshake-non-mismatch / Protocol: nothing
            // to print. The capabilities-section already shows the error.
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Run the unit tests — expect pass**

Run: `cargo test -p rimap-server --lib write_fingerprint_section`
Expected: 4 tests pass.

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/cli/dry_run.rs
git commit -m "feat(rimap-server): add write_fingerprint_section printer for dry-run

Pure function with three branches (unpinned-onboard, pinned-match,
pinned-mismatch) and a defensive fourth branch for non-TLS errors.
Not yet wired into run() — that is the next task. Unit tests cover
all four branches with synthesized inputs.

Refs: #151"
```

---

## Task 5: Wire `write_fingerprint_section` into `run`

**Files:**
- Modify: `crates/rimap-server/src/cli/dry_run.rs` (the per-account loop in `run`)

- [ ] **Step 1: Modify `run` to call the new printer**

In `crates/rimap-server/src/cli/dry_run.rs`, locate the per-account loop (around lines 80-99) where `match rimap_imap::preflight::probe_preflight(&conn_cfg).await` lives. Today the match prints capabilities on `Ok` and an `unavailable` line on `Err`. Add the fingerprint section after the capabilities/unavailable line, regardless of which arm fired.

Replace the existing match:

```rust
        let conn_cfg = rimap_server::boot::registry::build_account_connection(id, acfg);
        match rimap_imap::preflight::probe_preflight(&conn_cfg).await {
            Ok(info) => {
                writeln!(out, "Capabilities ({}:{}):", conn_cfg.host, conn_cfg.port)?;
                for cap in &info.capabilities {
                    writeln!(out, "  [ok ] {cap}")?;
                }
            }
            Err(e) => {
                writeln!(
                    out,
                    "Capabilities ({}:{}): unavailable ({e})",
                    conn_cfg.host, conn_cfg.port,
                )?;
            }
        }
```

with:

```rust
        let conn_cfg = rimap_server::boot::registry::build_account_connection(id, acfg);
        let preflight_result = rimap_imap::preflight::probe_preflight(&conn_cfg).await;
        match &preflight_result {
            Ok(info) => {
                writeln!(out, "Capabilities ({}:{}):", conn_cfg.host, conn_cfg.port)?;
                for cap in &info.capabilities {
                    writeln!(out, "  [ok ] {cap}")?;
                }
            }
            Err(e) => {
                writeln!(
                    out,
                    "Capabilities ({}:{}): unavailable ({e})",
                    conn_cfg.host, conn_cfg.port,
                )?;
            }
        }
        write_fingerprint_section(out, &preflight_result, conn_cfg.pinned_fingerprint)?;
```

- [ ] **Step 2: Run the existing dry_run unit tests — expect still passing**

Run: `cargo test -p rimap-server --lib dry_run`
Expected: existing tests (`dry_run_prints_matrix_with_default_posture`, `second_dry_run_against_same_audit_fails_with_config_error`, `dry_run_lists_infrastructure_tools_separately`, `dry_run_surfaces_parse_errors_as_anyhow`) plus the four new printer tests all pass.

The existing tests run against `127.0.0.1:1143` with no listener. The preflight fails with `Connect`, the printer's "other error" branch fires (no fingerprint section), so the tests still match their assertions.

- [ ] **Step 3: Run the existing dry_run CLI integration tests**

Run: `cargo test -p rimap-server --test dry_run_cli`
Expected: all three existing CLI tests still pass.

- [ ] **Step 4: Update the module doc-comment to show the new section**

In `crates/rimap-server/src/cli/dry_run.rs`, modify the sample output block at the top of the file (lines 14-23) to include the fingerprint section. Replace:

```text
//! ```text
//! Effective matrix (posture = draft-safe)
//!   [ok ] list_folders
//!   [ok ] search
//!   [deny] search.advanced_query
//!   ...
//! Infrastructure tools (always available):
//!   [ok ] use_account
//!   [ok ] list_accounts
//! ```
```

with:

```text
//! ```text
//! Effective matrix (posture = draft-safe)
//!   [ok ] list_folders
//!   [ok ] search
//!   [deny] search.advanced_query
//!   ...
//! Infrastructure tools (always available):
//!   [ok ] use_account
//!   [ok ] list_accounts
//! Capabilities (imap.example.com:993):
//!   [ok ] IMAP4REV1
//!   [ok ] IDLE
//! TLS fingerprint (sha256):
//!   ab:cd:...:ef
//!   (add `tls_fingerprint_sha256 = "ab:cd:...:ef"` under [imap] in config.toml to pin)
//! ```
```

- [ ] **Step 5: Run clippy**

Run: `cargo clippy -p rimap-server --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/rimap-server/src/cli/dry_run.rs
git commit -m "feat(rimap-server): wire fingerprint section into --dry-run output

Calls write_fingerprint_section after the capabilities line for each
account, so operators see the observed leaf-cert SHA-256 alongside the
capability list. Module doc-comment sample updated to match.

Refs: #151"
```

---

## Task 6: Update the preflight module doc

**Files:**
- Modify: `crates/rimap-imap/src/preflight.rs:1-4` (module doc-comment)

- [ ] **Step 1: Update the module doc-comment**

In `crates/rimap-imap/src/preflight.rs`, replace lines 1-4:

```rust
//! Pre-auth `CAPABILITY` probe used by `--dry-run` and other diagnostic
//! paths. Performs TCP connect → TLS handshake → IMAP greeting → pre-auth
//! `CAPABILITY` command, then drops the connection. Does NOT perform LOGIN
//! and does NOT emit any audit records.
```

with:

```rust
//! Pre-auth `CAPABILITY` probe used by `--dry-run` and other diagnostic
//! paths. Performs TCP connect → TLS handshake → IMAP greeting → pre-auth
//! `CAPABILITY` command, then drops the connection. Captures the leaf-cert
//! SHA-256 fingerprint observed during the handshake (returned via
//! `PreflightInfo.tls_fingerprint`). Does NOT perform LOGIN and does NOT
//! emit any audit records.
```

- [ ] **Step 2: Run a quick build to verify doc-comment compiles**

Run: `cargo build -p rimap-imap`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/rimap-imap/src/preflight.rs
git commit -m "docs(rimap-imap): note fingerprint capture in preflight module doc

Refs: #151"
```

---

## Task 7: Update user-facing docs

**Files:**
- Modify: `docs/quickstart-proton-bridge.md`
- Modify: `docs/quickstart-gmail.md` (only if it covers pinning)
- Modify: `docs/configuration.md`

- [ ] **Step 1: Inspect the proton-bridge quickstart pinning section**

Run: `sed -n '60,100p' docs/quickstart-proton-bridge.md`
Locate the section that walks the user through running `openssl s_client` to compute the fingerprint. The new content adds a primary path that uses `--dry-run`.

- [ ] **Step 2: Update `docs/quickstart-proton-bridge.md`**

Above the existing `openssl s_client | openssl x509 -fingerprint -sha256` recipe, add a new sub-section:

```markdown
### Get the TLS fingerprint (recommended path)

After saving an initial `config.toml` with `host`, `port`, and `username`,
run:

\`\`\`
rusty-imap-mcp --config config.toml --dry-run
\`\`\`

The output includes a `TLS fingerprint (sha256):` line followed by the
observed cert hash and a copy-pasteable line:

\`\`\`
TLS fingerprint (sha256):
  ab:cd:ef:...:ef
  (add `tls_fingerprint_sha256 = "ab:cd:ef:...:ef"` under [imap] in config.toml to pin)
\`\`\`

Copy the hex value into `tls_fingerprint_sha256` under `[imap]` and re-run
`--dry-run`; the fingerprint section now reads `(matches configured pin)`.
```

Then re-title the existing openssl section to "Alternative: extract the fingerprint with openssl" and add a one-line lead-in: "If you prefer not to run a partial config first, the fingerprint can also be extracted directly:".

- [ ] **Step 3: Inspect `docs/quickstart-gmail.md` for a pinning section**

Run: `rg -n "tls_fingerprint|fingerprint" docs/quickstart-gmail.md`
- If the file mentions pinning: apply a parallel update modeled on Step 2.
- If it does not (Gmail uses CA-signed certs and the quickstart skips pinning): no change. Note this in the commit message.

- [ ] **Step 4: Update `docs/configuration.md`**

Run: `rg -n "tls_fingerprint_sha256" docs/configuration.md`
Locate the table row at line ~105 that documents `tls_fingerprint_sha256`. Append one sentence to the description column:

```markdown
| `tls_fingerprint_sha256` | string | (none) | Pinned TLS certificate SHA-256 fingerprint. Hex, colons optional. Required for self-signed certs (e.g. Proton Bridge). Omit to use the system trust store. Run `--dry-run` to print the observed fingerprint for copy-paste pinning. |
```

- [ ] **Step 5: Commit**

```bash
git add docs/quickstart-proton-bridge.md docs/quickstart-gmail.md docs/configuration.md
git commit -m "docs: promote --dry-run as the canonical TLS pinning onboarding path

Quickstart now leads with --dry-run for fingerprint extraction;
the openssl recipe stays as a fallback. Configuration table row
points to --dry-run.

Refs: #151"
```

---

## Task 8: Verify end-to-end with the Dovecot harness (optional but recommended)

**Why:** All three new test cases run against Docker. If you have Docker or Podman locally, this is the time to verify the full path.

- [ ] **Step 1: Run the new Dovecot integration tests**

Run: `cargo test -p rimap-imap --test dovecot probe_preflight -- --nocapture`
Expected: both `case_NN_probe_preflight_returns_observed_fingerprint` and `case_NN_probe_preflight_mismatch_returns_typed_tls_error` pass. (Or silent skip without Docker.)

- [ ] **Step 2: Manual smoke test of dry-run output (with Docker)**

Run the harness manually and observe the dry-run output. (No commit step — purely a sanity check. Skip if no Docker.)

```bash
# Spin up the Dovecot fixture used by integration tests
just dovecot-up  # or whatever the project task is; check the justfile

# Write a minimal config pointing at it
cat > /tmp/issue-151-config.toml <<EOF
[imap]
host = "127.0.0.1"
port = 1993  # whatever DovecotHarness uses
username = "admin@localhost"
[audit]
path = "/tmp/issue-151-audit.jsonl"
allowed_base_dir = "/tmp"
EOF
chmod 700 /tmp

# Run --dry-run and confirm the fingerprint section appears
cargo run -p rimap-server -- --config /tmp/issue-151-config.toml --dry-run
```

Expected: stdout contains `TLS fingerprint (sha256):`, the observed hex, and the paste-into-config hint.

---

## Task 9: Mutation testing on touched files

**Files (under test):**
- `crates/rimap-imap/src/preflight.rs`
- `crates/rimap-imap/src/connection.rs` (the helper only — full file is too large)
- `crates/rimap-server/src/cli/dry_run.rs`

**Why:** Project-standing practice. Catches branch arms (e.g., the `(Some, Some) if a != b` guard) where a mutation might leave the test suite green.

- [ ] **Step 1: Run mutants on `dry_run.rs`**

Run: `cargo mutants --jobs 2 --file crates/rimap-server/src/cli/dry_run.rs`
Expected: zero unkilled mutants. If any escape, add a targeted unit test that catches the mutation.

- [ ] **Step 2: Run mutants on `preflight.rs`**

Run: `cargo mutants --jobs 2 --file crates/rimap-imap/src/preflight.rs`
Expected: zero unkilled mutants on the new lines. Pre-existing escapees are out of scope.

- [ ] **Step 3: Run mutants targeted at `enrich_tls_handshake_error`**

Run: `cargo mutants --jobs 2 --file crates/rimap-imap/src/connection.rs --regex 'enrich_tls_handshake_error'`
Expected: zero unkilled mutants.

- [ ] **Step 4: If any mutants escaped, add tests and commit**

For each escaped mutant, add a unit test that fails under the mutation. Commit per file:

```bash
git add <test-file>
git commit -m "test: kill <description> mutant in <file>

Refs: #151"
```

---

## Task 10: Final verification

- [ ] **Step 1: Run the full test suite for the touched crates**

Run: `cargo test -p rimap-imap -p rimap-server`
Expected: all tests pass.

- [ ] **Step 2: Run clippy across the workspace**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

- [ ] **Step 3: Run cargo fmt check**

Run: `cargo fmt --check`
Expected: clean.

- [ ] **Step 4: Open the PR**

```bash
git push -u origin feat/issue-151-tls-fingerprint-dry-run
gh pr create --title "feat: surface TLS cert fingerprint during --dry-run (#151)" --body "$(cat <<'EOF'
## Summary
- Adds `PreflightInfo.tls_fingerprint`, captured from `bundle.last_observed` after the handshake
- Extracts `enrich_tls_handshake_error` from `connect_inner` and reuses it in `probe_preflight` so a mismatch surfaces as `ImapError::Tls { observed, expected }` on both paths
- New `write_fingerprint_section` printer prints three cases under `--dry-run`: unpinned-onboard, pinned-match, pinned-mismatch
- Quickstart docs promote `--dry-run` as the canonical pinning onboarding path

Closes #151.

## Test plan
- [ ] `cargo test -p rimap-imap -p rimap-server` passes
- [ ] `cargo test -p rimap-imap --test dovecot probe_preflight` passes (with Docker) or silent-skips (without)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
- [ ] `cargo mutants --jobs 2 --file crates/rimap-server/src/cli/dry_run.rs` zero unkilled mutants on new lines
EOF
)"
```

Expected: PR opens, CI runs.

---

## Notes for the implementer

- All tests use synthesized fingerprints via `TlsFingerprint::from_cert_der(b"...")` for unit tests, and the harness's real cert fingerprint for integration tests. Both paths are stable across runs.
- The Dovecot harness silently skips when neither Docker nor Podman is available. The new integration tests inherit that behavior — verify locally with `cargo test -p rimap-imap --test dovecot` once before opening the PR if you have a container runtime; CI runs them on Linux x86_64.
- The defensive `(Ok(info), Some(_pin_mismatch_unreachable))` arm in `write_fingerprint_section` is only reachable if a future bug lets a mismatched-but-handshake-successful preflight slip through. Today this cannot happen: the `PinningVerifier` in `tls.rs` rejects the handshake on mismatch. The defensive branch is documented as such and prints observed-only — better than panicking on a `match` exhaustiveness gap.
- The plan assumes `tests/integration/dovecot.rs`'s `support` module is in scope via the `mod support;` declaration at the top of the file. New tests reference `support::container::DovecotHarness` directly.
