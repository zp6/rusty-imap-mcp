# IMAP STARTTLS support — design

Issue: #118
Target crates: `rimap-config`, `rimap-imap`, `rimap-server` (minor)
Related: #117 (TLS preflight in `--dry-run`), existing `SmtpEncryption::Starttls` precedent.

## 1. Problem

`rimap-imap` only supports implicit TLS. `crates/rimap-imap/src/connection.rs` (the `connect_with_bundle` path) performs TCP connect then `TlsConnector::connect` immediately, with no STARTTLS negotiation. `ImapConfig` has no encryption-mode field; its `port` is commented as "Server port (IMAPS)".

Proton Bridge's default IMAP connection mode is **STARTTLS on port 1143**. Bridge exposes an advanced "SSL" option, but default-installed users are expected to use STARTTLS. Today, a stock Bridge setup fails with `ERR_TLS: handshake failed: received corrupt message of type InvalidContentType` because rustls sees the plaintext IMAP greeting where it expected a TLS record.

The project advertises Proton Bridge as its primary target (README, dedicated `docs/quickstart-proton-bridge.md`, CHANGELOG entry for fingerprint pinning), but the stock config cannot connect. The Proton integration tests under `crates/rimap-imap/tests/integration/proton/` are gated behind `PROTON_BRIDGE_TEST=1`, so CI never catches this. The quickstart `openssl` example uses `-starttls imap`, which is itself evidence Bridge is STARTTLS-default — but the server flow cannot mirror that.

SMTP already supports STARTTLS (`rimap-smtp`, `SmtpEncryption::Starttls`), so there is a precedent pattern to follow.

## 2. Goals

- Let operators configure IMAP as STARTTLS with no silent security regressions.
- Preserve existing single-account TLS-only configs verbatim (zero migration).
- Keep transport-security guarantees identical across modes: fingerprint pinning, no credential resolution pre-TLS, no plaintext LOGIN, no downgrade fallback.
- Make the code change minimal and localized; do not introduce new crates, new audit events, or new public `ErrorCode` variants.

## 3. Non-goals

- Plaintext IMAP (`encryption = "none"`). SMTP has a `None` variant gated as "testing only"; IMAP will not.
- Port defaulting based on mode. Operators set `port` explicitly, matching SMTP.
- Matrix-testing the full existing Dovecot suite over both transports. See §7.
- Changes to `rimap-audit`, `rimap-authz`, `rimap-content`, or the `TlsConfigBundle`.

## 4. Architecture

Three crates touched; no new modules.

### 4.1 `rimap-config`
- New `ImapEncryption { Tls, Starttls }` enum, `#[serde(rename_all = "lowercase")]`, `#[default] Tls`.
- New `encryption: ImapEncryption` field on `ImapConfig`, `#[serde(default)]`.
- No new validation rules. Operator is responsible for matching `port` to mode, as with SMTP.

### 4.2 `rimap-imap`
- `ConnectionConfig` gains `encryption: ImapEncryption`. To avoid a reverse dependency, `rimap-imap` mirrors the enum locally; `rimap-server` maps between the two at the crate boundary.
- `connect_with_bundle` branches on `encryption`:
  - `Tls`: unchanged code path.
  - `Starttls`: new `starttls_upgrade(tcp, bundle, host)` helper produces the same `TlsStream<TcpStream>` the rest of the pipeline expects.
- New `ImapError::Starttls { reason: StarttlsFailure }` variant + `StarttlsFailure` sub-enum.
- `ImapError::code()` maps `Starttls { .. }` to `ErrorCode::Tls` — no new top-level code.

### 4.3 `rimap-server` and any other `ConnectionConfig` builders
- One-line change to thread `encryption` from `ImapConfig` into `ConnectionConfig`.

### 4.4 Unchanged
- Pin verification (`PinningVerifier`) and `last_observed` capture — run at TLS upgrade for both modes.
- `imap_login` — takes `TlsStream<TcpStream>`; unchanged.
- Audit event taxonomy — pre-TLS failures surface as `ErrorCode::Tls`, same bucket as handshake/pin failures.

## 5. Components

### 5.1 `ImapEncryption` (`rimap-config`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImapEncryption {
    /// Implicit TLS (IMAPS), typical port 993.
    #[default]
    Tls,
    /// STARTTLS upgrade on the IMAP port, typical port 143 or 1143.
    Starttls,
}
```

### 5.2 `ImapConfig` field addition

Insert one field between `username` and `tls_fingerprint_sha256`:

```rust
/// Transport encryption mode. Defaults to implicit TLS for
/// backward-compatibility with pre-STARTTLS configs.
#[serde(default)]
pub encryption: ImapEncryption,
```

Update the `port` doc comment from "Server port (IMAPS)" to "Server port (993 for TLS, 143/1143 for STARTTLS)".

### 5.3 `ConnectionConfig` mirror (`rimap-imap`)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImapEncryption { #[default] Tls, Starttls }
```

Add `pub encryption: ImapEncryption` to `ConnectionConfig`.

### 5.4 `starttls_upgrade` helper (new, `rimap-imap::connection`)

```rust
async fn starttls_upgrade(
    tcp: TcpStream,
    bundle: &TlsConfigBundle,
    host: &str,
) -> Result<TlsStream<TcpStream>, ImapError>
```

Steps, all inside the caller's `connect_timeout` budget:

1. `let mut client = async_imap::Client::new(tcp);` (plaintext)
2. `client.read_response()` → consume greeting. `BYE` → `Err(Starttls { reason: UnexpectedBye })`. `OK` → continue.
3. `run_command_and_check_ok("CAPABILITY", Some(tx))` + drain the unsolicited channel for `Response::Capabilities`. Token `STARTTLS` required; absent → `Err(Starttls { reason: CapabilityMissing })`.
4. `run_command_and_check_ok("STARTTLS", None)`. Tagged `NO`/`BAD` → `Err(Starttls { reason: ServerRefused { tagged_status } })`.
5. `let tcp = client.into_inner();` — drops the `Client` and its `ImapStream` buffer. This is the CVE-2011-0411 defense (see §8.4).
6. `ServerName::try_from(host.to_string())` → `TlsConnector::from(bundle.config.clone()).connect(server_name, tcp).await`. Same call the TLS-mode path makes. Pin verification runs here.
7. Return `TlsStream<TcpStream>`.

### 5.5 `ImapError::Starttls` + `StarttlsFailure` (`rimap-imap::error`)

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StarttlsFailure {
    /// Server's CAPABILITY response did not advertise STARTTLS.
    CapabilityMissing,
    /// Server returned a tagged NO or BAD in response to STARTTLS.
    ServerRefused { tagged_status: &'static str },
    /// Server greeted with BYE instead of OK.
    UnexpectedBye,
}

// In ImapError:
#[error("STARTTLS failed: {reason}")]
Starttls { reason: StarttlsFailure },
```

Display of `StarttlsFailure` follows the `AuthFailure` pattern.

### 5.6 `connect_with_bundle` branch (`rimap-imap::connection`)

After the existing TCP connect step, introduce:

```rust
let tls_stream = match cfg.encryption {
    ImapEncryption::Tls => {
        // existing TlsConnector::connect path
    }
    ImapEncryption::Starttls => {
        timeout(remaining, starttls_upgrade(tcp, bundle, &cfg.host))
            .await
            .map_err(|_| (ImapError::Timeout { op: "starttls_upgrade" }, None))?
            .map_err(|e| (e, None))?
    }
};
```

Both branches produce `TlsStream<TcpStream>`. Downstream `imap_login` is untouched.

### 5.7 Caller threading

`rimap-server` (and test harnesses building `ConnectionConfig` directly) add one line to pass `encryption` through.

## 6. Data flow

### 6.1 Config load → connection build

```
TOML file
  └─ rimap-config::load
       └─ ImapConfig { …, encryption: ImapEncryption }   // default Tls if omitted
            └─ validate/mod.rs                            // no new rules
                 └─ rimap-server startup
                      └─ ConnectionConfig { …, encryption }
                           └─ Connection::new(cfg)
```

Existing configs omitting `encryption` deserialize as `Tls`. Zero migration.

### 6.2 Lazy connect dispatch

```
TcpStream::connect(host, port)
  │
  ├─ Tls ──────────► TlsConnector.connect(server_name, tcp) ► TlsStream
  │
  └─ Starttls
       ├─ async_imap::Client::new(tcp)
       ├─ read_response()              // OK | BYE→UnexpectedBye
       ├─ CAPABILITY                   // require STARTTLS | →CapabilityMissing
       ├─ STARTTLS                     // NO/BAD →ServerRefused
       ├─ client.into_inner()          // buffer dropped
       └─ TlsConnector.connect(server_name, tcp) ► TlsStream
```

Both branches converge on `TlsStream<TcpStream>` before `imap_login`.

### 6.3 Post-upgrade (unchanged)

Per RFC 3501 §6.2.1, pre-TLS capabilities are invalidated after STARTTLS. `imap_login` already re-reads the greeting and re-issues CAPABILITY before LOGIN, so no code change there.

### 6.4 Timeout budget

`connect_timeout` is one budget covering the whole connect path. In STARTTLS mode it now covers: TCP connect + plaintext greeting + CAPABILITY + STARTTLS command + TLS upgrade + post-TLS greeting + CAPABILITY + LOGIN. Operators tune via `connect_timeout_seconds` as before. A stuck server mid-STARTTLS surfaces as `ImapError::Timeout { op: "starttls_upgrade" }` — a distinct `op` tag from `"tls_handshake"`.

### 6.5 Pin capture

`PinningVerifier` runs inside `TlsConnector::connect` at step 6.2's final arrow for both modes. `last_observed.toml` captures the post-upgrade cert fingerprint — the one a pin would need to match.

## 7. Testing

Targeted STARTTLS-specific tests (not a full matrix). The STARTTLS path diverges from implicit-TLS only at the pre-TLS handshake; once TLS is established, everything downstream is byte-identical to today's path and already covered.

### 7.1 Unit tests (`rimap-imap`, no Docker)

In-process mock TCP server scripts plaintext IMAP bytes:

- `starttls_upgrade_happy_path` — greeting + cap + tagged OK, then TLS handshake against a test-generated self-signed cert with matching pin. Asserts `TlsStream` returned.
- `starttls_capability_missing` — cap list lacks `STARTTLS`. Assert `StarttlsFailure::CapabilityMissing`; no STARTTLS command issued.
- `starttls_server_refused_no` — tagged `NO` on STARTTLS. Assert `ServerRefused { tagged_status: "NO" }`.
- `starttls_server_refused_bad` — tagged `BAD`. Assert `tagged_status: "BAD"`.
- `starttls_unexpected_bye` — greeting is `* BYE …`. Assert `UnexpectedBye`.
- `starttls_no_credential_resolve_on_failure` — credential resolver panics if invoked; run each of the four failure cases; assert no panic (proves resolver unreached pre-TLS).
- `starttls_buffer_injection_defense` — mock sends `a1 OK STARTTLS\r\n* BAD injected\r\n` in one TCP segment before client initiates TLS. Assert post-TLS client does not parse `* BAD injected` — bytes are dropped with `client.into_inner()`. Regression test for CVE-2011-0411 class.
- `starttls_timeout` — mock greets, then stalls. Assert `ImapError::Timeout { op: "starttls_upgrade" }`.

Uses `rcgen` (existing dev-dep) for the self-signed cert. No new crate deps.

### 7.2 Dovecot STARTTLS integration (gated behind existing `DOVECOT_TEST=1`)

- `dovecot/dovecot.conf` — add `inet_listener imap { port = 143 }`. Keep `ssl = required` so Dovecot enforces STARTTLS before LOGIN.
- `dovecot/docker-compose.yml` — expose port 143.
- `tests/integration/dovecot_starttls.rs` (new) — three tests:
  - successful STARTTLS connect + LIST + logout.
  - fingerprint-pinning-after-upgrade (reuse existing pin fixture).
  - plaintext LOGIN without STARTTLS is refused by Dovecot (`ssl = required` sanity check).

Existing implicit-TLS Dovecot suite is untouched.

### 7.3 Proton Bridge integration (`PROTON_BRIDGE_TEST`)

`crates/rimap-imap/tests/integration/proton.rs` — flip to `encryption = "starttls"`, `port = 1143`. Existing operation coverage must keep passing.

### 7.4 Config tests (`rimap-config`)

- `imap_config_without_encryption_defaults_to_tls`.
- `imap_config_encryption_starttls`.
- `imap_config_encryption_rejects_unknown` — `encryption = "mutual-tls"` fails deserialization.

### 7.5 Docs verification (not automated)

- `docs/quickstart-proton-bridge.md` — config snippet `encryption = "starttls"`, `port = 1143`.
- `docs/multi-account.md` — Proton example gains `encryption = "starttls"`.
- `docs/configuration.md` — document `imap.encryption` alongside `smtp.encryption`.

### 7.6 Not tested at this layer
- Full Dovecot IMAP-operations suite over STARTTLS (transport-agnostic).
- TLS handshake mechanics post-upgrade (identical to existing TLS path).
- `TlsConfigBundle` construction (unchanged).

## 8. Security

### 8.1 No silent downgrade

The only path from `TcpStream` to `imap_login` produces `TlsStream<TcpStream>`. There is no code path where `imap_login` accepts a plaintext client. Any STARTTLS-phase failure propagates as `Err`, short-circuiting before LOGIN. Plaintext LOGIN is structurally impossible.

### 8.2 No credentials before TLS

`starttls_upgrade` runs entirely before `credentials.resolve(…)`, which is only called inside `imap_login`. All STARTTLS-phase errors return `(err, None)` — the `None` carries through to audit as `credential_source = None`. The password never reaches memory on STARTTLS-failure paths.

### 8.3 Pin enforcement preserved

The TLS upgrade step in STARTTLS mode uses the same `TlsConfigBundle` as implicit-TLS mode, so `PinningVerifier` runs identically. A pinned fingerprint must match the post-upgrade cert in both modes.

### 8.4 Buffer-injection defense (CVE-2011-0411 class)

After the tagged OK for STARTTLS, a MITM could inject plaintext bytes *after* the server's response but *before* the TLS handshake starts. If those bytes got buffered by the plaintext parser and then replayed against the post-TLS stream, they would execute as authenticated commands.

`async_imap::Client::into_inner()` (verified against async-imap 0.11.2 `src/client.rs:147` and `src/imap_stream.rs:78`) returns the underlying `TcpStream` by moving it out of the `ImapStream` wrapper. The wrapper — including its `Buffer` — is dropped. Any buffered-but-unparsed plaintext bytes are unreachable from then on; `Client::new(tls)` constructs a fresh wrapper with an empty buffer.

The defense is structural, not incidental. Test §7.1 `starttls_buffer_injection_defense` pins this property so a future refactor cannot silently regress it.

### 8.5 Error-code stability

`ImapError::Starttls { .. }` maps to `ErrorCode::Tls`. No new `ErrorCode` variant; the MCP-facing error taxonomy is unchanged. STARTTLS failures are an internal-detail refinement of `ERR_TLS`.

## 9. Documentation changes

- `docs/quickstart-proton-bridge.md` — switch config snippet to `encryption = "starttls"`, `port = 1143`. The `openssl s_client -starttls imap` example already matches (#119).
- `docs/multi-account.md` — Proton example includes `encryption = "starttls"`.
- `docs/configuration.md` — new subsection on `imap.encryption` mirroring the `smtp.encryption` docs.

## 10. Acceptance criteria

- [ ] `ImapConfig` gains `encryption: ImapEncryption` with default `Tls`.
- [ ] `Connection::connect_with_bundle` handles both modes; STARTTLS mode runs greeting → CAPABILITY (require `STARTTLS`) → STARTTLS → TLS upgrade → re-greet → re-CAPABILITY → LOGIN.
- [ ] `ImapError::Starttls { reason: StarttlsFailure }` variant exists with `CapabilityMissing`, `ServerRefused`, and `UnexpectedBye` sub-reasons. Maps to `ErrorCode::Tls`.
- [ ] Buffered-plaintext bytes are discarded before the TLS upgrade, with a regression test covering the injection class.
- [ ] Pinning tests pass identically in both modes (unit).
- [ ] Proton Bridge integration test switches to STARTTLS + port 1143 and passes when `PROTON_BRIDGE_TEST=1`.
- [ ] Dovecot STARTTLS integration variant lands with three tests covered by §7.2.
- [ ] Existing implicit-TLS path unchanged behaviorally; all current tests pass without changes.
- [ ] Docs updated as listed in §9.

## 11. Out of scope / follow-ups

- #117 TLS preflight in `--dry-run` — should cover both modes once this lands.
- OAuth / XOAUTH2 on Proton Bridge.
- STARTTLS for ManageSieve or any other protocol.
