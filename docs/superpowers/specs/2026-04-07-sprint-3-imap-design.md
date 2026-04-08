# Sprint 3 — IMAP connection, TLS pinning, read operations

**Status:** Approved design, ready for implementation planning.
**Date:** 2026-04-07
**Parent design:** [`2026-04-07-rusty-imap-mcp-design.md`](./2026-04-07-rusty-imap-mcp-design.md) §12 Sprint 3

This document refines the parent design's Sprint 3 entry into an implementation-ready spec. Where this document and the parent design disagree, this document wins for Sprint 3 only; the parent design remains authoritative for the overall project shape.

## 1. Scope & non-goals

### In scope

- New `rimap-imap` crate body (currently a stub): `Connection` type wrapping a single `async-imap` session per account, lazy-connect, TCP-half-open detection with no auto-retry, idle disconnect on next-use only.
- TLS via `rustls` + custom `ServerCertVerifier` doing SHA-256 leaf-certificate-DER fingerprint pinning when configured, system trust store (via `webpki-roots`) when not.
- LOGIN/PLAIN authentication only (no XOAUTH2, SCRAM, or GSSAPI).
- Read-only IMAP operations: `LIST`, `STATUS`, `EXAMINE`/`SELECT`, `SEARCH` (`Structured` and `Raw` variants), `FETCH ENVELOPE`/`BODYSTRUCTURE`/`UID`/`FLAGS`/`RFC822.SIZE`, and `FETCH BODY[]` (raw bytes, hard size cap, connection drop on overflow).
- Per-account `connect_timeout` and `command_timeout` from `rimap-config`.
- `Auth` audit record emitted on every connect attempt — success and all failure modes — with observed and expected fingerprint.
- Dovecot Docker harness running in CI; Proton Bridge harness documented and env-gated for local developers only.
- Prerequisite issues land as part of this sprint: #21 (`TlsFingerprint` newtype), #24 (`AuditWriter::log_process_start` helper), #27 (`From<AuditError>` preserves `#[source]`).

### Explicitly out of scope

- `STORE`, `APPEND`, `MOVE`, `UID COPY` — Sprint 5.
- MCP tool surface and dispatch chain wiring — Sprint 5.
- MIME and RFC 5322 body parsing — Sprint 4 (`rimap-content`).
- XOAUTH2, SCRAM, GSSAPI — post-v1.
- Connection pooling — single connection per account is sufficient for v1.
- Background idle-timeout tasks — lazy-only.
- SEARCH redaction policy decision (#22) — Sprint 5.
- Canonicalize-and-contain `audit.path` (#29), supply-chain hardening (#30), and other unrelated tracks.

## 2. Crate layout

```
crates/rimap-imap/
├── Cargo.toml
├── src/
│   ├── lib.rs              # public re-exports, crate docs, no logic
│   ├── connection.rs       # Connection type, lifecycle, lazy connect, half-open detection
│   ├── tls.rs              # PinningVerifier, TlsConfig builder, system-roots fallback
│   ├── auth.rs             # LOGIN flow, AuthOutcome, audit-record construction
│   ├── ops/
│   │   ├── mod.rs          # pub use of submodules
│   │   ├── folders.rs      # LIST, STATUS, EXAMINE/SELECT
│   │   ├── search.rs       # SearchQuery, search()
│   │   └── fetch.rs        # FetchSpec, fetch envelope/bodystructure/body
│   ├── types.rs            # Envelope, BodyStructure, Folder, FolderStatus, Flag, Uid newtype
│   ├── error.rs            # rimap_imap::Error + From impls
│   └── time.rs             # tokio::time::timeout wrapper helpers
└── tests/
    ├── tls_pinning.rs      # unit-ish tests for PinningVerifier (no network)
    ├── error_mapping.rs    # round-trip error → RimapError preserves source chain
    └── integration/
        ├── dovecot.rs      # gated by Docker availability + RIMAP_REQUIRE_DOCKER
        ├── proton.rs       # gated by PROTON_BRIDGE_TEST=1
        └── support/
            ├── mod.rs
            ├── docker.rs   # compose up/down Drop guard, port wait, fingerprint extract
            └── fixtures.rs # canned .eml loader
```

### Module size discipline

No file is allowed to exceed the workspace 100-line function limit. Each file maps to one of: state machine (`connection.rs`), TLS (`tls.rs`), auth (`auth.rs`), or one IMAP verb family (`ops/*.rs`). If `connection.rs` exceeds approximately 400 lines, split the connect/send/recv state machine into `connection/state.rs`.

### Workspace integration

`rimap-imap` is added as a workspace member (the stub already exists). Internal-dep pattern stays — `rimap-core = { path = "...", version = "0.0.0" }` and likewise for `rimap-config`, `rimap-audit`, `rimap-authz`. Internal crates do not go into `[workspace.dependencies]` (cargo-deny wildcard rule per the watchlist).

### New external dependencies

- `async-imap = "0.10"` — IMAP protocol implementation. Single-purpose, only mainstream pure-Rust async IMAP client.
- `tokio-rustls = "0.26"` — TLS over tokio streams.
- `rustls = "0.23"` — added to `[workspace.dependencies]` if not already pinned.
- `webpki-roots = "0.26"` — Mozilla CA bundle for the unpinned trust path.

`x509-parser` was considered for cert DER extraction and rejected — `rustls::CertificateDer` already exposes the bytes, and `sha2` is in the workspace via `rimap-audit`. One fewer dep.

## 3. Public API

```rust
// rimap-imap/src/lib.rs
pub use connection::Connection;
pub use error::{Error, AuthFailure};
pub use rimap_core::tls::TlsFingerprint;
pub use types::{
    Envelope, BodyStructure, Folder, FolderStatus, Flag, Uid, MessageId,
    SearchQuery, FetchSpec, FetchedMessage, SelectedFolder, StatusItems,
};

// connection.rs
impl Connection {
    /// Build a connection handle. Does NOT open a socket.
    pub fn new(account: AccountConfig, audit: Arc<AuditWriter>) -> Self;

    /// Lazy-connect: opens the socket on first use, reuses thereafter.
    /// Reconnects automatically only if the previous connection was torn
    /// down by a prior error. Never auto-retries a failed command.
    pub async fn list_folders(&self, pattern: &str) -> Result<Vec<Folder>, Error>;
    pub async fn status(&self, folder: &str, items: StatusItems) -> Result<FolderStatus, Error>;
    pub async fn select(&self, folder: &str, read_only: bool) -> Result<SelectedFolder, Error>;
    pub async fn search(&self, folder: &str, query: SearchQuery) -> Result<Vec<Uid>, Error>;
    pub async fn fetch(&self, folder: &str, uids: &[Uid], spec: FetchSpec)
        -> Result<Vec<FetchedMessage>, Error>;
    pub async fn fetch_body(&self, folder: &str, uid: Uid) -> Result<Vec<u8>, Error>;

    /// Test/debug only: returns whether a live socket is currently held.
    #[cfg(any(test, feature = "test-introspection"))]
    pub fn is_connected(&self) -> bool;
}
```

### Concurrency model

`Connection` is `Send + Sync`. Internally holds `tokio::sync::Mutex<Option<Session>>` — `Option` because the session can be absent (never connected, or torn down). All public methods take `&self`, acquire the mutex, lazy-connect if `None`, run the command under `tokio::time::timeout(command_timeout, ...)`, and on `ConnectionLost`-class errors set the slot back to `None` before returning.

This uses `tokio::sync::Mutex`, not `std::sync::Mutex`, because the lock is held across `.await` points. This is the *opposite* of the audit-writer lock rule (which is std + never across `.await`). They are different locks with different invariants; both rules apply concurrently.

### Types (`types.rs`)

- `Uid(NonZeroU32)` newtype — IMAP UIDs are 1..u32::MAX; `NonZero` gives free niche optimization in `Option<Uid>`.
- `Envelope` — typed parse of IMAP `ENVELOPE`: `date`, `subject_raw: Vec<u8>`, `from`, `sender`, `reply_to`, `to`, `cc`, `bcc`, `in_reply_to`, `message_id`. Header values stay raw bytes; RFC 2047 decoding lives in Sprint 4.
- `BodyStructure` — recursive enum mirroring IMAP `BODYSTRUCTURE`: `Single { mime_type, mime_subtype, params, encoding, size, ... }` and `Multipart { subtype, parts: Vec<BodyStructure> }`. Used by Sprint 5 to plan body fetches without retrieving the whole message.
- `SearchQuery::Structured(StructuredQuery)` — typed builder (from, to, subject, since, before, seen/unseen, has-attachment); `SearchQuery::Raw(String)` — passthrough; the audit/dispatch layer (Sprint 5) decides redaction.
- `FetchSpec` — bitflags-style: `ENVELOPE | BODYSTRUCTURE | UID | FLAGS | SIZE`. `BODY[]` is its own method (`fetch_body`) because it is the only large/streaming op.
- `FetchedMessage` — populated subset matching the requested `FetchSpec`.

`AccountConfig` and `AuditWriter` come from `rimap-config` and `rimap-audit` respectively. `Connection::new` borrows the typed handles; no `From` impls back into those crates.

## 4. TLS pinning subsystem

### `TlsFingerprint` newtype (closes #21)

```rust
// rimap-core/src/tls.rs (NEW)
#[derive(Clone, Copy, Eq)]
pub struct TlsFingerprint([u8; 32]);

impl TlsFingerprint {
    pub fn from_hex(s: &str) -> Result<Self, FingerprintParseError>;
    pub fn from_cert_der(der: &[u8]) -> Self;     // sha256(der)
    pub fn as_bytes(&self) -> &[u8; 32];
    pub fn to_hex(&self) -> String;               // lowercase, no separators
    pub fn to_hex_colon(&self) -> String;         // openssl-style "AA:BB:..."
}

impl PartialEq for TlsFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()             // subtle::ConstantTimeEq
    }
}

impl fmt::Display for TlsFingerprint { /* lowercase hex */ }
// no Debug impl — print explicit hex via Display when needed
```

Lives in `rimap-core` (not `rimap-imap`) because both `rimap-config` (parses from TOML) and `rimap-audit` (records in `Auth.tls_fingerprint_sha256`) need it. Adds `subtle = "2"` to `rimap-core`'s deps for constant-time equality. RustCrypto crate, single-purpose, already in the project's transitive trust set via `sha2`.

### Audit field type change

The current `Auth.tls_fingerprint_sha256: Option<String>` becomes `Auth.tls_fingerprint_sha256: Option<TlsFingerprint>`. Serde impls emit lowercase hex on the wire, so the JSONL on-disk format is unchanged. Sprint 2 has zero in-tree consumers of the `Auth` variant (no emission yet), so the in-memory type change has no migration cost.

### `PinningVerifier`

```rust
// rimap-imap/src/tls.rs
struct PinningVerifier {
    pinned: Option<TlsFingerprint>,
    last_observed: OnceLock<TlsFingerprint>,
}

impl rustls::client::danger::ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let observed = TlsFingerprint::from_cert_der(end_entity.as_ref());
        let _ = self.last_observed.set(observed);
        match self.pinned {
            Some(expected) if expected == observed => Ok(ServerCertVerified::assertion()),
            Some(_expected) => Err(rustls::Error::General("tls fingerprint mismatch".into())),
            None => unreachable!("PinningVerifier only constructed when fingerprint pinned"),
        }
    }
    // signature_schemes / verify_tls12_signature / verify_tls13_signature:
    // delegate to rustls defaults via WebPkiServerVerifier so we still
    // enforce sane signature algorithms even when skipping chain validation.
}
```

### Two TLS modes

- **Pinned mode.** `PinningVerifier`. Skips chain validation, hostname check, and expiry. Pure TOFU-with-config: when an operator pins a specific cert, they have accepted that renewal requires a config update.
- **System trust mode.** Standard `rustls::ClientConfig::builder()` with `webpki-roots::TLS_SERVER_ROOTS`. Full hostname + chain + expiry. Used when no fingerprint is configured for an account.

### Capturing the observed fingerprint for audit

The verifier writes the observed fingerprint into a `OnceLock<TlsFingerprint>` *before* deciding success or failure. After the TLS handshake returns (success or error), `Connection` reads the slot and uses it to populate the `Auth` audit record. For the unpinned (system trust) mode we wrap `WebPkiServerVerifier` in a thin observer that captures the fingerprint the same way before delegating.

`OnceLock` is sufficient because each verifier instance is created fresh per connect attempt, single-use, and written exactly once. `rustls` requires `ServerCertVerifier: Send + Sync`; `OnceLock` satisfies this without Mutex poisoning concerns.

## 5. Auth flow & audit emission

### Connect sequence (`Connection::ensure_connected`)

1. Resolve `AccountConfig` → host, port, username, secret reference, optional pinned fingerprint, timeouts.
2. Open TCP under `connect_timeout` deadline (which covers TCP + TLS + greeting). On failure, emit `Auth { outcome: NetworkError(kind) }` and return `Error::Connect`.
3. TLS handshake using the `TlsConfig` from §4. The verifier captures the observed fingerprint into its `OnceLock` regardless of outcome.
4. **TLS error path:** if the verifier rejected the cert, read the captured `OnceLock` (which must be `Some` because the cert was seen before the mismatch decision), emit `Auth { outcome: TlsFingerprintMismatch { observed, expected }, tls_fingerprint_sha256: Some(observed) }`, and return `Error::Tls { observed, expected }`.
5. **Other TLS handshake errors** (signature algorithm, protocol, etc.) → emit `Auth { outcome: TlsHandshakeFailed }`, return `Error::TlsHandshake(err)`.
6. Wait for the IMAP greeting under the remaining `connect_timeout` budget. A `BYE` greeting triggers `Auth { outcome: ServerRejected }` and returns.
7. Run `CAPABILITY`. If `LOGINDISABLED` is advertised, emit `Auth { outcome: CapabilityMissing { needed: "LOGIN" } }`, return `Error::Auth(CapabilityMissing)`, and tear down the connection.
8. Issue `LOGIN <username> <secret>`. The secret is fetched from `rimap-config`'s credential resolver at this exact moment (not stored on `Connection`); it lives in a `secrecy::SecretString` and is zeroized after the LOGIN command bytes are written. The username is structurally present in the audit record but is never traced or logged in plaintext anywhere else (Sprint 2's `secret invariant` from commit 68cf620).
9. **LOGIN reject:** emit `Auth { outcome: LoginRejected, username, tls_fingerprint_sha256: Some(observed) }` and return `Error::Auth(LoginRejected)`.
10. **LOGIN success:** emit `Auth { outcome: Ok, username, server, tls_fingerprint_sha256: Some(observed), expected_fingerprint: pinned }`. Connection is now ready for ops.

### Audit lock discipline (load-bearing rule)

The audit lock is `std::sync::Mutex` and must NEVER be held across an `.await`. Every `Auth` emission inside `ensure_connected` happens via:

```rust
let audit = audit.clone();
tokio::task::spawn_blocking(move || audit.log_auth(record)).await??;
```

Yes, every connect pays one task hop for audit emission. This is intentional, worth it, and documented inline at every emission site so future maintainers do not "optimize" it away. A workspace-level note in `docs/architecture/audit-locking.md` explains the std-mutex-no-await vs tokio-mutex-yes-await split between the two locks.

### `log_process_start` helper (closes #24)

Sprint 3 is the first sprint that emits *anything* during the process lifetime, so the chain-of-history tamper signal needs an anchor. Without it, every gap looks like tampering.

```rust
// rimap-audit additions
pub struct ProcessStart {
    pub version: &'static str,                  // CARGO_PKG_VERSION
    pub pid: u32,
    pub started_at: Timestamp,                  // Timestamp::now() — preserves leap-second clamp
    pub config_hash: [u8; 32],                  // sha256(canonicalized config minus secrets)
}

impl AuditWriter {
    pub fn log_process_start(&self, record: ProcessStart) -> Result<(), AuditError>;
}
```

`rimap-server::main` calls `log_process_start` once after opening the audit writer, before any other emission. The existing audit-merge round-trip test asserts the first record on a fresh log is `ProcessStart`.

### `Auth` record schema

```rust
pub struct Auth {
    pub username: String,
    pub server: ServerEndpoint,                 // host + port newtype
    pub tls_fingerprint_sha256: Option<TlsFingerprint>,    // observed
    pub expected_fingerprint: Option<TlsFingerprint>,      // configured pin, if any
    pub outcome: AuthOutcome,
}

pub enum AuthOutcome {
    Ok,
    NetworkError { kind: NetworkErrorKind },    // ConnectRefused, Timeout, Dns, Other
    TlsHandshakeFailed,
    TlsFingerprintMismatch { observed: TlsFingerprint, expected: TlsFingerprint },
    ServerRejected,                             // BYE greeting
    CapabilityMissing { needed: &'static str },
    LoginRejected,
}
```

All variants are exhaustive at every match site. No `_ =>` wildcards, no `matches!` macro — workspace lint rules.

## 6. Error taxonomy

### `rimap_imap::Error` (thiserror)

| Variant | Maps to `RimapError` code |
|---|---|
| `Tls { observed: TlsFingerprint, expected: TlsFingerprint }` | `ERR_TLS` |
| `TlsHandshake(#[source] rustls::Error)` | `ERR_TLS` |
| `Connect(#[source] io::Error)` | `ERR_NETWORK` |
| `Timeout { op: &'static str }` | `ERR_TIMEOUT` |
| `Auth { reason: AuthFailure }` (where `AuthFailure` is `LoginRejected` or `CapabilityMissing { needed }`) | `ERR_AUTH` |
| `SizeLimit { limit: u64 }` | `ERR_SIZE_LIMIT` |
| `Protocol(#[source] async_imap::error::Error)` | `ERR_IMAP` |
| `ConnectionLost` (broken pipe / EOF mid-command) | `ERR_NETWORK` |

`From<rimap_imap::Error> for rimap_core::RimapError` preserves the `#[source]` chain. `From<AuditError> for RimapError` lands the same fix in passing, closing #27.

### Reconnect semantics

"Reconnect on half-open" refers to TCP half-open: the TCP connection is dead but the `Session` does not know yet, so the next command hits EOF / broken pipe. Behavior:

- Detect broken-connection error kinds from `async-imap` / `tokio::io`.
- Drop the dead session, set the slot back to `None`, **return the error to the caller** — do NOT auto-retry the command. The caller (eventually the dispatch chain in Sprint 5) decides whether to retry.
- The next call lazy-reconnects cleanly.

Rationale for no auto-retry: Sprint 3 only has read ops so retry would be safe today, but the API contract has to hold for Sprint 5's write ops too. Silent retry also hides network flakiness from the circuit breaker's failure counter.

This is **TCP half-open**, not circuit-breaker half-open. Name collision in the parent design. The breaker lives in `rimap-authz` and is invoked by the dispatch chain in Sprint 5. Sprint 3 does not call into `rimap-authz::breaker`; its existing unit tests cover the breaker's own state machine.

### Timeouts

- `connect_timeout` — TCP + TLS handshake + greeting + `CAPABILITY` probe, single deadline.
- `command_timeout` — applied to each IMAP command after login as `tokio::time::timeout` around the response.

Both come from `rimap-config` with hard-coded defaults if unset (10s connect, 30s command). Per-account override.

## 7. Test harness

### Dovecot harness (CI)

Layout:

```
tests/integration/dovecot/
├── docker-compose.yml      # pinned dovecot/dovecot:2.3.21 (or current stable LTS)
├── dovecot.conf            # IMAPS only, port 993, no plaintext
├── users                   # one user: rimap-test:{PLAIN}testpass
├── entrypoint.sh           # generates self-signed cert at start, writes
│                           # /shared/fingerprint.hex for the host to read
└── fixtures/
    ├── plain.eml
    ├── multipart.eml
    └── attachment.eml
```

`tests/integration/support/docker.rs` provides:

```rust
pub struct DovecotHarness {
    project: String,           // unique compose project name per test run
    fingerprint: TlsFingerprint,
    port: u16,
}

impl DovecotHarness {
    /// Returns Err(SkipReason::DockerUnavailable) when Docker is missing,
    /// unless RIMAP_REQUIRE_DOCKER=1 is set, in which case it hard-errors.
    pub fn try_start() -> Result<Self, HarnessError>;
    pub fn endpoint(&self) -> ServerEndpoint;
    pub fn pinned_fingerprint(&self) -> TlsFingerprint;
}

impl Drop for DovecotHarness {
    fn drop(&mut self) {
        // docker compose -p <project> down -v --remove-orphans
        // synchronous, best-effort, logged to stderr on failure, never panics
    }
}
```

Hand-rolled instead of `testcontainers-rs`: one fewer dep, full control over compose teardown, the same `docker-compose.yml` is usable directly for debugging. The harness is on the order of 200 lines.

Per-test isolation via unique compose project name (`format!("rimap-it-{}", Uuid::new_v4())`). Each test pays the container-startup tax. If startup time later becomes painful, revisit with a `OnceLock<Arc<DovecotHarness>>` shared pattern — not in Sprint 3.

### Dovecot test cases

1. `connect_with_correct_pin_succeeds` — happy path; assert connected, `is_connected()` is true.
2. `connect_with_wrong_pin_emits_audit_and_returns_tls_error` — pin a deliberately wrong fingerprint, assert `Error::Tls { observed, expected }`, read the audit file back, find one `Auth { outcome: TlsFingerprintMismatch }` with matching observed and expected.
3. `connect_with_no_pin_uses_system_trust_and_fails_self_signed` — verifies the unpinned path actually validates; Dovecot's self-signed cert is not in webpki-roots, so this should fail at handshake. Asserts the error is a webpki path error, not silently accepted.
4. `login_rejected_emits_audit` — wrong password; assert `Error::Auth(LoginRejected)` and one matching audit record.
5. `list_returns_seeded_folders` — connect, `LIST "" "*"`, assert `INBOX`, `Archive`, `INBOX/Subfolder` present.
6. `search_structured_subject_match` — fixture mailbox has a known subject; structured search returns its UID.
7. `search_raw_passthrough` — `SearchQuery::Raw(...)` returns the expected UID.
8. `fetch_envelope_and_bodystructure` — fetch a multipart fixture; assert structure has 2 parts and envelope subject is the expected raw bytes.
9. `fetch_body_under_limit` — fetch raw bytes; assert length matches the fixture file.
10. `fetch_body_over_limit_drops_connection` — set `max_fetch_bytes = 1024`, fetch a 2 KB fixture, assert `Error::SizeLimit { limit: 1024 }`, assert `is_connected()` is now false (connection dropped per the §6 invariant).
11. `tcp_half_open_recovery` — establish, kill the container's IMAP process (`docker compose exec dovecot pkill imap`); the next op should return `Error::ConnectionLost`; the *following* op should successfully reconnect. Tests both the no-auto-retry rule and lazy reconnect.

A 12th test case for `command_timeout` firing is hard to make deterministic against a real server. It is replaced with a unit test in `crates/rimap-imap/src/time.rs` covering the timeout wrapper helper directly against a `tokio::time::pause()`-driven clock.

That gives 11 Dovecot integration tests + 1 timeout unit test = the integration suite for Sprint 3 exit criteria.

### Proton Bridge harness (local only)

`tests/integration/proton.rs`. Each test starts with a runtime guard:

```rust
fn require_proton_bridge() -> ProtonBridgeConfig {
    if env::var("PROTON_BRIDGE_TEST").is_err() {
        eprintln!("skipping: set PROTON_BRIDGE_TEST=1 to run");
        return ProtonBridgeConfig::skip();
    }
    // read PROTON_BRIDGE_HOST, _PORT, _USER, _PASS, _FINGERPRINT
}
```

`tests/integration/proton/README.md` documents the env vars, how to find Bridge's host/port (default `127.0.0.1:1143`), how to extract its fingerprint with `openssl s_client -connect 127.0.0.1:1143 -starttls imap`, and the security implications of putting real credentials in env vars. Two tests: connect+list, connect+fetch one message. Never runs in CI.

## 8. Sprint task ordering

Each item below is a single reviewable atomic commit. This list becomes the implementation plan's chunk list.

1. `feat(core): add TlsFingerprint newtype` — closes #21. New `rimap-core/src/tls.rs`, `subtle` dep, hex parse/display, constant-time eq, serde impls. Unit tests on parse/format/round-trip. No callers yet — pure type addition.
2. `refactor(audit): type Auth.tls_fingerprint_sha256 as TlsFingerprint` — switches the field type, updates the JSONL serializer, no schema change on disk.
3. `feat(audit): add log_process_start helper` — closes #24. New `AuditWriter::log_process_start`, `ProcessStart` record type with `version` / `pid` / `started_at` / `config_hash`. Unit test asserts the record lands in the JSONL stream and is replayable by the reader.
4. `feat(server): emit process_start at startup` — `rimap-server::main` calls `log_process_start` once after opening the audit writer, before any other emission. Updates the existing e2e audit-merge round-trip test to assert the first record is `ProcessStart`.
5. `chore(imap): scaffold rimap-imap dependencies and module skeleton` — adds `async-imap`, `tokio-rustls`, `webpki-roots` (and `rustls` to workspace if not pinned). Empty modules per §2 layout. `cargo build` green, `cargo deny check` green (most likely place to surface dupes — fix via `cargo update` per the watchlist; do not add deny.toml skips).
6. `feat(imap): TlsConfig builder with PinningVerifier and system-trust modes` — `tls.rs` complete, no network. Unit tests in `tests/tls_pinning.rs` construct both verifier modes and exercise the `OnceLock` capture path with synthetic cert DER.
7. `feat(imap): types and error taxonomy` — `types.rs` (`Uid`, `Envelope`, `BodyStructure`, `Folder`, `FolderStatus`, `Flag`, `SearchQuery`, `FetchSpec`, `FetchedMessage`) and `error.rs` (`Error`, `AuthFailure`, `From` impls). `tests/error_mapping.rs` asserts the `#[source]` chain is preserved through `From<rimap_imap::Error> for RimapError` and closes #27 in passing.
8. `feat(imap): Connection::ensure_connected with auth and audit emission` — connect / handshake / login / `CAPABILITY` flow per §5, including the `spawn_blocking` audit emission. Unit-testable parts unit-tested; the full path waits for the Dovecot harness in step 12.
9. `feat(imap): list/status/select read ops` — `ops/folders.rs` with `list_folders` / `status` / `select`. Wires `command_timeout`. No integration test yet.
10. `feat(imap): search structured + raw and fetch envelope/bodystructure/uid/flags/size` — `ops/search.rs`, `ops/fetch.rs` (without `BODY[]`).
11. `feat(imap): fetch_body with size cap and connection drop on overflow` — the streaming path. Most subtle code in the sprint. Has its own integration test (case 10 above) and a unit test against a tokio mock for the size-cap-mid-stream path.
12. `test(imap): dovecot integration harness` — `tests/integration/dovecot/` directory tree, `support/docker.rs`, fixture files. Just the harness, no test bodies yet.
13. `test(imap): dovecot integration test cases 1-11` — the 11 dovecot tests + the `time.rs` unit test from §7. CI runs Docker; local devs without Docker get the skip path.
14. `docs(imap): proton bridge harness README and gated tests` — documentation + two gated tests. Never runs in CI.
15. `docs(audit): document the spawn_blocking audit emission rule` — short paragraph on `Connection::ensure_connected` and a workspace-level note in `docs/architecture/audit-locking.md` (new file) explaining std-mutex-no-await vs tokio-mutex-yes-await for the two locks.

## 9. Exit criteria

- All 15 commits land via `feat/sprint-3-implementation` branch into a single PR.
- All 7 CI checks green: rustfmt, clippy (`-D warnings`), test (stable), test (MSRV 1.88.0), cargo-deny, zizmor, SonarQube.
- Dovecot integration tests pass under `RIMAP_REQUIRE_DOCKER=1` (CI sets this).
- Local Proton Bridge tests pass (developer-verified, recorded in PR description).
- `cargo deny` clean with no new skips beyond the documented `hashbrown 0.14` and `windows-sys 0.48/0.52/0.59`.
- `Auth` audit records emit on every connect attempt against Dovecot, observable via `rimap-server audit merge`.
- `ProcessStart` audit record emits once at server startup.
- No `Connection::ensure_connected` audit emission holds the audit lock across an `.await` (manual review + rustdoc note).
- Issues #21, #24, #27 closed.

## 10. Security review sweep (before PR push)

- **`rust-safety-reviewer`** — load-bearing. New unsafe-adjacent surfaces: `PinningVerifier`, `Connection` mutex discipline, `tokio::time::timeout` semantics, `secrecy::SecretString` zeroize.
- **`email-imap-security-reviewer`** — load-bearing. IMAP protocol handling: LITERAL handling, response parsing trust, command injection in `LIST` / `STATUS` / `SELECT` (folder name escaping), `SEARCH::Raw` boundary.
- **`supply-chain-reviewer`** — load-bearing. The four new deps (`async-imap`, `tokio-rustls`, `webpki-roots`, `subtle`).
- **`local-security-reviewer`** — sanity sweep. Dovecot harness: container isolation, fixture file permissions, fingerprint extraction race.
- **`mcp-security-reviewer`** — sanity sweep. Sprint 3 does not touch the MCP surface; this pass mainly confirms no IMAP state leaks into stdout.
