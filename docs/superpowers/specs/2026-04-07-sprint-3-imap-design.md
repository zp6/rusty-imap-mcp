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
pub use connection::{Connection, ConnectionConfig};
pub use error::{Error, AuthFailure};
pub use rimap_core::tls::TlsFingerprint;
pub use types::{
    Envelope, BodyStructure, Folder, FolderStatus, Flag, Uid, MessageId,
    SearchQuery, FetchSpec, FetchedMessage, SelectedFolder, StatusItems,
};

// connection.rs
/// Everything `Connection` needs to open a session, pulled out of
/// `rimap-config::ValidatedConfig` by the caller. `Connection` owns a clone
/// of this value for the lifetime of the handle.
pub struct ConnectionConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub pinned_fingerprint: Option<TlsFingerprint>,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub max_fetch_body_bytes: u64,
}

impl Connection {
    /// Build a connection handle. Does NOT open a socket. The credential
    /// store is fetched fresh for each LOGIN attempt via `resolve_credential`.
    pub fn new(
        cfg: ConnectionConfig,
        audit: AuditWriter,
        credentials: Arc<dyn CredentialStore>,
    ) -> Self;

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

`ConnectionConfig` is assembled by the caller from `rimap-config::ValidatedConfig` (pulling `imap.host`, `imap.port`, `imap.username`, the parsed `TlsFingerprint`, `imap.command_timeout_seconds`, a new `imap.connect_timeout_seconds` field this sprint adds with a 10-second default, and `limits.max_fetch_body_bytes`). `AuditWriter` comes from `rimap-audit` and is cheaply cloneable (`Arc<Mutex<_>>` internally). `CredentialStore` is the existing `rimap-config::credential::CredentialStore` trait; `Arc<dyn CredentialStore>` lets tests inject an in-memory store.

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

### Audit field stays `Option<String>`

The existing `Auth.tls_fingerprint_sha256: Option<String>` (lowercase hex) is kept as-is. The emission site in `rimap-imap` converts the observed `TlsFingerprint` via `to_hex()` before building the record. No change to `rimap-audit` record schemas, no cascading changes to Sprint 2 tests. Issue #21 is scoped strictly to introducing the `TlsFingerprint` newtype in `rimap-core` and using it in `rimap-config::ValidatedConfig` (the parsed form of the pin) and `rimap-imap` (observed and compared in the verifier).

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

1. Read the `ConnectionConfig` held on `Connection`: host, port, username, optional pinned fingerprint, timeouts, body size cap.
2. Open TCP under `connect_timeout` deadline (covers TCP + TLS + greeting). On failure, emit an `Auth` failure record (see §5 audit emission) with `error_code = Some("ERR_NETWORK")` and return `Error::Connect`.
3. TLS handshake using the `TlsConfig` from §4. The verifier captures the observed fingerprint into its `OnceLock` regardless of outcome.
4. **TLS fingerprint mismatch:** the verifier rejected the cert. Read the captured `OnceLock` (must be `Some` because the cert was seen before the mismatch decision), emit `Auth { result: Failure, tls_fingerprint_sha256: Some(observed.to_hex()), fingerprint_match: Some(false), error_code: Some("ERR_TLS") }`, return `Error::Tls { observed, expected }`.
5. **Other TLS handshake errors** (signature algorithm, protocol, webpki path error in unpinned mode) → emit `Auth { result: Failure, tls_fingerprint_sha256: observed.map(|f| f.to_hex()), fingerprint_match: None, error_code: Some("ERR_TLS") }`, return `Error::TlsHandshake(err)`. `observed` is `None` here only if the handshake failed before the verifier ran.
6. Wait for the IMAP greeting under the remaining `connect_timeout` budget. A `BYE` greeting triggers `Auth { result: Failure, error_code: Some("ERR_AUTH") }` and returns `Error::Auth(ServerRejected)`.
7. Run `CAPABILITY`. If `LOGINDISABLED` is advertised, emit `Auth { result: Failure, error_code: Some("ERR_AUTH") }`, return `Error::Auth(CapabilityMissing { needed: "LOGIN" })`, and tear down the connection.
8. Fetch the password via `resolve_credential(&*credentials, &cfg.username, &cfg.host)`. The returned `String` is used exactly once (pass it to `async-imap`'s `login` call), then the local variable is dropped. It is never stored on `Connection`, never borrowed across `.await` boundaries except inside the LOGIN call itself, and never referenced by any audit record. The username is structurally present in the audit record but is never traced or logged in plaintext anywhere else (Sprint 2's secret invariant from commit 68cf620).
9. **LOGIN reject:** emit `Auth { result: Failure, tls_fingerprint_sha256: Some(observed.to_hex()), fingerprint_match: pinned.map(|p| p == observed), error_code: Some("ERR_AUTH") }`, return `Error::Auth(LoginRejected)`.
10. **LOGIN success:** emit `Auth { result: Success, tls_fingerprint_sha256: Some(observed.to_hex()), fingerprint_match: pinned.map(|p| p == observed), error_code: None }`. Connection is now ready for ops.

All ten Auth records share the same `host`, `port`, and `username` fields from `ConnectionConfig`.

### Audit lock discipline (load-bearing rule)

The audit lock is `std::sync::Mutex` and must NEVER be held across an `.await`. Every `Auth` emission inside `ensure_connected` happens via:

```rust
let audit = audit.clone();
tokio::task::spawn_blocking(move || audit.log_auth(record)).await??;
```

Yes, every connect pays one task hop for audit emission. This is intentional, worth it, and documented inline at every emission site so future maintainers do not "optimize" it away. A workspace-level note in `docs/architecture/audit-locking.md` explains the std-mutex-no-await vs tokio-mutex-yes-await split between the two locks.

### Per-process state on `AuditWriter` (new in Sprint 3)

Sprint 2 ships `AuditWriter::write_record(&self, &AuditRecord)` as the only emission entry point, requiring callers to supply `seq`, `ts`, `process_id` explicitly. That's fine for the Sprint 2 unit tests but wrong for a real running process, where `process_id` must be stable across every record of a run and `seq` must be per-process monotonic.

Sprint 3 extends `AuditWriter` with:

- A per-writer `process_id: ProcessId`, set at open time from `ProcessId::new_now()`.
- A per-writer `next_seq: Seq` counter (inside `Inner` under the existing mutex), initialized from a caller-supplied `Seq` (derived from `TrailingState::last_seq + 1` at open time, or `Seq::FIRST` for a fresh file).
- New typed emission helpers that allocate `seq`, stamp `ts = Timestamp::now()`, use the writer's `process_id`, and delegate to the existing `write_record` for the actual I/O:
  ```rust
  pub fn log_process_start(&self, inputs: ProcessStartInputs) -> Result<Seq, AuditError>;
  pub fn log_auth(&self, payload: Auth) -> Result<Seq, AuditError>;
  ```
- `AuditOptions` gains an `initial_seq: Seq` field (default `Seq::FIRST`). The caller runs `read_trailing_state` before `AuditWriter::open` and passes `trailing.last_seq.map(Seq::next).unwrap_or(Seq::FIRST)`.
- The existing `write_record(&self, &AuditRecord) -> Result<(), AuditError>` stays public for integration tests that need to inject specific seq values, but is only called from the typed helpers in production code.

### `log_process_start` helper (closes #24)

Sprint 3 is the first sprint that emits anything during the process lifetime, so the chain-of-history tamper signal needs an anchor. Without it, every gap looks like tampering.

The helper takes an input struct because the caller is the only one that knows the config path, posture, and can pre-compute the hash:

```rust
// rimap-audit additions
pub struct ProcessStartInputs {
    pub version: String,              // CARGO_PKG_VERSION
    pub git_commit: String,           // empty until vergen wired in Sprint 5
    pub posture: String,              // e.g. "draft-safe"
    pub config_path: PathBuf,
    pub config_hash_sha256: String,   // hex, caller computes
    pub trailing: TrailingState,      // from read_trailing_state before open
    pub current_inode: u64,           // from current_inode(path) after open
}

impl AuditWriter {
    /// Build a `ProcessStart` record from `inputs` and the writer's own
    /// `process_id`, allocate a `seq`, and write it through `write_record`.
    /// This is the ONLY supported way to emit a `process_start` record from
    /// a long-running process — tests still use the low-level `write_record`
    /// directly.
    pub fn log_process_start(&self, inputs: ProcessStartInputs) -> Result<Seq, AuditError>;
}
```

Implementation: builds the `ProcessStart` struct by mapping `trailing.last_seq` → `previous_last_seq`, `trailing.last_process_id` → `previous_process_id`, `current_inode` → `previous_file_inode`, and `audit_file_inode_changed = trailing.last_recorded_inode.is_some_and(|i| i != current_inode)`. Then delegates to `write_record`.

`rimap-server::main` calls `log_process_start` once after opening the audit writer, before any other emission. The existing audit-merge round-trip test is updated to assert the first record on a fresh log is `process_start`.

### `log_auth` helper

```rust
impl AuditWriter {
    /// Allocate a seq, stamp the timestamp, wrap `payload` in an
    /// `AuditRecord`, and write. Returns the allocated seq.
    pub fn log_auth(&self, payload: Auth) -> Result<Seq, AuditError>;
}
```

Where `Auth` is the existing Sprint 2 record type (not a new one):

```rust
// From crates/rimap-audit/src/record.rs — unchanged this sprint.
pub struct Auth {
    pub result: AuthResult,                     // Success | Failure
    pub host: String,
    pub port: u16,
    pub username: String,
    pub tls_fingerprint_sha256: Option<String>, // lowercase hex
    pub fingerprint_match: Option<bool>,
    pub error_code: Option<String>,             // stable code e.g. "ERR_TLS"
}

pub enum AuthResult { Success, Failure }
```

Every `Auth` record the dispatch in §5 emits is built directly as this struct — no intermediate enum layer, no new types.

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

1. `feat(core): add TlsFingerprint newtype` — closes #21. New `rimap-core/src/tls.rs`, `subtle` dep, hex parse / display / serde impls, `from_cert_der`, constant-time eq. Unit tests on parse/format/round-trip/eq. No callers yet — pure type addition.
2. `feat(config): parse tls_fingerprint_sha256 into TlsFingerprint and add connect_timeout_seconds` — `rimap-config::validate` turns the raw `Option<String>` from `ImapConfig` into `Option<TlsFingerprint>` on `ValidatedConfig`. Adds a new `imap.connect_timeout_seconds: u32` TOML field with a 10-second default (serde default). No schema break: existing configs omit the field and get the default.
3. `feat(audit): add per-process seq counter and process_id to AuditWriter` — `AuditOptions` gains `initial_seq: Seq`; `AuditWriter::open` records a `ProcessId::new_now()` and initializes `next_seq`. New helper `pub fn process_id(&self) -> ProcessId`. Existing `write_record` still accepts explicit seq/pid for tests. Unit test: two calls to a new typed helper produce records with the same `process_id` and monotonic `seq`.
4. `feat(audit): log_auth helper on AuditWriter` — `pub fn log_auth(&self, payload: Auth) -> Result<Seq, AuditError>`. Allocates `seq`, stamps `ts = Timestamp::now()`, wraps in `AuditRecord`, delegates to `write_record`. Unit test asserts the written line has the expected flat-kind discriminator and the allocated seq.
5. `feat(audit): log_process_start helper on AuditWriter` — closes #24. `ProcessStartInputs` struct, `pub fn log_process_start(&self, inputs: ProcessStartInputs) -> Result<Seq, AuditError>` that computes `audit_file_inode_changed` from `inputs.trailing.last_recorded_inode` vs `inputs.current_inode`. Unit test asserts chain-of-history fields populate correctly when `trailing` contains a previous run.
6. `feat(server): emit process_start at startup` — `rimap-server::main` runs `read_trailing_state` → `AuditWriter::open(initial_seq)` → `current_inode` → `log_process_start(...)` in that order. Updates the existing e2e audit-merge round-trip test to assert the first record on a fresh log is `process_start` with a matching `config_hash_sha256`.
7. `chore(imap): scaffold rimap-imap dependencies and module skeleton` — adds `async-imap`, `tokio-rustls`, `rustls` (if not already workspace-pinned), `webpki-roots`. Empty modules per §2 layout. Internal deps (`rimap-core`, `rimap-config`, `rimap-audit`) added via path+version per the workspace rule. `cargo build` green, `cargo deny check` green (if a duplicate version trips the ban, resolve via `cargo update`, never add deny.toml skips).
8. `feat(imap): types and error taxonomy` — `types.rs` (`Uid`, `Envelope`, `BodyStructure`, `Folder`, `FolderStatus`, `Flag`, `SearchQuery`, `FetchSpec`, `FetchedMessage`, `SelectedFolder`, `StatusItems`, `StructuredQuery`) and `error.rs` (`Error`, `AuthFailure`, `From<rimap_imap::Error> for RimapError`). `tests/error_mapping.rs` asserts the `#[source]` chain is preserved all the way through. Closes #27 in passing by adding `From<AuditError> for RimapError` with the same `#[source]` preservation.
9. `feat(imap): TlsConfig builder with PinningVerifier and system-trust modes` — `tls.rs` complete, no network. Unit tests in `tests/tls_pinning.rs` construct both verifier modes and exercise the `OnceLock` capture path with synthetic cert DER.
10. `feat(imap): ConnectionConfig and Connection::ensure_connected with auth and audit emission` — connect / handshake / login / `CAPABILITY` flow per §5, including the `spawn_blocking` audit emission. `auth.rs` holds the Auth-record construction helpers. Unit-testable pieces unit-tested; the full path waits for the Dovecot harness in step 14.
11. `feat(imap): list/status/select read ops` — `ops/folders.rs` with `list_folders` / `status` / `select`. Wires `command_timeout` via `time.rs` helper. No integration test yet.
12. `feat(imap): search and fetch envelope/bodystructure/uid/flags/size` — `ops/search.rs` (structured + raw) and `ops/fetch.rs` (without `BODY[]`).
13. `feat(imap): fetch_body with size cap and connection drop on overflow` — the streaming path. Unit test for `time.rs` timeout helper using `tokio::time::pause()`.
14. `test(imap): dovecot integration harness` — `tests/integration/dovecot/` directory tree, `support/docker.rs`, fixture files. Just the harness, no test bodies yet.
15. `test(imap): dovecot integration test cases 1-11` — the 11 dovecot tests from §7. CI runs Docker; local devs without Docker get the skip path.
16. `docs(imap): proton bridge harness README and gated tests` — documentation + two gated tests. Never runs in CI.
17. `docs(audit): document the spawn_blocking audit emission rule` — short paragraph on `Connection::ensure_connected` and a workspace-level note in `docs/architecture/audit-locking.md` (new file) explaining std-mutex-no-await vs tokio-mutex-yes-await for the two locks.

## 9. Exit criteria

- All 17 commits land via `feat/sprint-3-implementation` branch into a single PR.
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
