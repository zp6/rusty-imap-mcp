//! `Connection`: lazy-connect IMAP session with TLS fingerprint pinning,
//! command timeout enforcement, and `Auth` audit emission.
//!
//! ## Locking discipline
//!
//! - The `tokio::sync::Mutex` around `Option<Session>` IS held across `.await`
//!   points (it has to be — async-imap commands are themselves `.await`).
//! - The `rimap_audit::AuditWriter` lock (a `std::sync::Mutex`) is NEVER held
//!   across an `.await`. Every audit emission goes through
//!   `tokio::task::spawn_blocking`.
//!
//! These two rules are independent and both must hold. See
//! `docs/architecture/audit-locking.md` (added in Task 17).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_imap::Session;
use async_imap::imap_proto::{Capability as ImapCapability, Response, Status};
use async_imap::types::UnsolicitedResponse;
use rimap_audit::AuditWriter;
use rimap_audit::record::Auth;
use rimap_config::credential::{CredentialStore, resolve_credential};
use rimap_core::TlsFingerprint;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::auth::{AuthContext, auth_failure, auth_success};
use crate::error::{AuthFailure, ImapError};
use crate::tls::{TlsConfigBundle, build_tls_config};

/// Everything `Connection` needs to open a session, pulled out of a
/// `rimap_config::ValidatedAccountConfig` entry inside the overall
/// `ValidatedMultiConfig` by the caller. `Connection` clones this value
/// once at construction time.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Account name this connection belongs to. `None` for the legacy
    /// single-account `"default"` deployment; `Some(name)` in multi-account
    /// configs. Populated into `Auth` audit records.
    pub account: Option<String>,
    /// Account id used for keyring lookups. Always set — the default account
    /// uses `AccountId::default_account()`.
    pub account_id: rimap_core::account::AccountId,
    /// Credential fallback policy: whether to consult the env var when the
    /// keyring has no entry.
    pub fallback_mode: rimap_config::model::FallbackMode,
    /// IMAP server host.
    pub host: String,
    /// IMAP server port (typically 993 for IMAPS).
    pub port: u16,
    /// IMAP username.
    pub username: String,
    /// Optional pinned TLS fingerprint. `None` = use system trust roots.
    pub pinned_fingerprint: Option<TlsFingerprint>,
    /// TCP + TLS handshake + greeting + CAPABILITY deadline.
    pub connect_timeout: Duration,
    /// Per-IMAP-command deadline applied via `tokio::time::timeout`.
    pub command_timeout: Duration,
    /// Hard cap on `FETCH BODY[]` byte count.
    pub max_fetch_body_bytes: u64,
    /// Hard cap on `APPEND` message byte count.
    pub max_append_bytes: u64,
}

/// Active IMAP session type alias. `async-imap` parameterizes over the
/// underlying transport; we always use `TlsStream<TcpStream>`.
pub(crate) type ImapSession = Session<TlsStream<TcpStream>>;

/// Lazy-connect IMAP connection. Cheaply cloneable (`Arc` internally).
#[derive(Clone)]
pub struct Connection {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    cfg: ConnectionConfig,
    audit: AuditWriter,
    credentials: Arc<dyn CredentialStore>,
    /// `None` = never connected, or last command tore down the connection.
    /// `Some(_)` = live session ready for the next command.
    session: Mutex<Option<ImapSession>>,
    /// Server advertised MOVE capability (RFC 6851) after login.
    /// Reset to `false` on `invalidate()`.
    has_move: AtomicBool,
    /// Server advertised UIDPLUS capability (RFC 4315) after login.
    /// Reset to `false` on `invalidate()`.
    has_uidplus: AtomicBool,
    /// Server advertised LIST-STATUS capability (RFC 5819) after login.
    /// Currently informational: async-imap does not yet expose the
    /// extended LIST command, so `list_folders_with_status` always takes
    /// the per-folder STATUS fallback path. Once async-imap surfaces
    /// LIST-STATUS, the fallback can gate on this flag.
    has_list_status: AtomicBool,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("host", &self.inner.cfg.host)
            .field("port", &self.inner.cfg.port)
            .field("username", &self.inner.cfg.username)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Build a connection handle. Does NOT open a socket.
    #[must_use]
    pub fn new(
        cfg: ConnectionConfig,
        audit: AuditWriter,
        credentials: Arc<dyn CredentialStore>,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                cfg,
                audit,
                credentials,
                session: Mutex::new(None),
                has_move: AtomicBool::new(false),
                has_uidplus: AtomicBool::new(false),
                has_list_status: AtomicBool::new(false),
            }),
        }
    }

    /// Read the configured host (used by ops to log context).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.inner.cfg.host
    }

    /// Read the configured IMAP username. Typically the account's
    /// email address, and suitable for use as the `From:` header.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.inner.cfg.username
    }

    /// Acquire the session lock; lazy-connect if needed. The returned guard
    /// holds the tokio mutex; drop it before any other method on `Connection`.
    pub(crate) async fn session(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ImapSession>>, ImapError> {
        let mut guard = self.inner.session.lock().await;
        if guard.is_none() {
            let session = self.connect_inner().await?;
            *guard = Some(session);
        }
        Ok(guard)
    }

    /// Whether the server advertised the MOVE capability (RFC 6851).
    #[must_use]
    pub fn has_move_capability(&self) -> bool {
        self.inner.has_move.load(Ordering::Relaxed)
    }

    /// Whether the server advertised the UIDPLUS capability (RFC 4315).
    #[must_use]
    pub fn has_uidplus_capability(&self) -> bool {
        self.inner.has_uidplus.load(Ordering::Relaxed)
    }

    /// Whether the server advertises LIST-STATUS (RFC 5819).
    ///
    /// Currently informational — `list_folders_with_status` always uses
    /// the LIST-then-STATUS-per-folder fallback regardless. A future
    /// async-imap release may expose the extended LIST command.
    #[must_use]
    pub fn has_list_status_capability(&self) -> bool {
        self.inner.has_list_status.load(Ordering::Relaxed)
    }

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
        self.inner.has_move.store(false, Ordering::Relaxed);
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
        self.inner.has_list_status.store(false, Ordering::Relaxed);
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path.
    async fn connect_inner(&self) -> Result<ImapSession, ImapError> {
        let cfg = &self.inner.cfg;
        let bundle = build_tls_config(cfg.pinned_fingerprint)?;

        // Run the connect flow. The return type carries `credential_source` for
        // both the success and post-resolve-failure paths.  Pre-resolve failures
        // (TLS, connect, greeting, CAPABILITY) return `None`; post-resolve
        // failures (LoginRejected) and success both return `Some(source)`.
        let raw_outcome = self.connect_with_bundle(&bundle).await;
        let (outcome, credential_source) = match raw_outcome {
            Ok((session, src)) => (Ok(session), Some(src)),
            Err((ImapError::TlsHandshake(inner), src)) => {
                let enriched = match (cfg.pinned_fingerprint, bundle.last_observed.get().copied()) {
                    (Some(expected), Some(observed)) if expected != observed => {
                        ImapError::Tls { observed, expected }
                    }
                    (Some(_) | None, _) => ImapError::TlsHandshake(inner),
                };
                (Err(enriched), src)
            }
            Err((other, src)) => (Err(other), src),
        };

        let observed = bundle.last_observed.get().copied();
        let ctx = AuthContext {
            account: cfg.account.as_deref(),
            host: &cfg.host,
            port: cfg.port,
            username: &cfg.username,
            pinned: cfg.pinned_fingerprint,
            observed,
            credential_source,
        };

        match &outcome {
            Ok(_) => self.emit_auth(auth_success(&ctx)).await?,
            Err(err) => {
                // Deliberate: log but do NOT propagate emit_auth failures on
                // the error branch. The ORIGINAL outcome (ImapError::Auth,
                // ImapError::TlsHandshake, ImapError::Connect, ...) is what the
                // caller and monitoring need to see. Replacing it with
                // ImapError::Audit would mask brute-force signals from
                // whatever observed ERR_AUTH before. Audit-write failures
                // on this path are still visible via tracing; operators
                // running fail_open=false will additionally see the
                // suppressed_failures counter in process_end once #8
                // lands.
                if let Err(audit_err) = self.emit_auth(auth_failure(&ctx, err.code())).await {
                    tracing::error!(
                        original_error = %err,
                        audit_error = %audit_err,
                        "audit write failed during auth-failure emission; \
                         preserving original error for observability",
                    );
                }
            }
        }
        outcome
    }

    /// Returns `Ok((session, credential_source))` on success, or
    /// `Err((error, Option<credential_source>))` on failure. The
    /// `credential_source` in the `Err` variant is `Some` when the failure
    /// occurred after `resolve_credential` succeeded (e.g. server rejected
    /// the credentials), and `None` for pre-resolve failures (TLS, connect,
    /// greeting, CAPABILITY).
    async fn connect_with_bundle(
        &self,
        bundle: &TlsConfigBundle,
    ) -> Result<
        (ImapSession, rimap_core::CredentialSource),
        (ImapError, Option<rimap_core::CredentialSource>),
    > {
        let cfg = &self.inner.cfg;
        let total_deadline = cfg.connect_timeout;
        let started = std::time::Instant::now();

        // Step 1: TCP connect. Pre-resolve; failures carry `None`.
        let tcp = timeout(
            total_deadline,
            TcpStream::connect((cfg.host.as_str(), cfg.port)),
        )
        .await
        .map_err(|_| (ImapError::Timeout { op: "tcp_connect" }, None))?
        .map_err(|e| (ImapError::Connect(e), None))?;

        // Step 2: TLS handshake. Pre-resolve; failures carry `None`.
        let server_name = ServerName::try_from(cfg.host.clone()).map_err(|_| {
            (
                ImapError::Connect(std::io::Error::other("invalid server name for TLS")),
                None,
            )
        })?;
        let connector = TlsConnector::from(bundle.config.clone());
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        let tls_stream = timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| {
                (
                    ImapError::Timeout {
                        op: "tls_handshake",
                    },
                    None,
                )
            })?
            .map_err(|e| (map_tls_handshake_error(&e), None))?;

        // Step 3: IMAP greeting + capability check + login. The login step
        // may return a credential source on both success and certain failures.
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        timeout(remaining, self.imap_login(tls_stream))
            .await
            .map_err(|_| (ImapError::Timeout { op: "imap_login" }, None))?
    }

    /// Run the IMAP greeting + CAPABILITY probe + LOGIN sequence.
    ///
    /// ## async-imap 0.11 API notes
    ///
    /// `capabilities()` is on `Session` (post-login), not on `Client`. To
    /// check LOGINDISABLED pre-login we:
    ///   1. Read the greeting via `Connection::read_response()`.
    ///   2. Issue `CAPABILITY` via `Connection::run_command_and_check_ok(cmd, Some(tx))`
    ///      and drain the unsolicited channel for `Other(ResponseData)` items
    ///      containing `Response::Capabilities` data.
    ///   3. Call `client.login(user, pass)`.
    ///
    /// Returns `Ok((session, credential_source))` on success.
    /// Returns `Err((error, Some(source)))` when the failure occurred after
    /// `resolve_credential` succeeded (e.g. server rejected the credentials).
    /// Returns `Err((error, None))` for pre-resolve failures (greeting, CAPABILITY).
    async fn imap_login(
        &self,
        tls_stream: TlsStream<TcpStream>,
    ) -> Result<
        (ImapSession, rimap_core::CredentialSource),
        (ImapError, Option<rimap_core::CredentialSource>),
    > {
        let mut client = async_imap::Client::new(tls_stream);

        // Read the server greeting. An absent greeting (EOF) or BYE status
        // means the server immediately rejected us. Pre-resolve; carry `None`.
        let greeting = client
            .read_response()
            .await
            .map_err(|e| (ImapError::Connect(e), None))?
            .ok_or((
                ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                },
                None,
            ))?;

        if let Response::Data {
            status: Status::Bye,
            ..
        } = greeting.parsed()
        {
            return Err((
                ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                },
                None,
            ));
        }

        // Issue CAPABILITY and scan responses for LOGINDISABLED.
        // We create a bounded channel so intermediate untagged responses
        // (including `* CAPABILITY ...`) are routed through it rather than
        // being silently discarded. Pre-resolve; carry `None`.
        let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
        client
            .run_command_and_check_ok("CAPABILITY", Some(tx))
            .await
            .map_err(|e| (ImapError::Protocol(e), None))?;

        // Drain whatever arrived on the channel (non-blocking; the command
        // has already completed). A `Response::Capabilities` list containing
        // LOGINDISABLED means LOGIN is prohibited. Pre-resolve; carry `None`.
        let logindisabled = drain_for_logindisabled(&rx);
        if logindisabled {
            return Err((
                ImapError::Auth {
                    reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
                },
                None,
            ));
        }

        // Resolve the password from the credential store. A missing
        // credential is an authentication failure, not a network failure —
        // map it to ERR_AUTH so retry logic and operator messages stay
        // accurate. Pre-resolve; carry `None`.
        let cfg = &self.inner.cfg;
        let (password, credential_source) = resolve_credential(
            &*self.inner.credentials,
            &cfg.account_id,
            &cfg.username,
            &cfg.host,
            cfg.fallback_mode,
        )
        .map_err(|e| {
            (
                ImapError::Auth {
                    reason: AuthFailure::CredentialUnavailable(e.to_string()),
                },
                None,
            )
        })?;

        // From here on, all errors carry `Some(credential_source)` because
        // resolution succeeded.
        //
        // Attempt LOGIN. On NO response the server rejected the credentials.
        // Expose the secret only at the moment of use; the borrow ends
        // when `client.login` returns.
        let mut session = match client.login(&cfg.username, password.expose_secret()).await {
            Ok(session) => session,
            Err((err, _client)) => {
                return match err {
                    async_imap::error::Error::No(_) => Err((
                        ImapError::Auth {
                            reason: AuthFailure::LoginRejected,
                        },
                        Some(credential_source),
                    )),
                    other => Err((ImapError::Protocol(other), Some(credential_source))),
                };
            }
        };

        // Post-login: probe CAPABILITY for MOVE (RFC 6851),
        // UIDPLUS (RFC 4315), and LIST-STATUS (RFC 5819).
        let (has_move, has_uidplus, has_list_status) = match session.capabilities().await {
            Ok(caps) => (
                caps.has_str("MOVE"),
                caps.has_str("UIDPLUS"),
                caps.has_str("LIST-STATUS"),
            ),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; \
                     assuming no MOVE/UIDPLUS/LIST-STATUS support",
                );
                (false, false, false)
            }
        };
        self.inner.has_move.store(has_move, Ordering::Relaxed);
        self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);
        self.inner
            .has_list_status
            .store(has_list_status, Ordering::Relaxed);

        Ok((session, credential_source))
    }

    /// Emit an `Auth` audit record. Runs `AuditWriter::log_auth` inside
    /// `spawn_blocking` so the `std::sync::Mutex` inside `AuditWriter` is
    /// never held across an `.await` boundary.
    ///
    /// ## Cancellation behavior
    ///
    /// If the caller future is cancelled at the `.await` below, the
    /// `JoinHandle` is dropped but the `spawn_blocking` task runs to
    /// completion — `tokio` does not kill blocking tasks on handle drop.
    /// The audit record IS written in that case, but the `Result` is
    /// lost: the caller sees neither a success nor an error. This is the
    /// least-bad outcome (audit integrity preserved, caller just gets a
    /// cancellation). Callers that MUST know whether the write succeeded
    /// should not drop this future.
    ///
    /// ## `ImapError` message sanitization
    ///
    /// The `ImapError::Audit { message }` uses the short error code
    /// (`audit_err.code()`) rather than the full `Display`, because
    /// `AuditError::Write` / `Fsync` / `Rotate` include the audit file
    /// path, which is operator-configured filesystem layout and should
    /// not propagate into MCP tool responses or client-visible error
    /// chains. The full error is still preserved in the `source` field
    /// for observability and log inspection.
    async fn emit_auth(&self, record: Auth) -> Result<(), ImapError> {
        let audit = self.inner.audit.clone();
        let join_result = tokio::task::spawn_blocking(move || audit.log_auth(record)).await;
        match join_result {
            Err(join_err) => Err(ImapError::Audit {
                op: "emit_auth",
                message: "tokio join error during audit write".to_string(),
                source: Box::new(join_err),
            }),
            Ok(Err(audit_err)) => {
                tracing::error!(
                    error = %audit_err,
                    "audit log_auth failed; converting to ImapError::Audit",
                );
                // Sanitized message: use only the stable error code, not
                // the Display (which may include the audit file path).
                // The full error is preserved in source.
                let message = format!("emit_auth: {}", audit_err.code());
                Err(ImapError::Audit {
                    op: "emit_auth",
                    message,
                    source: Box::new(audit_err),
                })
            }
            Ok(Ok(_seq)) => Ok(()),
        }
    }

    /// Run an IMAP operation with a command timeout and automatic session
    /// invalidation on connection-level failures.
    ///
    /// The closure receives a mutable reference to the live `Session`.
    /// If it returns `ImapError::ConnectionLost` or `ImapError::Timeout`, the
    /// cached session is dropped so the next call lazy-reconnects.
    async fn with_session<T, F>(&self, op_name: &'static str, body: F) -> Result<T, ImapError>
    where
        F: for<'s> AsyncFnOnce(&'s mut ImapSession) -> Result<T, ImapError>,
    {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout(op_name, dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            body(session).await
        })
        .await;
        if let Err(ImapError::ConnectionLost | ImapError::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    ///
    /// Drops the cached session on `ConnectionLost` so the next call
    /// lazy-reconnects without auto-retrying the failed command.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::list` call.
    pub async fn list_folders(
        &self,
        pattern: &str,
    ) -> Result<Vec<crate::types::Folder>, ImapError> {
        self.with_session("list", async |session| {
            crate::ops::folders::list(session, pattern).await
        })
        .await
    }

    /// List folders and fetch their STATUS in a single operation,
    /// using RFC 5819 LIST-STATUS when the server advertises the
    /// capability. Currently always falls back to LIST-then-STATUS-
    /// per-folder (async-imap does not yet expose the extended LIST).
    ///
    /// Returns `(Folder, Option<FolderStatus>)` pairs. Non-selectable
    /// folders return `None` for the status.
    ///
    /// # Errors
    /// Propagates `ImapError` from the underlying commands.
    pub async fn list_folders_with_status(
        &self,
        pattern: &str,
    ) -> Result<Vec<(crate::types::Folder, Option<crate::types::FolderStatus>)>, ImapError> {
        let has_list_status = self.inner.has_list_status.load(Ordering::Relaxed);
        self.with_session("list_folders_with_status", async move |session| {
            crate::ops::folders::list_with_status(session, pattern, has_list_status).await
        })
        .await
    }

    /// `STATUS` for `folder` selecting the requested items.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::status` call.
    pub async fn status(
        &self,
        folder: &str,
        items: crate::types::StatusItems,
    ) -> Result<crate::types::FolderStatus, ImapError> {
        self.with_session("status", async |session| {
            crate::ops::folders::status(session, folder, items).await
        })
        .await
    }

    /// `SELECT` (or `EXAMINE` if `read_only`) the named folder.
    ///
    /// # Errors
    /// Propagates any `ImapError` produced by `time::with_timeout` or the
    /// underlying `ops::folders::select` call.
    pub async fn select(
        &self,
        folder: &str,
        read_only: bool,
    ) -> Result<crate::types::SelectedFolder, ImapError> {
        self.with_session("select", async |session| {
            crate::ops::folders::select(session, folder, read_only).await
        })
        .await
    }

    /// `SEARCH` against `folder`. Returns matching UIDs.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::search::search` call.
    pub async fn search(
        &self,
        folder: &str,
        query: crate::types::SearchQuery,
    ) -> Result<Vec<crate::types::Uid>, ImapError> {
        self.with_session("search", async |session| {
            crate::ops::search::search(session, folder, query).await
        })
        .await
    }

    /// `FETCH` for the given UIDs with the requested items. Does NOT include
    /// `BODY[]` — see `fetch_body` (Task 13) for full message retrieval.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal EXAMINE (read-only SELECT). A
    /// mismatch returns `ImapError::UidValidityChanged` before the FETCH is
    /// sent. Pass `None` to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::fetch::fetch` call.
    pub async fn fetch(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        spec: crate::types::FetchSpec,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::FetchedMessage>, Option<u32>), ImapError> {
        self.with_session("fetch", async |session| {
            crate::ops::fetch::fetch(session, folder, uids, spec, expected_uidvalidity).await
        })
        .await
    }

    /// Fetch the full `BODY[]` of `uid` from `folder`. Returns raw bytes
    /// (no MIME parsing — Sprint 4's `rimap-content` owns that). Drops
    /// the connection on size-limit overflow OR connection loss so the
    /// half-consumed response state never leaks to the next op.
    ///
    /// # Pre-flight size check
    ///
    /// Before issuing `FETCH BODY.PEEK[]`, this method issues
    /// `UID FETCH <uid> (RFC822.SIZE)` and rejects with
    /// `ImapError::SizeLimit` if the server-reported size exceeds
    /// `max_fetch_body_bytes`. This prevents async-imap from buffering
    /// the full body into memory for oversize messages, at the cost of
    /// one extra IMAP round-trip.
    ///
    /// The post-parse `project_size` check inside `ops::fetch::fetch_body`
    /// remains as defense-in-depth because servers can lie about
    /// `RFC822.SIZE`.
    ///
    /// # Errors
    /// Propagates `ImapError::SizeLimit` if the body exceeds the configured
    /// `max_fetch_body_bytes`, plus the usual timeout / protocol /
    /// connection-lost errors.
    pub async fn fetch_body(
        &self,
        folder: &str,
        uid: crate::types::Uid,
    ) -> Result<Vec<u8>, ImapError> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_fetch_body_bytes;
        let result = crate::time::with_timeout("fetch_body", dur, async {
            let mut guard = self.session().await?;
            let session =
                guard
                    .as_mut()
                    .ok_or(ImapError::Protocol(async_imap::error::Error::Bad(
                        "session invariant violated: guard is None after session()".to_string(),
                    )))?;
            let server_size = crate::ops::fetch::preflight_fetch_size(session, folder, uid).await?;
            crate::ops::fetch::preflight_size_check(server_size, limit)?;
            crate::ops::fetch::fetch_body(session, folder, uid, limit).await
        })
        .await;
        // Drop the cached session on EITHER ConnectionLost OR SizeLimit.
        // SizeLimit means we aborted mid-stream, so the IMAP response
        // state is half-consumed and the session cannot be reused.
        // The match here lists every ImapError variant explicitly because
        // workspace lints ban `_ =>` wildcards.
        let should_invalidate = match &result {
            Err(ImapError::ConnectionLost | ImapError::SizeLimit { .. }) => true,
            Err(
                ImapError::Tls { .. }
                | ImapError::TlsHandshake(_)
                | ImapError::Connect(_)
                | ImapError::Timeout { .. }
                | ImapError::Auth { .. }
                | ImapError::Protocol(_)
                | ImapError::InvalidInput { .. }
                | ImapError::BatchTooLarge { .. }
                | ImapError::UidValidityChanged { .. }
                | ImapError::Audit { .. },
            )
            | Ok(_) => false,
        };
        if should_invalidate {
            self.invalidate().await;
        }
        result
    }

    /// `UID STORE` — add or remove flags on messages.
    ///
    /// Batch limit: 100 UIDs. Returns the UIDs the server confirmed.
    ///
    /// If `expected_uidvalidity` is `Some(v)`, the value is compared against
    /// the UIDVALIDITY returned by the internal SELECT. A mismatch returns
    /// `ImapError::UidValidityChanged` before the STORE is sent. Pass `None`
    /// to skip the guard.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn store_flags(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        flags: &[crate::types::Flag],
        action: crate::types::FlagAction,
        expected_uidvalidity: Option<u32>,
    ) -> Result<(Vec<crate::types::Uid>, Option<u32>), ImapError> {
        self.with_session("store", async |session| {
            let selected = crate::ops::folders::select(session, folder, false).await?;
            let uid_validity = selected.uid_validity;
            crate::ops::fetch::check_uidvalidity(folder, expected_uidvalidity, uid_validity)?;
            let updated = crate::ops::store::store(session, uids, flags, action).await?;
            Ok((updated, uid_validity))
        })
        .await
    }

    /// Move messages from `source_folder` to `dest_folder`.
    ///
    /// Uses IMAP MOVE extension (RFC 6851) when the server advertised
    /// it; falls back to COPY + STORE \Deleted + EXPUNGE otherwise.
    /// The fallback is not atomic — callers should inspect
    /// `MoveOutcome::used_fallback` and surface a warning.
    ///
    /// If `expected_source_uidvalidity` is `Some(v)`, a STATUS probe is
    /// issued against `source_folder` before the move. A mismatch
    /// returns `ImapError::UidValidityChanged`. Pass `None` to skip the
    /// guard (Task 4 will thread the observed value from SELECT through
    /// tool input).
    ///
    /// Batch limit: 100 UIDs.
    ///
    /// # Errors
    /// Returns `ImapError::BatchTooLarge` if more than 100 UIDs are passed.
    /// Returns `ImapError::UidValidityChanged` on a UIDVALIDITY mismatch.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn move_messages(
        &self,
        source_folder: &str,
        dest_folder: &str,
        uids: &[crate::types::Uid],
        expected_source_uidvalidity: Option<u32>,
    ) -> Result<crate::ops::move_message::MoveOutcome, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("move", async |session| {
            crate::ops::folders::select(session, source_folder, false).await?;
            crate::ops::move_message::move_messages(
                session,
                source_folder,
                dest_folder,
                uids,
                expected_source_uidvalidity,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// `APPEND` a raw RFC 5322 message to `folder` with the given
    /// flags and keywords.
    ///
    /// Does NOT select the folder first -- APPEND targets a named
    /// mailbox directly per RFC 3501 section 6.3.11.
    ///
    /// # Errors
    ///
    /// - `ImapError::SizeLimit` if `message.len()` exceeds the configured
    ///   `max_append_bytes`.
    /// - `ImapError::InvalidInput` if any keyword or `Flag::Keyword` value
    ///   contains non-atom characters.
    /// - Propagates timeout, connection-lost, or protocol errors from
    ///   async-imap.
    pub async fn append_message(
        &self,
        folder: &str,
        message: &[u8],
        flags: &[crate::types::Flag],
        keywords: &[&str],
    ) -> Result<crate::types::AppendResult, ImapError> {
        let limit = self.inner.cfg.max_append_bytes;
        self.with_session("append", async |session| {
            crate::ops::append::append(session, folder, message, flags, keywords, limit).await
        })
        .await
    }

    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
    ) -> Result<crate::ops::delete::DeleteResult, ImapError> {
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        self.with_session("delete_message", async |session| {
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::delete::delete_message(
                session,
                uid,
                folder,
                trash_folder,
                has_move,
                has_uidplus,
            )
            .await
        })
        .await
    }

    /// Expunge all `\Deleted` messages from `folder`.
    ///
    /// Returns `(deleted_uids, expunged_count)` — the UIDs found by
    /// `UID SEARCH DELETED` before the expunge, and the count from the
    /// EXPUNGE response.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::ConnectionLost` or `ImapError::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn expunge(&self, folder: &str) -> Result<(Vec<crate::types::Uid>, u32), ImapError> {
        self.with_session("expunge", async |session| {
            let deleted_uids = crate::ops::expunge::count_deleted(session, folder).await?;
            crate::ops::folders::select(session, folder, false).await?;
            let count = crate::ops::expunge::expunge(session).await?;
            Ok((deleted_uids, count))
        })
        .await
    }

    /// Create a new IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` for invalid names, `ImapError::ConnectionLost`
    /// or `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn create_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("create_folder", async |session| {
            crate::ops::folder_management::create_folder(session, name).await
        })
        .await
    }

    /// Rename an IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if either `old_name` or `new_name`
    /// fails `validate_folder_name` (empty, too long, or containing forbidden
    /// characters). Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn rename_folder(&self, old_name: &str, new_name: &str) -> Result<(), ImapError> {
        self.with_session("rename_folder", async |session| {
            crate::ops::folder_management::rename_folder(session, old_name, new_name).await
        })
        .await
    }

    /// Delete an IMAP folder and all its contents.
    ///
    /// # Errors
    ///
    /// Returns `ImapError::InvalidInput` if `name` fails
    /// `validate_folder_name`. Returns `ImapError::ConnectionLost` or
    /// `ImapError::Timeout` on transport failure, or a protocol error if
    /// the server rejects the command.
    pub async fn delete_folder(&self, name: &str) -> Result<(), ImapError> {
        self.with_session("delete_folder", async |session| {
            crate::ops::folder_management::delete_folder(session, name).await
        })
        .await
    }
}

/// Drain the unsolicited-response channel and return `true` if any
/// `Response::Capabilities` item contains the `LOGINDISABLED` atom.
///
/// The channel is non-blocking at this point: `run_command_and_check_ok`
/// has already returned (the tagged Done was received), so all intermediate
/// responses are already queued.
fn drain_for_logindisabled(rx: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    while let Ok(item) = rx.try_recv() {
        if let UnsolicitedResponse::Other(resp) = item
            && let Response::Capabilities(caps) = resp.parsed()
        {
            for cap in caps {
                if let ImapCapability::Atom(name) = cap
                    && name.eq_ignore_ascii_case("LOGINDISABLED")
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Map an `io::ImapError` from the TLS connect call to `ImapError::TlsHandshake`.
/// `connect_inner` will enrich this into `ImapError::Tls { observed, expected }`
/// when the `TlsConfigBundle`'s `last_observed` slot shows a mismatch.
fn map_tls_handshake_error(err: &std::io::Error) -> ImapError {
    ImapError::TlsHandshake(tokio_rustls::rustls::Error::General(err.to_string()))
}

/// Map a connect/login error to its stable short error code for the
/// audit log. Kept for the test harness that pins the complete
/// [`ImapError`] -> [`rimap_core::ErrorCode`] mapping; production
/// callers pass `err.code()` directly through [`ImapError::code`].
#[cfg(test)]
fn error_code_for(err: &ImapError) -> &'static str {
    err.code().as_str()
}

#[cfg(test)]
#[expect(clippy::panic, reason = "tests")]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::{error_code_for, map_tls_handshake_error};
    use crate::error::{AuthFailure, ImapError};
    use rimap_core::TlsFingerprint;

    fn fp_zeros() -> TlsFingerprint {
        TlsFingerprint::from_hex(&"00".repeat(32)).expect("valid 32-byte hex literal")
    }

    #[test]
    fn error_code_for_covers_every_variant() {
        let cases: Vec<(ImapError, &str)> = vec![
            (
                ImapError::Tls {
                    observed: fp_zeros(),
                    expected: fp_zeros(),
                },
                "ERR_TLS",
            ),
            (
                ImapError::TlsHandshake(tokio_rustls::rustls::Error::General("x".into())),
                "ERR_TLS",
            ),
            (
                ImapError::Connect(std::io::Error::other("boom")),
                "ERR_CONNECTION_LOST",
            ),
            (ImapError::ConnectionLost, "ERR_CONNECTION_LOST"),
            (ImapError::Timeout { op: "select" }, "ERR_TIMEOUT"),
            (
                ImapError::Auth {
                    reason: AuthFailure::ServerRejected,
                },
                "ERR_AUTH",
            ),
            (
                ImapError::SizeLimit { limit: 0 },
                "ERR_ATTACHMENT_TOO_LARGE",
            ),
            (
                ImapError::Protocol(async_imap::error::Error::Bad("x".into())),
                "ERR_IMAP_PROTOCOL",
            ),
            (
                ImapError::InvalidInput {
                    field: "f",
                    reason: "r",
                },
                "ERR_INVALID_INPUT",
            ),
            (
                ImapError::BatchTooLarge {
                    count: 200,
                    limit: 100,
                },
                "ERR_INVALID_INPUT",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(error_code_for(err), *expected, "for {err:?}");
        }
    }

    #[test]
    fn map_tls_handshake_error_wraps_io_error() {
        let io_err = std::io::Error::other("handshake boom");
        let mapped = map_tls_handshake_error(&io_err);
        match mapped {
            ImapError::TlsHandshake(e) => {
                assert!(e.to_string().contains("handshake boom"));
            }
            other => panic!("expected TlsHandshake variant, got {other:?}"),
        }
    }
}
