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
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::auth::{AuthContext, auth_failure, auth_success};
use crate::error::{AuthFailure, Error};
use crate::tls::{TlsConfigBundle, build_tls_config};

/// Everything `Connection` needs to open a session, pulled out of
/// `rimap_config::ValidatedConfig` by the caller. `Connection` clones this
/// value once at construction time.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
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
            }),
        }
    }

    /// Read the configured host (used by ops to log context).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.inner.cfg.host
    }

    /// Acquire the session lock; lazy-connect if needed. The returned guard
    /// holds the tokio mutex; drop it before any other method on `Connection`.
    pub(crate) async fn session(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ImapSession>>, Error> {
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

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
        self.inner.has_move.store(false, Ordering::Relaxed);
        self.inner.has_uidplus.store(false, Ordering::Relaxed);
    }

    /// The full connect/handshake/login/CAPABILITY flow. Emits exactly one
    /// `Auth` audit record on every termination path.
    async fn connect_inner(&self) -> Result<ImapSession, Error> {
        let cfg = &self.inner.cfg;
        let bundle = build_tls_config(cfg.pinned_fingerprint)?;

        // Run the connect flow. If it failed with a TLS handshake error AND
        // we have a pinned fingerprint, enrich the error into Error::Tls
        // with the structured observed/expected fields by reading the
        // bundle's last_observed slot.
        let raw_outcome = self.connect_with_bundle(&bundle).await;
        let outcome = match raw_outcome {
            Ok(session) => Ok(session),
            Err(Error::TlsHandshake(inner)) => {
                match (cfg.pinned_fingerprint, bundle.last_observed.get().copied()) {
                    (Some(expected), Some(observed)) if expected != observed => {
                        Err(Error::Tls { observed, expected })
                    }
                    (Some(_) | None, _) => Err(Error::TlsHandshake(inner)),
                }
            }
            Err(other) => Err(other),
        };

        let observed = bundle.last_observed.get().copied();
        let ctx = AuthContext {
            host: &cfg.host,
            port: cfg.port,
            username: &cfg.username,
            pinned: cfg.pinned_fingerprint,
            observed,
        };

        match &outcome {
            Ok(_) => self.emit_auth(auth_success(&ctx)).await?,
            Err(err) => {
                // Deliberate: log but do NOT propagate emit_auth failures on
                // the error branch. The ORIGINAL outcome (Error::Auth,
                // Error::TlsHandshake, Error::Connect, ...) is what the
                // caller and monitoring need to see. Replacing it with
                // Error::Audit would mask brute-force signals from
                // whatever observed ERR_AUTH before. Audit-write failures
                // on this path are still visible via tracing; operators
                // running fail_open=false will additionally see the
                // suppressed_failures counter in process_end once #8
                // lands.
                if let Err(audit_err) = self
                    .emit_auth(auth_failure(&ctx, error_code_for(err)))
                    .await
                {
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

    async fn connect_with_bundle(&self, bundle: &TlsConfigBundle) -> Result<ImapSession, Error> {
        let cfg = &self.inner.cfg;
        let total_deadline = cfg.connect_timeout;
        let started = std::time::Instant::now();

        // Step 1: TCP connect.
        let tcp = timeout(
            total_deadline,
            TcpStream::connect((cfg.host.as_str(), cfg.port)),
        )
        .await
        .map_err(|_| Error::Timeout { op: "tcp_connect" })?
        .map_err(Error::Connect)?;

        // Step 2: TLS handshake.
        let server_name = ServerName::try_from(cfg.host.clone())
            .map_err(|_| Error::Connect(std::io::Error::other("invalid server name for TLS")))?;
        let connector = TlsConnector::from(bundle.config.clone());
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        let tls_stream = timeout(remaining, connector.connect(server_name, tcp))
            .await
            .map_err(|_| Error::Timeout {
                op: "tls_handshake",
            })?
            .map_err(|e| map_tls_handshake_error(&e))?;

        // Step 3: IMAP greeting + capability check + login.
        let elapsed = started.elapsed();
        let remaining = total_deadline.saturating_sub(elapsed);
        timeout(remaining, self.imap_login(tls_stream))
            .await
            .map_err(|_| Error::Timeout { op: "imap_login" })?
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
    async fn imap_login(&self, tls_stream: TlsStream<TcpStream>) -> Result<ImapSession, Error> {
        let mut client = async_imap::Client::new(tls_stream);

        // Read the server greeting. An absent greeting (EOF) or BYE status
        // means the server immediately rejected us.
        let greeting = client
            .read_response()
            .await
            .map_err(Error::Connect)?
            .ok_or(Error::Auth {
                reason: AuthFailure::ServerRejected,
            })?;

        if let Response::Data {
            status: Status::Bye,
            ..
        } = greeting.parsed()
        {
            return Err(Error::Auth {
                reason: AuthFailure::ServerRejected,
            });
        }

        // Issue CAPABILITY and scan responses for LOGINDISABLED.
        // We create a bounded channel so intermediate untagged responses
        // (including `* CAPABILITY ...`) are routed through it rather than
        // being silently discarded.
        let (tx, rx) = async_channel::bounded::<UnsolicitedResponse>(32);
        client
            .run_command_and_check_ok("CAPABILITY", Some(tx))
            .await
            .map_err(Error::Protocol)?;

        // Drain whatever arrived on the channel (non-blocking; the command
        // has already completed). A `Response::Capabilities` list containing
        // LOGINDISABLED means LOGIN is prohibited.
        let logindisabled = drain_for_logindisabled(&rx);
        if logindisabled {
            return Err(Error::Auth {
                reason: AuthFailure::CapabilityMissing { needed: "LOGIN" },
            });
        }

        // Resolve the password from the credential store. A missing
        // credential is an authentication failure, not a network failure —
        // map it to ERR_AUTH so retry logic and operator messages stay
        // accurate.
        let cfg = &self.inner.cfg;
        let password = resolve_credential(&*self.inner.credentials, &cfg.username, &cfg.host)
            .map_err(|e| Error::Auth {
                reason: AuthFailure::CredentialUnavailable(e.to_string()),
            })?;

        // Attempt LOGIN. On NO response the server rejected the credentials.
        let mut session = match client.login(&cfg.username, &password).await {
            Ok(session) => session,
            Err((err, _client)) => {
                return match err {
                    async_imap::error::Error::No(_) => Err(Error::Auth {
                        reason: AuthFailure::LoginRejected,
                    }),
                    other => Err(Error::Protocol(other)),
                };
            }
        };

        // Post-login: probe CAPABILITY for MOVE (RFC 6851) and
        // UIDPLUS (RFC 4315).
        let (has_move, has_uidplus) = match session.capabilities().await {
            Ok(caps) => (caps.has_str("MOVE"), caps.has_str("UIDPLUS")),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "post-login CAPABILITY probe failed; \
                     assuming no MOVE/UIDPLUS support",
                );
                (false, false)
            }
        };
        self.inner.has_move.store(has_move, Ordering::Relaxed);
        self.inner.has_uidplus.store(has_uidplus, Ordering::Relaxed);

        Ok(session)
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
    /// ## Error message sanitization
    ///
    /// The `Error::Audit { message }` uses the short error code
    /// (`audit_err.code()`) rather than the full `Display`, because
    /// `AuditError::Write` / `Fsync` / `Rotate` include the audit file
    /// path, which is operator-configured filesystem layout and should
    /// not propagate into MCP tool responses or client-visible error
    /// chains. The full error is still preserved in the `source` field
    /// for observability and log inspection.
    async fn emit_auth(&self, record: Auth) -> Result<(), Error> {
        let audit = self.inner.audit.clone();
        let join_result = tokio::task::spawn_blocking(move || audit.log_auth(record)).await;
        match join_result {
            Err(join_err) => Err(Error::Audit {
                op: "emit_auth",
                message: "tokio join error during audit write".to_string(),
                source: Box::new(join_err),
            }),
            Ok(Err(audit_err)) => {
                tracing::error!(
                    error = %audit_err,
                    "audit log_auth failed; converting to Error::Audit",
                );
                // Sanitized message: use only the stable error code, not
                // the Display (which may include the audit file path).
                // The full error is preserved in source.
                let message = format!("emit_auth: {}", audit_err.code());
                Err(Error::Audit {
                    op: "emit_auth",
                    message,
                    source: Box::new(audit_err),
                })
            }
            Ok(Ok(_seq)) => Ok(()),
        }
    }

    /// `LIST` against `pattern` (e.g. `"*"`, `"INBOX/*"`).
    ///
    /// Drops the cached session on `ConnectionLost` so the next call
    /// lazy-reconnects without auto-retrying the failed command.
    ///
    /// # Errors
    /// Propagates any `Error` produced by `time::with_timeout` or the
    /// underlying `ops::folders::list` call.
    pub async fn list_folders(&self, pattern: &str) -> Result<Vec<crate::types::Folder>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("list", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::list(session, pattern).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `STATUS` for `folder` selecting the requested items.
    ///
    /// # Errors
    /// Propagates any `Error` produced by `time::with_timeout` or the
    /// underlying `ops::folders::status` call.
    pub async fn status(
        &self,
        folder: &str,
        items: crate::types::StatusItems,
    ) -> Result<crate::types::FolderStatus, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("status", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::status(session, folder, items).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `SELECT` (or `EXAMINE` if `read_only`) the named folder.
    ///
    /// # Errors
    /// Propagates any `Error` produced by `time::with_timeout` or the
    /// underlying `ops::folders::select` call.
    pub async fn select(
        &self,
        folder: &str,
        read_only: bool,
    ) -> Result<crate::types::SelectedFolder, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("select", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::select(session, folder, read_only).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
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
    ) -> Result<Vec<crate::types::Uid>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("search", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::search::search(session, folder, query).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `FETCH` for the given UIDs with the requested items. Does NOT include
    /// `BODY[]` — see `fetch_body` (Task 13) for full message retrieval.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors from the
    /// underlying `ops::fetch::fetch` call.
    pub async fn fetch(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        spec: crate::types::FetchSpec,
    ) -> Result<Vec<crate::types::FetchedMessage>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("fetch", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::fetch::fetch(session, folder, uids, spec).await
        })
        .await;
        if let Err(Error::ConnectionLost) = &result {
            self.invalidate().await;
        }
        result
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
    /// `Error::SizeLimit` if the server-reported size exceeds
    /// `max_fetch_body_bytes`. This prevents async-imap from buffering
    /// the full body into memory for oversize messages, at the cost of
    /// one extra IMAP round-trip.
    ///
    /// The post-parse `project_size` check inside `ops::fetch::fetch_body`
    /// remains as defense-in-depth because servers can lie about
    /// `RFC822.SIZE`.
    ///
    /// # Errors
    /// Propagates `Error::SizeLimit` if the body exceeds the configured
    /// `max_fetch_body_bytes`, plus the usual timeout / protocol /
    /// connection-lost errors.
    pub async fn fetch_body(&self, folder: &str, uid: crate::types::Uid) -> Result<Vec<u8>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_fetch_body_bytes;
        let result = crate::time::with_timeout("fetch_body", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            let server_size = crate::ops::fetch::preflight_fetch_size(session, folder, uid).await?;
            crate::ops::fetch::preflight_size_check(server_size, limit)?;
            crate::ops::fetch::fetch_body(session, folder, uid, limit).await
        })
        .await;
        // Drop the cached session on EITHER ConnectionLost OR SizeLimit.
        // SizeLimit means we aborted mid-stream, so the IMAP response
        // state is half-consumed and the session cannot be reused.
        // The match here lists every Error variant explicitly because
        // workspace lints ban `_ =>` wildcards.
        let should_invalidate = match &result {
            Err(Error::ConnectionLost | Error::SizeLimit { .. }) => true,
            Err(
                Error::Tls { .. }
                | Error::TlsHandshake(_)
                | Error::Connect(_)
                | Error::Timeout { .. }
                | Error::Auth { .. }
                | Error::Protocol(_)
                | Error::InvalidInput { .. }
                | Error::BatchTooLarge { .. }
                | Error::Audit { .. },
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
    /// # Errors
    /// Returns `Error::BatchTooLarge` if more than 100 UIDs are passed.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn store_flags(
        &self,
        folder: &str,
        uids: &[crate::types::Uid],
        flags: &[crate::types::Flag],
        action: crate::types::FlagAction,
    ) -> Result<Vec<crate::types::Uid>, Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("store", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::select(session, folder, false).await?;
            crate::ops::store::store(session, uids, flags, action).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Move messages from `source_folder` to `dest_folder`.
    ///
    /// Uses IMAP MOVE extension (RFC 6851) when the server advertised
    /// it; falls back to COPY + STORE \Deleted + EXPUNGE otherwise.
    /// The fallback is not atomic — callers should inspect
    /// `MoveOutcome::used_fallback` and surface a warning.
    ///
    /// Batch limit: 100 UIDs.
    ///
    /// # Errors
    /// Returns `Error::BatchTooLarge` if more than 100 UIDs are passed.
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn move_messages(
        &self,
        source_folder: &str,
        dest_folder: &str,
        uids: &[crate::types::Uid],
    ) -> Result<crate::ops::move_msg::MoveOutcome, Error> {
        let dur = self.inner.cfg.command_timeout;
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        let result = crate::time::with_timeout("move", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folders::select(session, source_folder, false).await?;
            crate::ops::move_msg::move_messages(session, dest_folder, uids, has_move, has_uidplus)
                .await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// `APPEND` a raw RFC 5322 message to `folder` with the given
    /// flags and keywords.
    ///
    /// Does NOT select the folder first -- APPEND targets a named
    /// mailbox directly per RFC 3501 section 6.3.11.
    ///
    /// # Errors
    /// Propagates timeout, connection-lost, or protocol errors.
    pub async fn append_message(
        &self,
        folder: &str,
        message: &[u8],
        flags: &[crate::types::Flag],
        keywords: &[&str],
    ) -> Result<crate::types::AppendResult, Error> {
        let dur = self.inner.cfg.command_timeout;
        let limit = self.inner.cfg.max_append_bytes;
        let result = crate::time::with_timeout("append", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::append::append(session, folder, message, flags, keywords, limit).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Delete a message by flagging it as `\Deleted` and moving it to Trash.
    ///
    /// If the message is already in the Trash folder, only the flag is applied.
    ///
    /// # Errors
    ///
    /// Returns `Error::ConnectionLost` or `Error::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_message(
        &self,
        folder: &str,
        uid: crate::types::Uid,
        trash_folder: &str,
    ) -> Result<crate::ops::delete::DeleteResult, Error> {
        let dur = self.inner.cfg.command_timeout;
        let has_move = self.has_move_capability();
        let has_uidplus = self.has_uidplus_capability();
        let result = crate::time::with_timeout("delete_message", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
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
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Expunge all `\Deleted` messages from `folder`.
    ///
    /// Returns `(deleted_uids, expunged_count)` — the UIDs found by
    /// `UID SEARCH DELETED` before the expunge, and the count from the
    /// EXPUNGE response.
    ///
    /// # Errors
    ///
    /// Returns `Error::ConnectionLost` or `Error::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn expunge(&self, folder: &str) -> Result<(Vec<crate::types::Uid>, u32), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("expunge", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            let deleted_uids = crate::ops::expunge::count_deleted(session, folder).await?;
            crate::ops::folders::select(session, folder, false).await?;
            let count = crate::ops::expunge::expunge(session).await?;
            Ok((deleted_uids, count))
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Create a new IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidInput` for invalid names, `Error::ConnectionLost`
    /// or `Error::Timeout` on transport failure, or a protocol error if the
    /// server rejects the command.
    pub async fn create_folder(&self, name: &str) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("create_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::create_folder(session, name).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Rename an IMAP folder.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidInput` for an invalid `new_name`,
    /// `Error::ConnectionLost` or `Error::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn rename_folder(&self, old_name: &str, new_name: &str) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("rename_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::rename_folder(session, old_name, new_name).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
    }

    /// Delete an IMAP folder and all its contents.
    ///
    /// # Errors
    ///
    /// Returns `Error::ConnectionLost` or `Error::Timeout` on transport failure,
    /// or a protocol error if the server rejects the command.
    pub async fn delete_folder(&self, name: &str) -> Result<(), Error> {
        let dur = self.inner.cfg.command_timeout;
        let result = crate::time::with_timeout("delete_folder", dur, async {
            let mut guard = self.session().await?;
            let session = guard
                .as_mut()
                .unwrap_or_else(|| unreachable!("session() ensures Some"));
            crate::ops::folder_mgmt::delete_folder(session, name).await
        })
        .await;
        if let Err(Error::ConnectionLost | Error::Timeout { .. }) = &result {
            self.invalidate().await;
        }
        result
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

/// Map an `io::Error` from the TLS connect call to `Error::TlsHandshake`.
/// `connect_inner` will enrich this into `Error::Tls { observed, expected }`
/// when the `TlsConfigBundle`'s `last_observed` slot shows a mismatch.
fn map_tls_handshake_error(err: &std::io::Error) -> Error {
    Error::TlsHandshake(tokio_rustls::rustls::Error::General(err.to_string()))
}

/// Map a connect/login error to its stable short error code for the audit log.
fn error_code_for(err: &Error) -> &'static str {
    match err {
        Error::Tls { .. } | Error::TlsHandshake(_) => "ERR_TLS",
        Error::Connect(_) | Error::ConnectionLost => "ERR_NETWORK",
        Error::Timeout { .. } => "ERR_TIMEOUT",
        Error::Auth { .. } => "ERR_AUTH",
        Error::SizeLimit { .. } => "ERR_ATTACHMENT_TOO_LARGE",
        Error::Protocol(_) => "ERR_IMAP_PROTOCOL",
        Error::InvalidInput { .. } | Error::BatchTooLarge { .. } => "ERR_INVALID_INPUT",
        Error::Audit { .. } => "ERR_AUDIT",
    }
}
