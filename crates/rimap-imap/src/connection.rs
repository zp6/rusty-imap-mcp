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

    /// Drop any current session. Called by ops on connection-lost errors.
    pub(crate) async fn invalidate(&self) {
        let mut guard = self.inner.session.lock().await;
        *guard = None;
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
                self.emit_auth(auth_failure(&ctx, error_code_for(err)))
                    .await?;
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
        match client.login(&cfg.username, &password).await {
            Ok(session) => Ok(session),
            Err((err, _client)) => match err {
                async_imap::error::Error::No(_) => Err(Error::Auth {
                    reason: AuthFailure::LoginRejected,
                }),
                other => Err(Error::Protocol(other)),
            },
        }
    }

    /// Emit an `Auth` audit record. Runs `AuditWriter::log_auth` inside
    /// `spawn_blocking` so the `std::sync::Mutex` inside `AuditWriter` is
    /// never held across an `.await` boundary.
    async fn emit_auth(&self, record: Auth) -> Result<(), Error> {
        let audit = self.inner.audit.clone();
        tokio::task::spawn_blocking(move || audit.log_auth(record))
            .await
            .map_err(|join_err| {
                Error::Connect(std::io::Error::other(format!(
                    "audit join error: {join_err}"
                )))
            })?
            .map_err(|audit_err| {
                Error::Connect(std::io::Error::other(format!(
                    "audit write error: {audit_err}"
                )))
            })?;
        Ok(())
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
    /// # Size cap is enforced post-parse, not pre-allocation
    ///
    /// `async-imap 0.11` yields each FETCH item as an already-materialized
    /// `Fetch` whose `body()` slice has been parsed into memory by the
    /// upstream crate before this function gets a chance to inspect its
    /// length. That means a hostile (or misconfigured) server can force a
    /// single-item allocation up to the literal size it announces in the
    /// FETCH response, **independent of `max_fetch_body_bytes`**. Our cap
    /// is checked immediately after the item lands — so the session is
    /// torn down and `Error::SizeLimit` is returned before any bytes reach
    /// the caller — but the intermediate allocation inside async-imap has
    /// already happened.
    ///
    /// Callers exposed to untrusted servers should pair this with an
    /// external wall-clock memory limit (cgroups, `RLIMIT_AS`) until
    /// <https://github.com/randomparity/rusty-imap-mcp/issues/32> lands
    /// a pre-allocation path.
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
                | Error::InvalidInput { .. },
            )
            | Ok(_) => false,
        };
        if should_invalidate {
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
        Error::InvalidInput { .. } => "ERR_INVALID_INPUT",
    }
}
