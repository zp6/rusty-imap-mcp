//! Daemon harness backed by the live Dovecot Docker fixture.
//!
//! Wraps `rimap_imap::test_support::container::DovecotHarness` to bring
//! up a real IMAP server, then runs `boot::registry::build` and
//! `daemon::run` against it. Skips silently unless
//! `RIMAP_REQUIRE_LIVE_IMAP=1`. Use this for daemon-level scenarios
//! that need a real per-session pipeline through to IMAP; for tests
//! that don't need IMAP, prefer `TestDaemon::spawn_bare`.

#![cfg(unix)]
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rimap_audit::{AuditOptions, AuditWriter};
use rimap_config::credential::CredentialStore;
use rimap_config::model::{
    AttachmentsConfig, AuditConfig, Config, ImapConfig, ImapEncryption, LimitsConfig,
    SecurityConfig,
};
use rimap_config::validate::{ValidatedMultiConfig, validate_legacy_as_multi};
use rimap_imap::test_support::container::DovecotHarness;
use rimap_server::boot::registry;
use rimap_server::daemon::run::run;
use rimap_server::daemon::state::DaemonState;
use rimap_server::daemon::transport::unix::UnixSocketListener;
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// True when `RIMAP_REQUIRE_LIVE_IMAP=1` is set. When false, callers
/// should `return` early from each test so the suite skips silently
/// without a container runtime installed.
pub fn live_imap_required() -> bool {
    matches!(std::env::var("RIMAP_REQUIRE_LIVE_IMAP").as_deref(), Ok("1"))
}

/// A daemon spawned against a fresh Dovecot container.
pub struct DovecotDaemon {
    /// Caller-relevant — scenarios connect through this path.
    pub socket_path: PathBuf,
    audit_path: PathBuf,
    /// Held only for lifetime; tests don't need to reach in.
    _tempdir: TempDir,
    shutdown: Arc<Notify>,
    handle: JoinHandle<anyhow::Result<()>>,
    /// Held so the container's `Drop` (compose down) fires when this
    /// struct drops, AFTER the daemon has shut down. Field declaration
    /// order matters: this is last so all sibling fields drop first.
    _dovecot: DovecotHarness,
}

impl DovecotDaemon {
    /// Start a Dovecot container, build a real `AccountRegistry` against
    /// it, and spawn the daemon. Returns `None` when the container
    /// runtime is unavailable AND `RIMAP_REQUIRE_LIVE_IMAP` is unset —
    /// the test should `return` in that case so the suite skips silently.
    ///
    /// # Panics
    /// Panics on any setup failure when `RIMAP_REQUIRE_LIVE_IMAP=1`.
    pub async fn try_spawn(max_concurrent_sessions: usize) -> Option<Self> {
        Self::try_spawn_inner(max_concurrent_sessions, None).await
    }

    /// Like [`try_spawn`], but binds the daemon socket at the
    /// caller-supplied path instead of allocating one inside the
    /// tempdir. Used by the shim-reconnect scenario, which spawns two
    /// daemons in sequence at the same path.
    pub async fn try_spawn_at(
        max_concurrent_sessions: usize,
        socket_path: PathBuf,
    ) -> Option<Self> {
        Self::try_spawn_inner(max_concurrent_sessions, Some(socket_path)).await
    }

    async fn try_spawn_inner(
        max_concurrent_sessions: usize,
        socket_path_override: Option<PathBuf>,
    ) -> Option<Self> {
        let dovecot = match DovecotHarness::try_start() {
            Ok(h) => h,
            Err(e) => {
                assert!(
                    !live_imap_required(),
                    "RIMAP_REQUIRE_LIVE_IMAP=1 but Dovecot harness unavailable: {e}"
                );
                return None;
            }
        };

        let tempdir = TempDir::new().expect("tempdir");
        // `AuditWriter::open` rejects parent dirs with mode != 0700;
        // `TempDir::new` inherits the system umask, so chmod explicitly.
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");

        let audit_path = tempdir.path().join("audit.jsonl");
        let socket_path =
            socket_path_override.unwrap_or_else(|| tempdir.path().join("daemon.sock"));
        let download_dir: Arc<std::path::Path> =
            Arc::from(tempdir.path().to_path_buf().into_boxed_path());

        let multi = build_multi_config_for_dovecot(&dovecot, &audit_path);

        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: rimap_audit::Seq::FIRST,
        })
        .expect("open audit");

        let credentials: Arc<dyn CredentialStore> = Arc::new(DovecotStaticCreds);

        let registry = registry::build(&multi, &audit, &credentials, &download_dir)
            .await
            .expect("registry::build");

        let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();
        let session_permits = Arc::new(tokio::sync::Semaphore::new(max_concurrent_sessions));
        let state = Arc::new(DaemonState::new(
            Arc::new(registry),
            audit,
            download_dir,
            cancellation_tx,
            session_permits,
        ));

        let listener = UnixSocketListener::bind(&socket_path)
            .await
            .expect("bind socket");
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move { run(state, listener, shutdown_clone).await });

        Some(Self {
            socket_path,
            audit_path,
            _tempdir: tempdir,
            shutdown,
            handle,
            _dovecot: dovecot,
        })
    }

    /// Trigger graceful shutdown, await `run()`, and return the audit
    /// log contents plus the daemon's drain duration. The drain duration
    /// is measured before the held [`DovecotHarness`] drops, so it
    /// excludes the container's `compose down` (which runs SIGTERM with
    /// a 10-second grace and dominates wall-clock time).
    pub async fn shutdown(self) -> ShutdownResult {
        let started = Instant::now();
        self.shutdown.notify_one();
        let _ = self.handle.await;
        let drain_duration = started.elapsed();
        let log = std::fs::read_to_string(&self.audit_path).unwrap_or_default();
        ShutdownResult {
            drain_duration,
            log,
        }
        // `self` drops here: `_dovecot.drop()` runs `compose down`. The
        // timing is already captured above, so the test sees only the
        // daemon-side drain latency.
    }
}

/// Result of [`DovecotDaemon::shutdown`]: the audit-log contents plus the
/// time the daemon took to drain its sessions (excludes container
/// teardown).
pub struct ShutdownResult {
    pub drain_duration: Duration,
    pub log: String,
}

/// Build a `ValidatedMultiConfig` for the Dovecot container by going
/// through the legacy single-account validate path. The audit path's
/// containment is opted out (`allowed_base_dir = "/"`) so the tempdir
/// passes validation.
fn build_multi_config_for_dovecot(
    dovecot: &DovecotHarness,
    audit_path: &std::path::Path,
) -> ValidatedMultiConfig {
    let raw_config = Config {
        imap: ImapConfig {
            host: DovecotHarness::host().to_string(),
            port: dovecot.port(),
            username: DovecotHarness::username().to_string(),
            encryption: ImapEncryption::Tls,
            tls_fingerprint_sha256: Some(dovecot.pinned_fingerprint().to_hex()),
            command_timeout_seconds: 30,
            connect_timeout_seconds: 10,
        },
        smtp: None,
        security: SecurityConfig::default(),
        limits: LimitsConfig::default(),
        audit: AuditConfig {
            path: audit_path.to_path_buf(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            provenance_window_seconds: 60,
            fail_open: false,
            allowed_base_dir: Some(PathBuf::from("/")),
        },
        attachments: AttachmentsConfig::default(),
    };
    validate_legacy_as_multi(raw_config).expect("validate legacy config")
}

/// Minimal `CredentialStore` that returns the Dovecot fixture's
/// hard-coded password for any `(account, host, username)` lookup.
/// `set_password` panics — tests do not write credentials.
struct DovecotStaticCreds;

impl CredentialStore for DovecotStaticCreds {
    fn get_password(
        &self,
        _account: &str,
    ) -> Result<Option<SecretString>, rimap_config::ConfigError> {
        Ok(Some(SecretString::from(
            DovecotHarness::password().to_string(),
        )))
    }

    #[expect(clippy::panic, clippy::panic_in_result_fn, reason = "test stub")]
    fn set_password(
        &self,
        _account: &str,
        _password: &str,
    ) -> Result<(), rimap_config::ConfigError> {
        panic!("tests do not write credentials")
    }
}
