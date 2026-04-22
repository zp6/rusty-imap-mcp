//! In-process test harness for the daemon. Spawns the daemon's accept
//! loop as a background tokio task against a tempdir-backed audit file
//! and socket directory; returns a handle for clients to connect through.

#![cfg(unix)]
// Windows parity follows in Task 29.
// Some items in this shared harness module are only used by specific test
// binaries, not all of them. Allow dead_code at module level to avoid false
// positives when a test binary uses only a subset of the harness API.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use rimap_audit::{AuditOptions, AuditWriter, Seq};
use rimap_config::credential::{CredentialStore, KeyringStore};
use rimap_config::loader::load_and_validate;
use rimap_server::boot::registry;
use rimap_server::daemon::run::run;
use rimap_server::daemon::state::DaemonState;
use rimap_server::daemon::transport::unix::UnixSocketListener;
use tempfile::TempDir;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

/// Spawned daemon, ready for client connections.
pub struct TestDaemon {
    /// Path of the Unix socket the daemon is listening on.
    pub socket_path: PathBuf,
    /// Path of the JSONL audit log written by this daemon.
    pub audit_path: PathBuf,
    /// Tempdir backing the daemon's config, audit file, and socket.
    /// Held here for lifetime; tests may create additional files inside it.
    pub tempdir: TempDir,
    /// Trigger to request graceful shutdown.
    pub shutdown: Arc<Notify>,
    /// Background task running the daemon accept loop.
    pub handle: JoinHandle<anyhow::Result<()>>,
}

impl TestDaemon {
    /// Spawn a daemon with the supplied config TOML.
    ///
    /// The string `{tempdir}` inside `config_toml` is replaced with the
    /// actual tempdir path before writing, so callers can use it as a
    /// placeholder for `audit.path` and `audit.allowed_base_dir` without
    /// knowing the path ahead of time.  See [`default_config_toml`] for a
    /// ready-made template.
    ///
    /// The daemon is fully booted (config loaded, registry built, socket
    /// bound) before this function returns.
    ///
    /// # Panics
    ///
    /// Panics if any boot step fails — intentional in a test harness; the
    /// panic message includes the underlying error.
    #[expect(clippy::expect_used, reason = "test harness — panics on setup failure")]
    pub async fn spawn(config_toml: &str) -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let tempdir_str = tempdir.path().to_string_lossy();
        let resolved_toml = config_toml.replace("{tempdir}", &tempdir_str);

        let config_path = tempdir.path().join("config.toml");
        std::fs::write(&config_path, &resolved_toml).expect("write config");

        let audit_path = tempdir.path().join("audit.jsonl");
        let socket_path = tempdir.path().join("daemon.sock");

        let multi = load_and_validate(&config_path).expect("load config");

        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .expect("open audit");

        let credentials: Arc<dyn CredentialStore> = Arc::new(KeyringStore);
        let download_dir: Arc<std::path::Path> =
            Arc::from(tempdir.path().to_owned().into_boxed_path());

        let reg = registry::build(&multi, &audit, &credentials, &download_dir)
            .await
            .expect("build registry");

        let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();

        let state = Arc::new(DaemonState {
            registry: Arc::new(reg),
            audit,
            download_dir,
            cancellation_tx,
            started_at: std::time::Instant::now(),
        });

        let listener = UnixSocketListener::bind(&socket_path)
            .await
            .expect("bind test socket");

        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move { run(state, listener, shutdown_clone).await });

        Self {
            socket_path,
            audit_path,
            tempdir,
            shutdown,
            handle,
        }
    }

    /// Signal graceful shutdown and wait for the daemon task to complete.
    pub async fn shutdown(self) {
        // notify_one stores a permit even if the daemon task hasn't yet reached
        // the select! — safe for both spawn (slow boot) and spawn_bare (fast boot).
        self.shutdown.notify_one();
        let _ = self.handle.await;
    }
}

/// Build a minimal `DaemonState` suitable for integration tests that do not
/// need a real `AccountRegistry`. Registry is empty; audit writer is real
/// (backed by `audit_path`); download dir is `tempdir`.
///
/// # Panics
///
/// Panics if the audit file cannot be opened — intentional in a test helper.
#[expect(clippy::expect_used, reason = "test helper — panics on setup failure")]
pub fn test_daemon_state(
    tempdir: &std::path::Path,
    audit_path: &std::path::Path,
) -> Arc<DaemonState> {
    use rimap_server::boot::registry::AccountRegistry;

    let audit = AuditWriter::open(&AuditOptions {
        path: audit_path.to_owned(),
        rotate_bytes: 0,
        rotate_keep: 0,
        retention_seconds: None,
        fail_open: false,
        initial_seq: rimap_audit::Seq::FIRST,
    })
    .expect("open audit");

    let registry = Arc::new(AccountRegistry::new(std::collections::BTreeMap::new()));
    let download_dir: Arc<std::path::Path> = Arc::from(tempdir.to_owned().into_boxed_path());
    let (cancellation_tx, _cancellation_rx) = rimap_audit::cancellation_channel();

    Arc::new(DaemonState {
        registry,
        audit,
        download_dir,
        cancellation_tx,
        started_at: std::time::Instant::now(),
    })
}

impl TestDaemon {
    /// Spawn a daemon with a caller-supplied `DaemonState`. Bypasses
    /// `boot::registry::build` and its live-IMAP dependency. Suitable for
    /// tests that exercise session/transport/audit/shutdown semantics
    /// without needing a real IMAP server.
    ///
    /// # Panics
    ///
    /// Panics if the socket cannot be bound — intentional in a test harness.
    #[expect(clippy::expect_used, reason = "test harness — panics on setup failure")]
    pub async fn spawn_bare(
        tempdir: TempDir,
        audit_path: PathBuf,
        socket_path: PathBuf,
        state: Arc<DaemonState>,
    ) -> Self {
        let listener = UnixSocketListener::bind(&socket_path)
            .await
            .expect("bind test socket");
        let shutdown = Arc::new(Notify::new());
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = tokio::spawn(async move { run(state, listener, shutdown_clone).await });
        Self {
            socket_path,
            audit_path,
            tempdir,
            shutdown,
            handle,
        }
    }
}

/// Default config TOML for tests that don't need a real IMAP account.
///
/// Contains `{tempdir}` placeholders that [`TestDaemon::spawn`] replaces
/// with the actual tempdir path.  The IMAP host/port point to localhost
/// at port 1143 — tests that need a real server should substitute their
/// own config instead.
pub fn default_config_toml() -> String {
    r#"
[imap]
host = "127.0.0.1"
port = 1143
encryption = "tls"
username = "test@example.com"

[audit]
path = "{tempdir}/audit.jsonl"
allowed_base_dir = "{tempdir}"
"#
    .to_string()
}
