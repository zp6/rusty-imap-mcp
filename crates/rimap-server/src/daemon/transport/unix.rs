//! Unix-domain-socket transport for the daemon.
//!
//! Owns the filesystem path and unlinks on drop / shutdown. Uses
//! `peer_cred()` to populate `PeerIdentity::Unix`. Stale-socket recovery:
//! if the file at `path` exists but cannot be connected to, it is
//! assumed to be left over from a crashed prior daemon and is unlinked
//! before binding.

#![cfg(unix)]

use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use rimap_audit::record::PeerIdentity;
use tokio::net::{UnixListener, UnixStream};

use super::{AcceptedConnection, PlatformListener};

/// A Unix-socket listener. Owns the socket path so `Drop` can unlink.
///
/// `path` is stored in an `Option` so it can be taken out by either
/// `shutdown` or `Drop`, preventing a double-unlink.
#[derive(Debug)]
pub struct UnixSocketListener {
    inner: UnixListener,
    path: Option<PathBuf>,
}

/// RAII guard: sets the process umask to `mask` and restores the prior
/// value on drop.
///
/// Umask is *process-global*, so this briefly affects any concurrent
/// thread that creates a filesystem object during its lifetime. The
/// daemon's `bind` is a one-shot startup event on the main task, so the
/// exposure window is negligible; callers should still keep the guard
/// scoped as tightly as possible.
///
/// NOTE: `umask(2)` is process-global. On modern glibc (>= 2.32) it is
/// per-thread, but we do not rely on that: the daemon's `bind` runs on
/// the main task before any worker tasks are spawned, so no concurrent
/// `open(2)` / `mkdir(2)` in another thread can race the umask window.
struct UmaskGuard {
    prior: rustix::fs::Mode,
}

impl UmaskGuard {
    fn new(mask: u32) -> Self {
        let prior = rustix::process::umask(rustix::fs::Mode::from_bits_truncate(mask));
        Self { prior }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.prior);
    }
}

fn symlink_metadata_if_exists(path: &Path) -> io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl UnixSocketListener {
    /// Bind a new listener at `path`. The parent directory is expected
    /// to already exist with mode 0700 (caller's responsibility — see
    /// `daemon::socket_setup::prepare_socket_dir`).
    ///
    /// If `path` already exists and `connect()` succeeds against it,
    /// this call fails with `io::ErrorKind::AddrInUse` and does NOT
    /// unlink. If `path` exists but is a symlink, this call fails with
    /// `io::ErrorKind::PermissionDenied` — we never follow symlinks at
    /// the socket path to avoid a TOCTOU between socket-dir preparation
    /// and bind. If `path` exists but `connect()` fails and it is a
    /// regular file, the stale file is unlinked and `bind()` proceeds.
    ///
    /// Narrows the process umask to `0o077` across the bind syscall so
    /// the kernel creates the socket inode with mode `0o700` directly,
    /// closing the window in which a same-UID attacker could `connect()`
    /// between `bind` and the post-bind `chmod`. The post-bind
    /// `set_permissions(0o600)` remains as defense-in-depth.
    ///
    /// # Errors
    /// Returns an `io::Error` for bind failures, unexpected live
    /// listeners at the same path, symlinks at the socket path, or if
    /// `remove_file` / `set_permissions` fails during stale-socket
    /// recovery.
    pub async fn bind(path: &Path) -> io::Result<Self> {
        if let Some(metadata) = symlink_metadata_if_exists(path)? {
            if metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing to bind: {} is a symlink; remove the symlink or bind at a different path",
                        path.display()
                    ),
                ));
            }
            if UnixStream::connect(path).await.is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "socket at {} is already served by a live daemon",
                        path.display()
                    ),
                ));
            }
            // `unlink(2)` does NOT follow terminal symlinks; it unlinks the
            // link itself. Combined with the `symlink_metadata` pre-check
            // above, a same-UID attacker that races a symlink onto `path`
            // after the pre-check cannot make us delete the symlink's
            // target. Task 3's C3 regression test locks in this invariant.
            std::fs::remove_file(path)?;
            tracing::info!(path = %path.display(), "unlinked stale daemon socket");
        }

        // Narrow umask to 0077 so the kernel creates the socket inode
        // with mode 0700 (UnixListener::bind respects umask). Restored
        // on drop.
        let _umask = UmaskGuard::new(0o077);

        let inner = UnixListener::bind(path)?;

        // Defense in depth: if UmaskGuard ever regresses, narrow anyway.
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;

        // Verify post-bind mode matches our contract — fail closed on
        // surprise.
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("bound socket has mode {mode:o}, require 0600; check umask and filesystem"),
            ));
        }

        Ok(Self {
            inner,
            path: Some(path.to_owned()),
        })
    }

    /// Path this listener is bound to, or `None` after shutdown.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn unlink_socket(path: &Path) {
        if let Err(e) = std::fs::remove_file(path)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(error = %e, path = %path.display(), "failed to unlink daemon socket");
        }
    }
}

impl PlatformListener for UnixSocketListener {
    type Stream = UnixStream;

    async fn accept(&mut self) -> io::Result<AcceptedConnection<Self::Stream>> {
        let (stream, _addr) = self.inner.accept().await?;
        let cred = stream.peer_cred()?;
        let identity = PeerIdentity::Unix {
            uid: cred.uid(),
            pid: cred.pid(),
        };
        Ok(AcceptedConnection { stream, identity })
    }

    /// Unlink the socket path and release the listener.
    ///
    /// Shutdown is best-effort: errors are logged at `warn!` but not
    /// returned because the listener's lifetime is already ending. The
    /// `Drop` impl provides the same best-effort cleanup if `shutdown`
    /// is never called explicitly. `ErrorKind::NotFound` is silenced in
    /// both cases — it is expected when `shutdown` runs before `drop`.
    fn shutdown(mut self) {
        if let Some(path) = self.path.take() {
            Self::unlink_socket(&path);
        }
    }
}

impl Drop for UnixSocketListener {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            Self::unlink_socket(&path);
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bind_then_accept_round_trips_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let mut listener = UnixSocketListener::bind(&path).await.unwrap();
        let client_path = path.clone();
        let client = tokio::spawn(async move {
            let mut s = UnixStream::connect(&client_path).await.unwrap();
            s.write_all(b"hi").await.unwrap();
            let mut buf = [0u8; 4];
            let n = s.read(&mut buf).await.unwrap();
            buf[..n].to_vec()
        });
        let accepted = listener.accept().await.unwrap();
        let mut srv = accepted.stream;
        let mut buf = [0u8; 2];
        srv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        srv.write_all(b"bye").await.unwrap();
        let got = client.await.unwrap();
        assert_eq!(got, b"bye");
    }

    #[tokio::test]
    async fn peer_cred_reports_our_own_uid_for_same_process_connection() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let mut listener = UnixSocketListener::bind(&path).await.unwrap();
        let client_path = path.clone();
        let _client = tokio::spawn(async move {
            let s = UnixStream::connect(&client_path).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            drop(s);
        });
        let accepted = listener.accept().await.unwrap();
        let expected_uid = rustix::process::geteuid().as_raw();
        match accepted.identity {
            PeerIdentity::Unix { uid, pid: _ } => assert_eq!(uid, expected_uid),
            other @ PeerIdentity::Windows { .. } => {
                panic!("expected Unix identity, got {other:?}");
            }
        }
    }

    #[tokio::test]
    async fn bind_refuses_when_socket_is_live() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let _first = UnixSocketListener::bind(&path).await.unwrap();
        let second = UnixSocketListener::bind(&path).await;
        assert!(
            matches!(second, Err(ref e) if e.kind() == io::ErrorKind::AddrInUse),
            "expected AddrInUse, got {second:?}",
        );
    }

    #[tokio::test]
    async fn bind_recovers_stale_socket() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        std::fs::write(&path, "").unwrap();
        let listener = UnixSocketListener::bind(&path).await.unwrap();
        assert!(path.exists(), "post-rebind the socket file exists");
        drop(listener);
    }

    #[tokio::test]
    async fn socket_file_is_mode_0600_after_bind() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let _listener = UnixSocketListener::bind(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[tokio::test]
    async fn socket_file_is_mode_0600_even_under_permissive_umask() {
        // Force a wide-open umask before bind, then assert the mode==0600
        // invariant. This does NOT prove UmaskGuard is load-bearing, since
        // the post-bind `set_permissions(0o600)` also enforces it; the two
        // paths are indistinguishable from outside. The invariant is what
        // matters — either path (or both) satisfying it is acceptable.
        // Use rustix to avoid `unsafe` (workspace forbids `unsafe_code`).
        let prior = rustix::process::umask(rustix::fs::Mode::empty());
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.sock");
        let _listener = UnixSocketListener::bind(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        rustix::process::umask(prior);
        assert_eq!(mode, 0o600, "expected 0600 under 0000 umask, got {mode:o}");
    }
}
