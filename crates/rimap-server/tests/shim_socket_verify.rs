//! Integration test: the shim refuses to connect to sockets that are
//! symlinks, are not owned by the current UID, or have a mode other
//! than `0o600`. Guards against review finding I7 / C1 / C3.
#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;
use tokio::net::UnixListener;

/// The shim must refuse to connect when the socket path is a symlink.
#[tokio::test]
async fn shim_refuses_symlinked_socket() {
    let dir = TempDir::new().unwrap();
    let real = dir.path().join("real.sock");
    let _listener = UnixListener::bind(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link.sock");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let err = rimap_server::shim::verify_socket_path(&link).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("symlink"));
}

/// The shim must refuse to connect when the socket mode is not 0600.
#[tokio::test]
async fn shim_refuses_mode_other_than_0600() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("d.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let err = rimap_server::shim::verify_socket_path(&path).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("mode"));
}

/// Happy path: a genuine 0600 daemon-owned socket passes verification.
#[tokio::test]
async fn shim_accepts_same_uid_0600_socket() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("d.sock");
    let _listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    rimap_server::shim::verify_socket_path(&path).unwrap();
}
