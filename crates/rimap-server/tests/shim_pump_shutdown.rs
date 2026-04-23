//! Integration test for the shim stdio pump: verifies the pump exits
//! promptly when the server closes the socket (RUST-ASYNC-02) instead of
//! waiting for stdin to also close.

#![cfg(unix)]
#![expect(clippy::unwrap_used, reason = "tests")]

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{UnixListener, UnixStream};

/// When the server closes the socket (EOF), the shim pump must return
/// promptly — not wait for stdin to also close. Exercises the
/// sock→stdout completing while stdin→sock is still pinned on stdin.
#[tokio::test]
async fn pipe_stdio_returns_when_server_closes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("d.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let server_task = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"hello").await.unwrap();
        // Close immediately.
        drop(s);
    });
    let client = UnixStream::connect(&path).await.unwrap();
    // pipe_stdio must return within 1 second after the server drops.
    let elapsed = tokio::time::timeout(
        Duration::from_secs(1),
        rimap_server::shim::pipe_stdio_for_test(client),
    )
    .await;
    assert!(
        elapsed.is_ok(),
        "pipe_stdio did not return after server EOF (test timed out)",
    );
    server_task.await.unwrap();
}
