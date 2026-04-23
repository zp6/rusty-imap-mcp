//! Stdio↔socket adapter. MCP clients exec the shim as a child process;
//! the shim connects to the daemon and byte-pipes stdin/stdout to the
//! socket until either side closes.

use std::process::ExitCode;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::daemon::socket_path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::path::Path;

/// Validate that `path` is a non-symlinked, same-UID, mode-0600 socket.
/// Called by the shim before `UnixStream::connect` to defend against a
/// local attacker planting a replacement socket (see review finding I7 /
/// C1 / C3 of the multi-client-daemon review).
///
/// # Errors
/// Returns `io::ErrorKind::PermissionDenied` if `path` is a symlink,
/// is not owned by the current effective UID, or has any mode other
/// than `0o600`. Propagates `io::ErrorKind::NotFound` if the path
/// does not exist.
#[cfg(unix)]
pub fn verify_socket_path(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to connect: {} is a symlink; remove the symlink or bind at a different path",
                path.display()
            ),
        ));
    }
    let our_uid = rustix::process::geteuid().as_raw();
    if meta.uid() != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "socket {} is owned by uid {}, not {}",
                path.display(),
                meta.uid(),
                our_uid,
            ),
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("socket {} has mode {mode:o}, require 0600", path.display(),),
        ));
    }
    Ok(())
}

/// Bridge stdin/stdout to `sock` until either direction closes.
///
/// Both pumps run concurrently via `tokio::join!`. The stdin→socket pump
/// calls `shutdown()` on the write half when stdin hits EOF so the daemon
/// observes a clean half-close rather than a hung peer.
async fn pipe_stdio<S>(sock: S)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use tokio::io::AsyncWriteExt as _;
    let (mut read_half, mut write_half) = tokio::io::split(sock);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let stdin_to_sock = async move {
        let _ = tokio::io::copy(&mut stdin, &mut write_half).await;
        let _ = write_half.shutdown().await;
    };
    let sock_to_stdout = async move {
        let _ = tokio::io::copy(&mut read_half, &mut stdout).await;
    };
    tokio::join!(stdin_to_sock, sock_to_stdout);
}

#[cfg(unix)]
/// Connect to the daemon socket and pipe stdin/stdout until either side closes.
#[expect(
    clippy::print_stderr,
    reason = "shim runs before the tracing subscriber is initialised; \
              stderr is the only reliable channel for user-facing error messages"
)]
pub async fn run() -> ExitCode {
    use tokio::net::UnixStream;

    let ep = socket_path::resolve();
    let Some(path) = ep.as_path_buf() else {
        eprintln!("rusty-imap-mcp shim: resolved non-filesystem endpoint on unix");
        return ExitCode::from(1);
    };

    // Let `NotFound` fall through so the `UnixStream::connect` arm below
    // emits the richer "daemon not running" message with start-up hints.
    if let Err(e) = verify_socket_path(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "rusty-imap-mcp shim: refusing to connect to {}: {e}",
            path.display()
        );
        return ExitCode::from(1);
    }

    let sock = match UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "rusty-imap-mcp shim: cannot connect to daemon at {}\n\n\
                 The rusty-imap-mcp daemon is not running. Start it with:\n\n\
                 \x20\x20\x20 systemctl --user enable --now rusty-imap-mcp.service\n\n\
                 Or, if not using systemd:\n\n\
                 \x20\x20\x20 rusty-imap-mcp daemon\n\n\
                 Underlying error: {e}\n",
                path.display(),
            );
            return ExitCode::from(1);
        }
    };
    pipe_stdio(sock).await;
    ExitCode::SUCCESS
}

#[cfg(windows)]
/// Connect to the daemon named pipe and pipe stdin/stdout until either side closes.
#[expect(
    clippy::print_stderr,
    reason = "shim runs before the tracing subscriber is initialised; \
              stderr is the only reliable channel for user-facing error messages"
)]
pub async fn run() -> ExitCode {
    use tokio::net::windows::named_pipe::ClientOptions;

    let ep = match socket_path::resolve() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("rusty-imap-mcp shim: could not resolve pipe name: {e}");
            return ExitCode::from(1);
        }
    };
    let name = ep.as_str();
    // Retry for ERROR_PIPE_BUSY (all server instances busy).
    let mut attempts = 0u32;
    let sock = loop {
        match ClientOptions::new().open(name) {
            Ok(p) => break p,
            Err(e) => {
                attempts += 1;
                if attempts >= 3 {
                    eprintln!(
                        "rusty-imap-mcp shim: cannot connect to daemon pipe {name}\n\n\
                         The rusty-imap-mcp daemon is not running, or all pipe instances are busy.\n\
                         Start the daemon (Scheduled Task 'rusty-imap-mcp') or retry shortly.\n\n\
                         Underlying error: {e}\n",
                    );
                    return ExitCode::from(1);
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    };
    pipe_stdio(sock).await;
    ExitCode::SUCCESS
}
