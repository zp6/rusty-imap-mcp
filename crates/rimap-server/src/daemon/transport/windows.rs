//! Windows named-pipe transport for the daemon.
//!
//! Bind + accept are implemented via tokio's named-pipe API. The pipe's
//! DACL (from tokio's `ServerOptions` default) restricts connections to
//! the creating user, so scope A (same-user access) is enforced at the
//! OS level. Peer identity capture is reported as unknown until proper
//! `GetNamedPipeClientProcessId` + token-lookup support lands, which
//! requires `unsafe` FFI that the workspace currently forbids.

#![cfg(windows)]

use std::io;

use rimap_audit::record::PeerIdentity;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use super::{AcceptedConnection, PlatformListener};

/// A Windows named-pipe listener. Creates fresh pipe instances per
/// accepted client (one-instance-per-client idiom).
pub struct NamedPipeListener {
    pipe_name: String,
    /// The currently-pending (not-yet-connected) server instance.
    /// Taken by `accept()` and then replenished for the next call.
    pending: Option<NamedPipeServer>,
}

impl NamedPipeListener {
    /// Create a new listener against `pipe_name` (in the
    /// `\\.\pipe\...` namespace).
    ///
    /// The first instance is created eagerly so `accept()` can
    /// immediately await an incoming client.
    ///
    /// # Errors
    /// Returns an I/O error if pipe creation fails (most commonly
    /// `ERROR_ACCESS_DENIED` if the name is already in use by a
    /// live daemon, or `ERROR_INVALID_NAME` if the name is malformed).
    pub fn bind(pipe_name: &str) -> io::Result<Self> {
        let pending = Some(create_server_instance(pipe_name, true)?);
        Ok(Self {
            pipe_name: pipe_name.to_owned(),
            pending,
        })
    }
}

fn create_server_instance(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    if first {
        // Fails with ERROR_ACCESS_DENIED if a live daemon already owns the name.
        opts.first_pipe_instance(true);
    }
    // tokio constructs the pipe with a default SECURITY_ATTRIBUTES that
    // grants access only to the creating user — matching Windows NP defaults.
    // Scope B (multi-UID) will require a custom DACL here; tracked as a
    // follow-up alongside proper peer-identity capture.
    opts.create(name)
}

impl PlatformListener for NamedPipeListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> io::Result<AcceptedConnection<Self::Stream>> {
        let server = self.pending.take().ok_or_else(|| {
            io::Error::other(
                "accept() called after prior accept failure left the listener unreplenished",
            )
        })?;
        server.connect().await?;
        // SID + PID capture is a follow-up; the pipe DACL already restricts
        // connections to the creating user, so scope A is enforced at the OS
        // level even without reading the identity here.
        let identity = PeerIdentity::Windows {
            sid: None,
            pid: None,
        };
        // Eagerly create the next instance so the next accept() does not
        // race an incoming client through ERROR_PIPE_BUSY.
        self.pending = Some(create_server_instance(&self.pipe_name, false)?);
        Ok(AcceptedConnection {
            stream: server,
            identity,
        })
    }

    fn shutdown(self) {
        drop(self.pending);
        // Named pipes have no filesystem entry to unlink.
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;

    fn unique_pipe_name() -> String {
        format!(r"\\.\pipe\rusty-imap-mcp-test-{}", unique_suffix())
    }

    fn unique_suffix() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{nanos:x}-{}", std::process::id())
    }

    #[tokio::test]
    async fn bind_then_accept_round_trips_bytes() {
        let name = unique_pipe_name();
        let mut listener = NamedPipeListener::bind(&name).expect("bind");
        let name_client = name.clone();
        let client = tokio::spawn(async move {
            let mut last_err = None;
            for _ in 0..5u8 {
                match ClientOptions::new().open(&name_client) {
                    Ok(mut c) => {
                        c.write_all(b"hi").await.expect("write");
                        let mut buf = [0u8; 3];
                        c.read_exact(&mut buf).await.expect("read");
                        return buf;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
            }
            panic!("client failed: {last_err:?}");
        });
        let accepted = listener.accept().await.expect("accept");
        let mut srv = accepted.stream;
        let mut buf = [0u8; 2];
        srv.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hi");
        srv.write_all(b"bye").await.expect("write");
        let got = client.await.expect("join");
        assert_eq!(&got, b"bye");
    }

    #[tokio::test]
    async fn peer_identity_is_placeholder_windows_sid() {
        let name = unique_pipe_name();
        let mut listener = NamedPipeListener::bind(&name).expect("bind");
        let name_client = name.clone();
        let _client = tokio::spawn(async move {
            for _ in 0..5u8 {
                if let Ok(c) = ClientOptions::new().open(&name_client) {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    drop(c);
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
        let accepted = listener.accept().await.expect("accept");
        match accepted.identity {
            PeerIdentity::Windows { sid, pid } => {
                assert!(
                    sid.is_none() && pid.is_none(),
                    "expected unset identity until real SID lookup lands, got sid={sid:?} pid={pid:?}",
                );
            }
            other => panic!("expected Windows identity, got {other:?}"),
        }
    }
}
