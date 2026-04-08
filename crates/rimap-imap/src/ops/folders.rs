//! `LIST`, `STATUS`, `SELECT` / `EXAMINE` against an active `async-imap` session.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{Folder, FolderStatus, SelectedFolder, StatusItems};

pub(crate) async fn list(session: &mut ImapSession, pattern: &str) -> Result<Vec<Folder>, Error> {
    let mut stream = session
        .list(Some(""), Some(pattern))
        .await
        .map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(name) = stream.next().await {
        let name = name.map_err(map_err)?;
        out.push(Folder {
            name: name.name().to_string(),
            attributes: name
                .attributes()
                .iter()
                .map(|attr| format!("{attr:?}"))
                .collect(),
            delimiter: name.delimiter().and_then(|s| s.chars().next()),
        });
    }
    Ok(out)
}

pub(crate) async fn status(
    session: &mut ImapSession,
    folder: &str,
    items: StatusItems,
) -> Result<FolderStatus, Error> {
    let item_str = build_status_items(items);
    let mailbox = session.status(folder, &item_str).await.map_err(map_err)?;
    // STATUS response populates only the requested fields.
    // The async-imap Mailbox type uses u32 for exists/recent (from SELECT),
    // but STATUS might not return them. We map them to Option<u32> for our API.
    Ok(FolderStatus {
        messages: if items.messages {
            Some(mailbox.exists)
        } else {
            None
        },
        recent: if items.recent {
            Some(mailbox.recent)
        } else {
            None
        },
        uid_next: mailbox.uid_next,
        uid_validity: mailbox.uid_validity,
        unseen: mailbox.unseen,
    })
}

pub(crate) async fn select(
    session: &mut ImapSession,
    folder: &str,
    read_only: bool,
) -> Result<SelectedFolder, Error> {
    let mailbox = if read_only {
        session.examine(folder).await.map_err(map_err)?
    } else {
        session.select(folder).await.map_err(map_err)?
    };
    Ok(SelectedFolder {
        name: folder.to_string(),
        exists: mailbox.exists,
        recent: mailbox.recent,
        uid_validity: mailbox.uid_validity.unwrap_or(0),
        uid_next: mailbox.uid_next,
        read_only,
    })
}

fn build_status_items(items: StatusItems) -> String {
    let mut parts: Vec<&str> = Vec::with_capacity(5);
    if items.messages {
        parts.push("MESSAGES");
    }
    if items.recent {
        parts.push("RECENT");
    }
    if items.uid_next {
        parts.push("UIDNEXT");
    }
    if items.uid_validity {
        parts.push("UIDVALIDITY");
    }
    if items.unseen {
        parts.push("UNSEEN");
    }
    format!("({})", parts.join(" "))
}

/// Classify an async-imap error into our Error taxonomy.
///
/// Walks the `std::error::Error::source()` chain looking for a
/// `std::io::Error` whose `ErrorKind` indicates a dead TCP connection
/// (`ConnectionReset`, `ConnectionAborted`, `BrokenPipe`, `UnexpectedEof`,
/// `NotConnected`). Those surface as `ConnectionLost` so the caller can
/// drop the cached session and lazy-reconnect on the next op. Anything
/// else becomes `Protocol`.
///
/// The previous implementation substring-matched the lowercased `Display`
/// text, which missed async-imap's `Io(BrokenPipe)` formatting (the text
/// "I/O error: Broken pipe" does not contain the word "connection") and
/// left the session cached in a dead state. See #38 for the follow-up.
pub(super) fn map_err(err: async_imap::error::Error) -> Error {
    if is_connection_lost(&err) {
        Error::ConnectionLost
    } else {
        Error::Protocol(err)
    }
}

fn is_connection_lost(err: &async_imap::error::Error) -> bool {
    use std::error::Error as _;

    // Check the top-level error first — async-imap's `Io` variant wraps
    // the `io::Error` directly.
    if let async_imap::error::Error::Io(io_err) = err
        && is_dead_tcp_kind(io_err.kind())
    {
        return true;
    }

    // Otherwise walk the source chain in case a future async-imap version
    // wraps the io::Error more deeply.
    let mut src: Option<&(dyn std::error::Error + 'static)> = err.source();
    while let Some(cause) = src {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>()
            && is_dead_tcp_kind(io_err.kind())
        {
            return true;
        }
        src = cause.source();
    }

    false
}

fn is_dead_tcp_kind(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::BrokenPipe
        | ErrorKind::UnexpectedEof
        | ErrorKind::NotConnected => true,
        ErrorKind::NotFound
        | ErrorKind::PermissionDenied
        | ErrorKind::ConnectionRefused
        | ErrorKind::AddrInUse
        | ErrorKind::AddrNotAvailable
        | ErrorKind::AlreadyExists
        | ErrorKind::WouldBlock
        | ErrorKind::InvalidInput
        | ErrorKind::InvalidData
        | ErrorKind::TimedOut
        | ErrorKind::WriteZero
        | ErrorKind::Interrupted
        | ErrorKind::Unsupported
        | ErrorKind::OutOfMemory
        | ErrorKind::Other
        | _ => false,
    }
}
