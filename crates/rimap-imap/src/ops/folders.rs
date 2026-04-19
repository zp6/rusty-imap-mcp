//! `LIST`, `STATUS`, `SELECT` / `EXAMINE` against an active `async-imap` session.

use async_imap::types::NameAttribute;
use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::types::{Folder, FolderStatus, SelectedFolder, StatusItems};

pub(crate) async fn list(
    session: &mut ImapSession,
    pattern: &str,
) -> Result<Vec<Folder>, ImapError> {
    let mut stream = session
        .list(Some(""), Some(pattern))
        .await
        .map_err(map_err)?;
    let mut out = Vec::new();
    while let Some(name) = stream.next().await {
        let name = name.map_err(map_err)?;
        let attrs = name.attributes();
        let selectable = is_selectable(attrs);
        let special_use = crate::special_use::classify_special_use(attrs);
        out.push(Folder {
            name: name.name().to_string(),
            attributes: attrs.iter().map(|attr| format!("{attr:?}")).collect(),
            delimiter: name.delimiter().and_then(|s| s.chars().next()),
            selectable,
            special_use,
        });
    }
    Ok(out)
}

/// Returns `false` if any attribute marks the mailbox non-selectable —
/// RFC 3501 `\Noselect` or RFC 5258 `\NonExistent`. Running `STATUS`,
/// `SELECT`, or `EXAMINE` against such an entry is a protocol error on
/// strict servers (Gmail returns `[NONEXISTENT] Invalid folder` and drops
/// the response).
///
/// `\NonExistent` is not a dedicated variant in the `imap-proto` enum (it
/// arrives as `Extension("\\NonExistent")`), so the check walks both the
/// named variant and the extension string with a case-insensitive compare.
fn is_selectable(attrs: &[NameAttribute<'_>]) -> bool {
    for attr in attrs {
        match attr {
            NameAttribute::NoSelect => return false,
            NameAttribute::Extension(ext) if ext.eq_ignore_ascii_case("\\NonExistent") => {
                return false;
            }
            _ => {}
        }
    }
    true
}

pub(crate) async fn status(
    session: &mut ImapSession,
    folder: &str,
    items: StatusItems,
) -> Result<FolderStatus, ImapError> {
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
) -> Result<SelectedFolder, ImapError> {
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

/// Classify an async-imap error into our `ImapError` taxonomy.
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
pub(super) fn map_err(err: async_imap::error::Error) -> ImapError {
    if is_connection_lost(&err) {
        ImapError::ConnectionLost
    } else {
        ImapError::Protocol(err)
    }
}

fn is_connection_lost(err: &async_imap::error::Error) -> bool {
    use std::error::Error as _;

    // Check the top-level error first — async-imap's `Io` variant wraps
    // the `io::ImapError` directly.
    if let async_imap::error::Error::Io(io_err) = err
        && is_dead_tcp_kind(io_err.kind())
    {
        return true;
    }

    // Otherwise walk the source chain in case a future async-imap version
    // wraps the io::ImapError more deeply.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_selectable_accepts_normal_folder() {
        let attrs = [
            NameAttribute::Unmarked,
            NameAttribute::Extension("\\HasNoChildren".into()),
        ];
        assert!(is_selectable(&attrs));
    }

    #[test]
    fn is_selectable_rejects_noselect() {
        let attrs = [
            NameAttribute::Extension("\\HasChildren".into()),
            NameAttribute::NoSelect,
        ];
        assert!(!is_selectable(&attrs));
    }

    #[test]
    fn is_selectable_rejects_rfc5258_nonexistent_extension() {
        let attrs = [NameAttribute::Extension("\\NonExistent".into())];
        assert!(!is_selectable(&attrs));
    }

    #[test]
    fn is_selectable_nonexistent_match_is_case_insensitive() {
        let attrs = [NameAttribute::Extension("\\nonexistent".into())];
        assert!(!is_selectable(&attrs));
    }

    #[test]
    fn is_selectable_ignores_unrelated_extensions() {
        let attrs = [
            NameAttribute::Extension("\\All".into()),
            NameAttribute::Extension("\\Sent".into()),
        ];
        assert!(is_selectable(&attrs));
    }

    #[test]
    fn is_selectable_empty_attribute_list_is_selectable() {
        assert!(is_selectable(&[]));
    }

    #[test]
    fn status_items_empty_selection_renders_empty_parens() {
        let items = StatusItems {
            messages: false,
            recent: false,
            uid_next: false,
            uid_validity: false,
            unseen: false,
        };
        assert_eq!(build_status_items(items), "()");
    }

    #[test]
    fn status_items_preserves_canonical_order() {
        // IMAP STATUS items are space-separated and not order-sensitive per
        // RFC 3501, but this op always emits in the declared struct order
        // so the wire format is stable for golden tests.
        let items = StatusItems {
            messages: true,
            recent: true,
            uid_next: true,
            uid_validity: true,
            unseen: true,
        };
        assert_eq!(
            build_status_items(items),
            "(MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)"
        );
    }

    #[test]
    fn status_items_single_flag_emits_single_token() {
        let items = StatusItems {
            messages: false,
            recent: false,
            uid_next: true,
            uid_validity: false,
            unseen: false,
        };
        assert_eq!(build_status_items(items), "(UIDNEXT)");
    }

    #[test]
    fn is_dead_tcp_kind_covers_documented_dead_kinds() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::BrokenPipe,
            ErrorKind::UnexpectedEof,
            ErrorKind::NotConnected,
        ] {
            assert!(is_dead_tcp_kind(kind), "expected dead: {kind:?}");
        }
    }

    #[test]
    fn is_dead_tcp_kind_rejects_non_dead_kinds() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::Other,
        ] {
            assert!(!is_dead_tcp_kind(kind), "expected alive: {kind:?}");
        }
    }

    #[test]
    fn map_err_routes_io_broken_pipe_to_connection_lost() {
        // Regression: the previous substring matcher missed async-imap's
        // Io(BrokenPipe) formatting because "I/O error: Broken pipe" does
        // not contain the word "connection". Guard that here.
        let io = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken pipe");
        let mapped = map_err(async_imap::error::Error::Io(io));
        assert!(matches!(mapped, ImapError::ConnectionLost));
    }

    #[test]
    fn map_err_routes_io_timed_out_to_protocol() {
        let io = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        let mapped = map_err(async_imap::error::Error::Io(io));
        assert!(matches!(mapped, ImapError::Protocol(_)));
    }

    #[test]
    fn map_err_routes_bad_response_to_protocol() {
        let mapped = map_err(async_imap::error::Error::Bad("BAD".to_string()));
        assert!(matches!(mapped, ImapError::Protocol(_)));
    }
}
