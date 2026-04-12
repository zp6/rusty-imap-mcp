//! IMAP APPEND: upload a message to a mailbox.

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{AppendResult, Flag};

/// Append a raw RFC 5322 message to `folder` with the given system
/// flags and keywords.
///
/// Does NOT select the folder first — APPEND targets a named mailbox
/// directly per RFC 3501 section 6.3.11.
///
/// # Errors
///
/// Propagates connection-lost or protocol errors from async-imap.
pub async fn append(
    session: &mut ImapSession,
    folder: &str,
    message: &[u8],
    flags: &[Flag],
    keywords: &[&str],
) -> Result<AppendResult, Error> {
    let flag_str = build_flags_string(flags, keywords);
    let flags_arg = if flag_str.is_empty() {
        None
    } else {
        Some(format!("({flag_str})"))
    };

    session
        .append(folder, flags_arg.as_deref(), None, message)
        .await
        .map_err(super::folders::map_err)?;

    Ok(AppendResult { uid: None })
}

/// Build the combined flags string from system flags and keywords.
fn build_flags_string(flags: &[Flag], keywords: &[&str]) -> String {
    use crate::ops::store::flags_string;
    let mut s = flags_string(flags);
    for kw in keywords {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(kw);
    }
    s
}
