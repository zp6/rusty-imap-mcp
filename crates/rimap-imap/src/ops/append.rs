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
    max_append_bytes: u64,
) -> Result<AppendResult, Error> {
    check_append_size(message, max_append_bytes)?;
    let flag_str = build_flags_string(flags, keywords)?;
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

/// Reject messages exceeding the configured byte limit.
fn check_append_size(message: &[u8], max_append_bytes: u64) -> Result<(), Error> {
    let len = message.len() as u64;
    if len > max_append_bytes {
        return Err(Error::SizeLimit {
            limit: max_append_bytes,
        });
    }
    Ok(())
}

/// Build the combined flags string from system flags and keywords.
///
/// # Errors
///
/// Returns `Error::InvalidInput` if any keyword or `Flag::Keyword`
/// content contains non-atom characters.
fn build_flags_string(flags: &[Flag], keywords: &[&str]) -> Result<String, Error> {
    use crate::ops::store;
    let mut s = store::flags_string(flags)?;
    for kw in keywords {
        store::validate_keyword(kw)?;
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(kw);
    }
    Ok(s)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
#[expect(clippy::panic, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn append_rejects_oversized_message() {
        let limit: u64 = 100;
        let message = vec![b'X'; 101];
        let result = super::check_append_size(&message, limit);
        match result {
            Err(Error::SizeLimit { limit: l }) => assert_eq!(l, 100),
            other => panic!("expected SizeLimit, got {other:?}"),
        }
    }

    #[test]
    fn append_accepts_message_at_limit() {
        let limit: u64 = 100;
        let message = vec![b'X'; 100];
        assert!(super::check_append_size(&message, limit).is_ok());
    }

    #[test]
    fn build_flags_string_rejects_bad_keyword() {
        let flags = vec![Flag::Seen];
        let keywords = &["good", "inject\r\nDATA"];
        assert!(build_flags_string(&flags, keywords).is_err());
    }

    #[test]
    fn build_flags_string_accepts_valid() {
        let flags = vec![Flag::Flagged];
        let keywords = &["$label1", "Important"];
        let s = build_flags_string(&flags, keywords).unwrap();
        assert_eq!(s, "\\Flagged $label1 Important");
    }
}
