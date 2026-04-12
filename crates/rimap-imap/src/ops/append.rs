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
mod tests {
    use super::*;

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
