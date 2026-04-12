//! UID STORE: add or remove flags on messages by UID.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{Flag, FlagAction, Uid};

/// Maximum UIDs per STORE command.
const MAX_BATCH: usize = 100;

/// Add or remove `flags` on `uids` in the currently selected folder.
///
/// Returns the UIDs the server confirmed as updated.
///
/// # Errors
///
/// Returns `Error::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates connection-lost or protocol errors from async-imap.
pub async fn store(
    session: &mut ImapSession,
    uids: &[Uid],
    flags: &[Flag],
    action: FlagAction,
) -> Result<Vec<Uid>, Error> {
    if uids.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(Vec::new());
    }

    let uid_set = uid_set_string(uids);
    let flag_str = flags_string(flags)?;
    let query = match action {
        FlagAction::Add => format!("+FLAGS ({flag_str})"),
        FlagAction::Remove => format!("-FLAGS ({flag_str})"),
    };

    let mut stream = session
        .uid_store(&uid_set, &query)
        .await
        .map_err(super::folders::map_err)?;

    let mut updated = Vec::new();
    while let Some(item) = stream.next().await {
        let item = item.map_err(super::folders::map_err)?;
        if let Some(uid_val) = item.uid
            && let Some(uid) = Uid::new(uid_val)
        {
            updated.push(uid);
        }
    }

    Ok(updated)
}

/// Format UIDs as a comma-separated set for IMAP commands.
pub(crate) fn uid_set_string(uids: &[Uid]) -> String {
    let mut s = String::new();
    for (i, uid) in uids.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&uid.get().to_string());
    }
    s
}

/// Validate that a keyword string contains only IMAP atom characters.
/// Returns `Error::InvalidInput` if any non-atom byte is found.
///
/// IMAP atom = 1*ATOM-CHAR (RFC 3501 section 9 formal syntax)
/// ATOM-CHAR = any CHAR except atom-specials
/// atom-specials = "(" / ")" / "{" / SP / CTL /
///                 list-wildcards / quoted-specials / resp-specials
pub(crate) fn validate_keyword(keyword: &str) -> Result<(), Error> {
    if keyword.is_empty() {
        return Err(Error::InvalidInput {
            field: "keyword",
            reason: "keyword must not be empty",
        });
    }
    for byte in keyword.bytes() {
        match byte {
            // CTL (0x00-0x1f, 0x7f)
            0x00..=0x1f | 0x7f => {
                return Err(Error::InvalidInput {
                    field: "keyword",
                    reason: "contains control characters",
                });
            }
            // atom-specials: ( ) { SP % * " \ ] [
            b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']' | b'[' => {
                return Err(Error::InvalidInput {
                    field: "keyword",
                    reason: "contains IMAP atom-special characters",
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// Format flags as space-separated IMAP flag atoms.
///
/// Validates `Flag::Keyword` content against RFC 3501 atom syntax
/// to prevent IMAP command injection.
///
/// # Errors
///
/// Returns `Error::InvalidInput` if a keyword contains non-atom
/// characters (control bytes, spaces, specials).
pub(crate) fn flags_string(flags: &[Flag]) -> Result<String, Error> {
    let mut s = String::new();
    for (i, flag) in flags.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        match flag {
            Flag::Seen => s.push_str("\\Seen"),
            Flag::Answered => s.push_str("\\Answered"),
            Flag::Flagged => s.push_str("\\Flagged"),
            Flag::Deleted => s.push_str("\\Deleted"),
            Flag::Draft => s.push_str("\\Draft"),
            Flag::Recent => s.push_str("\\Recent"),
            Flag::Keyword(k) => {
                validate_keyword(k)?;
                s.push_str(k);
            }
        }
    }
    Ok(s)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn validate_keyword_accepts_valid_atom() {
        assert!(validate_keyword("Important").is_ok());
        assert!(validate_keyword("$label1").is_ok());
        assert!(validate_keyword("my-tag").is_ok());
    }

    #[test]
    fn validate_keyword_rejects_crlf() {
        let result = validate_keyword("bad\r\nSTORE");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidInput {
                field: "keyword",
                ..
            }
        ));
    }

    #[test]
    fn validate_keyword_rejects_space() {
        assert!(validate_keyword("has space").is_err());
    }

    #[test]
    fn validate_keyword_rejects_empty() {
        let err = validate_keyword("").unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidInput {
                field: "keyword",
                reason: "keyword must not be empty"
            }
        ));
    }

    #[test]
    fn validate_keyword_rejects_atom_specials() {
        for ch in ['(', ')', '{', '%', '*', '"', '\\', ']', '['] {
            let s = format!("bad{ch}kw");
            assert!(validate_keyword(&s).is_err(), "should reject '{ch}'");
        }
    }

    #[test]
    fn flags_string_propagates_keyword_error() {
        let flags = vec![Flag::Seen, Flag::Keyword("inject\r\n".to_string())];
        assert!(flags_string(&flags).is_err());
    }

    #[test]
    fn flags_string_valid_keywords() {
        let flags = vec![Flag::Seen, Flag::Keyword("Important".to_string())];
        let s = flags_string(&flags).unwrap();
        assert_eq!(s, "\\Seen Important");
    }
}
