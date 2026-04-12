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
    let flag_str = flags_string(flags);
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

/// Format flags as space-separated IMAP flag atoms.
pub(crate) fn flags_string(flags: &[Flag]) -> String {
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
            Flag::Keyword(k) => s.push_str(k),
        }
    }
    s
}
