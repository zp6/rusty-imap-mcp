//! UID MOVE with COPY+DELETE fallback for servers without the MOVE
//! extension (RFC 6851).

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::ops::store;
use crate::types::{Flag, FlagAction, MoveResult, Uid};

/// Maximum UIDs per MOVE command.
const MAX_BATCH: usize = 100;

/// Move `uids` from the currently selected folder to `dest_folder`.
///
/// Tries `UID MOVE` first (RFC 6851). If the server rejects the
/// command (BAD / unknown / not supported), falls back to
/// COPY + STORE \Deleted + EXPUNGE.
///
/// # Errors
///
/// Returns `Error::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates connection-lost or protocol errors from async-imap.
pub async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
) -> Result<Vec<MoveResult>, Error> {
    if uids.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(Vec::new());
    }

    let uid_set = store::uid_set_string(uids);

    // Try MOVE first; fall back to COPY+DELETE if the server rejects it.
    let move_result = session.uid_mv(&uid_set, dest_folder).await;

    match move_result {
        Ok(()) => Ok(build_results(uids)),
        Err(e) if is_move_unsupported(&e) => copy_delete_fallback(session, dest_folder, uids).await,
        Err(e) => Err(super::folders::map_err(e)),
    }
}

/// Fallback: COPY + STORE \Deleted + EXPUNGE. Not atomic.
///
/// The plain `EXPUNGE` command removes all messages with `\Deleted` in
/// the selected mailbox, not just the UIDs this operation flagged.
/// `UID EXPUNGE` (RFC 4315) would be UID-scoped but async-imap 0.11
/// does not expose it. Servers that support MOVE never reach this path.
async fn copy_delete_fallback(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
) -> Result<Vec<MoveResult>, Error> {
    let uid_set = store::uid_set_string(uids);

    // Step 1: COPY to destination.
    session
        .uid_copy(&uid_set, dest_folder)
        .await
        .map_err(super::folders::map_err)?;

    // Step 2: STORE +FLAGS \Deleted on the originals.
    store::store(session, uids, &[Flag::Deleted], FlagAction::Add).await?;

    // Step 3: EXPUNGE to remove deleted messages. The stream yields
    // sequence numbers of expunged messages; drain it to completion.
    // The stream is !Unpin, so we pin it before polling.
    let stream = session.expunge().await.map_err(super::folders::map_err)?;
    futures_util::pin_mut!(stream);
    while let Some(item) = stream.next().await {
        let _seq = item.map_err(super::folders::map_err)?;
    }

    Ok(build_results(uids))
}

/// Check whether the async-imap error indicates that the MOVE command
/// is not supported by the server (BAD response, "unknown command",
/// "not supported").
fn is_move_unsupported(err: &async_imap::error::Error) -> bool {
    match err {
        async_imap::error::Error::Bad(_) => true,
        async_imap::error::Error::No(msg) => {
            let lower = msg.to_ascii_lowercase();
            lower.contains("unknown command") || lower.contains("not supported")
        }
        // async_imap::error::Error is #[non_exhaustive], so the
        // wildcard is required. All other known variants (Io,
        // ConnectionLost, Parse, Validate, Append) are real failures.
        _ => false,
    }
}

/// Build `MoveResult` entries with `new_uid: None` (async-imap does
/// not expose UIDPLUS data).
fn build_results(uids: &[Uid]) -> Vec<MoveResult> {
    let mut results = Vec::with_capacity(uids.len());
    for &uid in uids {
        results.push(MoveResult {
            old_uid: uid,
            new_uid: None,
        });
    }
    results
}
