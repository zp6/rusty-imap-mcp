//! UID MOVE with COPY+DELETE fallback for servers without the MOVE
//! extension (RFC 6851).

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::ops::store;
use crate::types::{Flag, FlagAction, MoveResult, Uid};

/// Maximum UIDs per MOVE command.
const MAX_BATCH: usize = 100;

/// Outcome of a `move_messages` call.
#[derive(Debug)]
#[must_use = "check used_fallback for security warnings"]
pub struct MoveOutcome {
    /// Per-UID results.
    pub results: Vec<MoveResult>,
    /// `true` when the non-atomic COPY+DELETE+EXPUNGE fallback was used
    /// instead of the atomic UID MOVE command. Callers should surface a
    /// security warning when this is `true`.
    pub used_fallback: bool,
}

/// Move `uids` from the currently selected folder to `dest_folder`.
///
/// When `has_move` is `true` the server advertised the MOVE capability
/// and UID MOVE is used directly. A BAD response in this case is
/// propagated as an error (the server lied about its capabilities).
///
/// When `has_move` is `false` the COPY+DELETE fallback is used
/// immediately without attempting UID MOVE.
///
/// # Errors
///
/// Returns `Error::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates connection-lost or protocol errors from async-imap.
pub async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_move: bool,
    has_uidplus: bool,
) -> Result<MoveOutcome, Error> {
    if uids.len() > MAX_BATCH {
        return Err(Error::BatchTooLarge {
            count: uids.len(),
            limit: MAX_BATCH,
        });
    }
    if uids.is_empty() {
        return Ok(MoveOutcome {
            results: Vec::new(),
            used_fallback: false,
        });
    }

    if !has_move {
        let results = copy_delete_fallback(session, dest_folder, uids, has_uidplus).await?;
        return Ok(MoveOutcome {
            results,
            used_fallback: true,
        });
    }

    let uid_set = store::uid_set_string(uids);
    let move_result = session.uid_mv(&uid_set, dest_folder).await;

    match move_result {
        Ok(()) => Ok(MoveOutcome {
            results: build_results(uids),
            used_fallback: false,
        }),
        Err(e) => Err(super::folders::map_err(e)),
    }
}

/// Fallback: COPY + STORE \Deleted + EXPUNGE. Not atomic.
///
/// When `has_uidplus` is true, UID EXPUNGE (RFC 4315) is used to remove only
/// the flagged UIDs. Otherwise plain EXPUNGE removes all `\Deleted` messages,
/// which is a known data-loss risk for concurrent operations.
/// Servers that support MOVE never reach this path.
async fn copy_delete_fallback(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_uidplus: bool,
) -> Result<Vec<MoveResult>, Error> {
    let uid_set = store::uid_set_string(uids);

    // Step 1: COPY to destination.
    session
        .uid_copy(&uid_set, dest_folder)
        .await
        .map_err(super::folders::map_err)?;

    // Step 2: STORE +FLAGS \Deleted on the originals.
    store::store(session, uids, &[Flag::Deleted], FlagAction::Add).await?;

    // Step 3: Remove the flagged messages from the source folder.
    if has_uidplus {
        // UID EXPUNGE (RFC 4315): only expunge the UIDs we flagged.
        let stream = session
            .uid_expunge(&uid_set)
            .await
            .map_err(super::folders::map_err)?;
        futures_util::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let _uid = item.map_err(super::folders::map_err)?;
        }
    } else {
        // Plain EXPUNGE: removes ALL \Deleted messages. Known data-loss
        // risk with concurrent \Deleted flags. Servers without both MOVE
        // and UIDPLUS are rare in practice.
        let stream = session.expunge().await.map_err(super::folders::map_err)?;
        futures_util::pin_mut!(stream);
        while let Some(item) = stream.next().await {
            let _seq = item.map_err(super::folders::map_err)?;
        }
    }

    Ok(build_results(uids))
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
