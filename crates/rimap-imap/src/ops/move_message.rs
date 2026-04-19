//! UID MOVE with COPY+DELETE fallback for servers without the MOVE
//! extension (RFC 6851).

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::ops::store;
use crate::types::{Flag, FlagAction, MoveResult, Uid};

/// Maximum UIDs per MOVE command.
const MAX_BATCH: usize = 100;

/// Outcome of a `move_messages` call.
#[derive(Debug)]
#[must_use = "check used_fallback for security warnings"]
#[non_exhaustive]
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
/// Returns `ImapError::BatchTooLarge` if `uids.len() > MAX_BATCH`.
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn move_messages(
    session: &mut ImapSession,
    dest_folder: &str,
    uids: &[Uid],
    has_move: bool,
    has_uidplus: bool,
) -> Result<MoveOutcome, ImapError> {
    crate::ops::folders::validate_server_folder_name(dest_folder)?;
    if uids.len() > MAX_BATCH {
        return Err(ImapError::BatchTooLarge {
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
) -> Result<Vec<MoveResult>, ImapError> {
    crate::ops::folders::validate_server_folder_name(dest_folder)?;
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

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use super::*;

    fn uid(n: u32) -> Uid {
        Uid::new(n).expect("non-zero")
    }

    #[test]
    fn build_results_is_empty_for_empty_input() {
        assert!(build_results(&[]).is_empty());
    }

    #[test]
    fn build_results_preserves_order_and_leaves_new_uid_unknown() {
        // UIDPLUS is not parsed out of async-imap's MOVE response today,
        // so every entry records the old UID and a None for new_uid.
        // Documenting this at the unit layer prevents a future COPYUID
        // refactor from breaking the client contract silently.
        let uids = [uid(7), uid(3), uid(11)];
        let results = build_results(&uids);
        assert_eq!(results.len(), 3);
        for (i, r) in results.iter().enumerate() {
            assert_eq!(r.old_uid, uids[i]);
            assert!(r.new_uid.is_none());
        }
    }

    #[test]
    fn build_results_preserves_duplicates() {
        // MOVE is called with pre-deduped UIDs, but the helper itself does
        // no filtering — that responsibility sits with the caller.
        let uids = [uid(5), uid(5)];
        let results = build_results(&uids);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].old_uid, uids[0]);
        assert_eq!(results[1].old_uid, uids[1]);
    }

    #[test]
    fn server_folder_validator_rejects_nul_dest_folder() {
        // Pins that validate_server_folder_name — which move_messages and
        // copy_delete_fallback both call at entry — rejects control bytes.
        use crate::ops::folders::validate_server_folder_name;
        assert!(validate_server_folder_name("target\0folder").is_err());
        assert!(validate_server_folder_name("target\x1ffolder").is_err());
        assert!(validate_server_folder_name("normal/path").is_ok());
    }
}
