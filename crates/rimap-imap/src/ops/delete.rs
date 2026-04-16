//! `delete_message`: STORE +FLAGS (\Deleted) + UID MOVE to Trash.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::ImapError;
use crate::ops::store;
use crate::types::{Flag, FlagAction, Uid};

/// Delete a message: flag it as `\Deleted` and move it to Trash.
///
/// If the message is already in the Trash folder (case-insensitive match),
/// only the `\Deleted` flag is applied — no move is attempted.
///
/// Caller must SELECT the `source_folder` before calling this function.
///
/// # Errors
///
/// Propagates connection-lost or protocol errors from async-imap.
pub(crate) async fn delete_message(
    session: &mut ImapSession,
    uid: Uid,
    source_folder: &str,
    trash_folder: &str,
    has_move: bool,
    has_uidplus: bool,
) -> Result<DeleteResult, ImapError> {
    super::folder_management::validate_folder_name(source_folder)?;
    super::folder_management::validate_folder_name(trash_folder)?;

    // Step 1: STORE +FLAGS (\Deleted)
    store::store(session, &[uid], &[Flag::Deleted], FlagAction::Add).await?;

    // Step 2: If already in Trash, skip the move
    let in_trash = source_folder.eq_ignore_ascii_case(trash_folder);
    if in_trash {
        return Ok(DeleteResult {
            uid,
            moved_to_trash: false,
        });
    }

    // Step 3: Move to Trash
    let uid_set = store::uid_set_string(&[uid]);
    if has_move {
        session
            .uid_mv(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
    } else {
        // Fallback: COPY + scoped EXPUNGE.
        session
            .uid_copy(&uid_set, trash_folder)
            .await
            .map_err(super::folders::map_err)?;
        // The \Deleted flag was already set in step 1.
        if has_uidplus {
            // UID EXPUNGE (RFC 4315): only expunge this specific UID.
            let stream = session
                .uid_expunge(&uid_set)
                .await
                .map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _uid = item.map_err(super::folders::map_err)?;
            }
        } else {
            // Plain EXPUNGE: removes ALL \Deleted messages in the folder.
            // This is a known data-loss risk when other messages are
            // concurrently flagged \Deleted. Servers without both MOVE
            // and UIDPLUS are rare in practice.
            let stream = session.expunge().await.map_err(super::folders::map_err)?;
            futures_util::pin_mut!(stream);
            while let Some(item) = StreamExt::next(&mut stream).await {
                let _seq = item.map_err(super::folders::map_err)?;
            }
        }
    }

    Ok(DeleteResult {
        uid,
        moved_to_trash: true,
    })
}

/// Result of a `delete_message` operation.
#[derive(Debug)]
pub struct DeleteResult {
    /// The UID of the deleted message (in its original folder).
    pub uid: Uid,
    /// `true` if the message was moved to Trash; `false` if it was
    /// already in Trash and only flagged.
    pub moved_to_trash: bool,
}
