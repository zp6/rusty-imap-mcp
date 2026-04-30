//! Compile-time posture matrix: which tools are allowed at each base posture.
//!
//! Kept in `rimap-core` so that both `rimap-config` (validation) and
//! `rimap-authz` (runtime authorization) can query it without introducing
//! a circular dependency.

use crate::posture::Posture;
use crate::tool::ToolName;

/// Compile-time truth table. `true` = allowed by base posture.
///
/// Layout: outer by [`ToolName`] (22 tools),
/// inner `[readonly, draft_safe, full, destructive]`.
pub const POSTURE_MATRIX: [(ToolName, [bool; 4]); 22] = [
    (ToolName::ListFolders, [true, true, true, true]),
    (ToolName::Search, [true, true, true, true]),
    (ToolName::SearchAdvanced, [false, false, true, true]),
    (ToolName::FetchMessage, [true, true, true, true]),
    (ToolName::FetchMessageHtml, [false, false, true, true]),
    (ToolName::ListAttachments, [true, true, true, true]),
    (ToolName::DownloadAttachment, [true, true, true, true]),
    (ToolName::MarkRead, [false, true, true, true]),
    (ToolName::MarkUnread, [false, true, true, true]),
    (ToolName::Flag, [false, true, true, true]),
    (ToolName::Unflag, [false, true, true, true]),
    (ToolName::AddLabel, [false, true, true, true]),
    (ToolName::RemoveLabel, [false, true, true, true]),
    (ToolName::ListLabels, [true, true, true, true]),
    (ToolName::MoveMessage, [false, true, true, true]),
    (ToolName::CreateDraft, [false, true, true, true]),
    // v2 tools:
    (ToolName::SendEmail, [false, false, true, true]),
    (ToolName::DeleteMessage, [false, false, true, true]),
    (ToolName::CreateFolder, [false, false, true, true]),
    (ToolName::RenameFolder, [false, false, true, true]),
    (ToolName::Expunge, [false, false, false, true]),
    (ToolName::DeleteFolder, [false, false, false, true]),
];

fn posture_index(p: Posture) -> usize {
    match p {
        Posture::Readonly => 0,
        Posture::DraftSafe => 1,
        Posture::Full => 2,
        Posture::Destructive => 3,
    }
}

/// Query whether a tool is allowed at a given base posture, ignoring
/// per-tool overrides.
///
/// Infrastructure tools (`UseAccount`, `ListAccounts`) return `false`
/// here: they bypass the posture matrix entirely at dispatch time, so
/// the matrix builder must not include them in the allowed set. The
/// matrix-driven tool advertisement filter relies on this contract.
///
/// Used by `rimap-config` validation and `rimap-authz` to share a single
/// authoritative posture matrix without a circular crate dependency.
#[must_use]
pub fn base_allows(posture: Posture, tool: ToolName) -> bool {
    let idx = posture_index(posture);
    // Exhaustive match: a new posture-gated `ToolName` variant fails to
    // compile here until a row is added to `POSTURE_MATRIX` and an arm
    // is added below — replacing the previous runtime-fallthrough loop
    // that silently denied unknown variants.
    let row = match tool {
        ToolName::ListFolders => POSTURE_MATRIX[0].1,
        ToolName::Search => POSTURE_MATRIX[1].1,
        ToolName::SearchAdvanced => POSTURE_MATRIX[2].1,
        ToolName::FetchMessage => POSTURE_MATRIX[3].1,
        ToolName::FetchMessageHtml => POSTURE_MATRIX[4].1,
        ToolName::ListAttachments => POSTURE_MATRIX[5].1,
        ToolName::DownloadAttachment => POSTURE_MATRIX[6].1,
        ToolName::MarkRead => POSTURE_MATRIX[7].1,
        ToolName::MarkUnread => POSTURE_MATRIX[8].1,
        ToolName::Flag => POSTURE_MATRIX[9].1,
        ToolName::Unflag => POSTURE_MATRIX[10].1,
        ToolName::AddLabel => POSTURE_MATRIX[11].1,
        ToolName::RemoveLabel => POSTURE_MATRIX[12].1,
        ToolName::ListLabels => POSTURE_MATRIX[13].1,
        ToolName::MoveMessage => POSTURE_MATRIX[14].1,
        ToolName::CreateDraft => POSTURE_MATRIX[15].1,
        ToolName::SendEmail => POSTURE_MATRIX[16].1,
        ToolName::DeleteMessage => POSTURE_MATRIX[17].1,
        ToolName::CreateFolder => POSTURE_MATRIX[18].1,
        ToolName::RenameFolder => POSTURE_MATRIX[19].1,
        ToolName::Expunge => POSTURE_MATRIX[20].1,
        ToolName::DeleteFolder => POSTURE_MATRIX[21].1,
        // Infrastructure tools bypass posture at the dispatch site; the
        // matrix-builder caller relies on `false` here so they are not
        // advertised via `list_tools` based on posture.
        ToolName::UseAccount | ToolName::ListAccounts => return false,
    };
    row[idx]
}
