//! Label (custom keyword) tool handlers: `add_label`, `remove_label`,
//! `list_labels`.
//!
//! # UIDVALIDITY limitation
//!
//! All handlers in this module accept UIDs but do not return or cross-check
//! UIDVALIDITY. If the folder's UID namespace rotates between the caller's
//! UID acquisition and the call, the operation may affect unintended
//! messages. This is consistent with other flag tools (`mark_read`, `flag`,
//! etc.) and will be addressed in a future release.

use rimap_imap::types::{FetchSpec, Flag, FlagAction};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::flags::resolve_uids;

/// IMAP atom specials (RFC 3501 §9) plus backslash. Any of these
/// inside a keyword would break the STORE command or collide with
/// the system-flag namespace.
const ATOM_SPECIALS: &[char] = &['(', ')', '{', ' ', '%', '*', '"', '[', ']', '\\'];

/// System flag names that must not be used as custom keywords.
const SYSTEM_FLAGS: &[&str] = &["seen", "answered", "flagged", "deleted", "draft", "recent"];

/// Maximum label length in bytes.
const MAX_LABEL_BYTES: usize = 256;

/// Validate a custom keyword label for IMAP STORE safety.
pub(crate) fn validate_label(label: &str) -> Result<(), rimap_core::RimapError> {
    if label.is_empty() {
        return Err(invalid_input("label must not be empty"));
    }
    if !label.is_ascii() {
        return Err(invalid_input("label must be ASCII (RFC 3501 atom syntax)"));
    }
    if label.len() > MAX_LABEL_BYTES {
        return Err(invalid_input(&format!(
            "label exceeds maximum of {MAX_LABEL_BYTES} bytes"
        )));
    }
    if label.as_bytes().contains(&0) {
        return Err(invalid_input("label must not contain null bytes"));
    }
    if label.starts_with('\\') {
        return Err(invalid_input(
            "label must not start with '\\' (system flag namespace)",
        ));
    }
    if label.chars().any(|c| ATOM_SPECIALS.contains(&c)) {
        return Err(invalid_input("label contains IMAP atom special characters"));
    }
    if label.chars().any(|c| c.is_ascii_control()) {
        return Err(invalid_input(
            "label must not contain ASCII control characters",
        ));
    }
    if SYSTEM_FLAGS.contains(&label.to_ascii_lowercase().as_str()) {
        return Err(invalid_input(&format!(
            "'{label}' is a reserved system flag name"
        )));
    }
    Ok(())
}

fn invalid_input(message: &str) -> rimap_core::RimapError {
    rimap_core::RimapError::invalid_input(message)
}

/// Input for `add_label` and `remove_label` tools.
///
/// # Shape
///
/// This tool accepts either a single `uid` or a batch `uids` (XOR; max
/// 100). The asymmetry with single-target tools (`fetch_message`,
/// `list_attachments`, `download_attachment`, `delete_message`) is
/// deliberate: batch shapes are reserved for commutative, idempotent
/// mutations where per-UID ordering does not matter and results fan out
/// uniformly. Read-side and destructive single-target tools keep a
/// scalar `uid` so the response schema and error semantics stay
/// unambiguous.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct LabelInput {
    /// Target folder.
    pub folder: String,
    /// Single UID.
    pub uid: Option<u32>,
    /// Batch of UIDs (max 100).
    pub uids: Option<Vec<u32>>,
    /// Custom keyword label to add or remove.
    pub label: String,
}

/// Input for `list_labels` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListLabelsInput {
    /// Target folder.
    pub folder: String,
    /// Message UID.
    pub uid: u32,
}

/// Trusted metadata for `add_label` and `remove_label` responses.
#[derive(Debug, Serialize)]
pub struct LabelsMeta {
    /// Folder the label was applied to.
    pub folder: String,
    /// Label that was added or removed.
    pub label: String,
    /// UIDs that were updated.
    pub uids_updated: Vec<u32>,
}

/// Trusted metadata for a `list_labels` response.
#[derive(Debug, Serialize)]
pub struct ListLabelsMeta {
    /// Folder the labels were fetched from.
    pub folder: String,
    /// UID of the message.
    pub uid: u32,
    /// Custom keyword labels on the message.
    pub labels: Vec<String>,
}

/// `add_label` handler — STORE +FLAGS with a custom keyword.
/// See the module-level doc for the UIDVALIDITY limitation.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for invalid
/// labels (empty, control chars, atom-specials, system-flag collisions,
/// zero UID, batch over 100). Returns `RimapError::Imap { ... }` for
/// IMAP-layer failures.
pub async fn handle_add_label(
    account: &AccountState,
    input: LabelInput,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    handle_label_op(account, input, FlagAction::Add).await
}

/// `remove_label` handler — STORE -FLAGS with a custom keyword.
/// See the module-level doc for the UIDVALIDITY limitation.
///
/// # Errors
///
/// Same shape as [`handle_add_label`]: `Authz { InvalidInput }` for shape
/// errors and `Imap { ... }` for IMAP-layer failures.
pub async fn handle_remove_label(
    account: &AccountState,
    input: LabelInput,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    handle_label_op(account, input, FlagAction::Remove).await
}

/// Shared body for `add_label` / `remove_label`: validate the label,
/// resolve UIDs, issue a STORE ±FLAGS, return the per-UID result summary.
async fn handle_label_op(
    account: &AccountState,
    input: LabelInput,
    action: FlagAction,
) -> Result<ToolResponse<LabelsMeta>, rimap_core::RimapError> {
    validate_label(&input.label)?;
    let uids = resolve_uids(input.uid, input.uids)?;
    let updated = account
        .imap
        .store_flags(
            &input.folder,
            &uids,
            &[Flag::Keyword(input.label.clone())],
            action,
        )
        .await?;

    let updated_ids: Vec<u32> = updated.iter().map(|u| u.get()).collect();
    Ok(ToolResponse::meta_only(LabelsMeta {
        folder: input.folder,
        label: input.label,
        uids_updated: updated_ids,
    }))
}

/// `list_labels` handler — FETCH FLAGS and return keyword entries.
/// See the module-level doc for the UIDVALIDITY limitation.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput }` for zero UID,
/// `Authz { code: NotFound }` if the message UID is missing in the
/// folder, and `Imap { ... }` for IMAP-layer failures.
pub async fn handle_list_labels(
    account: &AccountState,
    input: ListLabelsInput,
) -> Result<ToolResponse<ListLabelsMeta>, rimap_core::RimapError> {
    let uid = rimap_imap::types::Uid::new(input.uid)
        .ok_or_else(|| invalid_input("UID must be non-zero"))?;

    let spec = FetchSpec {
        flags: true,
        ..FetchSpec::default()
    };
    let messages = account.imap.fetch(&input.folder, &[uid], spec).await?;

    let msg = messages
        .into_iter()
        .next()
        .ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::NotFound,
            message: format!(
                "message UID {} not found in folder '{}'",
                input.uid, input.folder
            ),
        })?;

    let labels: Vec<String> = msg
        .flags
        .as_ref()
        .map(|flags| {
            flags
                .iter()
                .filter_map(|f| match f {
                    Flag::Keyword(kw) => Some(kw.clone()),
                    Flag::Seen
                    | Flag::Answered
                    | Flag::Flagged
                    | Flag::Deleted
                    | Flag::Draft
                    | Flag::Recent => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(ToolResponse::meta_only(ListLabelsMeta {
        folder: input.folder,
        uid: input.uid,
        labels,
    }))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_label() {
        let err = validate_label("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_overlength_label() {
        let long = "a".repeat(257);
        let err = validate_label(&long).unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn accepts_max_length_label() {
        let exact = "a".repeat(256);
        validate_label(&exact).unwrap();
    }

    #[test]
    fn rejects_null_bytes() {
        let err = validate_label("foo\0bar").unwrap_err();
        assert!(err.to_string().contains("null"));
    }

    #[test]
    fn rejects_backslash_prefix() {
        let err = validate_label("\\Seen").unwrap_err();
        assert!(err.to_string().contains("system flag namespace"));
    }

    #[test]
    fn rejects_system_flags_case_insensitive() {
        for name in &[
            "Seen", "SEEN", "seen", "Answered", "Flagged", "Deleted", "Draft", "Recent", "DRAFT",
            "rEcEnT",
        ] {
            let err = validate_label(name).unwrap_err();
            assert!(
                err.to_string().contains("reserved system flag"),
                "expected rejection for '{name}', got: {err}"
            );
        }
    }

    #[test]
    fn rejects_atom_specials() {
        for ch in ATOM_SPECIALS {
            let label = format!("foo{ch}bar");
            let result = validate_label(&label);
            assert!(result.is_err(), "expected rejection for char '{ch}'");
        }
    }

    #[test]
    fn rejects_control_characters() {
        let err = validate_label("foo\x01bar").unwrap_err();
        assert!(err.to_string().contains("control"));

        let err = validate_label("foo\x7Fbar").unwrap_err();
        assert!(err.to_string().contains("control"));

        let err = validate_label("\t").unwrap_err();
        assert!(err.to_string().contains("control"));
    }

    #[test]
    fn accepts_valid_labels() {
        validate_label("Urgent").unwrap();
        validate_label("$PendingReview").unwrap();
        validate_label("project/alpha").unwrap();
        validate_label("my-label").unwrap();
        validate_label("Label_123").unwrap();
    }

    #[test]
    fn non_ascii_label_rejected() {
        assert!(validate_label("résumé").is_err());
        assert!(validate_label("Urgеnt").is_err()); // Cyrillic 'е'
        assert!(validate_label("\u{202E}evil").is_err()); // RTL override
        assert!(validate_label("foo\u{200B}bar").is_err()); // zero-width space
    }

    #[test]
    fn left_bracket_rejected() {
        assert!(validate_label("foo[bar").is_err());
    }

    #[test]
    fn accepts_dollar_prefix_keywords() {
        validate_label("$Junk").unwrap();
        validate_label("$NotJunk").unwrap();
        validate_label("$MDNSent").unwrap();
    }
}
