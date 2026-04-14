//! Tool identity. Models the v1 tool surface at *capability* granularity so
//! the posture matrix can gate sub-features (`search.advanced_query`,
//! `fetch_message.include_html`) independently of the parent tool.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use strum::{EnumIter, IntoEnumIterator};
use thiserror::Error;

/// Identifier for a dispatchable capability. This is a superset of the MCP
/// tool names because some MCP tools expose multiple gated capabilities
/// (e.g. `search` and `search_advanced`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub enum ToolName {
    /// `list_folders`
    ListFolders,
    /// `search` with the structured query form only.
    Search,
    /// `search` with `advanced_query` escape hatch. Requires `full` posture.
    SearchAdvanced,
    /// `fetch_message` returning text parts only.
    FetchMessage,
    /// `fetch_message` with `include_html = true`. Requires `full` posture.
    FetchMessageHtml,
    /// `list_attachments`
    ListAttachments,
    /// `download_attachment`
    DownloadAttachment,
    /// `mark_read`
    MarkRead,
    /// `mark_unread`
    MarkUnread,
    /// `flag`
    Flag,
    /// `unflag`
    Unflag,
    /// `add_label`
    AddLabel,
    /// `remove_label`
    RemoveLabel,
    /// `list_labels`
    ListLabels,
    /// `move_message`
    MoveMessage,
    /// `create_draft` (appends to Drafts with `$PendingReview`).
    CreateDraft,
    /// `send_email`
    SendEmail,
    /// `delete_message`
    DeleteMessage,
    /// `expunge`
    Expunge,
    /// `create_folder`
    CreateFolder,
    /// `rename_folder`
    RenameFolder,
    /// `delete_folder`
    DeleteFolder,
    /// `use_account` — switch the active account context.
    /// Bypasses posture/rate-limit checks.
    UseAccount,
    /// `list_accounts` — enumerate configured accounts.
    /// Bypasses posture/rate-limit checks.
    ListAccounts,
}

impl ToolName {
    /// Canonical snake-case name used in config overrides and audit log
    /// entries. Sub-capabilities reuse the parent tool name joined with a
    /// descriptive suffix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ListFolders => "list_folders",
            Self::Search => "search",
            Self::SearchAdvanced => "search.advanced_query",
            Self::FetchMessage => "fetch_message",
            Self::FetchMessageHtml => "fetch_message.include_html",
            Self::ListAttachments => "list_attachments",
            Self::DownloadAttachment => "download_attachment",
            Self::MarkRead => "mark_read",
            Self::MarkUnread => "mark_unread",
            Self::Flag => "flag",
            Self::Unflag => "unflag",
            Self::AddLabel => "add_label",
            Self::RemoveLabel => "remove_label",
            Self::ListLabels => "list_labels",
            Self::MoveMessage => "move_message",
            Self::CreateDraft => "create_draft",
            Self::SendEmail => "send_email",
            Self::DeleteMessage => "delete_message",
            Self::Expunge => "expunge",
            Self::CreateFolder => "create_folder",
            Self::RenameFolder => "rename_folder",
            Self::DeleteFolder => "delete_folder",
            Self::UseAccount => "use_account",
            Self::ListAccounts => "list_accounts",
        }
    }

    /// Every tool variant, in declaration order. Used for exhaustive matrix tests
    /// and for building the advertised-tools set in `list_tools`. Built from
    /// `EnumIter` so adding a new variant cannot silently desynchronize this
    /// list (compile-time parity).
    #[must_use]
    pub fn all() -> Vec<Self> {
        Self::iter().collect()
    }

    /// Whether this tool is an infrastructure tool that bypasses the
    /// posture matrix (not gated by posture, rate limits, or circuit
    /// breakers). Infrastructure tools are always available regardless
    /// of security posture.
    #[must_use]
    pub fn is_infrastructure(self) -> bool {
        matches!(self, Self::UseAccount | Self::ListAccounts)
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`ToolName::from_str`] when a name is not recognized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseToolNameError {
    /// The name is not a known tool.
    #[error("unknown tool name `{0}`")]
    Unknown(String),
}

impl FromStr for ToolName {
    type Err = ParseToolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for tool in Self::all() {
            if tool.as_str() == s {
                return Ok(tool);
            }
        }
        Err(ParseToolNameError::Unknown(s.to_string()))
    }
}

impl Serialize for ToolName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ToolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;
        Self::from_str(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::tool::{ParseToolNameError, ToolName};
    use core::str::FromStr;
    use strum::IntoEnumIterator;

    #[test]
    fn all_has_exactly_twenty_four_variants() {
        assert_eq!(ToolName::all().len(), 24);
        assert_eq!(ToolName::iter().count(), 24);
    }

    #[test]
    fn round_trip_all_tool_names() {
        for tool in ToolName::all() {
            let parsed = ToolName::from_str(tool.as_str()).unwrap();
            assert_eq!(parsed, tool);
        }
    }

    #[test]
    fn all_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in ToolName::all() {
            assert!(
                seen.insert(tool.as_str()),
                "duplicate name: {}",
                tool.as_str()
            );
        }
    }

    #[test]
    fn unknown_name_returns_unknown_error() {
        let err = ToolName::from_str("nuke_inbox").unwrap_err();
        assert_eq!(err, ParseToolNameError::Unknown("nuke_inbox".to_string()));
    }

    #[test]
    fn v2_tool_names_parse_as_real_variants() {
        assert_eq!(
            ToolName::from_str("send_email").unwrap(),
            ToolName::SendEmail
        );
        assert_eq!(
            ToolName::from_str("delete_message").unwrap(),
            ToolName::DeleteMessage
        );
        assert_eq!(ToolName::from_str("expunge").unwrap(), ToolName::Expunge);
        assert_eq!(
            ToolName::from_str("create_folder").unwrap(),
            ToolName::CreateFolder
        );
        assert_eq!(
            ToolName::from_str("rename_folder").unwrap(),
            ToolName::RenameFolder
        );
        assert_eq!(
            ToolName::from_str("delete_folder").unwrap(),
            ToolName::DeleteFolder
        );
    }

    #[test]
    fn display_uses_canonical_name() {
        assert_eq!(ToolName::Search.to_string(), "search");
        assert_eq!(
            ToolName::SearchAdvanced.to_string(),
            "search.advanced_query"
        );
    }
}
