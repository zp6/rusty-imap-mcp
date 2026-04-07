//! Tool identity. Models the v1 tool surface at *capability* granularity so
//! the posture matrix can gate sub-features (`search.advanced_query`,
//! `fetch_message.include_html`) independently of the parent tool.

use core::fmt;
use core::str::FromStr;

use thiserror::Error;

/// Identifier for a dispatchable capability. This is a superset of the MCP
/// tool names because some MCP tools expose multiple gated capabilities
/// (e.g. `search` and `search_advanced`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    /// `move_message`
    MoveMessage,
    /// `create_draft` (appends to Drafts with `$PendingReview`).
    CreateDraft,
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
            Self::MoveMessage => "move_message",
            Self::CreateDraft => "create_draft",
        }
    }

    /// Every v1 tool, in declaration order. Used for exhaustive matrix tests
    /// and for building the advertised-tools set in `list_tools`.
    #[must_use]
    pub fn all() -> [Self; 13] {
        [
            Self::ListFolders,
            Self::Search,
            Self::SearchAdvanced,
            Self::FetchMessage,
            Self::FetchMessageHtml,
            Self::ListAttachments,
            Self::DownloadAttachment,
            Self::MarkRead,
            Self::MarkUnread,
            Self::Flag,
            Self::Unflag,
            Self::MoveMessage,
            Self::CreateDraft,
        ]
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Known v2 tool names. These are rejected at config load with a distinct
/// error so users get "this is a v2 tool, not yet available" instead of
/// "unknown tool".
const V2_TOOL_NAMES: &[&str] = &["delete_message", "expunge", "send_email"];

/// Error returned by [`ToolName::from_str`] when a name is not recognized.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseToolNameError {
    /// The name is not a v1 tool and not a known v2 tool.
    #[error("unknown tool name `{0}`")]
    Unknown(String),
    /// The name refers to a v2 tool not available in v1.
    #[error("tool `{0}` is reserved for v2 and cannot be used in configuration")]
    V2(String),
}

impl FromStr for ToolName {
    type Err = ParseToolNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for tool in Self::all() {
            if tool.as_str() == s {
                return Ok(tool);
            }
        }
        if V2_TOOL_NAMES.contains(&s) {
            return Err(ParseToolNameError::V2(s.to_string()));
        }
        Err(ParseToolNameError::Unknown(s.to_string()))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::tool::{ParseToolNameError, ToolName};
    use core::str::FromStr;

    #[test]
    fn all_has_exactly_thirteen_variants() {
        assert_eq!(ToolName::all().len(), 13);
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
    fn v2_tool_names_return_v2_error() {
        for name in ["delete_message", "expunge", "send_email"] {
            let err = ToolName::from_str(name).unwrap_err();
            assert_eq!(err, ParseToolNameError::V2(name.to_string()));
        }
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
