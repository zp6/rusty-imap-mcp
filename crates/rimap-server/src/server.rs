//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` holds the validated config, IMAP connection, authz
//! guard, audit writer, and download directory. The `ServerHandler`
//! trait wires `list_tools` (posture-filtered) and `call_tool`
//! (dispatch pipeline + placeholder handlers).

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_authz::DispatchGuard;
use rimap_authz::breaker::SystemClock;
use rimap_config::validate::ValidatedConfig;
use rimap_core::tool::ToolName;
use rimap_imap::Connection;
use rmcp::RoleServer;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorData, Implementation, ListToolsResult,
    PaginatedRequestParams, ServerInfo, Tool,
};
use rmcp::service::RequestContext;

/// Core MCP server. Owns every resource the handler methods need.
#[expect(dead_code, reason = "fields used by tool handlers in later tasks")]
pub struct ImapMcpServer {
    /// Validated configuration snapshot.
    pub(crate) config: ValidatedConfig,
    /// Lazy-connect IMAP connection handle.
    pub(crate) imap: Connection,
    /// Posture + circuit breaker + rate limiter guard.
    pub(crate) guard: DispatchGuard<SystemClock>,
    /// Append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Directory for attachment downloads.
    pub(crate) download_dir: PathBuf,
}

impl ServerHandler for ImapMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::default().with_server_info(Implementation::new(
            "rusty-imap-mcp",
            env!("CARGO_PKG_VERSION"),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let allowed = self.guard.matrix().advertised();
        let tools: Vec<Tool> = allowed
            .iter()
            .filter_map(|&tn| tool_definition(tn))
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name = ToolName::from_str(&request.name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        if let Err(e) = crate::dispatch::pre_call_guards(&self.guard, tool_name) {
            return Err(crate::mcp_error::to_mcp_error(&e));
        }

        let result = dispatch_tool(tool_name);

        match result {
            Ok(resp) => {
                let value = serde_json::to_value(&resp)
                    .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
                Ok(CallToolResult::structured(value))
            }
            Err(e) => Err(crate::mcp_error::to_mcp_error(&e)),
        }
    }
}

/// Dispatch to the tool handler for `tool`. All arms return a
/// placeholder until real handlers land in later tasks.
///
/// The `Result` return and per-arm match structure are intentional:
/// each arm will be replaced with a real handler that can fail.
#[expect(
    clippy::unnecessary_wraps,
    reason = "real handlers will return Err; scaffolding"
)]
#[expect(
    clippy::match_same_arms,
    reason = "each arm will diverge when handlers land"
)]
fn dispatch_tool(tool: ToolName) -> Result<crate::response::ToolResponse, rimap_core::RimapError> {
    let placeholder = || crate::response::ToolResponse {
        meta: serde_json::json!({"status": "not_implemented"}),
        untrusted: None,
        security_warnings: Vec::new(),
    };

    match tool {
        ToolName::ListFolders => Ok(placeholder()),
        ToolName::Search => Ok(placeholder()),
        ToolName::SearchAdvanced => Ok(placeholder()),
        ToolName::FetchMessage => Ok(placeholder()),
        ToolName::FetchMessageHtml => Ok(placeholder()),
        ToolName::ListAttachments => Ok(placeholder()),
        ToolName::DownloadAttachment => Ok(placeholder()),
        ToolName::MarkRead => Ok(placeholder()),
        ToolName::MarkUnread => Ok(placeholder()),
        ToolName::Flag => Ok(placeholder()),
        ToolName::Unflag => Ok(placeholder()),
        ToolName::MoveMessage => Ok(placeholder()),
        ToolName::CreateDraft => Ok(placeholder()),
    }
}

/// Build an rmcp `Tool` definition for a `ToolName`. Returns `None`
/// for sub-capabilities that share an MCP tool name with a parent
/// (e.g. `SearchAdvanced` and `FetchMessageHtml` are gated
/// sub-capabilities, not separate MCP tools).
fn tool_definition(name: ToolName) -> Option<Tool> {
    let (tool_name, description): (&str, &str) = match name {
        ToolName::ListFolders => ("list_folders", "List all IMAP folders"),
        ToolName::Search => ("search", "Search messages with structured query"),
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
        ToolName::FetchMessage => ("fetch_message", "Fetch message metadata and text body"),
        ToolName::ListAttachments => ("list_attachments", "List attachments on a message"),
        ToolName::DownloadAttachment => (
            "download_attachment",
            "Download an attachment to the sandbox directory",
        ),
        ToolName::MarkRead => ("mark_read", "Mark messages as read"),
        ToolName::MarkUnread => ("mark_unread", "Mark messages as unread"),
        ToolName::Flag => ("flag", "Add the flagged flag to messages"),
        ToolName::Unflag => ("unflag", "Remove the flagged flag from messages"),
        ToolName::MoveMessage => ("move_message", "Move messages to another folder"),
        ToolName::CreateDraft => (
            "create_draft",
            "Create a draft email with $PendingReview flag",
        ),
    };

    Some(Tool::new(
        tool_name,
        description,
        Arc::new(serde_json::Map::new()),
    ))
}

#[cfg(test)]
mod tests {
    use rimap_core::tool::ToolName;

    use super::tool_definition;

    #[test]
    fn tool_definition_covers_all_mcp_tools() {
        let defs: Vec<_> = ToolName::all()
            .into_iter()
            .filter_map(tool_definition)
            .collect();
        // 13 capabilities minus 2 sub-capabilities = 11 MCP tools
        assert_eq!(defs.len(), 11);
    }

    #[test]
    fn sub_capabilities_return_none() {
        assert!(tool_definition(ToolName::SearchAdvanced).is_none());
        assert!(tool_definition(ToolName::FetchMessageHtml).is_none());
    }

    #[test]
    fn tool_names_are_snake_case() {
        for def in ToolName::all().into_iter().filter_map(tool_definition) {
            assert!(
                def.name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "tool name {} is not snake_case",
                def.name,
            );
        }
    }

    #[test]
    fn every_tool_has_a_description() {
        for def in ToolName::all().into_iter().filter_map(tool_definition) {
            assert!(
                def.description.is_some(),
                "tool {} missing description",
                def.name,
            );
        }
    }
}
