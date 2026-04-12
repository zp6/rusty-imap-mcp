//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` holds the validated config, IMAP connection, authz
//! guard, audit writer, and download directory. The `ServerHandler`
//! trait wires `list_tools` (posture-filtered) and `call_tool`
//! (dispatch pipeline).

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
#[expect(
    dead_code,
    reason = "config/audit/download_dir used by tool handlers in later tasks"
)]
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

        let args = request.arguments.unwrap_or_default();
        let result = Box::pin(self.dispatch_tool(tool_name, &args)).await;

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

impl ImapMcpServer {
    /// Dispatch to the tool handler for `tool`.
    pub(crate) async fn dispatch_tool(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<crate::response::ToolResponse, rimap_core::RimapError> {
        match tool {
            ToolName::ListFolders => Box::pin(crate::tools::list_folders::handle(self)).await,
            ToolName::MarkRead => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::flags::handle_mark_read(self, input)).await
            }
            ToolName::MarkUnread => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::flags::handle_mark_unread(self, input)).await
            }
            ToolName::Flag => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::flags::handle_flag(self, input)).await
            }
            ToolName::Unflag => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::flags::handle_unflag(self, input)).await
            }
            ToolName::MoveMessage => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::move_message::handle(self, input)).await
            }
            ToolName::Search | ToolName::SearchAdvanced => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::search::handle(self, input)).await
            }
            ToolName::FetchMessage | ToolName::FetchMessageHtml => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::fetch_message::handle(self, input)).await
            }
            ToolName::ListAttachments => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::list_attachments::handle(self, input)).await
            }
            ToolName::DownloadAttachment => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::download_attachment::handle(self, input)).await
            }
            ToolName::CreateDraft => {
                let input = parse_args(args)?;
                Box::pin(crate::tools::create_draft::handle(self, input)).await
            }
        }
    }
}

/// Deserialize tool arguments into a typed input struct.
fn parse_args<T: serde::de::DeserializeOwned>(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<T, rimap_core::RimapError> {
    serde_json::from_value(serde_json::Value::Object(args.clone()))
        .map_err(|e| rimap_core::RimapError::Internal(format!("invalid arguments: {e}")))
}

/// Convert a `schemars::JsonSchema` type into a JSON object map
/// suitable for an MCP tool's `inputSchema`.
fn schema_map<T: schemars::JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
    let schema = schemars::schema_for!(T);
    match serde_json::to_value(schema) {
        Ok(serde_json::Value::Object(mut map)) => {
            // Strip Rust struct name to avoid leaking implementation
            // details in the MCP list_tools response.
            map.remove("title");
            map
        }
        _ => serde_json::Map::new(),
    }
}

/// Build an rmcp `Tool` definition for a `ToolName`. Returns `None`
/// for sub-capabilities that share an MCP tool name with a parent
/// (e.g. `SearchAdvanced` and `FetchMessageHtml` are gated
/// sub-capabilities, not separate MCP tools).
fn tool_definition(name: ToolName) -> Option<Tool> {
    use crate::tools::{
        create_draft::CreateDraftInput, download_attachment::DownloadAttachmentInput,
        fetch_message::FetchMessageInput, flags::FlagInput, list_attachments::ListAttachmentsInput,
        move_message::MoveInput, search::SearchInput,
    };

    let (tool_name, description, schema): (&str, &str, serde_json::Map<_, _>) = match name {
        ToolName::ListFolders => (
            "list_folders",
            "List all IMAP folders",
            serde_json::Map::new(),
        ),
        ToolName::Search => (
            "search",
            "Search messages with structured query",
            schema_map::<SearchInput>(),
        ),
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
        ToolName::FetchMessage => (
            "fetch_message",
            "Fetch message metadata and text body",
            schema_map::<FetchMessageInput>(),
        ),
        ToolName::ListAttachments => (
            "list_attachments",
            "List attachments on a message",
            schema_map::<ListAttachmentsInput>(),
        ),
        ToolName::DownloadAttachment => (
            "download_attachment",
            "Download an attachment to the sandbox directory",
            schema_map::<DownloadAttachmentInput>(),
        ),
        ToolName::MarkRead => (
            "mark_read",
            "Mark messages as read",
            schema_map::<FlagInput>(),
        ),
        ToolName::MarkUnread => (
            "mark_unread",
            "Mark messages as unread",
            schema_map::<FlagInput>(),
        ),
        ToolName::Flag => (
            "flag",
            "Add the flagged flag to messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::Unflag => (
            "unflag",
            "Remove the flagged flag from messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::MoveMessage => (
            "move_message",
            "Move messages to another folder",
            schema_map::<MoveInput>(),
        ),
        ToolName::CreateDraft => (
            "create_draft",
            "Create a draft email with $PendingReview flag",
            schema_map::<CreateDraftInput>(),
        ),
    };

    Some(Tool::new(tool_name, description, Arc::new(schema)))
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
    fn tool_definitions_have_non_empty_schemas() {
        for def in ToolName::all().into_iter().filter_map(tool_definition) {
            // list_folders has no input — empty schema is expected.
            if def.name == "list_folders" {
                continue;
            }
            let schema = &def.input_schema;
            assert!(
                !schema.is_empty(),
                "tool {} has empty input schema",
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
