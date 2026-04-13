//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` owns an `AccountRegistry` (per-account IMAP/SMTP
//! connections, guards), an audit writer, and the download directory.
//! The `ServerHandler` trait wires `list_tools` (posture-filtered
//! union across accounts) and `call_tool` (account resolution +
//! dispatch pipeline).

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_core::tool::ToolName;
use rmcp::RoleServer;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorCode as McpCode, ErrorData, Implementation,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, RawResource,
    ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, ServerInfo, Tool,
};
use rmcp::service::RequestContext;

use crate::registry::{AccountRegistry, AccountState};

/// Core MCP server. Owns every resource the handler methods need.
pub struct ImapMcpServer {
    /// Account registry holding per-account state.
    pub(crate) registry: AccountRegistry,
    /// Append-only audit writer.
    #[expect(dead_code, reason = "used by audit logging in later sprint")]
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
        let mut tools: Vec<Tool> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Infrastructure tools — always advertised.
        for name in [ToolName::UseAccount, ToolName::ListAccounts] {
            if let Some(def) = tool_definition(name) {
                seen.insert(name);
                tools.push(def);
            }
        }

        // Union of posture-filtered tools from all accounts.
        for state in self.registry.accounts().values() {
            for &tn in &state.guard.matrix().advertised() {
                if seen.insert(tn)
                    && let Some(def) = tool_definition(tn)
                {
                    tools.push(def);
                }
            }
        }

        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources: Vec<Resource> = self
            .registry
            .accounts()
            .values()
            .map(|state| {
                let name = state.id.as_str();
                let desc = format!(
                    "IMAP account: {} on {}",
                    state.from_address,
                    state.imap.host(),
                );
                Resource {
                    raw: RawResource::new(format!("rimap://accounts/{name}"), name)
                        .with_description(desc)
                        .with_mime_type("application/json"),
                    annotations: None,
                }
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let uri = &request.uri;
        let account_name = uri.strip_prefix("rimap://accounts/").ok_or_else(|| {
            ErrorData::new(
                McpCode::INVALID_PARAMS,
                format!("unsupported resource URI: {uri}"),
                None,
            )
        })?;

        let state = self
            .registry
            .resolve(Some(account_name))
            .map_err(|e| crate::mcp_error::to_mcp_error(&e))?;

        let available_tools: Vec<String> = state
            .guard
            .matrix()
            .advertised()
            .iter()
            .filter_map(|tn| tool_definition(*tn).map(|d| d.name.to_string()))
            .collect();

        let metadata = serde_json::json!({
            "name": account_name,
            "imap_host": state.imap.host(),
            "posture": state.guard.matrix().posture().as_str(),
            "smtp_configured": state.smtp.is_some(),
            "available_tools": available_tools,
        });

        let text = serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        let contents =
            ResourceContents::text(text, uri.as_str()).with_mime_type("application/json");

        Ok(ReadResourceResult::new(vec![contents]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name = ToolName::from_str(&request.name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

        // Reject tools that have no definition (not yet implemented).
        // This prevents unimplemented v2 tools from consuming rate
        // limiter tokens and producing misleading INTERNAL_ERROR.
        if tool_definition(tool_name).is_none() {
            return Err(ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                format!("tool `{}` is not available", request.name),
                None,
            ));
        }

        let mut args = request.arguments.unwrap_or_default();

        // Infrastructure tools bypass account resolution and guards.
        if matches!(tool_name, ToolName::UseAccount | ToolName::ListAccounts) {
            return self.dispatch_infrastructure(tool_name, &args);
        }

        // Extract and strip the optional "account" key.
        let account_name = args
            .remove("account")
            .and_then(|v| v.as_str().map(String::from));

        let account = self
            .registry
            .resolve(account_name.as_deref())
            .map_err(|e| crate::mcp_error::to_mcp_error(&e))?;

        if let Err(e) = crate::dispatch::pre_call_guards(&account.guard, tool_name) {
            return Err(crate::mcp_error::to_mcp_error(&e));
        }

        let result = Box::pin(self.dispatch_tool(account, tool_name, &args)).await;

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
        account: &AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<crate::response::ToolResponse, rimap_core::RimapError> {
        use crate::tools::{
            create_draft, delete_message, download_attachment, expunge, fetch_message, flags,
            folder_mgmt, labels, list_attachments, list_folders, move_message, search, send_email,
        };
        match tool {
            ToolName::ListFolders => Box::pin(list_folders::handle(account)).await,
            ToolName::MarkRead => {
                Box::pin(flags::handle_mark_read(account, parse_args(args)?)).await
            }
            ToolName::MarkUnread => {
                Box::pin(flags::handle_mark_unread(account, parse_args(args)?)).await
            }
            ToolName::Flag => Box::pin(flags::handle_flag(account, parse_args(args)?)).await,
            ToolName::Unflag => Box::pin(flags::handle_unflag(account, parse_args(args)?)).await,
            ToolName::MoveMessage => {
                Box::pin(move_message::handle(account, parse_args(args)?)).await
            }
            ToolName::Search | ToolName::SearchAdvanced => {
                Box::pin(search::handle(account, parse_args(args)?)).await
            }
            ToolName::FetchMessage | ToolName::FetchMessageHtml => {
                Box::pin(fetch_message::handle(account, parse_args(args)?)).await
            }
            ToolName::ListAttachments => {
                Box::pin(list_attachments::handle(account, parse_args(args)?)).await
            }
            ToolName::DownloadAttachment => {
                let input = parse_args(args)?;
                Box::pin(download_attachment::handle(
                    account,
                    input,
                    &self.download_dir,
                ))
                .await
            }
            ToolName::CreateDraft => {
                Box::pin(create_draft::handle(account, parse_args(args)?)).await
            }
            ToolName::SendEmail => Box::pin(send_email::handle(account, parse_args(args)?)).await,
            ToolName::DeleteMessage => {
                Box::pin(delete_message::handle(account, parse_args(args)?)).await
            }
            ToolName::Expunge => Box::pin(expunge::handle(account, parse_args(args)?)).await,
            ToolName::CreateFolder => {
                Box::pin(folder_mgmt::handle_create(account, parse_args(args)?)).await
            }
            ToolName::RenameFolder => {
                Box::pin(folder_mgmt::handle_rename(account, parse_args(args)?)).await
            }
            ToolName::DeleteFolder => {
                Box::pin(folder_mgmt::handle_delete(account, parse_args(args)?)).await
            }
            ToolName::AddLabel => {
                Box::pin(labels::handle_add_label(account, parse_args(args)?)).await
            }
            ToolName::RemoveLabel => {
                Box::pin(labels::handle_remove_label(account, parse_args(args)?)).await
            }
            ToolName::ListLabels => {
                Box::pin(labels::handle_list_labels(account, parse_args(args)?)).await
            }
            ToolName::UseAccount | ToolName::ListAccounts => Err(rimap_core::RimapError::Internal(
                "infrastructure tools must not reach dispatch_tool".into(),
            )),
        }
    }

    /// Handle infrastructure tools that bypass account resolution.
    fn dispatch_infrastructure(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        let result = match tool {
            ToolName::UseAccount => {
                let input: crate::tools::accounts::UseAccountInput =
                    parse_args(args).map_err(|e| crate::mcp_error::to_mcp_error(&e))?;
                crate::tools::accounts::handle_use_account(&self.registry, &input)
            }
            ToolName::ListAccounts => crate::tools::accounts::handle_list_accounts(&self.registry),
            _ => {
                return Err(ErrorData::internal_error(
                    format!("not an infrastructure tool: {}", tool.as_str(),),
                    None,
                ));
            }
        };
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
    let (tool_name, description, schema) = tool_spec_v1(name)
        .or_else(|| tool_spec_v2(name))
        .or_else(|| tool_spec_v3(name))
        .or_else(|| tool_spec_infra(name))?;
    Some(Tool::new(tool_name, description, Arc::new(schema)))
}

/// Type alias for tool spec tuples.
type ToolSpec = (
    &'static str,
    &'static str,
    serde_json::Map<String, serde_json::Value>,
);

/// Return (name, description, schema) for v1 read/organize tools.
fn tool_spec_v1(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::{
        create_draft::CreateDraftInput, download_attachment::DownloadAttachmentInput,
        fetch_message::FetchMessageInput, flags::FlagInput, list_attachments::ListAttachmentsInput,
        move_message::MoveInput, search::SearchInput,
    };

    let tuple = match name {
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
        _ => return None,
    };
    Some(tuple)
}

/// Return (name, description, schema) for v2 write/management tools.
fn tool_spec_v2(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::{
        delete_message::DeleteMessageInput,
        expunge::ExpungeInput,
        folder_mgmt::{CreateFolderInput, DeleteFolderInput, RenameFolderInput},
        send_email::SendEmailInput,
    };

    let tuple = match name {
        ToolName::SendEmail => (
            "send_email",
            "Send an email via SMTP",
            schema_map::<SendEmailInput>(),
        ),
        ToolName::DeleteMessage => (
            "delete_message",
            "Delete a message (move to Trash)",
            schema_map::<DeleteMessageInput>(),
        ),
        ToolName::Expunge => (
            "expunge",
            "Permanently remove deleted messages from a folder",
            schema_map::<ExpungeInput>(),
        ),
        ToolName::CreateFolder => (
            "create_folder",
            "Create a new IMAP folder",
            schema_map::<CreateFolderInput>(),
        ),
        ToolName::RenameFolder => (
            "rename_folder",
            "Rename an IMAP folder",
            schema_map::<RenameFolderInput>(),
        ),
        ToolName::DeleteFolder => (
            "delete_folder",
            "Delete an IMAP folder and all its contents",
            schema_map::<DeleteFolderInput>(),
        ),
        _ => return None,
    };
    Some(tuple)
}

/// Return (name, description, schema) for v3 label tools.
fn tool_spec_v3(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::labels::{LabelInput, ListLabelsInput};

    let tuple = match name {
        ToolName::AddLabel => (
            "add_label",
            "Add a keyword label to messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::RemoveLabel => (
            "remove_label",
            "Remove a keyword label from messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::ListLabels => (
            "list_labels",
            "List keyword labels on a message",
            schema_map::<ListLabelsInput>(),
        ),
        _ => return None,
    };
    Some(tuple)
}

/// Return (name, description, schema) for infrastructure tools.
fn tool_spec_infra(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::accounts::UseAccountInput;

    let tuple = match name {
        ToolName::UseAccount => (
            "use_account",
            "Set the active account for subsequent tool calls",
            schema_map::<UseAccountInput>(),
        ),
        ToolName::ListAccounts => (
            "list_accounts",
            "List all configured email accounts",
            serde_json::Map::new(),
        ),
        _ => return None,
    };
    Some(tuple)
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
        // 24 tool variants minus 2 sub-capabilities = 22
        assert_eq!(defs.len(), 22);
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
            // list_folders and list_accounts have no input — empty
            // schema is expected.
            if def.name == "list_folders" || def.name == "list_accounts" {
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
