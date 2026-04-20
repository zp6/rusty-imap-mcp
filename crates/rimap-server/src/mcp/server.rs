//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` owns an `AccountRegistry` (per-account IMAP/SMTP
//! connections, guards, and the attachment download sandbox) and an
//! audit writer. The `ServerHandler` trait wires `list_tools`
//! (posture-filtered union across accounts) and `call_tool` (account
//! resolution + dispatch pipeline).

use std::str::FromStr;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_audit::CancelledToolEndSender;
use rimap_audit::redact::RedactionSalt;
use rimap_core::account::AccountId;
use rimap_core::tool::ToolName;
use rmcp::RoleServer;
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ErrorCode as McpCode, ErrorData, Implementation,
    ListResourcesResult, ListToolsResult, PaginatedRequestParams, RawResource,
    ReadResourceRequestParams, ReadResourceResult, Resource, ResourceContents, ServerInfo, Tool,
};
use rmcp::service::RequestContext;

use crate::boot::registry::AccountRegistry;
use crate::mcp::dispatch::{PostureContext, rimap_error_to_breaker_reason};
use crate::mcp::tool_catalog::TOOL_DEFS;
use crate::mcp::tool_name::{
    is_bare_simple_tool_name, is_legacy_single_account, refine_tool_name, split_tool_name,
};

/// Core MCP server. Owns every resource the handler methods need.
pub struct ImapMcpServer {
    /// Account registry holding per-account state.
    #[doc(hidden)]
    pub registry: AccountRegistry,
    /// Append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Channel used by `AuditEnvelopeGuard::drop` to emit synthetic
    /// cancellation `tool_end` records when the MCP dispatch future is
    /// dropped mid-call (#71, #99).
    pub(crate) cancellation_sender: CancelledToolEndSender,
    /// Per-process salt used when applying `Redactor` to tool arguments.
    /// Wrapped in `Arc` so `spawn_blocking` closures can cheaply capture it.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
}

impl ImapMcpServer {
    /// Construct a new server. Builds the per-process redaction salt;
    /// per-tool schemas are dispatched on demand via
    /// [`rimap_audit::redact::ToolRedactionSchema::redaction_schema`].
    #[must_use]
    pub fn new(
        registry: AccountRegistry,
        audit: AuditWriter,
        cancellation_sender: CancelledToolEndSender,
    ) -> Self {
        Self {
            registry,
            audit,
            cancellation_sender,
            redaction_salt: Arc::new(RedactionSalt::new_random()),
        }
    }
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

        // Infrastructure tools — always advertised, never namespaced.
        for name in [ToolName::UseAccount, ToolName::ListAccounts] {
            if let Some(def) = TOOL_DEFS.get(&name) {
                tools.push(def.clone());
            }
        }

        let accounts = self.registry.accounts();
        let use_bare_names = is_legacy_single_account(accounts);

        for (id, state) in accounts {
            for &tn in &state.guard.matrix().advertised() {
                let Some(base_def) = TOOL_DEFS.get(&tn) else {
                    continue;
                };
                let tool_name = if use_bare_names {
                    base_def.name.clone()
                } else {
                    format!("{}.{}", id.as_str(), base_def.name).into()
                };
                let description = if use_bare_names {
                    base_def.description.clone()
                } else {
                    Some(
                        format!(
                            "[account: {}, posture: {}] {}",
                            id.as_str(),
                            state.guard.matrix().posture().as_str(),
                            base_def.description.as_deref().unwrap_or(""),
                        )
                        .into(),
                    )
                };
                let mut def = base_def.clone();
                def.name = tool_name;
                def.description = description;
                tools.push(def);
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
                    state.imap.username(),
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

        // Validate the account name before using it in a lookup or
        // echoing it back in any error. Do not reflect the raw input.
        AccountId::new(account_name).map_err(|_| {
            ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                "invalid account name in resource URI".to_string(),
                None,
            )
        })?;

        let state = self
            .registry
            .resolve(Some(account_name))
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))?;

        let available_tools: Vec<String> = state
            .guard
            .matrix()
            .advertised()
            .iter()
            .filter_map(|tn| TOOL_DEFS.get(tn).map(|d| d.name.to_string()))
            .collect();

        let metadata = serde_json::json!({
            "name": account_name,
            "imap_host": state.imap.host(),
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
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let (namespaced_account, bare_name) = split_tool_name(&request.name);

        let tool_name = ToolName::from_str(bare_name)
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
        // Refine the tool name based on argument shape BEFORE DispatchGuard::pre_dispatch
        // so the posture check covers sub-capabilities (FetchMessageHtml vs
        // FetchMessage, SearchAdvanced vs Search) at a single seam rather
        // than being re-checked inside every handler.
        let tool_name = refine_tool_name(tool_name, request.arguments.as_ref());

        // Reject tools that have no definition (not yet implemented).
        // This prevents unimplemented v2 tools from consuming rate
        // limiter tokens and producing misleading INTERNAL_ERROR.
        if TOOL_DEFS.get(&tool_name).is_none() {
            return Err(ErrorData::new(
                McpCode::RESOURCE_NOT_FOUND,
                format!("tool `{}` is not available", request.name),
                None,
            ));
        }

        // Multi-account contract: bare simple tool names are only valid
        // in legacy single-account mode. In multi-account mode, clients
        // must use the advertised <account>.<tool> form. Sub-capability
        // dotted tools (e.g. search.advanced_query) and infrastructure
        // tools (use_account, list_accounts) remain valid bare forms
        // regardless. (#73)
        let accounts = self.registry.accounts();
        if !is_legacy_single_account(accounts) && is_bare_simple_tool_name(&request.name) {
            return Err(ErrorData::invalid_params(
                format!(
                    "tool name must be namespaced in multi-account mode: \
                     <account>.{}",
                    &request.name,
                ),
                None,
            ));
        }

        let mut args = request.arguments.unwrap_or_default();

        // Infrastructure tools bypass account resolution and guards and
        // must never be namespaced.
        if tool_name.is_infrastructure() {
            if namespaced_account.is_some() {
                return Err(ErrorData::invalid_params(
                    "infrastructure tools cannot be namespaced".to_string(),
                    None,
                ));
            }
            let result = Box::pin(self.dispatch_infrastructure(tool_name, &args)).await;
            // After a successful use_account, notify subscribed clients that
            // the effective tool list has changed (the session default account
            // flipped). Best-effort: transport failures do not fail the call
            // because use_account itself succeeded. (#80)
            if result.is_ok()
                && tool_name == ToolName::UseAccount
                && let Err(e) = context.peer.notify_tool_list_changed().await
            {
                tracing::warn!(
                    error = %e,
                    "failed to emit notifications/tools/list_changed after use_account",
                );
            }
            return result;
        }

        // Account resolution order: URI namespace > args["account"] >
        // session default > auto-select.
        let explicit_account = namespaced_account.map(String::from).or_else(|| {
            args.remove("account")
                .and_then(|v| v.as_str().map(String::from))
        });

        let account = self
            .registry
            .resolve(explicit_account.as_deref())
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))?;

        // Compute the account field for audit records. Legacy single-account
        // `"default"` records `None`; multi-account records the account name.
        let audit_account: Option<String> =
            if account.id.as_str() == rimap_core::account::DEFAULT_ACCOUNT_NAME {
                None
            } else {
                Some(account.id.as_str().to_string())
            };
        let posture = PostureContext::Account(account.guard.matrix().posture());

        self.run_with_audit_envelope(tool_name, audit_account, posture, &args, async {
            account.guard.pre_dispatch(tool_name)?;
            let result = Box::pin(self.dispatch_tool(account, tool_name, &args)).await;
            match &result {
                Ok(_) => account.guard.on_success(),
                Err(e) => {
                    if let Some(reason) = rimap_error_to_breaker_reason(e) {
                        account.guard.on_failure(reason);
                    }
                }
            }
            result
        })
        .await
    }
}
