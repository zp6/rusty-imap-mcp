//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` owns an `Arc<DaemonState>` (shared across all sessions),
//! an `Arc<SessionState>` (per-connection), and a `SessionAuditSink` that
//! automatically injects the session id into every audit record. The
//! `ServerHandler` trait wires `list_tools` (posture-filtered union across
//! accounts) and `call_tool` (account resolution + dispatch pipeline).

use std::str::FromStr;
use std::sync::Arc;

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

use crate::boot::registry::{AccountRegistry, AccountState};
use crate::daemon::audit_sink::SessionAuditSink;
use crate::daemon::state::{DaemonState, SessionState};
use crate::mcp::dispatch::{PostureContext, rimap_error_to_breaker_reason};
use crate::mcp::tool_catalog::TOOL_DEFS;
use crate::mcp::tool_name::{
    is_bare_simple_tool_name, is_legacy_single_account, refine_tool_name, split_tool_name,
};

/// Core MCP server. One instance per client connection.
pub struct ImapMcpServer {
    /// Shared daemon state. Cloned cheaply into every session.
    pub(crate) state: Arc<DaemonState>,
    /// This connection's session state.
    pub(crate) session: Arc<SessionState>,
    /// Session-scoped audit sink — guarantees `session_id` injection.
    pub(crate) audit: SessionAuditSink,
}

impl ImapMcpServer {
    /// Construct a per-session server. Per-tool schemas are dispatched on
    /// demand via [`rimap_audit::redact::ToolRedactionSchema::redaction_schema`];
    /// the per-process redaction salt lives on [`DaemonState`] and is shared
    /// across every session.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, session: Arc<SessionState>) -> Self {
        let audit = SessionAuditSink::new(state.audit.clone(), session.id);
        Self {
            state,
            session,
            audit,
        }
    }

    /// Convenience accessor for the account registry stored in shared state.
    #[must_use]
    pub fn registry(&self) -> &AccountRegistry {
        &self.state.registry
    }

    /// Run an account-scoped tool through the full dispatch pipeline:
    /// posture header + breaker / rate-limit guard + audit envelope +
    /// handler. Returns the MCP-shaped `CallToolResult`.
    ///
    /// Single source of truth for the account-scoped dispatch
    /// composition. Used by the real [`ServerHandler::call_tool`] trait
    /// method and by `execute_tool_for_test`, so the two paths cannot
    /// drift.
    pub(crate) async fn dispatch_account_scoped(
        &self,
        account: &AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
        arguments_redacted: serde_json::Value,
        arguments_hash_sha256: String,
    ) -> Result<CallToolResult, ErrorData> {
        // Legacy single-account `"default"` records `None`; multi-account
        // records the account name.
        let audit_account: Option<String> =
            if account.id.as_str() == rimap_core::account::DEFAULT_ACCOUNT_NAME {
                None
            } else {
                Some(account.id.as_str().to_string())
            };
        let posture = PostureContext::Account(account.guard.matrix().posture());

        self.run_with_audit_envelope(
            tool,
            audit_account,
            posture,
            arguments_redacted,
            arguments_hash_sha256,
            |ticket| async move {
                account.guard.pre_dispatch(tool)?;
                let result = Box::pin(self.dispatch_tool(ticket, account, tool, args)).await;
                match &result {
                    Ok(_) => account.guard.on_success(),
                    Err(e) => {
                        if let Some(reason) = rimap_error_to_breaker_reason(e) {
                            account.guard.on_failure(reason);
                        }
                    }
                }
                result
            },
        )
        .await
    }
}

/// Integration-test entry point. Exposed under `#[cfg(any(test, feature =
/// "test-support"))]` so tests exercise the exact same pipeline (account
/// resolve → `pre_dispatch` → audit envelope → `dispatch_tool`) as real
/// MCP clients, instead of re-implementing the composition and drifting
/// from the production path. Production builds without the feature
/// cannot see this method, and `dispatch_tool` itself is `pub(crate)`.
#[cfg(any(test, feature = "test-support"))]
impl ImapMcpServer {
    /// Execute `tool` through the full dispatch pipeline. Mirrors
    /// [`ServerHandler::call_tool`] but takes a pre-parsed `ToolName`
    /// and a raw JSON args value; returns the handler's JSON body
    /// (the `structured_content` of the MCP `CallToolResult`).
    ///
    /// # Errors
    ///
    /// Any pipeline failure — unknown account, posture denial, rate
    /// limit, breaker open, handler error — is returned as a
    /// [`rimap_core::RimapError`] (the MCP `ErrorData` shape is
    /// bridged back).
    pub async fn execute_tool_for_test(
        &self,
        account_name: Option<&str>,
        tool: ToolName,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, rimap_core::RimapError> {
        if account_name.is_some() && tool.is_infrastructure() {
            return Err(rimap_core::RimapError::invalid_input(
                "execute_tool_for_test: account_name must be None for infrastructure tools",
            ));
        }

        let args_map = match args {
            serde_json::Value::Object(m) => m,
            serde_json::Value::Null => serde_json::Map::new(),
            other => {
                return Err(rimap_core::RimapError::invalid_input(format!(
                    "execute_tool_for_test expects a JSON object or null, got {other}"
                )));
            }
        };

        // Compute the args hash BEFORE any consumer mutates `args_map`
        // (e.g. the production `resolve_account_for_call` removing
        // `"account"`) so the recorded hash matches the on-wire request.
        // See review finding MCP-INJ-02.
        let (arguments_redacted, arguments_hash_sha256) =
            self.compute_tool_args_artifacts(tool, &args_map);

        let call_tool_result = if tool.is_infrastructure() {
            Box::pin(self.dispatch_infrastructure(
                tool,
                &args_map,
                arguments_redacted,
                arguments_hash_sha256,
            ))
            .await
            .map_err(|e| error_data_to_rimap_error(&e))?
        } else {
            let account = self.registry().resolve(account_name)?;
            Box::pin(self.dispatch_account_scoped(
                account,
                tool,
                &args_map,
                arguments_redacted,
                arguments_hash_sha256,
            ))
            .await
            .map_err(|e| error_data_to_rimap_error(&e))?
        };

        Ok(extract_json_from_call_tool_result(call_tool_result))
    }

    /// Drive `run_with_audit_envelope` with a caller-supplied async
    /// factory. The factory receives no ticket (infrastructure posture,
    /// no account) and returns a future that can suspend at will.
    ///
    /// Used in integration tests that need a body that actually yields
    /// at an `.await` point — e.g. to verify the `AuditEnvelopeGuard`
    /// fires when the dispatch future is aborted mid-body. Real tool
    /// handlers complete synchronously so the abort never lands mid-body;
    /// this method lets the test inject a never-resolving body instead.
    pub async fn run_envelope_with_body_for_test<Fut>(
        &self,
        tool: ToolName,
        body_fut: Fut,
    ) -> Result<CallToolResult, ErrorData>
    where
        Fut: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        debug_assert!(
            tool.is_infrastructure(),
            "run_envelope_with_body_for_test only supports infrastructure tools; \
             use execute_tool_for_test for account-scoped tools"
        );
        let args = serde_json::Map::new();
        let (arguments_redacted, arguments_hash_sha256) =
            self.compute_tool_args_artifacts(tool, &args);
        self.run_with_audit_envelope(
            tool,
            None,
            crate::mcp::dispatch::PostureContext::Infrastructure,
            arguments_redacted,
            arguments_hash_sha256,
            |_ticket| body_fut,
        )
        .await
    }
}

/// Extract the structured JSON body from a [`CallToolResult`]. Prefers
/// the `structured_content` field (populated by `CallToolResult::structured`),
/// falling back to parsing the first text content item. Returns
/// `serde_json::Value::Null` when neither is available.
#[cfg(any(test, feature = "test-support"))]
fn extract_json_from_call_tool_result(result: CallToolResult) -> serde_json::Value {
    if let Some(value) = result.structured_content {
        return value;
    }
    result
        .content
        .into_iter()
        .next()
        .and_then(|content| content.as_text().map(|t| t.text.clone()))
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(serde_json::Value::Null)
}

/// Bridge an MCP `ErrorData` back to a `RimapError` for the test
/// helper's uniform `Result<_, RimapError>` surface. The original
/// message is preserved; the JSON-RPC / MCP code is surfaced as a
/// prefix so test assertions can still match on it.
#[cfg(any(test, feature = "test-support"))]
fn error_data_to_rimap_error(err: &ErrorData) -> rimap_core::RimapError {
    rimap_core::RimapError::Internal(format!("mcp error {}: {}", err.code.0, err.message))
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

        let accounts = self.registry().accounts();
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
            .registry()
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
            .registry()
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
        let (namespaced_account, tool_name) = parse_and_validate_tool_name(&request)?;

        // Multi-account contract: bare simple tool names are only valid
        // in legacy single-account mode. In multi-account mode, clients
        // must use the advertised <account>.<tool> form. Sub-capability
        // dotted tools (e.g. search.advanced_query) and infrastructure
        // tools (use_account, list_accounts) remain valid bare forms
        // regardless.
        let accounts = self.registry().accounts();
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

        // Compute the args hash BEFORE `resolve_account_for_call` removes
        // `"account"` so the audit record's hash matches the on-wire
        // JSON-RPC request. See review finding MCP-INJ-02.
        let (arguments_redacted, arguments_hash_sha256) =
            self.compute_tool_args_artifacts(tool_name, &args);

        if tool_name.is_infrastructure() {
            return self
                .route_infrastructure(
                    tool_name,
                    namespaced_account.as_deref(),
                    &args,
                    arguments_redacted,
                    arguments_hash_sha256,
                    &context,
                )
                .await;
        }

        let account = self.resolve_account_for_call(namespaced_account.as_deref(), &mut args)?;

        self.dispatch_account_scoped(
            account,
            tool_name,
            &args,
            arguments_redacted,
            arguments_hash_sha256,
        )
        .await
    }
}

/// Parse the incoming tool name, refine it by argument shape, and verify
/// it has a definition. Returns the namespaced-account prefix (owned so
/// the caller can continue to move `request.arguments`) and the refined
/// `ToolName`.
fn parse_and_validate_tool_name(
    request: &CallToolRequestParams,
) -> Result<(Option<String>, ToolName), ErrorData> {
    let (namespaced_account, bare_name) = split_tool_name(&request.name);
    let namespaced_account = namespaced_account.map(String::from);
    let tool_name = ToolName::from_str(bare_name)
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    // Refine the tool name based on argument shape BEFORE DispatchGuard::pre_dispatch
    // so the posture check covers sub-capabilities (FetchMessageHtml vs
    // FetchMessage, SearchAdvanced vs Search) at a single seam rather
    // than being re-checked inside every handler.
    let tool_name = refine_tool_name(tool_name, request.arguments.as_ref());
    // Reject tools that have no definition (not yet implemented). This
    // prevents unimplemented v2 tools from consuming rate limiter tokens
    // and producing misleading INTERNAL_ERROR.
    if TOOL_DEFS.get(&tool_name).is_none() {
        return Err(ErrorData::new(
            McpCode::RESOURCE_NOT_FOUND,
            format!("tool `{}` is not available", request.name),
            None,
        ));
    }
    Ok((namespaced_account, tool_name))
}

impl ImapMcpServer {
    /// Dispatch an infrastructure tool (`use_account`, `list_accounts`).
    /// Rejects namespaced calls (infrastructure tools have no account
    /// scope). After a successful `use_account`, emits a best-effort
    /// `notifications/tools/list_changed`.
    async fn route_infrastructure(
        &self,
        tool_name: ToolName,
        namespaced_account: Option<&str>,
        args: &serde_json::Map<String, serde_json::Value>,
        arguments_redacted: serde_json::Value,
        arguments_hash_sha256: String,
        context: &RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if namespaced_account.is_some() {
            return Err(ErrorData::invalid_params(
                "infrastructure tools cannot be namespaced".to_string(),
                None,
            ));
        }
        let result = Box::pin(self.dispatch_infrastructure(
            tool_name,
            args,
            arguments_redacted,
            arguments_hash_sha256,
        ))
        .await;
        if result.is_ok()
            && tool_name == ToolName::UseAccount
            && let Err(e) = context.peer.notify_tool_list_changed().await
        {
            tracing::warn!(
                error = %e,
                "failed to emit notifications/tools/list_changed after use_account",
            );
        }
        result
    }

    /// Resolve the target account for an account-scoped tool call.
    ///
    /// Precedence: URI namespace, then `args["account"]`, then the session
    /// default, then auto-select. Consumes the `account` entry from `args`
    /// so the downstream handler does not observe it as a tool argument.
    fn resolve_account_for_call(
        &self,
        namespaced_account: Option<&str>,
        args: &mut serde_json::Map<String, serde_json::Value>,
    ) -> Result<&AccountState, ErrorData> {
        let explicit_account = namespaced_account.map(String::from).or_else(|| {
            args.remove("account")
                .and_then(|v| v.as_str().map(String::from))
        });
        let session_default = self.session.active_account.load_full();
        self.registry()
            .resolve_with_active(explicit_account.as_deref(), session_default.as_deref())
            .map_err(|e| crate::mcp::error::to_mcp_error(&e))
    }
}
