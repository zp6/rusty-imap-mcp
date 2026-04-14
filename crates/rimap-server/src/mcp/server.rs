//! MCP server struct and `ServerHandler` implementation.
//!
//! `ImapMcpServer` owns an `AccountRegistry` (per-account IMAP/SMTP
//! connections, guards), an audit writer, and the download directory.
//! The `ServerHandler` trait wires `list_tools` (posture-filtered
//! union across accounts) and `call_tool` (account resolution +
//! dispatch pipeline).

use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use rimap_audit::AuditWriter;
use rimap_audit::record::{Provenance, ResultSummary, ToolStatus};
use rimap_audit::redact::{RedactionSalt, RedactionSchema, Redactor, hash_arguments, schemas};
use rimap_core::account::{AccountId, DEFAULT_ACCOUNT_NAME};
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

/// Core MCP server. Owns every resource the handler methods need.
pub struct ImapMcpServer {
    /// Account registry holding per-account state.
    pub(crate) registry: AccountRegistry,
    /// Append-only audit writer.
    pub(crate) audit: AuditWriter,
    /// Directory for attachment downloads.
    pub(crate) download_dir: PathBuf,
    /// Per-process salt used when applying `Redactor` to tool arguments.
    /// Wrapped in `Arc` so `spawn_blocking` closures can cheaply capture it.
    pub(crate) redaction_salt: Arc<RedactionSalt>,
    /// Redaction schemas keyed by tool name (matches `ToolName::as_str`).
    /// Built once at construction from `rimap_audit::redact::schemas()`.
    pub(crate) redaction_schemas: Arc<HashMap<ToolName, RedactionSchema>>,
}

impl ImapMcpServer {
    /// Construct a new server. Builds the redaction salt and schema map
    /// from [`rimap_audit::redact::schemas`].
    #[must_use]
    pub fn new(registry: AccountRegistry, audit: AuditWriter, download_dir: PathBuf) -> Self {
        let schema_map: HashMap<ToolName, RedactionSchema> =
            schemas().into_iter().map(|s| (s.tool, s)).collect();
        Self {
            registry,
            audit,
            download_dir,
            redaction_salt: Arc::new(RedactionSalt::new_random()),
            redaction_schemas: Arc::new(schema_map),
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
        _context: RequestContext<RoleServer>,
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
            return Box::pin(self.dispatch_infrastructure(tool_name, &args)).await;
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

/// Posture context recorded in audit envelope headers.
///
/// Per-account dispatches use the account's effective posture; the
/// infrastructure tools (`list_accounts`, `use_account`) bypass posture
/// gating by design and record the dedicated `Infrastructure` variant so
/// log readers can distinguish them from per-account dispatches.
#[derive(Debug, Clone, Copy)]
enum PostureContext {
    Account(rimap_core::Posture),
    Infrastructure,
}

impl PostureContext {
    /// The per-account [`rimap_core::Posture`] this context represents, or
    /// `None` for the infrastructure dispatch path. The audit writer maps
    /// `None` to the `"infrastructure"` sentinel it records on disk.
    fn posture(self) -> Option<rimap_core::Posture> {
        match self {
            Self::Account(p) => Some(p),
            Self::Infrastructure => None,
        }
    }
}

/// Map a [`RimapError`] to the breaker's [`FailureReason`], or `None`
/// when the error represents a user/agent/policy failure (which the
/// breaker must ignore per its contract).
fn rimap_error_to_breaker_reason(
    err: &rimap_core::RimapError,
) -> Option<rimap_authz::breaker::FailureReason> {
    use rimap_authz::breaker::FailureReason;
    use rimap_core::ErrorCode;
    match err.code() {
        ErrorCode::ConnectionLost => Some(FailureReason::ConnectionLost),
        ErrorCode::Auth => Some(FailureReason::Auth),
        ErrorCode::Timeout => Some(FailureReason::Timeout),
        ErrorCode::ImapProtocol | ErrorCode::SmtpProtocol => Some(FailureReason::Protocol),
        ErrorCode::Tls => Some(FailureReason::Tls),
        ErrorCode::InvalidInput
        | ErrorCode::PostureDenied
        | ErrorCode::RateLimited
        | ErrorCode::CircuitOpen
        | ErrorCode::NotFound
        | ErrorCode::AttachmentTooLarge
        | ErrorCode::ProtectedFolder
        | ErrorCode::ExpungeDenied
        | ErrorCode::Config
        | ErrorCode::Internal
        | ErrorCode::NoAccount
        | ErrorCode::UnknownAccount => None,
    }
}

impl ImapMcpServer {
    /// Wrap an inner dispatch `body` in the full audit envelope:
    /// redact+hash args, emit `tool_start`, time the body, emit
    /// `tool_end` with the status/error code derived from the body's
    /// result. Returns the MCP-shaped `CallToolResult` or `ErrorData`.
    async fn run_with_audit_envelope<F>(
        &self,
        tool: ToolName,
        audit_account: Option<String>,
        posture: PostureContext,
        args: &serde_json::Map<String, serde_json::Value>,
        body: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: std::future::Future<Output = Result<serde_json::Value, rimap_core::RimapError>>,
    {
        let args_value = serde_json::Value::Object(args.clone());
        let redacted = self.redact_tool_args(tool, &args_value);
        let hash = hash_arguments(&args_value);

        let start_seq = self
            .emit_tool_start(tool, audit_account.clone(), posture, redacted, hash)
            .await?;
        let start_time = std::time::Instant::now();

        let result = body.await;

        let duration_ms = start_time
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let (status, error_code) = match &result {
            Ok(_) => (ToolStatus::Ok, None),
            Err(e) => (ToolStatus::Error, Some(e.code())),
        };
        self.emit_tool_end(
            start_seq,
            tool,
            audit_account,
            status,
            error_code,
            duration_ms,
        )
        .await;

        match result {
            Ok(value) => Ok(CallToolResult::structured(value)),
            Err(e) => Err(crate::mcp::error::to_mcp_error(&e)),
        }
    }

    /// Dispatch to the tool handler for `tool`. Each arm serializes its
    /// typed response to `serde_json::Value` before returning, so the
    /// audit envelope works with a single future type.
    pub(crate) async fn dispatch_tool(
        &self,
        account: &AccountState,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Value, rimap_core::RimapError> {
        use crate::tools::{
            create_draft, delete_message, download_attachment, expunge, fetch_message, flags,
            folder_management, labels, list_attachments, list_folders, move_message, search,
            send_email,
        };
        let resp = match tool {
            ToolName::ListFolders => ser(Box::pin(list_folders::handle(account)).await?)?,
            ToolName::MarkRead => {
                ser(Box::pin(flags::handle_mark_read(account, parse_args(args)?)).await?)?
            }
            ToolName::MarkUnread => {
                ser(Box::pin(flags::handle_mark_unread(account, parse_args(args)?)).await?)?
            }
            ToolName::Flag => ser(Box::pin(flags::handle_flag(account, parse_args(args)?)).await?)?,
            ToolName::Unflag => {
                ser(Box::pin(flags::handle_unflag(account, parse_args(args)?)).await?)?
            }
            ToolName::MoveMessage => {
                ser(Box::pin(move_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::Search | ToolName::SearchAdvanced => {
                ser(Box::pin(search::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::FetchMessage | ToolName::FetchMessageHtml => {
                ser(Box::pin(fetch_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::ListAttachments => {
                ser(Box::pin(list_attachments::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::DownloadAttachment => {
                let input = parse_args(args)?;
                ser(Box::pin(download_attachment::handle(
                    account,
                    input,
                    &self.download_dir,
                ))
                .await?)?
            }
            ToolName::CreateDraft => {
                ser(Box::pin(create_draft::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::SendEmail => {
                ser(Box::pin(send_email::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::DeleteMessage => {
                ser(Box::pin(delete_message::handle(account, parse_args(args)?)).await?)?
            }
            ToolName::Expunge => ser(Box::pin(expunge::handle(account, parse_args(args)?)).await?)?,
            ToolName::CreateFolder => ser(Box::pin(folder_management::handle_create_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::RenameFolder => ser(Box::pin(folder_management::handle_rename_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::DeleteFolder => ser(Box::pin(folder_management::handle_delete_folder(
                account,
                parse_args(args)?,
            ))
            .await?)?,
            ToolName::AddLabel => {
                ser(Box::pin(labels::handle_add_label(account, parse_args(args)?)).await?)?
            }
            ToolName::RemoveLabel => {
                ser(Box::pin(labels::handle_remove_label(account, parse_args(args)?)).await?)?
            }
            ToolName::ListLabels => {
                ser(Box::pin(labels::handle_list_labels(account, parse_args(args)?)).await?)?
            }
            ToolName::UseAccount | ToolName::ListAccounts => {
                return Err(rimap_core::RimapError::Internal(
                    "infrastructure tools must not reach dispatch_tool".into(),
                ));
            }
        };
        Ok(resp)
    }

    /// Handle infrastructure tools that bypass account resolution.
    ///
    /// Infrastructure tools are not scoped to an account, so their audit
    /// records record `account: None` regardless of deployment mode.
    async fn dispatch_infrastructure(
        &self,
        tool: ToolName,
        args: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<CallToolResult, ErrorData> {
        // Infrastructure tools have no per-account posture; record an
        // explicit sentinel so log readers can distinguish these from
        // per-account dispatches.
        self.run_with_audit_envelope(tool, None, PostureContext::Infrastructure, args, async {
            // Infrastructure tools bypass posture + breaker, but still
            // enforce a process-wide rate limit.
            self.registry.check_infrastructure_rate()?;
            match tool {
                ToolName::UseAccount => {
                    let input = parse_args::<crate::tools::accounts::UseAccountInput>(args)?;
                    ser(crate::tools::accounts::handle_use_account(&self.registry, input).await?)
                }
                ToolName::ListAccounts => {
                    ser(crate::tools::accounts::handle_list_accounts(&self.registry).await?)
                }
                ToolName::ListFolders
                | ToolName::Search
                | ToolName::SearchAdvanced
                | ToolName::FetchMessage
                | ToolName::FetchMessageHtml
                | ToolName::ListAttachments
                | ToolName::DownloadAttachment
                | ToolName::MarkRead
                | ToolName::MarkUnread
                | ToolName::Flag
                | ToolName::Unflag
                | ToolName::AddLabel
                | ToolName::RemoveLabel
                | ToolName::ListLabels
                | ToolName::MoveMessage
                | ToolName::CreateDraft
                | ToolName::SendEmail
                | ToolName::DeleteMessage
                | ToolName::Expunge
                | ToolName::CreateFolder
                | ToolName::RenameFolder
                | ToolName::DeleteFolder => Err(rimap_core::RimapError::Internal(format!(
                    "not an infrastructure tool: {}",
                    tool.as_str(),
                ))),
            }
        })
        .await
    }

    /// Apply the registered [`rimap_audit::redact::Redactor`] schema for
    /// `tool`. If no schema matches, returns an empty object and emits
    /// a `warn!` — the schema registry is expected to cover every
    /// advertised tool.
    fn redact_tool_args(&self, tool: ToolName, args: &serde_json::Value) -> serde_json::Value {
        if let Some(schema) = self.redaction_schemas.get(&tool) {
            Redactor::new(schema, self.redaction_salt.as_ref()).apply(args)
        } else {
            tracing::warn!(
                tool = tool.as_str(),
                "no redaction schema for tool; recording empty arguments_redacted",
            );
            serde_json::Value::Object(serde_json::Map::new())
        }
    }

    /// Emit a `tool_start` audit record via `spawn_blocking`. Returns the
    /// allocated `seq` on success; on audit failure emits a `warn!` and
    /// returns a synthetic `Seq::FIRST` so the call can proceed.
    ///
    /// Errors bubble up only when `fail_open = false` AND the write fails:
    /// in that case the tool call MUST fail because the audit trail is
    /// broken. `fail_open = true` deployments swallow the error inside
    /// the writer and return `Ok`.
    async fn emit_tool_start(
        &self,
        tool: ToolName,
        account: Option<String>,
        posture: PostureContext,
        redacted: serde_json::Value,
        hash: String,
    ) -> Result<rimap_audit::Seq, ErrorData> {
        let audit = self.audit.clone();
        let posture_effective = posture.posture();
        let join = tokio::task::spawn_blocking(move || {
            audit.log_tool_start(tool, account.as_deref(), posture_effective, redacted, hash)
        })
        .await;
        match join {
            Ok(Ok(seq)) => Ok(seq),
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_start audit write failed");
                Err(ErrorData::internal_error(
                    format!("audit write failed: {audit_err}"),
                    None,
                ))
            }
            Err(join_err) => {
                tracing::error!(error = %join_err, "tool_start join error");
                let rimap_err = crate::mcp::spawn_blocking_panic_error(&join_err);
                Err(crate::mcp::error::to_mcp_error(&rimap_err))
            }
        }
    }

    /// Emit a `tool_end` audit record via `spawn_blocking`. Failures are
    /// logged but not propagated — at end-of-call the tool has already
    /// finished and the caller sees its original result.
    async fn emit_tool_end(
        &self,
        start_seq: rimap_audit::Seq,
        tool: ToolName,
        account: Option<String>,
        status: ToolStatus,
        error_code: Option<rimap_core::ErrorCode>,
        duration_ms: u64,
    ) {
        let audit = self.audit.clone();
        // The provenance ring buffer is not yet wired for multi-account.
        // Record an empty snapshot with the window placeholder until a
        // per-account buffer lands.
        let provenance = Provenance {
            window_seconds: 60,
            message_ids_recently_read: Vec::new(),
        };
        let summary = ResultSummary::default();
        let join = tokio::task::spawn_blocking(move || {
            audit.log_tool_end(
                start_seq,
                tool,
                account.as_deref(),
                status,
                error_code,
                duration_ms,
                summary,
                provenance,
            )
        })
        .await;
        match join {
            Ok(Ok(_)) => {}
            Ok(Err(audit_err)) => {
                tracing::error!(error = %audit_err, "tool_end audit write failed");
            }
            Err(join_err) => {
                let rimap_err = crate::mcp::spawn_blocking_panic_error(&join_err);
                tracing::error!(error = %rimap_err, "tool_end join error");
            }
        }
    }
}

/// Serialize a typed response to `serde_json::Value`.
///
/// Used in `dispatch_tool` and `dispatch_infrastructure` to unify
/// concrete handler return types into a single `Value` before the
/// audit envelope processes them.
fn ser<T: serde::Serialize>(resp: T) -> Result<serde_json::Value, rimap_core::RimapError> {
    serde_json::to_value(&resp).map_err(|e| {
        rimap_core::RimapError::Internal(format!("response serialization failed: {e}"))
    })
}

/// Deserialize tool arguments into a typed input struct.
fn parse_args<T: serde::de::DeserializeOwned>(
    args: &serde_json::Map<String, serde_json::Value>,
) -> Result<T, rimap_core::RimapError> {
    serde_json::from_value(serde_json::Value::Object(args.clone()))
        .map_err(|e| rimap_core::RimapError::invalid_input(format!("invalid arguments: {e}")))
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
        Ok(
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_)
            | serde_json::Value::Array(_),
        )
        | Err(_) => serde_json::Map::new(),
    }
}

/// Whether the registry holds exactly one account and its id is the
/// legacy `"default"` value. Used to preserve bare (non-namespaced)
/// tool names for single-account deployments.
fn is_legacy_single_account(
    accounts: &std::collections::BTreeMap<AccountId, AccountState>,
) -> bool {
    accounts.len() == 1
        && accounts
            .keys()
            .next()
            .is_some_and(|id| id.as_str() == DEFAULT_ACCOUNT_NAME)
}

/// Split a possibly-namespaced MCP tool name into `(account, tool)`.
///
/// Preserves sub-capability tool names that contain dots (e.g.
/// Promote a base `ToolName` to a sub-capability variant based on args.
/// Keeps sub-capability posture checks at the dispatch seam rather than
/// scattered across handlers.
fn refine_tool_name(
    base: ToolName,
    args: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ToolName {
    let Some(args) = args else {
        return base;
    };
    match base {
        ToolName::FetchMessage
            if args
                .get("include_html")
                .and_then(serde_json::Value::as_bool)
                == Some(true) =>
        {
            ToolName::FetchMessageHtml
        }
        ToolName::Search if args.get("advanced_query").is_some() => ToolName::SearchAdvanced,
        other => other,
    }
}

/// `search.advanced_query`): if the raw name parses as a `ToolName`
/// directly, return it as bare.
fn split_tool_name(raw: &str) -> (Option<&str>, &str) {
    if ToolName::from_str(raw).is_ok() {
        return (None, raw);
    }
    match raw.split_once('.') {
        Some((prefix, rest))
            if is_valid_account_prefix(prefix) && ToolName::from_str(rest).is_ok() =>
        {
            (Some(prefix), rest)
        }
        Some(_) | None => (None, raw),
    }
}

/// Structural check on an account-namespace prefix. Mirrors the
/// `AccountId` character rules (ASCII alphanumerics + hyphens, 1–64
/// chars) without allocating.
fn is_valid_account_prefix(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Type alias for tool spec tuples — `(description, schema)`. The wire
/// name comes from `ToolName::as_str()` so there is a single source of
/// truth for tool names.
type ToolSpec = (&'static str, serde_json::Map<String, serde_json::Value>);

/// Return (description, schema) for the given `ToolName`, or `None`
/// for sub-capabilities that share an MCP tool name with a parent
/// (e.g. `SearchAdvanced`, `FetchMessageHtml`).
fn tool_spec(name: ToolName) -> Option<ToolSpec> {
    use crate::tools::{
        accounts::UseAccountInput,
        create_draft::CreateDraftInput,
        delete_message::DeleteMessageInput,
        download_attachment::DownloadAttachmentInput,
        expunge::ExpungeInput,
        fetch_message::FetchMessageInput,
        flags::FlagInput,
        folder_management::{CreateFolderInput, DeleteFolderInput, RenameFolderInput},
        labels::{LabelInput, ListLabelsInput},
        list_attachments::ListAttachmentsInput,
        move_message::MoveMessageInput,
        search::SearchInput,
        send_email::SendEmailInput,
    };
    let tuple = match name {
        ToolName::ListFolders => ("List all IMAP folders", serde_json::Map::new()),
        ToolName::Search => (
            "Search messages with structured query",
            schema_map::<SearchInput>(),
        ),
        ToolName::FetchMessage => (
            "Fetch message metadata and text body",
            schema_map::<FetchMessageInput>(),
        ),
        ToolName::ListAttachments => (
            "List attachments on a message",
            schema_map::<ListAttachmentsInput>(),
        ),
        ToolName::DownloadAttachment => (
            "Download an attachment to the sandbox directory",
            schema_map::<DownloadAttachmentInput>(),
        ),
        ToolName::MarkRead => ("Mark messages as read", schema_map::<FlagInput>()),
        ToolName::MarkUnread => ("Mark messages as unread", schema_map::<FlagInput>()),
        ToolName::Flag => (
            "Add the flagged flag to messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::Unflag => (
            "Remove the flagged flag from messages",
            schema_map::<FlagInput>(),
        ),
        ToolName::MoveMessage => (
            "Move messages to another folder",
            schema_map::<MoveMessageInput>(),
        ),
        ToolName::CreateDraft => (
            "Create a draft email with $PendingReview flag",
            schema_map::<CreateDraftInput>(),
        ),
        ToolName::SendEmail => ("Send an email via SMTP", schema_map::<SendEmailInput>()),
        ToolName::DeleteMessage => (
            "Delete a message (move to Trash)",
            schema_map::<DeleteMessageInput>(),
        ),
        ToolName::Expunge => (
            "Permanently remove deleted messages from a folder",
            schema_map::<ExpungeInput>(),
        ),
        ToolName::CreateFolder => (
            "Create a new IMAP folder",
            schema_map::<CreateFolderInput>(),
        ),
        ToolName::RenameFolder => ("Rename an IMAP folder", schema_map::<RenameFolderInput>()),
        ToolName::DeleteFolder => (
            "Delete an IMAP folder and all its contents",
            schema_map::<DeleteFolderInput>(),
        ),
        ToolName::AddLabel => (
            "Add a keyword label to messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::RemoveLabel => (
            "Remove a keyword label from messages",
            schema_map::<LabelInput>(),
        ),
        ToolName::ListLabels => (
            "List keyword labels on a message",
            schema_map::<ListLabelsInput>(),
        ),
        ToolName::UseAccount => (
            "Set the active account for subsequent tool calls",
            schema_map::<UseAccountInput>(),
        ),
        ToolName::ListAccounts => ("List all configured email accounts", serde_json::Map::new()),
        // Sub-capabilities that share an MCP tool name with a parent
        // (e.g. `SearchAdvanced` shares `search`; `FetchMessageHtml`
        // shares `fetch_message`) are advertised under the parent entry,
        // so they have no standalone spec.
        ToolName::SearchAdvanced | ToolName::FetchMessageHtml => return None,
    };
    Some(tuple)
}

/// Memoized MCP tool definitions. Built once at first access; each
/// `list_tools` call reuses the same `Arc<JsonObject>` for schemas.
static TOOL_DEFS: std::sync::LazyLock<std::collections::HashMap<ToolName, Tool>> =
    std::sync::LazyLock::new(|| {
        let mut map = std::collections::HashMap::new();
        for tn in ToolName::all() {
            let Some((description, schema)) = tool_spec(tn) else {
                continue;
            };
            map.insert(tn, Tool::new(tn.as_str(), description, Arc::new(schema)));
        }
        map
    });

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use rimap_core::tool::ToolName;

    use super::{TOOL_DEFS, rimap_error_to_breaker_reason, split_tool_name};

    #[test]
    fn breaker_reason_maps_service_failures() {
        use rimap_authz::breaker::FailureReason;
        use rimap_core::{ErrorCode, RimapError};
        let err = RimapError::Imap {
            code: ErrorCode::Timeout,
            message: "x".into(),
            source: None,
        };
        assert_eq!(
            rimap_error_to_breaker_reason(&err),
            Some(FailureReason::Timeout),
        );
        let auth = RimapError::Imap {
            code: ErrorCode::Auth,
            message: "x".into(),
            source: None,
        };
        assert_eq!(
            rimap_error_to_breaker_reason(&auth),
            Some(FailureReason::Auth),
        );
        let tls = RimapError::Imap {
            code: ErrorCode::Tls,
            message: "x".into(),
            source: None,
        };
        assert_eq!(
            rimap_error_to_breaker_reason(&tls),
            Some(FailureReason::Tls)
        );
    }

    #[test]
    fn breaker_reason_ignores_user_errors() {
        use rimap_core::RimapError;
        assert_eq!(
            rimap_error_to_breaker_reason(&RimapError::invalid_input("bad")),
            None,
        );
        assert_eq!(
            rimap_error_to_breaker_reason(&RimapError::Internal("bug".into())),
            None,
        );
    }

    #[test]
    fn split_tool_name_bare() {
        assert_eq!(split_tool_name("send_email"), (None, "send_email"));
    }

    #[test]
    fn split_tool_name_namespaced() {
        assert_eq!(
            split_tool_name("work.send_email"),
            (Some("work"), "send_email"),
        );
    }

    #[test]
    fn split_tool_name_preserves_dotted_sub_capability() {
        // `search.advanced_query` is a valid ToolName and must not be
        // interpreted as account="search", tool="advanced_query".
        assert_eq!(
            split_tool_name("search.advanced_query"),
            (None, "search.advanced_query"),
        );
        assert_eq!(
            split_tool_name("fetch_message.include_html"),
            (None, "fetch_message.include_html"),
        );
    }

    #[test]
    fn split_tool_name_unknown_returns_bare() {
        // Unknown names pass through; `from_str` at the caller rejects.
        assert_eq!(split_tool_name("garbage"), (None, "garbage"));
        assert_eq!(split_tool_name("work.garbage"), (None, "work.garbage"),);
    }

    #[test]
    fn split_tool_name_rejects_invalid_prefix() {
        // Underscore is not valid in an account prefix.
        assert_eq!(
            split_tool_name("bad_name.send_email"),
            (None, "bad_name.send_email"),
        );
    }

    #[test]
    fn tool_definition_covers_all_mcp_tools() {
        // Sub-capabilities are surfaced via their parent tool's schema, not
        // as standalone MCP tools, so they do not appear in `TOOL_DEFS`.
        const SUB_CAPABILITIES: &[ToolName] =
            &[ToolName::SearchAdvanced, ToolName::FetchMessageHtml];
        let expected = ToolName::all().len() - SUB_CAPABILITIES.len();
        let defs: Vec<_> = ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
            .collect();
        assert_eq!(defs.len(), expected);
    }

    #[test]
    fn sub_capabilities_return_none() {
        assert!(TOOL_DEFS.get(&ToolName::SearchAdvanced).is_none());
        assert!(TOOL_DEFS.get(&ToolName::FetchMessageHtml).is_none());
    }

    #[test]
    fn tool_names_are_snake_case() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "tool name {} is not snake_case",
                def.name,
            );
        }
    }

    #[test]
    fn tool_definitions_have_non_empty_schemas() {
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
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
        for def in ToolName::all()
            .into_iter()
            .filter_map(|tn| TOOL_DEFS.get(&tn))
        {
            assert!(
                def.description.is_some(),
                "tool {} missing description",
                def.name,
            );
        }
    }

    #[tokio::test]
    async fn infrastructure_tool_emits_tool_start_and_tool_end() {
        use std::collections::BTreeMap;

        use rimap_audit::{AuditOptions, AuditWriter, Seq};
        use tempfile::TempDir;

        use crate::boot::registry::AccountRegistry;
        use crate::mcp::server::ImapMcpServer;

        let tmp = TempDir::new().expect("tempdir");
        let audit_path = tmp.path().join("audit.jsonl");
        let audit = AuditWriter::open(&AuditOptions {
            path: audit_path.clone(),
            rotate_bytes: 0,
            rotate_keep: 0,
            retention_seconds: None,
            fail_open: false,
            initial_seq: Seq::FIRST,
        })
        .expect("audit open");

        let registry = AccountRegistry::new(BTreeMap::new());
        let server = ImapMcpServer::new(registry, audit, tmp.path().to_path_buf());

        // list_accounts needs no args and no IMAP connection.
        let args = serde_json::Map::new();
        let _ = server
            .dispatch_infrastructure(ToolName::ListAccounts, &args)
            .await
            .expect("list_accounts dispatch");

        drop(server);

        let contents = std::fs::read_to_string(&audit_path).expect("read audit log");
        let records: Vec<serde_json::Value> = contents
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse record"))
            .collect();

        let start = records
            .iter()
            .find(|r| r["kind"] == "tool_start" && r["tool"] == "list_accounts")
            .expect("tool_start record");
        let end = records
            .iter()
            .find(|r| r["kind"] == "tool_end" && r["tool"] == "list_accounts")
            .expect("tool_end record");

        assert_eq!(start["seq"], end["start_seq"]);
        assert_eq!(end["status"], "ok");
        assert!(start["account"].is_null());
        assert!(end["account"].is_null());
    }
}
