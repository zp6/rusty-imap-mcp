//! `search` tool handler.

use rimap_core::error::ErrorCode;
use rimap_core::tool::ToolName;
use rimap_imap::types::{
    Address, FetchSpec, FetchedMessage, Flag, SearchQuery, StructuredQuery, Uid,
};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Maximum number of results per page.
const MAX_LIMIT: usize = 100;

/// Input for the `search` tool.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchInput {
    /// IMAP folder to search in.
    pub folder: String,
    /// Filter by `From` header substring.
    pub from: Option<String>,
    /// Filter by `To` header substring.
    pub to: Option<String>,
    /// Filter by `Subject` header substring.
    pub subject: Option<String>,
    /// Messages since this ISO date (inclusive), e.g. "2026-01-01".
    pub since: Option<String>,
    /// Messages before this ISO date (exclusive), e.g. "2026-02-01".
    pub before: Option<String>,
    /// Filter by seen/unseen status.
    pub seen: Option<bool>,
    /// Filter for messages with attachments.
    pub has_attachment: Option<bool>,
    /// Raw IMAP SEARCH query (full posture only).
    pub advanced_query: Option<String>,
    /// Max results to return (default 100, max 100).
    pub limit: Option<usize>,
    /// Offset into the result set (default 0).
    pub offset: Option<usize>,
}

/// Execute the `search` tool.
pub async fn handle(
    server: &ImapMcpServer,
    input: SearchInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let query = build_query(server, &input)?;

    let uids = server.imap.search(&input.folder, query).await?;
    let total_matched = uids.len();

    let offset = input.offset.unwrap_or(0);
    let limit = input.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT);

    let page_uids: Vec<Uid> = uids.into_iter().skip(offset).take(limit).collect();

    let truncated = total_matched > offset + page_uids.len();

    let messages = if page_uids.is_empty() {
        Vec::new()
    } else {
        let fetched = server
            .imap
            .fetch(
                &input.folder,
                &page_uids,
                FetchSpec {
                    envelope: true,
                    flags: true,
                    size: true,
                    ..FetchSpec::default()
                },
            )
            .await?;
        fetched.iter().map(format_search_result).collect()
    };

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": input.folder,
            "total_matched": total_matched,
            "returned": messages.len(),
            "truncated": truncated,
        }),
        untrusted: Some(serde_json::json!({
            "messages": messages,
        })),
        security_warnings: Vec::new(),
    })
}

/// Build a `SearchQuery` from the input, checking posture for
/// advanced queries.
fn build_query(
    server: &ImapMcpServer,
    input: &SearchInput,
) -> Result<SearchQuery, rimap_core::RimapError> {
    if let Some(raw) = &input.advanced_query {
        server
            .guard
            .matrix()
            .check(ToolName::SearchAdvanced)
            .map_err(|e| rimap_core::RimapError::Authz {
                code: e.code(),
                message: e.to_string(),
            })?;
        return Ok(SearchQuery::Raw(raw.clone()));
    }

    let since = input.since.as_deref().map(parse_iso_date).transpose()?;
    let before = input.before.as_deref().map(parse_iso_date).transpose()?;

    Ok(SearchQuery::Structured(StructuredQuery {
        from: input.from.clone(),
        to: input.to.clone(),
        subject: input.subject.clone(),
        since,
        before,
        seen: input.seen,
        has_attachment: input.has_attachment.unwrap_or(false),
    }))
}

/// Parse an ISO 8601 date string ("YYYY-MM-DD") into a `time::Date`.
fn parse_iso_date(s: &str) -> Result<time::Date, rimap_core::RimapError> {
    let format = time::format_description::well_known::Iso8601::DATE;
    time::Date::parse(s, &format).map_err(|e| rimap_core::RimapError::Authz {
        code: ErrorCode::InvalidInput,
        message: format!("invalid date '{s}': {e}"),
    })
}

/// Format an address as `"name <mailbox@host>"` or `"mailbox@host"`.
fn format_address(addr: &Address) -> String {
    let mailbox = addr
        .mailbox
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let host = addr
        .host
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let email = format!("{mailbox}@{host}");

    match &addr.name {
        Some(name) => {
            let name = String::from_utf8_lossy(name);
            if name.is_empty() {
                email
            } else {
                format!("{name} <{email}>")
            }
        }
        None => email,
    }
}

/// Format addresses list.
fn format_addresses(addrs: &[Address]) -> Vec<String> {
    addrs.iter().map(format_address).collect()
}

/// Format a flag for JSON output.
fn format_flag(flag: &Flag) -> &str {
    match flag {
        Flag::Seen => "\\Seen",
        Flag::Answered => "\\Answered",
        Flag::Flagged => "\\Flagged",
        Flag::Deleted => "\\Deleted",
        Flag::Draft => "\\Draft",
        Flag::Recent => "\\Recent",
        Flag::Keyword(kw) => kw.as_str(),
    }
}

/// Format a single `FetchedMessage` into a JSON value for search
/// results.
fn format_search_result(msg: &FetchedMessage) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "uid": msg.uid.get(),
    });

    if let Some(size) = msg.size {
        entry["size"] = serde_json::json!(size);
    }

    if let Some(flags) = &msg.flags {
        let flag_strs: Vec<&str> = flags.iter().map(format_flag).collect();
        entry["flags"] = serde_json::json!(flag_strs);
    }

    if let Some(env) = &msg.envelope {
        if let Some(subj) = &env.subject_raw {
            entry["subject"] = serde_json::json!(String::from_utf8_lossy(subj));
        }
        if let Some(date) = &env.date {
            entry["date"] = serde_json::json!(String::from_utf8_lossy(date));
        }
        if !env.from.is_empty() {
            entry["from"] = serde_json::json!(format_addresses(&env.from));
        }
        if !env.to.is_empty() {
            entry["to"] = serde_json::json!(format_addresses(&env.to));
        }
        if let Some(mid) = &env.message_id {
            entry["message_id"] = serde_json::json!(String::from_utf8_lossy(mid.as_bytes()));
        }
    }

    entry
}
