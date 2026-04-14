//! Infrastructure tool handlers for account management.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::registry::AccountRegistry;
use crate::response::ToolResponse;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UseAccountInput {
    /// Account name to select as the session default.
    pub account: String,
}

pub fn handle_use_account(
    registry: &AccountRegistry,
    input: &UseAccountInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let previous = registry.set_active(&input.account)?;
    Ok(ToolResponse {
        meta: serde_json::json!({
            "account": input.account,
            "previous": previous,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// List all configured accounts. Returns `Result` for consistency
/// with the dispatch pipeline, though it cannot currently fail.
#[expect(
    clippy::unnecessary_wraps,
    reason = "consistent Result return with dispatch pipeline"
)]
pub fn handle_list_accounts(
    registry: &AccountRegistry,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let mut accounts: Vec<serde_json::Value> = Vec::new();
    for state in registry.accounts().values() {
        accounts.push(serde_json::json!({
            "name": state.id.as_str(),
            "smtp_configured": state.smtp.is_some(),
        }));
    }
    let count = accounts.len();
    Ok(ToolResponse {
        meta: serde_json::json!({
            "accounts": accounts,
            "count": count,
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
