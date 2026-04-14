//! Infrastructure tool handlers for account management.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::boot::registry::AccountRegistry;
use crate::response::ToolResponse;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UseAccountInput {
    /// Account name to select as the session default.
    pub account: String,
}

/// Select `input.account` as the session's active account.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_use_account(
    registry: &AccountRegistry,
    input: UseAccountInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    // Validate the account-name shape first so invalid input cannot be
    // echoed into error messages or reach `set_active`'s lookup code.
    rimap_core::account::AccountId::new(&input.account)
        .map_err(|_| rimap_core::RimapError::invalid_input("invalid account name"))?;
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

/// List all configured accounts.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_list_accounts(
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
