//! Infrastructure tool handlers for account management.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boot::registry::AccountRegistry;
use crate::mcp::response::ToolResponse;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UseAccountInput {
    /// Account name to select as the session default.
    pub account: String,
}

/// Trusted metadata for a `use_account` response.
#[derive(Debug, Serialize)]
pub struct UseAccountMeta {
    /// The account that is now active.
    pub account: String,
    /// The previously active account, or `None` if none was set.
    pub previous: Option<String>,
}

/// A single account entry in a `list_accounts` response.
#[derive(Debug, Serialize)]
pub struct AccountEntry {
    /// Account name.
    pub name: String,
    /// Whether an SMTP configuration is present for this account.
    pub smtp_configured: bool,
}

/// Trusted metadata for a `list_accounts` response.
#[derive(Debug, Serialize)]
pub struct ListAccountsMeta {
    /// All configured accounts.
    pub accounts: Vec<AccountEntry>,
    /// Total number of configured accounts.
    pub count: usize,
}

/// Select `input.account` as the session's active account.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` if
/// `input.account` is not a valid account-name shape. Returns
/// `RimapError::UnknownAccount { ... }` if the name does not match a
/// configured account.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_use_account(
    registry: &AccountRegistry,
    input: UseAccountInput,
) -> Result<ToolResponse<UseAccountMeta>, rimap_core::RimapError> {
    // Validate the account-name shape first so invalid input cannot be
    // echoed into error messages or reach `set_active`'s lookup code.
    rimap_core::account::AccountId::new(&input.account)
        .map_err(|_| rimap_core::RimapError::invalid_input("invalid account name"))?;
    let previous = registry.set_active(&input.account)?;
    Ok(ToolResponse {
        meta: UseAccountMeta {
            account: input.account,
            previous,
        },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// List all configured accounts.
///
/// # Errors
///
/// Infallible in practice; the `Result` type is preserved for symmetry
/// with other tool handlers so they compose uniformly through the
/// dispatch pipeline.
#[expect(
    clippy::unused_async,
    reason = "handler shape uniform with async-handler siblings"
)]
pub async fn handle_list_accounts(
    registry: &AccountRegistry,
) -> Result<ToolResponse<ListAccountsMeta>, rimap_core::RimapError> {
    let mut accounts: Vec<AccountEntry> = Vec::new();
    for state in registry.accounts().values() {
        accounts.push(AccountEntry {
            name: state.id.as_str().to_string(),
            smtp_configured: state.smtp.is_some(),
        });
    }
    let count = accounts.len();
    Ok(ToolResponse {
        meta: ListAccountsMeta { accounts, count },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}
