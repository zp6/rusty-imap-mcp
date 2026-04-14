//! `send_email` tool handler: compose and send via SMTP, then APPEND
//! a copy to the Sent folder.

use crate::registry::AccountState;
use crate::response::ToolResponse;
use crate::tools::message_builder::{self, ComposeInput};

/// Input for `send_email` — identical fields to `create_draft`.
pub type SendEmailInput = ComposeInput;

/// `send_email` handler.
pub async fn handle(
    account: &AccountState,
    input: SendEmailInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;

    let smtp = account.smtp.as_ref().ok_or_else(|| {
        rimap_core::RimapError::Config("send_email requires SMTP configuration".into())
    })?;

    let from_addr = account.imap.username();
    let raw_msg = message_builder::build_message(account, from_addr, &input).await?;

    // Build SMTP envelope from the compose addresses
    let envelope = build_envelope(from_addr, &input)?;

    // Send via SMTP using raw bytes
    let smtp_response = smtp.send_raw(&envelope, &raw_msg).await?;
    tracing::info!(smtp_response, "send_email: SMTP send succeeded");

    // Extract Message-ID for the response
    let generated_msg_id = mail_parser::MessageParser::new()
        .parse(&raw_msg)
        .and_then(|m| m.message_id().map(ToString::to_string));

    // Best-effort: APPEND copy to Sent folder
    let sent_folder = "Sent";
    let (sent_uid, sent_copy_failed) = match account
        .imap
        .append_message(sent_folder, &raw_msg, &[rimap_imap::types::Flag::Seen], &[])
        .await
    {
        Ok(result) => (result.uid.map(rimap_imap::types::Uid::get), false),
        Err(e) => {
            tracing::warn!("failed to append to Sent folder: {e}");
            (None, true)
        }
    };

    Ok(ToolResponse {
        meta: serde_json::json!({
            "sent": true,
            "message_id": generated_msg_id,
            "smtp_status": "delivered",
            "sent_copy": {
                "folder": sent_folder,
                "uid": sent_uid,
                "failed": sent_copy_failed,
            },
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Build a lettre `Envelope` from the compose input addresses.
fn build_envelope(
    from_addr: &str,
    input: &ComposeInput,
) -> Result<lettre::address::Envelope, rimap_core::RimapError> {
    let from = from_addr
        .parse::<lettre::Address>()
        .map_err(|e| rimap_core::RimapError::Config(format!("invalid From address: {e}")))?;

    let mut recipients = Vec::new();
    for addr in &input.to {
        recipients.push(parse_lettre_addr(&addr.address)?);
    }
    if let Some(cc) = &input.cc {
        for addr in cc {
            recipients.push(parse_lettre_addr(&addr.address)?);
        }
    }
    if let Some(bcc) = &input.bcc {
        for addr in bcc {
            recipients.push(parse_lettre_addr(&addr.address)?);
        }
    }

    lettre::address::Envelope::new(Some(from), recipients).map_err(|e| {
        rimap_core::RimapError::Internal(format!("failed to build SMTP envelope: {e}"))
    })
}

fn parse_lettre_addr(addr: &str) -> Result<lettre::Address, rimap_core::RimapError> {
    addr.parse::<lettre::Address>()
        .map_err(|_| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "invalid email address in recipient list".into(),
        })
}
