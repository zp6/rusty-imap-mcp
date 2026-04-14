//! `send_email` tool handler: compose and send via SMTP, then APPEND
//! a copy to the Sent folder.

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::message_builder::{self, ComposeInput};

/// Input for `send_email` — identical fields to `create_draft`.
pub type SendEmailInput = ComposeInput;

/// `send_email` handler.
///
/// # Errors
///
/// Returns `RimapError::Authz { code: InvalidInput, ... }` for malformed
/// recipient addresses or compose-input violations. Returns
/// `RimapError::Config` if no SMTP is configured for the account.
/// Returns `RimapError::Smtp { ... }` on SMTP failure. Returns
/// `RimapError::Internal` if the lettre envelope cannot be built from an
/// already-validated compose input (should not happen in practice). The
/// copy-to-Sent APPEND is best-effort; an IMAP failure there surfaces via
/// `sent_copy_failed` in the response, not as an error.
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
    addr.parse::<lettre::Address>().map_err(|_| {
        rimap_core::RimapError::invalid_input("invalid email address in recipient list")
    })
}

#[cfg(test)]
#[expect(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests"
)]
mod tests {
    use super::{build_envelope, parse_lettre_addr};
    use crate::tools::message_builder::{AddressInput, ComposeInput};
    use rimap_core::{ErrorCode, RimapError};

    fn addr(address: &str) -> AddressInput {
        AddressInput {
            name: None,
            address: address.to_string(),
        }
    }

    fn compose(to: Vec<AddressInput>) -> ComposeInput {
        ComposeInput {
            to,
            cc: None,
            bcc: None,
            subject: "s".into(),
            body_text: "b".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        }
    }

    #[test]
    fn parse_lettre_addr_accepts_well_formed_mailbox() {
        let parsed = parse_lettre_addr("alice@example.com").expect("valid address");
        assert_eq!(parsed.to_string(), "alice@example.com");
    }

    #[test]
    fn parse_lettre_addr_rejects_garbage_with_invalid_input() {
        let err = parse_lettre_addr("not-an-email").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn build_envelope_single_recipient() {
        let env = build_envelope("from@example.com", &compose(vec![addr("a@example.com")]))
            .expect("envelope ok");
        assert_eq!(env.to().len(), 1);
        assert!(env.from().is_some());
    }

    #[test]
    fn build_envelope_unions_to_cc_bcc() {
        let mut input = compose(vec![addr("a@example.com")]);
        input.cc = Some(vec![addr("b@example.com")]);
        input.bcc = Some(vec![addr("c@example.com")]);
        let env = build_envelope("from@example.com", &input).expect("envelope ok");
        assert_eq!(env.to().len(), 3, "to + cc + bcc collapsed into envelope");
    }

    #[test]
    fn build_envelope_rejects_bad_from_with_config_error() {
        let err =
            build_envelope("not-an-email", &compose(vec![addr("a@example.com")])).unwrap_err();
        match err {
            RimapError::Config(_) => {}
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn build_envelope_rejects_bad_recipient_with_invalid_input() {
        let err =
            build_envelope("from@example.com", &compose(vec![addr("not-an-email")])).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }
}
