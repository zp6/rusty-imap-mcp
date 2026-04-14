//! `send_email` tool handler: compose and send via SMTP, then APPEND
//! a copy to the Sent folder.

use serde::Serialize;

use crate::boot::registry::AccountState;
use crate::mcp::response::ToolResponse;
use crate::tools::message_builder::{self, ComposeInput};

/// Input for `send_email` — identical fields to `create_draft`.
pub type SendEmailInput = ComposeInput;

/// Copy-to-Sent result included in a `send_email` response.
#[derive(Debug, Serialize)]
pub struct SentCopyInfo {
    /// Folder the copy was appended to.
    pub folder: String,
    /// UID assigned by the server, if returned.
    pub uid: Option<u32>,
    /// `true` if the APPEND failed (best-effort; send itself succeeded).
    pub failed: bool,
}

/// Trusted metadata for a `send_email` response.
#[derive(Debug, Serialize)]
pub struct SendEmailMeta {
    /// Whether the message was delivered via SMTP.
    pub sent: bool,
    /// RFC 2822 `Message-ID` assigned to the outgoing message.
    pub message_id: Option<String>,
    /// Human-readable SMTP delivery status.
    pub smtp_status: String,
    /// Result of the best-effort copy to the Sent folder.
    pub sent_copy: SentCopyInfo,
}

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
) -> Result<ToolResponse<SendEmailMeta>, rimap_core::RimapError> {
    message_builder::validate_compose_input(&input)?;

    let smtp = account.smtp.as_ref().ok_or_else(|| {
        rimap_core::RimapError::Config("send_email requires SMTP configuration".into())
    })?;

    let from_addr = account.imap.username();
    let raw_msg = message_builder::build_message(account, from_addr, &input).await?;

    // Build SMTP envelope from the compose addresses.
    let envelope = build_envelope(from_addr, &input);

    // Send via SMTP using raw bytes
    let smtp_response = smtp.send_raw(&envelope, &raw_msg).await?;
    tracing::info!(smtp_response, "send_email: SMTP send succeeded");

    // Extract Message-ID for the response
    let generated_msg_id = rimap_content::extract_message_id(&raw_msg);

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
        meta: SendEmailMeta {
            sent: true,
            message_id: generated_msg_id,
            smtp_status: "delivered".to_string(),
            sent_copy: SentCopyInfo {
                folder: sent_folder.to_string(),
                uid: sent_uid,
                failed: sent_copy_failed,
            },
        },
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Build a rimap-smtp `SendEnvelope` from the compose input addresses.
/// Address validation is delegated to rimap-smtp's parser at send time;
/// this helper only gathers the addresses into a single To / Cc / Bcc
/// recipient list and keeps the handler off the `lettre` type surface.
fn build_envelope(from_addr: &str, input: &ComposeInput) -> rimap_smtp::SendEnvelope {
    let mut recipients: Vec<String> = Vec::new();
    recipients.extend(input.to.iter().map(|a| a.address.clone()));
    if let Some(cc) = &input.cc {
        recipients.extend(cc.iter().map(|a| a.address.clone()));
    }
    if let Some(bcc) = &input.bcc {
        recipients.extend(bcc.iter().map(|a| a.address.clone()));
    }
    rimap_smtp::SendEnvelope {
        from: from_addr.to_string(),
        to: recipients,
    }
}

#[cfg(test)]
mod tests {
    use super::build_envelope;
    use crate::tools::message_builder::{AddressInput, ComposeInput};

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
    fn build_envelope_single_recipient() {
        let env = build_envelope("from@example.com", &compose(vec![addr("a@example.com")]));
        assert_eq!(env.from, "from@example.com");
        assert_eq!(env.to, vec!["a@example.com"]);
    }

    #[test]
    fn build_envelope_unions_to_cc_bcc() {
        let mut input = compose(vec![addr("a@example.com")]);
        input.cc = Some(vec![addr("b@example.com")]);
        input.bcc = Some(vec![addr("c@example.com")]);
        let env = build_envelope("from@example.com", &input);
        assert_eq!(
            env.to,
            vec!["a@example.com", "b@example.com", "c@example.com"],
        );
    }

    #[test]
    fn build_envelope_keeps_raw_strings_for_smtp_layer() {
        // The SMTP layer owns address validation — build_envelope itself
        // is infallible and preserves the user-supplied string so the
        // rejection text from rimap-smtp matches what the caller typed.
        let env = build_envelope("not-an-email", &compose(vec![addr("also-bad")]));
        assert_eq!(env.from, "not-an-email");
        assert_eq!(env.to, vec!["also-bad"]);
    }
}
