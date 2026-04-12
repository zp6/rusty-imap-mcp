//! `create_draft` tool handler: compose a draft email and APPEND it
//! to the Drafts folder with a `$PendingReview` keyword.

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_builder::headers::message_id::MessageId;
use serde::Deserialize;

use crate::response::ToolResponse;
use crate::server::ImapMcpServer;

/// Input for `create_draft`.
#[derive(Debug, Deserialize)]
pub struct CreateDraftInput {
    /// Recipient addresses.
    pub to: Vec<AddressInput>,
    /// CC addresses.
    pub cc: Option<Vec<AddressInput>>,
    /// BCC addresses.
    pub bcc: Option<Vec<AddressInput>>,
    /// Email subject.
    pub subject: String,
    /// Plain text body.
    pub body_text: String,
    /// UID of message to reply to (for threading headers).
    pub in_reply_to_uid: Option<u32>,
    /// Folder containing the message to reply to (default INBOX).
    pub in_reply_to_folder: Option<String>,
}

/// An email address with optional display name.
#[derive(Debug, Deserialize)]
pub struct AddressInput {
    /// Display name (optional).
    pub name: Option<String>,
    /// Email address.
    pub address: String,
}

/// `create_draft` handler.
pub async fn handle(
    server: &ImapMcpServer,
    input: CreateDraftInput,
) -> Result<ToolResponse, rimap_core::RimapError> {
    let raw_msg = build_draft(server, &input).await?;

    let drafts_folder = "Drafts";
    let result = server
        .imap
        .append_message(
            drafts_folder,
            &raw_msg,
            &[rimap_imap::types::Flag::Draft],
            &["$PendingReview"],
        )
        .await?;

    let generated_msg_id = mail_parser::MessageParser::new()
        .parse(&raw_msg)
        .and_then(|m| m.message_id().map(ToString::to_string));

    Ok(ToolResponse {
        meta: serde_json::json!({
            "folder": drafts_folder,
            "uid": result.uid.map(rimap_imap::types::Uid::get),
            "message_id": generated_msg_id,
            "keywords": ["$PendingReview"],
        }),
        untrusted: None,
        security_warnings: Vec::new(),
    })
}

/// Build a raw RFC 5322 message from the draft input.
///
/// Separated from `handle` so unit tests can exercise message
/// construction without an IMAP connection.
async fn build_draft(
    server: &ImapMcpServer,
    input: &CreateDraftInput,
) -> Result<Vec<u8>, rimap_core::RimapError> {
    let builder = build_message_headers(&server.config.config.imap.username, input);

    let builder = if let Some(reply_uid) = input.in_reply_to_uid {
        Box::pin(apply_threading_headers(server, builder, reply_uid, input)).await?
    } else {
        builder
    };

    builder.write_to_vec().map_err(|e| {
        rimap_core::RimapError::Internal(format!("failed to build draft message: {e}"))
    })
}

/// Set From, To, CC, BCC, Subject, and body on a `MessageBuilder`.
fn build_message_headers<'a>(
    from_addr: &'a str,
    input: &'a CreateDraftInput,
) -> MessageBuilder<'a> {
    let builder = MessageBuilder::new()
        .from(from_addr)
        .to(addresses_to_builder(&input.to))
        .subject(input.subject.as_str())
        .text_body(input.body_text.as_str());

    let builder = if let Some(cc) = &input.cc {
        builder.cc(addresses_to_builder(cc))
    } else {
        builder
    };

    if let Some(bcc) = &input.bcc {
        builder.bcc(addresses_to_builder(bcc))
    } else {
        builder
    }
}

/// Convert a slice of `AddressInput` into a mail-builder `Address`.
fn addresses_to_builder(addrs: &[AddressInput]) -> Address<'_> {
    if addrs.len() == 1 {
        return single_address(&addrs[0]);
    }
    let list: Vec<Address<'_>> = addrs.iter().map(single_address).collect();
    Address::new_list(list)
}

/// Convert a single `AddressInput` to a mail-builder `Address`.
fn single_address(addr: &AddressInput) -> Address<'_> {
    match &addr.name {
        Some(name) => Address::new_address(Some(name.as_str()), addr.address.as_str()),
        None => Address::new_address(None::<&str>, addr.address.as_str()),
    }
}

/// Fetch the referenced message and set In-Reply-To / References.
async fn apply_threading_headers<'a>(
    server: &ImapMcpServer,
    builder: MessageBuilder<'a>,
    reply_uid: u32,
    input: &CreateDraftInput,
) -> Result<MessageBuilder<'a>, rimap_core::RimapError> {
    let folder = input.in_reply_to_folder.as_deref().unwrap_or("INBOX");
    let uid =
        rimap_imap::types::Uid::new(reply_uid).ok_or_else(|| rimap_core::RimapError::Authz {
            code: rimap_core::error::ErrorCode::InvalidInput,
            message: "in_reply_to_uid must be non-zero".into(),
        })?;

    let raw = server.imap.fetch_body(folder, uid).await?;
    let parsed = mail_parser::MessageParser::new()
        .parse(&raw)
        .ok_or_else(|| {
            rimap_core::RimapError::Internal("failed to parse referenced message".into())
        })?;

    let Some(msg_id) = parsed.message_id() else {
        return Ok(builder);
    };

    let builder = builder.in_reply_to(msg_id.to_string());

    // Build References chain: existing References + this Message-ID.
    let mut ref_ids: Vec<String> = Vec::new();
    // HeaderValue is an external #[non_exhaustive]-style enum with
    // many variants; we only care about Text and TextList for
    // References headers.
    match parsed.references() {
        mail_parser::HeaderValue::Text(t) => {
            ref_ids.push(t.to_string());
        }
        mail_parser::HeaderValue::TextList(list) => {
            for r in list {
                ref_ids.push(r.to_string());
            }
        }
        // External type with many variants; other shapes are not
        // expected for References but are harmless to ignore.
        _ => {}
    }
    ref_ids.push(msg_id.to_string());

    let builder = builder.references(MessageId::new_list(ref_ids.into_iter()));

    Ok(builder)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic, reason = "tests")]
mod tests {
    use mail_builder::MessageBuilder;
    use mail_builder::headers::address::Address;
    use mail_builder::headers::message_id::MessageId;

    use super::{AddressInput, CreateDraftInput, addresses_to_builder};

    /// Build a minimal draft, parse it, verify headers round-trip.
    #[test]
    fn round_trip_simple_draft() {
        let input = CreateDraftInput {
            to: vec![AddressInput {
                name: Some("Bob".into()),
                address: "bob@example.com".into(),
            }],
            cc: Some(vec![AddressInput {
                name: None,
                address: "cc@example.com".into(),
            }]),
            bcc: None,
            subject: "Test subject".into(),
            body_text: "Hello, world!".into(),
            in_reply_to_uid: None,
            in_reply_to_folder: None,
        };

        let builder = super::build_message_headers("alice@example.com", &input);
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        // From
        let from = parsed.from().unwrap().first().unwrap();
        assert_eq!(from.address().unwrap(), "alice@example.com");

        // To
        let to = parsed.to().unwrap().first().unwrap();
        assert_eq!(to.name().unwrap(), "Bob");
        assert_eq!(to.address().unwrap(), "bob@example.com");

        // CC
        let cc = parsed.cc().unwrap().first().unwrap();
        assert_eq!(cc.address().unwrap(), "cc@example.com");

        // Subject
        assert_eq!(parsed.subject().unwrap(), "Test subject");

        // Body
        assert_eq!(parsed.body_text(0).unwrap().as_ref(), "Hello, world!");

        // Auto-generated Message-ID
        assert!(parsed.message_id().is_some());
    }

    /// Build an "original" message, then a reply, verify threading.
    #[test]
    fn threading_headers_round_trip() {
        // Simulate an original message with known Message-ID and
        // References.
        let original = MessageBuilder::new()
            .from("sender@example.com")
            .to("me@example.com")
            .message_id("original-id-123@example.com")
            .references(MessageId::new_list(["root-id@example.com"].into_iter()))
            .subject("Original")
            .text_body("original body")
            .write_to_vec()
            .unwrap();

        let parsed_original = mail_parser::MessageParser::new().parse(&original).unwrap();

        // Verify we can read the original's Message-ID.
        let orig_msg_id = parsed_original.message_id().unwrap();
        assert_eq!(orig_msg_id, "original-id-123@example.com");

        // Build the reply's threading headers manually (simulating
        // what apply_threading_headers does without IMAP).
        let mut ref_ids: Vec<String> = Vec::new();
        match parsed_original.references() {
            mail_parser::HeaderValue::Text(t) => {
                ref_ids.push(t.to_string());
            }
            mail_parser::HeaderValue::TextList(list) => {
                for r in list {
                    ref_ids.push(r.to_string());
                }
            }
            _ => {}
        }
        ref_ids.push(orig_msg_id.to_string());

        let reply = MessageBuilder::new()
            .from("me@example.com")
            .to("sender@example.com")
            .subject("Re: Original")
            .text_body("reply body")
            .in_reply_to(orig_msg_id.to_string())
            .references(MessageId::new_list(ref_ids.into_iter()))
            .write_to_vec()
            .unwrap();

        let parsed_reply = mail_parser::MessageParser::new().parse(&reply).unwrap();

        // In-Reply-To should match original's Message-ID.
        let in_reply_to = parsed_reply.in_reply_to();
        assert_eq!(
            in_reply_to.as_text().unwrap(),
            "original-id-123@example.com"
        );

        // References should contain root + original.
        match parsed_reply.references() {
            mail_parser::HeaderValue::TextList(list) => {
                let refs: Vec<&str> = list.iter().map(AsRef::as_ref).collect();
                assert_eq!(
                    refs,
                    vec!["root-id@example.com", "original-id-123@example.com",]
                );
            }
            other => panic!("expected TextList for References, got {other:?}"),
        }
    }

    /// Multiple To addresses produce a single To header with all
    /// addresses.
    #[test]
    fn multiple_to_addresses() {
        let addrs = vec![
            AddressInput {
                name: Some("A".into()),
                address: "a@example.com".into(),
            },
            AddressInput {
                name: None,
                address: "b@example.com".into(),
            },
        ];
        let addr = addresses_to_builder(&addrs);
        let builder = MessageBuilder::new()
            .from("from@example.com")
            .to(addr)
            .subject("multi")
            .text_body("body");
        let raw = builder.write_to_vec().unwrap();
        let parsed = mail_parser::MessageParser::new().parse(&raw).unwrap();

        let to_addrs = parsed.to().unwrap();
        let list = to_addrs.as_list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].address().unwrap(), "a@example.com");
        assert_eq!(list[1].address().unwrap(), "b@example.com");
    }

    /// Single address does not wrap in a list.
    #[test]
    fn single_address_no_list_wrap() {
        let addrs = vec![AddressInput {
            name: None,
            address: "solo@example.com".into(),
        }];
        let addr = addresses_to_builder(&addrs);
        if let Address::Address(email) = &addr {
            assert_eq!(email.email, "solo@example.com");
        } else {
            panic!("expected Address::Address for single input");
        }
    }
}
