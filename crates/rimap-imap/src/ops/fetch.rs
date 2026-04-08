//! `FETCH ENVELOPE BODYSTRUCTURE UID FLAGS RFC822.SIZE`. The streaming
//! `FETCH BODY[]` path is in Task 13.

use futures_util::StreamExt;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{Address, BodyStructure, Envelope, FetchSpec, FetchedMessage, MessageId, Uid};

pub(crate) async fn fetch(
    session: &mut ImapSession,
    folder: &str,
    uids: &[Uid],
    spec: FetchSpec,
) -> Result<Vec<FetchedMessage>, Error> {
    session
        .examine(folder)
        .await
        .map_err(super::folders::map_err)?;

    if uids.is_empty() {
        return Ok(Vec::new());
    }
    // TODO(T15): compress to range syntax (e.g., "1:5,7,9:12") to stay
    // under Dovecot's ~8KB command-line limit when fetching large UID
    // sets. Plain comma-joined lists exceed the cap around ~2000 UIDs.
    let uid_set = uids
        .iter()
        .map(|u| u.get().to_string())
        .collect::<Vec<_>>()
        .join(",");

    let items = build_fetch_items(spec);
    let mut stream = session
        .uid_fetch(&uid_set, &items)
        .await
        .map_err(super::folders::map_err)?;

    let mut out = Vec::with_capacity(uids.len());
    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        let Some(uid_raw) = msg.uid else {
            continue;
        };
        let Some(uid) = Uid::new(uid_raw) else {
            continue;
        };

        let envelope = if spec.envelope {
            convert_envelope(msg.envelope())
        } else {
            None
        };
        let bodystructure = if spec.bodystructure {
            convert_bodystructure(msg.bodystructure())
        } else {
            None
        };
        let flags = if spec.flags {
            Some(msg.flags().map(|f| convert_flag(&f)).collect())
        } else {
            None
        };
        let size = if spec.size { msg.size } else { None };

        out.push(FetchedMessage {
            uid,
            envelope,
            bodystructure,
            flags,
            size,
        });
    }
    Ok(out)
}

/// Fetch the full `BODY[]` of a single UID. Aborts with `Error::SizeLimit`
/// if the projected total would exceed `limit`. The caller MUST drop the
/// session on overflow — the IMAP response state is half-consumed and
/// cannot be reused.
///
/// # Errors
/// - `Error::SizeLimit { limit }` if the body exceeds `limit` bytes.
/// - `Error::Protocol(_)` if the server returned no body data for the UID.
/// - `Error::ConnectionLost` if the underlying transport tore down.
/// - Other `async-imap` errors propagated through `super::folders::map_err`.
///
/// NOTE: `async-imap` delivers each `Fetch` response as a parsed unit, so
/// the body bytes are already in memory before the size check fires. The
/// limit acts as an accept/reject gate, not a backpressure mechanism. A
/// future async-imap version with chunked body streaming would let us
/// enforce the limit mid-network-read.
pub(crate) async fn fetch_body(
    session: &mut ImapSession,
    folder: &str,
    uid: Uid,
    limit: u64,
) -> Result<Vec<u8>, Error> {
    session
        .examine(folder)
        .await
        .map_err(super::folders::map_err)?;

    let mut stream = session
        .uid_fetch(uid.get().to_string(), "BODY.PEEK[]")
        .await
        .map_err(super::folders::map_err)?;

    let mut acc: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    let mut found = false;

    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(super::folders::map_err)?;
        if let Some(body) = msg.body() {
            found = true;
            let new_total = project_size(total, body.len(), limit)?;
            acc.extend_from_slice(body);
            total = new_total;
        }
    }

    if !found {
        return Err(Error::Protocol(async_imap::error::Error::Bad(
            "FETCH BODY[] returned no body".to_string(),
        )));
    }
    Ok(acc)
}

/// Projection helper: extend `total` by `chunk` and return the new total,
/// or `Err(Error::SizeLimit { limit })` if it would exceed `limit`.
/// Saturates `chunk` at `u64::MAX` to handle hypothetical platforms where
/// `usize > u64`.
fn project_size(total: u64, chunk: usize, limit: u64) -> Result<u64, Error> {
    let chunk_u64 = u64::try_from(chunk).unwrap_or(u64::MAX);
    let projected = total.saturating_add(chunk_u64);
    if projected > limit {
        Err(Error::SizeLimit { limit })
    } else {
        Ok(projected)
    }
}

fn build_fetch_items(spec: FetchSpec) -> String {
    let mut parts: Vec<&str> = vec!["UID"]; // always request UID
    if spec.envelope {
        parts.push("ENVELOPE");
    }
    if spec.bodystructure {
        parts.push("BODYSTRUCTURE");
    }
    if spec.flags {
        parts.push("FLAGS");
    }
    if spec.size {
        parts.push("RFC822.SIZE");
    }
    format!("({})", parts.join(" "))
}

// ENVELOPE conversion.
fn convert_envelope(env: Option<&async_imap::imap_proto::Envelope<'_>>) -> Option<Envelope> {
    let env = env?;
    Some(Envelope {
        date: env.date.as_ref().map(|b| b.to_vec()),
        subject_raw: env.subject.as_ref().map(|b| b.to_vec()),
        from: convert_addresses(env.from.as_deref()),
        sender: convert_addresses(env.sender.as_deref()),
        reply_to: convert_addresses(env.reply_to.as_deref()),
        to: convert_addresses(env.to.as_deref()),
        cc: convert_addresses(env.cc.as_deref()),
        bcc: convert_addresses(env.bcc.as_deref()),
        in_reply_to: env.in_reply_to.as_ref().map(|b| b.to_vec()),
        message_id: env.message_id.as_ref().map(|b| MessageId::new(b.to_vec())),
    })
}

fn convert_addresses(addrs: Option<&[async_imap::imap_proto::Address<'_>]>) -> Vec<Address> {
    addrs
        .unwrap_or(&[])
        .iter()
        .map(|a| Address {
            name: a.name.as_ref().map(|b| b.to_vec()),
            adl: a.adl.as_ref().map(|b| b.to_vec()),
            mailbox: a.mailbox.as_ref().map(|b| b.to_vec()),
            host: a.host.as_ref().map(|b| b.to_vec()),
        })
        .collect()
}

// BODYSTRUCTURE recursive conversion. Walk the imap_proto BodyStructure enum
// and produce our own BodyStructure type.
fn convert_bodystructure(
    bs: Option<&async_imap::imap_proto::BodyStructure<'_>>,
) -> Option<BodyStructure> {
    bs.map(convert_bs_inner)
}

fn convert_bs_inner(bs: &async_imap::imap_proto::BodyStructure<'_>) -> crate::types::BodyStructure {
    use async_imap::imap_proto::BodyStructure as ImapProtoBodyStructure;

    match bs {
        ImapProtoBodyStructure::Multipart {
            common,
            bodies,
            extension: _,
        } => {
            let subtype = common.ty.subtype.to_string();
            let parts = bodies.iter().map(convert_bs_inner).collect();
            crate::types::BodyStructure::Multipart { subtype, parts }
        }
        ImapProtoBodyStructure::Basic {
            common,
            other,
            extension: _,
        }
        | ImapProtoBodyStructure::Text {
            common,
            other,
            lines: _,
            extension: _,
        } => {
            let mime_type = common.ty.ty.to_string();
            let mime_subtype = common.ty.subtype.to_string();
            let params = common
                .ty
                .params
                .as_ref()
                .map(|p| {
                    p.iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let encoding = match &other.transfer_encoding {
                async_imap::imap_proto::ContentEncoding::SevenBit => "7bit".to_string(),
                async_imap::imap_proto::ContentEncoding::EightBit => "8bit".to_string(),
                async_imap::imap_proto::ContentEncoding::Binary => "binary".to_string(),
                async_imap::imap_proto::ContentEncoding::Base64 => "base64".to_string(),
                async_imap::imap_proto::ContentEncoding::QuotedPrintable => {
                    "quoted-printable".to_string()
                }
                async_imap::imap_proto::ContentEncoding::Other(s) => s.to_string(),
            };
            let size = other.octets;
            crate::types::BodyStructure::Single {
                mime_type,
                mime_subtype,
                params,
                encoding,
                size,
            }
        }
        ImapProtoBodyStructure::Message { common, body, .. } => {
            let mime_subtype = common.ty.subtype.to_string();
            crate::types::BodyStructure::Message {
                mime_subtype,
                body: Box::new(convert_bs_inner(body)),
            }
        }
    }
}

// FLAG conversion. Match against the typed async_imap::types::Flag enum.
fn convert_flag(f: &async_imap::types::Flag<'_>) -> crate::types::Flag {
    use async_imap::types::Flag as AsyncImapFlag;

    match f {
        AsyncImapFlag::Seen => crate::types::Flag::Seen,
        AsyncImapFlag::Answered => crate::types::Flag::Answered,
        AsyncImapFlag::Flagged => crate::types::Flag::Flagged,
        AsyncImapFlag::Deleted => crate::types::Flag::Deleted,
        AsyncImapFlag::Draft => crate::types::Flag::Draft,
        AsyncImapFlag::Recent => crate::types::Flag::Recent,
        AsyncImapFlag::MayCreate => crate::types::Flag::Keyword("\\*".to_string()),
        AsyncImapFlag::Custom(s) => crate::types::Flag::Keyword(s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{convert_bs_inner, project_size};
    use crate::error::Error;
    use async_imap::imap_proto::{
        BodyContentCommon, BodyContentSinglePart, BodyStructure as ImapProtoBodyStructure,
        ContentEncoding, ContentType,
    };
    use std::borrow::Cow;

    #[test]
    #[expect(clippy::panic, reason = "test")]
    fn convert_bs_inner_preserves_message_variant_with_nested_body() {
        // Construct an inner Basic text/plain part
        let inner_bs = ImapProtoBodyStructure::Basic {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("text"),
                    subtype: Cow::Borrowed("plain"),
                    params: None,
                },
                disposition: None,
                language: None,
                location: None,
            },
            other: BodyContentSinglePart {
                id: None,
                md5: None,
                description: None,
                transfer_encoding: ContentEncoding::SevenBit,
                octets: 42,
            },
            extension: None,
        };

        // Construct a Message body with the Basic part inside
        let msg_bs = ImapProtoBodyStructure::Message {
            common: BodyContentCommon {
                ty: ContentType {
                    ty: Cow::Borrowed("message"),
                    subtype: Cow::Borrowed("rfc822"),
                    params: None,
                },
                disposition: None,
                language: None,
                location: None,
            },
            other: BodyContentSinglePart {
                id: None,
                md5: None,
                description: None,
                transfer_encoding: ContentEncoding::SevenBit,
                octets: 1024,
            },
            envelope: async_imap::imap_proto::Envelope {
                date: None,
                subject: None,
                from: None,
                sender: None,
                reply_to: None,
                to: None,
                cc: None,
                bcc: None,
                in_reply_to: None,
                message_id: None,
            },
            body: Box::new(inner_bs),
            lines: 10,
            extension: None,
        };

        let result = convert_bs_inner(&msg_bs);

        // Verify the Message variant is preserved and the nested body is intact
        match result {
            crate::types::BodyStructure::Message { mime_subtype, body } => {
                assert_eq!(mime_subtype, "rfc822");
                match body.as_ref() {
                    crate::types::BodyStructure::Single {
                        mime_type,
                        mime_subtype: inner_subtype,
                        size,
                        ..
                    } => {
                        assert_eq!(mime_type, "text");
                        assert_eq!(inner_subtype, "plain");
                        assert_eq!(*size, 42);
                    }
                    other => panic!("expected inner Single variant, got {other:?}"),
                }
            }
            other => panic!("expected Message variant, got {other:?}"),
        }
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn project_size_under_limit_returns_new_total() {
        let result = project_size(100, 50, 1000).unwrap();
        assert_eq!(result, 150);
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests")]
    fn project_size_at_exact_limit_is_accepted() {
        let result = project_size(950, 50, 1000).unwrap();
        assert_eq!(result, 1000);
    }

    #[test]
    #[expect(clippy::panic, reason = "tests")]
    fn project_size_over_limit_returns_size_limit_error() {
        let result = project_size(950, 51, 1000);
        match result {
            Err(Error::SizeLimit { limit }) => assert_eq!(limit, 1000),
            other => panic!("expected SizeLimit, got {other:?}"),
        }
    }
}
