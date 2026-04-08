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
        }
        | ImapProtoBodyStructure::Message {
            common,
            other,
            envelope: _,
            body: _,
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
