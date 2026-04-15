//! Structured-metadata extraction (`ContentMeta`).
//!
//! Reads the RFC 5322 address / subject / date / message-id headers
//! off a parsed `mail_parser::Message` and funnels every resulting
//! string through [`crate::unicode::sanitize`]. Address helpers
//! (`format_addr`, `addr_domain`) are shared with `headers.rs`.

use mail_parser::{Address, Message};
use time::OffsetDateTime;

use crate::output::{ContentMeta, SecurityWarning};
use crate::parse::MAX_HEADER_BYTES;
use crate::parse::attachments::extract_attachments;
use crate::parse::headers::{
    audit_addr_domain_bidi, extract_mailing_list, header_value_all_text, header_value_first_text,
};
use crate::unicode;

pub(super) fn extract_meta(
    message: &Message<'_>,
    original_size_bytes: u64,
    warnings: &mut Vec<SecurityWarning>,
) -> ContentMeta {
    let from = first_address_string(message.from(), "header:from", warnings);
    let to = address_strings(message.to(), "header:to", warnings);
    let cc = address_strings(message.cc(), "header:cc", warnings);
    let reply_to = first_address_string(message.reply_to(), "header:reply_to", warnings);
    let subject = sanitize_opt_str(message.subject(), "header:subject", warnings);
    let date = message.date().and_then(convert_datetime);
    let message_id = sanitize_opt_str(message.message_id(), "header:message_id", warnings);
    let in_reply_to =
        header_value_first_text(message.in_reply_to(), "header:in_reply_to", warnings);
    let references = header_value_all_text(message.references(), "header:references", warnings);
    let mailing_list = extract_mailing_list(message, warnings);
    let attachments = extract_attachments(message, warnings);

    ContentMeta {
        from,
        to,
        cc,
        reply_to,
        subject,
        date,
        message_id,
        in_reply_to,
        references,
        mailing_list,
        attachments,
        original_size_bytes,
        body_truncated: false,
    }
}

/// Sanitize an optional header string, appending any warnings.
fn sanitize_opt_str(
    value: Option<&str>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let value = value?;
    let (text, mut new_warnings) =
        unicode::sanitize(value.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Flatten an `Address` (list or group) into a sequence of display
/// strings and sanitize each one.
fn address_strings(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let Some(address) = address else {
        return Vec::new();
    };
    address
        .iter()
        .map(|addr| {
            audit_addr_domain_bidi(addr, location, warnings);
            let raw = format_addr(addr);
            let (text, mut new_warnings) =
                unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

/// Sanitize the first address in an `Address` value (if any).
fn first_address_string(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let addr = address?.first()?;
    audit_addr_domain_bidi(addr, location, warnings);
    let raw = format_addr(addr);
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Render a single `Addr` as `"Name <email@host>"` or just
/// `"email@host"` if the display name is absent or empty.
pub(super) fn format_addr(addr: &mail_parser::Addr<'_>) -> String {
    let email = addr.address.as_deref().unwrap_or("");
    match addr.name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
        Some(_) | None => email.to_string(),
    }
}

/// Extract the domain portion from a structured `mail_parser::Addr`.
pub(super) fn addr_domain(addr: &mail_parser::Addr<'_>) -> Option<String> {
    let email = addr.address.as_deref()?;
    let (_local, domain) = email.rsplit_once('@')?;
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// Convert a `mail_parser::DateTime` into a UTC `OffsetDateTime`,
/// returning `None` for invalid or out-of-range values.
fn convert_datetime(dt: &mail_parser::DateTime) -> Option<OffsetDateTime> {
    if !dt.is_valid() {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(dt.to_timestamp()).ok()
}
