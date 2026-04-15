//! Header-value extraction, sanitisation, and adversarial audits.
//!
//! These helpers are shared between `meta.rs` (which reads the RFC 5322
//! address/subject/date headers) and the parent module (which harvests
//! mailing-list headers and enforces header-count limits).

use mail_parser::{Address, HeaderValue, Message};

use crate::error::ContentError;
use crate::output::{MailingListInfo, SecurityWarning, WarningCode};
use crate::parse::meta::format_addr;
use crate::parse::{MAX_HEADER_BYTES, MAX_HEADER_COUNT};
use crate::unicode;

/// Append the domain of every address in `group` to `out`, tagging each
/// with `label`. No-op when `group` is `None`.
pub(super) fn push_domains_from(
    group: Option<&Address<'_>>,
    label: &str,
    out: &mut Vec<(String, String)>,
) {
    let Some(address) = group else { return };
    for addr in address.iter() {
        if let Some(domain) = crate::parse::meta::addr_domain(addr) {
            out.push((domain, label.to_string()));
        }
    }
}

/// Pre-extract domains from structured `Addr.address` fields for
/// all header address sources (From, To, Cc, Reply-To). Using the
/// parser's structured data is more reliable than re-parsing the
/// rendered display string.
pub(super) fn collect_header_domains(message: &Message<'_>) -> Vec<(String, String)> {
    let mut domains = Vec::new();
    push_domains_from(message.from(), "header:from", &mut domains);
    push_domains_from(message.to(), "header:to", &mut domains);
    push_domains_from(message.cc(), "header:cc", &mut domains);
    push_domains_from(message.reply_to(), "header:reply_to", &mut domains);
    domains
}

pub(super) fn enforce_header_count(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let header_count = message.headers().len();
    if header_count > MAX_HEADER_COUNT {
        warnings.push(SecurityWarning::at(
            WarningCode::ParseHeaderCountExceeded,
            format!("count={header_count} limit={MAX_HEADER_COUNT}"),
            "headers",
        ));
        return Err(ContentError::LimitExceeded {
            kind: "header_count",
            limit: MAX_HEADER_COUNT,
        });
    }
    Ok(())
}

/// Extract the first textual value from a `HeaderValue`, sanitize it,
/// and return `None` if the header is `Empty` or non-textual.
pub(super) fn header_value_first_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list.first()?.as_ref().to_string(),
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
    };
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Extract every textual value from a `HeaderValue` and sanitize each.
pub(super) fn header_value_all_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let raws: Vec<String> = match value {
        HeaderValue::Text(s) => vec![s.as_ref().to_string()],
        HeaderValue::TextList(list) => list.iter().map(|s| s.as_ref().to_string()).collect(),
        HeaderValue::Address(_)
        | HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return Vec::new(),
    };
    raws.into_iter()
        .map(|raw| {
            let (text, mut new_warnings) =
                unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

/// Extract `List-ID` / `List-Unsubscribe` / `List-Post` into a
/// `MailingListInfo`, returning `None` when none of the headers are
/// present.
pub(super) fn extract_mailing_list(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<MailingListInfo> {
    let list_id = sanitize_header_value(message.list_id(), "header:list_id", warnings);
    let list_unsubscribe = sanitize_header_value(
        message.list_unsubscribe(),
        "header:list_unsubscribe",
        warnings,
    );
    let list_post = sanitize_header_value(message.list_post(), "header:list_post", warnings);

    if list_id.is_none() && list_unsubscribe.is_none() && list_post.is_none() {
        return None;
    }
    Some(MailingListInfo {
        list_id,
        list_unsubscribe,
        list_post,
    })
}

/// Coerce a `HeaderValue` to a sanitized string. Handles `Text`,
/// `TextList`, and `Address` variants — mail-parser parses `List-*`
/// headers as addresses, so we flatten them back to a display string.
pub(super) fn sanitize_header_value(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list
            .iter()
            .map(std::convert::AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::Address(address) => address
            .iter()
            .map(|addr| {
                audit_addr_domain_bidi(addr, location, warnings);
                format_addr(addr)
            })
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::DateTime(_)
        | HeaderValue::ContentType(_)
        | HeaderValue::Received(_)
        | HeaderValue::Empty => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// If `raw_domain` contains any bidi-override codepoint, emit a
/// `LookalikeHomographDomain` warning with `reason=bidi_pre_strip`.
/// Detection must occur BEFORE `unicode::sanitize` strips the bidi
/// chars; afterwards no signal remains.
fn audit_domain_bidi_prestrip(
    raw_domain: &str,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    if !crate::parse::filename::contains_bidi_override(raw_domain) {
        return;
    }
    let ascii = idna::domain_to_ascii(raw_domain.trim()).unwrap_or_else(|_| "invalid".to_string());
    warnings.push(SecurityWarning::at(
        WarningCode::LookalikeHomographDomain,
        format!("domain={ascii},reason=bidi_pre_strip"),
        location,
    ));
}

/// Extract the domain from a `mail_parser::Addr` and run the
/// pre-strip bidi audit. No-op when the address is missing or has no
/// `@` separator.
pub(super) fn audit_addr_domain_bidi(
    addr: &mail_parser::Addr<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) {
    let Some(email) = addr.address.as_deref() else {
        return;
    };
    let Some((_local, domain)) = email.rsplit_once('@') else {
        return;
    };
    audit_domain_bidi_prestrip(domain, location, warnings);
}
