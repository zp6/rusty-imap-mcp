//! `SEARCH` (structured + raw passthrough).

use std::fmt::Write;

use crate::connection::ImapSession;
use crate::error::Error;
use crate::types::{SearchQuery, StructuredQuery, Uid};

pub(crate) async fn search(
    session: &mut ImapSession,
    folder: &str,
    query: SearchQuery,
) -> Result<Vec<Uid>, Error> {
    // Caller should have sent SELECT via the public API; this is a defensive
    // re-EXAMINE to keep the search scoped to the requested folder.
    session
        .examine(folder)
        .await
        .map_err(super::folders::map_err)?;

    let key = match query {
        SearchQuery::Structured(s) => structured_to_key(&s)?,
        SearchQuery::Raw(r) => r,
    };

    let uids = session
        .uid_search(&key)
        .await
        .map_err(super::folders::map_err)?;
    Ok(uids.into_iter().filter_map(Uid::new).collect())
}

fn structured_to_key(q: &StructuredQuery) -> Result<String, Error> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = &q.from {
        parts.push(format!("FROM {}", quote(s)?));
    }
    if let Some(s) = &q.to {
        parts.push(format!("TO {}", quote(s)?));
    }
    if let Some(s) = &q.subject {
        parts.push(format!("SUBJECT {}", quote(s)?));
    }
    if let Some(d) = q.since {
        parts.push(format!("SINCE {}", format_imap_date(d)));
    }
    if let Some(d) = q.before {
        parts.push(format!("BEFORE {}", format_imap_date(d)));
    }
    match q.seen {
        Some(true) => parts.push("SEEN".to_string()),
        Some(false) => parts.push("UNSEEN".to_string()),
        None => {}
    }
    if q.has_attachment {
        // Heuristic: scan the message body for the literal Content-Disposition
        // header. False negatives for unusual capitalization or nested MIME
        // structures are accepted — see StructuredQuery::has_attachment doc.
        parts.push("BODY \"Content-Disposition: attachment\"".to_string());
    }
    if parts.is_empty() {
        return Ok("ALL".to_string());
    }
    Ok(parts.join(" "))
}

fn quote(s: &str) -> Result<String, Error> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == b'\0') {
        return Err(Error::InvalidInput {
            field: "search string",
            reason: "contains forbidden control bytes (CR/LF/NUL)",
        });
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

fn format_imap_date(d: ::time::Date) -> String {
    // IMAP SEARCH dates use "DD-Mon-YYYY" with English month abbreviations.
    let month = match d.month() {
        ::time::Month::January => "Jan",
        ::time::Month::February => "Feb",
        ::time::Month::March => "Mar",
        ::time::Month::April => "Apr",
        ::time::Month::May => "May",
        ::time::Month::June => "Jun",
        ::time::Month::July => "Jul",
        ::time::Month::August => "Aug",
        ::time::Month::September => "Sep",
        ::time::Month::October => "Oct",
        ::time::Month::November => "Nov",
        ::time::Month::December => "Dec",
    };
    let mut out = String::with_capacity(11);
    let _ = write!(out, "{:02}-{}-{}", d.day(), month, d.year());
    out
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{format_imap_date, quote, structured_to_key};
    use crate::error::Error;
    use crate::types::StructuredQuery;

    #[test]
    fn structured_to_key_empty_query_yields_all() {
        let q = StructuredQuery::default();
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn structured_to_key_quotes_string_fields() {
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            subject: Some("hello world".to_string()),
            ..StructuredQuery::default()
        };
        let key = structured_to_key(&q).unwrap();
        assert!(key.contains("FROM \"alice@example.com\""), "got {key}");
        assert!(key.contains("SUBJECT \"hello world\""), "got {key}");
    }

    #[test]
    fn structured_to_key_emits_seen_or_unseen_per_option() {
        let q = StructuredQuery {
            seen: Some(true),
            ..StructuredQuery::default()
        };
        assert_eq!(structured_to_key(&q).unwrap(), "SEEN");
        let q = StructuredQuery {
            seen: Some(false),
            ..StructuredQuery::default()
        };
        assert_eq!(structured_to_key(&q).unwrap(), "UNSEEN");
        let q = StructuredQuery::default();
        assert_eq!(structured_to_key(&q).unwrap(), "ALL");
    }

    #[test]
    fn quote_escapes_backslash_and_double_quote() {
        assert_eq!(quote(r#"a"b\c"#).unwrap(), r#""a\"b\\c""#);
    }

    #[test]
    fn format_imap_date_uses_dd_mon_yyyy() {
        let d = ::time::Date::from_calendar_date(2026, ::time::Month::April, 7).unwrap();
        assert_eq!(format_imap_date(d), "07-Apr-2026");
    }

    #[test]
    fn structured_to_key_combines_multiple_criteria() {
        let q = StructuredQuery {
            from: Some("alice@example.com".to_string()),
            since: Some(::time::Date::from_calendar_date(2026, ::time::Month::January, 1).unwrap()),
            seen: Some(false),
            ..StructuredQuery::default()
        };
        assert_eq!(
            structured_to_key(&q).unwrap(),
            r#"FROM "alice@example.com" SINCE 01-Jan-2026 UNSEEN"#
        );
    }

    #[test]
    #[expect(clippy::panic, reason = "test failure path")]
    fn quote_rejects_embedded_newline() {
        let Err(Error::InvalidInput { field, reason }) = quote("injected\r\nNOOP") else {
            panic!("expected InvalidInput error");
        };
        assert_eq!(field, "search string");
        assert!(reason.contains("CR/LF/NUL"), "reason was: {reason}");
    }

    #[test]
    fn quote_rejects_embedded_lf() {
        assert!(quote("a\nb").is_err());
    }

    #[test]
    fn quote_rejects_embedded_nul() {
        assert!(quote("a\0b").is_err());
    }

    #[test]
    fn quote_accepts_clean_ascii() {
        assert_eq!(quote("Sprint 3").unwrap(), "\"Sprint 3\"");
    }

    #[test]
    fn quote_escapes_backslash_and_quote() {
        assert_eq!(quote(r#"a\b"c"#).unwrap(), r#""a\\b\"c""#);
    }
}
