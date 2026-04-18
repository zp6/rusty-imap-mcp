//! RFC 6154 special-use mailbox attributes and per-account resolution.
//!
//! Special-use attributes (`\Drafts`, `\Sent`, `\Trash`, `\Junk`,
//! `\Archive`, `\All`, `\Flagged`) identify a mailbox's role without
//! relying on server-specific naming conventions. Gmail's `[Gmail]/Drafts`,
//! Proton's `Drafts`, and Dovecot's `Drafts` all carry `\Drafts`; clients
//! can target "the drafts folder" without hardcoding a name per server.

use async_imap::types::NameAttribute;

/// RFC 6154 special-use attribute, plus the pseudo-attribute for
/// unrecognized `\Sent`/`\Drafts`-style extension strings that some
/// servers emit instead of the structured enum variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecialUse {
    /// `\Drafts` — the mailbox where draft messages live.
    Drafts,
    /// `\Sent` — the mailbox where copies of outgoing messages live.
    Sent,
    /// `\Trash` — the mailbox for deleted messages.
    Trash,
    /// `\Junk` — the mailbox for spam.
    Junk,
    /// `\Archive` — the archive mailbox.
    Archive,
    /// `\All` — aggregate view (Gmail's "All Mail").
    All,
    /// `\Flagged` — aggregate view of flagged/starred messages.
    Flagged,
}

/// Classify the first recognized RFC 6154 special-use marker in the
/// attribute list. Returns `None` if no special-use marker is present.
///
/// Checks both the structured `NameAttribute` variants and
/// `Extension("\\Drafts")`-style strings (case-insensitive). Some
/// servers are known to report RFC 6154 attributes as raw extension
/// strings rather than the structured variant; the extension arm keeps
/// us compatible with that shape without requiring a protocol upgrade.
#[must_use]
pub fn classify_special_use(attrs: &[NameAttribute<'_>]) -> Option<SpecialUse> {
    attrs.iter().find_map(match_variant)
}

fn match_variant(attr: &NameAttribute<'_>) -> Option<SpecialUse> {
    match attr {
        NameAttribute::Drafts => Some(SpecialUse::Drafts),
        NameAttribute::Sent => Some(SpecialUse::Sent),
        NameAttribute::Trash => Some(SpecialUse::Trash),
        NameAttribute::Junk => Some(SpecialUse::Junk),
        NameAttribute::Archive => Some(SpecialUse::Archive),
        NameAttribute::All => Some(SpecialUse::All),
        NameAttribute::Flagged => Some(SpecialUse::Flagged),
        NameAttribute::Extension(ext) => match_extension(ext),
        _ => None,
    }
}

fn match_extension(ext: &str) -> Option<SpecialUse> {
    if ext.eq_ignore_ascii_case("\\Drafts") {
        Some(SpecialUse::Drafts)
    } else if ext.eq_ignore_ascii_case("\\Sent") {
        Some(SpecialUse::Sent)
    } else if ext.eq_ignore_ascii_case("\\Trash") {
        Some(SpecialUse::Trash)
    } else if ext.eq_ignore_ascii_case("\\Junk") {
        Some(SpecialUse::Junk)
    } else if ext.eq_ignore_ascii_case("\\Archive") {
        Some(SpecialUse::Archive)
    } else if ext.eq_ignore_ascii_case("\\All") {
        Some(SpecialUse::All)
    } else if ext.eq_ignore_ascii_case("\\Flagged") {
        Some(SpecialUse::Flagged)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_each_rfc6154_variant() {
        for (attr, expected) in [
            (NameAttribute::Drafts, SpecialUse::Drafts),
            (NameAttribute::Sent, SpecialUse::Sent),
            (NameAttribute::Trash, SpecialUse::Trash),
            (NameAttribute::Junk, SpecialUse::Junk),
            (NameAttribute::Archive, SpecialUse::Archive),
            (NameAttribute::All, SpecialUse::All),
            (NameAttribute::Flagged, SpecialUse::Flagged),
        ] {
            let attrs = [attr.clone()];
            assert_eq!(classify_special_use(&attrs), Some(expected));
        }
    }

    #[test]
    fn classify_matches_extension_strings_case_insensitive() {
        let attrs = [NameAttribute::Extension("\\drafts".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));

        let attrs = [NameAttribute::Extension("\\SENT".into())];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Sent));
    }

    #[test]
    fn classify_returns_none_for_unrelated_attributes() {
        let attrs = [
            NameAttribute::Unmarked,
            NameAttribute::Extension("\\HasNoChildren".into()),
        ];
        assert_eq!(classify_special_use(&attrs), None);
    }

    #[test]
    fn classify_returns_first_match_when_multiple_present() {
        // \Drafts + \Sent on the same mailbox is pathological but possible
        // in misconfigured servers; we take the first match in iteration
        // order rather than erroring, to stay useful.
        let attrs = [NameAttribute::Drafts, NameAttribute::Sent];
        assert_eq!(classify_special_use(&attrs), Some(SpecialUse::Drafts));
    }

    #[test]
    fn classify_empty_attribute_list_returns_none() {
        assert_eq!(classify_special_use(&[]), None);
    }
}
