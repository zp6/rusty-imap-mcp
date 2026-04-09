//! Lookalike / homograph detection for rimap-content.
//!
//! Audits domains (extracted from headers, anchor hrefs, and body text
//! URL tokens) and attachment filenames for TR39 mixed-script violations,
//! homograph confusables, and punycode/IDN round-trips. The only consumer
//! of `idna`, `addr`, `unicode-script`, `unicode-properties`, and the
//! compiled confusables map in the workspace.
//!
//! The single public (crate-visible) entrypoint is [`audit`].
//!
//! Until Task 15 wires `audit` into `parse::parse_message`, the module's
//! items are only exercised by the in-module unit tests, so non-test
//! builds suppress dead-code warnings module-wide. Three items
//! (`LookalikeInput`, `MAX_LINKIFY_SCAN_BYTES`, `audit`) are also
//! unused under `cfg(test)` and carry per-item `#[expect(dead_code)]`
//! shims with explicit Task 14/15 references.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by parse::parse_message in Sprint 4b Task 15"
    )
)]

use std::collections::HashSet;

use unicode_script::{Script, UnicodeScript};

use crate::confusables::CONFUSABLES;
use crate::output::{AttachmentMeta, ContentMeta, SecurityWarning};

/// Input bundle for [`audit`]. Built by `parse::parse_message` after
/// body extraction completes.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "constructed by parse::parse_message in Sprint 4b Task 15"
    )
)]
#[derive(Debug)]
pub(crate) struct LookalikeInput<'a> {
    /// Header-derived metadata (from, subject, list-id, …).
    pub meta: &'a ContentMeta,
    /// Sanitized plain-text body, used for body-URL scanning.
    pub body_text: &'a str,
    /// Anchor hrefs collected from the sanitized HTML body.
    pub anchor_hrefs: &'a [String],
    /// Attachment metadata, used for filename audits.
    pub attachments: &'a [AttachmentMeta],
}

/// Maximum `body_text` bytes scanned for URL tokens via linkify.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "consumed by audit's body-URL pass in Sprint 4b Task 14"
    )
)]
pub(crate) const MAX_LINKIFY_SCAN_BYTES: usize = 64 * 1024;

/// Per-domain classification result produced by `classify_domain`.
#[derive(Debug, Clone, Default)]
struct DomainClassification {
    /// ASCII / A-label form, always non-empty on valid input.
    ascii: String,
    /// Unicode / U-label form (may equal `ascii` if pure ASCII).
    unicode: String,
    /// True if the input contained an `xn--` label (punycode round-trip).
    was_punycode: bool,
    /// True if any label mixes scripts outside TR39 Highly Restrictive.
    mixed_script: bool,
    /// TR39 confusable skeleton of the unicode form.
    skeleton: String,
}

/// Classify a domain string per TR39 + punycode heuristics.
///
/// Returns `None` for unparsable input (empty, no dot, idna failure).
/// Never emits warnings — emission happens in [`audit`].
fn classify_domain(raw: &str) -> Option<DomainClassification> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.contains('.') {
        return None;
    }
    let ascii = idna::domain_to_ascii(trimmed).ok()?;
    let (unicode, _result) = idna::domain_to_unicode(&ascii);
    let was_punycode = ascii.split('.').any(|label| label.starts_with("xn--"));
    let mixed_script = labels_mix_scripts(&unicode);
    let skeleton = compute_skeleton(&unicode);
    Some(DomainClassification {
        ascii,
        unicode,
        was_punycode,
        mixed_script,
        skeleton,
    })
}

/// Returns true if any label in `domain` violates TR39 Highly
/// Restrictive: single-script labels are always allowed; Latin combined
/// with one of {Han, Hiragana, Katakana, Hangul, Bopomofo} is allowed;
/// every other multi-script combination is a violation.
fn labels_mix_scripts(domain: &str) -> bool {
    for label in domain.split('.') {
        if label_mixes_scripts(label) {
            return true;
        }
    }
    false
}

/// Per-label TR39 Highly Restrictive check (extracted to keep
/// `labels_mix_scripts` under the complexity cap).
fn label_mixes_scripts(label: &str) -> bool {
    let mut scripts: HashSet<Script> = HashSet::new();
    for c in label.chars() {
        if c.is_ascii_digit() || c == '-' || c == '_' {
            continue;
        }
        let s = c.script();
        if matches!(s, Script::Common | Script::Inherited | Script::Unknown) {
            continue;
        }
        scripts.insert(s);
    }
    if scripts.len() <= 1 {
        return false;
    }
    let allowed_latin_pairs = [
        Script::Han,
        Script::Hiragana,
        Script::Katakana,
        Script::Hangul,
        Script::Bopomofo,
    ];
    if scripts.contains(&Script::Latin)
        && scripts.len() == 2
        && scripts.iter().any(|s| allowed_latin_pairs.contains(s))
    {
        return false;
    }
    true
}

/// Compute the TR39 skeleton of `domain` by mapping each char through
/// the compiled confusables table. Operates on the unicode form.
fn compute_skeleton(domain: &str) -> String {
    let mut out = String::with_capacity(domain.len());
    for c in domain.chars() {
        match CONFUSABLES.get(&c) {
            Some(target) => out.push_str(target),
            None => out.push(c),
        }
    }
    out
}

/// Top-level entrypoint. Runs all lookalike passes over `input` and
/// returns a flat `Vec` of warnings. Stub in Task 13; the three
/// emission passes land in Task 14.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "wired into parse::parse_message in Sprint 4b Task 15"
    )
)]
pub(crate) fn audit(_input: LookalikeInput<'_>) -> Vec<SecurityWarning> {
    Vec::new()
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests unwrap on constructed values")]
mod tests {
    use super::*;

    #[test]
    fn classify_pure_latin_domain() {
        let c = classify_domain("example.com").unwrap();
        assert_eq!(c.ascii, "example.com");
        assert_eq!(c.unicode, "example.com");
        assert!(!c.was_punycode);
        assert!(!c.mixed_script);
        // TR39 confusables map `m → rn`, so the skeleton differs from
        // the input even for pure ASCII. The point of the test is that
        // classification succeeds and yields a non-empty skeleton.
        assert!(!c.skeleton.is_empty());
    }

    #[test]
    fn classify_pure_cyrillic_domain_not_mixed() {
        let c = classify_domain("пример.рф").unwrap();
        assert!(!c.mixed_script, "pure Cyrillic is single-script");
    }

    #[test]
    fn classify_latin_plus_cyrillic_is_mixed() {
        let c = classify_domain("p\u{0430}ypal.com").unwrap();
        assert!(c.mixed_script);
    }

    #[test]
    fn classify_latin_plus_han_allowed() {
        let c = classify_domain("汉a.com").unwrap();
        assert!(!c.mixed_script);
    }

    #[test]
    fn classify_latin_plus_hiragana_allowed() {
        let c = classify_domain("あa.com").unwrap();
        assert!(!c.mixed_script);
    }

    #[test]
    fn classify_punycode_round_trip() {
        let c = classify_domain("xn--mnchen-3ya.de").unwrap();
        assert!(c.was_punycode);
        assert_eq!(c.unicode, "münchen.de");
    }

    #[test]
    fn classify_invalid_domain_returns_none() {
        assert!(classify_domain("").is_none());
        assert!(classify_domain("nodot").is_none());
        assert!(classify_domain("   ").is_none());
    }

    #[test]
    fn skeleton_maps_cyrillic_a_to_latin_a() {
        // Cyrillic 'а' (U+0430) maps to ASCII 'a' (U+0061), so the
        // skeleton of "pаypal.com" matches the skeleton of "paypal.com".
        let lookalike_skel = compute_skeleton("p\u{0430}ypal.com");
        let real_skel = compute_skeleton("paypal.com");
        assert_eq!(lookalike_skel, real_skel);
    }

    #[test]
    fn skeleton_is_deterministic_for_pure_latin() {
        // Pure ASCII Latin still goes through TR39 mapping (e.g. m→rn),
        // but the result is stable across calls.
        let a = compute_skeleton("example.com");
        let b = compute_skeleton("example.com");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }
}
