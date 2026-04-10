//! Lookalike / homograph detection for rimap-content.
//!
//! Audits domains (extracted from headers, anchor hrefs, and body text
//! URL tokens) and attachment filenames for TR39 mixed-script violations,
//! homograph confusables, and punycode/IDN round-trips. The only consumer
//! of `idna`, `addr`, `unicode-script`, `unicode-properties`, and the
//! compiled confusables map in the workspace.
//!
//! The single public (crate-visible) entrypoint is [`audit`].

use std::collections::HashSet;

use linkify::{LinkFinder, LinkKind};

use unicode_script::{Script, UnicodeScript};

use crate::confusables::CONFUSABLES;
use crate::output::{ContentMeta, SecurityWarning, WarningCode};

/// Input bundle for [`audit`]. Built by `parse::parse_message` after
/// body extraction completes.
#[derive(Debug)]
pub(crate) struct LookalikeInput<'a> {
    /// Header-derived metadata (from, subject, list-id, …).
    #[expect(dead_code, reason = "retained for future homograph comparison passes")]
    pub meta: &'a ContentMeta,
    /// Sanitized plain-text body, used for body-URL scanning.
    pub body_text: &'a str,
    /// Anchor hrefs collected from the sanitized HTML body.
    pub anchor_hrefs: &'a [String],
    /// Pre-extracted header address domains with their locations.
    /// Built at the `parse_message` boundary using structured
    /// `Addr.address` data rather than re-parsing rendered strings.
    pub header_domains: Vec<(String, String)>,
}

/// Maximum `body_text` bytes scanned for URL tokens via linkify.
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
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by homograph comparison in Sprint 4b Task 16"
        )
    )]
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

/// Top-level entrypoint. Runs three lookalike passes (header address
/// domains, anchor hrefs, body URL tokens) and returns a flat `Vec`
/// of warnings.
pub(crate) fn audit(input: &LookalikeInput<'_>) -> Vec<SecurityWarning> {
    let mut out: Vec<SecurityWarning> = Vec::new();
    scan_header_domains(input, &mut out);
    scan_anchor_hrefs(input.anchor_hrefs, &mut out);
    scan_body_urls(input.body_text, &mut out);
    out
}

/// Pass 1: classify pre-extracted header address domains from
/// `LookalikeInput::header_domains` (built at the parse boundary
/// using structured `Addr.address` data).
fn scan_header_domains(input: &LookalikeInput<'_>, out: &mut Vec<SecurityWarning>) {
    for (domain, location) in &input.header_domains {
        emit_classification(domain, location, out);
    }
}

/// Pass 2: classify anchor hrefs collected by the HTML sanitizer.
fn scan_anchor_hrefs(hrefs: &[String], out: &mut Vec<SecurityWarning>) {
    for href in hrefs {
        if let Some(domain) = extract_domain_from_url(href) {
            emit_classification(&domain, "html:anchor_href", out);
        }
    }
}

/// Pass 3: linkify the first `MAX_LINKIFY_SCAN_BYTES` of `body_text`
/// (rounded down to a UTF-8 char boundary) and classify each URL.
fn scan_body_urls(body_text: &str, out: &mut Vec<SecurityWarning>) {
    let mut end = MAX_LINKIFY_SCAN_BYTES.min(body_text.len());
    while end > 0 && !body_text.is_char_boundary(end) {
        end -= 1;
    }
    let scan_slice = &body_text[..end];
    let finder = LinkFinder::new();
    for link in finder.links(scan_slice) {
        if link.kind() != &LinkKind::Url {
            continue;
        }
        if let Some(domain) = extract_domain_from_url(link.as_str()) {
            emit_classification(&domain, "body:text", out);
        }
    }
}

/// Pull the domain from a header address. Handles `Name <user@host>`
/// and bare `user@host` forms. Returns `None` if no `@` is present
/// or the right-hand side is empty.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "used by test helper; retained for future audit passes"
    )
)]
fn extract_domain_from_address(addr: &str) -> Option<String> {
    let trimmed = addr.trim();
    let inner = if let (Some(lt), Some(gt)) = (trimmed.rfind('<'), trimmed.rfind('>'))
        && lt < gt
    {
        &trimmed[lt + 1..gt]
    } else {
        trimmed
    };
    let (_local, domain) = inner.rsplit_once('@')?;
    let domain = domain.trim();
    if domain.is_empty() {
        return None;
    }
    Some(domain.to_string())
}

/// Pull the host portion of a URL string. Strips scheme, userinfo,
/// port, path, query, and fragment, then drops a leading `www.`.
/// Returns `None` for hosts without a `.` (single-label, IPs are
/// fine in shape but rejected by `classify_domain` later anyway).
fn extract_domain_from_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let after_scheme = match trimmed.find("://") {
        Some(idx) => &trimmed[idx + 3..],
        None => trimmed,
    };
    let host_with_userinfo = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host = match host_with_userinfo.rsplit_once('@') {
        Some((_user, h)) => h,
        None => host_with_userinfo,
    };
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host.to_string())
}

/// Classify `domain` and push any warnings produced. Emits at most
/// one [`WarningCode::LookalikeMixedScript`] and one
/// [`WarningCode::LookalikeIdnPunycode`] per call. Homograph emission
/// is deliberately NOT performed here — TR39 confusables.txt has
/// identity-looking maps (e.g. `m → rn`) that fire on every Latin
/// domain, so the only safe homograph signal is the bidi-pre-strip
/// detection in `parse::sanitize_filename` (Sprint 4b Task 16).
fn emit_classification(domain: &str, location: &str, out: &mut Vec<SecurityWarning>) {
    let Some(c) = classify_domain(domain) else {
        return;
    };
    if c.mixed_script {
        out.push(SecurityWarning {
            code: WarningCode::LookalikeMixedScript,
            detail: Some(format!("domain={},unicode={}", c.ascii, c.unicode)),
            location: Some(location.to_string()),
        });
    }
    if c.was_punycode {
        out.push(SecurityWarning {
            code: WarningCode::LookalikeIdnPunycode,
            detail: Some(format!("domain={},ulabel={}", c.ascii, c.unicode)),
            location: Some(location.to_string()),
        });
    }
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

    /// Pins absolute skeleton outputs so a mutant that replaces
    /// [`compute_skeleton`] with a constant (e.g. `"xyzzy"`) can no
    /// longer survive on equality-of-two-calls assertions alone.
    #[test]
    fn skeleton_maps_known_confusables_to_expected_ascii() {
        // Cyrillic 'а' (U+0430) → Latin 'a' (U+0061); keep the ASCII dot.
        assert_eq!(compute_skeleton("\u{0430}"), "a");
        // Latin 'm' maps to "rn" under TR39 skeleton.
        let m = compute_skeleton("m");
        assert_eq!(m, "rn");
        // TR39 skeleton maps digit '1' to Latin 'l' (both are visually
        // similar lowercase glyphs).
        assert_eq!(compute_skeleton("1"), "l");
        // Different inputs must produce different skeletons (would fail
        // under a constant-return mutant).
        assert_ne!(compute_skeleton("abc"), compute_skeleton("xyz"));
    }

    fn empty_meta() -> ContentMeta {
        ContentMeta::default()
    }

    fn run_audit(
        meta: &ContentMeta,
        body_text: &str,
        anchor_hrefs: &[String],
    ) -> Vec<SecurityWarning> {
        let mut header_domains = Vec::new();
        if let Some(from) = meta.from.as_deref()
            && let Some(domain) = extract_domain_from_address(from)
        {
            header_domains.push((domain, "header:from".to_string()));
        }
        for addr in &meta.to {
            if let Some(domain) = extract_domain_from_address(addr) {
                header_domains.push((domain, "header:to".to_string()));
            }
        }
        for addr in &meta.cc {
            if let Some(domain) = extract_domain_from_address(addr) {
                header_domains.push((domain, "header:cc".to_string()));
            }
        }
        if let Some(reply_to) = meta.reply_to.as_deref()
            && let Some(domain) = extract_domain_from_address(reply_to)
        {
            header_domains.push((domain, "header:reply_to".to_string()));
        }
        audit(&LookalikeInput {
            meta,
            body_text,
            anchor_hrefs,
            header_domains,
        })
    }

    #[test]
    fn audit_flags_mixed_script_header_domain() {
        // Cyrillic 'а' (U+0430) inside a Latin label.
        let mut meta = empty_meta();
        meta.from = Some("Bank Support <support@p\u{0430}ypal.com>".to_string());
        let warnings = run_audit(&meta, "", &[]);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "expected LookalikeMixedScript, got {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .all(|w| w.location.as_deref() == Some("header:from")),
            "all emitted warnings should be located on header:from"
        );
    }

    #[test]
    fn audit_flags_mixed_script_reply_to_domain() {
        let mut meta = empty_meta();
        meta.from = Some("legit@example.com".to_string());
        meta.reply_to = Some("support@p\u{0430}ypal.com".to_string());
        let warnings = run_audit(&meta, "", &[]);
        let reply_to_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| {
                w.code == WarningCode::LookalikeMixedScript
                    && w.location.as_deref() == Some("header:reply_to")
            })
            .collect();
        assert_eq!(
            reply_to_warnings.len(),
            1,
            "expected one mixed-script hit on reply_to, \
             got {warnings:?}"
        );
    }

    #[test]
    fn audit_flags_mixed_script_body_url() {
        let body = "Please visit https://p\u{0430}ypal.com/account today.";
        let warnings = run_audit(&empty_meta(), body, &[]);
        let mixed: Vec<_> = warnings
            .iter()
            .filter(|w| w.code == WarningCode::LookalikeMixedScript)
            .collect();
        assert_eq!(
            mixed.len(),
            1,
            "expected one mixed-script hit, got {warnings:?}"
        );
        assert_eq!(mixed[0].location.as_deref(), Some("body:text"));
    }

    #[test]
    fn audit_informational_for_idn_punycode() {
        let hrefs = vec!["https://xn--mnchen-3ya.de/".to_string()];
        let warnings = run_audit(&empty_meta(), "", &hrefs);
        let punycode: Vec<_> = warnings
            .iter()
            .filter(|w| w.code == WarningCode::LookalikeIdnPunycode)
            .collect();
        assert_eq!(
            punycode.len(),
            1,
            "expected one IDN warning, got {warnings:?}"
        );
        assert_eq!(punycode[0].location.as_deref(), Some("html:anchor_href"));
        assert!(
            !warnings
                .iter()
                .any(|w| w.code == WarningCode::LookalikeMixedScript),
            "münchen.de is single-script Latin, must not flag mixed_script"
        );
    }

    #[test]
    fn audit_pure_ascii_latin_emits_no_warnings() {
        // Regression: TR39 confusables.txt has identity-looking maps
        // (e.g. m→rn) so naive skeleton-difference checks would fire on
        // every Latin domain. Audit must NOT emit anything for clean
        // pure-ASCII inputs.
        let mut meta = empty_meta();
        meta.from = Some("alice@example.com".to_string());
        meta.to = vec!["bob@google.com".to_string()];
        let hrefs = vec![
            "https://paypal.com/login".to_string(),
            "https://www.google.com/search".to_string(),
            "https://example.com/".to_string(),
        ];
        let warnings = run_audit(&meta, "Visit https://example.com/", &hrefs);
        assert!(
            warnings.is_empty(),
            "pure-ASCII inputs must not produce warnings, got {warnings:?}"
        );
    }

    #[test]
    fn audit_clean_multilingual_input_no_warnings() {
        let mut meta = empty_meta();
        meta.from = Some("Alice <alice@example.com>".to_string());
        meta.subject = Some("こんにちは / 你好".to_string());
        let body = "ご挨拶 — 你好世界。Visit https://example.com/ when you can.";
        let hrefs = vec!["https://example.com/".to_string()];
        let warnings = run_audit(&meta, body, &hrefs);
        assert!(
            warnings.is_empty(),
            "clean multilingual input must not flag warnings, got {warnings:?}"
        );
    }

    #[test]
    fn audit_respects_body_scan_cap() {
        // 200 KiB of clean filler followed by a mixed-script URL well
        // past MAX_LINKIFY_SCAN_BYTES. The cap means the URL is never
        // scanned, so no warning fires.
        let filler = "clean text. ".repeat(20_000);
        assert!(filler.len() > MAX_LINKIFY_SCAN_BYTES);
        let body = format!("{filler}https://p\u{0430}ypal.com/account");
        let warnings = run_audit(&empty_meta(), &body, &[]);
        assert!(
            warnings.is_empty(),
            "URL past the scan cap must be ignored, got {warnings:?}"
        );
    }
}
