//! Inline `style="..."` parsing and classification for hidden-element
//! detection.

use crate::html::HiddenMethod;

/// Parse a single `style="..."` attribute value into lowercased
/// `(property, value)` pairs.
///
/// Very permissive: declarations are split on `;`, then each
/// declaration is split on its first `:`. Empty properties or values
/// are dropped. The intent is "does this style contain X", not full
/// CSS conformance.
fn parse_inline_style(style: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for decl in style.split(';') {
        let Some((prop, val)) = decl.split_once(':') else {
            continue;
        };
        let prop = prop.trim().to_ascii_lowercase();
        let val = val.trim().to_ascii_lowercase();
        if prop.is_empty() || val.is_empty() {
            continue;
        }
        pairs.push((prop, val));
    }
    pairs
}

/// Parse a CSS length like `-9999px` into a pixel count.
///
/// Returns `None` for non-pixel units (em, rem, %, etc.) — they are
/// treated as non-offscreen by design (inline-style-only scope).
fn parse_px(val: &str) -> Option<f64> {
    let stripped = val.strip_suffix("px").unwrap_or(val);
    stripped.trim().parse::<f64>().ok()
}

/// Return `true` when an `opacity` value parses to (approximately) zero.
fn opacity_is_zero(val: &str) -> bool {
    let stripped = val.trim_end_matches('%').trim();
    stripped
        .parse::<f64>()
        .ok()
        .is_some_and(|n| n <= f64::EPSILON)
}

/// Return `true` when a `font-size` value parses to (approximately) zero.
fn font_size_is_zero(val: &str) -> bool {
    let digits: String = val
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    digits
        .parse::<f64>()
        .ok()
        .is_some_and(|n| n <= f64::EPSILON)
}

/// Parse a `transform: translate*(-Npx)` value and return the most
/// negative pixel offset found, or `None` if no translate pattern
/// matches.
fn parse_translate_px(val: &str) -> Option<f64> {
    let mut min: Option<f64> = None;
    for part in val.split(['(', ',', ')']) {
        let trimmed = part.trim();
        if let Some(px_val) = parse_px(trimmed) {
            match min {
                // cargo-mutants: known-equivalent — `<=` here is observably
                // identical to `<`. The two predicates differ only when
                // `px_val == current`, in which case both arms set
                // `min = Some(px_val)` to a value already equal to the
                // current minimum. The `Some(_)` arm below covers both
                // "not new minimum" cases identically.
                Some(current) if px_val < current => min = Some(px_val),
                None => min = Some(px_val),
                Some(_) => {}
            }
        }
    }
    min
}

/// Accumulator for off-screen / color-match detection across an inline
/// style declaration list.
#[derive(Default)]
struct StyleHints {
    position: Option<String>,
    left_px: Option<f64>,
    top_px: Option<f64>,
    transform_offset_px: Option<f64>,
    color: Option<String>,
    bg_color: Option<String>,
}

impl StyleHints {
    fn record(&mut self, prop: &str, val: &str) {
        match prop {
            "position" => self.position = Some(val.to_string()),
            "left" => self.left_px = parse_px(val),
            "top" => self.top_px = parse_px(val),
            "transform" => self.transform_offset_px = parse_translate_px(val),
            "color" => self.color = Some(val.to_string()),
            "background-color" => self.bg_color = Some(val.to_string()),
            _ => {}
        }
    }

    fn is_offscreen(&self) -> bool {
        let positioned = self
            .position
            .as_deref()
            .is_some_and(|p| p == "absolute" || p == "fixed");
        if !positioned {
            return false;
        }
        let off_left = self.left_px.is_some_and(|v| v < -100.0);
        let off_top = self.top_px.is_some_and(|v| v < -100.0);
        let off_transform = self.transform_offset_px.is_some_and(|v| v < -100.0);
        off_left || off_top || off_transform
    }

    fn is_color_match(&self) -> bool {
        match (self.color.as_ref(), self.bg_color.as_ref()) {
            (Some(c), Some(bg)) => c == bg,
            (Some(_) | None, None) | (None, Some(_)) => false,
        }
    }
}

/// Check a single declaration for an immediate hidden-method match.
///
/// Returns `Some` only for self-contained patterns (display, visibility,
/// opacity, font-size). Multi-property patterns (off-screen, color
/// match) accumulate via [`StyleHints`] and are resolved by the caller.
pub(super) fn classify_single_declaration(prop: &str, val: &str) -> Option<HiddenMethod> {
    match prop {
        "display" if val == "none" => Some(HiddenMethod::DisplayNone),
        "visibility" if val == "hidden" => Some(HiddenMethod::VisibilityHidden),
        "opacity" if opacity_is_zero(val) => Some(HiddenMethod::OpacityZero),
        "font-size" if font_size_is_zero(val) => Some(HiddenMethod::ZeroFont),
        _ => None,
    }
}

/// Classify an inline `style` string into a [`HiddenMethod`], if any.
pub(super) fn classify_inline_style(style: &str) -> Option<HiddenMethod> {
    let pairs = parse_inline_style(style);
    let mut hints = StyleHints::default();
    for (prop, val) in &pairs {
        if let Some(method) = classify_single_declaration(prop, val) {
            return Some(method);
        }
        hints.record(prop, val);
    }
    if hints.is_offscreen() {
        return Some(HiddenMethod::OffScreen);
    }
    if hints.is_color_match() {
        return Some(HiddenMethod::ColorMatch);
    }
    None
}

#[cfg(test)]
mod style_parse_tests {
    use super::{HiddenMethod, classify_inline_style, parse_translate_px};

    #[test]
    fn parse_inline_style_drops_empty_values() {
        // Kills `|| with &&` on the prop/val empty-skip guard. Under `&&`,
        // declarations with an empty value would survive into the pairs
        // vector, and `record` would store them in StyleHints. Pairing
        // empty `color:` and `background-color:` would then trip
        // `is_color_match` (Some("") == Some("")) and the classifier
        // would falsely return ColorMatch.
        assert_eq!(
            classify_inline_style("color:; background-color:"),
            None,
            "empty-value declarations must not feed StyleHints",
        );
    }

    #[test]
    fn parse_translate_px_picks_most_negative_offset() {
        // Kills both `< with false` and `< with ==` mutations on the
        // match guard `px_val < current`. With `false`, the guard
        // never fires after the first Some-match — first-wins instead
        // of min-wins. With `==`, the guard only fires on equal values,
        // which is the same first-wins outcome for distinct values.
        let out = parse_translate_px("(-50px, -200px)");
        assert_eq!(
            out,
            Some(-200.0),
            "expected the more-negative offset to win, got {out:?}",
        );
    }

    /// Build an inline style of `position: absolute; <prop>: <val>` and
    /// return the classifier's result.
    fn classify_with_positioned(prop: &str, val: &str) -> Option<HiddenMethod> {
        let style = format!("position: absolute; {prop}: {val}");
        classify_inline_style(&style)
    }

    #[test]
    fn is_offscreen_left_does_not_fire_at_minus_100px() {
        // Kills `< with <=` at line 110:55 (left_px boundary). With `<=`,
        // left = -100px is treated as off-screen (returns OffScreen);
        // the original `<` keeps it on-screen.
        let result = classify_with_positioned("left", "-100px");
        assert_ne!(result, Some(HiddenMethod::OffScreen));
    }

    #[test]
    fn is_offscreen_top_does_not_fire_at_minus_100px() {
        // Kills `< with <=` at line 111:53 (top_px boundary).
        let result = classify_with_positioned("top", "-100px");
        assert_ne!(result, Some(HiddenMethod::OffScreen));
    }

    #[test]
    fn is_offscreen_top_threshold_is_negative_one_hundred_px() {
        // Kills `delete -` at line 111:55 (the threshold's negative sign
        // on `-100.0`). With the `-` deleted, the threshold becomes
        // +100, and any negative top — including a clearly-on-screen
        // -50 — is reported as OffScreen.
        let result = classify_with_positioned("top", "-50px");
        assert_ne!(
            result,
            Some(HiddenMethod::OffScreen),
            "top: -50px must not classify as off-screen under the -100 threshold",
        );
    }

    #[test]
    fn is_offscreen_transform_does_not_fire_at_minus_100px() {
        // Kills `< with <=` at line 112:72 (transform_offset_px boundary).
        let result = classify_with_positioned("transform", "translate(-100px)");
        assert_ne!(result, Some(HiddenMethod::OffScreen));
    }
}
