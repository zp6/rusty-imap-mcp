//! Posture matrix: compile-time `const` truth table for v1 tools × postures,
//! plus the runtime `EffectiveMatrix` that merges per-tool overrides.
//!
//! Derived from design spec §4 "Posture matrix".

use std::collections::BTreeMap;

use rimap_config::model::Verdict;
use rimap_config::validate::ValidatedConfig;
use rimap_core::posture::Posture;
use rimap_core::tool::ToolName;

use crate::error::AuthzError;

/// Compile-time truth table. `true` = allowed by base posture.
///
/// Layout: outer by [`ToolName`] (13 tools), inner `[readonly, draft_safe, full]`.
pub(crate) const POSTURE_MATRIX: [(ToolName, [bool; 3]); 13] = [
    (ToolName::ListFolders, [true, true, true]),
    (ToolName::Search, [true, true, true]),
    (ToolName::SearchAdvanced, [false, false, true]),
    (ToolName::FetchMessage, [true, true, true]),
    (ToolName::FetchMessageHtml, [false, false, true]),
    (ToolName::ListAttachments, [true, true, true]),
    (ToolName::DownloadAttachment, [true, true, true]),
    (ToolName::MarkRead, [false, true, true]),
    (ToolName::MarkUnread, [false, true, true]),
    (ToolName::Flag, [false, true, true]),
    (ToolName::Unflag, [false, true, true]),
    (ToolName::MoveMessage, [false, true, true]),
    (ToolName::CreateDraft, [false, true, true]),
];

fn posture_index(p: Posture) -> usize {
    match p {
        Posture::Readonly => 0,
        Posture::DraftSafe => 1,
        Posture::Full => 2,
    }
}

/// Lookup against the base `const` matrix, before overrides.
#[must_use]
pub fn base_allows(posture: Posture, tool: ToolName) -> bool {
    let idx = posture_index(posture);
    for (t, row) in POSTURE_MATRIX {
        if t == tool {
            return row[idx];
        }
    }
    // Unreachable: POSTURE_MATRIX must cover all ToolName variants.
    // A compile-time exhaustiveness check lives in the test module.
    false
}

/// Effective authorization matrix: base posture merged with per-tool overrides.
///
/// Deny overrides Allow. An override pointing at a tool that is already in
/// the same state is a no-op (not an error).
#[derive(Debug, Clone)]
pub struct EffectiveMatrix {
    allowed: BTreeMap<ToolName, bool>,
    posture: Posture,
}

impl EffectiveMatrix {
    /// Build from a base [`Posture`] and per-tool overrides (already resolved
    /// to [`ToolName`] by config validation).
    #[must_use]
    pub fn build(posture: Posture, overrides: &BTreeMap<ToolName, Verdict>) -> Self {
        let mut allowed = BTreeMap::new();
        for tool in ToolName::all() {
            let base = base_allows(posture, tool);
            let effective = match overrides.get(&tool) {
                None => base,
                Some(Verdict::Allow) => true,
                Some(Verdict::Deny) => false,
            };
            allowed.insert(tool, effective);
        }
        Self { allowed, posture }
    }

    /// Build from a validated config.
    #[must_use]
    pub fn from_validated(cfg: &ValidatedConfig) -> Self {
        Self::build(cfg.config.security.posture, &cfg.tool_overrides)
    }

    /// Base posture used for construction (for logging / display only).
    #[must_use]
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// `Ok(())` if allowed, `Err(PostureDenied)` otherwise.
    ///
    /// # Errors
    /// Returns `AuthzError::PostureDenied` if `tool` is not allowed.
    pub fn check(&self, tool: ToolName) -> Result<(), AuthzError> {
        if *self.allowed.get(&tool).unwrap_or(&false) {
            Ok(())
        } else {
            Err(AuthzError::PostureDenied(tool))
        }
    }

    /// Return the set of allowed tools in declaration order — the advertised
    /// set for `list_tools`.
    #[must_use]
    pub fn advertised(&self) -> Vec<ToolName> {
        ToolName::all()
            .into_iter()
            .filter(|t| *self.allowed.get(t).unwrap_or(&false))
            .collect()
    }

    /// Iterate `(tool, allowed)` in declaration order. Used by `--dry-run`
    /// printing.
    pub fn rows(&self) -> impl Iterator<Item = (ToolName, bool)> + '_ {
        ToolName::all()
            .into_iter()
            .map(move |t| (t, *self.allowed.get(&t).unwrap_or(&false)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rimap_config::model::Verdict;
    use rimap_core::posture::Posture;
    use rimap_core::tool::ToolName;

    use crate::error::AuthzError;
    use crate::matrix::{EffectiveMatrix, POSTURE_MATRIX, base_allows};

    #[test]
    fn matrix_covers_every_tool_variant_exactly_once() {
        use std::collections::BTreeSet;
        let mut seen = BTreeSet::new();
        for (tool, _) in POSTURE_MATRIX {
            assert!(seen.insert(tool), "duplicate row for {tool}");
        }
        assert_eq!(seen.len(), ToolName::all().len());
        for t in ToolName::all() {
            assert!(seen.contains(&t), "missing row for {t}");
        }
    }

    #[test]
    fn base_readonly_row_matches_spec() {
        for t in [
            ToolName::ListFolders,
            ToolName::Search,
            ToolName::FetchMessage,
            ToolName::ListAttachments,
            ToolName::DownloadAttachment,
        ] {
            assert!(base_allows(Posture::Readonly, t), "{t} should be allowed");
        }
        for t in [
            ToolName::SearchAdvanced,
            ToolName::FetchMessageHtml,
            ToolName::MarkRead,
            ToolName::MarkUnread,
            ToolName::Flag,
            ToolName::Unflag,
            ToolName::MoveMessage,
            ToolName::CreateDraft,
        ] {
            assert!(!base_allows(Posture::Readonly, t), "{t} should be denied");
        }
    }

    #[test]
    fn base_draft_safe_row_matches_spec() {
        for t in [ToolName::SearchAdvanced, ToolName::FetchMessageHtml] {
            assert!(!base_allows(Posture::DraftSafe, t));
        }
        for t in ToolName::all() {
            if matches!(t, ToolName::SearchAdvanced | ToolName::FetchMessageHtml) {
                continue;
            }
            assert!(base_allows(Posture::DraftSafe, t), "{t} expected allowed");
        }
    }

    #[test]
    fn base_full_row_allows_everything() {
        for t in ToolName::all() {
            assert!(base_allows(Posture::Full, t), "full should allow {t}");
        }
    }

    #[test]
    fn exhaustive_posture_times_tool_lookup_is_stable() {
        for p in Posture::all() {
            for t in ToolName::all() {
                let a = base_allows(p, t);
                let b = base_allows(p, t);
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn deny_override_beats_allow_in_base() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::Search, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(matches!(
            m.check(ToolName::Search),
            Err(AuthzError::PostureDenied(_))
        ));
        assert!(m.check(ToolName::ListFolders).is_ok());
    }

    #[test]
    fn allow_override_promotes_denied_tool() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::SearchAdvanced, Verdict::Allow);
        let m = EffectiveMatrix::build(Posture::DraftSafe, &overrides);
        assert!(m.check(ToolName::SearchAdvanced).is_ok());
    }

    #[test]
    fn override_same_as_base_is_noop() {
        let mut overrides = BTreeMap::new();
        overrides.insert(ToolName::ListFolders, Verdict::Allow);
        overrides.insert(ToolName::CreateDraft, Verdict::Deny);
        let m = EffectiveMatrix::build(Posture::Readonly, &overrides);
        assert!(m.check(ToolName::ListFolders).is_ok());
        assert!(matches!(
            m.check(ToolName::CreateDraft),
            Err(AuthzError::PostureDenied(_))
        ));
    }

    #[test]
    fn advertised_matches_allowed_set_in_order() {
        let m = EffectiveMatrix::build(Posture::Readonly, &BTreeMap::new());
        let adv = m.advertised();
        assert_eq!(
            adv,
            vec![
                ToolName::ListFolders,
                ToolName::Search,
                ToolName::FetchMessage,
                ToolName::ListAttachments,
                ToolName::DownloadAttachment,
            ]
        );
    }

    #[test]
    fn rows_iterates_every_tool() {
        let m = EffectiveMatrix::build(Posture::Full, &BTreeMap::new());
        let rows: Vec<_> = m.rows().collect();
        assert_eq!(rows.len(), ToolName::all().len());
        assert!(rows.iter().all(|(_, allowed)| *allowed));
    }

    #[test]
    fn posture_accessor_returns_construction_value() {
        let m = EffectiveMatrix::build(Posture::DraftSafe, &BTreeMap::new());
        assert_eq!(m.posture(), Posture::DraftSafe);
    }
}
