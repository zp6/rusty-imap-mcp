//! Security posture enum. Controls which tools are advertised and dispatchable.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The three supported postures. Default is [`Posture::DraftSafe`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    /// Read-only operations only. No flag changes, no drafts, no moves.
    Readonly,
    /// Read + safe mutations (flags, moves, draft creation with `$PendingReview`).
    #[default]
    DraftSafe,
    /// Read + mutations + escape hatches (`advanced_query`, `include_html`).
    Full,
}

impl Posture {
    /// Canonical kebab-case string form used in config files and error messages.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::DraftSafe => "draft-safe",
            Self::Full => "full",
        }
    }

    /// Every posture, in declaration order. Useful for exhaustive tests.
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::Readonly, Self::DraftSafe, Self::Full]
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`Posture::from_str`] for unrecognized values.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown posture `{0}`; expected one of: readonly, draft-safe, full")]
pub struct UnknownPosture(pub String);

impl FromStr for Posture {
    type Err = UnknownPosture;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "readonly" => Ok(Self::Readonly),
            "draft-safe" => Ok(Self::DraftSafe),
            "full" => Ok(Self::Full),
            other => Err(UnknownPosture(other.to_string())),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use crate::posture::{Posture, UnknownPosture};
    use core::str::FromStr;

    #[test]
    fn default_is_draft_safe() {
        assert_eq!(Posture::default(), Posture::DraftSafe);
    }

    #[test]
    fn round_trip_all_postures() {
        for posture in Posture::all() {
            let s = posture.as_str();
            let parsed = Posture::from_str(s).unwrap();
            assert_eq!(parsed, posture, "round-trip failed for {s}");
        }
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(Posture::Readonly.to_string(), "readonly");
        assert_eq!(Posture::DraftSafe.to_string(), "draft-safe");
        assert_eq!(Posture::Full.to_string(), "full");
    }

    #[test]
    fn unknown_posture_is_rejected() {
        let err = Posture::from_str("yolo").unwrap_err();
        assert_eq!(err, UnknownPosture("yolo".to_string()));
        assert!(err.to_string().contains("yolo"));
        assert!(err.to_string().contains("draft-safe"));
    }

    #[test]
    fn underscore_alias_is_rejected() {
        // We accept only the kebab-case form. "draft_safe" must NOT parse.
        assert!(Posture::from_str("draft_safe").is_err());
    }
}
