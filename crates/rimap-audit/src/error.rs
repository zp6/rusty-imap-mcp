//! Audit crate error type. Open-time errors map to `ERR_CONFIG`; runtime
//! write/flush/fsync errors map to `ERR_INTERNAL`. See design spec §10.

use std::path::PathBuf;

use rimap_core::{ErrorCode, RimapError};
use thiserror::Error;

/// Errors produced by `rimap-audit`.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The audit file could not be opened for read+write.
    #[error("failed to open audit file `{path}`: {source}")]
    Open {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file's parent directory could not be created.
    #[error("failed to create parent directory for `{path}`: {source}")]
    ParentDir {
        /// Attempted path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The audit file is already locked by another process.
    #[error(
        "audit file `{path}` is already locked by another rusty-imap-mcp process; \
         only one instance may run against a given audit path"
    )]
    Locked {
        /// Path that could not be locked.
        path: PathBuf,
    },
    /// A record could not be serialized to JSON.
    #[error("failed to serialize audit record: {0}")]
    Serialize(#[source] serde_json::Error),
    /// A record could not be written to disk.
    #[error("failed to write audit record to `{path}`: {source}")]
    Write {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// `fsync` failed after a flush.
    #[error("failed to fsync audit file `{path}`: {source}")]
    Fsync {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Rotation rename or fresh-file creation failed.
    #[error("failed to rotate audit file `{path}`: {reason}")]
    Rotate {
        /// The active file path that was being rotated.
        path: PathBuf,
        /// Specific reason.
        reason: String,
    },
    /// Reading the audit file for self-check or `audit merge` failed.
    #[error("failed to read audit file `{path}`{}: {source}", Self::fmt_line(*line))]
    Read {
        /// The audit file path.
        path: PathBuf,
        /// Line number (1-based) when the error originated from JSON parsing
        /// a specific line. `None` for whole-file I/O errors.
        line: Option<usize>,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl AuditError {
    fn fmt_line(line: Option<usize>) -> String {
        match line {
            Some(n) => format!(" (line {n})"),
            None => String::new(),
        }
    }
}

impl AuditError {
    /// The stable [`ErrorCode`] this error maps to at the top-level boundary.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Open { .. } | Self::ParentDir { .. } | Self::Locked { .. } => ErrorCode::Config,
            Self::Serialize(_)
            | Self::Write { .. }
            | Self::Fsync { .. }
            | Self::Rotate { .. }
            | Self::Read { .. } => ErrorCode::Internal,
        }
    }
}

impl From<AuditError> for RimapError {
    fn from(err: AuditError) -> Self {
        let code = err.code();
        Self::Audit {
            code,
            source: Box::new(err),
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests")]
mod tests {
    use std::path::PathBuf;

    use rimap_core::ErrorCode;

    use crate::error::AuditError;

    #[test]
    fn open_time_errors_map_to_config() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        assert_eq!(err.code(), ErrorCode::Config);

        let err = AuditError::Open {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert_eq!(err.code(), ErrorCode::Config);
    }

    #[test]
    fn runtime_errors_map_to_internal() {
        let err = AuditError::Write {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        assert_eq!(err.code(), ErrorCode::Internal);
    }

    #[test]
    fn locked_message_names_the_path() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/a.jsonl"));
        assert!(msg.contains("another rusty-imap-mcp process"));
    }

    #[test]
    fn rimap_error_conversion_preserves_code_and_source() {
        use std::error::Error as _;

        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let rimap: rimap_core::RimapError = err.into();

        // Open-time errors still carry ERR_CONFIG.
        assert_eq!(rimap.code(), ErrorCode::Config);

        // Display form must include the code AND the original path so
        // operators see what went wrong.
        let display = rimap.to_string();
        assert!(display.contains("ERR_CONFIG"), "got: {display}");
        assert!(display.contains("/tmp/a.jsonl"), "got: {display}");

        // Source chain preserved.
        let source = rimap.source().expect("source chain must be preserved");
        assert!(
            source.to_string().contains("/tmp/a.jsonl"),
            "source should be the AuditError with path, got: {source}",
        );

        // Runtime error still maps to ERR_INTERNAL.
        let err = AuditError::Write {
            path: PathBuf::from("/tmp/a.jsonl"),
            source: std::io::Error::from(std::io::ErrorKind::BrokenPipe),
        };
        let rimap: rimap_core::RimapError = err.into();
        assert_eq!(rimap.code(), ErrorCode::Internal);
    }
}
