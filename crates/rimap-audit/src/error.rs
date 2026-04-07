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
    #[error("failed to read audit file `{path}`: {source}")]
    Read {
        /// The audit file path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
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
        match err.code() {
            ErrorCode::Config => Self::Config(err.to_string()),
            _ => Self::Internal(err.to_string()),
        }
    }
}

#[cfg(test)]
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
    fn rimap_error_conversion_preserves_code() {
        let err = AuditError::Locked {
            path: PathBuf::from("/tmp/a.jsonl"),
        };
        let rimap: rimap_core::RimapError = err.into();
        assert_eq!(rimap.code(), ErrorCode::Config);
    }
}
