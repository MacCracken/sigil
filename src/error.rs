//! Sigil error types.

use std::fmt;
use std::path::PathBuf;

/// The error type for all Sigil operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum SigilError {
    /// A requested key was not found in the keyring.
    KeyNotFound {
        /// The key ID that was looked up.
        key_id: String,
    },

    /// An Ed25519 signature failed verification.
    SignatureInvalid {
        /// Human-readable detail.
        detail: String,
    },

    /// An artifact or key has been revoked.
    RevocationViolation {
        /// What was revoked (key ID or content hash).
        subject: String,
        /// Why it was revoked.
        reason: String,
    },

    /// A file's hash did not match the expected baseline.
    IntegrityMismatch {
        /// The file that failed verification.
        path: PathBuf,
        /// Expected hash value.
        expected: String,
        /// Actual hash value.
        actual: String,
    },

    /// Invalid input was provided (bad hex, wrong length, missing fields, etc.).
    InvalidInput {
        /// What was wrong.
        detail: String,
    },

    /// An I/O error occurred (file read/write, directory listing, etc.).
    Io {
        /// The underlying I/O error.
        source: std::io::Error,
        /// Optional path context.
        path: Option<PathBuf>,
    },

    /// A serialization or deserialization error occurred.
    Serialization {
        /// The underlying serde_json error.
        source: serde_json::Error,
    },

    /// An Ed25519 cryptographic operation failed.
    Crypto {
        /// Human-readable detail.
        detail: String,
    },
}

impl fmt::Display for SigilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound { key_id } => write!(f, "key not found: {key_id}"),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::RevocationViolation { subject, reason } => {
                write!(f, "revoked ({subject}): {reason}")
            }
            Self::IntegrityMismatch {
                path,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "integrity mismatch for {}: expected {expected}, got {actual}",
                    path.display()
                )
            }
            Self::InvalidInput { detail } => write!(f, "invalid input: {detail}"),
            Self::Io { source, path } => match path {
                Some(p) => write!(f, "I/O error on {}: {source}", p.display()),
                None => write!(f, "I/O error: {source}"),
            },
            Self::Serialization { source } => write!(f, "serialization error: {source}"),
            Self::Crypto { detail } => write!(f, "crypto error: {detail}"),
        }
    }
}

impl std::error::Error for SigilError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialization { source } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SigilError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            source: err,
            path: None,
        }
    }
}

impl From<serde_json::Error> for SigilError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization { source: err }
    }
}

/// Convenience alias used throughout the crate's public API.
pub type Result<T> = std::result::Result<T, SigilError>;

/// Helper to attach path context to an I/O error.
pub(crate) fn io_err(err: std::io::Error, path: &std::path::Path) -> SigilError {
    SigilError::Io {
        source: err,
        path: Some(path.to_path_buf()),
    }
}
