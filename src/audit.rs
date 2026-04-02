//! Structured verification audit log.
//!
//! Records all trust-relevant operations as typed events with timestamps.
//! Events can be serialized to JSON lines for file-backed persistence.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{ArtifactType, TrustLevel};

/// A single audit event recording a trust-relevant operation.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    /// An artifact was verified.
    ArtifactVerified {
        /// Path to the artifact.
        path: PathBuf,
        /// Type of the artifact.
        artifact_type: ArtifactType,
        /// Trust level required for verification.
        trust_level: TrustLevel,
        /// Whether verification passed.
        passed: bool,
        /// SHA-256 hash of the artifact contents.
        content_hash: String,
        /// When the verification occurred.
        timestamp: DateTime<Utc>,
    },
    /// An artifact was signed and registered.
    ArtifactSigned {
        /// Path to the artifact.
        path: PathBuf,
        /// Type of the artifact.
        artifact_type: ArtifactType,
        /// Key ID of the signer.
        signer_key_id: String,
        /// SHA-256 hash of the artifact contents.
        content_hash: String,
        /// When the signing occurred.
        timestamp: DateTime<Utc>,
    },
    /// A revocation entry was added.
    RevocationAdded {
        /// Key ID that was revoked, if applicable.
        key_id: Option<String>,
        /// Content hash that was revoked, if applicable.
        content_hash: Option<String>,
        /// Human-readable reason for revocation.
        reason: String,
        /// When the revocation was recorded.
        timestamp: DateTime<Utc>,
    },
    /// A key was rotated.
    KeyRotated {
        /// Key ID of the outgoing key.
        key_id: String,
        /// Key ID of the replacement key.
        new_key_id: String,
        /// When the rotation occurred.
        timestamp: DateTime<Utc>,
    },
    /// A key chain was validated.
    ChainValidated {
        /// Key ID at the tip of the chain.
        key_id: String,
        /// Number of keys in the chain.
        chain_length: usize,
        /// Whether the chain was valid.
        valid: bool,
        /// When the validation occurred.
        timestamp: DateTime<Utc>,
    },
}

/// Collects audit events for later inspection or persistence.
#[derive(Debug, Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    /// Create a new empty audit log.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Record an event.
    pub fn record(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    /// Return all recorded events.
    #[must_use]
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Serialize all events as JSON lines (one JSON object per line).
    pub fn to_json_lines(&self) -> crate::error::Result<String> {
        let mut out = String::new();
        for event in &self.events {
            let line = serde_json::to_string(event)?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    /// Deserialize events from JSON lines.
    pub fn from_json_lines(data: &str) -> crate::error::Result<Self> {
        let mut log = Self::new();
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(line)?;
            log.events.push(event);
        }
        Ok(log)
    }

    /// Append events to a file (JSON lines format).
    pub fn append_to_file(&self, path: &std::path::Path) -> crate::error::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| crate::error::io_err(e, path))?;
        for event in &self.events {
            let line = serde_json::to_string(event)?;
            writeln!(file, "{line}").map_err(|e| crate::error::io_err(e, path))?;
        }
        Ok(())
    }

    /// Load events from a file (JSON lines format).
    pub fn load_from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let data = std::fs::read_to_string(path).map_err(|e| crate::error::io_err(e, path))?;
        Self::from_json_lines(&data)
    }
}
