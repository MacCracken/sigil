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
        path: PathBuf,
        artifact_type: ArtifactType,
        trust_level: TrustLevel,
        passed: bool,
        content_hash: String,
        timestamp: DateTime<Utc>,
    },
    /// An artifact was signed and registered.
    ArtifactSigned {
        path: PathBuf,
        artifact_type: ArtifactType,
        signer_key_id: String,
        content_hash: String,
        timestamp: DateTime<Utc>,
    },
    /// A revocation entry was added.
    RevocationAdded {
        key_id: Option<String>,
        content_hash: Option<String>,
        reason: String,
        timestamp: DateTime<Utc>,
    },
    /// A key was rotated.
    KeyRotated {
        key_id: String,
        new_key_id: String,
        timestamp: DateTime<Utc>,
    },
    /// A key chain was validated.
    ChainValidated {
        key_id: String,
        chain_length: usize,
        valid: bool,
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
