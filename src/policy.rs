//! Policy enforcement — RevocationList management.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{self, SigilError};

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// A single revocation entry — either a key or a specific artifact hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Revoke all artifacts signed by this key.
    pub key_id: Option<String>,
    /// Revoke a specific artifact by its content hash.
    pub content_hash: Option<String>,
    /// Reason for revocation.
    pub reason: String,
    /// When the revocation was created.
    pub revoked_at: DateTime<Utc>,
    /// Identity of the revoker.
    pub revoked_by: String,
    /// If set, only artifacts verified *after* this timestamp are considered
    /// revoked. Artifacts signed/verified before this point remain valid.
    /// This supports "revoked after" semantics for key compromises that
    /// occurred at a known point in time.
    #[serde(default)]
    pub revoked_after: Option<DateTime<Utc>>,
}

/// A list of revoked keys and artifact hashes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationList {
    pub(super) entries: Vec<RevocationEntry>,
    /// Index of revoked key IDs for O(1) lookups.
    #[serde(skip)]
    revoked_keys: HashSet<String>,
    /// Index of revoked content hashes for O(1) lookups.
    #[serde(skip)]
    revoked_hashes: HashSet<String>,
}

impl RevocationList {
    /// Create an empty revocation list.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            revoked_keys: HashSet::new(),
            revoked_hashes: HashSet::new(),
        }
    }

    /// Add a revocation entry.
    ///
    /// At least one of `key_id` or `content_hash` must be `Some`,
    /// otherwise an error is returned.
    pub fn add(&mut self, entry: RevocationEntry) -> error::Result<()> {
        if entry.key_id.is_none() && entry.content_hash.is_none() {
            return Err(SigilError::InvalidInput {
                detail: "RevocationEntry must have at least one of key_id or content_hash set"
                    .to_string(),
            });
        }
        if let Some(ref kid) = entry.key_id {
            self.revoked_keys.insert(kid.clone());
        }
        if let Some(ref hash) = entry.content_hash {
            self.revoked_hashes.insert(hash.clone());
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Check whether a key ID has been revoked.
    ///
    /// If `at` is `Some`, only revocations that apply at that timestamp are
    /// considered (honoring `revoked_after` semantics).
    #[must_use]
    pub fn is_key_revoked(&self, key_id: &str) -> bool {
        self.is_key_revoked_at(key_id, None)
    }

    /// Check whether a key ID has been revoked at a specific time.
    #[must_use]
    pub fn is_key_revoked_at(&self, key_id: &str, at: Option<DateTime<Utc>>) -> bool {
        if !self.revoked_keys.contains(key_id) {
            return false;
        }
        // If no timestamp given, treat as unconditionally revoked
        let Some(when) = at else { return true };
        // Check if any matching entry applies at this timestamp
        self.entries
            .iter()
            .filter(|e| e.key_id.as_deref() == Some(key_id))
            .any(|e| match e.revoked_after {
                Some(after) => when >= after,
                None => true, // No revoked_after means unconditional
            })
    }

    /// Check whether an artifact content hash has been revoked.
    #[must_use]
    pub fn is_artifact_revoked(&self, content_hash: &str) -> bool {
        self.is_artifact_revoked_at(content_hash, None)
    }

    /// Check whether an artifact content hash has been revoked at a specific time.
    #[must_use]
    pub fn is_artifact_revoked_at(&self, content_hash: &str, at: Option<DateTime<Utc>>) -> bool {
        if !self.revoked_hashes.contains(content_hash) {
            return false;
        }
        let Some(when) = at else { return true };
        self.entries
            .iter()
            .filter(|e| e.content_hash.as_deref() == Some(content_hash))
            .any(|e| match e.revoked_after {
                Some(after) => when >= after,
                None => true,
            })
    }

    /// Number of entries in the revocation list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the revocation list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> error::Result<String> {
        Ok(serde_json::to_string_pretty(&self.entries)?)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> error::Result<Self> {
        let entries: Vec<RevocationEntry> = serde_json::from_str(json)?;
        let mut list = Self::new();
        for entry in entries {
            // Entries from JSON are assumed valid (already validated on creation).
            if let Some(ref kid) = entry.key_id {
                list.revoked_keys.insert(kid.clone());
            }
            if let Some(ref hash) = entry.content_hash {
                list.revoked_hashes.insert(hash.clone());
            }
            list.entries.push(entry);
        }
        Ok(list)
    }
}
