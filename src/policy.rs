//! Policy enforcement — RevocationList management.

use std::collections::HashSet;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    pub fn add(&mut self, entry: RevocationEntry) -> Result<()> {
        if entry.key_id.is_none() && entry.content_hash.is_none() {
            anyhow::bail!("RevocationEntry must have at least one of key_id or content_hash set");
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
    #[must_use]
    pub fn is_key_revoked(&self, key_id: &str) -> bool {
        self.revoked_keys.contains(key_id)
    }

    /// Check whether an artifact content hash has been revoked.
    #[must_use]
    pub fn is_artifact_revoked(&self, content_hash: &str) -> bool {
        self.revoked_hashes.contains(content_hash)
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
    pub fn to_json(&self) -> Result<String> {
        use anyhow::Context;
        serde_json::to_string_pretty(&self.entries).context("Failed to serialize revocation list")
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        use anyhow::Context;
        let entries: Vec<RevocationEntry> =
            serde_json::from_str(json).context("Failed to deserialize revocation list")?;
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
