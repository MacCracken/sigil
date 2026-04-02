//! Verification logic — SigilVerifier implementation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

use super::types::{
    ArtifactType, SigilStats, TrustCheck, TrustEnforcement, TrustLevel, TrustPolicy,
    TrustedArtifact, VerificationResult,
};
use crate::audit::{AuditEvent, AuditLog};
use crate::error;
#[cfg(feature = "integrity")]
use crate::integrity::{IntegrityPolicy, IntegrityReport, IntegrityVerifier};
#[cfg(feature = "policy")]
use crate::policy::{RevocationEntry, RevocationList};
use crate::trust::{
    PublisherKeyring, hash_data_with, key_id_from_verifying_key, sign_data, verify_signature,
};

// ---------------------------------------------------------------------------
// Verification cache
// ---------------------------------------------------------------------------

/// Cached file metadata used to skip re-verification when a file hasn't changed.
#[derive(Debug, Clone)]
struct CacheEntry {
    mtime: SystemTime,
    size: u64,
    result: VerificationResult,
}

// ---------------------------------------------------------------------------
// Key pinning
// ---------------------------------------------------------------------------

/// A key pin binding a key ID to a path prefix.
///
/// When a pin exists for a path, only the pinned key may sign artifacts
/// under that prefix. This prevents supply-chain attacks where a valid
/// but unauthorized publisher signs a critical system path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPin {
    /// The key ID that is authorized for this path prefix.
    pub key_id: String,
    /// Path prefix that this pin applies to (e.g. "/boot/", "/usr/lib/agents/").
    pub path_prefix: PathBuf,
}

// ---------------------------------------------------------------------------
// SigilVerifier — the main trust engine
// ---------------------------------------------------------------------------

/// System-wide trust verification engine.
///
/// Combines Ed25519 signing from the marketplace keyring with file-level
/// integrity checks and a revocation list to provide unified trust
/// verification across the entire OS.
pub struct SigilVerifier {
    /// Publisher keyring for signature verification.
    keyring: PublisherKeyring,
    /// Active trust policy.
    policy: TrustPolicy,
    /// Revocation list.
    #[cfg(feature = "policy")]
    revocations: RevocationList,
    /// File integrity verifier (used by boot chain verification and future
    /// periodic integrity sweeps).
    #[cfg(feature = "integrity")]
    integrity: IntegrityVerifier,
    /// Trust store keyed by content hash.
    trust_store: HashMap<String, TrustedArtifact>,
    /// Key pins: path prefix -> authorized key ID.
    key_pins: Vec<KeyPin>,
    /// Verification cache keyed by canonical path.
    /// Uses `RwLock` so caching works through `&self` methods and is thread-safe.
    cache: RwLock<HashMap<PathBuf, CacheEntry>>,
    /// Whether the verification cache is enabled.
    cache_enabled: bool,
    /// Structured audit log.
    audit_log: RwLock<AuditLog>,
}

impl SigilVerifier {
    /// Create a new verifier with the given keyring and policy.
    pub fn new(keyring: PublisherKeyring, policy: TrustPolicy) -> Self {
        info!(
            enforcement = %policy.enforcement,
            minimum_trust = %policy.minimum_trust_level,
            "Sigil trust verifier initialised"
        );
        Self {
            keyring,
            policy,
            #[cfg(feature = "policy")]
            revocations: RevocationList::new(),
            #[cfg(feature = "integrity")]
            integrity: IntegrityVerifier::new(IntegrityPolicy::default()),
            trust_store: HashMap::new(),
            key_pins: Vec::new(),
            cache: RwLock::new(HashMap::new()),
            cache_enabled: false,
            audit_log: RwLock::new(AuditLog::new()),
        }
    }

    /// Enable or disable the verification cache.
    ///
    /// When enabled, `verify_artifact` skips re-reading and re-hashing a file
    /// if its mtime and size have not changed since the last verification.
    /// This can significantly speed up repeated verification of the same files.
    pub fn set_cache_enabled(&mut self, enabled: bool) {
        self.cache_enabled = enabled;
        if !enabled && let Ok(mut c) = self.cache.write() {
            c.clear();
        }
    }

    /// Clear the verification cache.
    pub fn clear_cache(&self) {
        if let Ok(mut c) = self.cache.write() {
            c.clear();
        }
    }

    /// Number of entries currently in the verification cache.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Return a reference to the audit log for reading events.
    #[must_use]
    pub fn audit_log(&self) -> &RwLock<AuditLog> {
        &self.audit_log
    }

    /// Add a key pin: only `key_id` may sign artifacts under `path_prefix`.
    pub fn add_key_pin(&mut self, pin: KeyPin) {
        self.key_pins.push(pin);
    }

    /// Remove all pins for a given path prefix. Returns the number removed.
    pub fn remove_key_pins(&mut self, path_prefix: &Path) -> usize {
        let before = self.key_pins.len();
        self.key_pins.retain(|p| p.path_prefix != path_prefix);
        before - self.key_pins.len()
    }

    /// Return all active key pins.
    #[must_use]
    pub fn key_pins(&self) -> &[KeyPin] {
        &self.key_pins
    }

    /// Check whether a key is authorized for a given path.
    ///
    /// Returns `true` if no pin matches the path (unpinned paths allow any key),
    /// or if the signer matches the pin.
    fn is_key_authorized_for_path(&self, path: &Path, signer_key_id: Option<&str>) -> bool {
        let matching_pins: Vec<&KeyPin> = self
            .key_pins
            .iter()
            .filter(|p| path.starts_with(&p.path_prefix))
            .collect();

        if matching_pins.is_empty() {
            return true; // No pin for this path — any key is fine
        }

        match signer_key_id {
            Some(kid) => matching_pins.iter().any(|p| p.key_id == kid),
            None => false, // Pinned path requires a signature
        }
    }

    /// Verify an artifact on disk.
    ///
    /// Reads the file, computes its hash, checks the trust store for a
    /// known signature, validates against the revocation list, and returns
    /// a detailed `VerificationResult`.
    pub fn verify_artifact(
        &self,
        path: &Path,
        artifact_type: ArtifactType,
    ) -> error::Result<VerificationResult> {
        // Check cache before doing any I/O
        if self.cache_enabled
            && let Ok(meta) = std::fs::metadata(path)
            && let Ok(mtime) = meta.modified()
            && let Ok(cache) = self.cache.read()
            && let Some(entry) = cache.get(path)
            && entry.mtime == mtime
            && entry.size == meta.len()
        {
            debug!(path = %path.display(), "Verification cache hit");
            return Ok(entry.result.clone());
        }

        let data = std::fs::read(path).map_err(|e| error::io_err(e, path))?;

        let content_hash = hash_data_with(&data, self.policy.hash_algorithm);
        let mut checks: Vec<TrustCheck> = Vec::new();
        let mut trust_level = TrustLevel::Unverified;
        let now = Utc::now();

        // --- Check: file exists and is readable ---
        checks.push(TrustCheck {
            name: "file_readable".to_string(),
            passed: true,
            detail: format!("File read successfully: {}", path.display()),
        });

        // --- Check: hash integrity (if previously registered) ---
        let stored = self.trust_store.get(&content_hash);
        if let Some(artifact) = stored {
            trust_level = artifact.trust_level;
            checks.push(TrustCheck {
                name: "trust_store".to_string(),
                passed: true,
                detail: format!(
                    "Artifact found in trust store with level {}",
                    artifact.trust_level
                ),
            });
        } else {
            checks.push(TrustCheck {
                name: "trust_store".to_string(),
                passed: false,
                detail: "Artifact not found in trust store".to_string(),
            });
        }

        // --- Check: signature verification ---
        let sig_check = if let Some(artifact) = stored {
            if let (Some(sig), Some(key_id)) = (&artifact.signature, &artifact.signer_key_id) {
                match self.keyring.get_current_key(key_id) {
                    Some(kv) => match kv.verifying_key() {
                        Ok(vk) => match verify_signature(content_hash.as_bytes(), sig, &vk) {
                            Ok(()) => {
                                if trust_level < TrustLevel::Verified {
                                    trust_level = TrustLevel::Verified;
                                }
                                TrustCheck {
                                    name: "signature".to_string(),
                                    passed: true,
                                    detail: format!("Signature verified with key {}", key_id),
                                }
                            }
                            Err(e) => {
                                trust_level = TrustLevel::Unverified;
                                TrustCheck {
                                    name: "signature".to_string(),
                                    passed: false,
                                    detail: format!("Signature verification failed: {}", e),
                                }
                            }
                        },
                        Err(e) => TrustCheck {
                            name: "signature".to_string(),
                            passed: false,
                            detail: format!("Failed to decode verifying key: {}", e),
                        },
                    },
                    None => TrustCheck {
                        name: "signature".to_string(),
                        passed: false,
                        detail: format!("Signer key {} not found in keyring", key_id),
                    },
                }
            } else {
                TrustCheck {
                    name: "signature".to_string(),
                    passed: false,
                    detail: "Artifact has no signature".to_string(),
                }
            }
        } else {
            TrustCheck {
                name: "signature".to_string(),
                passed: false,
                detail: "Artifact not in trust store; no signature to check".to_string(),
            }
        };
        checks.push(sig_check);

        // --- Check: trust chain (if signer has an issuer) ---
        if let Some(artifact) = stored
            && let Some(key_id) = &artifact.signer_key_id
            && let Some(kv) = self.keyring.get_current_key(key_id)
            && kv.issued_by.is_some()
        {
            let chain_valid = self.keyring.validate_chain(key_id).unwrap_or(false);
            checks.push(TrustCheck {
                name: "trust_chain".to_string(),
                passed: chain_valid,
                detail: if chain_valid {
                    format!("Key {} has valid chain to root", key_id)
                } else {
                    format!("Key {} has broken or incomplete trust chain", key_id)
                },
            });
            if !chain_valid {
                trust_level = TrustLevel::Community;
            }
        }

        // --- Check: revocation ---
        #[cfg(feature = "policy")]
        if self.policy.revocation_check {
            let key_id = stored.and_then(|a| a.signer_key_id.as_deref());
            let revoked = self.check_revocation_at(key_id, &content_hash, Some(now));
            if revoked {
                trust_level = TrustLevel::Revoked;
                warn!(
                    path = %path.display(),
                    hash = %content_hash,
                    "Artifact or signing key is revoked"
                );
            }
            checks.push(TrustCheck {
                name: "revocation".to_string(),
                passed: !revoked,
                detail: if revoked {
                    "Artifact or signing key is revoked".to_string()
                } else {
                    "Not revoked".to_string()
                },
            });
        }

        // --- Check: key pinning ---
        if !self.key_pins.is_empty() {
            let signer = stored.and_then(|a| a.signer_key_id.as_deref());
            let authorized = self.is_key_authorized_for_path(path, signer);
            checks.push(TrustCheck {
                name: "key_pin".to_string(),
                passed: authorized,
                detail: if authorized {
                    "Key authorized for path (or path not pinned)".to_string()
                } else {
                    format!(
                        "Key {} not authorized for pinned path {}",
                        signer.unwrap_or("<unsigned>"),
                        path.display()
                    )
                },
            });
            if !authorized {
                trust_level = TrustLevel::Unverified;
            }
        }

        // --- Check: trust level meets policy ---
        let meets_policy = trust_level >= self.policy.minimum_trust_level;
        checks.push(TrustCheck {
            name: "policy".to_string(),
            passed: meets_policy,
            detail: format!(
                "Trust level {} {} minimum {}",
                trust_level,
                if meets_policy { "meets" } else { "below" },
                self.policy.minimum_trust_level
            ),
        });

        // Determine overall pass/fail based on enforcement mode
        let all_critical_passed = meets_policy && trust_level != TrustLevel::Revoked;
        let passed = match self.policy.enforcement {
            TrustEnforcement::Strict => all_critical_passed,
            TrustEnforcement::Permissive => {
                if !all_critical_passed {
                    warn!(
                        path = %path.display(),
                        trust_level = %trust_level,
                        "Permissive mode: allowing artifact below minimum trust"
                    );
                }
                trust_level != TrustLevel::Revoked
            }
            TrustEnforcement::AuditOnly => {
                if !all_critical_passed {
                    warn!(
                        path = %path.display(),
                        trust_level = %trust_level,
                        "Audit-only: artifact would be blocked under strict policy"
                    );
                }
                // Revoked artifacts must NEVER pass regardless of enforcement mode
                trust_level != TrustLevel::Revoked
            }
        };

        let artifact = TrustedArtifact {
            path: path.to_path_buf(),
            artifact_type,
            content_hash,
            signature: stored.and_then(|a| a.signature.clone()),
            signer_key_id: stored.and_then(|a| a.signer_key_id.clone()),
            trust_level,
            verified_at: Some(now),
            metadata: stored.map(|a| a.metadata.clone()).unwrap_or_default(),
        };

        debug!(
            path = %path.display(),
            trust_level = %trust_level,
            passed = passed,
            checks = checks.len(),
            "Artifact verification complete"
        );

        let result = VerificationResult {
            artifact,
            passed,
            checks,
            verified_at: now,
        };

        // Record audit event
        if let Ok(mut log) = self.audit_log.write() {
            log.record(AuditEvent::ArtifactVerified {
                path: result.artifact.path.clone(),
                artifact_type: result.artifact.artifact_type,
                trust_level: result.artifact.trust_level,
                passed: result.passed,
                content_hash: result.artifact.content_hash.clone(),
                timestamp: now,
            });
        }

        // Store in cache
        if self.cache_enabled
            && let Ok(meta) = std::fs::metadata(path)
            && let Ok(mtime) = meta.modified()
            && let Ok(mut c) = self.cache.write()
        {
            c.insert(
                path.to_path_buf(),
                CacheEntry {
                    mtime,
                    size: meta.len(),
                    result: result.clone(),
                },
            );
        }

        Ok(result)
    }

    /// Convenience method: verify an agent binary.
    ///
    /// In addition to standard artifact verification, checks that the file
    /// has execute permission and that unsigned agents are allowed by policy.
    pub fn verify_agent_binary(&self, path: &Path) -> error::Result<VerificationResult> {
        // Early-return if policy says not to verify on execute
        if !self.policy.verify_on_execute {
            debug!(
                path = %path.display(),
                "Skipping agent binary verification (verify_on_execute=false)"
            );
            let now = Utc::now();
            return Ok(VerificationResult {
                artifact: TrustedArtifact {
                    path: path.to_path_buf(),
                    artifact_type: ArtifactType::AgentBinary,
                    content_hash: String::new(),
                    signature: None,
                    signer_key_id: None,
                    trust_level: TrustLevel::Unverified,
                    verified_at: Some(now),
                    metadata: HashMap::new(),
                },
                passed: true,
                checks: vec![TrustCheck {
                    name: "skipped".to_string(),
                    passed: true,
                    detail: "Verification skipped: verify_on_execute is disabled".to_string(),
                }],
                verified_at: now,
            });
        }

        let mut result = self.verify_artifact(path, ArtifactType::AgentBinary)?;

        // Check execute permission
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path).map_err(|e| error::io_err(e, path))?;
            let executable = meta.permissions().mode() & 0o111 != 0;
            result.checks.push(TrustCheck {
                name: "execute_permission".to_string(),
                passed: executable,
                detail: if executable {
                    "File has execute permission".to_string()
                } else {
                    "File lacks execute permission".to_string()
                },
            });
            if !executable {
                result.passed = false;
            }
        }

        // Unsigned agent check — blocks in both Strict and Permissive when
        // allow_unsigned_agents is false.
        if result.artifact.signature.is_none() && !self.policy.allow_unsigned_agents {
            result.checks.push(TrustCheck {
                name: "unsigned_agent".to_string(),
                passed: false,
                detail: "Unsigned agent binaries are not allowed by policy".to_string(),
            });
            if self.policy.enforcement == TrustEnforcement::Strict
                || self.policy.enforcement == TrustEnforcement::Permissive
            {
                result.passed = false;
            }
        }

        Ok(result)
    }

    /// Verify a package file (`.ark` or `.deb`).
    ///
    /// If `expected_hash` is provided, the file's hash must match it exactly.
    pub fn verify_package(
        &self,
        path: &Path,
        expected_hash: Option<&str>,
    ) -> error::Result<VerificationResult> {
        // Early-return if policy says not to verify on install
        if !self.policy.verify_on_install {
            debug!(
                path = %path.display(),
                "Skipping package verification (verify_on_install=false)"
            );
            let now = Utc::now();
            return Ok(VerificationResult {
                artifact: TrustedArtifact {
                    path: path.to_path_buf(),
                    artifact_type: ArtifactType::Package,
                    content_hash: String::new(),
                    signature: None,
                    signer_key_id: None,
                    trust_level: TrustLevel::Unverified,
                    verified_at: Some(now),
                    metadata: HashMap::new(),
                },
                passed: true,
                checks: vec![TrustCheck {
                    name: "skipped".to_string(),
                    passed: true,
                    detail: "Verification skipped: verify_on_install is disabled".to_string(),
                }],
                verified_at: now,
            });
        }

        let mut result = self.verify_artifact(path, ArtifactType::Package)?;

        if let Some(expected) = expected_hash {
            let matches: bool = result
                .artifact
                .content_hash
                .as_bytes()
                .ct_eq(expected.as_bytes())
                .into();
            result.checks.push(TrustCheck {
                name: "expected_hash".to_string(),
                passed: matches,
                detail: if matches {
                    format!("Content hash matches expected {}", expected)
                } else {
                    format!(
                        "Hash mismatch: got {} expected {}",
                        result.artifact.content_hash, expected
                    )
                },
            });
            if !matches {
                result.passed = false;
            }
        }

        Ok(result)
    }

    /// Sign an artifact and register it in the trust store.
    ///
    /// Reads the file, computes the SHA-256 hash, signs the hash with the
    /// given key, and stores the result.
    pub fn sign_artifact(
        &mut self,
        path: &Path,
        signing_key: &SigningKey,
        artifact_type: ArtifactType,
    ) -> error::Result<TrustedArtifact> {
        let data = std::fs::read(path).map_err(|e| error::io_err(e, path))?;

        let content_hash = hash_data_with(&data, self.policy.hash_algorithm);
        let signature = sign_data(content_hash.as_bytes(), signing_key);
        let vk = signing_key.verifying_key();
        let key_id = key_id_from_verifying_key(&vk);
        let now = Utc::now();

        // Determine trust level based on whether the key is in the keyring
        // and currently valid. Unknown signers get Community trust.
        let trust_level = match self.keyring.get_current_key(&key_id) {
            Some(_) => TrustLevel::Verified,
            None => {
                warn!(
                    key_id = %key_id,
                    "Signing key not found in keyring; assigning Community trust"
                );
                TrustLevel::Community
            }
        };

        let artifact = TrustedArtifact {
            path: path.to_path_buf(),
            artifact_type,
            content_hash: content_hash.clone(),
            signature: Some(signature),
            signer_key_id: Some(key_id.clone()),
            trust_level,
            verified_at: Some(now),
            metadata: HashMap::new(),
        };

        info!(
            path = %path.display(),
            key_id = %key_id,
            hash = %content_hash,
            "Artifact signed and registered"
        );

        if let Ok(mut log) = self.audit_log.write() {
            log.record(AuditEvent::ArtifactSigned {
                path: artifact.path.clone(),
                artifact_type: artifact.artifact_type,
                signer_key_id: key_id,
                content_hash: content_hash.clone(),
                timestamp: now,
            });
        }

        self.trust_store.insert(content_hash, artifact.clone());
        Ok(artifact)
    }

    /// Register a pre-built `TrustedArtifact` in the trust store.
    ///
    /// `SystemCore` trust level is not allowed through this method — it will
    /// be downgraded to `Verified`. Use `register_system_core()` for
    /// system-critical components.
    pub fn register_trusted(&mut self, mut artifact: TrustedArtifact) {
        if artifact.trust_level == TrustLevel::SystemCore {
            warn!(
                path = %artifact.path.display(),
                hash = %artifact.content_hash,
                "SystemCore trust level not allowed via register_trusted; downgrading to Verified"
            );
            artifact.trust_level = TrustLevel::Verified;
        }
        debug!(
            path = %artifact.path.display(),
            hash = %artifact.content_hash,
            trust_level = %artifact.trust_level,
            "Artifact registered in trust store"
        );
        self.trust_store
            .insert(artifact.content_hash.clone(), artifact);
    }

    /// Register a system-core artifact in the trust store.
    ///
    /// This is the only path to `SystemCore` trust. In the future this may
    /// require additional attestation (e.g. TPM measurement).
    pub fn register_system_core(&mut self, artifact: TrustedArtifact) {
        debug!(
            path = %artifact.path.display(),
            hash = %artifact.content_hash,
            "SystemCore artifact registered in trust store"
        );
        let mut art = artifact;
        art.trust_level = TrustLevel::SystemCore;
        self.trust_store.insert(art.content_hash.clone(), art);
    }

    /// Check whether a key or artifact hash has been revoked.
    ///
    /// Returns `true` if revoked. Does not consider `revoked_after` timestamps
    /// (treats all revocations as unconditional).
    #[cfg(feature = "policy")]
    #[must_use]
    pub fn check_revocation(&self, key_id: Option<&str>, content_hash: &str) -> bool {
        self.check_revocation_at(key_id, content_hash, None)
    }

    /// Check whether a key or artifact hash has been revoked at a specific time.
    ///
    /// When `at` is `Some`, revocation entries with `revoked_after` are only
    /// considered if `at >= revoked_after`. This allows artifacts verified
    /// before a key compromise to remain valid.
    #[cfg(feature = "policy")]
    #[must_use]
    pub fn check_revocation_at(
        &self,
        key_id: Option<&str>,
        content_hash: &str,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> bool {
        if self.revocations.is_artifact_revoked_at(content_hash, at) {
            return true;
        }
        if let Some(kid) = key_id
            && self.revocations.is_key_revoked_at(kid, at)
        {
            return true;
        }
        false
    }

    /// Return the number of entries in the revocation list.
    #[cfg(feature = "policy")]
    #[must_use]
    pub fn revocation_count(&self) -> usize {
        self.revocations.len()
    }

    /// Add a revocation entry.
    #[cfg(feature = "policy")]
    pub fn add_revocation(&mut self, entry: RevocationEntry) -> error::Result<()> {
        info!(
            key_id = ?entry.key_id,
            content_hash = ?entry.content_hash,
            reason = %entry.reason,
            "Revocation added"
        );
        self.revocations.add(entry)
    }

    /// Look up the trust level for a content hash. Returns `Unverified` if
    /// the hash is not in the trust store.
    #[must_use]
    pub fn trust_level_for(&self, content_hash: &str) -> TrustLevel {
        self.trust_store
            .get(content_hash)
            .map(|a| a.trust_level)
            .unwrap_or(TrustLevel::Unverified)
    }

    /// Return a reference to the active trust policy.
    #[must_use]
    pub fn policy(&self) -> &TrustPolicy {
        &self.policy
    }

    /// Verify a list of boot-critical component paths.
    ///
    /// Builds an `IntegrityPolicy` from the trust store entries for the
    /// given paths and runs a full integrity check.
    #[cfg(feature = "chain")]
    pub fn verify_boot_chain(&mut self, components: &[PathBuf]) -> error::Result<IntegrityReport> {
        use super::chain::verify_boot_chain_impl;
        verify_boot_chain_impl(
            &self.policy,
            &mut self.integrity,
            &self.trust_store,
            components,
        )
    }

    /// Save the trust store to a JSON file on disk.
    pub fn save_trust_store(&self, path: &Path) -> error::Result<()> {
        let artifacts: Vec<&TrustedArtifact> = self.trust_store.values().collect();
        let json = serde_json::to_string_pretty(&artifacts)?;
        std::fs::write(path, json).map_err(|e| error::io_err(e, path))?;
        info!(path = %path.display(), count = artifacts.len(), "Trust store saved");
        Ok(())
    }

    /// Load trust store entries from a JSON file on disk.
    ///
    /// Returns the number of entries loaded. Existing entries with the same
    /// content hash are overwritten.
    pub fn load_trust_store(&mut self, path: &Path) -> error::Result<usize> {
        let json = std::fs::read_to_string(path).map_err(|e| error::io_err(e, path))?;
        let artifacts: Vec<TrustedArtifact> = serde_json::from_str(&json)?;
        let count = artifacts.len();
        for artifact in artifacts {
            self.trust_store
                .insert(artifact.content_hash.clone(), artifact);
        }
        info!(path = %path.display(), count = count, "Trust store loaded");
        Ok(count)
    }

    /// Save the revocation list to a JSON file on disk.
    #[cfg(feature = "policy")]
    pub fn save_revocations(&self, path: &Path) -> error::Result<()> {
        let json = self.revocations.to_json()?;
        std::fs::write(path, json).map_err(|e| error::io_err(e, path))?;
        info!(path = %path.display(), count = self.revocations.len(), "Revocations saved");
        Ok(())
    }

    /// Load revocation entries from a JSON file on disk.
    ///
    /// Returns the number of entries loaded. Entries are appended to the
    /// existing revocation list.
    #[cfg(feature = "policy")]
    pub fn load_revocations(&mut self, path: &Path) -> error::Result<usize> {
        let json = std::fs::read_to_string(path).map_err(|e| error::io_err(e, path))?;
        let loaded = RevocationList::from_json(&json)?;
        let count = loaded.len();
        for entry in loaded.entries {
            self.revocations.add(entry)?;
        }
        info!(path = %path.display(), count = count, "Revocations loaded");
        Ok(count)
    }

    /// Compute summary statistics for the trust store.
    #[must_use]
    pub fn stats(&self) -> SigilStats {
        let total_artifacts = self.trust_store.len();
        let verified_count = self
            .trust_store
            .values()
            .filter(|a| a.verified_at.is_some())
            .count();
        let revoked_count = self
            .trust_store
            .values()
            .filter(|a| a.trust_level == TrustLevel::Revoked)
            .count();

        let mut trust_level_counts: HashMap<TrustLevel, usize> = HashMap::new();
        for artifact in self.trust_store.values() {
            *trust_level_counts.entry(artifact.trust_level).or_insert(0) += 1;
        }

        SigilStats {
            total_artifacts,
            verified_count,
            revoked_count,
            trust_level_counts,
        }
    }

    /// Verify multiple artifacts in a single call.
    ///
    /// Returns a `Vec` of results in the same order as the input. Each entry
    /// is `Ok(VerificationResult)` or `Err(SigilError)` if the file could not
    /// be read.
    ///
    /// With the `parallel` feature enabled, file I/O and hash computation
    /// are parallelized via rayon.
    #[must_use]
    pub fn verify_batch(
        &self,
        artifacts: &[(&Path, ArtifactType)],
    ) -> Vec<error::Result<VerificationResult>> {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            artifacts
                .par_iter()
                .map(|(path, artifact_type)| self.verify_artifact(path, *artifact_type))
                .collect()
        }
        #[cfg(not(feature = "parallel"))]
        {
            artifacts
                .iter()
                .map(|(path, artifact_type)| self.verify_artifact(path, *artifact_type))
                .collect()
        }
    }

    /// Snapshot the trust store for later diffing.
    #[must_use]
    pub fn snapshot_trust_store(&self) -> HashMap<String, TrustedArtifact> {
        self.trust_store.clone()
    }

    /// Compute the diff between the current trust store and a previous snapshot.
    #[must_use]
    pub fn diff_trust_store(&self, old: &HashMap<String, TrustedArtifact>) -> TrustStoreDiff {
        TrustStoreDiff::compute(old, &self.trust_store)
    }
}

// ---------------------------------------------------------------------------
// Trust store diff
// ---------------------------------------------------------------------------

/// A changed artifact in the trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactChange {
    /// Content hash of the artifact.
    pub content_hash: String,
    /// Trust level before the change (None if added).
    pub old_trust_level: Option<TrustLevel>,
    /// Trust level after the change (None if removed).
    pub new_trust_level: Option<TrustLevel>,
    /// Path of the artifact.
    pub path: PathBuf,
}

/// Diff between two trust store snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStoreDiff {
    /// Artifacts added since the old snapshot.
    pub added: Vec<ArtifactChange>,
    /// Artifacts removed since the old snapshot.
    pub removed: Vec<ArtifactChange>,
    /// Artifacts whose trust level changed.
    pub changed: Vec<ArtifactChange>,
}

impl TrustStoreDiff {
    /// Compute the diff between an old and new trust store.
    #[must_use]
    pub fn compute(
        old: &HashMap<String, TrustedArtifact>,
        new: &HashMap<String, TrustedArtifact>,
    ) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut changed = Vec::new();

        // Find added and changed
        for (hash, new_art) in new {
            match old.get(hash) {
                None => added.push(ArtifactChange {
                    content_hash: hash.clone(),
                    old_trust_level: None,
                    new_trust_level: Some(new_art.trust_level),
                    path: new_art.path.clone(),
                }),
                Some(old_art) if old_art.trust_level != new_art.trust_level => {
                    changed.push(ArtifactChange {
                        content_hash: hash.clone(),
                        old_trust_level: Some(old_art.trust_level),
                        new_trust_level: Some(new_art.trust_level),
                        path: new_art.path.clone(),
                    });
                }
                _ => {}
            }
        }

        // Find removed
        for (hash, old_art) in old {
            if !new.contains_key(hash) {
                removed.push(ArtifactChange {
                    content_hash: hash.clone(),
                    old_trust_level: Some(old_art.trust_level),
                    new_trust_level: None,
                    path: old_art.path.clone(),
                });
            }
        }

        Self {
            added,
            removed,
            changed,
        }
    }

    /// Returns true if there are no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Total number of changes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.added.len() + self.removed.len() + self.changed.len()
    }
}
