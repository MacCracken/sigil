//! Marketplace Trust & Signing
//!
//! Ed25519 package signing and verification. Publishers sign their bundles
//! offline; the registry and local installer verify signatures before use.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

use crate::types::HashAlgorithm;

use crate::error::{self, SigilError};

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/// Metadata describing a key's publisher and authorized scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Human-readable publisher name (e.g. "AGNOS Core Team").
    #[serde(default)]
    pub publisher_name: Option<String>,
    /// Publisher contact (e.g. email or URL).
    #[serde(default)]
    pub publisher_contact: Option<String>,
    /// Artifact types this key is authorized to sign.
    /// Empty means all types are allowed.
    #[serde(default)]
    pub allowed_artifact_types: Vec<crate::types::ArtifactType>,
    /// Path prefixes this key is authorized to sign.
    /// Empty means all paths are allowed.
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,
}

/// The role of a key in the trust hierarchy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum KeyRole {
    /// Root of trust — self-signed, highest authority.
    Root,
    /// Intermediate CA — signed by root or another intermediate.
    Intermediate,
    /// End-entity publisher key — signs artifacts.
    #[default]
    Publisher,
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root => write!(f, "Root"),
            Self::Intermediate => write!(f, "Intermediate"),
            Self::Publisher => write!(f, "Publisher"),
        }
    }
}

/// A versioned publisher key with validity window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Short hex identifier (first 8 bytes of public key).
    pub key_id: String,
    /// When this key became valid.
    pub valid_from: DateTime<Utc>,
    /// When this key expires (None = no expiry).
    pub valid_until: Option<DateTime<Utc>>,
    /// Ed25519 public key bytes (32 bytes, hex-encoded for serialization).
    pub public_key_hex: String,
    /// Role in the trust hierarchy.
    #[serde(default)]
    pub role: KeyRole,
    /// Key ID of the issuer that signed this key (None = self-signed / root).
    #[serde(default)]
    pub issued_by: Option<String>,
    /// Signature from the issuer over this key's public key bytes.
    #[serde(default)]
    pub issuer_signature: Option<Vec<u8>>,
    /// Publisher and scope metadata.
    #[serde(default)]
    pub metadata: KeyMetadata,
}

impl KeyVersion {
    /// Check if the key is valid at the given time.
    #[must_use]
    pub fn is_valid_at(&self, when: DateTime<Utc>) -> bool {
        if when < self.valid_from {
            return false;
        }
        if let Some(until) = self.valid_until
            && when > until
        {
            return false;
        }
        true
    }

    /// Decode the public key from hex.
    pub fn verifying_key(&self) -> error::Result<VerifyingKey> {
        let bytes = hex::decode(&self.public_key_hex).map_err(|e| SigilError::InvalidInput {
            detail: format!("invalid hex in public key: {e}"),
        })?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| SigilError::InvalidInput {
            detail: "public key must be 32 bytes".to_string(),
        })?;
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| SigilError::Crypto {
            detail: format!("invalid Ed25519 public key: {e}"),
        })
    }
}

/// Keyring storing trusted publisher public keys.
pub struct PublisherKeyring {
    /// Keys indexed by key_id.
    keys: HashMap<String, Vec<KeyVersion>>,
    /// Directory where key files are stored.
    keys_dir: PathBuf,
}

impl PublisherKeyring {
    /// Create a new keyring backed by the given directory.
    pub fn new(keys_dir: &Path) -> Self {
        Self {
            keys: HashMap::new(),
            keys_dir: keys_dir.to_path_buf(),
        }
    }

    /// Load all key files from the keys directory.
    pub fn load(&mut self) -> error::Result<usize> {
        self.keys.clear();
        let mut count = 0;

        if !self.keys_dir.exists() {
            return Ok(0);
        }

        let entries =
            std::fs::read_dir(&self.keys_dir).map_err(|e| error::io_err(e, &self.keys_dir))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match std::fs::read_to_string(&path) {
                    Ok(content) => match serde_json::from_str::<Vec<KeyVersion>>(&content) {
                        Ok(versions) => {
                            for kv in &versions {
                                self.keys
                                    .entry(kv.key_id.clone())
                                    .or_default()
                                    .push(kv.clone());
                                count += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Skipping malformed key file {}: {}", path.display(), e);
                        }
                    },
                    Err(e) => {
                        tracing::warn!("Failed to read key file {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(count)
    }

    /// Add a key version to the keyring (in-memory only).
    pub fn add_key(&mut self, key: KeyVersion) {
        self.keys.entry(key.key_id.clone()).or_default().push(key);
    }

    /// Look up the current valid key for a given key_id.
    #[must_use]
    pub fn get_current_key(&self, key_id: &str) -> Option<&KeyVersion> {
        let now = Utc::now();
        self.keys.get(key_id)?.iter().find(|k| k.is_valid_at(now))
    }

    /// Get all key versions for a key_id (including expired).
    #[must_use]
    pub fn get_all_versions(&self, key_id: &str) -> Vec<&KeyVersion> {
        self.keys
            .get(key_id)
            .map(|versions| versions.iter().collect())
            .unwrap_or_default()
    }

    /// Number of distinct key IDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the keyring contains no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Rotate a key: expire the current version and add a new one.
    ///
    /// The old key's `valid_until` is set to `overlap_until`, and the new key's
    /// `valid_from` is set to `now`. This creates an overlap window where both
    /// keys are valid, allowing a graceful transition.
    ///
    /// Returns the new `KeyVersion` that was added.
    pub fn rotate_key(
        &mut self,
        key_id: &str,
        new_public_key_hex: String,
        overlap_until: DateTime<Utc>,
    ) -> error::Result<KeyVersion> {
        let now = Utc::now();

        // Expire the current active version
        let versions = self
            .keys
            .get_mut(key_id)
            .ok_or_else(|| SigilError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

        for v in versions.iter_mut() {
            if v.is_valid_at(now) && v.valid_until.is_none() {
                v.valid_until = Some(overlap_until);
            }
        }

        let new_version = KeyVersion {
            key_id: key_id.to_string(),
            valid_from: now,
            valid_until: None,
            public_key_hex: new_public_key_hex,
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };

        versions.push(new_version.clone());
        Ok(new_version)
    }

    /// Check whether any version of a key was valid at the given time.
    ///
    /// Useful for historical verification — e.g., verifying an artifact that
    /// was signed before a key was rotated.
    #[must_use]
    pub fn get_key_valid_at(&self, key_id: &str, when: DateTime<Utc>) -> Option<&KeyVersion> {
        self.keys.get(key_id)?.iter().find(|k| k.is_valid_at(when))
    }

    /// Return all distinct key IDs in the keyring.
    #[must_use]
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(|s| s.as_str()).collect()
    }

    /// Find all keys by publisher name (case-insensitive substring match).
    #[must_use]
    pub fn find_by_publisher(&self, name: &str) -> Vec<&KeyVersion> {
        let lower = name.to_lowercase();
        self.keys
            .values()
            .flatten()
            .filter(|kv| {
                kv.metadata
                    .publisher_name
                    .as_ref()
                    .is_some_and(|n| n.to_lowercase().contains(&lower))
            })
            .collect()
    }

    /// Find all keys with a given role.
    #[must_use]
    pub fn find_by_role(&self, role: KeyRole) -> Vec<&KeyVersion> {
        self.keys
            .values()
            .flatten()
            .filter(|kv| kv.role == role)
            .collect()
    }

    /// Get the trust chain for a key: walks `issued_by` links back to a root.
    ///
    /// Returns the chain from the given key up to the root (inclusive).
    /// Returns `None` if any link in the chain is missing from the keyring.
    #[must_use]
    pub fn get_chain(&self, key_id: &str) -> Option<Vec<&KeyVersion>> {
        let mut chain = Vec::new();
        let mut current_id = key_id;
        let now = Utc::now();

        loop {
            let kv = self
                .keys
                .get(current_id)?
                .iter()
                .find(|k| k.is_valid_at(now))?;
            chain.push(kv);

            match &kv.issued_by {
                Some(issuer_id) if issuer_id != current_id => {
                    current_id = issuer_id;
                }
                _ => break, // Self-signed or no issuer = root
            }
        }

        Some(chain)
    }

    /// Validate a key's chain of trust back to a root key.
    ///
    /// Verifies that each key in the chain was signed by its issuer.
    /// Returns `true` if the chain is valid and terminates at a `Root` key.
    pub fn validate_chain(&self, key_id: &str) -> error::Result<bool> {
        let chain = self
            .get_chain(key_id)
            .ok_or_else(|| SigilError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

        if chain.is_empty() {
            return Ok(false);
        }

        // Last element should be a root
        let root = &chain[chain.len() - 1];
        if root.role != KeyRole::Root {
            return Ok(false);
        }

        // Validate each link: chain[i] should be signed by chain[i+1]
        for window in chain.windows(2) {
            let child = &window[0];
            let parent = &window[1];

            let sig = match &child.issuer_signature {
                Some(s) => s,
                None => return Ok(false),
            };

            let parent_vk = parent.verifying_key()?;
            let child_pub_bytes =
                hex::decode(&child.public_key_hex).map_err(|e| SigilError::InvalidInput {
                    detail: format!("invalid hex in child key: {e}"),
                })?;

            if verify_signature(&child_pub_bytes, sig, &parent_vk).is_err() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Save all keys to the keys directory as JSON files.
    ///
    /// Each key ID gets its own file: `<key_id>.json`.
    pub fn save(&self) -> error::Result<usize> {
        std::fs::create_dir_all(&self.keys_dir).map_err(|e| error::io_err(e, &self.keys_dir))?;
        let mut count = 0;
        for (key_id, versions) in &self.keys {
            let path = self.keys_dir.join(format!("{key_id}.json"));
            let json = serde_json::to_string_pretty(versions)?;
            std::fs::write(&path, json).map_err(|e| error::io_err(e, &path))?;
            count += versions.len();
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of arbitrary data.
#[must_use]
pub fn hash_data(data: &[u8]) -> String {
    hash_data_with(data, HashAlgorithm::Sha256)
}

/// Compute hash of arbitrary data using the specified algorithm.
#[must_use]
pub fn hash_data_with(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize().as_slice())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            hex::encode(hasher.finalize().as_slice())
        }
    }
}

/// Sign data with an Ed25519 signing key. Returns the signature bytes.
#[must_use]
pub fn sign_data(data: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    let signature = signing_key.sign(data);
    signature.to_bytes().to_vec()
}

/// Verify a signature against data and a verifying key.
pub fn verify_signature(
    data: &[u8],
    signature_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> error::Result<()> {
    let sig_bytes: [u8; 64] =
        signature_bytes
            .try_into()
            .map_err(|_| SigilError::SignatureInvalid {
                detail: "signature must be 64 bytes".to_string(),
            })?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(data, &signature)
        .map_err(|e| SigilError::SignatureInvalid {
            detail: format!("verification failed: {e}"),
        })
}

/// Generate a new Ed25519 keypair. Returns (signing_key, verifying_key, key_id).
#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey, String) {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    let key_id = hex::encode(&verifying_key.to_bytes()[..8]);
    (signing_key, verifying_key, key_id)
}

/// Derive key_id from a verifying key (hex of first 8 bytes).
#[must_use]
pub fn key_id_from_verifying_key(vk: &VerifyingKey) -> String {
    hex::encode(&vk.to_bytes()[..8])
}

/// Hex-encode raw bytes. Exposed for crate-internal use (e.g. integrity hash output).
#[must_use]
pub(crate) fn hash_hex(data: &[u8]) -> String {
    hex::encode(data)
}

// Minimal inline hex implementation — avoids adding the `hex` crate.
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    pub fn decode(s: &str) -> std::result::Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("hex string has odd length".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex: {e}")))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (sk, vk, key_id) = generate_keypair();
        assert_eq!(key_id.len(), 16); // 8 bytes = 16 hex chars
        assert_eq!(key_id, key_id_from_verifying_key(&vk));
        // Verify signing key matches verifying key
        assert_eq!(sk.verifying_key(), vk);
    }

    #[test]
    fn test_sign_and_verify() {
        let (sk, vk, _) = generate_keypair();
        let data = b"hello marketplace";
        let sig = sign_data(data, &sk);
        assert_eq!(sig.len(), 64);
        assert!(verify_signature(data, &sig, &vk).is_ok());
    }

    #[test]
    fn test_verify_wrong_data() {
        let (sk, vk, _) = generate_keypair();
        let sig = sign_data(b"original", &sk);
        assert!(verify_signature(b"tampered", &sig, &vk).is_err());
    }

    #[test]
    fn test_verify_wrong_key() {
        let (sk, _, _) = generate_keypair();
        let (_, vk2, _) = generate_keypair();
        let sig = sign_data(b"data", &sk);
        assert!(verify_signature(b"data", &sig, &vk2).is_err());
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let (_, vk, _) = generate_keypair();
        assert!(verify_signature(b"data", &[0u8; 32], &vk).is_err());
    }

    #[test]
    fn test_hash_data() {
        let hash = hash_data(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_hash_data_empty() {
        let hash = hash_data(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_key_version_validity() {
        let now = Utc::now();
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: now - chrono::Duration::hours(1),
            valid_until: Some(now + chrono::Duration::hours(1)),
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        assert!(kv.is_valid_at(now));
        assert!(!kv.is_valid_at(now - chrono::Duration::hours(2)));
        assert!(!kv.is_valid_at(now + chrono::Duration::hours(2)));
    }

    #[test]
    fn test_key_version_no_expiry() {
        let now = Utc::now();
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: now - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        assert!(kv.is_valid_at(now));
        assert!(kv.is_valid_at(now + chrono::Duration::days(365)));
    }

    #[test]
    fn test_key_version_not_yet_valid() {
        let now = Utc::now();
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: now + chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        assert!(!kv.is_valid_at(now));
    }

    #[test]
    fn test_key_version_verifying_key() {
        let (_, vk, _) = generate_keypair();
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: hex::encode(&vk.to_bytes()),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        let recovered = kv.verifying_key().unwrap();
        assert_eq!(recovered, vk);
    }

    #[test]
    fn test_key_version_invalid_hex() {
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "not-hex".to_string(),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        assert!(kv.verifying_key().is_err());
    }

    #[test]
    fn test_key_version_wrong_length() {
        let kv = KeyVersion {
            key_id: "test".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "aabb".to_string(),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        };
        assert!(kv.verifying_key().is_err());
    }

    #[test]
    fn test_keyring_empty() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = PublisherKeyring::new(dir.path());
        assert!(keyring.is_empty());
        assert_eq!(keyring.len(), 0);
    }

    #[test]
    fn test_keyring_add_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());
        let (_, vk, key_id) = generate_keypair();

        keyring.add_key(KeyVersion {
            key_id: key_id.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&vk.to_bytes()),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        assert_eq!(keyring.len(), 1);
        let found = keyring.get_current_key(&key_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().key_id, key_id);
    }

    #[test]
    fn test_keyring_expired_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());
        let now = Utc::now();

        keyring.add_key(KeyVersion {
            key_id: "expired".to_string(),
            valid_from: now - chrono::Duration::hours(2),
            valid_until: Some(now - chrono::Duration::hours(1)),
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        assert!(keyring.get_current_key("expired").is_none());
        assert_eq!(keyring.get_all_versions("expired").len(), 1);
    }

    #[test]
    fn test_keyring_load_from_dir() {
        let dir = tempfile::tempdir().unwrap();
        let (_, vk, key_id) = generate_keypair();

        let keys = vec![KeyVersion {
            key_id: key_id.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&vk.to_bytes()),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        }];

        let key_file = dir.path().join("publisher.json");
        std::fs::write(&key_file, serde_json::to_string(&keys).unwrap()).unwrap();

        let mut keyring = PublisherKeyring::new(dir.path());
        let count = keyring.load().unwrap();
        assert_eq!(count, 1);
        assert!(keyring.get_current_key(&key_id).is_some());
    }

    #[test]
    fn test_keyring_load_nonexistent_dir() {
        let mut keyring = PublisherKeyring::new(Path::new("/tmp/nonexistent_keyring_dir_12345"));
        let count = keyring.load().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_keyring_load_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.json"), "not valid json").unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());
        let count = keyring.load().unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_keyring_get_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = PublisherKeyring::new(dir.path());
        assert!(keyring.get_current_key("nope").is_none());
        assert!(keyring.get_all_versions("nope").is_empty());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0u8, 1, 15, 16, 255];
        let encoded = hex::encode(&data);
        assert_eq!(encoded, "00010f10ff");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_error() {
        assert!(hex::decode("zz").is_err());
        assert!(hex::decode("abc").is_err()); // odd length
    }

    #[test]
    fn test_sign_verify_roundtrip_with_keyring() {
        let (sk, vk, key_id) = generate_keypair();
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        keyring.add_key(KeyVersion {
            key_id: key_id.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&vk.to_bytes()),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        let data = b"package content hash";
        let sig = sign_data(data, &sk);

        let kv = keyring.get_current_key(&key_id).unwrap();
        let recovered_vk = kv.verifying_key().unwrap();
        assert!(verify_signature(data, &sig, &recovered_vk).is_ok());
    }

    #[test]
    fn test_rotate_key() {
        let dir = tempfile::tempdir().unwrap();
        let (_, vk1, key_id) = generate_keypair();
        let (_, vk2, _) = generate_keypair();

        let mut keyring = PublisherKeyring::new(dir.path());
        keyring.add_key(KeyVersion {
            key_id: key_id.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(2),
            valid_until: None,
            public_key_hex: hex::encode(&vk1.to_bytes()),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        let overlap_until = Utc::now() + chrono::Duration::hours(1);
        let new_version = keyring
            .rotate_key(&key_id, hex::encode(&vk2.to_bytes()), overlap_until)
            .unwrap();

        // New version should be valid now
        assert!(new_version.is_valid_at(Utc::now()));

        // Both versions should be valid during overlap
        let versions = keyring.get_all_versions(&key_id);
        assert_eq!(versions.len(), 2);
        let valid_now: Vec<_> = versions
            .iter()
            .filter(|v| v.is_valid_at(Utc::now()))
            .collect();
        assert_eq!(valid_now.len(), 2);

        // After overlap, only new version should be valid
        let after_overlap = overlap_until + chrono::Duration::hours(1);
        let valid_after: Vec<_> = versions
            .iter()
            .filter(|v| v.is_valid_at(after_overlap))
            .collect();
        assert_eq!(valid_after.len(), 1);
    }

    #[test]
    fn test_rotate_key_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());
        let result = keyring.rotate_key(
            "nonexistent",
            "aa".repeat(32),
            Utc::now() + chrono::Duration::hours(1),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_get_key_valid_at_historical() {
        let dir = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let mut keyring = PublisherKeyring::new(dir.path());

        // Old key: valid from 10h ago to 2h ago
        keyring.add_key(KeyVersion {
            key_id: "rotated".to_string(),
            valid_from: now - chrono::Duration::hours(10),
            valid_until: Some(now - chrono::Duration::hours(2)),
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        // New key: valid from 3h ago (overlap window was 3h ago to 2h ago)
        keyring.add_key(KeyVersion {
            key_id: "rotated".to_string(),
            valid_from: now - chrono::Duration::hours(3),
            valid_until: None,
            public_key_hex: "11".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        // Historical lookup at 5h ago should find the old key
        let old = keyring
            .get_key_valid_at("rotated", now - chrono::Duration::hours(5))
            .unwrap();
        assert_eq!(old.public_key_hex, "00".repeat(32));

        // Current lookup should find the new key
        let current = keyring.get_current_key("rotated").unwrap();
        assert_eq!(current.public_key_hex, "11".repeat(32));
    }

    #[test]
    fn test_key_ids() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());
        keyring.add_key(KeyVersion {
            key_id: "key_a".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "00".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });
        keyring.add_key(KeyVersion {
            key_id: "key_b".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "11".repeat(32),
            role: KeyRole::default(),
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        let mut ids = keyring.key_ids();
        ids.sort();
        assert_eq!(ids, vec!["key_a", "key_b"]);
    }

    #[test]
    fn test_find_by_publisher() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        keyring.add_key(KeyVersion {
            key_id: "pub1".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "00".repeat(32),
            role: KeyRole::Publisher,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata {
                publisher_name: Some("AGNOS Core Team".to_string()),
                ..KeyMetadata::default()
            },
        });

        let found = keyring.find_by_publisher("agnos");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key_id, "pub1");

        assert!(keyring.find_by_publisher("unknown").is_empty());
    }

    #[test]
    fn test_find_by_role() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        keyring.add_key(KeyVersion {
            key_id: "root1".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "00".repeat(32),
            role: KeyRole::Root,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });
        keyring.add_key(KeyVersion {
            key_id: "pub1".to_string(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: "11".repeat(32),
            role: KeyRole::Publisher,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        assert_eq!(keyring.find_by_role(KeyRole::Root).len(), 1);
        assert_eq!(keyring.find_by_role(KeyRole::Publisher).len(), 1);
        assert!(keyring.find_by_role(KeyRole::Intermediate).is_empty());
    }

    #[test]
    fn test_chain_validation() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        // Generate root key
        let (root_sk, root_vk, root_kid) = generate_keypair();

        // Generate publisher key
        let (_pub_sk, pub_vk, pub_kid) = generate_keypair();

        // Root signs the publisher's public key
        let pub_sig = sign_data(&pub_vk.to_bytes(), &root_sk);

        // Add root key (self-signed)
        keyring.add_key(KeyVersion {
            key_id: root_kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&root_vk.to_bytes()),
            role: KeyRole::Root,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata {
                publisher_name: Some("AGNOS Root".to_string()),
                ..KeyMetadata::default()
            },
        });

        // Add publisher key (issued by root)
        keyring.add_key(KeyVersion {
            key_id: pub_kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&pub_vk.to_bytes()),
            role: KeyRole::Publisher,
            issued_by: Some(root_kid.clone()),
            issuer_signature: Some(pub_sig),
            metadata: KeyMetadata {
                publisher_name: Some("Third-Party Publisher".to_string()),
                ..KeyMetadata::default()
            },
        });

        // Chain should be valid
        assert!(keyring.validate_chain(&pub_kid).unwrap());

        // Chain for root itself should be valid (single-element chain)
        assert!(keyring.validate_chain(&root_kid).unwrap());

        // Chain for unknown key should error
        assert!(keyring.validate_chain("nonexistent").is_err());
    }

    #[test]
    fn test_chain_invalid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        let (_, root_vk, root_kid) = generate_keypair();
        let (_, pub_vk, pub_kid) = generate_keypair();

        keyring.add_key(KeyVersion {
            key_id: root_kid.clone(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: hex::encode(&root_vk.to_bytes()),
            role: KeyRole::Root,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });

        // Publisher with bogus signature
        keyring.add_key(KeyVersion {
            key_id: pub_kid.clone(),
            valid_from: Utc::now(),
            valid_until: None,
            public_key_hex: hex::encode(&pub_vk.to_bytes()),
            role: KeyRole::Publisher,
            issued_by: Some(root_kid),
            issuer_signature: Some(vec![0u8; 64]),
            metadata: KeyMetadata::default(),
        });

        assert!(!keyring.validate_chain(&pub_kid).unwrap());
    }

    #[test]
    fn test_get_chain_three_levels() {
        let dir = tempfile::tempdir().unwrap();
        let mut keyring = PublisherKeyring::new(dir.path());

        let (root_sk, root_vk, root_kid) = generate_keypair();
        let (int_sk, int_vk, int_kid) = generate_keypair();
        let (_pub_sk, pub_vk, pub_kid) = generate_keypair();

        let int_sig = sign_data(&int_vk.to_bytes(), &root_sk);
        let pub_sig = sign_data(&pub_vk.to_bytes(), &int_sk);

        keyring.add_key(KeyVersion {
            key_id: root_kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&root_vk.to_bytes()),
            role: KeyRole::Root,
            issued_by: None,
            issuer_signature: None,
            metadata: KeyMetadata::default(),
        });
        keyring.add_key(KeyVersion {
            key_id: int_kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&int_vk.to_bytes()),
            role: KeyRole::Intermediate,
            issued_by: Some(root_kid),
            issuer_signature: Some(int_sig),
            metadata: KeyMetadata::default(),
        });
        keyring.add_key(KeyVersion {
            key_id: pub_kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: hex::encode(&pub_vk.to_bytes()),
            role: KeyRole::Publisher,
            issued_by: Some(int_kid),
            issuer_signature: Some(pub_sig),
            metadata: KeyMetadata::default(),
        });

        let chain = keyring.get_chain(&pub_kid).unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].role, KeyRole::Publisher);
        assert_eq!(chain[1].role, KeyRole::Intermediate);
        assert_eq!(chain[2].role, KeyRole::Root);

        assert!(keyring.validate_chain(&pub_kid).unwrap());
    }
}
