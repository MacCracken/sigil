//! Sigil types — all public types for the trust verification module.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Hash algorithm
// ---------------------------------------------------------------------------

/// Cryptographic hash algorithm used for content hashing.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HashAlgorithm {
    /// SHA-256 (default).
    #[default]
    Sha256,
    /// SHA-512.
    Sha512,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha512 => write!(f, "SHA-512"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trust levels
// ---------------------------------------------------------------------------

/// Trust level assigned to an artifact or component.
///
/// Ordered from highest trust to lowest. `SystemCore` is the most trusted,
/// `Revoked` the least.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Core OS component — signed by the AGNOS project key, measured at boot.
    SystemCore,
    /// Third-party artifact whose signature has been verified against a
    /// trusted publisher key.
    Verified,
    /// Community-contributed artifact with a valid signature but from a
    /// publisher that is not in the curated keyring.
    Community,
    /// Artifact with no signature or unknown signer.
    Unverified,
    /// Artifact or key that has been explicitly revoked.
    Revoked,
}

impl TrustLevel {
    /// Numeric rank for ordering (higher = more trusted).
    #[must_use]
    pub(super) fn rank(self) -> u8 {
        match self {
            Self::SystemCore => 4,
            Self::Verified => 3,
            Self::Community => 2,
            Self::Unverified => 1,
            Self::Revoked => 0,
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemCore => write!(f, "SystemCore"),
            Self::Verified => write!(f, "Verified"),
            Self::Community => write!(f, "Community"),
            Self::Unverified => write!(f, "Unverified"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

impl PartialOrd for TrustLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TrustLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// ---------------------------------------------------------------------------
// Enforcement mode
// ---------------------------------------------------------------------------

/// How strictly the trust policy is enforced.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustEnforcement {
    /// Block any artifact that does not meet the minimum trust level.
    Strict,
    /// Allow artifacts below the minimum trust level with a warning.
    Permissive,
    /// Log violations but never block — useful during migration.
    AuditOnly,
}

impl fmt::Display for TrustEnforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Permissive => write!(f, "Permissive"),
            Self::AuditOnly => write!(f, "AuditOnly"),
        }
    }
}

// ---------------------------------------------------------------------------
// Artifact types
// ---------------------------------------------------------------------------

/// Classification of a trusted artifact.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    /// An agent binary (executed by the runtime).
    AgentBinary,
    /// A core system binary (part of the OS).
    SystemBinary,
    /// A configuration file.
    Config,
    /// An `.ark` or `.deb` package.
    Package,
    /// A boot-critical component (kernel, initramfs, etc.).
    BootComponent,
}

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentBinary => write!(f, "AgentBinary"),
            Self::SystemBinary => write!(f, "SystemBinary"),
            Self::Config => write!(f, "Config"),
            Self::Package => write!(f, "Package"),
            Self::BootComponent => write!(f, "BootComponent"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trust policy
// ---------------------------------------------------------------------------

/// Configurable trust policy controlling verification behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// How violations are handled.
    pub enforcement: TrustEnforcement,
    /// Minimum trust level required for an artifact to be accepted.
    pub minimum_trust_level: TrustLevel,
    /// Whether unsigned agent binaries are allowed to execute.
    pub allow_unsigned_agents: bool,
    /// Verify boot-critical components on startup.
    pub verify_on_boot: bool,
    /// Verify packages before installation.
    pub verify_on_install: bool,
    /// Verify agent binaries before execution.
    pub verify_on_execute: bool,
    /// Check the revocation list during verification.
    pub revocation_check: bool,
    /// Hash algorithm used for content hashing.
    pub hash_algorithm: HashAlgorithm,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            enforcement: TrustEnforcement::Strict,
            minimum_trust_level: TrustLevel::Verified,
            allow_unsigned_agents: false,
            verify_on_boot: true,
            verify_on_install: true,
            verify_on_execute: true,
            revocation_check: true,
            hash_algorithm: HashAlgorithm::default(),
        }
    }
}

impl TrustPolicy {
    /// Start building a new `TrustPolicy` from the strict defaults.
    #[must_use]
    pub fn builder() -> TrustPolicyBuilder {
        TrustPolicyBuilder(TrustPolicy::default())
    }
}

/// Builder for [`TrustPolicy`].
#[derive(Debug, Clone)]
pub struct TrustPolicyBuilder(TrustPolicy);

impl TrustPolicyBuilder {
    /// Set the enforcement mode.
    #[must_use]
    pub fn enforcement(mut self, mode: TrustEnforcement) -> Self {
        self.0.enforcement = mode;
        self
    }

    /// Set the minimum trust level.
    #[must_use]
    pub fn minimum_trust_level(mut self, level: TrustLevel) -> Self {
        self.0.minimum_trust_level = level;
        self
    }

    /// Allow or disallow unsigned agent binaries.
    #[must_use]
    pub fn allow_unsigned_agents(mut self, allow: bool) -> Self {
        self.0.allow_unsigned_agents = allow;
        self
    }

    /// Enable or disable boot-time verification.
    #[must_use]
    pub fn verify_on_boot(mut self, enabled: bool) -> Self {
        self.0.verify_on_boot = enabled;
        self
    }

    /// Enable or disable install-time verification.
    #[must_use]
    pub fn verify_on_install(mut self, enabled: bool) -> Self {
        self.0.verify_on_install = enabled;
        self
    }

    /// Enable or disable execute-time verification.
    #[must_use]
    pub fn verify_on_execute(mut self, enabled: bool) -> Self {
        self.0.verify_on_execute = enabled;
        self
    }

    /// Enable or disable revocation checking.
    #[must_use]
    pub fn revocation_check(mut self, enabled: bool) -> Self {
        self.0.revocation_check = enabled;
        self
    }

    /// Set the hash algorithm.
    #[must_use]
    pub fn hash_algorithm(mut self, algo: HashAlgorithm) -> Self {
        self.0.hash_algorithm = algo;
        self
    }

    /// Consume the builder and produce the final [`TrustPolicy`].
    #[must_use]
    pub fn build(self) -> TrustPolicy {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Trusted artifact
// ---------------------------------------------------------------------------

/// An artifact that has been registered in the trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedArtifact {
    /// Filesystem path of the artifact.
    pub path: PathBuf,
    /// What kind of artifact this is.
    pub artifact_type: ArtifactType,
    /// SHA-256 hash of the artifact's contents.
    pub content_hash: String,
    /// Ed25519 signature bytes (if signed).
    pub signature: Option<Vec<u8>>,
    /// Key ID of the signer (if signed).
    pub signer_key_id: Option<String>,
    /// Determined trust level.
    pub trust_level: TrustLevel,
    /// When the artifact was last verified.
    pub verified_at: Option<DateTime<Utc>>,
    /// Arbitrary metadata (e.g. version, publisher name).
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

/// Outcome of verifying a single artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// The artifact that was verified.
    pub artifact: TrustedArtifact,
    /// Whether the artifact passed all checks.
    pub passed: bool,
    /// Individual checks that were performed.
    pub checks: Vec<TrustCheck>,
    /// When verification occurred.
    pub verified_at: DateTime<Utc>,
}

/// A single check performed during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCheck {
    /// Short name of the check (e.g. "signature", "revocation").
    pub name: String,
    /// Whether this check passed.
    pub passed: bool,
    /// Human-readable detail about the outcome.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Summary statistics from the trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilStats {
    /// Total artifacts in the trust store.
    pub total_artifacts: usize,
    /// How many have been verified at least once.
    pub verified_count: usize,
    /// How many are currently revoked.
    pub revoked_count: usize,
    /// Breakdown by trust level.
    pub trust_level_counts: HashMap<TrustLevel, usize>,
}
