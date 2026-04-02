//! Sigil — System-Wide Trust Verification for AGNOS
//!
//! Unified trust module that extends marketplace signing into a complete
//! trust chain covering boot, agent binaries, configs, and packages.
//! Named after the Latin word for "seal" — sigil seals trust into AGNOS.

pub mod audit;
#[cfg(feature = "chain")]
pub mod chain;
pub mod error;
#[cfg(feature = "integrity")]
pub mod integrity;
#[cfg(feature = "policy")]
pub mod policy;
pub mod trust;
pub mod types;
pub mod verify;

#[cfg(test)]
mod tests;

// Re-export the full public API surface.
pub use audit::{AuditEvent, AuditLog};
pub use error::{Result, SigilError};
#[cfg(feature = "integrity")]
pub use integrity::{BaselineEntry, IntegritySnapshot};
#[cfg(feature = "policy")]
pub use policy::{RevocationEntry, RevocationList};
pub use trust::{KeyMetadata, KeyRole};
pub use types::{
    ArtifactType, HashAlgorithm, SigilStats, TrustCheck, TrustEnforcement, TrustLevel, TrustPolicy,
    TrustPolicyBuilder, TrustedArtifact, VerificationResult,
};
pub use verify::{ArtifactChange, KeyPin, SigilVerifier, TrustStoreDiff};
