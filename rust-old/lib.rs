#![forbid(unsafe_code)]
#![warn(missing_docs)]
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
#[cfg(feature = "tpm")]
pub mod tpm;
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
pub use policy::{Crl, RevocationEntry, RevocationList};
pub use trust::{KeyMetadata, KeyRole};
pub use types::{
    ArtifactType, Cosignature, HashAlgorithm, SigilStats, SignatureAlgorithm, TrustCheck,
    TrustEnforcement, TrustLevel, TrustPolicy, TrustPolicyBuilder, TrustedArtifact,
    VerificationResult,
};
pub use verify::{ArtifactChange, ComplianceReport, KeyPin, SigilVerifier, TrustStoreDiff};
