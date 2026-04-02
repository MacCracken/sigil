//! TPM integration for hardware-backed trust attestation.
//!
//! This module defines the interface contract for TPM-backed operations.
//! The actual TPM implementation will be provided by agnosys once its
//! TPM subsystem exports are available.
//!
//! Requires the `tpm` feature flag.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error;

/// A TPM Platform Configuration Register measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurement {
    /// PCR index (0-23 for TPM 2.0).
    pub index: u8,
    /// Expected digest value (hex-encoded).
    pub expected_digest: String,
    /// Actual digest value from TPM (hex-encoded, if measured).
    pub actual_digest: Option<String>,
}

/// Result of a TPM attestation check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Whether all PCR measurements matched.
    pub passed: bool,
    /// Individual PCR measurement results.
    pub measurements: Vec<PcrMeasurement>,
    /// TPM quote signature (if remote attestation was performed).
    pub quote_signature: Option<Vec<u8>>,
}

/// Trait for TPM operations.
///
/// Implementors provide the bridge to actual TPM hardware or a TPM simulator.
/// Sigil calls these methods during `register_system_core` (when the `tpm`
/// feature is enabled) and for remote attestation flows.
///
/// The default implementation will be provided by the agnosys TPM subsystem.
pub trait TpmProvider: Send + Sync {
    /// Read the current value of a PCR register.
    fn read_pcr(&self, index: u8) -> error::Result<String>;

    /// Extend a PCR register with a new measurement.
    fn extend_pcr(&self, index: u8, digest: &str) -> error::Result<()>;

    /// Verify that all expected PCR values match the TPM state.
    fn verify_pcrs(&self, expected: &[PcrMeasurement]) -> error::Result<AttestationResult>;

    /// Seal data to the current PCR state (only readable when PCRs match).
    fn seal(&self, data: &[u8], pcr_indices: &[u8]) -> error::Result<Vec<u8>>;

    /// Unseal data (fails if PCR state has changed since sealing).
    fn unseal(&self, sealed: &[u8]) -> error::Result<Vec<u8>>;

    /// Generate a TPM quote for remote attestation.
    fn quote(&self, nonce: &[u8], pcr_indices: &[u8]) -> error::Result<Vec<u8>>;
}

/// Register a system-core component with TPM attestation.
///
/// This function measures the file into the specified PCR and returns
/// the measurement for inclusion in the trust store.
///
/// # Arguments
/// * `provider` - TPM provider implementation
/// * `path` - Path to the system-core component
/// * `pcr_index` - PCR register to extend with the measurement
pub fn measure_system_component(
    provider: &dyn TpmProvider,
    path: &Path,
    pcr_index: u8,
) -> error::Result<PcrMeasurement> {
    let hash = crate::integrity::IntegrityVerifier::compute_hash(path)?;
    provider.extend_pcr(pcr_index, &hash)?;
    let actual = provider.read_pcr(pcr_index)?;

    Ok(PcrMeasurement {
        index: pcr_index,
        expected_digest: hash,
        actual_digest: Some(actual),
    })
}
