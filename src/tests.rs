//! Tests for the sigil module.

#[cfg(test)]
#[allow(clippy::module_inception)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write as IoWrite;
    use std::path::{Path, PathBuf};

    use chrono::Utc;

    use crate::trust::PublisherKeyring;
    use crate::trust::hash_data;
    use crate::{
        ArtifactType, RevocationEntry, RevocationList, SigilVerifier, TrustEnforcement, TrustLevel,
        TrustPolicy, TrustedArtifact,
    };

    /// Helper: create a temp dir with a file inside.
    fn temp_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content).unwrap();
        p
    }

    /// Helper: make a file executable on Unix.
    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    /// Helper: generate a keyring with one key already added.
    fn keyring_with_key(
        dir: &Path,
    ) -> (
        PublisherKeyring,
        ed25519_dalek::SigningKey,
        ed25519_dalek::VerifyingKey,
        String,
    ) {
        use crate::trust::{KeyVersion, generate_keypair};

        let (sk, vk, kid) = generate_keypair();
        let mut kr = PublisherKeyring::new(dir);
        kr.add_key(KeyVersion {
            key_id: kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: {
                // Inline hex encode (same logic as trust.rs)
                vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect()
            },
        });
        (kr, sk, vk, kid)
    }

    // -----------------------------------------------------------------------
    // TrustLevel
    // -----------------------------------------------------------------------

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::SystemCore > TrustLevel::Verified);
        assert!(TrustLevel::Verified > TrustLevel::Community);
        assert!(TrustLevel::Community > TrustLevel::Unverified);
        assert!(TrustLevel::Unverified > TrustLevel::Revoked);
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(TrustLevel::SystemCore.to_string(), "SystemCore");
        assert_eq!(TrustLevel::Verified.to_string(), "Verified");
        assert_eq!(TrustLevel::Community.to_string(), "Community");
        assert_eq!(TrustLevel::Unverified.to_string(), "Unverified");
        assert_eq!(TrustLevel::Revoked.to_string(), "Revoked");
    }

    #[test]
    fn trust_level_equality() {
        assert_eq!(TrustLevel::Verified, TrustLevel::Verified);
        assert_ne!(TrustLevel::Verified, TrustLevel::Community);
    }

    // -----------------------------------------------------------------------
    // TrustPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn trust_policy_defaults() {
        let p = TrustPolicy::default();
        assert_eq!(p.enforcement, TrustEnforcement::Strict);
        assert_eq!(p.minimum_trust_level, TrustLevel::Verified);
        assert!(!p.allow_unsigned_agents);
        assert!(p.verify_on_boot);
        assert!(p.verify_on_install);
        assert!(p.verify_on_execute);
        assert!(p.revocation_check);
    }

    // -----------------------------------------------------------------------
    // TrustEnforcement
    // -----------------------------------------------------------------------

    #[test]
    fn trust_enforcement_variants() {
        assert_eq!(TrustEnforcement::Strict.to_string(), "Strict");
        assert_eq!(TrustEnforcement::Permissive.to_string(), "Permissive");
        assert_eq!(TrustEnforcement::AuditOnly.to_string(), "AuditOnly");
    }

    // -----------------------------------------------------------------------
    // ArtifactType
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_type_variants() {
        assert_eq!(ArtifactType::AgentBinary.to_string(), "AgentBinary");
        assert_eq!(ArtifactType::SystemBinary.to_string(), "SystemBinary");
        assert_eq!(ArtifactType::Config.to_string(), "Config");
        assert_eq!(ArtifactType::Package.to_string(), "Package");
        assert_eq!(ArtifactType::BootComponent.to_string(), "BootComponent");
    }

    // -----------------------------------------------------------------------
    // Verify artifact — valid signature
    // -----------------------------------------------------------------------

    #[test]
    fn verify_artifact_with_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "agent.bin", b"trusted binary");

        let (kr, sk, _vk, kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        // Sign and register
        let artifact = verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();
        assert_eq!(artifact.trust_level, TrustLevel::Verified);
        assert_eq!(artifact.signer_key_id.as_deref(), Some(kid.as_str()));

        // Verify
        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "signature" && c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // Verify artifact — no signature, strict → fail
    // -----------------------------------------------------------------------

    #[test]
    fn verify_unsigned_artifact_strict_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "unsigned.bin", b"no sig");

        let kr = PublisherKeyring::new(dir.path());
        let verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(!result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Unverified);
    }

    // -----------------------------------------------------------------------
    // Verify artifact — no signature, permissive → pass with lower trust
    // -----------------------------------------------------------------------

    #[test]
    fn verify_unsigned_artifact_permissive_passes() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "unsigned.bin", b"no sig");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::Permissive;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        // Permissive allows non-revoked artifacts even below minimum trust
        assert!(result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Unverified);
    }

    // -----------------------------------------------------------------------
    // Verify artifact — wrong signature
    // -----------------------------------------------------------------------

    #[test]
    fn verify_artifact_wrong_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "bad_sig.bin", b"content");
        let content_hash = hash_data(b"content");

        let (kr, _sk, _vk, kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        // Register with a bogus signature
        verifier.register_trusted(TrustedArtifact {
            path: path.clone(),
            artifact_type: ArtifactType::AgentBinary,
            content_hash: content_hash.clone(),
            signature: Some(vec![0u8; 64]),
            signer_key_id: Some(kid),
            trust_level: TrustLevel::Verified,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        // Signature check should fail
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "signature" && !c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // Revoked key
    // -----------------------------------------------------------------------

    #[test]
    fn verify_revoked_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "rev.bin", b"revoked key content");

        let (kr, sk, _vk, kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();

        // Revoke the key
        verifier
            .add_revocation(RevocationEntry {
                key_id: Some(kid.clone()),
                content_hash: None,
                reason: "Compromised".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "admin".to_string(),
            })
            .unwrap();

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(!result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Revoked);
    }

    // -----------------------------------------------------------------------
    // Revoked artifact hash
    // -----------------------------------------------------------------------

    #[test]
    fn verify_revoked_artifact_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "rev_hash.bin", b"revoked hash content");
        let content_hash = hash_data(b"revoked hash content");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .sign_artifact(&path, &sk, ArtifactType::Config)
            .unwrap();

        verifier
            .add_revocation(RevocationEntry {
                key_id: None,
                content_hash: Some(content_hash),
                reason: "Malicious config".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "audit-bot".to_string(),
            })
            .unwrap();

        let result = verifier
            .verify_artifact(&path, ArtifactType::Config)
            .unwrap();
        assert!(!result.passed);
    }

    // -----------------------------------------------------------------------
    // RevocationList
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_list_add_check() {
        let mut rl = RevocationList::new();
        assert!(rl.is_empty());
        assert_eq!(rl.len(), 0);

        rl.add(RevocationEntry {
            key_id: Some("key1".to_string()),
            content_hash: None,
            reason: "test".to_string(),
            revoked_at: Utc::now(),
            revoked_by: "tester".to_string(),
        })
        .unwrap();
        assert_eq!(rl.len(), 1);
        assert!(rl.is_key_revoked("key1"));
        assert!(!rl.is_key_revoked("key2"));
        assert!(!rl.is_artifact_revoked("somehash"));
    }

    #[test]
    fn revocation_list_artifact_revoked() {
        let mut rl = RevocationList::new();
        rl.add(RevocationEntry {
            key_id: None,
            content_hash: Some("abc123".to_string()),
            reason: "bad".to_string(),
            revoked_at: Utc::now(),
            revoked_by: "admin".to_string(),
        })
        .unwrap();
        assert!(rl.is_artifact_revoked("abc123"));
        assert!(!rl.is_artifact_revoked("def456"));
    }

    #[test]
    fn revocation_list_serialize_deserialize() {
        let mut rl = RevocationList::new();
        rl.add(RevocationEntry {
            key_id: Some("k1".to_string()),
            content_hash: Some("h1".to_string()),
            reason: "compromised".to_string(),
            revoked_at: Utc::now(),
            revoked_by: "root".to_string(),
        })
        .unwrap();

        let json = rl.to_json().unwrap();
        let recovered = RevocationList::from_json(&json).unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered.is_key_revoked("k1"));
        assert!(recovered.is_artifact_revoked("h1"));
    }

    #[test]
    fn revocation_list_empty() {
        let rl = RevocationList::new();
        assert!(rl.is_empty());
        assert!(!rl.is_key_revoked("anything"));
        assert!(!rl.is_artifact_revoked("anything"));
        let json = rl.to_json().unwrap();
        let recovered = RevocationList::from_json(&json).unwrap();
        assert!(recovered.is_empty());
    }

    // -----------------------------------------------------------------------
    // Sign and verify roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "roundtrip.bin", b"roundtrip data");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let artifact = verifier
            .sign_artifact(&path, &sk, ArtifactType::SystemBinary)
            .unwrap();
        assert!(artifact.signature.is_some());
        assert!(artifact.signer_key_id.is_some());

        let result = verifier
            .verify_artifact(&path, ArtifactType::SystemBinary)
            .unwrap();
        assert!(result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Verified);
    }

    // -----------------------------------------------------------------------
    // Trust store registration and lookup
    // -----------------------------------------------------------------------

    #[test]
    fn trust_store_register_and_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let hash = "deadbeef".to_string();
        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/opt/agent/bin"),
            artifact_type: ArtifactType::AgentBinary,
            content_hash: hash.clone(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Community,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        assert_eq!(verifier.trust_level_for(&hash), TrustLevel::Community);
        assert_eq!(verifier.trust_level_for("unknown"), TrustLevel::Unverified);
    }

    // -----------------------------------------------------------------------
    // verify_agent_binary with real temp file
    // -----------------------------------------------------------------------

    #[test]
    fn verify_agent_binary_real_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "my_agent", b"agent code");
        #[cfg(unix)]
        make_executable(&path);

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();

        let result = verifier.verify_agent_binary(&path).unwrap();
        assert!(result.passed);
        #[cfg(unix)]
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "execute_permission" && c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // verify_package — matching hash
    // -----------------------------------------------------------------------

    #[test]
    fn verify_package_matching_hash() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"package data v1.0";
        let path = temp_file(dir.path(), "pkg.ark", content);
        let expected_hash = hash_data(content);

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .sign_artifact(&path, &sk, ArtifactType::Package)
            .unwrap();

        let result = verifier
            .verify_package(&path, Some(&expected_hash))
            .unwrap();
        assert!(result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "expected_hash" && c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // verify_package — mismatched hash
    // -----------------------------------------------------------------------

    #[test]
    fn verify_package_mismatched_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "pkg.ark", b"real content");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .sign_artifact(&path, &sk, ArtifactType::Package)
            .unwrap();

        let result = verifier
            .verify_package(&path, Some("wrong_hash_value"))
            .unwrap();
        assert!(!result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "expected_hash" && !c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // verify_boot_chain — all clean
    // -----------------------------------------------------------------------

    #[test]
    fn verify_boot_chain_clean() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = temp_file(dir.path(), "vmlinuz", b"kernel image");
        let p2 = temp_file(dir.path(), "initramfs", b"initramfs image");

        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let report = verifier.verify_boot_chain(&[p1, p2]).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.total, 2);
        assert_eq!(report.verified, 2);
    }

    // -----------------------------------------------------------------------
    // verify_boot_chain — tampered file
    // -----------------------------------------------------------------------

    #[test]
    fn verify_boot_chain_tampered() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = temp_file(dir.path(), "vmlinuz", b"kernel");
        let hash1 = hash_data(b"kernel");

        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        // Register baseline via register_system_core (SystemCore trust)
        verifier.register_system_core(TrustedArtifact {
            path: p1.clone(),
            artifact_type: ArtifactType::BootComponent,
            content_hash: hash1.clone(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::SystemCore,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        // Tamper
        std::fs::write(&p1, b"modified kernel").unwrap();

        let report = verifier.verify_boot_chain(&[p1]).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.mismatches.len(), 1);
    }

    // -----------------------------------------------------------------------
    // SigilStats accuracy
    // -----------------------------------------------------------------------

    #[test]
    fn sigil_stats_accuracy() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/a"),
            artifact_type: ArtifactType::AgentBinary,
            content_hash: "h1".to_string(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Verified,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });
        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/b"),
            artifact_type: ArtifactType::Config,
            content_hash: "h2".to_string(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Revoked,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });
        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/c"),
            artifact_type: ArtifactType::Package,
            content_hash: "h3".to_string(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Verified,
            verified_at: None,
            metadata: HashMap::new(),
        });

        let stats = verifier.stats();
        assert_eq!(stats.total_artifacts, 3);
        assert_eq!(stats.verified_count, 2); // two have verified_at
        assert_eq!(stats.revoked_count, 1);
        assert_eq!(
            *stats.trust_level_counts.get(&TrustLevel::Verified).unwrap(),
            2
        );
        assert_eq!(
            *stats.trust_level_counts.get(&TrustLevel::Revoked).unwrap(),
            1
        );
    }

    // -----------------------------------------------------------------------
    // Policy enforcement: strict blocks unverified
    // -----------------------------------------------------------------------

    #[test]
    fn policy_strict_blocks_unverified() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "unverified.bin", b"data");

        let kr = PublisherKeyring::new(dir.path());
        let verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(!result.passed);
    }

    // -----------------------------------------------------------------------
    // Policy enforcement: audit-only logs but allows
    // -----------------------------------------------------------------------

    #[test]
    fn policy_audit_only_allows() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "audit.bin", b"data");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::AuditOnly;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(result.passed);
        // Policy check itself reports not-met
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "policy" && !c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // Policy enforcement: permissive allows with warning
    // -----------------------------------------------------------------------

    #[test]
    fn policy_permissive_allows_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "perm.bin", b"data");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::Permissive;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Unverified);
    }

    // -----------------------------------------------------------------------
    // TrustedArtifact serialization
    // -----------------------------------------------------------------------

    #[test]
    fn trusted_artifact_serialization() {
        let artifact = TrustedArtifact {
            path: PathBuf::from("/opt/agent"),
            artifact_type: ArtifactType::AgentBinary,
            content_hash: "abc".to_string(),
            signature: Some(vec![1, 2, 3]),
            signer_key_id: Some("key1".to_string()),
            trust_level: TrustLevel::Verified,
            verified_at: Some(Utc::now()),
            metadata: {
                let mut m = HashMap::new();
                m.insert("version".to_string(), "1.0".to_string());
                m
            },
        };

        let json = serde_json::to_string(&artifact).unwrap();
        let recovered: TrustedArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.content_hash, "abc");
        assert_eq!(recovered.trust_level, TrustLevel::Verified);
        assert_eq!(recovered.metadata.get("version").unwrap(), "1.0");
    }

    // -----------------------------------------------------------------------
    // VerificationResult checks detail
    // -----------------------------------------------------------------------

    #[test]
    fn verification_result_checks_detail() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "detail.bin", b"test");

        let kr = PublisherKeyring::new(dir.path());
        let verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let result = verifier
            .verify_artifact(&path, ArtifactType::Config)
            .unwrap();

        // Should have at least: file_readable, trust_store, signature, revocation, policy
        assert!(result.checks.len() >= 4);
        for check in &result.checks {
            assert!(!check.name.is_empty());
            assert!(!check.detail.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Multiple artifacts in trust store
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_artifacts_in_trust_store() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        for i in 0..5 {
            verifier.register_trusted(TrustedArtifact {
                path: PathBuf::from(format!("/artifact_{}", i)),
                artifact_type: ArtifactType::AgentBinary,
                content_hash: format!("hash_{}", i),
                signature: None,
                signer_key_id: None,
                trust_level: TrustLevel::Verified,
                verified_at: Some(Utc::now()),
                metadata: HashMap::new(),
            });
        }

        let stats = verifier.stats();
        assert_eq!(stats.total_artifacts, 5);
        for i in 0..5 {
            assert_eq!(
                verifier.trust_level_for(&format!("hash_{}", i)),
                TrustLevel::Verified
            );
        }
    }

    // -----------------------------------------------------------------------
    // Revocation after trust
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_after_trust() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "trusted_then_revoked.bin", b"trusted");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let artifact = verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();

        // Initially trusted
        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(result.passed);

        // Revoke by hash
        verifier
            .add_revocation(RevocationEntry {
                key_id: None,
                content_hash: Some(artifact.content_hash.clone()),
                reason: "Supply chain compromise".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "security-team".to_string(),
            })
            .unwrap();

        // Now should fail
        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        assert!(!result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Revoked);
    }

    // -----------------------------------------------------------------------
    // Sign artifact registers in trust store
    // -----------------------------------------------------------------------

    #[test]
    fn sign_artifact_registers_in_trust_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "to_sign.bin", b"sign me");
        let content_hash = hash_data(b"sign me");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        assert_eq!(
            verifier.trust_level_for(&content_hash),
            TrustLevel::Unverified
        );

        verifier
            .sign_artifact(&path, &sk, ArtifactType::Config)
            .unwrap();

        assert_eq!(
            verifier.trust_level_for(&content_hash),
            TrustLevel::Verified
        );
    }

    // -----------------------------------------------------------------------
    // check_revocation helper
    // -----------------------------------------------------------------------

    #[test]
    fn check_revocation_direct() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        assert!(!verifier.check_revocation(Some("k1"), "h1"));

        verifier
            .add_revocation(RevocationEntry {
                key_id: Some("k1".to_string()),
                content_hash: None,
                reason: "test".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "test".to_string(),
            })
            .unwrap();

        assert!(verifier.check_revocation(Some("k1"), "h1"));
        assert!(!verifier.check_revocation(Some("k2"), "h1"));
        assert!(!verifier.check_revocation(None, "h1"));
    }

    // -----------------------------------------------------------------------
    // Policy accessor
    // -----------------------------------------------------------------------

    #[test]
    fn policy_accessor() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::Permissive;
        let verifier = SigilVerifier::new(kr, policy);

        assert_eq!(verifier.policy().enforcement, TrustEnforcement::Permissive);
    }

    // -----------------------------------------------------------------------
    // Agent binary without execute permission
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn verify_agent_binary_no_execute_permission() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "no_exec", b"agent code");
        // Do NOT make executable

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut policy = TrustPolicy::default();
        policy.allow_unsigned_agents = true;
        let mut verifier = SigilVerifier::new(kr, policy);

        verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();

        let result = verifier.verify_agent_binary(&path).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "execute_permission" && !c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // AUDIT FIX TESTS
    // -----------------------------------------------------------------------

    // CRITICAL 1: AuditOnly mode blocks revoked artifacts
    #[test]
    fn audit_only_blocks_revoked_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "revoked_audit.bin", b"audit revoked");

        let (kr, sk, _vk, kid) = keyring_with_key(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::AuditOnly;
        let mut verifier = SigilVerifier::new(kr, policy);

        verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();

        // Revoke the signing key
        verifier
            .add_revocation(RevocationEntry {
                key_id: Some(kid),
                content_hash: None,
                reason: "Key compromised".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "admin".to_string(),
            })
            .unwrap();

        let result = verifier
            .verify_artifact(&path, ArtifactType::AgentBinary)
            .unwrap();
        // Even in AuditOnly, revoked must NOT pass
        assert!(!result.passed);
        assert_eq!(result.artifact.trust_level, TrustLevel::Revoked);
    }

    // CRITICAL 2: verify_on_execute=false skips verification
    #[test]
    fn verify_on_execute_false_skips_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "skip_exec.bin", b"skip me");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.verify_on_execute = false;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier.verify_agent_binary(&path).unwrap();
        assert!(result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "skipped" && c.passed)
        );
    }

    // CRITICAL 2: verify_on_install=false skips verification
    #[test]
    fn verify_on_install_false_skips_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "skip_pkg.ark", b"skip pkg");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.verify_on_install = false;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier.verify_package(&path, Some("wrong_hash")).unwrap();
        // Should pass even with wrong expected hash because verification is skipped
        assert!(result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "skipped" && c.passed)
        );
    }

    // CRITICAL 2: verify_on_boot=false skips verification
    #[test]
    fn verify_on_boot_false_skips_verification() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = temp_file(dir.path(), "vmlinuz", b"kernel");

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.verify_on_boot = false;
        let mut verifier = SigilVerifier::new(kr, policy);

        let report = verifier.verify_boot_chain(&[p1]).unwrap();
        assert!(report.is_clean());
    }

    // HIGH 1: sign_artifact with unknown key gets Community trust
    #[test]
    fn sign_artifact_unknown_key_gets_community_trust() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "community.bin", b"community data");

        // Create a keyring but do NOT add the signing key to it
        let kr = PublisherKeyring::new(dir.path());
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let artifact = verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();
        assert_eq!(artifact.trust_level, TrustLevel::Community);
    }

    // HIGH 2: register_trusted downgrades SystemCore to Verified
    #[test]
    fn register_trusted_downgrades_system_core() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let hash = "sys_core_hash".to_string();
        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/boot/vmlinuz"),
            artifact_type: ArtifactType::BootComponent,
            content_hash: hash.clone(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::SystemCore,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        // Should have been downgraded to Verified
        assert_eq!(verifier.trust_level_for(&hash), TrustLevel::Verified);
    }

    // HIGH 2: register_system_core keeps SystemCore trust
    #[test]
    fn register_system_core_keeps_trust() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        let hash = "sys_core_hash2".to_string();
        verifier.register_system_core(TrustedArtifact {
            path: PathBuf::from("/boot/vmlinuz"),
            artifact_type: ArtifactType::BootComponent,
            content_hash: hash.clone(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Verified, // even if lower is passed
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        // Should be forced to SystemCore
        assert_eq!(verifier.trust_level_for(&hash), TrustLevel::SystemCore);
    }

    // HIGH 3: save/load trust store roundtrip
    #[test]
    fn save_load_trust_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("trust_store.json");

        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/opt/agent1"),
            artifact_type: ArtifactType::AgentBinary,
            content_hash: "hash_a".to_string(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Verified,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });
        verifier.register_trusted(TrustedArtifact {
            path: PathBuf::from("/opt/agent2"),
            artifact_type: ArtifactType::Config,
            content_hash: "hash_b".to_string(),
            signature: None,
            signer_key_id: None,
            trust_level: TrustLevel::Community,
            verified_at: Some(Utc::now()),
            metadata: HashMap::new(),
        });

        verifier.save_trust_store(&store_path).unwrap();

        // Load into a fresh verifier
        let kr2 = PublisherKeyring::new(dir.path());
        let mut verifier2 = SigilVerifier::new(kr2, TrustPolicy::default());
        let count = verifier2.load_trust_store(&store_path).unwrap();

        assert_eq!(count, 2);
        assert_eq!(verifier2.trust_level_for("hash_a"), TrustLevel::Verified);
        assert_eq!(verifier2.trust_level_for("hash_b"), TrustLevel::Community);
    }

    // HIGH 3: save/load revocations roundtrip
    #[test]
    fn save_load_revocations_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let rev_path = dir.path().join("revocations.json");

        let kr = PublisherKeyring::new(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

        verifier
            .add_revocation(RevocationEntry {
                key_id: Some("key_x".to_string()),
                content_hash: None,
                reason: "test revocation".to_string(),
                revoked_at: Utc::now(),
                revoked_by: "admin".to_string(),
            })
            .unwrap();

        verifier.save_revocations(&rev_path).unwrap();

        // Load into a fresh verifier
        let kr2 = PublisherKeyring::new(dir.path());
        let mut verifier2 = SigilVerifier::new(kr2, TrustPolicy::default());
        let count = verifier2.load_revocations(&rev_path).unwrap();

        assert_eq!(count, 1);
        assert!(verifier2.check_revocation(Some("key_x"), "any_hash"));
    }

    // HIGH 5: RevocationEntry with both None rejected
    #[test]
    fn revocation_entry_both_none_rejected() {
        let mut rl = RevocationList::new();
        let result = rl.add(RevocationEntry {
            key_id: None,
            content_hash: None,
            reason: "invalid entry".to_string(),
            revoked_at: Utc::now(),
            revoked_by: "test".to_string(),
        });
        assert!(result.is_err());
        assert!(rl.is_empty());
    }

    // MEDIUM: unsigned agent blocked in Permissive mode when allow_unsigned=false
    #[test]
    fn unsigned_agent_blocked_in_permissive_when_disallowed() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "unsigned_perm.bin", b"unsigned agent");
        #[cfg(unix)]
        make_executable(&path);

        let kr = PublisherKeyring::new(dir.path());
        let mut policy = TrustPolicy::default();
        policy.enforcement = TrustEnforcement::Permissive;
        policy.allow_unsigned_agents = false;
        let verifier = SigilVerifier::new(kr, policy);

        let result = verifier.verify_agent_binary(&path).unwrap();
        assert!(!result.passed);
        assert!(
            result
                .checks
                .iter()
                .any(|c| c.name == "unsigned_agent" && !c.passed)
        );
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_trust_level() {
        for level in [
            TrustLevel::SystemCore,
            TrustLevel::Verified,
            TrustLevel::Community,
            TrustLevel::Unverified,
            TrustLevel::Revoked,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let recovered: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, level);
        }
    }

    #[test]
    fn serde_roundtrip_trust_enforcement() {
        for e in [
            TrustEnforcement::Strict,
            TrustEnforcement::Permissive,
            TrustEnforcement::AuditOnly,
        ] {
            let json = serde_json::to_string(&e).unwrap();
            let recovered: TrustEnforcement = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, e);
        }
    }

    #[test]
    fn serde_roundtrip_artifact_type() {
        for at in [
            ArtifactType::AgentBinary,
            ArtifactType::SystemBinary,
            ArtifactType::Config,
            ArtifactType::Package,
            ArtifactType::BootComponent,
        ] {
            let json = serde_json::to_string(&at).unwrap();
            let recovered: ArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, at);
        }
    }

    #[test]
    fn serde_roundtrip_trust_policy() {
        let policy = TrustPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let recovered: TrustPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.enforcement, policy.enforcement);
        assert_eq!(recovered.minimum_trust_level, policy.minimum_trust_level);
        assert_eq!(
            recovered.allow_unsigned_agents,
            policy.allow_unsigned_agents
        );
        assert_eq!(recovered.verify_on_boot, policy.verify_on_boot);
        assert_eq!(recovered.verify_on_install, policy.verify_on_install);
        assert_eq!(recovered.verify_on_execute, policy.verify_on_execute);
        assert_eq!(recovered.revocation_check, policy.revocation_check);
    }

    #[test]
    fn serde_roundtrip_revocation_entry() {
        let entry = RevocationEntry {
            key_id: Some("key1".to_string()),
            content_hash: Some("hash1".to_string()),
            reason: "compromised".to_string(),
            revoked_at: Utc::now(),
            revoked_by: "admin".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let recovered: RevocationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.key_id, entry.key_id);
        assert_eq!(recovered.content_hash, entry.content_hash);
        assert_eq!(recovered.reason, entry.reason);
        assert_eq!(recovered.revoked_by, entry.revoked_by);
    }

    #[test]
    fn serde_roundtrip_verification_result() {
        let dir = tempfile::tempdir().unwrap();
        let path = temp_file(dir.path(), "serde_vr.bin", b"data");

        let (kr, sk, _vk, _kid) = keyring_with_key(dir.path());
        let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());
        verifier
            .sign_artifact(&path, &sk, ArtifactType::Config)
            .unwrap();

        let result = verifier
            .verify_artifact(&path, ArtifactType::Config)
            .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let recovered: crate::types::VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.passed, result.passed);
        assert_eq!(
            recovered.artifact.content_hash,
            result.artifact.content_hash
        );
        assert_eq!(recovered.checks.len(), result.checks.len());
    }

    #[test]
    fn serde_roundtrip_sigil_stats() {
        let dir = tempfile::tempdir().unwrap();
        let kr = PublisherKeyring::new(dir.path());
        let verifier = SigilVerifier::new(kr, TrustPolicy::default());
        let stats = verifier.stats();
        let json = serde_json::to_string(&stats).unwrap();
        let recovered: crate::types::SigilStats = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.total_artifacts, stats.total_artifacts);
    }

    #[test]
    fn serde_roundtrip_key_version() {
        use crate::trust::KeyVersion;
        let kv = KeyVersion {
            key_id: "test_key".to_string(),
            valid_from: Utc::now(),
            valid_until: Some(Utc::now() + chrono::Duration::days(365)),
            public_key_hex: "00".repeat(32),
        };
        let json = serde_json::to_string(&kv).unwrap();
        let recovered: KeyVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.key_id, kv.key_id);
        assert_eq!(recovered.public_key_hex, kv.public_key_hex);
    }

    #[test]
    fn serde_roundtrip_measurement_status() {
        use crate::integrity::MeasurementStatus;
        for status in [
            MeasurementStatus::Pending,
            MeasurementStatus::Verified,
            MeasurementStatus::Mismatch,
            MeasurementStatus::FileNotFound,
            MeasurementStatus::Error("test error".to_string()),
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let recovered: MeasurementStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(recovered, status);
        }
    }

    #[test]
    fn serde_roundtrip_integrity_policy() {
        use crate::integrity::IntegrityPolicy;
        let mut policy = IntegrityPolicy::default();
        policy.check_interval_seconds = 300;
        policy.enforce = true;
        let json = serde_json::to_string(&policy).unwrap();
        let recovered: IntegrityPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(
            recovered.check_interval_seconds,
            policy.check_interval_seconds
        );
        assert_eq!(recovered.enforce, policy.enforce);
    }

    #[test]
    fn serde_roundtrip_integrity_report() {
        use crate::integrity::IntegrityReport;
        let report = IntegrityReport {
            total: 5,
            verified: 3,
            mismatches: vec![],
            errors: vec![],
            checked_at: Utc::now(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let recovered: IntegrityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.total, report.total);
        assert_eq!(recovered.verified, report.verified);
        assert!(recovered.is_clean());
    }

    // -----------------------------------------------------------------------
    // v0.2.0 API additions
    // -----------------------------------------------------------------------

    #[test]
    fn measurement_status_display() {
        use crate::integrity::MeasurementStatus;
        assert_eq!(MeasurementStatus::Pending.to_string(), "Pending");
        assert_eq!(MeasurementStatus::Verified.to_string(), "Verified");
        assert_eq!(MeasurementStatus::Mismatch.to_string(), "Mismatch");
        assert_eq!(MeasurementStatus::FileNotFound.to_string(), "FileNotFound");
        assert_eq!(
            MeasurementStatus::Error("oops".to_string()).to_string(),
            "Error: oops"
        );
    }

    #[test]
    fn trust_policy_builder() {
        let policy = TrustPolicy::builder()
            .enforcement(TrustEnforcement::Permissive)
            .minimum_trust_level(TrustLevel::Community)
            .allow_unsigned_agents(true)
            .verify_on_boot(false)
            .verify_on_install(false)
            .verify_on_execute(false)
            .revocation_check(false)
            .build();

        assert_eq!(policy.enforcement, TrustEnforcement::Permissive);
        assert_eq!(policy.minimum_trust_level, TrustLevel::Community);
        assert!(policy.allow_unsigned_agents);
        assert!(!policy.verify_on_boot);
        assert!(!policy.verify_on_install);
        assert!(!policy.verify_on_execute);
        assert!(!policy.revocation_check);
    }

    #[test]
    fn trust_policy_builder_defaults() {
        let policy = TrustPolicy::builder().build();
        let default = TrustPolicy::default();
        assert_eq!(policy.enforcement, default.enforcement);
        assert_eq!(policy.minimum_trust_level, default.minimum_trust_level);
    }

    #[test]
    fn keyring_save_and_reload() {
        use crate::trust::{KeyVersion, generate_keypair};

        let dir = tempfile::tempdir().unwrap();
        let (_, vk, kid) = generate_keypair();

        let mut kr = PublisherKeyring::new(dir.path());
        kr.add_key(KeyVersion {
            key_id: kid.clone(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            public_key_hex: vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
        });

        let saved = kr.save().unwrap();
        assert_eq!(saved, 1);

        // Reload into fresh keyring
        let mut kr2 = PublisherKeyring::new(dir.path());
        let loaded = kr2.load().unwrap();
        assert_eq!(loaded, 1);
        assert!(kr2.get_current_key(&kid).is_some());
    }

    #[test]
    fn integrity_remove_baseline() {
        use crate::integrity::{IntegrityPolicy, IntegrityVerifier};

        let dir = tempfile::tempdir().unwrap();
        let p1 = temp_file(dir.path(), "keep.txt", b"keep");
        let p2 = temp_file(dir.path(), "remove.txt", b"remove");

        let policy = IntegrityPolicy::default();
        let mut verifier = IntegrityVerifier::new(policy);
        verifier.add_baseline(&p1).unwrap();
        verifier.add_baseline(&p2).unwrap();

        assert!(verifier.remove_baseline(&p2));
        assert!(!verifier.remove_baseline(&p2)); // already removed

        let report = verifier.verify_all();
        assert_eq!(report.total, 1);
        assert!(report.is_clean());
    }

    #[test]
    fn sigil_error_display() {
        use crate::error::SigilError;
        let err = SigilError::KeyNotFound {
            key_id: "abc123".to_string(),
        };
        assert_eq!(err.to_string(), "key not found: abc123");

        let err = SigilError::InvalidInput {
            detail: "bad data".to_string(),
        };
        assert_eq!(err.to_string(), "invalid input: bad data");
    }

    #[test]
    fn sigil_error_from_io() {
        use crate::error::SigilError;
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let sigil_err: SigilError = io_err.into();
        assert!(sigil_err.to_string().contains("file missing"));
    }
}
