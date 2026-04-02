use criterion::{Criterion, black_box, criterion_group, criterion_main};

use sigil::trust::{generate_keypair, hash_data, sign_data, verify_signature};

fn bench_hash_data(c: &mut Criterion) {
    let data = vec![0u8; 4096];
    c.bench_function("hash_data_4kb", |b| {
        b.iter(|| hash_data(black_box(&data)));
    });

    let large = vec![0u8; 1024 * 1024];
    c.bench_function("hash_data_1mb", |b| {
        b.iter(|| hash_data(black_box(&large)));
    });
}

fn bench_sign_verify(c: &mut Criterion) {
    let (sk, vk, _) = generate_keypair();
    let data = vec![0u8; 4096];
    let sig = sign_data(&data, &sk);

    c.bench_function("sign_4kb", |b| {
        b.iter(|| sign_data(black_box(&data), black_box(&sk)));
    });

    c.bench_function("verify_4kb", |b| {
        b.iter(|| verify_signature(black_box(&data), black_box(&sig), black_box(&vk)));
    });
}

fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("generate_keypair", |b| {
        b.iter(generate_keypair);
    });
}

fn bench_integrity_compute_hash(c: &mut Criterion) {
    use sigil::integrity::IntegrityVerifier;

    let dir = tempfile::tempdir().unwrap();
    let path_4k = dir.path().join("bench_4k.bin");
    std::fs::write(&path_4k, vec![0u8; 4096]).unwrap();
    let path_1m = dir.path().join("bench_1m.bin");
    std::fs::write(&path_1m, vec![0u8; 1024 * 1024]).unwrap();

    c.bench_function("compute_hash_file_4kb", |b| {
        b.iter(|| IntegrityVerifier::compute_hash(black_box(&path_4k)));
    });

    c.bench_function("compute_hash_file_1mb", |b| {
        b.iter(|| IntegrityVerifier::compute_hash(black_box(&path_1m)));
    });
}

fn bench_revocation_lookup(c: &mut Criterion) {
    use sigil::policy::{RevocationEntry, RevocationList};

    let mut rl = RevocationList::new();
    for i in 0..1000 {
        rl.add(RevocationEntry {
            key_id: Some(format!("key_{}", i)),
            content_hash: Some(format!("hash_{}", i)),
            reason: "bench".to_string(),
            revoked_at: chrono::Utc::now(),
            revoked_by: "bench".to_string(),
        })
        .unwrap();
    }

    c.bench_function("revocation_key_lookup_1k", |b| {
        b.iter(|| rl.is_key_revoked(black_box("key_999")));
    });

    c.bench_function("revocation_hash_lookup_1k", |b| {
        b.iter(|| rl.is_artifact_revoked(black_box("hash_999")));
    });
}

fn bench_verify_artifact(c: &mut Criterion) {
    use sigil::trust::{KeyVersion, PublisherKeyring};
    use sigil::verify::SigilVerifier;
    use sigil::{ArtifactType, TrustPolicy};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bench_artifact.bin");
    std::fs::write(&path, vec![0u8; 4096]).unwrap();

    let (sk, vk, kid) = generate_keypair();
    let mut kr = PublisherKeyring::new(dir.path());
    kr.add_key(KeyVersion {
        key_id: kid.clone(),
        valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
        valid_until: None,
        public_key_hex: vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
    });

    let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());
    verifier
        .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
        .unwrap();

    c.bench_function("verify_artifact_signed_4kb", |b| {
        b.iter(|| {
            verifier
                .verify_artifact(black_box(&path), ArtifactType::AgentBinary)
                .unwrap()
        });
    });
}

fn bench_verify_batch(c: &mut Criterion) {
    use sigil::trust::{KeyVersion, PublisherKeyring};
    use sigil::verify::SigilVerifier;
    use sigil::{ArtifactType, TrustPolicy};

    let dir = tempfile::tempdir().unwrap();
    let (sk, vk, kid) = generate_keypair();
    let mut kr = PublisherKeyring::new(dir.path());
    kr.add_key(KeyVersion {
        key_id: kid.clone(),
        valid_from: chrono::Utc::now() - chrono::Duration::hours(1),
        valid_until: None,
        public_key_hex: vk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect(),
    });

    let mut verifier = SigilVerifier::new(kr, TrustPolicy::default());

    // Create 10 files and sign them
    let mut paths = Vec::new();
    for i in 0..10 {
        let path = dir.path().join(format!("batch_{i}.bin"));
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        verifier
            .sign_artifact(&path, &sk, ArtifactType::AgentBinary)
            .unwrap();
        paths.push(path);
    }

    let batch: Vec<(&std::path::Path, ArtifactType)> = paths
        .iter()
        .map(|p| (p.as_path(), ArtifactType::AgentBinary))
        .collect();

    c.bench_function("verify_batch_10x4kb", |b| {
        b.iter(|| verifier.verify_batch(black_box(&batch)));
    });
}

criterion_group!(
    benches,
    bench_hash_data,
    bench_sign_verify,
    bench_keypair_generation,
    bench_integrity_compute_hash,
    bench_revocation_lookup,
    bench_verify_artifact,
    bench_verify_batch,
);
criterion_main!(benches);
