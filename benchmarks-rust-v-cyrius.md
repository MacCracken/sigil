# Sigil Benchmarks — Rust v1.0.0 (Final)

Rust implementation final benchmarks, preserved for comparison against Cyrius port.

## v1.0.0 Final (2026-04-02)

| Benchmark | Estimate | Unit |
|-----------|----------|------|
| hash_data_4kb | 2.0638 | us |
| hash_data_1mb | 493.72 | us |
| sign_4kb | 27.349 | us |
| verify_4kb | 34.046 | us |
| generate_keypair | 14.826 | us |
| compute_hash_file_4kb | 5.6811 | us |
| compute_hash_file_1mb | 608.00 | us |
| revocation_key_lookup_1k | 16.964 | ns |
| revocation_hash_lookup_1k | 16.699 | ns |
| verify_artifact_signed_4kb | 40.378 | us |
| verify_artifact_signed_1mb | 590.32 | us |
| verify_batch_10x4kb | 423.50 | us |

## Full History (Rust)

```csv
timestamp,label,benchmark,estimate,unit
2026-04-02T01:11:31Z,p-1-baseline,hash_data_4kb,2.0050,us
2026-04-02T01:11:31Z,p-1-baseline,hash_data_1mb,496.34,us
2026-04-02T01:11:31Z,p-1-baseline,sign_4kb,27.366,us
2026-04-02T01:11:31Z,p-1-baseline,verify_4kb,39.491,us
2026-04-02T01:11:31Z,p-1-baseline,generate_keypair,15.140,us
2026-04-02T01:11:31Z,p-1-baseline,compute_hash_file_4kb,5.6559,us
2026-04-02T01:11:31Z,p-1-baseline,compute_hash_file_1mb,611.11,us
2026-04-02T01:11:31Z,p-1-baseline,revocation_key_lookup_1k,16.776,ns
2026-04-02T01:11:31Z,p-1-baseline,revocation_hash_lookup_1k,17.092,ns
2026-04-02T01:11:31Z,p-1-baseline,verify_artifact_signed_4kb,45.298,us
2026-04-02T01:34:10Z,v0.2.0,hash_data_4kb,2.0100,us
2026-04-02T01:34:10Z,v0.2.0,hash_data_1mb,495.45,us
2026-04-02T01:34:10Z,v0.2.0,sign_4kb,27.568,us
2026-04-02T01:34:10Z,v0.2.0,verify_4kb,34.556,us
2026-04-02T01:34:10Z,v0.2.0,generate_keypair,15.026,us
2026-04-02T01:34:10Z,v0.2.0,compute_hash_file_4kb,5.7188,us
2026-04-02T01:34:10Z,v0.2.0,compute_hash_file_1mb,613.92,us
2026-04-02T01:34:10Z,v0.2.0,revocation_key_lookup_1k,17.703,ns
2026-04-02T01:34:10Z,v0.2.0,revocation_hash_lookup_1k,18.684,ns
2026-04-02T01:34:10Z,v0.2.0,verify_artifact_signed_4kb,52.412,us
2026-04-02T01:40:44Z,v0.3.0,hash_data_4kb,1.9879,us
2026-04-02T01:40:44Z,v0.3.0,hash_data_1mb,487.19,us
2026-04-02T01:40:44Z,v0.3.0,sign_4kb,27.678,us
2026-04-02T01:40:44Z,v0.3.0,verify_4kb,34.817,us
2026-04-02T01:40:44Z,v0.3.0,generate_keypair,15.110,us
2026-04-02T01:40:44Z,v0.3.0,compute_hash_file_4kb,8.5151,us
2026-04-02T01:40:44Z,v0.3.0,compute_hash_file_1mb,666.69,us
2026-04-02T01:40:44Z,v0.3.0,revocation_key_lookup_1k,17.268,ns
2026-04-02T01:40:44Z,v0.3.0,revocation_hash_lookup_1k,17.283,ns
2026-04-02T01:40:44Z,v0.3.0,verify_artifact_signed_4kb,64.004,us
2026-04-02T01:40:44Z,v0.3.0,verify_batch_10x4kb,744.70,us
2026-04-02T01:57:41Z,v0.4.0,hash_data_4kb,2.0121,us
2026-04-02T01:57:41Z,v0.4.0,hash_data_1mb,494.57,us
2026-04-02T01:57:41Z,v0.4.0,sign_4kb,27.484,us
2026-04-02T01:57:41Z,v0.4.0,verify_4kb,35.042,us
2026-04-02T01:57:41Z,v0.4.0,generate_keypair,15.230,us
2026-04-02T01:57:41Z,v0.4.0,compute_hash_file_4kb,5.6673,us
2026-04-02T01:57:41Z,v0.4.0,compute_hash_file_1mb,608.11,us
2026-04-02T01:57:41Z,v0.4.0,revocation_key_lookup_1k,16.775,ns
2026-04-02T01:57:41Z,v0.4.0,revocation_hash_lookup_1k,16.853,ns
2026-04-02T01:57:41Z,v0.4.0,verify_artifact_signed_4kb,46.886,us
2026-04-02T01:57:41Z,v0.4.0,verify_batch_10x4kb,491.22,us
2026-04-02T02:08:01Z,v0.4.0-optimized,hash_data_4kb,2.2174,us
2026-04-02T02:08:01Z,v0.4.0-optimized,hash_data_1mb,525.49,us
2026-04-02T02:08:01Z,v0.4.0-optimized,sign_4kb,28.632,us
2026-04-02T02:08:01Z,v0.4.0-optimized,verify_4kb,39.885,us
2026-04-02T02:08:01Z,v0.4.0-optimized,generate_keypair,15.608,us
2026-04-02T02:08:01Z,v0.4.0-optimized,compute_hash_file_4kb,6.0692,us
2026-04-02T02:08:01Z,v0.4.0-optimized,compute_hash_file_1mb,664.05,us
2026-04-02T02:08:01Z,v0.4.0-optimized,revocation_key_lookup_1k,18.660,ns
2026-04-02T02:08:01Z,v0.4.0-optimized,revocation_hash_lookup_1k,19.089,ns
2026-04-02T02:08:01Z,v0.4.0-optimized,verify_artifact_signed_4kb,42.794,us
2026-04-02T02:08:01Z,v0.4.0-optimized,verify_batch_10x4kb,429.01,us
2026-04-02T02:10:52Z,v0.4.0-final,hash_data_4kb,2.3913,us
2026-04-02T02:10:52Z,v0.4.0-final,hash_data_1mb,522.65,us
2026-04-02T02:10:52Z,v0.4.0-final,sign_4kb,28.661,us
2026-04-02T02:10:52Z,v0.4.0-final,verify_4kb,40.156,us
2026-04-02T02:10:52Z,v0.4.0-final,generate_keypair,16.605,us
2026-04-02T02:10:52Z,v0.4.0-final,compute_hash_file_4kb,6.3574,us
2026-04-02T02:10:52Z,v0.4.0-final,compute_hash_file_1mb,656.51,us
2026-04-02T02:10:52Z,v0.4.0-final,revocation_key_lookup_1k,18.358,ns
2026-04-02T02:10:52Z,v0.4.0-final,revocation_hash_lookup_1k,18.426,ns
2026-04-02T02:10:52Z,v0.4.0-final,verify_artifact_signed_4kb,42.512,us
2026-04-02T02:10:52Z,v0.4.0-final,verify_artifact_signed_1mb,620.73,us
2026-04-02T02:10:52Z,v0.4.0-final,verify_batch_10x4kb,429.11,us
2026-04-02T02:20:16Z,near-term-complete,hash_data_4kb,2.3939,us
2026-04-02T02:20:16Z,near-term-complete,hash_data_1mb,559.20,us
2026-04-02T02:20:16Z,near-term-complete,sign_4kb,38.978,us
2026-04-02T02:20:16Z,near-term-complete,verify_4kb,40.451,us
2026-04-02T02:20:16Z,near-term-complete,generate_keypair,18.570,us
2026-04-02T02:20:16Z,near-term-complete,compute_hash_file_4kb,7.5172,us
2026-04-02T02:20:16Z,near-term-complete,compute_hash_file_1mb,769.39,us
2026-04-02T02:20:16Z,near-term-complete,revocation_key_lookup_1k,28.382,ns
2026-04-02T02:20:16Z,near-term-complete,revocation_hash_lookup_1k,30.073,ns
2026-04-02T02:20:16Z,near-term-complete,verify_artifact_signed_4kb,54.594,us
2026-04-02T02:20:16Z,near-term-complete,verify_artifact_signed_1mb,723.81,us
2026-04-02T02:20:16Z,near-term-complete,verify_batch_10x4kb,496.41,us
2026-04-02T02:38:38Z,v0.5.0,hash_data_4kb,2.3070,us
2026-04-02T02:38:38Z,v0.5.0,hash_data_1mb,546.32,us
2026-04-02T02:38:38Z,v0.5.0,sign_4kb,30.948,us
2026-04-02T02:38:38Z,v0.5.0,verify_4kb,39.205,us
2026-04-02T02:38:38Z,v0.5.0,generate_keypair,19.638,us
2026-04-02T02:38:38Z,v0.5.0,compute_hash_file_4kb,7.5543,us
2026-04-02T02:38:38Z,v0.5.0,compute_hash_file_1mb,769.26,us
2026-04-02T02:38:38Z,v0.5.0,revocation_key_lookup_1k,22.583,ns
2026-04-02T02:38:38Z,v0.5.0,revocation_hash_lookup_1k,23.099,ns
2026-04-02T02:38:38Z,v0.5.0,verify_artifact_signed_4kb,53.119,us
2026-04-02T02:38:38Z,v0.5.0,verify_artifact_signed_1mb,704.59,us
2026-04-02T02:38:38Z,v0.5.0,verify_batch_10x4kb,510.09,us
2026-04-02T03:42:15Z,v0.9.0,hash_data_4kb,2.0677,us
2026-04-02T03:42:15Z,v0.9.0,hash_data_1mb,492.37,us
2026-04-02T03:42:15Z,v0.9.0,sign_4kb,27.626,us
2026-04-02T03:42:15Z,v0.9.0,verify_4kb,34.915,us
2026-04-02T03:42:15Z,v0.9.0,generate_keypair,15.185,us
2026-04-02T03:42:15Z,v0.9.0,compute_hash_file_4kb,5.8367,us
2026-04-02T03:42:15Z,v0.9.0,compute_hash_file_1mb,622.78,us
2026-04-02T03:42:15Z,v0.9.0,revocation_key_lookup_1k,17.369,ns
2026-04-02T03:42:15Z,v0.9.0,revocation_hash_lookup_1k,18.095,ns
2026-04-02T03:42:15Z,v0.9.0,verify_artifact_signed_4kb,51.956,us
2026-04-02T03:42:15Z,v0.9.0,verify_artifact_signed_1mb,702.98,us
2026-04-02T03:42:15Z,v0.9.0,verify_batch_10x4kb,564.21,us
2026-04-02T03:49:56Z,v1.0.0,hash_data_4kb,2.0638,us
2026-04-02T03:49:56Z,v1.0.0,hash_data_1mb,493.72,us
2026-04-02T03:49:56Z,v1.0.0,sign_4kb,27.349,us
2026-04-02T03:49:56Z,v1.0.0,verify_4kb,34.046,us
2026-04-02T03:49:56Z,v1.0.0,generate_keypair,14.826,us
2026-04-02T03:49:56Z,v1.0.0,compute_hash_file_4kb,5.6811,us
2026-04-02T03:49:56Z,v1.0.0,compute_hash_file_1mb,608.00,us
2026-04-02T03:49:56Z,v1.0.0,revocation_key_lookup_1k,16.964,ns
2026-04-02T03:49:56Z,v1.0.0,revocation_hash_lookup_1k,16.699,ns
2026-04-02T03:49:56Z,v1.0.0,verify_artifact_signed_4kb,40.378,us
2026-04-02T03:49:56Z,v1.0.0,verify_artifact_signed_1mb,590.32,us
2026-04-02T03:49:56Z,v1.0.0,verify_batch_10x4kb,423.50,us
```

## Notes

- All benchmarks run on same hardware (criterion, statistical estimates)
- Rust used: ed25519-dalek, sha2, serde_json, chrono, rayon (for batch)
- Binary size: ~800KB release (Rust)
- Cyrius comparison column will be added as the port progresses
