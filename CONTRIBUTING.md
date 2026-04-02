# Contributing to Sigil

## Getting Started

```bash
git clone https://github.com/MacCracken/sigil.git
cd sigil
cargo test
```

## Development Process

Sigil follows a structured work loop. See `CLAUDE.md` for the full process.

### Before Submitting

All changes must pass the cleanliness check:

```bash
cargo fmt --check
cargo clippy --all-features --all-targets -- -D warnings
cargo audit
cargo deny check
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo test
```

### Benchmarks

Performance-sensitive changes must include benchmark results:

```bash
./scripts/bench-history.sh "description-of-change"
```

Include before/after numbers in PR descriptions for any performance claims.

## Key Principles

- Sigil IS the trust boundary — every crypto decision lives here
- `#[non_exhaustive]` on all public enums
- `#[must_use]` on all pure functions
- Every type must be `Serialize + Deserialize`
- Zero `unwrap`/`panic` in library code
- No custom crypto — use audited crates
- No timing side-channels in crypto paths
- Key material must be zeroized on drop

## Code Style

- `cargo fmt` enforced
- `cargo clippy` with `-D warnings`
- No unnecessary dependencies
- Feature-gate optional modules

## Security

If you discover a security vulnerability, please report it privately. See `SECURITY.md`.
