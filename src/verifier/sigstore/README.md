# Sigstore Verification Module

This module implements Sigstore verification for code provenance, ensuring that code running in secure enclaves matches published open-source builds.

## Why Not Use sigstore-rs Directly?

As of January 2025, **sigstore-rs 0.13+** cannot be used because:

1. **Rust 2024 Edition Requirement**: sigstore-rs uses Rust 2024 edition features, specifically `let-chains` (stabilized in Rust 1.88), which don't compile on stable Rust 1.87.

2. **Mandatory OAuth Module**: Even for verification-only use cases, sigstore-rs requires the `oauth` module which contains the incompatible syntax.

3. **No Feature Flag Workaround**: There's no way to disable the problematic code paths via feature flags.

See: [rust-lang/rust#145878](https://github.com/rust-lang/rust/issues/145878)

## Our Approach

We adapted specific modules from sigstore-rs and implemented the rest manually:

### Adapted from sigstore-rs

- `keyring.rs` - CT log public key management
- `transparency.rs` - SCT (Signed Certificate Timestamp) verification

These modules are self-contained with minimal external dependencies, making them easy to extract.

### Implemented Manually

- `certificate.rs` - Certificate validation with typed x509-cert extension parsing
- `trust.rs` - Embedded trust root management (Fulcio CAs, Rekor keys, CT logs)
- `fulcio.rs` - Fulcio CA chain verification
- `rekor.rs` - Rekor transparency log verification (checkpoint signatures, Merkle proofs)
- `dsse.rs` - DSSE envelope signature verification

While sigstore-rs has equivalent modules, we implemented these manually because:

1. **Heavy interconnection** - Unlike keyring/transparency, these modules are deeply intertwined with sigstore-rs infrastructure (TrustRoot, SigningContext, VerificationMaterials, etc.)

2. **Different trust model** - sigstore-rs uses TUF (The Update Framework) for network-based trust root updates; we use embedded JSON for offline verification without network dependencies

3. **Verification-only scope** - sigstore-rs modules handle both signing and verification with additional complexity; we only need the verification path

## Module Structure

```
sigstore/
├── mod.rs           # Public API: verify_repo()
├── certificate.rs   # Certificate validation (KeyUsage, ExtendedKeyUsage, Fulcio OIDs)
├── dsse.rs          # DSSE envelope handling (PAE encoding, signature verification)
├── fulcio.rs        # Fulcio CA chain verification (P-384 ECDSA)
├── keyring.rs       # CT log keyring (adapted from sigstore-rs)
├── rekor.rs         # Rekor verification (ECDSA/Ed25519, Merkle proofs)
├── transparency.rs  # SCT verification (adapted from sigstore-rs)
└── trust.rs         # Trust root management (embedded JSON)
```

## Designed for Swappability

The module structure mirrors sigstore-rs's organization intentionally. Once Rust 1.88+ becomes widely available, we can replace this implementation with:

```toml
sigstore = { version = "0.13+", default-features = false, features = ["verify", "rustls-tls"] }
```

The public API (`verify_repo()`) can remain stable while the implementation switches to the official crate.

## Verification Flow

1. **Fetch** latest release digest from GitHub
2. **Fetch** Sigstore attestation bundle
3. **Verify DSSE signature** (P-256 ECDSA over PAE-encoded payload)
4. **Verify SCT** (Certificate Transparency timestamp)
5. **Verify certificate identity** (GitHub Actions OIDC issuer + repo)
6. **Verify Rekor entry** (checkpoint signature + Merkle inclusion proof)
7. **Verify Fulcio chain** (certificate signed by trusted CA)
8. **Extract measurement** from verified bundle

## Trust Root

The embedded trust root (`assets/trusted_root.json`) contains:

- Fulcio CA certificates (intermediate + root)
- Rekor transparency log public keys (ECDSA P-256 and Ed25519)
- Certificate Transparency log public keys

This enables offline verification without TUF network calls.
