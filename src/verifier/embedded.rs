//! Embedded assets compiled into the binary.
//!
//! These assets are embedded at compile time for offline verification.

/// AMD Genoa certificate chain (ASK + ARK) for SEV-SNP verification.
/// Downloaded from https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
pub const GENOA_CERT_CHAIN: &[u8] = include_bytes!("../../assets/genoa_cert_chain.pem");

/// Sigstore trusted root containing Rekor, Fulcio, and CT log trust material.
/// Used for verifying GitHub Actions attestation bundles.
pub const TRUSTED_ROOT: &[u8] = include_bytes!("../../assets/trusted_root.json");
