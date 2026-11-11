//! Offline verification of Tinfoil enclave attestation documents.
//!
//! This crate is the functional core of the SDK. It opens no connections,
//! reads no files and keeps no state between calls: a caller hands it an
//! attestation document and gets back either the verified facts or the reason
//! the document must not be trusted. Fetching documents and binding
//! connections to a verified enclave belong to the `tinfoil` client crate.
//!
//! The crate is under construction. It exports the error model, the
//! measurement types and the challenge nonce; the verifier itself is not
//! here yet.

// Clippy has no test exemption for this lint, unlike the other denied
// lints (see clippy.toml). Overflow in a test is a test failure, not a risk.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

mod canonical;
#[cfg(test)]
mod differential_tests;
mod document;
mod embedded;
mod endorsement;
mod error;
mod fingerprint;
mod instant;
mod json;
mod measurement;
mod options;
mod policy;
#[cfg(test)]
mod probes;
mod quote;
mod runtime;
mod semver;
mod sigstore;
mod stub;
mod trust;
mod verification;
mod verifier;
mod x509;

pub use document::collateral::RuntimeReference;
pub use document::{
    ATTESTATION_V3_FORMAT, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS,
    CRYPTO_MATERIAL_V1_FORMAT, CryptoMaterialItem, DEVICE_EVIDENCE_V1_FORMAT,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE,
    NVIDIA_GPU_EVIDENCE_V1_FORMAT, REPORT_DATA_V1_ALGORITHM, SEV_SNP_REPORT_V1_FORMAT,
    TDX_QUOTE_V1_FORMAT, random_nonce,
};
pub use embedded::{EmbeddedConfig, EmbeddedReferences};
pub use endorsement::{PUBLIC_REGISTRY_ID, Reference};
pub use error::{BoxError, Error, Layer, UsageError, VerificationError};
pub use fingerprint::cert_pubkey_fp;
pub use measurement::{Expected, Measurement, REGISTER_SIZE, Register};
pub use options::{ConfigEndorsement, PublicKey, VerifierBuilder};
pub use verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, SoftwareIdentity, Verification,
    VerificationMetadata, crypto_material_data,
};
pub use verifier::{Verifier, parse_reference};

/// Internal modules, exposed to the conformance adapter only. This module
/// exists only in builds that pass `--cfg tinfoil_conformance`; it is not
/// part of the public API and carries no stability promise.
#[cfg(tinfoil_conformance)]
#[doc(hidden)]
pub mod conformance {
    /// The attestation document and its strict parsing.
    pub mod document {
        pub use crate::document::*;
    }
    /// Authentication of reference values.
    pub mod endorsement {
        pub use crate::endorsement::*;
    }
    /// The verifier's time type.
    pub mod instant {
        pub use crate::instant::*;
    }
    /// The platform policy artifact.
    pub mod policy {
        pub use crate::policy::*;
    }
    /// Authentication and appraisal of CPU evidence.
    pub mod quote {
        pub use crate::quote::*;
    }
    /// Sigstore bundles, trusted roots and timestamps.
    pub mod sigstore {
        pub use crate::sigstore::*;
    }
    /// Certificates and public keys.
    pub mod x509 {
        pub use crate::x509::*;
    }
}
