//! Offline verification of Tinfoil enclave attestation documents.
//!
//! This crate is the functional core of the SDK. It opens no connections,
//! reads no files and keeps no state between calls: a caller hands it an
//! attestation document and gets back either the verified facts or the reason
//! the document must not be trusted. Fetching documents and binding
//! connections to a verified enclave belong to the `tinfoil` client crate.
//!
//! # Verifying a document
//!
//! A [`Verifier`] holds the policy: which repository or config to accept,
//! how old a freshness proof may be, and optional register pins. Its
//! [`verify_v3`](Verifier::verify_v3) takes the document, the nonce that the
//! caller sent with its request, and a repository pin, and returns a
//! [`Verification`] with the endorsed keys to bind traffic to.
//!
//! ```no_run
//! use tinfoil_verifier::{Error, Verifier, random_nonce};
//!
//! # fn fetch(_nonce: &[u8]) -> Vec<u8> { Vec::new() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let nonce = random_nonce()?;
//! let document = fetch(&nonce);
//! let verifier = Verifier::new();
//! match verifier.verify_v3(&document, &nonce, "tinfoilsh/confidential-model-router") {
//!     Ok(verified) => println!("TLS key: {:?}", verified.tls_public_key_fp()),
//!     Err(Error::Verification(rejected)) => println!("rejected at {}", rejected.layer()),
//!     Err(other) => return Err(other.into()),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! An error is either a [`UsageError`], for a verifier that was built or
//! called with invalid inputs, or a [`VerificationError`], for a document
//! that must not be trusted, with the [`Layer`] that rejected it.
//!
//! # Trust anchors
//!
//! The trust anchors are embedded in the crate and cannot be replaced
//! through its API: the methods that take a replacement anchor exist only
//! in a build for the conformance adapter, which passes
//! `--cfg tinfoil_conformance` to the compiler.
//!
//! ```compile_fail
//! // An ordinary build has no way to supply a Sigstore trusted root.
//! let _ = tinfoil_verifier::Verifier::builder().dangerous_test_only_sigstore_root(b"{}");
//! ```
//!
//! ```compile_fail
//! // Nor a vendor root.
//! let _ = tinfoil_verifier::Verifier::builder().dangerous_test_only_vendor_roots(None, None);
//! ```
//!
//! # Features
//!
//! - `serde`: implements `serde::Serialize` for [`Verification`],
//!   [`Register`], [`Measurement`] and [`Expected`], in the shape of
//!   [`Verification::to_json`]. Off by default.

// Clippy has no test exemption for this lint, unlike the other denied
// lints (see clippy.toml). Overflow in a test is a test failure, not a risk.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

mod canonical;
#[cfg(test)]
mod differential_tests;
mod embedded;
mod error;
mod fingerprint;
mod measurement;
mod options;
#[cfg(test)]
mod probes;
mod semver;
mod stub;
mod verification;
mod verifier;

// The verifier drives the modules below, and each of them also has items
// that only the single-layer stages of the conformance adapter and the unit
// tests reach: accessors of intermediate values, constructors that take a
// replacement trust anchor, and re-exports. Those have no caller in an
// ordinary build, where the allowance applies; a conformance build exports
// the modules.
#[cfg_attr(not(tinfoil_conformance), allow(dead_code, unused_imports))]
mod document;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code, unused_imports))]
mod endorsement;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code))]
mod instant;
#[cfg_attr(not(tinfoil_conformance), allow(unused_imports))]
mod policy;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code, unused_imports))]
mod quote;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code))]
mod sigstore;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code, unused_imports))]
mod x509;

// These are not exported to the adapter. Only the tests read the detail of
// a JSON error and the recorded hashes of the embedded trust anchors, and
// the runtime module gathers the names of its types whether or not the
// crate spells each of them out.
#[cfg_attr(not(test), allow(dead_code))]
mod json;
#[allow(unused_imports)]
mod runtime;
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod trust;

pub use document::{
    ATTESTATION_V3_FORMAT, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS,
    CRYPTO_MATERIAL_V1_FORMAT, CryptoMaterialItem, DEVICE_EVIDENCE_V1_FORMAT,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE,
    NVIDIA_GPU_EVIDENCE_V1_FORMAT, REPORT_DATA_V1_ALGORITHM, SEV_SNP_REPORT_V1_FORMAT,
    TDX_QUOTE_V1_FORMAT, random_nonce,
};
pub use embedded::{EmbeddedConfig, EmbeddedReferences, RuntimeReference};
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
