//! Offline verification of Tinfoil enclave attestation documents.
//!
//! This crate is the functional core of the SDK. It opens no connections,
//! reads no files and keeps no state between calls: a caller hands it an
//! attestation document and gets back either a report with the verified
//! facts or the reason that the document must not be trusted, with a report
//! of the step that rejected it. Fetching documents and binding
//! connections to a verified enclave belong to the `tinfoil` client crate.
//!
//! # Verifying a document
//!
//! A [`Verifier`] holds the policy: a [`ConfigTrust`] that selects who
//! vouches for the config, and a [`Policy`] with how old a freshness proof
//! may be, optional register pins and how the runtime and platform
//! artifacts are trusted. Each choice of trust is one value, so that two
//! sources of trust that would conflict cannot be configured together. Its
//! [`verify_v3`](Verifier::verify_v3) takes the document, the nonce that the
//! caller sent with its request, and a [`Pin`], and returns a
//! [`VerificationReport`]: the [`Step`] that each layer took, and the
//! [`VerifiedFacts`] with the endorsed keys to bind traffic to.
//!
//! ```no_run
//! use tinfoil_verifier::{Error, Pin, Verifier, random_nonce};
//!
//! # fn fetch(_nonce: &[u8]) -> Vec<u8> { Vec::new() }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let nonce = random_nonce()?;
//! let document = fetch(&nonce);
//! let verifier = Verifier::default();
//! match verifier.verify_v3(&document, &nonce, &Pin::repo("owner/repository")) {
//!     Ok(report) => {
//!         let verified = report.verified_facts().expect("an accepted document is verified");
//!         println!("TLS key: {:?}", verified.tls_public_key_fp());
//!     }
//!     Err(Error::Verification(rejected)) => {
//!         for step in rejected.report().steps() {
//!             println!("{}: {} {}", step.layer, step.status, step.message);
//!         }
//!     }
//!     Err(other) => return Err(other.into()),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! An error is either a [`UsageError`], for a verifier that was built or
//! called with invalid inputs, or a [`VerificationError`], for a document
//! that must not be trusted, with the [`Layer`] that rejected it and its
//! report. The report of a rejection holds [`PartialFacts`]: what the steps
//! before the failed one established, such as the expected and the measured
//! registers of a measurement that does not match. They authorize nothing;
//! only verified facts carry the keys that a channel may be bound to.
//!
//! # Trust anchors
//!
//! The Sigstore trusted root and the AMD and Intel roots are embedded in
//! the crate and cannot be replaced through its API: the methods that take
//! a replacement root exist only in a build for the conformance adapter,
//! which passes `--cfg tinfoil_conformance` to the compiler.
//!
//! Tinfoil's public signing keys are a default, not an anchor of that
//! kind: [`ConfigTrust::SigningKeys`] and the `freshness_keys` of
//! [`ArtifactTrust`] replace the keys that config endorsements and
//! artifact approvals are verified under.
//!
#![cfg_attr(not(tinfoil_conformance), doc = "```compile_fail,E0599")]
#![cfg_attr(tinfoil_conformance, doc = "```no_run")]
//! // An ordinary build has no way to supply a Sigstore trusted root or a
//! // vendor root.
//! use tinfoil_verifier::{ConfigTrust, Policy, Verifier};
//! let _ = Verifier::dangerous_test_only_new(
//!     ConfigTrust::default(),
//!     Policy::default(),
//!     Default::default(),
//! );
//! ```
//!
//! # Features
//!
//! - `serde`: implements `serde::Serialize` for [`VerificationReport`],
//!   [`VerifiedFacts`], [`Register`], [`Measurement`] and [`Expected`], in
//!   the shape of [`VerificationReport::to_json`] and
//!   [`VerifiedFacts::to_json`]. Off by default.

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
mod report;
mod semver;
mod stub;
mod verification;
mod verifier;
#[cfg(test)]
mod verifier_tests;

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
#[cfg_attr(not(tinfoil_conformance), allow(unused_imports))]
mod runtime;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code))]
mod sigstore;
#[cfg_attr(not(tinfoil_conformance), allow(dead_code, unused_imports))]
mod x509;

// These are not exported to the adapter. Only the tests read the detail of
// a JSON error and the recorded hashes of the embedded trust anchors.
#[cfg_attr(not(test), allow(dead_code))]
mod json;
#[cfg_attr(not(test), allow(dead_code, unused_imports))]
mod trust;

pub use document::{
    ATTESTATION_V3_FORMAT, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS,
    CRYPTO_MATERIAL_V1_FORMAT, CryptoMaterialItem, DEVICE_EVIDENCE_V1_FORMAT,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_SPKI_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE,
    NVIDIA_GPU_EVIDENCE_V1_FORMAT, REPORT_DATA_V1_ALGORITHM, SEV_SNP_REPORT_V1_FORMAT,
    TDX_QUOTE_V1_FORMAT, random_nonce,
};
pub use embedded::{EmbeddedConfig, RuntimeReference};
pub use endorsement::{PUBLIC_REGISTRY_ID, Reference};
pub use error::{BoxError, Error, Layer, UsageError, VerificationError};
pub use fingerprint::cert_pubkey_fp;
pub use measurement::{Expected, Measurement, REGISTER_SIZE, Register};
pub use options::{
    ArtifactTrust, ConfigAuthorizer, ConfigEndorsement, ConfigTrust, Policy, PublicKey,
};
pub use report::{
    CpuEvidence, ExpectedFacts, MeasuredFacts, PartialFacts, Step, StepStatus, VerificationReport,
    hpke_public_key_fp,
};
pub use verification::{
    ArtifactVerification, ConfigVerification, ReferenceSource, SoftwareIdentity,
    VerificationMetadata, VerifiedFacts, crypto_material_data,
};
pub use verifier::{Pin, Verifier, parse_reference};

#[cfg(tinfoil_conformance)]
pub use options::DangerousTestOnlyRoots;

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
    /// The runtime manifest, and the runtime pin of a config.
    pub mod runtime {
        pub use crate::runtime::*;
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
