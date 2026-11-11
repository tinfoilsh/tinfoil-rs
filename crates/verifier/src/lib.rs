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

// The verification entry point that drives the internal modules is not in
// the crate yet, so much of them has no caller in an ordinary build.
#[allow(dead_code)]
mod canonical;
#[allow(dead_code, unused_imports)]
mod document;
mod error;
#[allow(dead_code)]
mod instant;
#[allow(dead_code)]
mod json;
mod measurement;
#[allow(dead_code, unused_imports)]
mod policy;
#[cfg(test)]
mod probes;
#[allow(dead_code, unused_imports)]
mod runtime;
#[allow(dead_code)]
mod semver;
#[allow(dead_code, unused_macros, unused_imports)]
mod stub;
#[allow(dead_code, unused_imports, unused_variables)]
mod x509;

pub use document::{NONCE_SIZE, random_nonce};
pub use error::{Error, Layer, UsageError, VerificationError};
pub use measurement::{Expected, Measurement, REGISTER_SIZE, Register};

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
}
