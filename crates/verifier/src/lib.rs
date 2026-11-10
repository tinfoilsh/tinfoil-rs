//! Offline verification of Tinfoil enclave attestation documents.
//!
//! This crate is the functional core of the SDK. It opens no connections,
//! reads no files and keeps no state between calls: a caller hands it an
//! attestation document and gets back either the verified facts or the reason
//! the document must not be trusted. Fetching documents and binding
//! connections to a verified enclave belong to the `tinfoil` client crate.
//!
//! The crate is under construction. It exports the error model and the
//! measurement types; the verifier itself is not here yet.

// Clippy has no test exemption for this lint, unlike the other denied
// lints (see clippy.toml). Overflow in a test is a test failure, not a risk.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

// The verification entry point that drives the internal modules is not in
// the crate yet, so much of them has no caller in an ordinary build.
#[allow(dead_code)]
mod canonical;
mod error;
#[allow(dead_code)]
mod json;
mod measurement;
#[allow(dead_code)]
mod semver;

pub use error::{Error, Layer, UsageError, VerificationError};
pub use measurement::{Expected, Measurement, REGISTER_SIZE, Register};
