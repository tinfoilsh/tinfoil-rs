//! Core verification machinery for Tinfoil attestation.
//!
//! Submodules tagged `#[doc(hidden)]` are reachable from the in-tree
//! conformance binary and integration tests but are excluded from rustdoc;
//! treat them as not part of the public API contract. Re-exported types
//! below (`GroundTruth`, `Measurement`, etc.) are the supported surface.

pub(crate) mod dcode;

#[doc(hidden)]
pub mod attestation;
#[doc(hidden)]
pub mod embedded;
#[doc(hidden)]
pub mod github;
#[doc(hidden)]
pub mod sigstore;
#[doc(hidden)]
pub mod tls;
#[doc(hidden)]
pub mod util;

// Re-export commonly used types
pub use attestation::{
    fetch, verify_complete, verify_full, AttestationDocument, GroundTruth, Measurement,
    MeasurementError, PredicateType, Verification,
};
