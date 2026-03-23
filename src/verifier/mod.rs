//! Core verification machinery for Tinfoil attestation.

pub mod attestation;
pub(crate) mod dcode;
pub mod embedded;
pub mod github;
pub mod sigstore;
pub mod tls;
pub(crate) mod util;

// Re-export commonly used types
pub use attestation::{
    fetch, verify_complete, verify_full, AttestationDocument, GroundTruth, Measurement,
    MeasurementError, PredicateType, Verification,
};
