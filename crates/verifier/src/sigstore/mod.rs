//! Sigstore bundle verification against a supplied trusted root.
//!
//! Three kinds of bundle are verified here, all DSSE envelopes around an
//! in-toto statement:
//!
//! - bundles signed with a short-lived Fulcio certificate
//!   ([`certificate::verify_fulcio_bundle`]): build provenance and freshness
//!   witnesses;
//! - bundles signed with a registry-issued certificate
//!   ([`certificate::verify_certified_bundle`]): certified config
//!   endorsements;
//! - bundles signed with a pinned key ([`keyed::verify_keyed_bundle`]):
//!   config and artifact approvals.
//!
//! Verification uses only what the bundle and the trusted root carry. Trust
//! material is selected by the times that the bundle itself proves (a log's
//! signed entry timestamp, an RFC 3161 timestamp), never by a clock. No
//! function of this module takes the appraisal instant:
//! [`timestamp::verify_timestamp`] returns the time that a timestamp
//! authenticates, and the caller that bounds an approval's age compares
//! that time with a [`timestamp::AppraisalWindow`], which the endorsement
//! module builds from the appraisal instant.

pub mod bundle;
pub mod certificate;
pub mod checkpoint;
pub mod keyed;
pub mod merkle;
pub mod rekor;
pub mod sct;
pub mod statement;
pub mod timestamp;
pub mod trusted_root;

#[cfg(test)]
pub(crate) mod testutil;

use crate::stub::message_error;

message_error! {
    /// A bundle, trusted root or timestamp that does not parse or does not
    /// verify.
    pub struct SigstoreError;
}

impl From<crate::x509::X509Error> for SigstoreError {
    fn from(error: crate::x509::X509Error) -> Self {
        Self::new(error.to_string())
    }
}

impl From<crate::json::JsonError> for SigstoreError {
    fn from(error: crate::json::JsonError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<crate::json::decode::DecodeError> for SigstoreError {
    fn from(error: crate::json::decode::DecodeError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<crate::canonical::CanonicalError> for SigstoreError {
    fn from(error: crate::canonical::CanonicalError) -> Self {
        Self::new(error.to_string())
    }
}

impl From<merkle::MerkleError> for SigstoreError {
    fn from(error: merkle::MerkleError) -> Self {
        Self::new(error.to_string())
    }
}
