//! Authentication of reference values: who published a release, a platform
//! policy, a runtime or a config, and how recently.
//!
//! Three kinds of evidence are verified here, all on top of
//! [`sigstore`](crate::sigstore):
//!
//! - build provenance: a bundle signed by a pinned GitHub Actions workflow
//!   identity ([`provenance`], [`runtime`]);
//! - freshness witnesses of the repository-release flow: a bundle signed by
//!   the witness workflow, dated by the transparency log ([`freshness`]);
//! - approvals: config endorsements and artifact freshness statements
//!   signed with pinned keys or registry certificates, dated by an inner
//!   RFC 3161 timestamp ([`approval`]).
//!
//! Nothing here reads a clock or fetches anything. The appraisal instant
//! arrives as an argument wherever age is judged.

pub mod approval;
pub mod freshness;
pub mod provenance;
pub mod reference;
pub mod runtime;
pub mod signing_keys;
pub mod time;

use crate::stub::message_error;

pub use approval::{
    ApprovalVerifier, Artifact, ArtifactKind, ConfigPolicy, ConfigVerified, ConfigVerifier,
    FreshnessPolicy, FreshnessVerified, FreshnessVerifier, PUBLIC_REGISTRY_ID,
};
pub use provenance::{Code, PlatformEndorsements, ProvenanceClient};
pub use reference::{AuthenticatedArtifact, Reference, WorkflowIdentity, parse_reference};
pub use runtime::RuntimeArtifact;
pub use signing_keys::public_signing_keys;
pub use time::{DEFAULT_FUTURE_SKEW, DEFAULT_MAX_AGE, approval_window};

message_error! {
    /// Reference values that do not authenticate, do not match what was
    /// asked for, or are too old.
    pub struct EndorsementError;
}

macro_rules! endorsement_error_from {
    ($($source:ty),* $(,)?) => {
        $(impl From<$source> for EndorsementError {
            fn from(error: $source) -> Self {
                Self::new(error.to_string())
            }
        })*
    };
}

endorsement_error_from!(
    crate::sigstore::SigstoreError,
    crate::x509::X509Error,
    crate::policy::PolicyError,
    crate::runtime::ManifestError,
    crate::runtime::RuntimeConfigError,
    crate::document::collateral::CollateralError,
    crate::canonical::CanonicalError,
);
