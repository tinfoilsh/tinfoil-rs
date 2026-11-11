//! Runtime provenance: the manifest of a runtime release and the bundle
//! that signs it.

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::AuthenticatedArtifact;
use crate::document::collateral::{Runtime, RuntimeReference};
use crate::runtime::Manifest;
use crate::stub::pending;

/// The predicate type of runtime provenance.
pub const SLSA_PROVENANCE_V1: &str = "https://slsa.dev/provenance/v1";

/// A verified runtime release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeArtifact {
    /// The release that the bundle identifies. Its subject name is the
    /// manifest's file name.
    pub artifact: AuthenticatedArtifact,
    /// The runtime manifest.
    pub manifest: Manifest,
}

/// The file name of the manifest of the runtime release `tag`:
/// `tinfoil-inference-<tag>-manifest.json`.
pub fn manifest_name(tag: &str) -> String {
    format!("tinfoil-inference-{tag}-manifest.json")
}

impl ProvenanceClient {
    /// Authenticates the runtime that an endorsed config pins.
    ///
    /// In order:
    ///
    /// 1. the collateral names exactly the pinned release: its reference
    ///    equals `expected`;
    /// 2. the manifest is the pinned one and decodes
    ///    ([`parse_manifest`](crate::runtime::parse_manifest));
    /// 3. the bundle verifies for
    ///    [`WorkflowIdentity::runtime_release`](super::reference::WorkflowIdentity::runtime_release)
    ///    of the release tag and `expected.digest`, with the named-subject
    ///    rule for [`manifest_name`] of `expected.tag`. The release tag is
    ///    `expected.tag` without build metadata;
    /// 4. the statement is an in-toto v1 statement with the predicate type
    ///    [`SLSA_PROVENANCE_V1`];
    /// 5. the release identity
    ///    ([`authenticated_artifact`](super::provenance::authenticated_artifact))
    ///    for `expected.repo` and the release tag, with the label
    ///    `runtime`; its subject name is then set to the manifest's name.
    pub fn authenticate_runtime(
        &self,
        material: &Runtime,
        expected: &RuntimeReference,
    ) -> Result<RuntimeArtifact, EndorsementError> {
        pending("endorsement::runtime::ProvenanceClient::authenticate_runtime")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_is_named_after_its_release() {
        assert_eq!(
            manifest_name("v1.2.3"),
            "tinfoil-inference-v1.2.3-manifest.json"
        );
    }
}
