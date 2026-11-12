//! Runtime provenance: the manifest of a runtime release and the bundle
//! that signs it.

use super::EndorsementError;
use super::provenance::{ProvenanceClient, authenticated_artifact};
use super::reference::{AuthenticatedArtifact, WorkflowIdentity};
use crate::document::collateral::{Runtime, RuntimeReference};
use crate::runtime::{Manifest, parse_manifest};
use crate::semver;
use crate::sigstore::statement::STATEMENT_TYPE;

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
    ///    ([`parse_manifest`]);
    /// 3. the bundle verifies for
    ///    [`WorkflowIdentity::runtime_release`](super::reference::WorkflowIdentity::runtime_release)
    ///    of the release tag and `expected.digest`, with the named-subject
    ///    rule for [`manifest_name`] of `expected.tag`. The release tag is
    ///    `expected.tag` without build metadata;
    /// 4. the statement is an in-toto v1 statement with the predicate type
    ///    [`SLSA_PROVENANCE_V1`];
    /// 5. the release identity
    ///    ([`authenticated_artifact`])
    ///    for `expected.repo` and the release tag, with the label
    ///    `runtime`; its subject name is then set to the manifest's name.
    pub fn authenticate_runtime(
        &self,
        material: &Runtime,
        expected: &RuntimeReference,
    ) -> Result<RuntimeArtifact, EndorsementError> {
        if material.reference != *expected {
            return Err(EndorsementError::new(
                "runtime collateral does not match the endorsed config's runtime pin",
            ));
        }
        let manifest = parse_manifest(&material.manifest, expected)?;
        let subject = manifest_name(&expected.tag);
        let release_tag = release_tag(&expected.tag);
        let verified = self
            .verify_bundle_for_subject(
                &material.bundle,
                &WorkflowIdentity::runtime_release(&release_tag),
                &expected.digest,
                Some(&subject),
            )
            .map_err(|cause| cause.within("verifying runtime provenance"))?;
        if verified.statement.statement_type != STATEMENT_TYPE
            || verified.statement.predicate_type != SLSA_PROVENANCE_V1
        {
            return Err(EndorsementError::new("runtime provenance must use SLSA v1"));
        }
        let mut artifact = authenticated_artifact(
            &verified,
            &expected.repo,
            &release_tag,
            &expected.digest,
            "runtime",
        )?;
        artifact.subject_name = subject;
        Ok(RuntimeArtifact { artifact, manifest })
    }
}

/// The tag that a runtime version is released at: the version in full,
/// without build metadata. Empty when `version` is not a version.
pub(crate) fn release_tag(version: &str) -> String {
    semver::parse(version)
        .map(|version| {
            format!(
                "v{}.{}.{}{}",
                version.major, version.minor, version.patch, version.prerelease
            )
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_tag_is_the_version_without_build_metadata() {
        for (version, tag) in [
            ("v1.2.3", "v1.2.3"),
            ("v1.2.3+build.5", "v1.2.3"),
            ("v1.2.3-rc.1+build", "v1.2.3-rc.1"),
            ("v1.2", "v1.2.0"),
            ("v1", "v1.0.0"),
            ("1.2.3", ""),
            ("", ""),
        ] {
            assert_eq!(release_tag(version), tag, "{version}");
        }
    }

    #[test]
    fn a_manifest_is_named_after_its_release() {
        assert_eq!(
            manifest_name("v1.2.3"),
            "tinfoil-inference-v1.2.3-manifest.json"
        );
    }
}
