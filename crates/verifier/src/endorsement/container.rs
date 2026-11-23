//! Container provenance: the build attestation of a container image, for a
//! config that requires one.

use super::EndorsementError;
use super::provenance::ProvenanceClient;
use super::reference::{WorkflowIdentity, is_git_commit, matches_ref_pattern};
use super::runtime::SLSA_PROVENANCE_V1;
use crate::json::Value;
use crate::runtime::ContainerProvenance;
use crate::sigstore::certificate::FulcioExtensions;
use crate::sigstore::statement::{STATEMENT_TYPE, Statement};

/// What precedes the repository in the URI of a repository on GitHub.
const GITHUB_REPOSITORY_URI_PREFIX: &str = "https://github.com/";

/// A container image whose build was authenticated against the requirement
/// that its config declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// The SHA-256 of the image, as the requirement states it.
    pub digest: String,
    /// The repository whose workflow built the image.
    pub repository: String,
    /// The file name of the workflow.
    pub workflow: String,
    /// The ref that the workflow ran at.
    pub git_ref: String,
    /// The commit that the workflow ran at: 40 lowercase hex digits.
    pub commit: String,
}

impl ProvenanceClient {
    /// Authenticates the build attestation of a container image against
    /// the requirement of its config.
    ///
    /// In order:
    ///
    /// 1. the bundle verifies for
    ///    [`WorkflowIdentity::container_build`](super::reference::WorkflowIdentity::container_build)
    ///    of the required repository, workflow and ref pattern, and for
    ///    the required digest, with the first-subject rule
    ///    ([`ProvenanceClient::verify_bundle_for_subject`]);
    /// 2. the source of the run is the required one
    ///    ([`authenticated_container`]).
    pub fn authenticate_container(
        &self,
        bundle: &Value,
        required: &ContainerProvenance,
    ) -> Result<Container, EndorsementError> {
        let identity = WorkflowIdentity::container_build(
            &required.repository,
            &required.workflow,
            &required.git_ref,
        );
        let verified = self
            .verify_bundle_for_subject(bundle, &identity, &required.digest, None)
            .map_err(|cause| cause.within("verifying container provenance"))?;
        authenticated_container(&verified.statement, &verified.identity.extensions, required)
    }
}

/// Checks a verified statement and the claims of its signing certificate
/// against a requirement.
///
/// The signing identity names the workflow file that ran, which a workflow
/// of another repository can call. The source claims name the repository
/// and the ref that triggered the run. In order:
///
/// 1. the statement is an in-toto v1 statement with the predicate type
///    [`SLSA_PROVENANCE_V1`];
/// 2. the certificate's source repository URI is that of the required
///    repository on GitHub;
/// 3. its source repository identifier is the required one;
/// 4. its source repository ref matches the required ref pattern
///    ([`matches_ref_pattern`]);
/// 5. its source repository digest is a Git commit ([`is_git_commit`]).
pub fn authenticated_container(
    statement: &Statement,
    claims: &FulcioExtensions,
    required: &ContainerProvenance,
) -> Result<Container, EndorsementError> {
    if statement.statement_type != STATEMENT_TYPE || statement.predicate_type != SLSA_PROVENANCE_V1
    {
        return Err(EndorsementError::new(
            "container provenance must use SLSA v1",
        ));
    }
    let source = claims.source_repository_uri.as_str();
    if source.strip_prefix(GITHUB_REPOSITORY_URI_PREFIX) != Some(required.repository.as_str()) {
        return Err(EndorsementError::new(format!(
            "container provenance source repository {source:?} does not match {:?}",
            required.repository
        )));
    }
    if claims.source_repository_identifier != required.repository_id {
        return Err(EndorsementError::new(
            "container provenance source repository ID does not match the required repository",
        ));
    }
    let source_ref = claims.source_repository_ref.as_str();
    if !matches_ref_pattern(&required.git_ref, source_ref) {
        return Err(EndorsementError::new(format!(
            "container provenance source ref {source_ref:?} does not match {:?}",
            required.git_ref
        )));
    }
    let commit = claims.source_repository_digest.as_str();
    if !is_git_commit(commit) {
        return Err(EndorsementError::new(
            "container provenance source digest is not a lowercase Git commit",
        ));
    }
    Ok(Container {
        digest: required.digest.clone(),
        repository: required.repository.clone(),
        workflow: required.workflow.clone(),
        git_ref: source_ref.to_string(),
        commit: commit.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;
    use crate::sigstore::statement::{DIGEST_ALGORITHM, Subject};

    /// The published build attestation of the image with
    /// [`RECORDED_DIGEST`].
    const RECORDED_BUNDLE: &[u8] =
        include_bytes!("../../tests/data/endorsement/container_provenance_bundle.json");
    const RECORDED_REPOSITORY: &str = "tinfoilsh/measure-image-action";
    const RECORDED_REPOSITORY_ID: &str = "924941172";
    const RECORDED_DIGEST: &str =
        "85306e3ab312a2d80466e901081e855cc53f21c4802c638f861e6ef31ba4f5d1";
    const RECORDED_COMMIT: &str = "01a05df207140a8e8e1d2cd26028ab7c51dad9d1";
    const RECORDED_REF: &str = "refs/tags/build-v0.14.2";

    /// A change to a requirement.
    type Requirement = fn(&mut ContainerProvenance);
    /// A change to the claims of a signing certificate and to the statement
    /// that it signs.
    type Evidence = fn(&mut FulcioExtensions, &mut Statement);

    fn recorded_requirement() -> ContainerProvenance {
        ContainerProvenance {
            container: "app".to_string(),
            digest: RECORDED_DIGEST.to_string(),
            repository: RECORDED_REPOSITORY.to_string(),
            repository_id: RECORDED_REPOSITORY_ID.to_string(),
            workflow: "build.yml".to_string(),
            git_ref: "refs/tags/build-v*".to_string(),
        }
    }

    #[test]
    fn the_recorded_build_attestation_authenticates_against_its_requirement() {
        let client = ProvenanceClient::embedded().unwrap();
        let bundle = json::parse(RECORDED_BUNDLE).unwrap();
        let authenticate = |required: &ContainerProvenance| {
            client
                .authenticate_container(&bundle, required)
                .map_err(|error| error.to_string())
        };
        assert_eq!(
            authenticate(&recorded_requirement()),
            Ok(Container {
                digest: RECORDED_DIGEST.to_string(),
                repository: RECORDED_REPOSITORY.to_string(),
                workflow: "build.yml".to_string(),
                git_ref: RECORDED_REF.to_string(),
                commit: RECORDED_COMMIT.to_string(),
            })
        );
        let mut exact = recorded_requirement();
        exact.git_ref = RECORDED_REF.to_string();
        assert!(authenticate(&exact).is_ok());

        let identity = "verifying container provenance: verifying: signing certificate identity \"https://github.com/tinfoilsh/measure-image-action/.github/workflows/build.yml@refs/tags/build-v0.14.2\" is not the expected workflow";
        let changes: [(&str, Requirement, &str); 12] = [
            (
                "another image",
                |required| required.digest.replace_range(..2, "00"),
                "verifying container provenance: verifying: provided artifact digest does not match any digest in statement",
            ),
            (
                "another repository",
                |required| required.repository = "tinfoilsh/cvmimage".to_string(),
                identity,
            ),
            (
                "repository prefix",
                |required| required.repository = "tinfoilsh/measure-image".to_string(),
                identity,
            ),
            (
                "another repository ID",
                |required| required.repository_id = "902195777".to_string(),
                "container provenance source repository ID does not match the required repository",
            ),
            (
                "another workflow",
                |required| required.workflow = "release.yml".to_string(),
                identity,
            ),
            (
                "workflow prefix",
                |required| required.workflow = "build.ym".to_string(),
                identity,
            ),
            (
                "workflow as a pattern",
                |required| required.workflow = "build.y*".to_string(),
                identity,
            ),
            (
                "another tag series",
                |required| required.git_ref = "refs/tags/v*".to_string(),
                identity,
            ),
            (
                "exact other tag",
                |required| required.git_ref = "refs/tags/build-v0.14.3".to_string(),
                identity,
            ),
            (
                "tag prefix",
                |required| required.git_ref = "refs/tags/build-v0.14".to_string(),
                identity,
            ),
            (
                "pattern with a trailing line break",
                |required| required.git_ref = "refs/tags/build-v*\n".to_string(),
                identity,
            ),
            (
                "branch",
                |required| required.git_ref = "refs/heads/main".to_string(),
                identity,
            ),
        ];
        for (name, change, want) in changes {
            let mut required = recorded_requirement();
            change(&mut required);
            assert_eq!(authenticate(&required), Err(want.to_string()), "{name}");
        }
    }

    fn slsa_statement() -> Statement {
        Statement {
            statement_type: STATEMENT_TYPE.to_string(),
            subjects: vec![Subject {
                name: "ghcr.io/tinfoilsh/measure-image-action".to_string(),
                digest: [(DIGEST_ALGORITHM.to_string(), RECORDED_DIGEST.to_string())].into(),
            }],
            predicate_type: SLSA_PROVENANCE_V1.to_string(),
            predicate: json::parse(b"{}").unwrap(),
        }
    }

    fn recorded_claims() -> FulcioExtensions {
        FulcioExtensions {
            source_repository_uri: format!("{GITHUB_REPOSITORY_URI_PREFIX}{RECORDED_REPOSITORY}"),
            source_repository_identifier: RECORDED_REPOSITORY_ID.to_string(),
            source_repository_ref: RECORDED_REF.to_string(),
            source_repository_digest: RECORDED_COMMIT.to_string(),
            ..FulcioExtensions::default()
        }
    }

    #[test]
    fn the_source_of_a_build_is_the_required_repository_at_a_required_ref() {
        let required = recorded_requirement();
        let check = |change: Evidence| {
            let (mut claims, mut statement) = (recorded_claims(), slsa_statement());
            change(&mut claims, &mut statement);
            authenticated_container(&statement, &claims, &required)
                .map_err(|error| error.to_string())
        };
        let container = check(|_, _| {}).unwrap();
        assert_eq!(container.git_ref, RECORDED_REF);
        assert_eq!(container.commit, RECORDED_COMMIT);
        let cases: [(&str, Evidence, &str); 15] = [
            // A workflow of another repository can call the required
            // workflow file, which then signs with its own identity.
            (
                "called from another repository",
                |claims, _| {
                    claims.source_repository_uri =
                        format!("{GITHUB_REPOSITORY_URI_PREFIX}attacker/fork");
                },
                "source repository \"https://github.com/attacker/fork\" does not match",
            ),
            (
                "repository with a suffix",
                |claims, _| claims.source_repository_uri.push_str("-fork"),
                "source repository \"https://github.com/tinfoilsh/measure-image-action-fork\"",
            ),
            (
                "repository with a trailing line break",
                |claims, _| claims.source_repository_uri.push('\n'),
                "source repository \"https://github.com/tinfoilsh/measure-image-action\\n\"",
            ),
            (
                "repository on another host",
                |claims, _| {
                    claims.source_repository_uri =
                        format!("https://github.com.example/{RECORDED_REPOSITORY}");
                },
                "source repository \"https://github.com.example/",
            ),
            (
                "no repository",
                |claims, _| claims.source_repository_uri.clear(),
                "source repository \"\" does not match",
            ),
            (
                "recreated repository",
                |claims, _| claims.source_repository_identifier = "1".to_string(),
                "source repository ID",
            ),
            (
                "repository ID with a trailing line break",
                |claims, _| claims.source_repository_identifier.push('\n'),
                "source repository ID",
            ),
            (
                "missing repository ID",
                |claims, _| claims.source_repository_identifier.clear(),
                "source repository ID",
            ),
            (
                "pull request ref",
                |claims, _| claims.source_repository_ref = "refs/pull/7/merge".to_string(),
                "source ref \"refs/pull/7/merge\" does not match \"refs/tags/build-v*\"",
            ),
            (
                "nested tag",
                |claims, _| claims.source_repository_ref = "refs/tags/build-v1/extra".to_string(),
                "source ref \"refs/tags/build-v1/extra\"",
            ),
            (
                "no ref",
                |claims, _| claims.source_repository_ref.clear(),
                "source ref \"\"",
            ),
            (
                "no commit",
                |claims, _| claims.source_repository_digest.clear(),
                "Git commit",
            ),
            (
                "commit in uppercase",
                |claims, _| claims.source_repository_digest.make_ascii_uppercase(),
                "Git commit",
            ),
            (
                "another predicate",
                |_, statement| {
                    statement.predicate_type = "https://spdx.dev/Document/v2.3".to_string();
                },
                "SLSA v1",
            ),
            (
                "another statement type",
                |_, statement| {
                    statement.statement_type = "https://in-toto.io/Statement/v0.1".to_string();
                },
                "SLSA v1",
            ),
        ];
        for (name, change, want) in cases {
            let error = check(change).unwrap_err();
            assert!(error.contains(want), "{name}: {error}");
        }

        // A ref that is required exactly is matched as a whole.
        let mut exact = recorded_requirement();
        exact.git_ref = RECORDED_REF.to_string();
        assert!(authenticated_container(&slsa_statement(), &recorded_claims(), &exact).is_ok());
        for other in [
            format!("{RECORDED_REF}\n"),
            format!("{RECORDED_REF}.1"),
            format!("x{RECORDED_REF}"),
        ] {
            let mut claims = recorded_claims();
            claims.source_repository_ref = other;
            let error = authenticated_container(&slsa_statement(), &claims, &exact).unwrap_err();
            assert!(error.to_string().contains("source ref"), "{error}");
        }
    }
}
