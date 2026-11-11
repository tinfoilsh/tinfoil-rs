//! Build provenance: Sigstore bundles signed by pinned GitHub Actions
//! workflow identities.

use std::sync::Arc;

use super::EndorsementError;
use super::reference::{AuthenticatedArtifact, Reference, WorkflowIdentity};
use crate::json::Value;
use crate::measurement::{Expected, Register};
use crate::policy::{Artifact, Shape};
use crate::sigstore::certificate::VerifiedBundle;
use crate::sigstore::trusted_root::TrustedRoot;
use crate::stub::pending;

/// The predicate type of a code release: the SEV-SNP launch measurement and
/// the TDX RTMR1 and RTMR2 that the release fixes.
pub const MULTI_PLATFORM_PREDICATE_TYPE: &str =
    "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1";

/// Authenticates provenance against one Sigstore trusted root.
///
/// A client holds its own trusted root, so which root a verification used
/// is a property of the object that did it. The root is never refreshed at
/// run time.
#[derive(Debug, Clone)]
pub struct ProvenanceClient {
    root: Arc<TrustedRoot>,
}

/// The verified content of a code-provenance bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    /// The release that the bundle identifies.
    pub artifact: AuthenticatedArtifact,
    /// The SEV-SNP launch measurement that the release fixes.
    pub sev_snp_launch: Register,
    /// The TDX RTMR1 that the release fixes.
    pub tdx_rtmr1: Register,
    /// The TDX RTMR2 that the release fixes.
    pub tdx_rtmr2: Register,
    /// The VM shape that the release declares.
    pub shape: Shape,
}

impl Code {
    /// The registers that the release fixes on SEV-SNP.
    pub fn sev_snp_expected(&self) -> Expected {
        Expected::SevSnp {
            launch: Some(self.sev_snp_launch),
        }
    }

    /// The registers that the release fixes on TDX: RTMR1 and RTMR2. The
    /// others are left to the platform policy.
    pub fn tdx_expected(&self) -> Expected {
        Expected::Tdx {
            mrtd: None,
            rtmr0: None,
            rtmr1: Some(self.tdx_rtmr1),
            rtmr2: Some(self.tdx_rtmr2),
            rtmr3: None,
        }
    }
}

/// The verified platform policy artifact and the release that carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformEndorsements {
    /// The release that the bundle identifies.
    pub artifact: AuthenticatedArtifact,
    /// The policy artifact, decoded from the signed predicate.
    pub policy: Artifact,
}

impl ProvenanceClient {
    /// A client that trusts the Sigstore trusted root embedded in the
    /// crate. An error only if the embedded root does not parse.
    pub fn embedded() -> Result<Self, EndorsementError> {
        Self::from_trusted_root_json(crate::trust::SIGSTORE_TRUSTED_ROOT_JSON)
    }

    /// A client that trusts the given trusted root document
    /// ([`TrustedRoot::from_json`]).
    pub fn from_trusted_root_json(trusted_root: &[u8]) -> Result<Self, EndorsementError> {
        let root = TrustedRoot::from_json(trusted_root)
            .map_err(|cause| cause.within("parsing trust root"))?;
        Ok(Self {
            root: Arc::new(root),
        })
    }

    /// The trusted root that the client verifies against.
    pub fn trusted_root(&self) -> &Arc<TrustedRoot> {
        &self.root
    }

    /// Verifies a bundle against a workflow identity and returns what it
    /// proves.
    ///
    /// `digest` is the SHA-256 that the statement must name, as hex in
    /// either case. In order:
    ///
    /// 1. `digest` decodes to 32 bytes;
    /// 2. the bundle decodes ([`Bundle::from_value`](crate::sigstore::bundle::Bundle::from_value))
    ///    and verifies as a Fulcio bundle for that digest
    ///    ([`verify_fulcio_bundle`](crate::sigstore::certificate::verify_fulcio_bundle));
    /// 3. the signing certificate's subject alternative name matches
    ///    `identity`, its OIDC issuer is
    ///    [`OIDC_ISSUER`](super::reference::OIDC_ISSUER), and its runner
    ///    environment is
    ///    [`GITHUB_HOSTED_RUNNER`](super::reference::GITHUB_HOSTED_RUNNER);
    /// 4. the subject rule. Without `subject_name`: the statement has a
    ///    subject, and the first subject's SHA-256 digest equals `digest`
    ///    ignoring case. With `subject_name`: exactly one subject has that
    ///    name, and every subject with that name has `digest` as its
    ///    SHA-256 digest, ignoring case.
    pub fn verify_bundle_for_subject(
        &self,
        bundle: &Value,
        identity: &WorkflowIdentity,
        digest: &str,
        subject_name: Option<&str>,
    ) -> Result<VerifiedBundle, EndorsementError> {
        pending("endorsement::provenance::ProvenanceClient::verify_bundle_for_subject")
    }

    /// Authenticates code provenance against a pinned reference.
    ///
    /// `tag` and `digest` are the document's hints; a tag or digest in
    /// `pin` takes precedence over them. In order:
    ///
    /// 1. the bundle verifies for the release identity of `pin.repo`
    ///    ([`WorkflowIdentity::tagged_release`]) and the digest, with the
    ///    first-subject rule
    ///    ([`ProvenanceClient::verify_bundle_for_subject`]);
    /// 2. the statement's predicate type is
    ///    [`MULTI_PLATFORM_PREDICATE_TYPE`]; the predicate has
    ///    `snp_measurement`, and `tdx_measurement` with `rtmr1` and
    ///    `rtmr2`, each a register in hex of either case;
    /// 3. the predicate has `vm_shape`, an object with `cpus`, `memory_mb`,
    ///    `gpus` and `disks`. Each is a JSON number that, read as a double,
    ///    is a whole number, not negative and below 2^63; `4.0` and `4e0`
    ///    therefore read as 4. Other members of `vm_shape` are ignored;
    /// 4. the release identity ([`authenticated_artifact`]) with the label
    ///    `code`.
    pub fn authenticate_code(
        &self,
        bundle: &Value,
        pin: &Reference,
        tag: &str,
        digest: &str,
    ) -> Result<Code, EndorsementError> {
        pending("endorsement::provenance::ProvenanceClient::authenticate_code")
    }

    /// Authenticates the platform policy artifact.
    ///
    /// `artifact_format` is chosen by the verification flow, not by the
    /// document. In order:
    ///
    /// 1. `artifact_format` is one of the two policy artifact formats
    ///    ([`ARTIFACT_FORMAT`](crate::policy::ARTIFACT_FORMAT),
    ///    [`ARTIFACT_FORMAT_V2`](crate::policy::ARTIFACT_FORMAT_V2));
    /// 2. `repo` is
    ///    [`PLATFORM_ENDORSEMENTS_REPO`](super::reference::PLATFORM_ENDORSEMENTS_REPO);
    /// 3. the bundle verifies for
    ///    [`WorkflowIdentity::platform_endorsements`] and `digest`, with
    ///    the first-subject rule;
    /// 4. the statement's predicate decodes as a policy artifact
    ///    ([`policy::parse_value`](crate::policy::parse_value)) from the
    ///    predicate as signed, so that every number keeps its literal;
    /// 5. the statement's predicate type and the artifact's format are both
    ///    `artifact_format`;
    /// 6. the release identity ([`authenticated_artifact`]) with the label
    ///    `platform endorsements`, where `tag` is the document's hint.
    pub fn authenticate_platform_endorsements(
        &self,
        bundle: &Value,
        repo: &str,
        tag: &str,
        digest: &str,
        artifact_format: &str,
    ) -> Result<PlatformEndorsements, EndorsementError> {
        pending("endorsement::provenance::ProvenanceClient::authenticate_platform_endorsements")
    }
}

/// Derives the release identity from a verified bundle.
///
/// `tag` is the expected tag, or empty to accept the tag that the
/// certificate names. In order:
///
/// 1. for the runtime repository
///    ([`RUNTIME_REPO`](crate::document::collateral::RUNTIME_REPO)), the
///    certificate's source repository identifier and owner identifier are
///    the pinned ones;
/// 2. the certificate's source repository ref starts with `refs/tags/`;
///    the rest is the authenticated tag, and equals `tag` when that is not
///    empty;
/// 3. the certificate's source repository digest is a Git commit
///    ([`is_git_commit`](super::reference::is_git_commit));
/// 4. the statement's first subject has a non-empty name.
///
/// The result carries `repo`, the authenticated tag, the commit, the first
/// subject's name and `digest` in lowercase.
pub fn authenticated_artifact(
    verified: &VerifiedBundle,
    repo: &str,
    tag: &str,
    digest: &str,
    label: &str,
) -> Result<AuthenticatedArtifact, EndorsementError> {
    pending("endorsement::provenance::authenticated_artifact")
}
