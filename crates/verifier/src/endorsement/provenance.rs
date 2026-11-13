//! Build provenance: Sigstore bundles signed by pinned GitHub Actions
//! workflow identities.

use std::sync::Arc;

use super::EndorsementError;
use super::reference::{
    AuthenticatedArtifact, GITHUB_HOSTED_RUNNER, OIDC_ISSUER, PLATFORM_ENDORSEMENTS_REPO,
    RUNTIME_REPOSITORY_ID, Reference, TINFOIL_ORGANIZATION_ID, WorkflowIdentity, is_git_commit,
};
use crate::canonical::decode_hex;
use crate::document::collateral::RUNTIME_REPO;
use crate::json::{self, Object, Value};
use crate::measurement::{Expected, Register};
use crate::policy::{self, ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, Artifact, Shape};
use crate::sigstore::bundle::Bundle;
use crate::sigstore::certificate::{VerifiedBundle, verify_fulcio_bundle};
use crate::sigstore::statement::{DIGEST_ALGORITHM, Statement};
use crate::sigstore::trusted_root::TrustedRoot;

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

    /// A client that trusts a trusted root that is already decoded.
    pub fn with_trusted_root(root: Arc<TrustedRoot>) -> Self {
        Self { root }
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
    /// 1. the bundle decodes
    ///    ([`Bundle::from_value`](crate::sigstore::bundle::Bundle::from_value));
    /// 2. `digest` decodes to 32 bytes;
    /// 3. the bundle verifies as a Fulcio bundle for that digest
    ///    ([`verify_fulcio_bundle`]);
    /// 4. the signing certificate's subject alternative name matches
    ///    `identity`, its OIDC issuer is
    ///    [`OIDC_ISSUER`], and its runner
    ///    environment is
    ///    [`GITHUB_HOSTED_RUNNER`];
    /// 5. the subject rule. Without `subject_name`: the statement has a
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
        let bundle = Bundle::from_value(bundle).map_err(|cause| cause.within("parsing bundle"))?;
        let digest_bytes: [u8; 32] = decode_hex(digest)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| EndorsementError::new("decoding hex digest: want a SHA-256 in hex"))?;
        let verified = verify_fulcio_bundle(&self.root, &bundle, &digest_bytes)
            .map_err(|cause| cause.within("verifying"))?;

        let signer = &verified.identity;
        if !identity.matches(&signer.subject_alternative_name) {
            return Err(EndorsementError::new(format!(
                "verifying: signing certificate identity {:?} is not the expected workflow",
                signer.subject_alternative_name
            )));
        }
        if signer.extensions.issuer != OIDC_ISSUER {
            return Err(EndorsementError::new(format!(
                "verifying: expected issuer value {OIDC_ISSUER:?}, got {:?}",
                signer.extensions.issuer
            )));
        }
        if signer.extensions.runner_environment != GITHUB_HOSTED_RUNNER {
            return Err(EndorsementError::new(format!(
                "verifying: expected runner environment {GITHUB_HOSTED_RUNNER:?}, got {:?}",
                signer.extensions.runner_environment
            )));
        }

        match subject_name {
            None => check_first_subject(&verified.statement, digest)?,
            Some(name) => check_named_subject(&verified.statement, name, digest)?,
        }
        Ok(verified)
    }

    /// Authenticates code provenance against a pinned reference.
    ///
    /// `tag` and `digest` are the document's hints; a tag or digest in
    /// `pin` takes precedence over them. In order:
    ///
    /// 1. `pin.repo` is a repository slug
    ///    ([`WorkflowIdentity::tagged_release`]);
    /// 2. the bundle verifies for the release identity of `pin.repo` and
    ///    the digest, with the first-subject rule
    ///    ([`ProvenanceClient::verify_bundle_for_subject`]);
    /// 3. the statement's predicate type is
    ///    [`MULTI_PLATFORM_PREDICATE_TYPE`]; the predicate has
    ///    `snp_measurement`, and `tdx_measurement`, an object with `rtmr1`
    ///    and `rtmr2`; each of the three is a string of 96 hex digits in
    ///    either case;
    /// 4. the predicate has `vm_shape`, an object with `cpus`, `memory_mb`,
    ///    `gpus` and `disks`. Each is a JSON number that, read as a double,
    ///    is a whole number, not negative and below 2^63; `4.0`, `4e0` and
    ///    `-0` therefore read as whole numbers, and an integer literal
    ///    above 2^53 reads as the nearest double. Other members of
    ///    `vm_shape` and of the predicate are ignored;
    /// 5. the release identity ([`authenticated_artifact`]) with the label
    ///    `code`.
    pub fn authenticate_code(
        &self,
        bundle: &Value,
        pin: &Reference,
        tag: &str,
        digest: &str,
    ) -> Result<Code, EndorsementError> {
        let repo = pin.repo.as_str();
        let tag = pinned(&pin.tag).unwrap_or(tag);
        let digest = pinned(&pin.digest).unwrap_or(digest);
        let identity = WorkflowIdentity::tagged_release(repo)
            .map_err(|cause| cause.within("verifying bundle"))?;
        let verified = self
            .verify_bundle_for_subject(bundle, &identity, digest, None)
            .map_err(|cause| cause.within("verifying bundle"))?;
        let (sev_snp_launch, tdx_rtmr1, tdx_rtmr2) =
            measurements_from_statement(&verified.statement)
                .map_err(|cause| cause.within("code predicate"))?;
        let shape = shape_from_predicate(&verified.statement.predicate)
            .map_err(|cause| cause.within("code predicate"))?;
        let artifact = authenticated_artifact(&verified, repo, tag, digest, "code")?;
        Ok(Code {
            artifact,
            sev_snp_launch,
            tdx_rtmr1,
            tdx_rtmr2,
            shape,
        })
    }

    /// Authenticates the platform policy artifact.
    ///
    /// `artifact_format` is chosen by the verification flow, not by the
    /// document. In order:
    ///
    /// 1. `artifact_format` is one of the two policy artifact formats
    ///    ([`ARTIFACT_FORMAT`],
    ///    [`ARTIFACT_FORMAT_V2`]);
    /// 2. `repo` is
    ///    [`PLATFORM_ENDORSEMENTS_REPO`];
    /// 3. the bundle verifies for
    ///    [`WorkflowIdentity::platform_endorsements`] and `digest`, with
    ///    the first-subject rule;
    /// 4. the signed payload has a `predicate` member that is an object,
    ///    and it decodes as a policy artifact
    ///    ([`policy::parse_value`]) from the
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
        if artifact_format != ARTIFACT_FORMAT && artifact_format != ARTIFACT_FORMAT_V2 {
            return Err(EndorsementError::new(format!(
                "unsupported platform artifact format {artifact_format:?}"
            )));
        }
        if repo != PLATFORM_ENDORSEMENTS_REPO {
            return Err(EndorsementError::new(format!(
                "platform endorsements repo {repo:?} does not equal {PLATFORM_ENDORSEMENTS_REPO:?}"
            )));
        }
        let verified = self
            .verify_bundle_for_subject(
                bundle,
                &WorkflowIdentity::platform_endorsements(),
                digest,
                None,
            )
            .map_err(|cause| cause.within("verifying platform endorsements bundle"))?;
        let predicate = signed_predicate(&verified.payload)
            .map_err(|cause| cause.within("platform endorsements statement"))?;
        let policy = policy::parse_value(predicate)?;
        if verified.statement.predicate_type != artifact_format || policy.format != artifact_format
        {
            return Err(EndorsementError::new(format!(
                "platform predicate and artifact must use {artifact_format:?}"
            )));
        }
        let artifact =
            authenticated_artifact(&verified, repo, tag, digest, "platform endorsements")?;
        Ok(PlatformEndorsements { artifact, policy })
    }
}

/// The pinned part of a reference; an empty one pins nothing.
fn pinned(pin: &Option<String>) -> Option<&str> {
    pin.as_deref().filter(|pin| !pin.is_empty())
}

/// The first-subject rule: the statement has a subject, and the first one
/// names `digest` as its SHA-256, in hex of either case.
fn check_first_subject(statement: &Statement, digest: &str) -> Result<(), EndorsementError> {
    let Some(subject) = statement.subjects.first() else {
        return Err(EndorsementError::new("in-toto statement has no subject"));
    };
    let stated = subject
        .digest
        .get(DIGEST_ALGORITHM)
        .map(String::as_str)
        .unwrap_or_default();
    if !stated.eq_ignore_ascii_case(digest) {
        return Err(EndorsementError::new(format!(
            "subject[0] digest {stated:?} does not match expected artifact digest {digest:?}"
        )));
    }
    Ok(())
}

/// The named-subject rule: exactly one subject is called `name`, and every
/// subject of that name has `digest` as its SHA-256, in hex of either case.
fn check_named_subject(
    statement: &Statement,
    name: &str,
    digest: &str,
) -> Result<(), EndorsementError> {
    let mut matches = 0usize;
    for subject in statement
        .subjects
        .iter()
        .filter(|subject| subject.name == name)
    {
        let stated = subject
            .digest
            .get(DIGEST_ALGORITHM)
            .map(String::as_str)
            .unwrap_or_default();
        if !stated.eq_ignore_ascii_case(digest) {
            return Err(EndorsementError::new(
                "runtime provenance subject digest does not match",
            ));
        }
        matches = matches.saturating_add(1);
    }
    if matches != 1 {
        return Err(EndorsementError::new(
            "runtime provenance requires exactly one matching manifest subject",
        ));
    }
    Ok(())
}

/// The registers that a code release fixes: the SEV-SNP launch
/// measurement, then the TDX RTMR1 and RTMR2.
fn measurements_from_statement(
    statement: &Statement,
) -> Result<(Register, Register, Register), EndorsementError> {
    let invalid =
        |what: String| EndorsementError::new(format!("invalid multiplatform measurement: {what}"));
    if statement.predicate_type != MULTI_PLATFORM_PREDICATE_TYPE {
        return Err(EndorsementError::new(format!(
            "unsupported predicate type: {}",
            statement.predicate_type
        )));
    }
    let empty = Object::default();
    let predicate = statement.predicate.as_object().unwrap_or(&empty);
    let Some(tdx) = predicate.get("tdx_measurement") else {
        return Err(invalid("no tdx measurement".to_string()));
    };
    let Some(rtmrs) = tdx.as_object() else {
        return Err(invalid("tdx measurement is not a struct".to_string()));
    };
    let Some(launch) = predicate.get("snp_measurement") else {
        return Err(invalid("no snp measurement".to_string()));
    };
    let (Some(rtmr1), Some(rtmr2)) = (rtmrs.get("rtmr1"), rtmrs.get("rtmr2")) else {
        let missing = if rtmrs.get("rtmr1").is_none() {
            "rtmr1"
        } else {
            "rtmr2"
        };
        return Err(invalid(format!("no {missing}")));
    };
    // A value that is not a string reads as the empty string, which is not
    // a register.
    let register = |name: &str, value: &Value| {
        value
            .as_str()
            .unwrap_or_default()
            .parse::<Register>()
            .map_err(|cause| invalid(format!("{name}: {cause}")))
    };
    Ok((
        register("snp measurement", launch)?,
        register("rtmr1", rtmr1)?,
        register("rtmr2", rtmr2)?,
    ))
}

/// Two to the power of 63 as a double: the first whole number that a
/// signed 64-bit integer cannot hold.
const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;

/// The VM shape that a code predicate declares.
fn shape_from_predicate(predicate: &Value) -> Result<Shape, EndorsementError> {
    let Some(shape) = predicate
        .as_object()
        .and_then(|predicate| predicate.get("vm_shape"))
    else {
        return Err(EndorsementError::new("code predicate declares no vm_shape"));
    };
    let Some(shape) = shape.as_object() else {
        return Err(EndorsementError::new("vm_shape is not an object"));
    };
    let member = |name: &str| -> Result<i64, EndorsementError> {
        let Some(value) = shape.get(name) else {
            return Err(EndorsementError::new(format!(
                "vm_shape is missing {name:?}"
            )));
        };
        value
            .as_number()
            .and_then(|number| number.as_str().parse::<f64>().ok())
            .and_then(whole_number)
            .ok_or_else(|| {
                EndorsementError::new(format!(
                    "vm_shape member {name:?} is not a non-negative integer"
                ))
            })
    };
    Ok(Shape {
        cpus: member("cpus")?,
        memory_mb: member("memory_mb")?,
        gpus: Some(member("gpus")?),
        disks: member("disks")?,
    })
}

/// The integer that a double stands for, when it is a whole number that is
/// not negative and is below 2^63. Negative zero is zero.
fn whole_number(double: f64) -> Option<i64> {
    let acceptable =
        double.is_finite() && double >= 0.0 && double.fract() == 0.0 && double < TWO_POW_63;
    // The conversion is exact: the value is a whole number within range.
    acceptable.then_some(double as i64)
}

/// The `predicate` member of a signed statement, as signed: an object whose
/// numbers keep their literals.
fn signed_predicate(payload: &[u8]) -> Result<Value, EndorsementError> {
    let statement =
        json::parse(payload).map_err(|cause| EndorsementError::new(format!("parsing: {cause}")))?;
    let mut statement = statement;
    let members = match &mut statement {
        Value::Object(object) => std::mem::take(object).into_members(),
        _ => Vec::new(),
    };
    members
        .into_iter()
        .find(|(name, _)| name == "predicate")
        .map(|(_, predicate)| predicate)
        .filter(|predicate| predicate.as_object().is_some())
        .ok_or_else(|| EndorsementError::new("predicate is not an object"))
}

/// Derives the release identity from a verified bundle.
///
/// `tag` is the expected tag, or empty to accept the tag that the
/// certificate names. In order:
///
/// 1. for the runtime repository
///    ([`RUNTIME_REPO`]), the
///    certificate's source repository identifier and owner identifier are
///    the pinned ones;
/// 2. the certificate's source repository ref starts with `refs/tags/`;
///    the rest is the authenticated tag, and equals `tag` when that is not
///    empty;
/// 3. the certificate's source repository digest is a Git commit
///    ([`is_git_commit`]);
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
    const TAG_REF_PREFIX: &str = "refs/tags/";
    let claims = &verified.identity.extensions;
    if repo == RUNTIME_REPO {
        if claims.source_repository_identifier != RUNTIME_REPOSITORY_ID {
            return Err(EndorsementError::new(format!(
                "{label} source repository ID does not match the pinned repository"
            )));
        }
        if claims.source_repository_owner_identifier != TINFOIL_ORGANIZATION_ID {
            return Err(EndorsementError::new(format!(
                "{label} source repository owner ID does not match the pinned organization"
            )));
        }
    }
    let source_ref = claims.source_repository_ref.as_str();
    let Some(authenticated_tag) = source_ref.strip_prefix(TAG_REF_PREFIX) else {
        return Err(EndorsementError::new(format!(
            "{label} source ref {source_ref:?} is not a tag"
        )));
    };
    if !tag.is_empty() && authenticated_tag != tag {
        return Err(EndorsementError::new(format!(
            "{label} source ref {source_ref:?} does not match tag {tag:?}"
        )));
    }
    let commit = claims.source_repository_digest.as_str();
    if !is_git_commit(commit) {
        return Err(EndorsementError::new(format!(
            "{label} source digest is not a lowercase Git commit"
        )));
    }
    let Some(subject_name) = verified
        .statement
        .subjects
        .first()
        .map(|subject| subject.name.as_str())
        .filter(|name| !name.is_empty())
    else {
        return Err(EndorsementError::new(format!(
            "{label} statement has no named subject"
        )));
    };
    Ok(AuthenticatedArtifact {
        repo: repo.to_string(),
        tag: authenticated_tag.to_string(),
        commit: commit.to_string(),
        subject_name: subject_name.to_string(),
        digest: digest.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::statement::Subject;

    fn statement(predicate_type: &str, subjects: Vec<Subject>, predicate: &str) -> Statement {
        Statement {
            statement_type: String::new(),
            subjects,
            predicate_type: predicate_type.to_string(),
            predicate: json::parse(predicate.as_bytes()).unwrap(),
        }
    }

    fn subject(name: &str, digest: &str) -> Subject {
        Subject {
            name: name.to_string(),
            digest: [(DIGEST_ALGORITHM.to_string(), digest.to_string())].into(),
        }
    }

    fn code_predicate(launch: &str, rtmr1: &str, rtmr2: &str) -> String {
        format!(
            r#"{{"snp_measurement":"{launch}","tdx_measurement":{{"rtmr1":"{rtmr1}","rtmr2":"{rtmr2}"}}}}"#
        )
    }

    #[test]
    fn a_code_predicate_fixes_three_registers() {
        let (launch, rtmr1, rtmr2) = ("aa".repeat(48), "bb".repeat(48), "CC".repeat(48));
        let read = |predicate: &str| {
            measurements_from_statement(&statement(
                MULTI_PLATFORM_PREDICATE_TYPE,
                Vec::new(),
                predicate,
            ))
        };
        let registers = read(&code_predicate(&launch, &rtmr1, &rtmr2)).unwrap();
        assert_eq!(registers.0.to_string(), launch);
        assert_eq!(registers.1.to_string(), rtmr1);
        assert_eq!(registers.2.to_string(), rtmr2.to_lowercase());

        for (name, predicate) in [
            ("short launch", code_predicate("abcd", &rtmr1, &rtmr2)),
            (
                "non-hex rtmr1",
                code_predicate(&launch, &"zz".repeat(48), &rtmr2),
            ),
            ("empty rtmr2", code_predicate(&launch, &rtmr1, "")),
            ("no registers", "{}".to_string()),
            (
                "registers that are not an object",
                format!(r#"{{"snp_measurement":"{launch}","tdx_measurement":[]}}"#),
            ),
            (
                "a launch that is not a string",
                format!(
                    r#"{{"snp_measurement":null,"tdx_measurement":{{"rtmr1":"{rtmr1}","rtmr2":"{rtmr2}"}}}}"#
                ),
            ),
        ] {
            let error = read(&predicate).unwrap_err().to_string();
            assert!(
                error.contains("invalid multiplatform measurement"),
                "{name}: {error}"
            );
        }

        let other = statement(
            "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            Vec::new(),
            &code_predicate(&launch, &rtmr1, &rtmr2),
        );
        let error = measurements_from_statement(&other).unwrap_err().to_string();
        assert!(error.contains("unsupported predicate type"), "{error}");
    }

    #[test]
    fn a_shape_is_read_as_doubles_that_are_whole() {
        let read = |shape: &str| {
            let predicate = json::parse(format!(r#"{{"vm_shape":{shape}}}"#).as_bytes()).unwrap();
            shape_from_predicate(&predicate)
        };
        let shape =
            read(r#"{"cpus":8,"memory_mb":3.2768e4,"gpus":-0,"disks":2.0,"extra":"x"}"#).unwrap();
        assert_eq!(
            shape,
            Shape {
                cpus: 8,
                memory_mb: 32768,
                gpus: Some(0),
                disks: 2
            }
        );
        // An integer that no double holds exactly reads as the nearest one.
        let shape =
            read(r#"{"cpus":9007199254740993,"memory_mb":1e18,"gpus":0,"disks":1}"#).unwrap();
        assert_eq!(shape.cpus, 9_007_199_254_740_992);
        assert_eq!(shape.memory_mb, 1_000_000_000_000_000_000);

        for rejected in [
            r#"{"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":-1,"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":1.5,"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":"8","memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":null,"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":9223372036854775808,"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":9223372036854775807,"memory_mb":1,"gpus":1,"disks":1}"#,
            r#"{"cpus":1e400,"memory_mb":1,"gpus":1,"disks":1}"#,
            "[]",
            "null",
            "4",
        ] {
            assert!(read(rejected).is_err(), "{rejected}");
        }
        let none = json::parse(b"{}").unwrap();
        assert!(shape_from_predicate(&none).is_err());
    }

    #[test]
    fn the_first_subject_names_the_digest_in_either_case() {
        let digest = "ab".repeat(32);
        let other = "cd".repeat(32);
        let check = |subjects: Vec<Subject>, digest: &str| {
            check_first_subject(&statement("", subjects, "{}"), digest)
        };
        assert!(check(vec![subject("a", &digest)], &digest).is_ok());
        assert!(check(vec![subject("a", &digest)], &digest.to_uppercase()).is_ok());
        assert!(check(vec![subject("a", &digest.to_uppercase())], &digest).is_ok());
        assert!(check(vec![subject("a", &digest), subject("b", &other)], &digest).is_ok());
        assert!(check(vec![subject("b", &other), subject("a", &digest)], &digest).is_err());
        assert!(check(vec![subject("a", &digest)], &"ff".repeat(32)).is_err());
        assert!(check(Vec::new(), &digest).is_err());
    }

    #[test]
    fn a_named_subject_is_unique_and_names_the_digest() {
        const NAME: &str = "tinfoil-inference-v0.15.0-manifest.json";
        let digest = "ab".repeat(32);
        let matching = || subject(NAME, &digest);
        let other = || subject("other-artifact", &"cd".repeat(32));
        let check = |subjects: Vec<Subject>| {
            check_named_subject(&statement("", subjects, "{}"), NAME, &digest)
        };
        assert!(check(vec![other(), matching()]).is_ok());
        assert!(check(vec![subject(NAME, &digest.to_uppercase())]).is_ok());
        for (name, subjects) in [
            ("missing", vec![other()]),
            ("duplicate", vec![matching(), matching()]),
            ("wrong digest", vec![subject(NAME, &"cd".repeat(32))]),
            (
                "one right and one wrong",
                vec![matching(), subject(NAME, &"cd".repeat(32))],
            ),
            ("none", Vec::new()),
        ] {
            assert!(check(subjects).is_err(), "{name}");
        }
        // The first-subject rule is not satisfied by a later subject.
        assert!(
            check_first_subject(&statement("", vec![other(), matching()], "{}"), &digest).is_err()
        );
    }

    #[test]
    fn a_signed_predicate_keeps_its_literals() {
        let payload = |predicate: &str| {
            format!(r#"{{"_type":"t","subject":[],"predicateType":"t","predicate":{predicate}}}"#)
        };
        let predicate =
            signed_predicate(payload(r#"{"vector":9223372036854775809,"build":21.0}"#).as_bytes())
                .unwrap();
        let members = predicate.as_object().unwrap();
        let literal = |name: &str| members.get(name).unwrap().as_number().unwrap().as_str();
        assert_eq!(literal("vector"), "9223372036854775809");
        assert_eq!(literal("build"), "21.0");

        for rejected in [
            r#"{"_type":"t","subject":[],"predicateType":"t"}"#.to_string(),
            payload("null"),
            payload("[]"),
            payload(r#""x""#),
            "{".to_string(),
            "null".to_string(),
        ] {
            assert!(signed_predicate(rejected.as_bytes()).is_err(), "{rejected}");
        }
    }

    #[test]
    fn the_platform_flow_and_repository_are_checked_before_the_bundle() {
        let client = ProvenanceClient::embedded().unwrap();
        let digest = "a".repeat(64);
        for (repo, format) in [
            ("tinfoilsh/platform-endorsements", ARTIFACT_FORMAT_V2),
            ("tinfoilsh/platform-endorsements", ARTIFACT_FORMAT),
            (PLATFORM_ENDORSEMENTS_REPO, "unsupported"),
        ] {
            let error = client
                .authenticate_platform_endorsements(
                    &Value::Null,
                    repo,
                    "platform-v1.2.3",
                    &digest,
                    format,
                )
                .unwrap_err()
                .to_string();
            assert!(!error.contains("parsing bundle"), "{error}");
        }
        let error = client
            .authenticate_platform_endorsements(
                &Value::Null,
                PLATFORM_ENDORSEMENTS_REPO,
                "platform-v1.2.3",
                &digest,
                ARTIFACT_FORMAT,
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains("parsing bundle"), "{error}");
    }

    #[test]
    fn a_code_pin_needs_a_repository_name() {
        let client = ProvenanceClient::embedded().unwrap();
        for repo in ["", "noslash", "a/b/c", "a/(b|c)"] {
            let pin = Reference {
                repo: repo.to_string(),
                tag: None,
                digest: None,
            };
            let error = client
                .authenticate_code(&Value::Null, &pin, "v1", &"a".repeat(64))
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid repository name"), "{repo}: {error}");
        }
    }
}
