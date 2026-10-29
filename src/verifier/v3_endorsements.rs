//! Authentication of V3 documents carrying legacy release collateral.
//!
//! V3 is the envelope version; this module intentionally implements only the
//! legacy code/platform collateral format currently used by the pinned CLI.
//! Release selection belongs to the caller. No latest-release lookup occurs.

use super::{
    attestation::{
        sev,
        types::{Measurement, PredicateType},
    },
    sigstore::provided::{authenticate_bundle, is_lower_hex, AuthenticatedBundle, Statement},
    v3_document::{DecodedCollateral, SigstoreReference},
};
use crate::error::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_FRESHNESS_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const MAX_FUTURE_SKEW: u64 = 5 * 60;
const PLATFORM_FORMAT: &str = "https://tinfoil.sh/predicate/platform-endorsements/v1";
const FRESHNESS_FORMAT: &str = "https://tinfoil.sh/predicate/freshness-witness/v1";

/// Immutable release identity approved by the embedding application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRelease {
    pub repo: String,
    pub tag: String,
    /// Lowercase SHA-256 of the release artifact (without `sha256:`).
    pub digest: String,
}

impl PinnedRelease {
    pub(crate) fn validate(&self) -> Result<()> {
        if !valid_repo(&self.repo)
            || self.tag.is_empty()
            || self.tag.contains('@')
            || self.tag.bytes().any(|b| b.is_ascii_whitespace())
            || !is_lower_hex(&self.digest, 64)
        {
            return Err(failure("invalid pinned release repository/tag/digest"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedArtifact {
    pub repo: String,
    pub tag: String,
    pub commit: String,
    pub subject_name: String,
    pub digest: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VmShape {
    pub cpus: u64,
    pub memory_mb: u64,
    pub gpus: u64,
    pub disks: u64,
}

pub(crate) struct VerifiedRefs {
    pub measurement: Measurement,
    /// Entire strictly decoded, signed platform artifact. A machine policy may
    /// only be selected from this value; document hints are not a substitute.
    pub platform_artifact: Value,
    pub shape: VmShape,
    pub code_identity: AuthenticatedArtifact,
    pub platform_identity: AuthenticatedArtifact,
    pub freshness_expires_at: SystemTime,
}

pub(crate) fn authenticate_legacy_refs(
    collateral: &DecodedCollateral,
    approved: &PinnedRelease,
    now: SystemTime,
) -> Result<VerifiedRefs> {
    approved.validate()?;
    let code = collateral
        .sigstore_code
        .as_ref()
        .ok_or_else(|| failure("missing code collateral"))?;
    if code.repo != approved.repo || code.tag != approved.tag || code.digest != approved.digest {
        return Err(failure(
            "code collateral hints conflict with approved release",
        ));
    }
    let code_bundle = authenticate_bundle(
        &code.bundle,
        &approved.repo,
        &workflow_pattern(&approved.repo, r"[^/@]+", r"refs/tags/[^@]+"),
        &approved.digest,
    )?;
    let code_identity = artifact_identity(
        &code_bundle,
        &approved.repo,
        &approved.tag,
        &approved.digest,
    )?;
    let (measurement, shape) = code_measurement(&code_bundle.statement)?;

    let platform = collateral
        .sigstore_platform
        .as_ref()
        .ok_or_else(|| failure("missing platform collateral"))?;
    validate_platform_reference(platform)?;
    let platform_bundle = authenticate_bundle(
        &platform.bundle,
        "tinfoilsh/cvmimage",
        &workflow_pattern(
            "tinfoilsh/cvmimage",
            r"platform-release\.yml",
            r"refs/tags/platform-v[0-9][^@]*",
        ),
        &platform.digest,
    )?;
    let platform_identity = artifact_identity(
        &platform_bundle,
        "tinfoilsh/cvmimage",
        &platform.tag,
        &platform.digest,
    )?;
    if platform_bundle.statement.predicate_type != PLATFORM_FORMAT {
        return Err(failure(
            "platform predicate type is not legacy platform-endorsements/v1",
        ));
    }
    validate_platform_artifact(&platform_bundle.statement.predicate)?;

    let code_freshness = collateral
        .freshness
        .get("code-freshness")
        .ok_or_else(|| failure("missing code freshness witness"))?;
    let platform_freshness = collateral
        .freshness
        .get("platform-freshness")
        .ok_or_else(|| failure("missing platform freshness witness"))?;
    if [&code_freshness.format, &platform_freshness.format]
        .iter()
        .any(|f| f.as_str() != "https://tinfoil.sh/collateral/sigstore-freshness/v1")
    {
        return Err(failure("unsupported freshness collateral wrapper"));
    }
    // The collateral decoder checks the registered wrapper format; signatures
    // below authenticate its payload and bind the exact artifact identity.
    let code_logged = authenticate_freshness(&code_freshness.bundle, &code_identity, now)?;
    let platform_logged =
        authenticate_freshness(&platform_freshness.bundle, &platform_identity, now)?;
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(code_logged.min(platform_logged)))
        .and_then(|t| t.checked_add(MAX_FRESHNESS_AGE))
        .ok_or_else(|| failure("freshness expiry overflow"))?;
    Ok(VerifiedRefs {
        measurement,
        shape,
        platform_artifact: platform_bundle.statement.predicate,
        code_identity,
        platform_identity,
        freshness_expires_at: expiry,
    })
}

fn failure(message: impl Into<String>) -> Error {
    Error::SigstoreVerification(message.into())
}
fn valid_repo(repo: &str) -> bool {
    let pieces: Vec<_> = repo.split('/').collect();
    pieces.len() == 2
        && pieces.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
}
fn workflow_pattern(repo: &str, workflow: &str, git_ref: &str) -> String {
    format!(
        r"^https://github\.com/{}/\.github/workflows/{}@{}$",
        regex::escape(repo),
        workflow,
        git_ref
    )
}

fn artifact_identity(
    bundle: &AuthenticatedBundle,
    repo: &str,
    tag: &str,
    digest: &str,
) -> Result<AuthenticatedArtifact> {
    let authenticated_tag = bundle
        .identity
        .source_ref
        .strip_prefix("refs/tags/")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| failure("artifact source ref is not a tag"))?;
    if authenticated_tag != tag {
        return Err(failure("artifact source tag does not match approved tag"));
    }
    let name = &bundle
        .statement
        .subject
        .first()
        .ok_or_else(|| failure("missing artifact subject"))?
        .name;
    if name.is_empty() {
        return Err(failure("artifact subject is unnamed"));
    }
    Ok(AuthenticatedArtifact {
        repo: repo.into(),
        tag: authenticated_tag.into(),
        commit: bundle.identity.source_commit.clone(),
        subject_name: name.clone(),
        digest: digest.into(),
    })
}

fn code_measurement(statement: &Statement) -> Result<(Measurement, VmShape)> {
    if statement.predicate_type != "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1" {
        return Err(failure("unsupported code measurement predicate"));
    }
    let snp = statement.predicate["snp_measurement"]
        .as_str()
        .ok_or_else(|| failure("missing SNP measurement"))?;
    let rtmr1 = statement.predicate["tdx_measurement"]["rtmr1"]
        .as_str()
        .ok_or_else(|| failure("missing RTMR1"))?;
    let rtmr2 = statement.predicate["tdx_measurement"]["rtmr2"]
        .as_str()
        .ok_or_else(|| failure("missing RTMR2"))?;
    for value in [snp, rtmr1, rtmr2] {
        if !is_lower_hex(value, 96) {
            return Err(failure("malformed 48-byte code measurement"));
        }
    }
    let shape: VmShape = serde_json::from_value(statement.predicate["vm_shape"].clone())
        .map_err(|e| failure(format!("code VM shape: {e}")))?;
    if [shape.cpus, shape.memory_mb, shape.gpus, shape.disks]
        .iter()
        .any(|n| *n > i64::MAX as u64)
    {
        return Err(failure("code VM shape exceeds signed integer range"));
    }
    Ok((
        Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec![snp.into(), rtmr1.into(), rtmr2.into()],
        },
        shape,
    ))
}

fn validate_platform_reference(reference: &SigstoreReference) -> Result<()> {
    if reference.repo != "tinfoilsh/cvmimage"
        || !is_lower_hex(&reference.digest, 64)
        || !regex::Regex::new(r"^platform-v[0-9][^@]*$")
            .unwrap()
            .is_match(&reference.tag)
    {
        return Err(failure("invalid platform publisher/release reference"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessWitness {
    format: String,
    endorses: WitnessEndorsement,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessEndorsement {
    repo: String,
    tag: String,
    commit: String,
    subject: WitnessSubject,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSubject {
    name: String,
    digest: String,
}

fn authenticate_freshness(
    bundle: &Value,
    expected: &AuthenticatedArtifact,
    now: SystemTime,
) -> Result<u64> {
    let authenticated = authenticate_bundle(
        bundle,
        "tinfoilsh/freshness-witness",
        &workflow_pattern(
            "tinfoilsh/freshness-witness",
            r"freshness\.yml",
            r"refs/heads/main",
        ),
        &expected.digest,
    )?;
    validate_witness_statement(&authenticated.statement, expected)?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| failure("verification time predates Unix epoch"))?
        .as_secs();
    validate_freshness_time(authenticated.verified_tlog_time, now)?;
    Ok(authenticated.verified_tlog_time)
}

fn validate_witness_statement(
    statement: &Statement,
    expected: &AuthenticatedArtifact,
) -> Result<()> {
    if statement.statement_type != "https://in-toto.io/Statement/v1"
        || statement.predicate_type != FRESHNESS_FORMAT
        || statement.subject.len() != 1
        || statement.subject[0].name != expected.subject_name
        || statement.subject[0].digest.get("sha256") != Some(&expected.digest)
    {
        return Err(failure(
            "freshness statement does not match authenticated artifact",
        ));
    }
    let witness: FreshnessWitness = serde_json::from_value(statement.predicate.clone())
        .map_err(|e| failure(format!("freshness predicate: {e}")))?;
    let endorsed = witness.endorses;
    if witness.format != FRESHNESS_FORMAT
        || endorsed.repo != expected.repo
        || endorsed.tag != expected.tag
        || endorsed.commit != expected.commit
        || endorsed.subject.name != expected.subject_name
        || endorsed.subject.digest != format!("sha256:{}", expected.digest)
    {
        return Err(failure(
            "freshness witness identity does not match authenticated artifact",
        ));
    }
    Ok(())
}

fn validate_freshness_time(logged: u64, now: u64) -> Result<()> {
    if logged > now.saturating_add(MAX_FUTURE_SKEW) {
        return Err(failure("freshness witness timestamp is in the future"));
    }
    if now.saturating_sub(logged) > MAX_FRESHNESS_AGE.as_secs() {
        return Err(failure("freshness witness is stale"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformArtifact {
    format: String,
    #[serde(default)]
    measurements: BTreeMap<String, PlatformMeasurement>,
    #[serde(default)]
    machines: BTreeMap<String, String>,
    #[serde(default)]
    policies: BTreeMap<String, PlatformPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformMeasurement {
    mrtd: String,
    rtmr0: String,
    shape: PlatformShape,
    #[serde(default)]
    stack: Option<Stack>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformShape {
    cpus: u64,
    memory_mb: u64,
    #[serde(default)]
    gpus: Option<u64>,
    disks: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stack {
    #[serde(default)]
    qemu: String,
    #[serde(default)]
    ovmf: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlatformPolicy {
    platform: String,
    #[serde(default)]
    sev_snp: Option<Value>,
    #[serde(default)]
    tdx: Option<TdxPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TdxPolicy {
    qe_vendor_id: String,
    minimum_tee_tcb_svn: String,
    mr_seam: String,
    td_attributes: String,
    xfam: String,
    minimum_tcb_evaluation_data_number: u64,
    #[serde(default)]
    platform_measurements: Vec<String>,
}

fn validate_platform_artifact(value: &Value) -> Result<()> {
    let artifact: PlatformArtifact = serde_json::from_value(value.clone())
        .map_err(|e| failure(format!("platform artifact: {e}")))?;
    if artifact.format != PLATFORM_FORMAT {
        return Err(failure("unsupported platform artifact format"));
    }
    for policy in artifact.policies.values() {
        match policy.platform.as_str() {
            "sev-snp" if policy.sev_snp.is_some() && policy.tdx.is_none() => {
                let sev_policy = policy.sev_snp.as_ref().unwrap();
                if sev_policy["host_data"]
                    .as_str()
                    .is_none_or(|s| s.is_empty())
                {
                    return Err(failure("legacy SNP policy requires host_data"));
                }
                sev::validate_policy(sev_policy)?;
            }
            "tdx" if policy.tdx.is_some() && policy.sev_snp.is_none() => {
                let p = policy.tdx.as_ref().unwrap();
                for (name, v, n) in [
                    ("qe_vendor_id", &p.qe_vendor_id, 32),
                    ("minimum_tee_tcb_svn", &p.minimum_tee_tcb_svn, 32),
                    ("mr_seam", &p.mr_seam, 96),
                    ("td_attributes", &p.td_attributes, 16),
                    ("xfam", &p.xfam, 16),
                ] {
                    if !is_lower_hex(v, n) {
                        return Err(failure(format!("malformed TDX {name}")));
                    }
                }
                if p.minimum_tcb_evaluation_data_number > i64::MAX as u64
                    || p.platform_measurements.is_empty()
                {
                    return Err(failure(
                        "invalid legacy TDX minimum TCB or measurement references",
                    ));
                }
                for reference in &p.platform_measurements {
                    if !artifact.measurements.contains_key(reference) {
                        return Err(failure("dangling TDX platform measurement reference"));
                    }
                }
            }
            _ => {
                return Err(failure(
                    "platform policy requires exactly its recognized platform block",
                ))
            }
        }
    }
    for m in artifact.measurements.values() {
        if !is_lower_hex(&m.mrtd, 96)
            || !is_lower_hex(&m.rtmr0, 96)
            || [m.shape.cpus, m.shape.memory_mb, m.shape.disks]
                .iter()
                .any(|n| *n == 0 || *n > i64::MAX as u64)
            || m.shape.gpus.is_some_and(|n| n > i64::MAX as u64)
        {
            return Err(failure("invalid endorsed platform measurement or shape"));
        }
        // Stack is authenticated informational metadata, never an appraisal input.
        if let Some(stack) = &m.stack {
            let _ = (&stack.qemu, &stack.ovmf);
        }
    }
    for (machine, name) in &artifact.machines {
        let policy = artifact
            .policies
            .get(name)
            .ok_or_else(|| failure("machine references unknown policy"))?;
        let width = if policy.platform == "sev-snp" {
            128
        } else {
            32
        };
        if !is_lower_hex(machine, width) {
            return Err(failure("malformed machine identifier for platform"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn artifact() -> AuthenticatedArtifact {
        AuthenticatedArtifact {
            repo: "owner/repo".into(),
            tag: "v1".into(),
            commit: "a".repeat(40),
            subject_name: "manifest.json".into(),
            digest: "b".repeat(64),
        }
    }
    fn witness() -> Statement {
        let a = artifact();
        Statement {
            statement_type: "https://in-toto.io/Statement/v1".into(),
            predicate_type: FRESHNESS_FORMAT.into(),
            subject: vec![super::super::sigstore::provided::Subject {
                name: a.subject_name.clone(),
                digest: BTreeMap::from([("sha256".into(), a.digest.clone())]),
            }],
            predicate: serde_json::json!({"format":FRESHNESS_FORMAT,"endorses":{"repo":a.repo,"tag":a.tag,"commit":a.commit,
                "subject":{"name":a.subject_name,"digest":format!("sha256:{}",a.digest)}}}),
        }
    }
    #[test]
    fn freshness_matches_all_authenticated_identity_components() {
        let a = artifact();
        assert!(validate_witness_statement(&witness(), &a).is_ok());
        for field in ["repo", "tag", "commit"] {
            let mut wrong = witness();
            wrong.predicate["endorses"][field] = Value::String("wrong".into());
            assert!(validate_witness_statement(&wrong, &a).is_err(), "{field}");
        }
        for field in ["name", "digest"] {
            let mut wrong = witness();
            wrong.predicate["endorses"]["subject"][field] = Value::String("wrong".into());
            assert!(validate_witness_statement(&wrong, &a).is_err(), "{field}");
        }
        let mut wrong = witness();
        wrong.subject[0]
            .digest
            .insert("sha256".into(), "c".repeat(64));
        assert!(validate_witness_statement(&wrong, &a).is_err());
        let mut wrong = witness();
        wrong.predicate["unexpected"] = Value::Bool(true);
        assert!(validate_witness_statement(&wrong, &a).is_err());
    }
    #[test]
    fn freshness_age_and_future_skew_are_bounded() {
        let now = 2_000_000;
        let age = MAX_FRESHNESS_AGE.as_secs();
        assert!(validate_freshness_time(now - age, now).is_ok());
        assert!(validate_freshness_time(now - age - 1, now).is_err());
        assert!(validate_freshness_time(now + MAX_FUTURE_SKEW, now).is_ok());
        assert!(validate_freshness_time(now + MAX_FUTURE_SKEW + 1, now).is_err());
    }
    #[test]
    fn platform_rejects_unknown_members_and_machine_policy_substitution() {
        let empty = serde_json::json!({"format":PLATFORM_FORMAT,"machines":{},"policies":{}});
        assert!(validate_platform_artifact(&empty).is_ok());
        let mut wrong = empty.clone();
        wrong["unsigned_hint"] = Value::Bool(true);
        assert!(validate_platform_artifact(&wrong).is_err());
        let mut wrong = empty.clone();
        wrong["machines"]["a".repeat(128)] = "unendorsed".into();
        assert!(validate_platform_artifact(&wrong).is_err());
        let mut wrong = empty;
        wrong["format"] = "https://tinfoil.sh/predicate/platform-endorsements/v2".into();
        assert!(validate_platform_artifact(&wrong).is_err());
    }
    #[test]
    fn pins_require_exact_lowercase_digest() {
        let mut p = PinnedRelease {
            repo: "owner/repo".into(),
            tag: "v1".into(),
            digest: "a".repeat(64),
        };
        assert!(p.validate().is_ok());
        p.digest = "A".repeat(64);
        assert!(p.validate().is_err());
    }
}
