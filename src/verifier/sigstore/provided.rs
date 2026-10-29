//! Offline verification of document-carried Sigstore bundles.
//!
//! Mirrors the certificate/DSSE/SCT/Rekor policy used by the pinned Go SDK.
//! Nothing in this module fetches a latest release or network trust material.

use std::collections::{BTreeMap, HashSet};

use der::Decode;
use serde::Deserialize;
use serde_json::Value;
use x509_cert::{
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

use super::{certificate, dsse, fulcio, rekor};
use crate::error::{Error, Result};
use crate::verifier::{util::decode_b64, v3_document::parse_strict_json};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Statement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub predicate_type: String,
    pub predicate: Value,
    pub subject: Vec<Subject>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub(crate) struct SourceIdentity {
    pub issuer: String,
    pub workflow: String,
    pub repository: String,
    pub source_ref: String,
    pub source_commit: String,
    pub runner_environment: String,
    pub repository_identifier: String,
    pub owner_identifier: String,
}

#[derive(Debug)]
pub(crate) struct AuthenticatedBundle {
    pub statement: Statement,
    pub identity: SourceIdentity,
    pub verified_tlog_time: u64,
}

/// Authenticate exactly these supplied bytes, including an authenticated Rekor
/// observer timestamp. The subject digest check uses subject[0], like Go.
pub(crate) fn authenticate_bundle(
    bundle: &Value,
    repo: &str,
    workflow_pattern: &str,
    expected_digest: &str,
) -> Result<AuthenticatedBundle> {
    validate_bundle_shape(bundle)?;
    let (cert_der, not_before, not_after) = super::extract_cert_with_validity(bundle)?;
    let cert =
        Certificate::from_der(&cert_der).map_err(|e| failure(format!("certificate: {e}")))?;
    let identity = extract_identity(&cert)?;
    validate_identity(&identity, repo, workflow_pattern)?;
    dsse::verify_dsse_signature(bundle)?;
    fulcio::verify_fulcio_chain(&cert_der, not_before)?;
    let verified_tlog_time = rekor::verify_rekor_timestamp(bundle, not_before, not_after)?;
    let envelope = &bundle["dsseEnvelope"];
    if envelope["payloadType"].as_str() != Some("application/vnd.in-toto+json") {
        return Err(failure("unsupported DSSE payload type"));
    }
    let payload = decode_b64(
        envelope["payload"]
            .as_str()
            .ok_or_else(|| failure("missing payload"))?,
    )
    .map_err(|e| failure(format!("payload base64: {e}")))?;
    let value = parse_strict_json(&payload)?;
    let statement: Statement =
        serde_json::from_value(value).map_err(|e| failure(format!("in-toto statement: {e}")))?;
    if statement.statement_type != "https://in-toto.io/Statement/v1"
        && statement.statement_type != "https://in-toto.io/Statement/v0.1"
    {
        return Err(failure("unsupported in-toto statement type"));
    }
    let subject = statement
        .subject
        .first()
        .ok_or_else(|| failure("missing in-toto subject"))?;
    if !subject
        .digest
        .get("sha256")
        .is_some_and(|d| d.eq_ignore_ascii_case(expected_digest))
    {
        return Err(failure("subject[0] sha256 does not match approved digest"));
    }
    Ok(AuthenticatedBundle {
        statement,
        identity,
        verified_tlog_time,
    })
}

fn failure(message: impl Into<String>) -> Error {
    Error::SigstoreVerification(message.into())
}

fn extract_identity(cert: &Certificate) -> Result<SourceIdentity> {
    let mut fields = BTreeMap::new();
    let mut seen = HashSet::new();
    for ext in cert.tbs_certificate.extensions.iter().flatten() {
        let oid = ext.extn_id.to_string();
        if !seen.insert(oid.clone()) {
            return Err(failure("duplicate certificate extension"));
        }
        if oid.starts_with("1.3.6.1.4.1.57264.1.") {
            let value = certificate::decode_asn1_string(ext.extn_value.as_bytes())
                .ok_or_else(|| failure("invalid Fulcio identity extension"))?;
            fields.insert(oid, value);
        }
    }
    let required = |suffix: &str| -> Result<String> {
        fields
            .get(&format!("1.3.6.1.4.1.57264.1.{suffix}"))
            .filter(|s| !s.is_empty())
            .cloned()
            .ok_or_else(|| failure(format!("missing Fulcio identity extension {suffix}")))
    };
    let (_, names) = cert
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|e| failure(format!("certificate SAN: {e}")))?
        .ok_or_else(|| failure("missing certificate SAN"))?;
    let uris: Vec<_> = names
        .0
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str()),
            _ => None,
        })
        .collect();
    if uris.len() != 1 {
        return Err(failure("GitHub signer requires one unambiguous URI SAN"));
    }
    Ok(SourceIdentity {
        issuer: required("8")?,
        workflow: uris[0].to_owned(),
        runner_environment: required("11")?,
        repository: required("12")?,
        source_commit: required("13")?,
        source_ref: required("14")?,
        repository_identifier: fields
            .get("1.3.6.1.4.1.57264.1.15")
            .cloned()
            .unwrap_or_default(),
        owner_identifier: fields
            .get("1.3.6.1.4.1.57264.1.17")
            .cloned()
            .unwrap_or_default(),
    })
}

pub(crate) fn validate_identity(
    identity: &SourceIdentity,
    repo: &str,
    pattern: &str,
) -> Result<()> {
    let signer =
        regex::Regex::new(pattern).map_err(|e| failure(format!("identity pattern: {e}")))?;
    if identity.issuer != "https://token.actions.githubusercontent.com"
        || identity.runner_environment != "github-hosted"
        || identity.repository != format!("https://github.com/{repo}")
        || !signer.is_match(&identity.workflow)
        || !identity
            .workflow
            .ends_with(&format!("@{}", identity.source_ref))
    {
        return Err(failure(
            "GitHub hosted workflow/source identity does not match policy",
        ));
    }
    if !is_lower_hex(&identity.source_commit, 40) {
        return Err(failure("source digest is not a lowercase Git commit"));
    }
    // The platform publisher's stable GitHub IDs prevent slug-reuse attacks.
    if repo == "tinfoilsh/cvmimage"
        && (identity.repository_identifier != "902195777"
            || identity.owner_identifier != "168487856")
    {
        return Err(failure(
            "platform source repository/owner identifier does not match policy",
        ));
    }
    Ok(())
}

pub(crate) fn is_lower_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Strict protobuf-JSON subset emitted by the v0.3 DSSE bundles Tinfoil uses.
/// An unsupported future or legacy layout fails closed instead of being
/// partially interpreted. Crypto verification still uses the original value.
#[allow(dead_code)]
fn validate_bundle_shape(bundle: &Value) -> Result<()> {
    if let Some(timestamp_data) = bundle
        .get("verificationMaterial")
        .and_then(|material| material.get("timestampVerificationData"))
    {
        if !timestamp_data
            .as_object()
            .is_some_and(|data| data.is_empty())
        {
            return Err(failure(
                "only an empty timestampVerificationData object is supported",
            ));
        }
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Bundle {
        media_type: String,
        verification_material: Material,
        dsse_envelope: Envelope,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Material {
        certificate: Raw,
        tlog_entries: Vec<Entry>,
        // Protobuf JSON emits this empty optional message on current Tinfoil
        // bundles. We use Rekor SET observer times; RFC 3161 timestamps are
        // intentionally unsupported, so only the empty container is accepted.
        #[serde(default)]
        timestamp_verification_data: Option<EmptyTimestampData>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EmptyTimestampData {}
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Raw {
        raw_bytes: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Envelope {
        payload_type: String,
        payload: String,
        signatures: Vec<Signature>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Signature {
        sig: String,
        #[serde(default)]
        keyid: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Entry {
        log_index: Value,
        log_id: LogId,
        kind_version: Kind,
        integrated_time: Value,
        inclusion_promise: Promise,
        inclusion_proof: Proof,
        canonicalized_body: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LogId {
        key_id: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Kind {
        kind: String,
        version: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Promise {
        signed_entry_timestamp: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Proof {
        log_index: Value,
        root_hash: String,
        tree_size: Value,
        hashes: Vec<String>,
        checkpoint: Checkpoint,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Checkpoint {
        envelope: String,
    }
    let parsed: Bundle = serde_json::from_value(bundle.clone())
        .map_err(|e| failure(format!("Sigstore bundle shape: {e}")))?;
    if parsed.media_type != "application/vnd.dev.sigstore.bundle.v0.3+json" {
        return Err(failure(
            "only Sigstore v0.3 single-certificate bundles are supported",
        ));
    }
    // Fields are consumed by the cryptographic verifiers above. Reading them
    // here is unnecessary; the typed parse solely rejects unknown structure.
    let _ = (parsed.verification_material, parsed.dsse_envelope);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticates_public_bundle_with_pinned_identity_digest_and_observer_time() {
        // Existing upstream public Sigstore fixture. This performs the complete
        // offline DSSE/Fulcio/SCT/Rekor/SET path, including SET reconstruction.
        let bundle: Value =
            serde_json::from_str(include_str!("../../../assets/rekor_test_bundle.json")).unwrap();
        let repo = "tinfoilsh/confidential-model-router";
        let pattern = r"^https://github\.com/tinfoilsh/confidential-model-router/\.github/workflows/tinfoil-release\.yml@refs/tags/v0\.0\.75$";
        let digest = "c337d719792307909947c779db80d834d1f73515199436ef3a7b880e60898c92";
        let verified = authenticate_bundle(&bundle, repo, pattern, digest).unwrap();
        assert_eq!(verified.verified_tlog_time, 1_774_548_286);
        assert_eq!(verified.identity.source_ref, "refs/tags/v0.0.75");
        assert_eq!(
            verified.statement.subject[0].name,
            "tinfoil-deployment.json"
        );
        let mut empty_timestamp_container = bundle.clone();
        empty_timestamp_container["verificationMaterial"]["timestampVerificationData"] =
            serde_json::json!({});
        assert!(authenticate_bundle(&empty_timestamp_container, repo, pattern, digest).is_ok());
        for unexpected in [
            serde_json::json!({"rfc3161Timestamps": []}),
            serde_json::json!({"unexpected": true}),
            serde_json::json!([]),
            Value::Null,
        ] {
            let mut unsupported = bundle.clone();
            unsupported["verificationMaterial"]["timestampVerificationData"] = unexpected;
            assert!(authenticate_bundle(&unsupported, repo, pattern, digest).is_err());
        }
        assert!(authenticate_bundle(&bundle, repo, pattern, &"0".repeat(64)).is_err());
        assert!(authenticate_bundle(&bundle, "attacker/repo", pattern, digest).is_err());
        assert!(
            authenticate_bundle(&bundle, repo, r"^https://github\.com/attacker/.*$", digest)
                .is_err()
        );
    }

    fn identity() -> SourceIdentity {
        SourceIdentity {
            issuer: "https://token.actions.githubusercontent.com".into(),
            workflow: "https://github.com/owner/repo/.github/workflows/release.yml@refs/tags/v1"
                .into(),
            repository: "https://github.com/owner/repo".into(),
            source_ref: "refs/tags/v1".into(),
            source_commit: "a".repeat(40),
            runner_environment: "github-hosted".into(),
            repository_identifier: String::new(),
            owner_identifier: String::new(),
        }
    }
    #[test]
    fn rejects_identity_substitution_and_self_hosted_runner() {
        let pattern = r"^https://github\.com/owner/repo/\.github/workflows/[^/@]+@refs/tags/[^@]+$";
        assert!(validate_identity(&identity(), "owner/repo", pattern).is_ok());
        let mut wrong = identity();
        wrong.runner_environment = "self-hosted".into();
        assert!(validate_identity(&wrong, "owner/repo", pattern).is_err());
        let mut wrong = identity();
        wrong.workflow.push_str("/evil");
        assert!(validate_identity(&wrong, "owner/repo", pattern).is_err());
        let mut wrong = identity();
        wrong.source_ref = "refs/tags/v2".into();
        assert!(validate_identity(&wrong, "owner/repo", pattern).is_err());
        let mut wrong = identity();
        wrong.repository = "https://github.com/attacker/repo".into();
        assert!(validate_identity(&wrong, "owner/repo", pattern).is_err());
        let mut wrong = identity();
        wrong.source_commit = "A".repeat(40);
        assert!(validate_identity(&wrong, "owner/repo", pattern).is_err());
    }
}
