//! Sigstore verification for code provenance.
//!
//! This module verifies that the code running in the enclave matches
//! the published open-source code by:
//! 1. Fetching the latest release from GitHub
//! 2. Fetching the Sigstore attestation bundle
//! 3. Verifying the DSSE signature cryptographically
//! 4. Verifying Rekor transparency log inclusion (mandatory)
//! 5. Validating the certificate is from GitHub Actions
//! 6. Extracting the expected measurement

// Submodules adapted from sigstore-rs (Apache 2.0 License)
pub mod certificate;
pub mod checkpoint;
pub mod dsse;
pub mod fulcio;
pub mod keyring;
pub mod merkle;
pub mod rekor;
pub mod transparency;
pub mod trust;

use super::attestation::types::{Measurement, PredicateType};
use super::github;
use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;
use serde::Deserialize;

/// In-toto statement from the decoded payload.
///
/// SPEC §5.4: the statement MUST contain only the recognized top-level fields;
/// deny_unknown_fields rejects any extra ones at parse time (matching
/// tinfoil-go's strict protojson parser and tinfoil-py/-js). Tinfoil produces
/// canonical statements, so an unknown top-level field is non-canonical.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    _type_: String,
    predicate_type: String,
    predicate: serde_json::Value,
    subject: Vec<Subject>,
}

#[derive(Debug, Deserialize)]
struct Subject {
    name: String,
    digest: std::collections::HashMap<String, String>,
}

// Re-export CertificateInfo from certificate module
pub use certificate::CertificateInfo;

/// Result of Sigstore verification: the code measurement and the release digest.
#[derive(Debug)]
pub struct SigstoreResult {
    pub measurement: Measurement,
    pub digest: String,
    /// Predicate type URI from the verified in-toto statement.
    pub predicate_type: String,
    /// in-toto statement `_type` value from the verified payload.
    pub in_toto_statement_type: String,
    /// `subject[0].name` from the verified in-toto statement.
    pub subject_name: String,
    /// `subject[0].digest.sha256` from the verified statement (lowercased).
    pub subject_digest_sha256_hex: String,
    /// OIDC issuer extension value from the signing certificate.
    pub cert_oidc_issuer: String,
    /// The certificate's GitHubWorkflowRepository extension value.
    pub cert_workflow_repository: String,
    /// The certificate's Build-Signer-URI extension value
    /// (`https://github.com/owner/repo/.github/workflows/<file>@<ref>`).
    pub cert_workflow_signer_uri: String,
}

/// Policy parameters for Sigstore verification.
///
/// All Tinfoil-specific policy decisions are funneled through this struct.
/// `Policy::tinfoil_default(repo)` returns the canonical settings used by the
/// SDK's standard verification path; tests and the conformance binary build
/// alternative policies to exercise specific clauses of SPEC §5.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Expected OIDC issuer extension value (exact match). SPEC §5.3.
    pub oidc_issuer: String,
    /// Required prefix on the cert's BuildSignerURI ref portion (e.g. `refs/tags/`). SPEC §5.3.
    pub workflow_ref_prefix: String,
    /// Expected GitHubWorkflowRepository extension value (exact match). SPEC §5.3.
    pub workflow_repository: String,
    /// Allow-list of predicate type URIs (SPEC §5.5). `None` means any.
    pub predicate_types_allowed: Option<Vec<String>>,
    /// Allow-list of in-toto statement `_type` values. `None` means any.
    /// SPEC §5.4 is silent here; Tinfoil's default pins to v0.1/v1.
    pub in_toto_statement_types_allowed: Option<Vec<String>>,
    /// Required DSSE envelope `payload_type` (exact match). SPEC §5.4.
    pub payload_type: String,
}

impl Policy {
    /// Canonical Tinfoil policy: GitHub Actions OIDC, tag-triggered builds,
    /// multiplatform predicate, in-toto v0.1/v1 statements.
    pub fn tinfoil_default(repo: &str) -> Self {
        Self {
            oidc_issuer: "https://token.actions.githubusercontent.com".to_string(),
            workflow_ref_prefix: "refs/tags/".to_string(),
            workflow_repository: repo.to_string(),
            predicate_types_allowed: Some(vec![
                "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1".to_string(),
            ]),
            in_toto_statement_types_allowed: Some(vec![
                "https://in-toto.io/Statement/v0.1".to_string(),
                "https://in-toto.io/Statement/v1".to_string(),
            ]),
            payload_type: "application/vnd.in-toto+json".to_string(),
        }
    }
}

/// Verify a repository and return the expected measurement and release digest.
///
/// Thin wrapper around [`verify_bundle_with_policy`] that:
/// 1. Fetches the latest release digest from GitHub.
/// 2. Fetches the Sigstore attestation bundle from GitHub.
/// 3. Calls [`verify_bundle_with_policy`] with [`Policy::tinfoil_default`] and
///    the embedded Sigstore trust root.
pub async fn verify_repo(repo: &str) -> Result<SigstoreResult> {
    // Install the rustls crypto provider before any HTTP client is built.
    crate::ensure_crypto_provider();

    let release_digest = github::fetch_latest_digest(repo).await?;
    let bundle_json = github::fetch_attestation_bundle(repo, &release_digest).await?;

    let policy = Policy::tinfoil_default(repo);
    verify_bundle_with_policy(
        &bundle_json,
        &release_digest,
        &policy,
        trust::embedded_trust_root_json(),
    )
}

/// Verify a Sigstore bundle against an explicit policy and trust root.
///
/// This is the mid-level entry point that the standard SDK path
/// ([`verify_repo`]) and the conformance binary both call. It performs no
/// network I/O — bundle bytes, expected digest, policy and trust root are
/// all provided by the caller.
///
/// Verification steps follow SPEC §5:
/// 1. Parse bundle JSON.
/// 2. Verify DSSE envelope signature with SCTs (uses Fulcio CAs + CT logs
///    from `trust_root_json`).
/// 3. Validate certificate identity against `policy` (OIDC issuer, workflow
///    repository, workflow-ref prefix).
/// 4. Verify Rekor transparency-log inclusion (uses Rekor keys from
///    `trust_root_json`).
/// 5. Verify Fulcio CA chain (uses Fulcio CAs from `trust_root_json`).
/// 6. Validate and extract the in-toto statement: payload type, statement
///    type, predicate type allow-list, subject-digest match, measurement
///    registers.
pub fn verify_bundle_with_policy(
    bundle_bytes: &[u8],
    expected_digest: &str,
    policy: &Policy,
    trust_root_json: &str,
) -> Result<SigstoreResult> {
    let bundle: serde_json::Value = serde_json::from_slice(bundle_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse bundle: {}", e)))?;

    dsse::verify_dsse_signature_with_trust(&bundle, trust_root_json)?;

    let cert_info = extract_certificate_info_from_bundle(&bundle)?;
    verify_certificate_identity_with_policy(&cert_info, policy)?;

    let (cert_der, cert_not_before, cert_not_after) = extract_cert_with_validity(&bundle)?;
    rekor::verify_rekor_entry_with_trust(
        &bundle,
        cert_not_before,
        cert_not_after,
        trust_root_json,
    )?;

    fulcio::verify_fulcio_chain_with_trust(&cert_der, cert_not_before, trust_root_json)?;

    extract_measurement_with_policy(&bundle, expected_digest, policy, &cert_info)
}

/// Extract certificate DER bytes and validity window (not_before, not_after) as Unix timestamps
fn extract_cert_with_validity(bundle: &serde_json::Value) -> Result<(Vec<u8>, u64, u64)> {
    use x509_cert::Certificate;
    use der::Decode;

    // Get the certificate
    let cert_b64 = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|rb| rb.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No certificate in bundle".into()))?;

    let cert_der = decode_b64(cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode certificate: {}", e)))?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate: {}", e)))?;

    let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs();
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs();

    Ok((cert_der, not_before, not_after))
}

/// Extract certificate info from the bundle
fn extract_certificate_info_from_bundle(bundle: &serde_json::Value) -> Result<CertificateInfo> {
    use x509_cert::Certificate;
    use der::Decode;

    // Get the certificate
    let cert_b64 = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|rb| rb.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No certificate in bundle".into()))?;

    let cert_der = decode_b64(cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode certificate: {}", e)))?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate: {}", e)))?;

    // Use the certificate module's extract function
    certificate::extract_certificate_info(&cert)
}

/// Validate the signing certificate against the policy.
///
/// Each check maps to a SPEC §5.3 clause. The error message prefix is
/// intentionally stable — the conformance binary string-matches it to map
/// to the spec-anchored rejection code taxonomy (until structured error
/// variants land).
fn verify_certificate_identity_with_policy(
    cert_info: &CertificateInfo,
    policy: &Policy,
) -> Result<()> {
    if cert_info.issuer != policy.oidc_issuer {
        return Err(Error::SigstoreVerification(format!(
            "OIDC_ISSUER_MISMATCH: cert OIDC issuer {:?} does not equal policy.oidc_issuer {:?}",
            cert_info.issuer, policy.oidc_issuer
        )));
    }

    if cert_info.repository != policy.workflow_repository {
        return Err(Error::SigstoreVerification(format!(
            "WORKFLOW_REPOSITORY_MISMATCH: cert repository {:?} does not equal policy.workflow_repository {:?}",
            cert_info.repository, policy.workflow_repository
        )));
    }

    // BuildSignerURI is shaped `https://github.com/{repo}/.github/workflows/<file>@<ref>`.
    // The ref portion must begin with `policy.workflow_ref_prefix`. Using `[^@]+` for
    // the workflow filename guarantees we anchor on the *first* `@`, which prevents
    // attacker-controlled URIs like `…@refs/heads/main@refs/tags/v1` from sneaking
    // through via substring matching.
    let pattern = format!(
        r"^https://github\.com/{}/\.github/workflows/[^@]+@{}",
        regex::escape(&policy.workflow_repository),
        regex::escape(&policy.workflow_ref_prefix),
    );
    let re = regex::Regex::new(&pattern).map_err(|e| {
        Error::SigstoreVerification(format!("Invalid workflow ref regex: {}", e))
    })?;
    if !re.is_match(&cert_info.subject_workflow) {
        return Err(Error::SigstoreVerification(format!(
            "WORKFLOW_REF_PREFIX_MISMATCH: cert subject_workflow {:?} does not match prefix {:?}",
            cert_info.subject_workflow, policy.workflow_ref_prefix
        )));
    }

    Ok(())
}

/// Validate the verified DSSE envelope against the policy and extract the
/// measurement plus the full set of fields surfaced in [`SigstoreResult`].
///
/// Error message prefixes are stable — the conformance binary maps them to
/// rejection codes.
fn extract_measurement_with_policy(
    bundle: &serde_json::Value,
    expected_digest: &str,
    policy: &Policy,
    cert_info: &CertificateInfo,
) -> Result<SigstoreResult> {
    let dsse_envelope = bundle
        .get("dsseEnvelope")
        .ok_or_else(|| Error::SigstoreVerification("BUNDLE_MALFORMED: No dsseEnvelope in bundle".into()))?;

    let payload_type = dsse_envelope
        .get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("BUNDLE_MALFORMED: No payloadType in DSSE envelope".into()))?;
    if payload_type != policy.payload_type {
        return Err(Error::SigstoreVerification(format!(
            "PAYLOAD_TYPE_MISMATCH: DSSE payload_type {:?} does not equal policy.payload_type {:?}",
            payload_type, policy.payload_type
        )));
    }

    let payload_b64 = dsse_envelope
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("BUNDLE_MALFORMED: No payload in DSSE envelope".into()))?;
    let payload_bytes = decode_b64(payload_b64)
        .map_err(|e| Error::SigstoreVerification(format!("BUNDLE_MALFORMED: Failed to decode payload: {}", e)))?;
    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("BUNDLE_MALFORMED: Failed to parse statement: {}", e)))?;

    if let Some(allowed) = &policy.in_toto_statement_types_allowed {
        if !allowed.iter().any(|t| t == &statement._type_) {
            return Err(Error::SigstoreVerification(format!(
                "IN_TOTO_STATEMENT_TYPE_NOT_ALLOWED: in-toto statement type {:?} not in policy.in_toto_statement_types_allowed",
                statement._type_
            )));
        }
    }

    let subject = statement
        .subject
        .first()
        .ok_or_else(|| Error::SigstoreVerification("SUBJECT_MISSING: No subject in statement".into()))?;
    let payload_digest = subject
        .digest
        .get("sha256")
        .ok_or_else(|| Error::SigstoreVerification("BUNDLE_MALFORMED: No sha256 digest in subject".into()))?;

    // Lowercase normalize per SPEC §7.3.
    if payload_digest.to_lowercase() != expected_digest.to_lowercase() {
        return Err(Error::SigstoreVerification(format!(
            "SUBJECT_DIGEST_MISMATCH: bundle subject digest {:?} does not equal expected {:?}",
            payload_digest, expected_digest
        )));
    }

    if let Some(allowed) = &policy.predicate_types_allowed {
        if !allowed.iter().any(|t| t == &statement.predicate_type) {
            return Err(Error::SigstoreVerification(format!(
                "PREDICATE_TYPE_NOT_ALLOWED: predicate type {:?} not in policy.predicate_types_allowed",
                statement.predicate_type
            )));
        }
    }

    // Currently only the multiplatform predicate ships with a typed Measurement;
    // others would require additional extraction logic when added to the SDK.
    let measurement = if statement.predicate_type
        == "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
    {
        let snp_measurement = statement
            .predicate
            .get("snp_measurement")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::SigstoreVerification(
                "PREDICATE_MEASUREMENT_INVALID: Missing snp_measurement".into(),
            ))?;
        let tdx = statement
            .predicate
            .get("tdx_measurement")
            .ok_or_else(|| Error::SigstoreVerification(
                "PREDICATE_MEASUREMENT_INVALID: Missing tdx_measurement".into(),
            ))?;
        let rtmr1 = tdx
            .get("rtmr1")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::SigstoreVerification(
                "PREDICATE_MEASUREMENT_INVALID: Missing tdx_measurement.rtmr1".into(),
            ))?;
        let rtmr2 = tdx
            .get("rtmr2")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::SigstoreVerification(
                "PREDICATE_MEASUREMENT_INVALID: Missing tdx_measurement.rtmr2".into(),
            ))?;
        Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec![
                snp_measurement.to_string(),
                rtmr1.to_string(),
                rtmr2.to_string(),
            ],
        }
    } else {
        // Allow-listed by policy but not yet extractable by the SDK.
        return Err(Error::SigstoreVerification(format!(
            "PREDICATE_MEASUREMENT_INVALID: predicate type {:?} allowed by policy but extraction not implemented",
            statement.predicate_type
        )));
    };

    Ok(SigstoreResult {
        measurement,
        digest: expected_digest.to_lowercase(),
        predicate_type: statement.predicate_type,
        in_toto_statement_type: statement._type_,
        subject_name: subject.name.clone(),
        subject_digest_sha256_hex: payload_digest.to_lowercase(),
        cert_oidc_issuer: cert_info.issuer.clone(),
        cert_workflow_repository: cert_info.repository.clone(),
        cert_workflow_signer_uri: cert_info.subject_workflow.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_repo_full() {
        let result = verify_repo("tinfoilsh/confidential-llama3-3-70b").await;
        assert!(result.is_ok(), "Failed to verify repo: {:?}", result);
        let r = result.unwrap();
        assert!(!r.measurement.registers[0].is_empty());
        assert!(!r.digest.is_empty());
        assert_eq!(r.digest.len(), 64);
    }
}
