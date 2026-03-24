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

/// In-toto statement from the decoded payload
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InTotoStatement {
    #[serde(rename = "_type")]
    _type_: String,
    predicate_type: String,
    predicate: serde_json::Value,
    subject: Vec<Subject>,
}

#[derive(Debug, Deserialize)]
struct Subject {
    #[allow(dead_code)]
    name: String,
    digest: std::collections::HashMap<String, String>,
}

// Re-export CertificateInfo from certificate module
pub use certificate::CertificateInfo;

/// Verify a repository and return the expected measurement.
///
/// This performs full Sigstore verification:
/// 1. Fetches latest release digest from GitHub
/// 2. Fetches Sigstore attestation bundle
/// 3. Verifies the DSSE signature cryptographically
/// 4. Validates certificate is from GitHub Actions for the repo
/// 5. Verifies Rekor transparency log entry (mandatory)
/// 6. Verifies certificate was issued by trusted Fulcio CA
/// 7. Extracts and returns the measurement
pub async fn verify_repo(repo: &str) -> Result<Measurement> {
    // 1. Fetch latest release digest
    let digest = github::fetch_latest_digest(repo).await?;

    // 2. Fetch the Sigstore attestation bundle
    let bundle_json = github::fetch_attestation_bundle(repo, &digest).await?;

    // 3. Parse bundle
    let bundle: serde_json::Value = serde_json::from_slice(&bundle_json)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse bundle: {}", e)))?;

    // 4. Verify DSSE signature cryptographically
    dsse::verify_dsse_signature(&bundle)?;

    // 5. Verify certificate is from GitHub Actions for this repo
    let cert_info = extract_certificate_info_from_bundle(&bundle)?;
    verify_certificate_identity(&cert_info, repo)?;

    // 6. Verify Rekor transparency log entry (mandatory)
    let (cert_der, cert_not_before, cert_not_after) = extract_cert_with_validity(&bundle)?;
    rekor::verify_rekor_entry(&bundle, cert_not_before, cert_not_after)?;

    // 7. Verify certificate was issued by trusted Fulcio CA
    fulcio::verify_fulcio_chain(&cert_der, cert_not_before)?;

    // 8. Extract measurement from verified bundle and verify digest matches
    extract_measurement_from_bundle(&bundle, &digest)
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

/// Verify that the certificate is from GitHub Actions for the expected repo
fn verify_certificate_identity(cert_info: &CertificateInfo, expected_repo: &str) -> Result<()> {
    // Verify OIDC issuer is GitHub Actions (exact match, not substring)
    if cert_info.issuer != "https://token.actions.githubusercontent.com" {
        return Err(Error::SigstoreVerification(format!(
            "Certificate not from GitHub Actions. Issuer: {}",
            cert_info.issuer
        )));
    }

    // Verify repository matches the certificate's repository extension (matches Python/JS)
    if cert_info.repository != expected_repo {
        return Err(Error::SigstoreVerification(format!(
            "Certificate repository does not match. Expected: {}, Got: {}",
            expected_repo, cert_info.repository
        )));
    }

    // Verify workflow URI matches expected pattern for this repo
    let pattern = format!(
        r"^https://github\.com/{}/.github/workflows/.*@refs/tags/",
        regex::escape(expected_repo)
    );
    let re = regex::Regex::new(&pattern)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid regex: {}", e)))?;

    if !re.is_match(&cert_info.subject_workflow) {
        return Err(Error::SigstoreVerification(format!(
            "Certificate workflow doesn't match expected pattern. Expected repo: {}, Got: {}",
            expected_repo, cert_info.subject_workflow
        )));
    }

    Ok(())
}

/// Extract measurement from a bundle's DSSE envelope and verify digest matches
fn extract_measurement_from_bundle(bundle: &serde_json::Value, expected_digest: &str) -> Result<Measurement> {
    let dsse_envelope = bundle.get("dsseEnvelope")
        .ok_or_else(|| Error::SigstoreVerification("No dsseEnvelope in bundle".into()))?;

    // Validate payloadType is in-toto (matches Python/JS)
    let payload_type = dsse_envelope.get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No payloadType in DSSE envelope".into()))?;

    if payload_type != "application/vnd.in-toto+json" {
        return Err(Error::SigstoreVerification(format!(
            "Unsupported DSSE payload type: \"{}\". Expected \"application/vnd.in-toto+json\"",
            payload_type
        )));
    }

    let payload_b64 = dsse_envelope.get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No payload in DSSE envelope".into()))?;

    let payload_bytes = decode_b64(payload_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode payload: {}", e)))?;

    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse statement: {}", e)))?;

    // Validate in-toto statement type
    if statement._type_ != "https://in-toto.io/Statement/v0.1"
        && statement._type_ != "https://in-toto.io/Statement/v1"
    {
        return Err(Error::SigstoreVerification(format!(
            "Unsupported in-toto statement type: \"{}\"",
            statement._type_
        )));
    }

    // Verify that the provided digest matches the digest in the DSSE payload subject
    let subject = statement.subject.first()
        .ok_or_else(|| Error::SigstoreVerification("No subject in statement".into()))?;

    let payload_digest = subject.digest.get("sha256")
        .ok_or_else(|| Error::SigstoreVerification("No sha256 digest in subject".into()))?;

    if payload_digest != expected_digest {
        return Err(Error::SigstoreVerification(format!(
            "Provided digest does not match verified DSSE payload digest. Expected: {}, Got: {}",
            expected_digest, payload_digest
        )));
    }

    // Only accept multiplatform predicate (matches Python/Go behavior)
    if statement.predicate_type != "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1" {
        return Err(Error::SigstoreVerification(format!(
            "Unsupported predicate type: {}",
            statement.predicate_type
        )));
    }

    let snp_measurement = statement.predicate.get("snp_measurement")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing snp_measurement".into()))?;

    let tdx = statement.predicate.get("tdx_measurement")
        .ok_or_else(|| Error::SigstoreVerification("Missing tdx_measurement".into()))?;

    let rtmr1 = tdx.get("rtmr1")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing rtmr1".into()))?;

    let rtmr2 = tdx.get("rtmr2")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing rtmr2".into()))?;

    let registers = vec![snp_measurement.to_string(), rtmr1.to_string(), rtmr2.to_string()];
    
    Ok(Measurement {
        type_: PredicateType::SnpTdxMultiPlatformV1,
        registers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verify_repo_full() {
        let measurement = verify_repo("tinfoilsh/confidential-llama3-3-70b").await;
        assert!(measurement.is_ok(), "Failed to verify repo: {:?}", measurement);
        let m = measurement.unwrap();
        println!("Measurement (cryptographically verified): {:?}", m);
        assert!(!m.registers[0].is_empty());
    }
}
