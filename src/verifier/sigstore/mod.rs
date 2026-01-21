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
pub mod fulcio;
pub mod keyring;
pub mod rekor;
pub mod transparency;
pub mod trust;

use super::attestation::types::{Measurement, PredicateType};
use super::github;
use crate::error::{Error, Result};
use base64::Engine;
use serde::Deserialize;

/// Verify Signed Certificate Timestamps (SCTs) embedded in the certificate.
///
/// Uses the sigstore-rs adapted transparency module for RFC 6962 compliant verification:
/// 1. Parses SCTs from the certificate using x509-cert types
/// 2. Reconstructs the PreCert (issuer key hash + TBS without SCT extension)
/// 3. Builds the digitally-signed struct with proper TLS encoding
/// 4. Verifies the ECDSA signature against the CT log's public key
/// 5. Requires at least one valid SCT from a known Sigstore CT log
fn verify_sct(cert_der: &[u8], issuer_spki_der: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate for SCT: {}", e)))?;

    // Create SCT wrapper using the transparency module
    let embedded_sct = transparency::CertificateEmbeddedSCT::new_with_spki(&cert, issuer_spki_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to extract SCT: {}", e)))?;

    // Load CT log keyring
    let ct_keyring = trust::load_ctlog_keyring()?;

    // Verify SCT using the sigstore-rs adapted verification
    transparency::verify_sct(&embedded_sct, &ct_keyring)
        .map_err(|e| Error::SigstoreVerification(format!("SCT verification failed: {}", e)))
}

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
    verify_dsse_signature(&bundle)?;

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

    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode certificate: {}", e)))?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate: {}", e)))?;

    let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration().as_secs();
    let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration().as_secs();

    Ok((cert_der, not_before, not_after))
}

/// Compute DSSE Pre-Authentication Encoding (PAE)
/// 
/// PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
/// Where:
///   SP = ASCII space (0x20)
///   LEN(s) = ASCII decimal encoding of the byte length of s
fn compute_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let type_len = type_bytes.len().to_string();
    let body_len = payload.len().to_string();
    
    let mut pae = Vec::new();
    pae.extend_from_slice(b"DSSEv1");
    pae.push(0x20); // SP
    pae.extend_from_slice(type_len.as_bytes());
    pae.push(0x20); // SP
    pae.extend_from_slice(type_bytes);
    pae.push(0x20); // SP
    pae.extend_from_slice(body_len.as_bytes());
    pae.push(0x20); // SP
    pae.extend_from_slice(payload);
    
    pae
}

/// Verify the DSSE envelope signature cryptographically
/// 
/// DSSE (Dead Simple Signing Envelope) verification:
/// 1. Extract certificate public key from bundle
/// 2. Compute PAE (Pre-Authentication Encoding) of payload
/// 3. Verify ECDSA signature over PAE
fn verify_dsse_signature(bundle: &serde_json::Value) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    
    // Get the certificate
    let cert_b64 = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|rb| rb.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No certificate in bundle".into()))?;
    
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode certificate: {}", e)))?;
    
    // Parse certificate and extract public key
    use x509_cert::Certificate;
    use der::Decode;
    
    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate: {}", e)))?;

    // Validate certificate has required extensions (KeyUsage: digitalSignature, ExtKeyUsage: codeSigning)
    certificate::validate_certificate_extensions(&cert)?;

    // Find the issuer certificate's SPKI for SCT verification
    let issuer_spki_der = fulcio::find_issuer_spki(&cert)?;

    // Verify Signed Certificate Timestamps (SCTs) with full cryptographic verification
    verify_sct(&cert_der, &issuer_spki_der)?;

    let pubkey_bytes = cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    
    // The public key should be P-256 (secp256r1) - Fulcio uses this
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid public key: {}", e)))?;
    
    // Get DSSE envelope
    let dsse = bundle.get("dsseEnvelope")
        .ok_or_else(|| Error::SigstoreVerification("No dsseEnvelope in bundle".into()))?;
    
    let payload_type = dsse.get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No payloadType".into()))?;
    
    let payload_b64 = dsse.get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No payload".into()))?;
    
    let signature_b64 = dsse.get("signatures")
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|sig| sig.get("sig"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No signature".into()))?;
    
    // Decode payload (it's base64 in the envelope)
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode payload: {}", e)))?;
    
    // Compute PAE (Pre-Authentication Encoding)
    let pae = compute_pae(payload_type, &payload);
    
    // Decode signature - could be DER-encoded or raw
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode signature: {}", e)))?;
    
    // Try DER format first (starts with 0x30), then raw format
    let signature = if signature_bytes.first() == Some(&0x30) {
        Signature::from_der(&signature_bytes)
            .map_err(|e| Error::SigstoreVerification(format!("Invalid DER signature: {}", e)))?
    } else {
        // Raw r||s format (64 bytes for P-256)
        Signature::from_slice(&signature_bytes)
            .map_err(|e| Error::SigstoreVerification(format!("Invalid raw signature: {}", e)))?
    };
    
    // Verify!
    verifying_key.verify(&pae, &signature)
        .map_err(|e| Error::SigstoreVerification(format!("DSSE signature verification failed: {}", e)))?;
    
    Ok(())
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

    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode certificate: {}", e)))?;

    let cert = Certificate::from_der(&cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse certificate: {}", e)))?;

    // Use the certificate module's extract function
    certificate::extract_certificate_info(&cert)
}

/// Verify that the certificate is from GitHub Actions for the expected repo
fn verify_certificate_identity(cert_info: &CertificateInfo, expected_repo: &str) -> Result<()> {
    // Verify OIDC issuer is GitHub Actions
    if !cert_info.issuer.contains("token.actions.githubusercontent.com") {
        return Err(Error::SigstoreVerification(format!(
            "Certificate not from GitHub Actions. Issuer: {}",
            cert_info.issuer
        )));
    }

    // Verify repository matches using regex pattern for workflow URI
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

    let payload_b64 = dsse_envelope.get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::SigstoreVerification("No payload in DSSE envelope".into()))?;

    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode payload: {}", e)))?;

    let statement: InTotoStatement = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse statement: {}", e)))?;

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

    let measurement_type = match statement.predicate_type.as_str() {
        "https://tinfoil.sh/predicate/sev-snp-guest/v2" => PredicateType::SevGuestV2,
        "https://tinfoil.sh/predicate/tdx-guest/v2" => PredicateType::TdxGuestV2,
        "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1" => PredicateType::SnpTdxMultiPlatformV1,
        other => return Err(Error::SigstoreVerification(format!("Unknown predicate type: {}", other))),
    };
    
    let registers = match measurement_type {
        PredicateType::SevGuestV2 => {
            let snp_measurement = statement.predicate.get("snp_measurement")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::SigstoreVerification("Missing snp_measurement".into()))?;
            vec![snp_measurement.to_string()]
        }
        PredicateType::SnpTdxMultiPlatformV1 => {
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
            
            vec![snp_measurement.to_string(), rtmr1.to_string(), rtmr2.to_string()]
        }
        _ => return Err(Error::SigstoreVerification(format!("Unsupported predicate type: {:?}", measurement_type))),
    };
    
    Ok(Measurement {
        type_: measurement_type,
        registers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pae_encoding() {
        // Test vector from DSSE spec
        let payload_type = "http://example.com/HelloWorld";
        let payload = b"hello world";
        let pae = compute_pae(payload_type, payload);
        
        // Expected: "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        let expected = b"DSSEv1 29 http://example.com/HelloWorld 11 hello world";
        assert_eq!(pae, expected);
    }
    
    #[tokio::test]
    async fn test_verify_repo_full() {
        let measurement = verify_repo("tinfoilsh/confidential-llama3-3-70b").await;
        assert!(measurement.is_ok(), "Failed to verify repo: {:?}", measurement);
        let m = measurement.unwrap();
        println!("Measurement (cryptographically verified): {:?}", m);
        assert!(!m.registers[0].is_empty());
    }
}
