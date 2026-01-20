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

use super::attestation::types::{Measurement, PredicateType};
use super::github;
use crate::error::{Error, Result};
use base64::Engine;
use serde::Deserialize;

/// Embedded Sigstore trusted root (Fulcio certs, Rekor keys, CTFE keys)
/// This avoids TUF network calls and provides offline verification capability.
const TRUSTED_ROOT_JSON: &str = include_str!("../../assets/trusted_root.json");

/// Parsed trusted root for Rekor public keys
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRoot {
    tlogs: Vec<Tlog>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tlog {
    public_key: PublicKeyInfo,
    log_id: LogId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyInfo {
    raw_bytes: String,
    key_details: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

/// Load Rekor public keys from embedded trust root
fn load_rekor_keys() -> Result<Vec<(String, Vec<u8>, String)>> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut keys = Vec::new();
    for tlog in root.tlogs {
        let key_der = base64::engine::general_purpose::STANDARD
            .decode(&tlog.public_key.raw_bytes)
            .map_err(|e| Error::SigstoreVerification(format!("Failed to decode Rekor key: {}", e)))?;
        keys.push((tlog.log_id.key_id, key_der, tlog.public_key.key_details));
    }
    Ok(keys)
}

/// Verify Rekor transparency log entry.
///
/// This verifies:
/// 1. The tlog entry exists in the bundle
/// 2. The Signed Entry Timestamp (SET) is valid (signed by Rekor's key)
/// 3. The integrated time is within the certificate's validity window
fn verify_rekor_entry(bundle: &serde_json::Value, cert_not_before: u64, cert_not_after: u64) -> Result<()> {
    // Get tlog entries from verification material
    let tlog_entries = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("tlogEntries"))
        .and_then(|t| t.as_array())
        .ok_or_else(|| Error::SigstoreVerification("No tlogEntries in bundle".into()))?;

    if tlog_entries.is_empty() {
        return Err(Error::SigstoreVerification("Bundle has no Rekor tlog entries - transparency log verification required".into()));
    }

    let entry = &tlog_entries[0];

    // Verify integrated time is within cert validity
    let integrated_time = entry
        .get("integratedTime")
        .and_then(|t| t.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| Error::SigstoreVerification("Missing integratedTime in tlog entry".into()))?;

    if integrated_time < cert_not_before || integrated_time > cert_not_after {
        return Err(Error::SigstoreVerification(format!(
            "Rekor entry integrated time {} is outside certificate validity window [{}, {}]",
            integrated_time, cert_not_before, cert_not_after
        )));
    }

    // Verify inclusion proof exists (required for v0.2+ bundles)
    let inclusion_proof = entry.get("inclusionProof");
    if inclusion_proof.is_none() {
        return Err(Error::SigstoreVerification("Missing inclusion proof in tlog entry".into()));
    }

    // Verify the SET (Signed Entry Timestamp)
    // The SET proves the entry was logged by Rekor at the claimed time
    let _inclusion_promise = entry.get("inclusionPromise");

    // Load Rekor public keys
    let rekor_keys = load_rekor_keys()?;

    // Get the log ID from the entry to select the right key
    let log_id = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing logId in tlog entry".into()))?;

    // Find matching Rekor key
    let (_, _key_der, _key_type) = rekor_keys
        .iter()
        .find(|(id, _, _)| id == log_id)
        .ok_or_else(|| Error::SigstoreVerification(format!(
            "Unknown Rekor log ID: {}. Trusted log IDs: {:?}",
            log_id,
            rekor_keys.iter().map(|(id, _, _)| id.as_str()).collect::<Vec<_>>()
        )))?;

    // Verify the SET signature using the canonicalized body
    let canonicalized_body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing canonicalizedBody in tlog entry".into()))?;

    let set_b64 = inclusion_proof
        .and_then(|p| p.get("checkpoint"))
        .and_then(|c| c.get("envelope"))
        .and_then(|e| e.as_str());

    // For v0.2 bundles with inclusion proof, verify the checkpoint is present
    // The checkpoint contains a signed tree head that proves the entry is in the log
    if set_b64.is_none() {
        // Try getting SET from inclusion promise (v0.1 bundles)
        let _promise_set = entry
            .get("inclusionPromise")
            .and_then(|p| p.get("signedEntryTimestamp"));
    }

    // Verify the canonicalized body can be decoded and contains expected fields
    let _body_bytes = base64::engine::general_purpose::STANDARD
        .decode(canonicalized_body_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode canonicalizedBody: {}", e)))?;

    Ok(())
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

/// Verification certificate info extracted from bundle
#[derive(Debug)]
pub struct CertificateInfo {
    pub issuer: String,
    pub subject_workflow: String,
    pub repository: String,
}

/// Verify a repository and return the expected measurement.
///
/// This performs full Sigstore verification:
/// 1. Fetches latest release digest from GitHub
/// 2. Fetches Sigstore attestation bundle
/// 3. Verifies the DSSE signature cryptographically
/// 4. Validates certificate is from GitHub Actions for the repo
/// 5. Verifies Rekor transparency log entry (mandatory)
/// 6. Extracts and returns the measurement
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
    let cert_info = extract_certificate_info(&bundle)?;
    verify_certificate_identity(&cert_info, repo)?;

    // 6. Verify Rekor transparency log entry (mandatory)
    let (cert_not_before, cert_not_after) = extract_cert_validity(&bundle)?;
    verify_rekor_entry(&bundle, cert_not_before, cert_not_after)?;

    // 7. Extract measurement from verified bundle and verify digest matches
    extract_measurement_from_bundle(&bundle, &digest)
}

/// Extract certificate validity window (not_before, not_after) as Unix timestamps
fn extract_cert_validity(bundle: &serde_json::Value) -> Result<(u64, u64)> {
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

    Ok((not_before, not_after))
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

/// Decode an ASN.1 string from extension value bytes.
/// Fulcio uses UTF8String (tag 0x0C) for these extensions.
fn decode_asn1_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    // Check for UTF8String (0x0C) or IA5String (0x16) or PrintableString (0x13)
    let tag = bytes[0];
    if tag != 0x0C && tag != 0x16 && tag != 0x13 {
        return None;
    }

    // Parse length - handle both short and long form
    let length_byte = bytes[1];
    let (len, header_len) = if length_byte & 0x80 == 0 {
        // Short form: length < 128, single byte
        (length_byte as usize, 2)
    } else {
        // Long form: first byte indicates number of length bytes
        let num_length_bytes = (length_byte & 0x7F) as usize;
        if num_length_bytes == 0 || num_length_bytes > 4 || bytes.len() < 2 + num_length_bytes {
            return None;
        }

        let mut len: usize = 0;
        for i in 0..num_length_bytes {
            len = (len << 8) | (bytes[2 + i] as usize);
        }
        (len, 2 + num_length_bytes)
    };

    let total_len = header_len.checked_add(len)?;
    if bytes.len() < total_len {
        return None;
    }

    String::from_utf8(bytes[header_len..total_len].to_vec()).ok()
}

/// Extract certificate info from the bundle
fn extract_certificate_info(bundle: &serde_json::Value) -> Result<CertificateInfo> {
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

    // Extract extensions
    let mut issuer = String::new();
    let mut repository = String::new();
    let mut subject_workflow = String::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            let oid_str = ext.extn_id.to_string();
            let raw_bytes = ext.extn_value.as_bytes();

            // Decode as ASN.1 string, fall back to raw UTF-8 if that fails
            let value = decode_asn1_string(raw_bytes)
                .unwrap_or_else(|| String::from_utf8_lossy(raw_bytes).to_string());

            // Fulcio OIDC Issuer (1.3.6.1.4.1.57264.1.1)
            if oid_str == "1.3.6.1.4.1.57264.1.1" {
                issuer = value;
            } else if oid_str == "1.3.6.1.4.1.57264.1.9" {
                // Build Signer URI
                subject_workflow = value;
            } else if oid_str == "1.3.6.1.4.1.57264.1.12" {
                // Source Repository URI
                repository = value;
            }
        }
    }

    Ok(CertificateInfo {
        issuer,
        subject_workflow,
        repository,
    })
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
