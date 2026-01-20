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

/// Verify that the certificate in the bundle matches the certificate in the Rekor entry.
///
/// This is critical for security: the Rekor entry's canonicalizedBody contains the
/// certificate that was actually logged. If we don't verify this binding, an attacker
/// could substitute a different certificate in the bundle while keeping the valid
/// Rekor entry, bypassing the transparency log protection.
fn verify_certificate_binding(bundle: &serde_json::Value, canonicalized_body: &[u8]) -> Result<()> {
    // Parse the canonicalizedBody as JSON
    let entry: serde_json::Value = serde_json::from_slice(canonicalized_body)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e)))?;

    // Determine the entry kind and extract certificate accordingly
    let kind = entry.get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("unknown");

    let rekor_cert_der = match kind {
        "dsse" => {
            // DSSE format: spec.signatures[0].verifier contains base64-encoded PEM
            let verifier_b64 = entry
                .get("spec")
                .and_then(|s| s.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("verifier"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::SigstoreVerification(
                    "Missing certificate in DSSE Rekor entry (spec.signatures[0].verifier)".into()
                ))?;

            // Decode base64 to get PEM string
            let verifier_pem_bytes = base64::engine::general_purpose::STANDARD
                .decode(verifier_b64)
                .map_err(|e| Error::SigstoreVerification(format!("Failed to decode verifier: {}", e)))?;

            let verifier_pem = String::from_utf8(verifier_pem_bytes)
                .map_err(|e| Error::SigstoreVerification(format!("Invalid UTF-8 in verifier: {}", e)))?;

            // Parse PEM to get DER
            parse_pem_certificate(&verifier_pem)?
        }
        "hashedrekord" => {
            // hashedrekord format: spec.signature.publicKey.content contains raw PEM
            let rekor_cert_pem = entry
                .get("spec")
                .and_then(|s| s.get("signature"))
                .and_then(|s| s.get("publicKey"))
                .and_then(|pk| pk.get("content"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| Error::SigstoreVerification(
                    "Missing certificate in hashedrekord Rekor entry (spec.signature.publicKey.content)".into()
                ))?;

            parse_pem_certificate(rekor_cert_pem)?
        }
        _ => {
            return Err(Error::SigstoreVerification(format!(
                "Unknown Rekor entry kind: {}. Expected 'dsse' or 'hashedrekord'", kind
            )));
        }
    };

    // Get certificate from bundle (base64-encoded DER in verificationMaterial.certificate.rawBytes)
    let bundle_cert_b64 = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|rb| rb.as_str())
        .ok_or_else(|| Error::SigstoreVerification(
            "Missing certificate in bundle (verificationMaterial.certificate.rawBytes)".into()
        ))?;

    // Decode the bundle certificate from base64
    let bundle_cert_der = base64::engine::general_purpose::STANDARD
        .decode(bundle_cert_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode bundle certificate: {}", e)))?;

    // Compare the DER bytes
    if rekor_cert_der != bundle_cert_der {
        return Err(Error::SigstoreVerification(
            "Certificate mismatch: bundle certificate does not match Rekor entry certificate. \
             This could indicate a substitution attack.".into()
        ));
    }

    Ok(())
}

/// Verify that the signature in the bundle matches the signature in the Rekor entry.
///
/// This is critical for security: the Rekor entry's canonicalizedBody contains the
/// signature that was actually logged. If we don't verify this binding, an attacker
/// could substitute a different signature in the bundle while keeping the valid
/// Rekor entry.
fn verify_signature_binding(bundle: &serde_json::Value, canonicalized_body: &[u8]) -> Result<()> {
    // Parse the canonicalizedBody as JSON
    let entry: serde_json::Value = serde_json::from_slice(canonicalized_body)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e)))?;

    // Determine the entry kind and extract signature accordingly
    let kind = entry.get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("unknown");

    let rekor_signature_bytes = match kind {
        "dsse" => {
            // DSSE format: spec.signatures[0].signature contains base64-encoded signature
            let sig_b64 = entry
                .get("spec")
                .and_then(|s| s.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("signature"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::SigstoreVerification(
                    "Missing signature in DSSE Rekor entry (spec.signatures[0].signature)".into()
                ))?;

            base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .map_err(|e| Error::SigstoreVerification(format!("Failed to decode Rekor signature: {}", e)))?
        }
        "hashedrekord" => {
            // hashedrekord format: spec.signature.content contains base64-encoded signature
            let sig_b64 = entry
                .get("spec")
                .and_then(|s| s.get("signature"))
                .and_then(|s| s.get("content"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| Error::SigstoreVerification(
                    "Missing signature in hashedrekord Rekor entry (spec.signature.content)".into()
                ))?;

            base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .map_err(|e| Error::SigstoreVerification(format!("Failed to decode Rekor signature: {}", e)))?
        }
        _ => {
            return Err(Error::SigstoreVerification(format!(
                "Unknown Rekor entry kind: {}. Expected 'dsse' or 'hashedrekord'", kind
            )));
        }
    };

    // Get signature from bundle's DSSE envelope
    let bundle_sig_b64 = bundle
        .get("dsseEnvelope")
        .and_then(|dsse| dsse.get("signatures"))
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|sig| sig.get("sig"))
        .and_then(|s| s.as_str())
        .ok_or_else(|| Error::SigstoreVerification(
            "Missing signature in bundle (dsseEnvelope.signatures[0].sig)".into()
        ))?;

    let bundle_sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(bundle_sig_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode bundle signature: {}", e)))?;

    // Compare the signatures
    if rekor_signature_bytes != bundle_sig_bytes {
        return Err(Error::SigstoreVerification(
            "Signature mismatch: bundle signature does not match Rekor entry signature. \
             This could indicate a substitution attack.".into()
        ));
    }

    Ok(())
}

/// Parse a PEM-encoded certificate and return the DER bytes.
fn parse_pem_certificate(pem: &str) -> Result<Vec<u8>> {
    // Find the certificate content between BEGIN and END markers
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";

    let start = pem.find(begin_marker)
        .ok_or_else(|| Error::SigstoreVerification("Invalid PEM: missing BEGIN CERTIFICATE".into()))?;
    let end = pem.find(end_marker)
        .ok_or_else(|| Error::SigstoreVerification("Invalid PEM: missing END CERTIFICATE".into()))?;

    if start >= end {
        return Err(Error::SigstoreVerification("Invalid PEM: markers in wrong order".into()));
    }

    // Extract the base64 content (skip the BEGIN marker)
    let b64_content: String = pem[start + begin_marker.len()..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Decode the base64 to get DER bytes
    base64::engine::general_purpose::STANDARD
        .decode(&b64_content)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode PEM certificate: {}", e)))
}

/// Verify Rekor transparency log entry with full cryptographic verification.
///
/// This verifies:
/// 1. The tlog entry exists in the bundle
/// 2. The integrated time is within the certificate's validity window
/// 3. The checkpoint signature is valid (signed by Rekor's key)
/// 4. The inclusion proof is valid (Merkle path from leaf to root)
/// 5. The certificate in the bundle matches the one in the Rekor entry
/// 6. The signature in the bundle matches the one in the Rekor entry
fn verify_rekor_entry(bundle: &serde_json::Value, cert_not_before: u64, cert_not_after: u64) -> Result<()> {
    use sha2::{Sha256, Digest};

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

    // Get inclusion proof (required for v0.2+ bundles)
    let inclusion_proof = entry.get("inclusionProof")
        .ok_or_else(|| Error::SigstoreVerification("Missing inclusion proof in tlog entry".into()))?;

    // Load Rekor public keys from trusted root
    let rekor_keys = load_rekor_keys()?;

    // Get the log ID from the entry to select the right key
    let log_id = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing logId in tlog entry".into()))?;

    // Find matching Rekor key
    let (_, key_der, key_type) = rekor_keys
        .iter()
        .find(|(id, _, _)| id == log_id)
        .ok_or_else(|| Error::SigstoreVerification(format!(
            "Unknown Rekor log ID: {}. Trusted log IDs: {:?}",
            log_id,
            rekor_keys.iter().map(|(id, _, _)| id.as_str()).collect::<Vec<_>>()
        )))?;

    // Get checkpoint (signed tree head)
    let checkpoint = inclusion_proof
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .and_then(|e| e.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing checkpoint in inclusion proof".into()))?;

    // Verify checkpoint signature
    verify_checkpoint_signature(checkpoint, key_der, key_type)?;

    // Get root hash from inclusion proof
    let root_hash_b64 = inclusion_proof
        .get("rootHash")
        .and_then(|r| r.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing rootHash in inclusion proof".into()))?;

    let root_hash = base64::engine::general_purpose::STANDARD
        .decode(root_hash_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode rootHash: {}", e)))?;

    // Get log index and tree size
    let log_index = inclusion_proof
        .get("logIndex")
        .and_then(|i| i.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| Error::SigstoreVerification("Missing logIndex in inclusion proof".into()))?;

    let tree_size = inclusion_proof
        .get("treeSize")
        .and_then(|t| t.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| Error::SigstoreVerification("Missing treeSize in inclusion proof".into()))?;

    // Get Merkle proof hashes
    let proof_hashes: Vec<Vec<u8>> = inclusion_proof
        .get("hashes")
        .and_then(|h| h.as_array())
        .ok_or_else(|| Error::SigstoreVerification("Missing hashes in inclusion proof".into()))?
        .iter()
        .filter_map(|h| h.as_str())
        .map(|s| base64::engine::general_purpose::STANDARD.decode(s))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode proof hash: {}", e)))?;

    // Compute leaf hash from canonicalizedBody
    let canonicalized_body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing canonicalizedBody in tlog entry".into()))?;

    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(canonicalized_body_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode canonicalizedBody: {}", e)))?;

    // Verify certificate binding: ensure the certificate in the bundle matches the one in the Rekor entry
    verify_certificate_binding(bundle, &body_bytes)?;

    // Verify signature binding: ensure the signature in the bundle matches the one in the Rekor entry
    verify_signature_binding(bundle, &body_bytes)?;

    // RFC 6962 leaf hash: SHA256(0x00 || data)
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00]);
    leaf_hasher.update(&body_bytes);
    let leaf_hash: [u8; 32] = leaf_hasher.finalize().into();

    // Verify Merkle inclusion proof
    verify_merkle_inclusion(&leaf_hash, log_index, tree_size, &proof_hashes, &root_hash)?;

    Ok(())
}

/// Verify checkpoint signature using the appropriate key type.
fn verify_checkpoint_signature(checkpoint: &str, key_der: &[u8], key_type: &str) -> Result<()> {
    // Parse checkpoint note format:
    // <origin>\n<tree_size>\n<root_hash_base64>\n[<extension_lines>]\n\n— <origin> <signature_base64>\n
    let parts: Vec<&str> = checkpoint.split("\n\n").collect();
    if parts.len() < 2 {
        return Err(Error::SigstoreVerification("Invalid checkpoint format: missing signature section".into()));
    }

    let note_body = parts[0];
    let signature_line = parts[1].trim();

    // Signature line format: "— <origin> <signature_base64>"
    if !signature_line.starts_with("— ") {
        return Err(Error::SigstoreVerification("Invalid checkpoint signature line format".into()));
    }

    let sig_parts: Vec<&str> = signature_line[4..].splitn(2, ' ').collect();
    if sig_parts.len() < 2 {
        return Err(Error::SigstoreVerification("Invalid checkpoint signature format".into()));
    }

    let signature_b64 = sig_parts[1].trim();
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode checkpoint signature: {}", e)))?;

    // The message to verify is the note body with a trailing newline
    let message = format!("{}\n", note_body);

    match key_type {
        "PKIX_ECDSA_P256_SHA_256" => {
            verify_ecdsa_p256_signature(message.as_bytes(), &signature_bytes, key_der)
        }
        "PKIX_ED25519" => {
            verify_ed25519_signature(message.as_bytes(), &signature_bytes, key_der)
        }
        _ => Err(Error::SigstoreVerification(format!(
            "Unsupported Rekor key type: {}", key_type
        ))),
    }
}

/// Verify ECDSA P-256 signature (for original Rekor log).
fn verify_ecdsa_p256_signature(message: &[u8], signature: &[u8], key_der: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use p256::pkcs8::DecodePublicKey;

    // Checkpoint signatures include a 4-byte key hint prefix
    if signature.len() < 4 {
        return Err(Error::SigstoreVerification("Checkpoint signature too short".into()));
    }
    let sig_bytes = &signature[4..];

    // Parse the public key from SPKI DER
    let verifying_key = VerifyingKey::from_public_key_der(key_der)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid Rekor ECDSA public key: {}", e)))?;

    // Parse the signature (DER-encoded)
    let sig = Signature::from_der(sig_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid ECDSA signature format: {}", e)))?;

    // Verify
    verifying_key.verify(message, &sig)
        .map_err(|_| Error::SigstoreVerification("Checkpoint ECDSA signature verification failed".into()))?;

    Ok(())
}

/// Verify Ed25519 signature (for Rekor log2025-1).
fn verify_ed25519_signature(message: &[u8], signature: &[u8], key_der: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};

    // Checkpoint signatures include a 4-byte key hint prefix
    if signature.len() < 4 + 64 {
        return Err(Error::SigstoreVerification("Ed25519 checkpoint signature too short".into()));
    }
    let sig_bytes = &signature[4..4 + 64];

    // Ed25519 public key in SPKI format: skip the SPKI header to get raw 32-byte key
    // SPKI for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
    if key_der.len() < 44 {
        return Err(Error::SigstoreVerification("Invalid Ed25519 SPKI key length".into()));
    }
    let raw_key = &key_der[key_der.len() - 32..];

    let verifying_key = VerifyingKey::try_from(raw_key)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid Rekor Ed25519 public key: {}", e)))?;

    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid Ed25519 signature format: {}", e)))?;

    verifying_key.verify(message, &sig)
        .map_err(|_| Error::SigstoreVerification("Checkpoint Ed25519 signature verification failed".into()))?;

    Ok(())
}

/// Verify RFC 6962 Merkle inclusion proof.
fn verify_merkle_inclusion(
    leaf_hash: &[u8; 32],
    index: u64,
    tree_size: u64,
    proof: &[Vec<u8>],
    expected_root: &[u8],
) -> Result<()> {
    use sha2::{Sha256, Digest};

    if index >= tree_size {
        return Err(Error::SigstoreVerification(format!(
            "Log index {} >= tree size {}", index, tree_size
        )));
    }

    let mut current_hash = *leaf_hash;
    let mut idx = index;
    let mut size = tree_size;

    for sibling in proof {
        if sibling.len() != 32 {
            return Err(Error::SigstoreVerification("Invalid proof hash length".into()));
        }

        // RFC 6962 interior node hash: SHA256(0x01 || left || right)
        let mut hasher = Sha256::new();
        hasher.update([0x01]);

        // Determine if current node is left or right child
        if idx % 2 == 0 && idx + 1 < size {
            // Current is left child
            hasher.update(current_hash);
            hasher.update(sibling);
        } else {
            // Current is right child
            hasher.update(sibling);
            hasher.update(current_hash);
        }

        current_hash = hasher.finalize().into();
        idx /= 2;
        size = (size + 1) / 2;
    }

    if current_hash.as_slice() != expected_root {
        return Err(Error::SigstoreVerification(
            "Merkle inclusion proof verification failed: computed root does not match".into()
        ));
    }

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
