//! Rekor transparency log verification.
//!
//! This module verifies that signatures and certificates were logged in
//! Rekor, Sigstore's transparency log, providing an immutable audit trail.

use sha2::{Sha256, Digest};

use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;
use super::trust;

/// Verify Rekor transparency log entry with full cryptographic verification.
///
/// This verifies:
/// 1. The tlog entry exists in the bundle
/// 2. The integrated time is within the certificate's validity window
/// 3. The checkpoint signature is valid (signed by Rekor's key)
/// 4. The inclusion proof is valid (Merkle path from leaf to root)
/// 5. The certificate in the bundle matches the one in the Rekor entry
/// 6. The signature in the bundle matches the one in the Rekor entry
pub fn verify_rekor_entry(bundle: &serde_json::Value, cert_not_before: u64, cert_not_after: u64) -> Result<()> {
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
    let rekor_keys = trust::load_rekor_keys()?;

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

    // Verify checkpoint signature and get the root hash from the signed body
    let checkpoint_root_hash = verify_checkpoint_signature(checkpoint, key_der, key_type)?;

    // Get root hash from inclusion proof
    let root_hash_b64 = inclusion_proof
        .get("rootHash")
        .and_then(|r| r.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing rootHash in inclusion proof".into()))?;

    let root_hash = decode_b64(root_hash_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode rootHash: {}", e)))?;

    // CRITICAL: Verify root hash from signed checkpoint matches inclusion proof.
    // This prevents substitution attacks where an attacker provides a valid signed
    // checkpoint but modifies the inclusion proof's root hash.
    // See: sigstore-python PR #634, checkpoint.py verify_checkpoint()
    if checkpoint_root_hash != root_hash {
        return Err(Error::SigstoreVerification(format!(
            "Inclusion proof contains invalid root hash: signed checkpoint has {}, inclusion proof has {}",
            hex::encode(&checkpoint_root_hash),
            hex::encode(&root_hash)
        )));
    }

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
        .map(decode_b64)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode proof hash: {}", e)))?;

    // Compute leaf hash from canonicalizedBody
    let canonicalized_body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing canonicalizedBody in tlog entry".into()))?;

    let body_bytes = decode_b64(canonicalized_body_b64)
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
            let verifier_pem_bytes = decode_b64(verifier_b64)
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
    let bundle_cert_der = decode_b64(bundle_cert_b64)
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

            decode_b64(sig_b64)
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

            decode_b64(sig_b64)
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

    let bundle_sig_bytes = decode_b64(bundle_sig_b64)
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
    decode_b64(&b64_content)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode PEM certificate: {}", e)))
}

/// Verify checkpoint signature and return the root hash from the signed body.
///
/// The checkpoint note format is:
/// ```text
/// <origin>
/// <tree_size>
/// <root_hash_base64>
/// [<extension_lines>]
///
/// — <origin> <signature_base64>
/// ```
///
/// Returns the root hash extracted from the signed checkpoint body.
/// This must be compared against the inclusion proof's root hash to prevent
/// substitution attacks (see sigstore-python PR #634).
fn verify_checkpoint_signature(checkpoint: &str, key_der: &[u8], key_type: &str) -> Result<Vec<u8>> {
    // Parse checkpoint note format:
    // <origin>\n<tree_size>\n<root_hash_base64>\n[<extension_lines>]\n\n— <origin> <signature_base64>\n
    let parts: Vec<&str> = checkpoint.split("\n\n").collect();
    if parts.len() < 2 {
        return Err(Error::SigstoreVerification("Invalid checkpoint format: missing signature section".into()));
    }

    let note_body = parts[0];
    let signature_line = parts[1].trim();

    // Parse the note body to extract root hash (line 3, 0-indexed line 2)
    let lines: Vec<&str> = note_body.lines().collect();
    if lines.len() < 3 {
        return Err(Error::SigstoreVerification(
            "Checkpoint note body must have at least 3 lines (origin, tree_size, root_hash)".into()
        ));
    }
    let checkpoint_root_hash = decode_b64(lines[2])
        .map_err(|e| Error::SigstoreVerification(
            format!("Failed to decode checkpoint root hash: {}", e)
        ))?;

    // Signature line format: "— <origin> <signature_base64>"
    if !signature_line.starts_with("— ") {
        return Err(Error::SigstoreVerification("Invalid checkpoint signature line format".into()));
    }

    let sig_parts: Vec<&str> = signature_line[4..].splitn(2, ' ').collect();
    if sig_parts.len() < 2 {
        return Err(Error::SigstoreVerification("Invalid checkpoint signature format".into()));
    }

    let signature_b64 = sig_parts[1].trim();
    let signature_bytes = decode_b64(signature_b64)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode checkpoint signature: {}", e)))?;

    // The message to verify is the note body with a trailing newline
    let message = format!("{}\n", note_body);

    match key_type {
        "PKIX_ECDSA_P256_SHA_256" => {
            verify_ecdsa_p256_signature(message.as_bytes(), &signature_bytes, key_der)?;
        }
        "PKIX_ED25519" => {
            verify_ed25519_signature(message.as_bytes(), &signature_bytes, key_der)?;
        }
        _ => {
            return Err(Error::SigstoreVerification(format!(
                "Unsupported Rekor key type: {}", key_type
            )));
        }
    }

    Ok(checkpoint_root_hash)
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
