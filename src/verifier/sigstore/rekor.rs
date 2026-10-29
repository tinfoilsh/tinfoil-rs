//! Rekor transparency log verification.
//!
//! This module verifies that signatures and certificates were logged in
//! Rekor, Sigstore's transparency log, providing an immutable audit trail.

use super::checkpoint::SignedCheckpoint;
use super::merkle::rfc6962::Rfc6269HasherTrait;
use super::merkle::{MerkleProofVerifier, Rfc6269Default};
use super::trust;
use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;
use digest::Output;
use sha2::{Digest, Sha256};

/// Authenticate an observer timestamp, in addition to the inclusion evidence.
///
/// The inclusion proof authenticates the logged body, not the bundle's
/// `integratedTime` field. Freshness MUST use the timestamp covered by Rekor's
/// signed entry timestamp (SET). This is deliberately separate from the legacy
/// verifier so an old caller cannot accidentally treat an unchecked hint as an
/// authenticated timestamp.
pub(crate) fn verify_rekor_timestamp(
    bundle: &serde_json::Value,
    cert_not_before: u64,
    cert_not_after: u64,
) -> Result<u64> {
    verify_rekor_entry(bundle, cert_not_before, cert_not_after)?;
    let entry = &bundle["verificationMaterial"]["tlogEntries"][0];
    let integer = |name: &str| -> Result<u64> {
        entry[name]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| entry[name].as_u64())
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| Error::SigstoreVerification(format!("invalid Rekor {name}")))
    };
    let integrated_time = integer("integratedTime")?;
    // Rekor v1 SET signs the GLOBAL index. The inclusion proof below uses
    // its shard-local index; those counters intentionally need not be equal.
    // sigstore protobuf-specs v0.5.1 sigstore_rekor.proto defines both.
    let log_index = integer("logIndex")?;
    let log_id = entry["logId"]["keyId"]
        .as_str()
        .ok_or_else(|| Error::SigstoreVerification("missing Rekor key ID".into()))?;
    let keys = trust::load_rekor_keys()?;
    let key = keys
        .iter()
        .find(|k| {
            k.key_id == log_id
                && k.valid_from.is_none_or(|t| integrated_time >= t)
                && k.valid_until.is_none_or(|t| integrated_time <= t)
        })
        .ok_or_else(|| Error::SigstoreVerification("no trusted Rekor timestamp key".into()))?;
    let body = entry["canonicalizedBody"]
        .as_str()
        .ok_or_else(|| Error::SigstoreVerification("missing Rekor body".into()))?;
    let signature = decode_b64(
        entry["inclusionPromise"]["signedEntryTimestamp"]
            .as_str()
            .ok_or_else(|| {
                Error::SigstoreVerification(
                    "freshness requires Rekor signed entry timestamp".into(),
                )
            })?,
    )
    .map_err(|e| Error::SigstoreVerification(format!("invalid SET: {e}")))?;
    // Rekor's SET payload is RFC 8785 canonical JSON. These four values are
    // ASCII strings and nonnegative int64 values, so sorted compact JSON has
    // exactly the canonical representation (no floating point or Unicode).
    let payload = serde_json::json!({
        "body": body,
        "integratedTime": integrated_time,
        "logID": hex::encode(decode_b64(log_id).map_err(|e|
            Error::SigstoreVerification(format!("invalid Rekor log ID: {e}")))?),
        "logIndex": log_index,
    });
    let message = serde_json::to_vec(&payload)
        .map_err(|e| Error::SigstoreVerification(format!("encoding SET payload: {e}")))?;
    verify_set_signature(&message, &signature, &key.key_der, &key.key_type)?;

    // Both the proof root AND size must be authenticated by the checkpoint.
    let proof = &entry["inclusionProof"];
    let checkpoint = SignedCheckpoint::decode(
        proof["checkpoint"]["envelope"]
            .as_str()
            .ok_or_else(|| Error::SigstoreVerification("missing Rekor checkpoint".into()))?,
    )?;
    let proof_size = proof["treeSize"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| proof["treeSize"].as_u64())
        .ok_or_else(|| Error::SigstoreVerification("invalid Rekor proof tree size".into()))?;
    if checkpoint.note.size != proof_size {
        return Err(Error::SigstoreVerification(
            "Rekor checkpoint/proof tree size mismatch".into(),
        ));
    }
    Ok(integrated_time)
}

fn verify_set_signature(
    message: &[u8],
    signature: &[u8],
    key_der: &[u8],
    key_type: &str,
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    use p256::pkcs8::DecodePublicKey;
    let verified = match key_type {
        "PKIX_ECDSA_P256_SHA_256" => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(key_der)
                .map_err(|e| Error::SigstoreVerification(format!("invalid SET key: {e}")))?;
            let signature = p256::ecdsa::Signature::from_der(signature)
                .map_err(|e| Error::SigstoreVerification(format!("invalid SET signature: {e}")))?;
            key.verify(message, &signature).is_ok()
        }
        "PKIX_ED25519" => {
            use der::Decode;
            let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(key_der)
                .map_err(|e| Error::SigstoreVerification(format!("invalid SET key: {e}")))?;
            if spki.algorithm.oid.to_string() != "1.3.101.112"
                || spki.algorithm.parameters.is_some()
            {
                return Err(Error::SigstoreVerification(
                    "invalid Ed25519 SET key algorithm".into(),
                ));
            }
            let key = ed25519_dalek::VerifyingKey::try_from(spki.subject_public_key.raw_bytes())
                .map_err(|e| Error::SigstoreVerification(format!("invalid SET key: {e}")))?;
            let signature = ed25519_dalek::Signature::try_from(signature)
                .map_err(|e| Error::SigstoreVerification(format!("invalid SET signature: {e}")))?;
            key.verify_strict(message, &signature).is_ok()
        }
        _ => {
            return Err(Error::SigstoreVerification(
                "unsupported SET signature algorithm".into(),
            ))
        }
    };
    if !verified {
        return Err(Error::SigstoreVerification(
            "Rekor signed entry timestamp signature failed".into(),
        ));
    }
    Ok(())
}

/// Verify Rekor transparency log entry with full cryptographic verification.
///
/// This verifies:
/// 1. The tlog entry exists in the bundle (no duplicates)
/// 2. The integrated time is within the certificate's validity window
/// 3. The checkpoint signature is valid (signed by Rekor's key)
/// 4. The inclusion proof is valid (Merkle path from leaf to root)
/// 5. The entry body kind/version matches the metadata
/// 6. The certificate in the bundle matches the one in the Rekor entry
/// 7. The signature in the bundle matches the one in the Rekor entry
/// 8. The payload hash in the Rekor entry matches the DSSE payload
pub fn verify_rekor_entry(
    bundle: &serde_json::Value,
    cert_not_before: u64,
    cert_not_after: u64,
) -> Result<()> {
    // Get tlog entries from verification material
    let tlog_entries = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("tlogEntries"))
        .and_then(|t| t.as_array())
        .ok_or_else(|| Error::SigstoreVerification("No tlogEntries in bundle".into()))?;

    if tlog_entries.len() != 1 {
        return Err(Error::SigstoreVerification(format!(
            "Expected exactly 1 tlog entry, got {}",
            tlog_entries.len()
        )));
    }

    let entry = &tlog_entries[0];

    // Verify integrated time is within cert validity.
    // Handle both JSON string (protobuf JSON int64 encoding) and JSON number formats.
    let integrated_time = entry
        .get("integratedTime")
        .and_then(|t| {
            t.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| t.as_u64())
        })
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing or invalid integratedTime in tlog entry".into())
        })?;

    if integrated_time < cert_not_before || integrated_time > cert_not_after {
        return Err(Error::SigstoreVerification(format!(
            "Rekor entry integrated time {} is outside certificate validity window [{}, {}]",
            integrated_time, cert_not_before, cert_not_after
        )));
    }

    // Get inclusion proof (required for v0.2+ bundles)
    let inclusion_proof = entry.get("inclusionProof").ok_or_else(|| {
        Error::SigstoreVerification("Missing inclusion proof in tlog entry".into())
    })?;

    // Load Rekor public keys from trusted root
    let rekor_keys = trust::load_rekor_keys()?;

    // Get the log ID from the entry to select the right key
    let log_id = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing logId in tlog entry".into()))?;

    // Find matching Rekor key that was valid at the integrated time
    let rekor_key = rekor_keys
        .iter()
        .find(|k| {
            if k.key_id != log_id {
                return false;
            }
            // Check key was valid at integrated_time (matches sigstore-browser checkpoint.ts)
            if let Some(from) = k.valid_from {
                if integrated_time < from {
                    return false;
                }
            }
            if let Some(until) = k.valid_until {
                if integrated_time > until {
                    return false;
                }
            }
            true
        })
        .ok_or_else(|| {
            Error::SigstoreVerification(format!(
                "No Rekor key valid at time {} for log ID: {}. Trusted log IDs: {:?}",
                integrated_time,
                log_id,
                rekor_keys
                    .iter()
                    .map(|k| k.key_id.as_str())
                    .collect::<Vec<_>>()
            ))
        })?;
    let key_der = &rekor_key.key_der;
    let key_type = &rekor_key.key_type;

    // Get checkpoint (signed tree head), verify its signature, and extract root hash
    let checkpoint_str = inclusion_proof
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .and_then(|e| e.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing checkpoint in inclusion proof".into())
        })?;

    let signed_checkpoint = SignedCheckpoint::decode(checkpoint_str)?;
    signed_checkpoint.verify_signature(key_der, key_type)?;

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
    if signed_checkpoint.note.hash.as_slice() != root_hash.as_slice() {
        return Err(Error::SigstoreVerification(format!(
            "Inclusion proof contains invalid root hash: signed checkpoint has {}, inclusion proof has {}",
            hex::encode(signed_checkpoint.note.hash),
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
        .map(|h| {
            h.as_str().ok_or_else(|| {
                Error::SigstoreVerification("Non-string element in inclusion proof hashes".into())
            })
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .map(decode_b64)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode proof hash: {}", e)))?;

    // Compute leaf hash from canonicalizedBody
    let canonicalized_body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing canonicalizedBody in tlog entry".into())
        })?;

    let body_bytes = decode_b64(canonicalized_body_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode canonicalizedBody: {}", e))
    })?;

    // Verify the canonicalizedBody kind/version matches the entry's kindVersion metadata.
    // Prevents accepting a body that was re-interpreted under a different schema.
    verify_kind_version(entry, &body_bytes)?;

    // Verify certificate binding: ensure the certificate in the bundle matches the one in the Rekor entry
    verify_certificate_binding(bundle, &body_bytes)?;

    // Verify signature binding: ensure the signature in the bundle matches the one in the Rekor entry
    verify_signature_binding(bundle, &body_bytes)?;

    // Verify payload hash binding: ensure the DSSE payload hash in the Rekor entry
    // matches a fresh hash of the bundle's DSSE payload
    verify_payload_hash_binding(bundle, &body_bytes)?;

    // RFC 6962 leaf hash: SHA256(0x00 || data)
    let leaf_hash = Rfc6269Default::hash_leaf(&body_bytes);

    // Convert proof hashes from Vec<Vec<u8>> to Vec<Output<Sha256>>
    let proof_outputs: Vec<Output<Sha256>> = proof_hashes
        .iter()
        .map(|h| {
            <[u8; 32]>::try_from(h.as_slice())
                .map(Into::into)
                .map_err(|_| {
                    Error::SigstoreVerification(
                        "Invalid proof hash length (expected 32 bytes)".into(),
                    )
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let root_output: Output<Sha256> = <[u8; 32]>::try_from(root_hash.as_slice())
        .map(Into::into)
        .map_err(|_| {
            Error::SigstoreVerification("Invalid root hash length (expected 32 bytes)".into())
        })?;

    // Verify Merkle inclusion proof using RFC 6962 two-phase decomposition
    Rfc6269Default::verify_inclusion(
        log_index,
        &leaf_hash,
        tree_size,
        &proof_outputs,
        &root_output,
    )
    .map_err(|e| {
        Error::SigstoreVerification(format!("Merkle inclusion proof verification failed: {}", e))
    })?;

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
    let entry: serde_json::Value = serde_json::from_slice(canonicalized_body).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e))
    })?;

    // Determine the entry kind and extract certificate accordingly
    let kind = entry
        .get("kind")
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
                .ok_or_else(|| {
                    Error::SigstoreVerification(
                        "Missing certificate in DSSE Rekor entry (spec.signatures[0].verifier)"
                            .into(),
                    )
                })?;

            // Decode base64 to get PEM string
            let verifier_pem_bytes = decode_b64(verifier_b64).map_err(|e| {
                Error::SigstoreVerification(format!("Failed to decode verifier: {}", e))
            })?;

            let verifier_pem = String::from_utf8(verifier_pem_bytes).map_err(|e| {
                Error::SigstoreVerification(format!("Invalid UTF-8 in verifier: {}", e))
            })?;

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
                "Unknown Rekor entry kind: {}. Expected 'dsse' or 'hashedrekord'",
                kind
            )));
        }
    };

    // Get certificate from bundle (base64-encoded DER in verificationMaterial.certificate.rawBytes)
    let bundle_cert_b64 = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("certificate"))
        .and_then(|c| c.get("rawBytes"))
        .and_then(|rb| rb.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification(
                "Missing certificate in bundle (verificationMaterial.certificate.rawBytes)".into(),
            )
        })?;

    // Decode the bundle certificate from base64
    let bundle_cert_der = decode_b64(bundle_cert_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode bundle certificate: {}", e))
    })?;

    // Compare the DER bytes
    if rekor_cert_der != bundle_cert_der {
        return Err(Error::SigstoreVerification(
            "Certificate mismatch: bundle certificate does not match Rekor entry certificate. \
             This could indicate a substitution attack."
                .into(),
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
    let entry: serde_json::Value = serde_json::from_slice(canonicalized_body).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e))
    })?;

    // Determine the entry kind and extract signature accordingly
    let kind = entry
        .get("kind")
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
                .ok_or_else(|| {
                    Error::SigstoreVerification(
                        "Missing signature in DSSE Rekor entry (spec.signatures[0].signature)"
                            .into(),
                    )
                })?;

            decode_b64(sig_b64).map_err(|e| {
                Error::SigstoreVerification(format!("Failed to decode Rekor signature: {}", e))
            })?
        }
        "hashedrekord" => {
            // hashedrekord format: spec.signature.content contains base64-encoded signature
            let sig_b64 = entry
                .get("spec")
                .and_then(|s| s.get("signature"))
                .and_then(|s| s.get("content"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| {
                    Error::SigstoreVerification(
                        "Missing signature in hashedrekord Rekor entry (spec.signature.content)"
                            .into(),
                    )
                })?;

            decode_b64(sig_b64).map_err(|e| {
                Error::SigstoreVerification(format!("Failed to decode Rekor signature: {}", e))
            })?
        }
        _ => {
            return Err(Error::SigstoreVerification(format!(
                "Unknown Rekor entry kind: {}. Expected 'dsse' or 'hashedrekord'",
                kind
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
        .ok_or_else(|| {
            Error::SigstoreVerification(
                "Missing signature in bundle (dsseEnvelope.signatures[0].sig)".into(),
            )
        })?;

    let bundle_sig_bytes = decode_b64(bundle_sig_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode bundle signature: {}", e))
    })?;

    // Compare the signatures
    if rekor_signature_bytes != bundle_sig_bytes {
        return Err(Error::SigstoreVerification(
            "Signature mismatch: bundle signature does not match Rekor entry signature. \
             This could indicate a substitution attack."
                .into(),
        ));
    }

    Ok(())
}

/// Verify that the canonicalizedBody's kind and apiVersion match the entry's kindVersion metadata.
/// This prevents accepting a body that was re-interpreted under a different Rekor entry schema.
fn verify_kind_version(entry: &serde_json::Value, canonicalized_body: &[u8]) -> Result<()> {
    let kind_version = match entry.get("kindVersion") {
        Some(kv) => kv,
        None => {
            return Err(Error::SigstoreVerification(
                "Missing kindVersion in tlog entry metadata".into(),
            ));
        }
    };

    let expected_kind = kind_version.get("kind").and_then(|k| k.as_str());
    let expected_version = kind_version.get("version").and_then(|v| v.as_str());

    let body: serde_json::Value = serde_json::from_slice(canonicalized_body).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e))
    })?;

    let body_kind = body.get("kind").and_then(|k| k.as_str());
    let body_version = body.get("apiVersion").and_then(|v| v.as_str());

    if body_kind != expected_kind || body_version != expected_version {
        return Err(Error::SigstoreVerification(format!(
            "Tlog entry kind/version mismatch: body has {:?}/{:?}, metadata has {:?}/{:?}",
            body_kind, body_version, expected_kind, expected_version
        )));
    }

    Ok(())
}

/// Verify that the DSSE payload hash in the Rekor entry matches the bundle's DSSE payload.
/// This cross-check ensures the Rekor entry was created for this exact payload, preventing
/// an attacker from binding a valid signature to a different payload.
fn verify_payload_hash_binding(
    bundle: &serde_json::Value,
    canonicalized_body: &[u8],
) -> Result<()> {
    let body: serde_json::Value = serde_json::from_slice(canonicalized_body).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to parse canonicalizedBody: {}", e))
    })?;

    // Only applies to DSSE entries that have a payloadHash field
    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");
    if kind != "dsse" {
        return Ok(());
    }

    let payload_hash_obj = match body.get("spec").and_then(|s| s.get("payloadHash")) {
        Some(h) => h,
        None => {
            return Err(Error::SigstoreVerification(
                "DSSE Rekor entry missing required payloadHash field".into(),
            ));
        }
    };

    let expected_hash = match payload_hash_obj.get("value").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => {
            return Err(Error::SigstoreVerification(
                "Malformed payloadHash: object present but missing 'value' field".into(),
            ));
        }
    };

    let algorithm = payload_hash_obj
        .get("algorithm")
        .and_then(|a| a.as_str())
        .unwrap_or("");
    if algorithm != "sha256" {
        return Err(Error::SigstoreVerification(format!(
            "Unsupported payload hash algorithm: {algorithm}. Expected sha256"
        )));
    }

    // Get the DSSE payload from the bundle and compute its hash
    let payload_b64 = bundle
        .get("dsseEnvelope")
        .and_then(|d| d.get("payload"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing DSSE payload in bundle for hash check".into())
        })?;

    let payload = decode_b64(payload_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode DSSE payload: {}", e))
    })?;

    let actual_hash = hex::encode(Sha256::digest(&payload));

    if actual_hash != expected_hash {
        return Err(Error::SigstoreVerification(format!(
            "Payload hash mismatch: Rekor entry expects {}, computed {}",
            expected_hash, actual_hash
        )));
    }

    Ok(())
}

/// Parse a PEM-encoded certificate and return the DER bytes.
fn parse_pem_certificate(pem_str: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_str)
        .map_err(|e| Error::SigstoreVerification(format!("Invalid PEM certificate: {}", e)))?;
    Ok(parsed.into_contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE_JSON: &str = include_str!("../../../assets/rekor_test_bundle.json");

    // Certificate validity window extracted from the test bundle's certificate.
    // notBefore=Mar 26 18:04:46 2026 GMT -> 1774548286
    // notAfter=Mar 26 18:14:46 2026 GMT  -> 1774548886
    const CERT_NOT_BEFORE: u64 = 1774548286;
    const CERT_NOT_AFTER: u64 = 1774548886;

    fn parse_bundle() -> serde_json::Value {
        serde_json::from_str(BUNDLE_JSON).expect("parse test bundle")
    }

    #[test]
    fn signed_timestamp_covers_time_index_and_body() {
        use p256::ecdsa::{signature::Signer, SigningKey};
        use p256::pkcs8::EncodePublicKey;
        let key = SigningKey::from_slice(&[42; 32]).unwrap();
        let public = key.verifying_key().to_public_key_der().unwrap();
        let message = br#"{"body":"YWJj","integratedTime":123,"logID":"abcd","logIndex":7}"#;
        let signature: p256::ecdsa::DerSignature = key.sign(message);
        assert!(verify_set_signature(
            message,
            signature.as_bytes(),
            public.as_bytes(),
            "PKIX_ECDSA_P256_SHA_256"
        )
        .is_ok());
        for modified in [
            br#"{"body":"YWJj","integratedTime":124,"logID":"abcd","logIndex":7}"#.as_slice(),
            br#"{"body":"YWJj","integratedTime":123,"logID":"abcd","logIndex":8}"#.as_slice(),
            br#"{"body":"ZXZpbA==","integratedTime":123,"logID":"abcd","logIndex":7}"#.as_slice(),
        ] {
            assert!(verify_set_signature(
                modified,
                signature.as_bytes(),
                public.as_bytes(),
                "PKIX_ECDSA_P256_SHA_256"
            )
            .is_err());
        }
    }

    #[test]
    fn missing_or_changed_set_cannot_be_used_as_authenticated_time() {
        let mut bundle = parse_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"] =
            serde_json::json!({});
        assert!(verify_rekor_timestamp(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err());
        let mut bundle = parse_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]["integratedTime"] =
            serde_json::json!((CERT_NOT_BEFORE + 1).to_string());
        assert!(verify_rekor_timestamp(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err());
    }

    #[test]
    fn test_verify_rekor_entry_valid() {
        let bundle = parse_bundle();
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_ok(),
            "valid bundle should pass verification"
        );
    }

    #[test]
    fn test_modified_certificate() {
        let mut bundle = parse_bundle();
        // Replace the certificate with a different base64 string
        bundle["verificationMaterial"]["certificate"]["rawBytes"] =
            serde_json::Value::String("dGFtcGVyZWQ=".to_string()); // "tampered" in base64
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified certificate should fail cert binding"
        );
    }

    #[test]
    fn test_modified_signature() {
        let mut bundle = parse_bundle();
        // Alter the DSSE signature
        let sig = bundle["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .unwrap()
            .to_string();
        // Flip a character in the base64 signature
        let mut tampered = sig.into_bytes();
        if let Some(b) = tampered.get_mut(10) {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        bundle["dsseEnvelope"]["signatures"][0]["sig"] =
            serde_json::Value::String(String::from_utf8(tampered).unwrap());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified signature should fail signature binding"
        );
    }

    #[test]
    fn test_modified_payload() {
        let mut bundle = parse_bundle();
        // Tamper with the DSSE payload (changes its hash)
        let payload = bundle["dsseEnvelope"]["payload"]
            .as_str()
            .unwrap()
            .to_string();
        let mut tampered = payload.into_bytes();
        if let Some(b) = tampered.get_mut(5) {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        bundle["dsseEnvelope"]["payload"] =
            serde_json::Value::String(String::from_utf8(tampered).unwrap());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified payload should fail payload hash binding"
        );
    }

    #[test]
    fn test_modified_checkpoint() {
        let mut bundle = parse_bundle();
        // Corrupt the checkpoint envelope
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]
            ["envelope"] = serde_json::Value::String("corrupted checkpoint".to_string());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified checkpoint should fail checkpoint signature"
        );
    }

    #[test]
    fn test_modified_root_hash() {
        let mut bundle = parse_bundle();
        // Swap first and second half of the root hash
        let root = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"]
            .as_str()
            .unwrap()
            .to_string();
        let mut tampered =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &root).unwrap();
        // Flip a byte
        tampered[0] ^= 0xFF;
        let new_root =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tampered);
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["rootHash"] =
            serde_json::Value::String(new_root);
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified root hash should fail cross-check"
        );
    }

    #[test]
    fn test_modified_log_index() {
        let mut bundle = parse_bundle();
        let idx = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["logIndex"]
            .as_str()
            .unwrap()
            .to_string();
        let new_idx: u64 = idx.parse::<u64>().unwrap() + 1;
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["logIndex"] =
            serde_json::Value::String(new_idx.to_string());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified log index should fail Merkle inclusion"
        );
    }

    #[test]
    fn test_modified_tree_size() {
        let mut bundle = parse_bundle();
        let size = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["treeSize"]
            .as_str()
            .unwrap()
            .to_string();
        // Double the tree size to definitely break the proof decomposition
        let new_size: u64 = size.parse::<u64>().unwrap() * 2;
        bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["treeSize"] =
            serde_json::Value::String(new_size.to_string());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified tree size should fail Merkle inclusion"
        );
    }

    #[test]
    fn test_modified_kind_version() {
        let mut bundle = parse_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]["kindVersion"]["kind"] =
            serde_json::Value::String("hashedrekord".to_string());
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "modified kind should fail kind/version check"
        );
    }

    #[test]
    fn test_time_outside_window() {
        let bundle = parse_bundle();
        // Set cert validity window that excludes the integrated time
        // The real integrated time is 1774548286, so set window far in the future
        assert!(
            verify_rekor_entry(&bundle, 2000000000, 2000000600).is_err(),
            "integrated time outside cert window should fail"
        );
    }

    #[test]
    fn test_multiple_tlog_entries() {
        let mut bundle = parse_bundle();
        // Duplicate the tlog entry
        let entry = bundle["verificationMaterial"]["tlogEntries"][0].clone();
        bundle["verificationMaterial"]["tlogEntries"]
            .as_array_mut()
            .unwrap()
            .push(entry);
        assert!(
            verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).is_err(),
            "multiple tlog entries should be rejected"
        );
    }
}
