//! Rekor transparency log verification.
//!
//! This module verifies that signatures and certificates were logged in
//! Rekor, Sigstore's transparency log, providing an immutable audit trail.

use super::checkpoint::SignedCheckpoint;
use super::dsse::compute_pae;
use super::merkle::rfc6962::Rfc6269HasherTrait;
use super::merkle::{MerkleProofVerifier, Rfc6269Default};
use super::trust::{self, RekorKey, TimestampAuthority};
use super::tsa;
use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;
use digest::Output;
use sha2::{Digest, Sha256};

/// Verify the bundle's Rekor entry with the embedded trust root: exactly one
/// entry; an observer timestamp inside the cert validity (SET-signed
/// `integratedTime` for v1 dsse/hashedrekord 0.0.1, RFC 3161 for v2
/// hashedrekord 0.0.2); checkpoint signature by the log's key under its name
/// and key hint; Merkle inclusion; body kind/version, certificate, signature
/// and payload (v1) or PAE (v2) digest bound to the bundle.
pub fn verify_rekor_entry(
    bundle: &serde_json::Value,
    cert_not_before: u64,
    cert_not_after: u64,
) -> Result<()> {
    verify_rekor_entry_with_trust(
        bundle,
        cert_not_before,
        cert_not_after,
        &trust::load_rekor_keys()?,
        &trust::load_timestamp_authorities()?,
    )
}

/// [`verify_rekor_entry`] against caller-supplied Rekor keys and timestamp authorities.
pub fn verify_rekor_entry_with_trust(
    bundle: &serde_json::Value,
    cert_not_before: u64,
    cert_not_after: u64,
    rekor_keys: &[RekorKey],
    timestamp_authorities: &[TimestampAuthority],
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

    let canonicalized_body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing canonicalizedBody in tlog entry".into())
        })?;

    let body_bytes = decode_b64(canonicalized_body_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode canonicalizedBody: {}", e))
    })?;

    verify_kind_version(entry, &body_bytes)?;
    let kind = entry["kindVersion"]["kind"].as_str().unwrap_or("");
    let version = entry["kindVersion"]["version"].as_str().unwrap_or("");

    // Unverifiable timestamps are skipped (sigstore-go); verified ones must sit inside cert validity.
    let (tsa_times, tsa_errors) = tsa::verify_timestamps(
        bundle,
        &bundle_dsse_signature(bundle)?,
        timestamp_authorities,
    )?;
    let no_timestamp = |what: &str| {
        let detail = if tsa_errors.is_empty() {
            " in bundle".to_string()
        } else {
            let joined: Vec<String> = tsa_errors.iter().map(|e| e.to_string()).collect();
            format!(" ({})", joined.join("; "))
        };
        Error::SigstoreVerification(format!("{what}: no verified RFC 3161 timestamp{detail}"))
    };
    for t in &tsa_times {
        if *t < cert_not_before || *t > cert_not_after {
            return Err(Error::SigstoreVerification(format!(
                "RFC 3161 timestamp {} is outside certificate validity window [{}, {}]",
                t, cert_not_before, cert_not_after
            )));
        }
    }

    // The observer time also selects which Rekor key (by validity period) may have signed.
    let observer_time = match (kind, version) {
        ("dsse" | "hashedrekord", "0.0.1") => {
            // Handle both JSON string (protobuf JSON int64 encoding) and JSON number formats.
            let integrated_time = entry
                .get("integratedTime")
                .and_then(|t| {
                    t.as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .or_else(|| t.as_u64())
                })
                .ok_or_else(|| {
                    Error::SigstoreVerification(
                        "Missing or invalid integratedTime in tlog entry".into(),
                    )
                })?;

            if integrated_time < cert_not_before || integrated_time > cert_not_after {
                return Err(Error::SigstoreVerification(format!(
                    "Rekor entry integrated time {} is outside certificate validity window [{}, {}]",
                    integrated_time, cert_not_before, cert_not_after
                )));
            }
            // integratedTime is only authenticated by the SET; without one a TSA time must anchor it.
            if entry
                .pointer("/inclusionPromise/signedEntryTimestamp")
                .is_none()
                && tsa_times.is_empty()
            {
                return Err(no_timestamp(
                    "Rekor v1 entry has no inclusion promise, cannot establish signing time",
                ));
            }
            integrated_time
        }
        // Rekor v2 logs DSSE as hashedrekord over the PAE (rekor-v2-spec §6.1.4).
        ("hashedrekord", "0.0.2") => *tsa_times.iter().min().ok_or_else(|| {
            no_timestamp("Rekor v2 entry has no integratedTime, an RFC 3161 timestamp is required")
        })?,
        _ => {
            return Err(Error::SigstoreVerification(format!(
                "Unsupported Rekor entry type: {kind}/{version}"
            )))
        }
    };

    // Get inclusion proof (required for v0.2+ bundles)
    let inclusion_proof = entry.get("inclusionProof").ok_or_else(|| {
        Error::SigstoreVerification("Missing inclusion proof in tlog entry".into())
    })?;

    // Get the log ID from the entry to select the right key
    let log_id = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|k| k.as_str())
        .ok_or_else(|| Error::SigstoreVerification("Missing logId in tlog entry".into()))?;
    let log_id_bytes = decode_b64(log_id)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode logId: {}", e)))?;

    // Find matching Rekor key that was valid at the observer time
    let rekor_key = rekor_keys
        .iter()
        .find(|k| {
            if k.key_id != log_id {
                return false;
            }
            // Check key was valid at observer_time (matches sigstore-browser checkpoint.ts)
            if let Some(from) = k.valid_from {
                if observer_time < from {
                    return false;
                }
            }
            if let Some(until) = k.valid_until {
                if observer_time > until {
                    return false;
                }
            }
            true
        })
        .ok_or_else(|| {
            Error::SigstoreVerification(format!(
                "No Rekor key valid at time {} for log ID: {}. Trusted log IDs: {:?}",
                observer_time,
                log_id,
                rekor_keys
                    .iter()
                    .map(|k| k.key_id.as_str())
                    .collect::<Vec<_>>()
            ))
        })?;

    // Get checkpoint (signed tree head), verify its signature, and extract root hash
    let checkpoint_str = inclusion_proof
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .and_then(|e| e.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification("Missing checkpoint in inclusion proof".into())
        })?;

    if version == "0.0.1" && entry.get("inclusionPromise").is_some() {
        verify_signed_entry_timestamp(entry, rekor_key)?;
    }

    let signed_checkpoint = SignedCheckpoint::decode(checkpoint_str)?;
    signed_checkpoint.verify_signature(
        &rekor_key.key_der,
        &rekor_key.key_type,
        &rekor_key.host,
        &log_id_bytes,
    )?;

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
        "hashedrekord" if entry.pointer("/spec/hashedRekordV002").is_some() => {
            let raw_b64 = entry
                .pointer("/spec/hashedRekordV002/signature/verifier/x509Certificate/rawBytes")
                .and_then(|r| r.as_str())
                .ok_or_else(|| Error::SigstoreVerification(
                    "Missing certificate in hashedrekord 0.0.2 Rekor entry (signature.verifier.x509Certificate.rawBytes)".into()
                ))?;
            decode_b64(raw_b64).map_err(|e| {
                Error::SigstoreVerification(format!(
                    "Failed to decode Rekor entry certificate: {}",
                    e
                ))
            })?
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
            // 0.0.1: spec.signature.content; 0.0.2 nests it under spec.hashedRekordV002
            let spec = entry.get("spec");
            let sig_b64 = spec
                .and_then(|s| s.get("hashedRekordV002").or(Some(s)))
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

    // Compare the signatures
    if rekor_signature_bytes != bundle_dsse_signature(bundle)? {
        return Err(Error::SigstoreVerification(
            "Signature mismatch: bundle signature does not match Rekor entry signature. \
             This could indicate a substitution attack."
                .into(),
        ));
    }

    Ok(())
}

/// Verify the Rekor v1 SET: the log's signature over canonical JSON
/// `{body, integratedTime, logID, logIndex}`. The Merkle leaf covers only the
/// body, so this is what authenticates `integratedTime`.
pub fn verify_signed_entry_timestamp(
    entry: &serde_json::Value,
    rekor_key: &RekorKey,
) -> Result<()> {
    let field = |ptr: &str| {
        entry
            .pointer(ptr)
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::SigstoreVerification(format!("Missing {ptr} in tlog entry")))
    };
    let int_field = |ptr: &str| -> Result<u64> {
        entry
            .pointer(ptr)
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| v.as_u64())
            })
            .ok_or_else(|| Error::SigstoreVerification(format!("Missing {ptr} in tlog entry")))
    };
    let log_id = decode_b64(field("/logId/keyId")?)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to decode logId: {}", e)))?;
    let set = decode_b64(field("/inclusionPromise/signedEntryTimestamp")?).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode signedEntryTimestamp: {}", e))
    })?;
    let payload = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        field("/canonicalizedBody")?,
        int_field("/integratedTime")?,
        hex::encode(log_id),
        int_field("/logIndex")?,
    );
    super::checkpoint::verify_log_signature(
        payload.as_bytes(),
        &set,
        &rekor_key.key_der,
        &rekor_key.key_type,
    )
    .map_err(|e| {
        Error::SigstoreVerification(format!(
            "Rekor signed entry timestamp (SET) did not verify: {e}"
        ))
    })
}

/// The bundle's DSSE signature bytes (`dsseEnvelope.signatures[0].sig`).
fn bundle_dsse_signature(bundle: &serde_json::Value) -> Result<Vec<u8>> {
    let sig_b64 = bundle
        .pointer("/dsseEnvelope/signatures/0/sig")
        .and_then(|s| s.as_str())
        .ok_or_else(|| {
            Error::SigstoreVerification(
                "Missing signature in bundle (dsseEnvelope.signatures[0].sig)".into(),
            )
        })?;
    decode_b64(sig_b64).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to decode bundle signature: {}", e))
    })
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

    let kind = body.get("kind").and_then(|k| k.as_str()).unwrap_or("");

    // Rekor v2 hashedrekord-over-DSSE: data.digest is SHA-256 of the DSSE PAE.
    if let Some(data) = body.pointer("/spec/hashedRekordV002/data") {
        let algorithm = data.get("algorithm").and_then(|a| a.as_str()).unwrap_or("");
        if algorithm != "SHA2_256" {
            return Err(Error::SigstoreVerification(format!(
                "Unsupported hashedrekord digest algorithm: {algorithm}. Expected SHA2_256"
            )));
        }
        let expected = data
            .get("digest")
            .and_then(|d| d.as_str())
            .ok_or_else(|| {
                Error::SigstoreVerification("hashedrekord 0.0.2 entry missing data.digest".into())
            })
            .and_then(|d| {
                decode_b64(d).map_err(|e| {
                    Error::SigstoreVerification(format!("Failed to decode data.digest: {}", e))
                })
            })?;
        let envelope = bundle.get("dsseEnvelope").ok_or_else(|| {
            Error::SigstoreVerification("Missing dsseEnvelope in bundle for hash check".into())
        })?;
        let payload_type = envelope
            .get("payloadType")
            .and_then(|t| t.as_str())
            .ok_or_else(|| Error::SigstoreVerification("Missing DSSE payloadType".into()))?;
        let payload = envelope
            .get("payload")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::SigstoreVerification("Missing DSSE payload".into()))
            .and_then(|p| {
                decode_b64(p).map_err(|e| {
                    Error::SigstoreVerification(format!("Failed to decode DSSE payload: {}", e))
                })
            })?;
        let actual = Sha256::digest(compute_pae(payload_type, &payload));
        if actual[..] != expected[..] {
            return Err(Error::SigstoreVerification(format!(
                "Payload hash mismatch: Rekor entry expects PAE digest {}, computed {}",
                hex::encode(&expected),
                hex::encode(actual)
            )));
        }
        return Ok(());
    }

    // Only applies to DSSE entries that have a payloadHash field
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

    #[test]
    fn test_set_tampered() {
        let mut bundle = parse_bundle();
        let set = &mut bundle["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]
            ["signedEntryTimestamp"];
        let mut raw = decode_b64(set.as_str().unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        *set = serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            raw,
        ));
        let e = verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).unwrap_err();
        assert!(e.to_string().contains("SET"), "{e}");
    }

    #[test]
    fn test_integrated_time_tampered_fails_set() {
        // integratedTime is not in the Merkle leaf; only the SET binds it.
        let mut bundle = parse_bundle();
        let entry = &mut bundle["verificationMaterial"]["tlogEntries"][0];
        let t: u64 = entry["integratedTime"].as_str().unwrap().parse().unwrap();
        entry["integratedTime"] = serde_json::Value::String((t + 1).to_string());
        let e = verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).unwrap_err();
        assert!(e.to_string().contains("SET"), "{e}");
    }

    #[test]
    fn test_v1_without_promise_or_timestamp_rejected() {
        let mut bundle = parse_bundle();
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionPromise");
        let e = verify_rekor_entry(&bundle, CERT_NOT_BEFORE, CERT_NOT_AFTER).unwrap_err();
        assert!(
            e.to_string().contains("cannot establish signing time"),
            "{e}"
        );
    }

    // --- Rekor v2 (hashedrekord 0.0.2 + RFC 3161 observer timestamp) ---

    const V2_BUNDLE: &str = include_str!("../../../assets/rekor2_dsse_test_bundle.json");
    const V2_TRUSTED_ROOT: &str = include_str!("../../../assets/rekor2_test_trusted_root.json");

    fn verify_v2(mutate: impl FnOnce(&mut serde_json::Value)) -> Result<()> {
        let mut bundle: serde_json::Value = serde_json::from_str(V2_BUNDLE).unwrap();
        mutate(&mut bundle);
        let (_, not_before, not_after) = super::super::extract_cert_with_validity(&bundle).unwrap();
        verify_rekor_entry_with_trust(
            &bundle,
            not_before,
            not_after,
            &trust::load_rekor_keys_from_json(V2_TRUSTED_ROOT).unwrap(),
            &trust::load_timestamp_authorities_from_json(V2_TRUSTED_ROOT).unwrap(),
        )
    }

    #[test]
    fn test_rekor_v2_entry_valid() {
        verify_v2(|_| {}).unwrap();
    }

    #[test]
    fn test_rekor_v2_requires_timestamp() {
        let e = verify_v2(|b| {
            b["verificationMaterial"]["timestampVerificationData"] = serde_json::json!({});
        })
        .unwrap_err();
        assert!(
            e.to_string().contains("RFC 3161 timestamp is required"),
            "{e}"
        );
    }

    #[test]
    fn test_rekor_v2_invalid_extra_timestamp_tolerated() {
        // sigstore-go semantics: an unverifiable extra timestamp is skipped as
        // long as one verified observer timestamp remains.
        verify_v2(|b| {
            b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"signedTimestamp": "AAAA"}));
        })
        .unwrap();
    }

    #[test]
    fn test_rekor_v2_timestamp_outside_cert_validity() {
        let bundle: serde_json::Value = serde_json::from_str(V2_BUNDLE).unwrap();
        let (_, not_before, _) = super::super::extract_cert_with_validity(&bundle).unwrap();
        let e = verify_rekor_entry_with_trust(
            &bundle,
            not_before,
            not_before, // window closes before the TSA genTime
            &trust::load_rekor_keys_from_json(V2_TRUSTED_ROOT).unwrap(),
            &trust::load_timestamp_authorities_from_json(V2_TRUSTED_ROOT).unwrap(),
        )
        .unwrap_err();
        assert!(
            e.to_string().contains("outside certificate validity"),
            "{e}"
        );
    }

    #[test]
    fn test_rekor_v2_payload_not_logged() {
        // Different payload → PAE digest no longer matches the logged hashedrekord.
        let e = verify_v2(|b| {
            b["dsseEnvelope"]["payload"] = serde_json::Value::String("e30=".into());
            // "{}"
        })
        .unwrap_err();
        assert!(e.to_string().contains("PAE digest"), "{e}");
    }

    #[test]
    fn test_rekor_v2_checkpoint_signer_name_mismatch() {
        let e = verify_v2(|b| {
            let env = &mut b["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
                ["checkpoint"]["envelope"];
            let s = env.as_str().unwrap().replace(
                "\u{2014} log2025-alpha3.rekor.sigstage.dev",
                "\u{2014} log2025-alpha3.rekor.github.dev",
            );
            *env = serde_json::Value::String(s);
        })
        .unwrap_err();
        assert!(e.to_string().contains("checkpoint signature"), "{e}");
    }

    #[test]
    fn test_rekor_v2_dsse_kind_unsupported() {
        let e = verify_v2(|b| {
            let entry = &mut b["verificationMaterial"]["tlogEntries"][0];
            entry["kindVersion"]["kind"] = serde_json::Value::String("dsse".into());
            let body = decode_b64(entry["canonicalizedBody"].as_str().unwrap()).unwrap();
            let body = String::from_utf8(body)
                .unwrap()
                .replacen("hashedrekord", "dsse", 1);
            entry["canonicalizedBody"] = serde_json::Value::String(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                body,
            ));
        })
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("Unsupported Rekor entry type: dsse/0.0.2"),
            "{e}"
        );
    }
}
