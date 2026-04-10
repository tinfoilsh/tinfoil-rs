/// Sigstore conformance test CLI for tinfoil-rs.
///
/// Implements the sigstore-conformance CLI protocol for `verify-bundle`.
/// See: https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md
use std::{env, fs, process};

use der::Decode;
use digest::Output;
use p256::ecdsa::{
    signature::{hazmat::PrehashVerifier, Verifier as _},
    Signature as P256Signature, VerifyingKey,
};

/// Curve OID constants
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

/// Public key info: raw bytes + curve OID string
struct PubKeyInfo {
    raw_bytes: Vec<u8>,
    curve_oid: Option<String>,
}
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use tinfoil::verifier::sigstore::checkpoint::SignedCheckpoint;
use tinfoil::verifier::sigstore::dsse::compute_pae;
use tinfoil::verifier::sigstore::merkle::rfc6962::Rfc6269HasherTrait;
use tinfoil::verifier::sigstore::merkle::{MerkleProofVerifier, Rfc6269Default};
use tinfoil::verifier::sigstore::trust;
use tinfoil::verifier::util::decode_b64;

const DEFAULT_TRUSTED_ROOT: &str = include_str!("../../assets/trusted_root.json");

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <sign-bundle|verify-bundle> [options]", args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "sign-bundle" => {
            eprintln!("sign-bundle not implemented");
            process::exit(1);
        }
        "verify-bundle" => {
            if let Err(e) = verify_bundle(&args[2..]) {
                eprintln!("Verification failed: {e}");
                process::exit(1);
            }
        }
        other => {
            eprintln!("Unknown subcommand: {other}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct VerifyArgs {
    #[allow(dead_code)]
    staging: bool,
    bundle_path: String,
    certificate_identity: Option<String>,
    certificate_oidc_issuer: Option<String>,
    key_path: Option<String>,
    trusted_root_path: Option<String>,
    artifact: String,
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    let mut staging = false;
    let mut bundle_path = None;
    let mut cert_identity = None;
    let mut cert_issuer = None;
    let mut key_path = None;
    let mut trusted_root = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--staging" => staging = true,
            "--bundle" => {
                i += 1;
                bundle_path = Some(args.get(i).ok_or("--bundle requires a value")?.clone());
            }
            "--certificate-identity" => {
                i += 1;
                cert_identity =
                    Some(args.get(i).ok_or("--certificate-identity requires a value")?.clone());
            }
            "--certificate-oidc-issuer" => {
                i += 1;
                cert_issuer = Some(
                    args.get(i)
                        .ok_or("--certificate-oidc-issuer requires a value")?
                        .clone(),
                );
            }
            "--key" => {
                i += 1;
                key_path = Some(args.get(i).ok_or("--key requires a value")?.clone());
            }
            "--trusted-root" => {
                i += 1;
                trusted_root =
                    Some(args.get(i).ok_or("--trusted-root requires a value")?.clone());
            }
            _ if !args[i].starts_with("--") => {
                return Ok(VerifyArgs {
                    staging,
                    bundle_path: bundle_path.ok_or("--bundle is required")?,
                    certificate_identity: cert_identity,
                    certificate_oidc_issuer: cert_issuer,
                    key_path,
                    trusted_root_path: trusted_root,
                    artifact: args[i].clone(),
                });
            }
            other => return Err(format!("Unknown option: {other}")),
        }
        i += 1;
    }

    Err("Missing positional artifact argument".into())
}

// ---------------------------------------------------------------------------
// Main verification flow
// ---------------------------------------------------------------------------

fn verify_bundle(args: &[String]) -> Result<(), String> {
    let vargs = parse_verify_args(args)?;

    // 1. Load and parse bundle
    let bundle_json =
        fs::read_to_string(&vargs.bundle_path).map_err(|e| format!("Read bundle: {e}"))?;
    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| format!("Parse bundle JSON: {e}"))?;

    // 2. Load trusted root
    let tr_json = match &vargs.trusted_root_path {
        Some(path) => fs::read_to_string(path).map_err(|e| format!("Read trusted root: {e}"))?,
        None => DEFAULT_TRUSTED_ROOT.to_string(),
    };

    // 3. Determine bundle signature type
    let has_msg_sig = bundle.get("messageSignature").is_some();
    let has_dsse = bundle.get("dsseEnvelope").is_some();
    if !has_msg_sig && !has_dsse {
        return Err("Bundle has neither messageSignature nor dsseEnvelope".into());
    }

    // 4. Determine verification mode (certificate-based vs key-based)
    let is_key_based = vargs.key_path.is_some();

    // 5. Extract leaf certificate (for cert-based)
    let cert_der = if !is_key_based {
        Some(extract_leaf_cert_der(&bundle)?)
    } else {
        None
    };

    // 6. Resolve artifact SHA256 digest
    let artifact_sha256 = resolve_artifact_sha256(&vargs.artifact)?;

    // 7. Verify signature
    if has_msg_sig {
        verify_message_signature(&bundle, cert_der.as_deref(), vargs.key_path.as_deref())?;
    } else {
        verify_dsse_signature(&bundle, cert_der.as_deref(), vargs.key_path.as_deref())?;
    }

    // 8. Certificate identity verification
    if let Some(ref cert_bytes) = cert_der {
        let cert = Certificate::from_der(cert_bytes).map_err(|e| format!("Parse cert: {e}"))?;

        // Verify SAN matches expected identity
        if let Some(ref identity) = vargs.certificate_identity {
            verify_cert_san(&cert, identity)?;
        }
        // Verify OIDC issuer extension matches
        if let Some(ref issuer) = vargs.certificate_oidc_issuer {
            verify_cert_oidc_issuer(&cert, issuer)?;
        }
        // Validate certificate extensions (KeyUsage + ExtKeyUsage)
        tinfoil::verifier::sigstore::certificate::validate_certificate_extensions(&cert)
            .map_err(|e| format!("Certificate validation: {e}"))?;
    }

    // 9. Verify Rekor transparency log entry
    verify_rekor_entry(
        &bundle,
        &tr_json,
        cert_der.as_deref(),
        vargs.key_path.as_deref(),
        has_dsse,
    )?;

    // 10. Verify Fulcio certificate chain (cert-based only)
    if let Some(ref cert_bytes) = cert_der {
        verify_fulcio_chain(cert_bytes, &tr_json)?;
    }

    // 11. Verify artifact digest matches bundle content
    verify_artifact_digest(&bundle, &artifact_sha256, has_msg_sig, &vargs.artifact)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Certificate extraction
// ---------------------------------------------------------------------------

fn extract_leaf_cert_der(bundle: &serde_json::Value) -> Result<Vec<u8>, String> {
    let vm = bundle
        .get("verificationMaterial")
        .ok_or("Missing verificationMaterial")?;

    // v0.3: single certificate
    if let Some(cert_b64) = vm
        .get("certificate")
        .and_then(|c| c.get("rawBytes"))
        .and_then(|r| r.as_str())
    {
        return decode_b64(cert_b64).map_err(|e| format!("Decode certificate: {e}"));
    }

    // v0.1: certificate chain
    if let Some(certs) = vm
        .get("x509CertificateChain")
        .and_then(|c| c.get("certificates"))
        .and_then(|c| c.as_array())
    {
        if certs.is_empty() {
            return Err("Empty certificate chain".into());
        }
        let cert_b64 = certs[0]
            .get("rawBytes")
            .and_then(|r| r.as_str())
            .ok_or("Missing rawBytes in certificate chain")?;
        return decode_b64(cert_b64).map_err(|e| format!("Decode certificate: {e}"));
    }

    Err("No certificate in verificationMaterial".into())
}

// ---------------------------------------------------------------------------
// Artifact digest resolution
// ---------------------------------------------------------------------------

fn resolve_artifact_sha256(artifact: &str) -> Result<Vec<u8>, String> {
    // Check if it's a sha256:hex digest
    if let Some(hex_str) = artifact.strip_prefix("sha256:") {
        if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            // Check it's not also a file on disk
            if !std::path::Path::new(artifact).exists() {
                return hex::decode(hex_str).map_err(|e| format!("Decode hex digest: {e}"));
            }
        }
    }

    // Otherwise read file and compute SHA256
    let data = fs::read(artifact).map_err(|e| format!("Read artifact '{artifact}': {e}"))?;
    Ok(Sha256::digest(&data).to_vec())
}

// ---------------------------------------------------------------------------
// Message signature verification
// ---------------------------------------------------------------------------

fn verify_message_signature(
    bundle: &serde_json::Value,
    cert_der: Option<&[u8]>,
    key_path: Option<&str>,
) -> Result<(), String> {
    let msg_sig = bundle.get("messageSignature").ok_or("Missing messageSignature")?;
    let sig_b64 = msg_sig
        .get("signature")
        .and_then(|s| s.as_str())
        .ok_or("Missing signature in messageSignature")?;
    let sig_bytes = decode_b64(sig_b64).map_err(|e| format!("Decode signature: {e}"))?;

    let digest_b64 = msg_sig
        .get("messageDigest")
        .and_then(|d| d.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or("Missing messageDigest.digest")?;
    let digest_bytes = decode_b64(digest_b64).map_err(|e| format!("Decode digest: {e}"))?;

    let key_info = get_verifying_key_info(bundle, cert_der, key_path)?;

    match key_info.curve_oid.as_deref() {
        Some(OID_P384) => {
            let verifying_key =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&key_info.raw_bytes)
                    .map_err(|e| format!("Invalid P384 public key: {e}"))?;
            let signature = if sig_bytes.first() == Some(&0x30) {
                p384::ecdsa::Signature::from_der(&sig_bytes)
            } else {
                p384::ecdsa::Signature::from_slice(&sig_bytes)
            }
            .map_err(|e| format!("Invalid signature: {e}"))?;
            p384::ecdsa::signature::hazmat::PrehashVerifier::verify_prehash(
                &verifying_key,
                &digest_bytes,
                &signature,
            )
            .map_err(|e| format!("Message signature verification failed: {e}"))
        }
        _ => {
            // Default to P256
            let verifying_key = VerifyingKey::from_sec1_bytes(&key_info.raw_bytes)
                .map_err(|e| format!("Invalid public key: {e}"))?;
            let signature = if sig_bytes.first() == Some(&0x30) {
                P256Signature::from_der(&sig_bytes)
            } else {
                P256Signature::from_slice(&sig_bytes)
            }
            .map_err(|e| format!("Invalid signature: {e}"))?;
            verifying_key
                .verify_prehash(&digest_bytes, &signature)
                .map_err(|e| format!("Message signature verification failed: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// DSSE signature verification
// ---------------------------------------------------------------------------

fn verify_dsse_signature(
    bundle: &serde_json::Value,
    cert_der: Option<&[u8]>,
    key_path: Option<&str>,
) -> Result<(), String> {
    let dsse = bundle.get("dsseEnvelope").ok_or("Missing dsseEnvelope")?;

    let payload_type = dsse
        .get("payloadType")
        .and_then(|v| v.as_str())
        .ok_or("Missing payloadType")?;
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or("Missing payload")?;
    let signatures = dsse
        .get("signatures")
        .and_then(|s| s.as_array())
        .ok_or("Missing signatures array")?;

    if signatures.is_empty() {
        return Err("DSSE envelope has no signatures".into());
    }

    let sig_b64 = signatures[0]
        .get("sig")
        .and_then(|s| s.as_str())
        .ok_or("Missing sig in DSSE signature")?;

    let payload = decode_b64(payload_b64).map_err(|e| format!("Decode DSSE payload: {e}"))?;
    let sig_bytes = decode_b64(sig_b64).map_err(|e| format!("Decode DSSE signature: {e}"))?;

    let pae = compute_pae(payload_type, &payload);

    let key_info = get_verifying_key_info(bundle, cert_der, key_path)?;

    match key_info.curve_oid.as_deref() {
        Some(OID_P384) => {
            let verifying_key =
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&key_info.raw_bytes)
                    .map_err(|e| format!("Invalid P384 public key: {e}"))?;
            let signature = if sig_bytes.first() == Some(&0x30) {
                p384::ecdsa::Signature::from_der(&sig_bytes)
            } else {
                p384::ecdsa::Signature::from_slice(&sig_bytes)
            }
            .map_err(|e| format!("Invalid DSSE signature: {e}"))?;
            p384::ecdsa::signature::Verifier::verify(&verifying_key, &pae, &signature)
                .map_err(|e| format!("DSSE signature verification failed: {e}"))
        }
        _ => {
            // Default to P256
            let verifying_key = VerifyingKey::from_sec1_bytes(&key_info.raw_bytes)
                .map_err(|e| format!("Invalid public key: {e}"))?;
            let signature = if sig_bytes.first() == Some(&0x30) {
                P256Signature::from_der(&sig_bytes)
            } else {
                P256Signature::from_slice(&sig_bytes)
            }
            .map_err(|e| format!("Invalid DSSE signature: {e}"))?;
            verifying_key
                .verify(&pae, &signature)
                .map_err(|e| format!("DSSE signature verification failed: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Public key extraction
// ---------------------------------------------------------------------------

fn get_verifying_key_info(
    bundle: &serde_json::Value,
    cert_der: Option<&[u8]>,
    key_path: Option<&str>,
) -> Result<PubKeyInfo, String> {
    if let Some(cert_bytes) = cert_der {
        let cert =
            Certificate::from_der(cert_bytes).map_err(|e| format!("Parse certificate: {e}"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let curve_oid = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
            .map(|oid| oid.to_string());
        Ok(PubKeyInfo {
            raw_bytes: spki.subject_public_key.raw_bytes().to_vec(),
            curve_oid,
        })
    } else if let Some(path) = key_path {
        let pem_str = fs::read_to_string(path).map_err(|e| format!("Read key file: {e}"))?;
        let parsed = pem::parse(&pem_str).map_err(|e| format!("Parse PEM key: {e}"))?;
        extract_ec_pubkey_info_from_spki(&parsed.into_contents())
    } else if let Some(_hint) = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("publicKey"))
        .and_then(|pk| pk.get("hint"))
    {
        // Key-based bundle but no --key provided
        Err("Key-based bundle requires --key argument".into())
    } else {
        Err("No certificate or key available for signature verification".into())
    }
}

fn extract_ec_pubkey_info_from_spki(spki_der: &[u8]) -> Result<PubKeyInfo, String> {
    let spki = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(spki_der)
        .map_err(|e| format!("Parse SPKI: {e}"))?;
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
        .map(|oid| oid.to_string());
    Ok(PubKeyInfo {
        raw_bytes: spki.subject_public_key.raw_bytes().to_vec(),
        curve_oid,
    })
}

// ---------------------------------------------------------------------------
// Certificate identity verification
// ---------------------------------------------------------------------------

fn verify_cert_san(cert: &Certificate, expected_identity: &str) -> Result<(), String> {
    use x509_cert::ext::pkix::SubjectAltName;

    let san = cert
        .tbs_certificate
        .get::<SubjectAltName>()
        .map_err(|e| format!("Parse SAN: {e}"))?
        .ok_or("Certificate missing SubjectAltName")?;

    for name in san.1 .0.iter() {
        match name {
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) => {
                if uri.as_str() == expected_identity {
                    return Ok(());
                }
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(email) => {
                if email.as_str() == expected_identity {
                    return Ok(());
                }
            }
            _ => {}
        }
    }

    Err(format!(
        "Certificate SAN does not match expected identity '{expected_identity}'"
    ))
}

fn verify_cert_oidc_issuer(cert: &Certificate, expected_issuer: &str) -> Result<(), String> {
    // OIDC Issuer V2 OID: 1.3.6.1.4.1.57264.1.8
    // OIDC Issuer V1 OID: 1.3.6.1.4.1.57264.1.1
    let v2_oid = "1.3.6.1.4.1.57264.1.8";
    let v1_oid = "1.3.6.1.4.1.57264.1.1";

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        // Try V2 first
        for ext in extensions.iter() {
            let oid_str = ext.extn_id.to_string();
            if oid_str == v2_oid || oid_str == v1_oid {
                if let Some(value) = decode_asn1_string(ext.extn_value.as_bytes()) {
                    if value == expected_issuer {
                        return Ok(());
                    } else {
                        return Err(format!(
                            "OIDC issuer mismatch: expected '{expected_issuer}', got '{value}'"
                        ));
                    }
                }
            }
        }
    }

    Err("Certificate missing OIDC issuer extension".into())
}

fn decode_asn1_string(bytes: &[u8]) -> Option<String> {
    if let Ok(s) = der::asn1::Utf8StringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    if let Ok(s) = der::asn1::Ia5StringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    if let Ok(s) = der::asn1::PrintableStringRef::from_der(bytes) {
        return Some(s.to_string());
    }
    // Fallback: older Fulcio V1 certificates stored the OIDC issuer as raw
    // UTF-8 bytes without an ASN.1 tag wrapper.
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Rekor transparency log verification
// ---------------------------------------------------------------------------

fn verify_rekor_entry(
    bundle: &serde_json::Value,
    trusted_root_json: &str,
    cert_der: Option<&[u8]>,
    key_path: Option<&str>,
    is_dsse: bool,
) -> Result<(), String> {
    let tlog_entries = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("tlogEntries"))
        .and_then(|t| t.as_array())
        .ok_or("Missing tlogEntries")?;

    if tlog_entries.len() != 1 {
        return Err(format!(
            "Expected exactly 1 tlog entry, got {}",
            tlog_entries.len()
        ));
    }

    let entry = &tlog_entries[0];

    // Get the kind/version to determine rekor v1 vs v2
    let kind_version = entry.get("kindVersion").ok_or("Missing kindVersion")?;
    let entry_version = kind_version
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.1");

    // For Rekor v1 (0.0.1): verify integrated time within cert validity
    if entry_version == "0.0.1" {
        if let Some(cert_bytes) = cert_der {
            let integrated_time = entry
                .get("integratedTime")
                .and_then(|t| t.as_str().and_then(|s| s.parse::<u64>().ok()).or(t.as_u64()))
                .ok_or("Missing integratedTime")?;

            let cert = Certificate::from_der(cert_bytes)
                .map_err(|e| format!("Parse cert for validity check: {e}"))?;
            let not_before = cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs();
            let not_after = cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();

            if integrated_time < not_before || integrated_time > not_after {
                return Err(format!(
                    "Integrated time {integrated_time} outside cert validity [{not_before}, {not_after}]"
                ));
            }
        }
    }
    // For Rekor v2 (0.0.2): need TSA timestamp verification
    // We verify what we can (checkpoint, inclusion proof) and check TSA if present
    if entry_version == "0.0.2" {
        if let Some(cert_bytes) = cert_der {
            // Try to verify timestamp from TSA
            verify_tsa_timestamp(bundle, cert_bytes, trusted_root_json)?;
        }
    }

    // Get inclusion proof
    let inclusion_proof = entry
        .get("inclusionProof")
        .ok_or("Missing inclusion proof")?;

    // Load Rekor keys from trusted root
    let rekor_keys = trust::load_rekor_keys_from_json(trusted_root_json)
        .map_err(|e| format!("Load Rekor keys: {e}"))?;

    // Get log ID
    let log_id = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|k| k.as_str())
        .ok_or("Missing logId")?;

    // For v1, use integrated time for key validity check; for v2, accept any valid key
    let timestamp_for_key = if entry_version == "0.0.1" {
        entry
            .get("integratedTime")
            .and_then(|t| t.as_str().and_then(|s| s.parse::<u64>().ok()).or(t.as_u64()))
    } else {
        None
    };

    let rekor_key = rekor_keys
        .iter()
        .find(|k| {
            if k.key_id != log_id {
                return false;
            }
            if let Some(ts) = timestamp_for_key {
                if let Some(from) = k.valid_from {
                    if ts < from {
                        return false;
                    }
                }
                if let Some(until) = k.valid_until {
                    if ts > until {
                        return false;
                    }
                }
            }
            true
        })
        .ok_or_else(|| format!("No matching Rekor key for log ID: {log_id}"))?;

    // Verify checkpoint signature
    let checkpoint_str = inclusion_proof
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .and_then(|e| e.as_str())
        .ok_or("Missing checkpoint")?;

    let signed_checkpoint =
        SignedCheckpoint::decode(checkpoint_str).map_err(|e| format!("Parse checkpoint: {e}"))?;

    signed_checkpoint
        .verify_signature(&rekor_key.key_der, &rekor_key.key_type)
        .map_err(|e| format!("Checkpoint signature: {e}"))?;

    // Verify root hash matches checkpoint
    let root_hash_b64 = inclusion_proof
        .get("rootHash")
        .and_then(|r| r.as_str())
        .ok_or("Missing rootHash")?;
    let root_hash = decode_b64(root_hash_b64).map_err(|e| format!("Decode rootHash: {e}"))?;

    if signed_checkpoint.note.hash.as_slice() != root_hash.as_slice() {
        return Err(format!(
            "Root hash mismatch: checkpoint has {}, proof has {}",
            hex::encode(signed_checkpoint.note.hash),
            hex::encode(&root_hash)
        ));
    }

    // Get log index and tree size
    let log_index = inclusion_proof
        .get("logIndex")
        .and_then(|i| {
            i.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or(i.as_u64())
        })
        .ok_or("Missing logIndex")?;

    let tree_size = inclusion_proof
        .get("treeSize")
        .and_then(|t| {
            t.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or(t.as_u64())
        })
        .ok_or("Missing treeSize")?;

    // Get proof hashes
    let proof_hashes: Vec<Vec<u8>> = inclusion_proof
        .get("hashes")
        .and_then(|h| h.as_array())
        .ok_or("Missing hashes")?
        .iter()
        .map(|h| {
            h.as_str()
                .ok_or_else(|| "Non-string hash".to_string())
                .and_then(|s| decode_b64(s).map_err(|e| format!("Decode hash: {e}")))
        })
        .collect::<Result<_, _>>()?;

    // Get canonicalized body
    let body_b64 = entry
        .get("canonicalizedBody")
        .and_then(|b| b.as_str())
        .ok_or("Missing canonicalizedBody")?;
    let body_bytes = decode_b64(body_b64).map_err(|e| format!("Decode body: {e}"))?;

    // Verify kind/version matches
    verify_kind_version(entry, &body_bytes)?;

    // Verify certificate or key binding
    if cert_der.is_some() {
        verify_cert_binding(bundle, &body_bytes)?;
    } else if key_path.is_some() {
        verify_key_binding(key_path.unwrap(), &body_bytes)?;
    }

    // Verify signature binding
    verify_sig_binding(bundle, &body_bytes, is_dsse)?;

    // Verify payload hash binding (DSSE only)
    if is_dsse {
        verify_payload_hash_binding(bundle, &body_bytes)?;
    }

    // Verify Merkle inclusion proof
    let leaf_hash = Rfc6269Default::hash_leaf(&body_bytes);
    let proof_outputs: Vec<Output<Sha256>> = proof_hashes
        .iter()
        .map(|h| {
            <[u8; 32]>::try_from(h.as_slice())
                .map(Into::into)
                .map_err(|_| "Invalid proof hash length".to_string())
        })
        .collect::<Result<_, _>>()?;

    let root_output: Output<Sha256> = <[u8; 32]>::try_from(root_hash.as_slice())
        .map(Into::into)
        .map_err(|_| "Invalid root hash length".to_string())?;

    Rfc6269Default::verify_inclusion(log_index, &leaf_hash, tree_size, &proof_outputs, &root_output)
        .map_err(|e| format!("Merkle inclusion proof failed: {e}"))
}

// ---------------------------------------------------------------------------
// TSA timestamp verification (basic)
// ---------------------------------------------------------------------------

fn verify_tsa_timestamp(
    bundle: &serde_json::Value,
    cert_der: &[u8],
    _trusted_root_json: &str,
) -> Result<(), String> {
    // Extract TSA timestamps from bundle
    let timestamps = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("timestampVerificationData"))
        .and_then(|tvd| tvd.get("rfc3161Timestamps"))
        .and_then(|ts| ts.as_array());

    let timestamps = match timestamps {
        Some(ts) if !ts.is_empty() => ts,
        _ => return Err("Rekor v2 entry requires TSA timestamp".into()),
    };

    // Parse the first timestamp to extract the signing time
    let ts_b64 = timestamps[0]
        .get("signedTimestamp")
        .and_then(|s| s.as_str())
        .ok_or("Missing signedTimestamp")?;
    let ts_bytes = decode_b64(ts_b64).map_err(|e| format!("Decode TSA timestamp: {e}"))?;

    // Extract signing time from the CMS SignedData structure
    // The TSTInfo is embedded in the CMS content. We do basic ASN.1 parsing
    // to extract the genTime field.
    let signing_time = extract_tsa_gen_time(&ts_bytes)?;

    // Verify the signing time is within the certificate's validity period
    let cert =
        Certificate::from_der(cert_der).map_err(|e| format!("Parse cert for TSA check: {e}"))?;
    let not_before = cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let not_after = cert
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();

    if signing_time < not_before || signing_time > not_after {
        return Err(format!(
            "TSA timestamp {signing_time} outside cert validity [{not_before}, {not_after}]"
        ));
    }

    Ok(())
}

/// Extract genTime from an RFC 3161 TimeStampResp/TimeStampToken.
/// This does minimal ASN.1 parsing to find the GeneralizedTime in TSTInfo.
fn extract_tsa_gen_time(ts_bytes: &[u8]) -> Result<u64, String> {
    // The signedTimestamp is a CMS SignedData structure (or TimeStampResp).
    // Structure: SEQUENCE { contentType, content: [0] EXPLICIT SEQUENCE { ... } }
    // We need to find the TSTInfo which contains genTime (GeneralizedTime).
    //
    // TSTInfo ::= SEQUENCE {
    //   version INTEGER,
    //   policy OBJECT IDENTIFIER,
    //   messageImprint MessageImprint,
    //   serialNumber INTEGER,
    //   genTime GeneralizedTime,  <-- this is what we want
    //   ...
    // }
    //
    // We search for GeneralizedTime tags (0x18) in the DER data.
    // This is a heuristic but works for well-formed TSA responses.

    let mut i = 0;
    while i < ts_bytes.len() {
        if ts_bytes[i] == 0x18 {
            // GeneralizedTime tag
            if i + 1 < ts_bytes.len() {
                let len = ts_bytes[i + 1] as usize;
                if i + 2 + len <= ts_bytes.len() {
                    let time_str = std::str::from_utf8(&ts_bytes[i + 2..i + 2 + len])
                        .map_err(|_| "Invalid GeneralizedTime encoding")?;
                    if let Ok(ts) = parse_generalized_time(time_str) {
                        return Ok(ts);
                    }
                }
            }
        }
        i += 1;
    }

    Err("Could not find genTime in TSA timestamp".into())
}

fn parse_generalized_time(s: &str) -> Result<u64, String> {
    // Format: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.fffZ
    let s = s.trim_end_matches('Z');
    let s = s.split('.').next().unwrap_or(s); // strip fractional seconds

    if s.len() < 14 {
        return Err("GeneralizedTime too short".into());
    }

    let year: i32 = s[0..4].parse().map_err(|_| "Invalid year")?;
    let month: u8 = s[4..6].parse().map_err(|_| "Invalid month")?;
    let day: u8 = s[6..8].parse().map_err(|_| "Invalid day")?;
    let hour: u8 = s[8..10].parse().map_err(|_| "Invalid hour")?;
    let minute: u8 = s[10..12].parse().map_err(|_| "Invalid minute")?;
    let second: u8 = s[12..14].parse().map_err(|_| "Invalid second")?;

    let dt = time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(year, month.try_into().map_err(|_| "Invalid month")?, day)
            .map_err(|e| format!("Invalid date: {e}"))?,
        time::Time::from_hms(hour, minute, second).map_err(|e| format!("Invalid time: {e}"))?,
    )
    .assume_offset(time::UtcOffset::UTC);

    let ts = dt.unix_timestamp();
    if ts < 0 {
        return Err("Timestamp before epoch".into());
    }
    Ok(ts as u64)
}

// ---------------------------------------------------------------------------
// Rekor entry sub-verifications
// ---------------------------------------------------------------------------

fn verify_kind_version(entry: &serde_json::Value, body: &[u8]) -> Result<(), String> {
    let kv = entry.get("kindVersion").ok_or("Missing kindVersion")?;
    let expected_kind = kv.get("kind").and_then(|k| k.as_str());
    let expected_version = kv.get("version").and_then(|v| v.as_str());

    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Parse canonicalizedBody: {e}"))?;
    let body_kind = body_json.get("kind").and_then(|k| k.as_str());
    let body_version = body_json.get("apiVersion").and_then(|v| v.as_str());

    if body_kind != expected_kind || body_version != expected_version {
        return Err(format!(
            "Kind/version mismatch: body={body_kind:?}/{body_version:?}, expected={expected_kind:?}/{expected_version:?}"
        ));
    }
    Ok(())
}

/// For hashedrekord entries, get the inner spec object handling both v0.0.1 and v0.0.2 layouts.
fn hashedrekord_inner_spec<'a>(spec: &'a serde_json::Value) -> &'a serde_json::Value {
    spec.get("hashedRekordV002").unwrap_or(spec)
}

/// For dsse entries, get the inner spec object handling both v0.0.1 and v0.0.2 layouts.
fn dsse_inner_spec<'a>(spec: &'a serde_json::Value) -> &'a serde_json::Value {
    spec.get("dsseV002").unwrap_or(spec)
}

/// Decode a base64-encoded or raw PEM string to DER.
fn pem_field_to_der(val: &str) -> Result<Vec<u8>, String> {
    if val.starts_with("-----") {
        pem_to_der(val)
    } else {
        let decoded = decode_b64(val).map_err(|e| format!("Decode PEM field: {e}"))?;
        let text = String::from_utf8(decoded).map_err(|e| format!("PEM field UTF-8: {e}"))?;
        pem_to_der(&text)
    }
}

/// Extract a DER-encoded certificate from a Rekor entry body.
fn extract_rekor_cert_der(body_json: &serde_json::Value) -> Result<Vec<u8>, String> {
    let kind = body_json
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("");
    let spec = body_json.get("spec").ok_or("Missing spec")?;

    match kind {
        "dsse" => {
            let inner = dsse_inner_spec(spec);

            // v0.0.2: signatures[0].verifier.x509Certificate.rawBytes
            if let Some(raw_b64) = inner
                .get("signatures")
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("verifier"))
                .and_then(|v| v.get("x509Certificate"))
                .and_then(|c| c.get("rawBytes"))
                .and_then(|r| r.as_str())
            {
                return decode_b64(raw_b64).map_err(|e| format!("Decode dsse v002 cert: {e}"));
            }

            // v0.0.1: signatures[0].verifier (base64-encoded PEM)
            let verifier_b64 = inner
                .get("signatures")
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("verifier"))
                .and_then(|v| v.as_str())
                .ok_or("Missing verifier in DSSE Rekor entry")?;

            let pem_bytes =
                decode_b64(verifier_b64).map_err(|e| format!("Decode verifier: {e}"))?;
            let pem_str = String::from_utf8(pem_bytes).map_err(|e| format!("UTF-8: {e}"))?;
            pem_to_der(&pem_str)
        }
        "intoto" => {
            // intoto v0.0.2: spec.content.envelope.signatures[0].publicKey (base64 PEM)
            let pk_b64 = spec
                .get("content")
                .and_then(|c| c.get("envelope"))
                .and_then(|e| e.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("publicKey"))
                .and_then(|v| v.as_str())
                .ok_or("Missing publicKey in intoto Rekor entry")?;

            pem_field_to_der(pk_b64)
        }
        "hashedrekord" => {
            let inner = hashedrekord_inner_spec(spec);

            // v0.0.2: signature.verifier.x509Certificate.rawBytes (base64 DER)
            if let Some(raw_b64) = inner
                .get("signature")
                .and_then(|s| s.get("verifier"))
                .and_then(|v| v.get("x509Certificate"))
                .and_then(|c| c.get("rawBytes"))
                .and_then(|r| r.as_str())
            {
                return decode_b64(raw_b64).map_err(|e| format!("Decode v002 cert: {e}"));
            }

            // v0.0.1: signature.publicKey.content (base64-encoded PEM or raw PEM)
            let pem_str = inner
                .get("signature")
                .and_then(|s| s.get("publicKey"))
                .and_then(|pk| pk.get("content"))
                .and_then(|c| c.as_str())
                .ok_or("Missing publicKey/verifier in hashedrekord")?;

            pem_field_to_der(pem_str)
        }
        _ => Err(format!("Unknown Rekor entry kind: {kind}")),
    }
}

/// Extract a signature from a Rekor entry body.
fn extract_rekor_signature(body_json: &serde_json::Value) -> Result<Vec<u8>, String> {
    let kind = body_json
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("");
    let spec = body_json.get("spec").ok_or("Missing spec")?;

    let sig_b64 = match kind {
        "dsse" => {
            let inner = dsse_inner_spec(spec);
            // v0.0.2 uses "content", v0.0.1 uses "signature"
            inner
                .get("signatures")
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("content").or(sig.get("signature")))
                .and_then(|v| v.as_str())
                .ok_or("Missing signature in DSSE Rekor entry")?
        }
        "intoto" => {
            // intoto v0.0.2 stores sig as base64(base64(raw_sig))
            let sig_b64_b64 = spec
                .get("content")
                .and_then(|c| c.get("envelope"))
                .and_then(|e| e.get("signatures"))
                .and_then(|s| s.as_array())
                .and_then(|arr| arr.first())
                .and_then(|sig| sig.get("sig"))
                .and_then(|v| v.as_str())
                .ok_or("Missing sig in intoto Rekor entry")?;
            // First decode gives us the inner base64 string
            let inner_b64 =
                decode_b64(sig_b64_b64).map_err(|e| format!("Decode intoto sig outer: {e}"))?;
            // Second decode gives us the raw signature
            let inner_str = String::from_utf8(inner_b64)
                .map_err(|e| format!("intoto sig inner not UTF-8: {e}"))?;
            return decode_b64(&inner_str)
                .map_err(|e| format!("Decode intoto sig inner: {e}"));
        }
        "hashedrekord" => {
            let inner = hashedrekord_inner_spec(spec);
            inner
                .get("signature")
                .and_then(|s| s.get("content"))
                .and_then(|c| c.as_str())
                .ok_or("Missing signature in hashedrekord")?
        }
        _ => return Err(format!("Unknown kind: {kind}")),
    };
    decode_b64(sig_b64).map_err(|e| format!("Decode Rekor sig: {e}"))
}

fn verify_cert_binding(bundle: &serde_json::Value, body: &[u8]) -> Result<(), String> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Parse body: {e}"))?;

    let rekor_cert_der = extract_rekor_cert_der(&body_json)?;
    let bundle_cert_der = extract_leaf_cert_der(bundle)?;

    if rekor_cert_der != bundle_cert_der {
        return Err("Certificate binding mismatch".into());
    }
    Ok(())
}

fn verify_key_binding(key_path: &str, body: &[u8]) -> Result<(), String> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Parse body: {e}"))?;

    let kind = body_json
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("");

    let inner = match kind {
        "hashedrekord" => hashedrekord_inner_spec(
            body_json.get("spec").ok_or("Missing spec")?,
        ),
        _ => body_json.get("spec").ok_or("Missing spec")?,
    };

    let rekor_key_pem = inner
        .get("signature")
        .and_then(|s| s.get("publicKey"))
        .and_then(|pk| pk.get("content"))
        .and_then(|c| c.as_str())
        .ok_or("Missing publicKey in Rekor entry")?;

    let rekor_key_text = if rekor_key_pem.starts_with("-----") {
        rekor_key_pem.to_string()
    } else {
        let decoded = decode_b64(rekor_key_pem).map_err(|e| format!("Decode key: {e}"))?;
        String::from_utf8(decoded).map_err(|e| format!("Key UTF-8: {e}"))?
    };

    let rekor_key_der = pem_to_der(&rekor_key_text)?;

    let key_pem = fs::read_to_string(key_path).map_err(|e| format!("Read key: {e}"))?;
    let key_der = pem_to_der(&key_pem)?;

    if rekor_key_der != key_der {
        return Err("Key binding mismatch".into());
    }
    Ok(())
}

fn verify_sig_binding(
    bundle: &serde_json::Value,
    body: &[u8],
    is_dsse: bool,
) -> Result<(), String> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Parse body: {e}"))?;

    let rekor_sig = extract_rekor_signature(&body_json)?;

    let bundle_sig = if is_dsse {
        let sig_b64 = bundle
            .get("dsseEnvelope")
            .and_then(|d| d.get("signatures"))
            .and_then(|s| s.as_array())
            .and_then(|arr| arr.first())
            .and_then(|sig| sig.get("sig"))
            .and_then(|s| s.as_str())
            .ok_or("Missing DSSE sig in bundle")?;
        decode_b64(sig_b64).map_err(|e| format!("Decode bundle sig: {e}"))?
    } else {
        let sig_b64 = bundle
            .get("messageSignature")
            .and_then(|ms| ms.get("signature"))
            .and_then(|s| s.as_str())
            .ok_or("Missing messageSignature.signature")?;
        decode_b64(sig_b64).map_err(|e| format!("Decode bundle sig: {e}"))?
    };

    if rekor_sig != bundle_sig {
        return Err("Signature binding mismatch".into());
    }
    Ok(())
}

fn verify_payload_hash_binding(bundle: &serde_json::Value, body: &[u8]) -> Result<(), String> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("Parse body: {e}"))?;
    let kind = body_json
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("");

    if kind != "dsse" && kind != "intoto" {
        return Ok(());
    }

    let spec = body_json.get("spec").ok_or("Missing spec")?;
    let payload_hash = match kind {
        "intoto" => spec.get("content").and_then(|c| c.get("payloadHash")),
        "dsse" => {
            let inner = dsse_inner_spec(spec);
            inner.get("payloadHash")
        }
        _ => spec.get("payloadHash"),
    };

    let payload_hash = match payload_hash {
        Some(h) => h,
        None => return Err("DSSE Rekor entry missing payloadHash".into()),
    };

    let algo = payload_hash
        .get("algorithm")
        .and_then(|a| a.as_str())
        .unwrap_or("");
    if algo != "sha256" && algo != "SHA2_256" {
        return Err(format!("Unsupported hash algorithm: {algo}"));
    }

    // v0.0.1 uses "value" (hex), v0.0.2 uses "digest" (base64)
    let expected_hash = if let Some(val) = payload_hash.get("value").and_then(|v| v.as_str()) {
        val.to_string()
    } else if let Some(digest_b64) = payload_hash.get("digest").and_then(|d| d.as_str()) {
        let digest_bytes =
            decode_b64(digest_b64).map_err(|e| format!("Decode payloadHash digest: {e}"))?;
        hex::encode(digest_bytes)
    } else {
        return Err("Missing payloadHash value/digest".into());
    };

    let payload_b64 = bundle
        .get("dsseEnvelope")
        .and_then(|d| d.get("payload"))
        .and_then(|p| p.as_str())
        .ok_or("Missing DSSE payload")?;

    let payload = decode_b64(payload_b64).map_err(|e| format!("Decode payload: {e}"))?;
    let actual_hash = hex::encode(Sha256::digest(&payload));

    if actual_hash != expected_hash {
        return Err(format!(
            "Payload hash mismatch: expected {expected_hash}, got {actual_hash}"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fulcio CA chain verification
// ---------------------------------------------------------------------------

fn verify_fulcio_chain(cert_der: &[u8], trusted_root_json: &str) -> Result<(), String> {
    let signing_cert =
        Certificate::from_der(cert_der).map_err(|e| format!("Parse signing cert: {e}"))?;

    let cert_not_before = signing_cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();

    let fulcio_cas = trust::load_fulcio_cas_from_json(trusted_root_json)
        .map_err(|e| format!("Load Fulcio CAs: {e}"))?;

    for ca in &fulcio_cas {
        if cert_not_before < ca.valid_from {
            continue;
        }
        if let Some(end) = ca.valid_until {
            if cert_not_before > end {
                continue;
            }
        }
        if ca.cert_chain_der.is_empty() {
            continue;
        }

        let issuer_cert = match Certificate::from_der(&ca.cert_chain_der[0]) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if signing_cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
            continue;
        }

        let tbs_bytes = signing_cert
            .tbs_certificate
            .to_der()
            .map_err(|e| format!("Encode TBS: {e}"))?;
        let sig_bytes = signing_cert.signature.raw_bytes();
        let issuer_spki = &issuer_cert.tbs_certificate.subject_public_key_info;
        let issuer_pubkey = issuer_spki.subject_public_key.raw_bytes();

        // Dispatch on the signature algorithm of the signed certificate
        let sig_algo_oid = signing_cert.signature_algorithm.oid.to_string();
        let curve_oid = issuer_spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
            .map(|oid| oid.to_string());

        let verified = match sig_algo_oid.as_str() {
            // ecdsa-with-SHA256
            "1.2.840.10045.4.3.2" => match curve_oid.as_deref() {
                Some("1.2.840.10045.3.1.7") => {
                    verify_ecdsa_p256(&tbs_bytes, sig_bytes, issuer_pubkey)
                }
                _ => continue,
            },
            // ecdsa-with-SHA384
            "1.2.840.10045.4.3.3" => match curve_oid.as_deref() {
                Some("1.2.840.10045.3.1.7") => {
                    // P-256 key with SHA-384 signing
                    verify_ecdsa_p256_sha384(&tbs_bytes, sig_bytes, issuer_pubkey)
                }
                Some("1.3.132.0.34") => {
                    verify_ecdsa_p384(&tbs_bytes, sig_bytes, issuer_pubkey)
                }
                _ => continue,
            },
            // sha256WithRSAEncryption
            "1.2.840.113549.1.1.11" => {
                let issuer_spki_der = issuer_spki.to_der().unwrap_or_default();
                verify_rsa_sha256(&tbs_bytes, sig_bytes, &issuer_spki_der)
            }
            _ => continue,
        };

        if verified {
            return Ok(());
        }
    }

    Err("Certificate not issued by any trusted Fulcio CA".into())
}

fn verify_ecdsa_p256(tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let Some(key) = VerifyingKey::from_sec1_bytes(pubkey).ok() else {
        return false;
    };
    let Some(signature) = Signature::from_der(sig).ok() else {
        return false;
    };
    key.verify(tbs, &signature).is_ok()
}

fn verify_ecdsa_p256_sha384(tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let Some(key) = VerifyingKey::from_sec1_bytes(pubkey).ok() else {
        return false;
    };
    let Some(signature) = Signature::from_der(sig).ok() else {
        return false;
    };
    let digest = sha2::Sha384::digest(tbs);
    key.verify_prehash(&digest, &signature).is_ok()
}

fn verify_ecdsa_p384(tbs: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    let Some(key) = VerifyingKey::from_sec1_bytes(pubkey).ok() else {
        return false;
    };
    let Some(signature) = Signature::from_der(sig).ok() else {
        return false;
    };
    key.verify(tbs, &signature).is_ok()
}

fn verify_rsa_sha256(tbs: &[u8], sig: &[u8], spki_der: &[u8]) -> bool {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::Pkcs1v15Sign;
    use rsa::RsaPublicKey;

    let Ok(key) = RsaPublicKey::from_public_key_der(spki_der) else {
        return false;
    };
    let digest = Sha256::digest(tbs);
    key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
        .is_ok()
}

// ---------------------------------------------------------------------------
// Artifact digest verification
// ---------------------------------------------------------------------------

fn verify_artifact_digest(
    bundle: &serde_json::Value,
    artifact_sha256: &[u8],
    is_msg_sig: bool,
    artifact_input: &str,
) -> Result<(), String> {
    if is_msg_sig {
        // For messageSignature: verify digest matches
        let digest_b64 = bundle
            .get("messageSignature")
            .and_then(|ms| ms.get("messageDigest"))
            .and_then(|d| d.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or("Missing messageDigest.digest")?;
        let bundle_digest =
            decode_b64(digest_b64).map_err(|e| format!("Decode message digest: {e}"))?;

        if artifact_sha256 != bundle_digest.as_slice() {
            return Err("Artifact digest does not match message digest in bundle".into());
        }
    } else {
        // For DSSE with in-toto: verify subject matches
        let payload_b64 = bundle
            .get("dsseEnvelope")
            .and_then(|d| d.get("payload"))
            .and_then(|p| p.as_str())
            .ok_or("Missing DSSE payload")?;
        let payload = decode_b64(payload_b64).map_err(|e| format!("Decode payload: {e}"))?;
        let statement: serde_json::Value =
            serde_json::from_slice(&payload).map_err(|e| format!("Parse statement: {e}"))?;

        let subjects = statement
            .get("subject")
            .and_then(|s| s.as_array())
            .ok_or("Missing subject in in-toto statement")?;

        let artifact_hex = hex::encode(artifact_sha256);

        // Check if input is a digest (sha256:hex)
        let is_digest_input = artifact_input.starts_with("sha256:")
            && artifact_input.len() == 71
            && artifact_input[7..].chars().all(|c| c.is_ascii_hexdigit());

        let mut found = false;
        for subject in subjects {
            let subject_digest = subject
                .get("digest")
                .and_then(|d| d.get("sha256"))
                .and_then(|s| s.as_str())
                .unwrap_or("");

            if subject_digest == artifact_hex {
                found = true;
                break;
            }

            // For file path input, also check subject name
            if !is_digest_input {
                let subject_name = subject.get("name").and_then(|n| n.as_str()).unwrap_or("");
                // The artifact input might be a relative path, compare just the filename
                let input_name = std::path::Path::new(artifact_input)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(artifact_input);
                if subject_name == input_name || subject_name == artifact_input {
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return Err("Artifact does not match any subject in in-toto statement".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, String> {
    let parsed = pem::parse(pem_str).map_err(|e| format!("Parse PEM: {e}"))?;
    Ok(parsed.into_contents())
}

use der::Encode;
