//! Rekor transparency-log entries: the signed entry timestamp, inclusion in
//! the log at a signed checkpoint, and the binding of the logged entry to
//! the bundle that carries it.
//!
//! These are the steps; which of them a bundle must pass, and what time
//! they establish, is decided by the bundle verifiers in
//! [`certificate`](super::certificate) and [`keyed`](super::keyed).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256, Sha384};

use super::SigstoreError;
use super::bundle::{DsseEnvelope, TlogEntry};
use super::checkpoint::{SignedCheckpoint, verify_entry_timestamp_signature};
use super::merkle;
use super::statement::pae;
use crate::canonical::{decode_base64, encode_lower_hex};
use crate::json::{self, Value};
use crate::x509::der::pem_certificates;
use crate::x509::{Certificate, KeyAlgorithm, PublicKey};

/// The entry kind that logs a DSSE envelope in Rekor v1.
pub const KIND_DSSE: &str = "dsse";
/// The entry kind that logs a signature over a digest.
pub const KIND_HASHEDREKORD: &str = "hashedrekord";
/// The version of [`KIND_DSSE`] entries in Rekor v1.
pub const VERSION_0_0_1: &str = "0.0.1";
/// The version of [`KIND_HASHEDREKORD`] entries in Rekor v2.
pub const VERSION_0_0_2: &str = "0.0.2";

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// What signed the envelope that a log entry records.
#[derive(Debug, Clone, Copy)]
pub enum EntrySigner<'a> {
    /// The bundle's signing certificate.
    Certificate(&'a Certificate),
    /// A key that the verifier holds.
    Key(&'a PublicKey),
}

/// The text that a Rekor v1 signed entry timestamp covers: the canonical
/// JSON of the entry's body (as base64), integrated time, log identifier
/// (as lowercase hex) and log index.
pub fn signed_entry_timestamp_payload(entry: &TlogEntry) -> String {
    format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        STANDARD.encode(&entry.canonicalized_body),
        entry.integrated_time,
        encode_lower_hex(&entry.log_id),
        entry.log_index,
    )
}

/// Verifies an entry's signed entry timestamp under the log's key: ECDSA
/// with SHA-256, whatever the key's curve. A log with a key of another
/// kind issues no entry timestamps, so one that claims to is an error.
///
/// The Merkle leaf covers only the entry's body, so this signature is what
/// authenticates the entry's integrated time. An entry without an inclusion
/// promise is an error.
pub fn verify_signed_entry_timestamp(
    entry: &TlogEntry,
    log_key: &PublicKey,
) -> Result<(), SigstoreError> {
    let promise = entry
        .inclusion_promise
        .as_deref()
        .ok_or_else(|| error("log entry has no inclusion promise"))?;
    let payload = signed_entry_timestamp_payload(entry);
    verify_entry_timestamp_signature(log_key, payload.as_bytes(), promise)
        .map_err(|cause| cause.within("signed entry timestamp"))
}

/// Whether a checkpoint origin ends in a tree identifier: ` - ` followed by
/// decimal digits. Logs that are split into shards sign such origins; a
/// log that is one tree signs its bare name.
fn has_tree_id(origin: &str) -> bool {
    origin.rsplit_once(" - ").is_some_and(|(_, tree_id)| {
        !tree_id.is_empty() && tree_id.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Whether `origin` is exactly `log_name`, the separator and a tree
/// identifier of digits.
fn is_shard_of(origin: &str, log_name: &str) -> bool {
    origin
        .strip_prefix(log_name)
        .and_then(|rest| rest.strip_prefix(" - "))
        .is_some_and(|tree_id| {
            !tree_id.is_empty() && tree_id.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Verifies that an entry is in its log.
///
/// The entry has an inclusion proof whose checkpoint decodes. The
/// checkpoint's origin tells which kind of log signed it, and the kind
/// decides how the checkpoint is authenticated and what the proof must
/// agree with. In both kinds the proof's root hash equals the checkpoint's,
/// and the Merkle proof leads from the leaf hash of the entry's body to
/// that root. The caller has bound the body to the bundle
/// ([`verify_body_binding`]), so the leaf is the record of this bundle.
///
/// - An origin with a tree identifier (`<name> - <digits>`) is a log made
///   of shards, and `<name>` is `log_name`. The log alone signs such a
///   checkpoint: every signature line is by `log_key`
///   ([`SignedCheckpoint::verify_every_signature`]). The proof's index
///   counts within the shard while the entry's index counts across the
///   whole log, so the proof is verified at its own index and tree size,
///   and neither is compared with the entry or the checkpoint.
/// - Any other origin is a log of one tree, whose entries are
///   `hashedrekord` 0.0.2 records. The origin is `log_name`; the
///   checkpoint is a note signed by `log_name` with `log_key`, possibly
///   among witnesses
///   ([`SignedCheckpoint::verify_named_signature`]); the proof's tree size
///   equals the checkpoint's and its index equals the entry's index.
pub fn verify_inclusion(
    entry: &TlogEntry,
    log_key: &PublicKey,
    log_name: &str,
) -> Result<(), SigstoreError> {
    let proof = entry
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| error("log entry has no inclusion proof"))?;
    let signed = SignedCheckpoint::decode(&proof.checkpoint)?;
    let checkpoint = signed.checkpoint();
    if has_tree_id(&checkpoint.origin) {
        signed.verify_every_signature(log_key)?;
        // The shard still belongs to this log: the tree identifier follows
        // the log's own name.
        if !is_shard_of(&checkpoint.origin, log_name) {
            return Err(error(format!(
                "checkpoint origin is {:?}, want a shard of {log_name:?}",
                checkpoint.origin
            )));
        }
    } else {
        if (entry.kind.as_str(), entry.version.as_str()) != (KIND_HASHEDREKORD, VERSION_0_0_2) {
            return Err(error(format!(
                "a {} {} entry cannot be in a log of one tree",
                entry.kind, entry.version
            )));
        }
        signed.verify_named_signature(log_key, log_name)?;
        if checkpoint.origin != log_name {
            return Err(error(format!(
                "checkpoint origin is {:?}, want {log_name:?}",
                checkpoint.origin
            )));
        }
        if proof.tree_size != checkpoint.size {
            return Err(error(
                "inclusion proof tree size differs from the signed checkpoint",
            ));
        }
        if proof.log_index != entry.log_index {
            return Err(error(
                "inclusion proof index differs from the index of the log entry",
            ));
        }
    }
    // The checkpoint is what the log signed, so the proof must lead to its
    // root, not merely to the root that the proof itself states.
    if checkpoint.root_hash != proof.root_hash {
        return Err(error(
            "inclusion proof root hash differs from the signed checkpoint",
        ));
    }
    let leaf_hash = merkle::hash_leaf(&entry.canonicalized_body);
    merkle::verify_inclusion(
        proof.log_index,
        &leaf_hash,
        proof.tree_size,
        &proof.hashes,
        &proof.root_hash,
    )?;
    Ok(())
}

/// The body of the `hashedrekord` 0.0.2 entry that records `envelope` as
/// signed by `signer`: the canonical JSON that a log stores and hashes
/// into its tree.
///
/// The record names the signature, the signer (the certificate, or the
/// key's SubjectPublicKeyInfo) with the name of its signature algorithm,
/// and the digest of the pre-authentication encoding of the payload under
/// the hash of the signer's curve: SHA-256 for P-256, SHA-384 for P-384. A
/// signer with a key of another kind has no such record.
pub fn hashedrekord_body(
    envelope: &DsseEnvelope,
    signer: EntrySigner<'_>,
) -> Result<Vec<u8>, SigstoreError> {
    let (algorithm, verifier_name, verifier_bytes) = match signer {
        EntrySigner::Certificate(certificate) => (
            certificate.public_key()?.algorithm(),
            "x509Certificate",
            certificate.der(),
        ),
        EntrySigner::Key(key) => (key.algorithm(), "publicKey", key.spki_der()),
    };
    let encoded = pae(&envelope.payload_type, &envelope.payload);
    let (key_details, hash_name, digest) = match algorithm {
        KeyAlgorithm::EcdsaP256 => (
            "PKIX_ECDSA_P256_SHA_256",
            "SHA2_256",
            Sha256::digest(&encoded).to_vec(),
        ),
        KeyAlgorithm::EcdsaP384 => (
            "PKIX_ECDSA_P384_SHA_384",
            "SHA2_384",
            Sha384::digest(&encoded).to_vec(),
        ),
        other => {
            return Err(error(format!(
                "a {other:?} key has no hashedrekord log entry"
            )));
        }
    };
    Ok(format!(
        concat!(
            r#"{{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{{"hashedRekordV002":{{"#,
            r#""data":{{"algorithm":"{}","digest":"{}"}},"#,
            r#""signature":{{"content":"{}","verifier":{{"keyDetails":"{}","{}":{{"rawBytes":"{}"}}}}}}}}}}}}"#
        ),
        hash_name,
        STANDARD.encode(digest),
        STANDARD.encode(&envelope.signature),
        key_details,
        verifier_name,
        STANDARD.encode(verifier_bytes),
    )
    .into_bytes())
}

/// Verifies that the logged entry is about this envelope and this signer.
///
/// By the entry's kind and version:
///
/// - `hashedrekord` 0.0.2: the entry's body is, byte for byte, the record
///   of this envelope and signer ([`hashedrekord_body`]);
/// - `dsse` 0.0.1, for a certificate only: the body is strict JSON whose
///   `kind` and `apiVersion` equal the entry's; the certificate in the body
///   is the signing certificate, byte for byte; the signature in the body
///   is the envelope's signature; and the payload hash in the body is the
///   SHA-256 of the envelope's payload;
/// - anything else is an error.
pub fn verify_body_binding(
    entry: &TlogEntry,
    envelope: &DsseEnvelope,
    signer: EntrySigner<'_>,
) -> Result<(), SigstoreError> {
    match (entry.kind.as_str(), entry.version.as_str(), signer) {
        (KIND_HASHEDREKORD, VERSION_0_0_2, signer) => {
            if entry.canonicalized_body != hashedrekord_body(envelope, signer)? {
                return Err(error(
                    "log entry is not the record of this bundle: the signature, the signer or \
                     the digest of the payload's pre-authentication encoding differs",
                ));
            }
            Ok(())
        }
        (KIND_DSSE, VERSION_0_0_1, EntrySigner::Certificate(certificate)) => {
            let body = json::parse(&entry.canonicalized_body)
                .map_err(|cause| error(format!("log entry body: {cause}")))?;
            let kind = text(&body, &["kind"]);
            let version = text(&body, &["apiVersion"]);
            if kind != Some(KIND_DSSE) || version != Some(VERSION_0_0_1) {
                return Err(error(format!(
                    "log entry body is {kind:?} {version:?}, but the entry says {:?} {:?}",
                    entry.kind, entry.version
                )));
            }
            bind_dsse(&body, envelope, certificate.der())
        }
        (kind, version, _) => Err(error(format!(
            "unsupported log entry type {kind} {version}"
        ))),
    }
}

fn bind_dsse(
    body: &Value,
    envelope: &DsseEnvelope,
    certificate_der: &[u8],
) -> Result<(), SigstoreError> {
    let signature = at(body, &["spec", "signatures"])
        .and_then(Value::as_array)
        .and_then(<[Value]>::first)
        .ok_or_else(|| error("dsse log entry has no signature"))?;

    // The verifier is the base64 of the PEM certificate.
    let verifier = bytes(signature, &["verifier"], "dsse log entry verifier")?;
    let mut certificates = pem_certificates(&verifier)?;
    let (Some(logged_certificate), true) = (certificates.pop(), certificates.is_empty()) else {
        return Err(error("dsse log entry verifier is not one certificate"));
    };
    if logged_certificate != certificate_der {
        return Err(error(
            "bundle certificate is not the certificate in the log entry",
        ));
    }

    let logged_signature = bytes(signature, &["signature"], "dsse log entry signature")?;
    if logged_signature != envelope.signature {
        return Err(error(
            "bundle signature is not the signature in the log entry",
        ));
    }

    if text(body, &["spec", "payloadHash", "algorithm"]) != Some("sha256") {
        return Err(error("dsse log entry payload hash is not SHA-256"));
    }
    let logged_hash = text(body, &["spec", "payloadHash", "value"])
        .ok_or_else(|| error("dsse log entry has no payload hash"))?;
    if logged_hash != encode_lower_hex(&Sha256::digest(&envelope.payload)) {
        return Err(error("bundle payload is not the payload in the log entry"));
    }
    Ok(())
}

/// The value at a path of object member names.
fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |value, name| value.as_object()?.get(name))
}

/// The string at a path of object member names.
fn text<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    at(value, path).and_then(Value::as_str)
}

/// The canonical base64 byte string at a path of object member names.
fn bytes(value: &Value, path: &[&str], what: &str) -> Result<Vec<u8>, SigstoreError> {
    let encoded = text(value, path).ok_or_else(|| error(format!("{what} is missing")))?;
    Ok(decode_base64(what, encoded)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigstore::bundle::Bundle;
    use crate::sigstore::testutil::{self, TestLog};

    fn production() -> (Bundle, TestLog) {
        let bundle = testutil::bundle(testutil::REKOR_V1_BUNDLE);
        let log = testutil::log(
            testutil::PRODUCTION_TRUSTED_ROOT,
            &bundle.tlog_entries[0].log_id,
        );
        (bundle, log)
    }

    fn staging() -> (Bundle, TestLog) {
        let bundle = testutil::bundle(testutil::REKOR_V2_BUNDLE);
        let log = testutil::log(
            testutil::STAGING_TRUSTED_ROOT,
            &bundle.tlog_entries[0].log_id,
        );
        (bundle, log)
    }

    fn bind(bundle: &Bundle) -> Result<(), SigstoreError> {
        let certificate = Certificate::from_der(bundle.certificate_der().unwrap())?;
        verify_body_binding(
            &bundle.tlog_entries[0],
            &bundle.envelope,
            EntrySigner::Certificate(&certificate),
        )
    }

    fn included(bundle: &Bundle, log: &TestLog) -> Result<(), SigstoreError> {
        verify_inclusion(&bundle.tlog_entries[0], &log.key, &log.name)
    }

    #[test]
    fn a_production_entry_passes_every_step() {
        let (bundle, log) = production();
        let entry = &bundle.tlog_entries[0];
        assert_eq!(
            (entry.kind.as_str(), entry.version.as_str()),
            ("dsse", "0.0.1")
        );
        assert_eq!(entry.integrated_time, 1_774_548_286);
        verify_signed_entry_timestamp(entry, &log.key).unwrap();
        included(&bundle, &log).unwrap();
        bind(&bundle).unwrap();
    }

    #[test]
    fn another_certificate_is_not_the_logged_one() {
        let (mut bundle, _) = production();
        bundle.key_material = staging().0.key_material;
        let error = bind(&bundle).unwrap_err();
        assert!(error.to_string().contains("certificate"), "{error}");
    }

    #[test]
    fn another_signature_is_not_the_logged_one() {
        let (mut bundle, _) = production();
        bundle.envelope.signature[10] ^= 1;
        let error = bind(&bundle).unwrap_err();
        assert!(error.to_string().contains("signature"), "{error}");
    }

    #[test]
    fn another_payload_is_not_the_logged_one() {
        let (mut bundle, _) = production();
        bundle.envelope.payload[5] ^= 1;
        let error = bind(&bundle).unwrap_err();
        assert!(error.to_string().contains("payload"), "{error}");
    }

    #[test]
    fn an_entry_that_states_another_kind_than_its_body_is_rejected() {
        let (mut bundle, _) = production();
        bundle.tlog_entries[0].kind = "hashedrekord".to_string();
        assert!(bind(&bundle).is_err());
        let (mut bundle, _) = production();
        bundle.tlog_entries[0].version = "0.0.2".to_string();
        assert!(bind(&bundle).is_err());
    }

    #[test]
    fn a_corrupt_checkpoint_fails_inclusion() {
        let (mut bundle, log) = production();
        bundle.tlog_entries[0]
            .inclusion_proof
            .as_mut()
            .unwrap()
            .checkpoint = "corrupted checkpoint".to_string();
        assert!(included(&bundle, &log).is_err());
    }

    #[test]
    fn a_proof_root_that_the_checkpoint_does_not_sign_fails_inclusion() {
        let (mut bundle, log) = production();
        bundle.tlog_entries[0]
            .inclusion_proof
            .as_mut()
            .unwrap()
            .root_hash[0] ^= 0xff;
        let error = included(&bundle, &log).unwrap_err();
        assert!(error.to_string().contains("signed checkpoint"), "{error}");
    }

    #[test]
    fn a_changed_index_size_hash_or_body_fails_inclusion() {
        let (bundle, log) = production();
        let change = |edit: fn(&mut TlogEntry)| {
            let mut changed = bundle.clone();
            edit(&mut changed.tlog_entries[0]);
            included(&changed, &log)
        };
        assert!(change(|entry| entry.inclusion_proof.as_mut().unwrap().log_index += 1).is_err());
        assert!(change(|entry| entry.inclusion_proof.as_mut().unwrap().tree_size *= 2).is_err());
        assert!(change(|entry| entry.inclusion_proof.as_mut().unwrap().hashes[0][0] ^= 1).is_err());
        assert!(
            change(|entry| entry.inclusion_proof.as_mut().unwrap().hashes.truncate(1)).is_err()
        );
        assert!(change(|entry| entry.canonicalized_body.push(b' ')).is_err());
        assert!(change(|entry| entry.inclusion_proof = None).is_err());
        assert!(change(|_| {}).is_ok());
    }

    #[test]
    fn a_changed_promise_fails_the_signed_entry_timestamp() {
        let (mut bundle, log) = production();
        let promise = bundle.tlog_entries[0].inclusion_promise.as_mut().unwrap();
        let last = promise.len() - 1;
        promise[last] ^= 1;
        let error = verify_signed_entry_timestamp(&bundle.tlog_entries[0], &log.key).unwrap_err();
        assert!(
            error.to_string().contains("signed entry timestamp"),
            "{error}"
        );
    }

    #[test]
    fn the_signed_entry_timestamp_covers_time_index_log_and_body() {
        let (bundle, log) = production();
        let change = |edit: fn(&mut TlogEntry)| {
            let mut entry = bundle.tlog_entries[0].clone();
            edit(&mut entry);
            verify_signed_entry_timestamp(&entry, &log.key)
        };
        // The integrated time is not in the Merkle leaf; only this signature
        // binds it.
        assert!(change(|entry| entry.integrated_time += 1).is_err());
        assert!(change(|entry| entry.log_index += 1).is_err());
        assert!(change(|entry| entry.log_id[0] ^= 1).is_err());
        assert!(change(|entry| entry.canonicalized_body.push(b' ')).is_err());
        assert!(change(|entry| entry.inclusion_promise = None).is_err());
        assert!(change(|_| {}).is_ok());
    }

    #[test]
    fn the_signed_entry_timestamp_payload_is_canonical_json() {
        let (bundle, _) = production();
        let payload = signed_entry_timestamp_payload(&bundle.tlog_entries[0]);
        assert!(payload.starts_with(r#"{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEi"#));
        assert!(payload.ends_with(
            r#"","integratedTime":1774548286,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":1186330805}"#
        ));
    }

    #[test]
    fn a_staging_entry_in_a_tiled_log_passes_inclusion_and_binding() {
        let (bundle, log) = staging();
        let entry = &bundle.tlog_entries[0];
        assert_eq!(
            (entry.kind.as_str(), entry.version.as_str()),
            ("hashedrekord", "0.0.2")
        );
        assert_eq!(entry.integrated_time, 0);
        assert!(entry.inclusion_promise.is_none());
        included(&bundle, &log).unwrap();
        bind(&bundle).unwrap();
        assert!(verify_signed_entry_timestamp(entry, &log.key).is_err());
    }

    #[test]
    fn a_sharded_log_counts_the_proof_index_within_the_shard() {
        let (bundle, log) = production();
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        assert!(has_tree_id(&checkpoint.checkpoint().origin));
        assert_ne!(proof.log_index, entry.log_index);
        included(&bundle, &log).unwrap();
    }

    #[test]
    fn a_single_tree_log_must_agree_with_its_checkpoint_and_entry() {
        let (bundle, log) = staging();
        let entry = &bundle.tlog_entries[0];
        let proof = entry.inclusion_proof.as_ref().unwrap();
        let checkpoint = SignedCheckpoint::decode(&proof.checkpoint).unwrap();
        assert!(!has_tree_id(&checkpoint.checkpoint().origin));
        assert_eq!(checkpoint.checkpoint().origin, log.name);
        assert_eq!(proof.tree_size, checkpoint.checkpoint().size);
        assert_eq!(proof.log_index, entry.log_index);

        // Another index for the entry, with the proof left as it verifies.
        let mut changed = bundle.clone();
        changed.tlog_entries[0].log_index += 1;
        let error = included(&changed, &log).unwrap_err();
        assert!(error.to_string().contains("index differs"), "{error}");

        // Another tree size in the proof than the log signed.
        let mut changed = bundle.clone();
        changed.tlog_entries[0]
            .inclusion_proof
            .as_mut()
            .unwrap()
            .tree_size += 1;
        let error = included(&changed, &log).unwrap_err();
        assert!(error.to_string().contains("tree size differs"), "{error}");
    }

    #[test]
    fn a_tree_identifier_is_a_decimal_suffix_of_the_origin() {
        assert!(has_tree_id("rekor.sigstore.dev - 1193050959916656506"));
        assert!(has_tree_id("a - b - 7"));
        for origin in [
            "log2025-alpha3.rekor.sigstage.dev",
            "rekor.sigstore.dev - ",
            "rekor.sigstore.dev - 12x",
            "rekor.sigstore.dev -12",
            "rekor.sigstore.dev- 12",
            "",
        ] {
            assert!(!has_tree_id(origin), "{origin:?}");
        }
    }

    #[test]
    fn a_payload_that_was_not_logged_fails_the_digest_of_its_encoding() {
        let (mut bundle, _) = staging();
        bundle.envelope.payload = b"{}".to_vec();
        let error = bind(&bundle).unwrap_err();
        assert!(error.to_string().contains("pre-authentication"), "{error}");
        let (mut bundle, _) = staging();
        bundle.envelope.payload_type.push('x');
        assert!(bind(&bundle).is_err());
    }

    #[test]
    fn a_checkpoint_signed_under_another_name_fails_inclusion() {
        let (mut bundle, log) = staging();
        let proof = bundle.tlog_entries[0].inclusion_proof.as_mut().unwrap();
        proof.checkpoint = proof.checkpoint.replace(
            "\u{2014} log2025-alpha3.rekor.sigstage.dev",
            "\u{2014} log2025-alpha3.rekor.github.dev",
        );
        let error = included(&bundle, &log).unwrap_err();
        assert!(error.to_string().contains("not signed by"), "{error}");
    }

    #[test]
    fn a_dsse_entry_of_the_newer_version_is_unsupported() {
        let (mut bundle, _) = staging();
        let entry = &mut bundle.tlog_entries[0];
        entry.kind = "dsse".to_string();
        let body = String::from_utf8(entry.canonicalized_body.clone()).unwrap();
        entry.canonicalized_body = body.replacen("hashedrekord", "dsse", 1).into_bytes();
        let error = bind(&bundle).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported log entry type dsse 0.0.2"),
            "{error}"
        );
    }

    #[test]
    fn a_body_with_a_repeated_member_is_rejected() {
        let (mut bundle, _) = production();
        let entry = &mut bundle.tlog_entries[0];
        let body = String::from_utf8(entry.canonicalized_body.clone()).unwrap();
        entry.canonicalized_body = body
            .replacen(r#""kind":"dsse""#, r#""kind":"dsse","kind":"dsse""#, 1)
            .into_bytes();
        assert!(bind(&bundle).is_err());
    }

    #[test]
    fn a_shard_origin_names_its_own_log() {
        assert!(is_shard_of("log.example - 7", "log.example"));
        for (origin, log_name) in [
            ("other.example - 7", "log.example"),
            ("log.example - 7", "log.exampl"),
            ("log.example.evil - 7", "log.example"),
            ("log.example - x - 7", "log.example"),
            ("log.example - ", "log.example"),
            ("log.example", "log.example"),
            ("log.example -7", "log.example"),
        ] {
            assert!(
                !is_shard_of(origin, log_name),
                "{origin:?} for {log_name:?}"
            );
        }
    }
}
