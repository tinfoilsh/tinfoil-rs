//! Rekor transparency-log entries: the signed entry timestamp, inclusion in
//! the log at a signed checkpoint, and the binding of the logged entry to
//! the bundle that carries it.
//!
//! These are the steps; which of them a bundle must pass, and what time
//! they establish, is decided by the bundle verifiers in
//! [`certificate`](super::certificate) and [`keyed`](super::keyed).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::SigstoreError;
use super::bundle::{DsseEnvelope, TlogEntry};
use super::checkpoint::{SignedCheckpoint, verify_log_signature};
use super::merkle;
use super::statement::pae;
use crate::canonical::{decode_base64, encode_lower_hex};
use crate::json::{self, Value};
use crate::x509::PublicKey;
use crate::x509::der::pem_certificates;

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

/// Verifies an entry's signed entry timestamp under the log's key.
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
    verify_log_signature(log_key, payload.as_bytes(), promise)
        .map_err(|cause| cause.within("signed entry timestamp"))
}

/// Verifies that an entry is in its log.
///
/// In order: the entry has an inclusion proof; the proof's checkpoint
/// decodes and carries a valid signature by the log's key under the name
/// `log_name` and the key hint of the entry's log identifier; the
/// checkpoint's root hash equals the proof's root hash; the Merkle proof
/// leads from the leaf hash of the entry's body, at the proof's index in a
/// tree of the proof's size, to that root.
pub fn verify_inclusion(
    entry: &TlogEntry,
    log_key: &PublicKey,
    log_name: &str,
) -> Result<(), SigstoreError> {
    let proof = entry
        .inclusion_proof
        .as_ref()
        .ok_or_else(|| error("log entry has no inclusion proof"))?;
    let checkpoint = SignedCheckpoint::decode(&proof.checkpoint)?;
    checkpoint.verify_signature(log_key, log_name, &entry.log_id)?;
    // The checkpoint is what the log signed, so the proof must lead to its
    // root, not merely to the root that the proof itself states.
    if checkpoint.checkpoint.root_hash != proof.root_hash {
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

/// Verifies that the logged entry is about this envelope and this signing
/// certificate.
///
/// The entry's body is strict JSON. In order:
///
/// 1. the body's `kind` and `apiVersion` equal the entry's kind and
///    version, and are `dsse` 0.0.1 or `hashedrekord` 0.0.2;
/// 2. the certificate in the body is `certificate_der`, byte for byte;
/// 3. the signature in the body is the envelope's signature;
/// 4. the digest in the body is that of the envelope: for `dsse`, SHA-256
///    of the payload; for `hashedrekord`, SHA-256 of the pre-authentication
///    encoding of the payload type and payload.
pub fn verify_body_binding(
    entry: &TlogEntry,
    envelope: &DsseEnvelope,
    certificate_der: &[u8],
) -> Result<(), SigstoreError> {
    let body = json::parse(&entry.canonicalized_body)
        .map_err(|cause| error(format!("log entry body: {cause}")))?;
    let kind = text(&body, &["kind"]);
    let version = text(&body, &["apiVersion"]);
    if kind != Some(entry.kind.as_str()) || version != Some(entry.version.as_str()) {
        return Err(error(format!(
            "log entry body is {kind:?} {version:?}, but the entry says {:?} {:?}",
            entry.kind, entry.version
        )));
    }
    match (entry.kind.as_str(), entry.version.as_str()) {
        (KIND_DSSE, VERSION_0_0_1) => bind_dsse(&body, envelope, certificate_der),
        (KIND_HASHEDREKORD, VERSION_0_0_2) => bind_hashedrekord(&body, envelope, certificate_der),
        (kind, version) => Err(error(format!(
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

fn bind_hashedrekord(
    body: &Value,
    envelope: &DsseEnvelope,
    certificate_der: &[u8],
) -> Result<(), SigstoreError> {
    let record = at(body, &["spec", "hashedRekordV002"])
        .ok_or_else(|| error("hashedrekord log entry has no record"))?;

    let logged_certificate = bytes(
        record,
        &["signature", "verifier", "x509Certificate", "rawBytes"],
        "hashedrekord log entry certificate",
    )?;
    if logged_certificate != certificate_der {
        return Err(error(
            "bundle certificate is not the certificate in the log entry",
        ));
    }

    let logged_signature = bytes(
        record,
        &["signature", "content"],
        "hashedrekord log entry signature",
    )?;
    if logged_signature != envelope.signature {
        return Err(error(
            "bundle signature is not the signature in the log entry",
        ));
    }

    if text(record, &["data", "algorithm"]) != Some("SHA2_256") {
        return Err(error("hashedrekord log entry digest is not SHA-256"));
    }
    let logged_digest = bytes(record, &["data", "digest"], "hashedrekord log entry digest")?;
    let digest = Sha256::digest(pae(&envelope.payload_type, &envelope.payload));
    if logged_digest[..] != digest[..] {
        return Err(error(
            "bundle payload is not the payload in the log entry: the digest of its \
             pre-authentication encoding differs",
        ));
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
        verify_body_binding(
            &bundle.tlog_entries[0],
            &bundle.envelope,
            bundle.certificate_der().unwrap(),
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
        bundle.key_material =
            crate::sigstore::bundle::KeyMaterial::Certificate(b"tampered".to_vec());
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
        assert!(
            error.to_string().contains("checkpoint signature"),
            "{error}"
        );
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
}
