//! Bundles signed with a key that the verifier already holds: approvals.
//!
//! An approval carries no certificate chain. Authority comes from a pinned
//! key, named in the bundle by its hint; the transparency log shows that
//! the signature was published; and freshness comes from the timestamp
//! inside the signed statement, not from the bundle.

use super::SigstoreError;
use super::bundle::{Bundle, KeyMaterial};
use super::evidence::{statement_for_digest, verify_envelope_signature, verify_log_entries};
use super::rekor::{EntrySigner, KIND_HASHEDREKORD, VERSION_0_0_2};
use super::statement::{PAYLOAD_TYPE, key_hint};
use super::timestamp::MAX_TIMESTAMP_SIZE;
use super::trusted_root::TrustedRoot;
use crate::x509::{Certificate, KeyAlgorithm, MAX_CERTIFICATE_SIZE, PublicKey};

/// The most log entries in an approval bundle.
pub const MAX_LOG_RECEIPTS: usize = 8;

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// Checks that a bundle has the layout of an approval.
///
/// Rules, each an error when broken:
///
/// - the bundle's media type is
///   [`BUNDLE_V03_MEDIA_TYPE`](super::bundle::BUNDLE_V03_MEDIA_TYPE), not
///   its older spelling; the envelope's payload type is the in-toto
///   statement type, and its one signature is not empty;
/// - the bundle names its key by a non-empty hint, or carries a
///   certificate of 1 to
///   [`MAX_CERTIFICATE_SIZE`](crate::x509::MAX_CERTIFICATE_SIZE) bytes
///   that parses and whose key has a hint
///   ([`statement::key_hint`](super::statement::key_hint));
/// - the envelope's key identifier is empty or equals that hint. The
///   layout tolerates the hint here; signature verification does not (see
///   [`verify_keyed_bundle`]), so in effect only an empty identifier
///   verifies;
/// - there are 1 to [`MAX_LOG_RECEIPTS`] log entries, each `hashedrekord`
///   0.0.2 with an inclusion proof, no inclusion promise (not even one
///   with an empty timestamp) and no integrated time;
/// - a bundle with a certificate has exactly one RFC 3161 timestamp, of 1
///   to [`MAX_TIMESTAMP_SIZE`](super::timestamp::MAX_TIMESTAMP_SIZE) bytes;
///   a bundle with a key hint has none.
pub fn check_approval_layout(bundle: &Bundle) -> Result<(), SigstoreError> {
    if bundle.media_type != super::bundle::BUNDLE_V03_MEDIA_TYPE
        || bundle.envelope.payload_type != PAYLOAD_TYPE
    {
        return Err(error("expected a v0.3 approval DSSE bundle"));
    }
    if bundle.envelope.signature.is_empty() {
        return Err(error("approval requires exactly one signature"));
    }
    let hint = match &bundle.key_material {
        KeyMaterial::PublicKey { hint } => {
            if hint.is_empty() {
                return Err(error("expected an independently trusted public-key hint"));
            }
            hint.clone()
        }
        KeyMaterial::Certificate(der) => {
            if der.is_empty() || der.len() > MAX_CERTIFICATE_SIZE {
                return Err(error("invalid signing certificate size"));
            }
            key_hint(&Certificate::from_der(der)?.public_key()?)?
        }
    };
    if !bundle.envelope.key_id.is_empty() && bundle.envelope.key_id != hint {
        return Err(error("DSSE key ID disagrees with key hint"));
    }
    if bundle.tlog_entries.is_empty() || bundle.tlog_entries.len() > MAX_LOG_RECEIPTS {
        return Err(error(
            "signed bundle requires bounded Rekor inclusion evidence",
        ));
    }
    if bundle.tlog_entries.iter().any(|entry| {
        (entry.kind.as_str(), entry.version.as_str()) != (KIND_HASHEDREKORD, VERSION_0_0_2)
            || entry.integrated_time != 0
            || entry.inclusion_proof.is_none()
            || entry.inclusion_promise.is_some()
    }) {
        return Err(error("signed bundle requires Rekor v2 inclusion proofs"));
    }
    match (&bundle.key_material, bundle.timestamps.as_slice()) {
        (KeyMaterial::Certificate(_), [timestamp])
            if !timestamp.is_empty() && timestamp.len() <= MAX_TIMESTAMP_SIZE =>
        {
            Ok(())
        }
        (KeyMaterial::Certificate(_), _) => Err(error(
            "certified registry endorsement requires one bounded signature timestamp",
        )),
        (KeyMaterial::PublicKey { .. }, []) => Ok(()),
        (KeyMaterial::PublicKey { .. }, _) => {
            Err(error("signed bundle cannot contain observer timestamps"))
        }
    }
}

/// Verifies an approval bundle under a pinned key.
///
/// The caller has checked the layout ([`check_approval_layout`]) and
/// selected `key` as the pinned key whose hint the bundle names.
/// `artifact_digest` is the SHA-256 that the signed statement must name.
/// In order:
///
/// 1. the trusted root lists at least one Rekor log, the bundle names its
///    key by a hint, and `key` is an ECDSA P-256 key;
/// 2. log entries. Every entry is a `hashedrekord` 0.0.2 record whose
///    verifier is `key` (the same SubjectPublicKeyInfo), whose signature
///    is the envelope's and whose digest is the SHA-256 of the
///    pre-authentication encoding of the payload. An entry whose log the
///    trusted root does not list is then skipped, and every other entry
///    must be in its log at a checkpoint signed by the log
///    ([`rekor::verify_inclusion`](super::rekor::verify_inclusion)). At
///    least one entry must verify;
/// 3. the envelope's key identifier is empty or the key's SSH fingerprint,
///    and the signature verifies under `key` over the pre-authentication
///    encoding of the payload: ECDSA P-256 with SHA-256, in DER. A pinned
///    key's hint is never its SSH fingerprint, so a bundle whose identifier
///    equals the hint passes the layout check and is rejected here;
/// 4. the payload decodes as a statement and one of its subjects has
///    `artifact_digest` as its SHA-256 digest.
///
/// No time is established and none is needed: a pinned key does not
/// expire, and the approval's age is judged by its inner timestamp.
pub fn verify_keyed_bundle(
    root: &TrustedRoot,
    bundle: &Bundle,
    key: &PublicKey,
    artifact_digest: &[u8; 32],
) -> Result<(), SigstoreError> {
    if root.rekor_logs().is_empty() {
        return Err(error("Rekor trust is required"));
    }
    if bundle.key_hint().is_none() {
        return Err(error("expected key signature, not certificate"));
    }
    if key.algorithm() != KeyAlgorithm::EcdsaP256 {
        return Err(error("approval requires an ECDSA P-256 key"));
    }
    let evidence = verify_log_entries(root, bundle, EntrySigner::Key(key), false)?;
    if evidence.verified_logs == 0 {
        return Err(error(
            "not enough verified log entries from transparency log",
        ));
    }
    verify_envelope_signature(&bundle.envelope, key)?;
    statement_for_digest(&bundle.envelope, artifact_digest)?;
    Ok(())
}
