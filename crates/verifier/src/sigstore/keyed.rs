//! Bundles signed with a key that the verifier already holds: approvals.
//!
//! An approval carries no certificate chain. Authority comes from a pinned
//! key, named in the bundle by its hint; the transparency log shows that
//! the signature was published; and freshness comes from the timestamp
//! inside the signed statement, not from the bundle.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use sha2::{Digest, Sha256, Sha384};

use super::SigstoreError;
use super::bundle::{Bundle, DsseEnvelope, KeyMaterial, TlogEntry};
use super::certificate::{TimeSource, VerifiedTime};
use super::rekor::{
    self, EntrySigner, KIND_HASHEDREKORD, VERSION_0_0_2, verify_body_binding, verify_inclusion,
    verify_signed_entry_timestamp,
};
use super::statement::{DIGEST_ALGORITHM, PAYLOAD_TYPE, Statement, key_hint, pae};
use super::timestamp::MAX_TIMESTAMP_SIZE;
use super::trusted_root::TrustedRoot;
use crate::canonical::decode_hex;
use crate::instant::Instant;
use crate::x509::{
    Certificate, EcdsaHash, KeyAlgorithm, MAX_CERTIFICATE_SIZE, PublicKey, SignatureScheme,
};

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

/// What verifying the log entries of a bundle established.
#[derive(Debug, Default)]
pub(super) struct LogEvidence {
    /// How many different logs of the trusted root hold a verified entry.
    pub verified_logs: usize,
    /// The integrated times that signed entry timestamps authenticate, one
    /// per log, in bundle order.
    pub times: Vec<VerifiedTime>,
}

/// Verifies the log entries of a bundle against the Rekor logs of a
/// trusted root.
///
/// Every entry, whatever its log, must be the record of this envelope and
/// signer ([`verify_body_binding`]). Then, per entry and in order:
///
/// 1. an entry whose log the trusted root does not list is skipped;
/// 2. a `hashedrekord` 0.0.2 entry must have an inclusion proof;
/// 3. an entry with a signed entry timestamp is skipped unless the
///    timestamp verifies: the entry is a `dsse` 0.0.1 entry, the integrated
///    time is within the period of the log's key, and the signature
///    verifies ([`verify_signed_entry_timestamp`]);
/// 4. an entry with an inclusion proof must be in the log
///    ([`verify_inclusion`]);
/// 5. an entry that states an integrated time must state one within the
///    validity of the signing certificate, when there is one;
/// 6. the entry counts for its log, and with `trust_integrated_time` the
///    first entry of each log with a verified signed entry timestamp
///    contributes its integrated time.
pub(super) fn verify_log_entries(
    root: &TrustedRoot,
    bundle: &Bundle,
    signer: EntrySigner<'_>,
    trust_integrated_time: bool,
) -> Result<LogEvidence, SigstoreError> {
    for entry in &bundle.tlog_entries {
        verify_body_binding(entry, &bundle.envelope, signer)?;
    }
    let mut verified_logs: Vec<&[u8]> = Vec::new();
    let mut timed_logs: Vec<&[u8]> = Vec::new();
    let mut times = Vec::new();
    for entry in &bundle.tlog_entries {
        let Some(log) = root.rekor_log(&entry.log_id) else {
            continue;
        };
        let is_tiled = entry.kind == KIND_HASHEDREKORD;
        if is_tiled && entry.inclusion_proof.is_none() {
            return Err(error("a hashedrekord entry must have an inclusion proof"));
        }
        let integrated = integrated_time(entry);
        let promised = entry.signed_entry_timestamp().is_some();
        if promised {
            let trusted_at_time = integrated.is_some_and(|at| log.valid_for.contains(at));
            if is_tiled
                || !trusted_at_time
                || verify_signed_entry_timestamp(entry, &log.key).is_err()
            {
                continue;
            }
        }
        if entry.inclusion_proof.is_some() {
            verify_inclusion(entry, &log.key, log.checkpoint_name()?)?;
        }
        if entry.integrated_time != 0 {
            if let EntrySigner::Certificate(certificate) = signer {
                if !integrated.is_some_and(|at| certificate.is_valid_at(at)) {
                    return Err(error("integrated time outside certificate validity"));
                }
            }
        }
        if !verified_logs.contains(&entry.log_id.as_slice()) {
            verified_logs.push(&entry.log_id);
        }
        if trust_integrated_time && promised && !timed_logs.contains(&entry.log_id.as_slice()) {
            timed_logs.push(&entry.log_id);
            if let Some(at) = integrated {
                times.push(VerifiedTime {
                    source: TimeSource::TransparencyLog,
                    at,
                });
            }
        }
    }
    Ok(LogEvidence {
        verified_logs: verified_logs.len(),
        times,
    })
}

/// The integrated time of an entry as an instant; `None` when the entry
/// states none or states one outside the representable range.
fn integrated_time(entry: &TlogEntry) -> Option<Instant> {
    if entry.integrated_time == 0 {
        return None;
    }
    Instant::from_unix(entry.integrated_time, 0)
}

/// Whether a DSSE key identifier is acceptable for a signature by `key`:
/// empty, or the key's SSH public key fingerprint (`SHA256:` and the
/// unpadded base64 of the SHA-256 of the key in SSH wire form).
fn key_id_names(key_id: &str, key: &PublicKey) -> bool {
    if key_id.is_empty() {
        return true;
    }
    let (kind, curve) = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => ("ecdsa-sha2-nistp256", "nistp256"),
        KeyAlgorithm::EcdsaP384 => ("ecdsa-sha2-nistp384", "nistp384"),
        _ => return false,
    };
    let point_len = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => 65,
        _ => 97,
    };
    let spki = key.spki_der();
    let Some(point) = spki
        .len()
        .checked_sub(point_len)
        .and_then(|at| spki.get(at..))
    else {
        return false;
    };
    let mut wire = Vec::new();
    for field in [kind.as_bytes(), curve.as_bytes(), point] {
        let Ok(length) = u32::try_from(field.len()) else {
            return false;
        };
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(field);
    }
    key_id == format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&wire)))
}

/// Verifies the envelope's signature under `key`, over the
/// pre-authentication encoding of the payload: ECDSA in DER with SHA-256
/// for a P-256 key, and with SHA-384 or SHA-256 for a P-384 key. The
/// envelope's key identifier must be empty or the key's SSH fingerprint.
pub(super) fn verify_envelope_signature(
    envelope: &DsseEnvelope,
    key: &PublicKey,
) -> Result<(), SigstoreError> {
    if !key_id_names(&envelope.key_id, key) {
        return Err(error("DSSE key identifier does not name the signing key"));
    }
    let hashes: &[EcdsaHash] = match key.algorithm() {
        KeyAlgorithm::EcdsaP256 => &[EcdsaHash::Sha256],
        KeyAlgorithm::EcdsaP384 => &[EcdsaHash::Sha384, EcdsaHash::Sha256],
        other => {
            return Err(error(format!("a {other:?} key cannot sign a bundle")));
        }
    };
    let message = pae(&envelope.payload_type, &envelope.payload);
    if hashes.iter().any(|hash| {
        key.verify(
            SignatureScheme::EcdsaDer(*hash),
            &message,
            &envelope.signature,
        )
        .is_ok()
    }) {
        Ok(())
    } else {
        Err(error("DSSE signature does not verify"))
    }
}

/// Decodes the envelope's payload as a statement and checks that it names
/// `artifact_digest`.
///
/// The payload type is the in-toto statement type; the statement decodes
/// ([`Statement::from_payload`]); every digest of every subject is hex, in
/// either case; and one subject has `artifact_digest` as its SHA-256
/// digest.
pub(super) fn statement_for_digest(
    envelope: &DsseEnvelope,
    artifact_digest: &[u8; 32],
) -> Result<Statement, SigstoreError> {
    if envelope.payload_type != PAYLOAD_TYPE {
        return Err(error("envelope payload is not an in-toto statement"));
    }
    let statement = Statement::from_payload(&envelope.payload)?;
    let mut named = false;
    for subject in &statement.subjects {
        for (algorithm, digest) in &subject.digest {
            let bytes =
                decode_hex(digest).ok_or_else(|| error("statement subject digest is not hex"))?;
            if algorithm == DIGEST_ALGORITHM && bytes == artifact_digest {
                named = true;
            }
        }
    }
    if !named {
        return Err(error(
            "provided artifact digest does not match any digest in statement",
        ));
    }
    Ok(statement)
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
