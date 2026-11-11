//! The evidence that the bundle verifiers share: log entries, the envelope
//! signature, the signed statement, and the times that evidence proves.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use sha2::{Digest, Sha256};

use super::SigstoreError;
use super::bundle::{Bundle, DsseEnvelope, TlogEntry};
use super::rekor::{
    EntrySigner, KIND_HASHEDREKORD, verify_body_binding, verify_inclusion,
    verify_signed_entry_timestamp,
};
use super::statement::{DIGEST_ALGORITHM, PAYLOAD_TYPE, Statement, pae};
use super::trusted_root::TrustedRoot;
use crate::canonical::decode_hex;
use crate::instant::Instant;
use crate::x509::{EcdsaHash, KeyAlgorithm, PublicKey, SignatureScheme};

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// Where a verified time comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// A transparency log's integrated time, authenticated by the log's
    /// signed entry timestamp.
    TransparencyLog,
    /// An RFC 3161 timestamp over the signature.
    TimestampAuthority,
}

/// A time at which the bundle's signature is proven to have existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTime {
    /// The evidence for the time.
    pub source: TimeSource,
    /// The time.
    pub at: Instant,
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
/// 2. an entry must have a signed entry timestamp or an inclusion proof,
///    and a `hashedrekord` 0.0.2 entry must have an inclusion proof;
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
        // Decoding already refuses such an entry; a bundle that was built
        // in memory must not get an unauthenticated entry counted either.
        if !promised && entry.inclusion_proof.is_none() {
            return Err(error(
                "a log entry must have a signed entry timestamp or an inclusion proof",
            ));
        }
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
        if entry.integrated_time != 0
            && let EntrySigner::Certificate(certificate) = signer
            && !integrated.is_some_and(|at| certificate.is_valid_at(at))
        {
            return Err(error("integrated time outside certificate validity"));
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
