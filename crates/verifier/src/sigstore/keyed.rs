//! Bundles signed with a key that the verifier already holds: approvals.
//!
//! An approval carries no certificate chain. Authority comes from a pinned
//! key, named in the bundle by its hint; the transparency log shows that
//! the signature was published; and freshness comes from the timestamp
//! inside the signed statement, not from the bundle.

use super::SigstoreError;
use super::bundle::Bundle;
use super::trusted_root::TrustedRoot;
use crate::stub::pending;
use crate::x509::PublicKey;

/// The most log entries in an approval bundle.
pub const MAX_LOG_RECEIPTS: usize = 8;

/// Checks that a bundle has the layout of an approval.
///
/// Rules, each an error when broken:
///
/// - the envelope's payload type is the in-toto statement type, and its
///   one signature is not empty;
/// - the bundle names its key by a non-empty hint, or carries a
///   certificate of 1 to
///   [`MAX_CERTIFICATE_SIZE`](crate::x509::MAX_CERTIFICATE_SIZE) bytes
///   that parses and whose key has a hint
///   ([`statement::key_hint`](super::statement::key_hint));
/// - the envelope's key identifier is empty or equals that hint;
/// - there are 1 to [`MAX_LOG_RECEIPTS`] log entries, each `hashedrekord`
///   0.0.2 with an inclusion proof, no inclusion promise and no integrated
///   time;
/// - a bundle with a certificate has exactly one RFC 3161 timestamp, of 1
///   to [`MAX_TIMESTAMP_SIZE`](super::timestamp::MAX_TIMESTAMP_SIZE) bytes;
///   a bundle with a key hint has none.
pub fn check_approval_layout(bundle: &Bundle) -> Result<(), SigstoreError> {
    pending("sigstore::keyed::check_approval_layout")
}

/// Verifies an approval bundle under a pinned key.
///
/// The caller has checked the layout ([`check_approval_layout`]) and
/// selected `key` as the pinned key whose hint the bundle names.
/// `artifact_digest` is the SHA-256 that the signed statement must name.
/// In order:
///
/// 1. the trusted root lists at least one Rekor log;
/// 2. log entries. An entry whose log the trusted root does not list is
///    skipped. Every other entry must verify: its body is a `hashedrekord`
///    0.0.2 record whose verifier is `key` (the same
///    SubjectPublicKeyInfo), whose signature is the envelope's and whose
///    digest is the SHA-256 of the pre-authentication encoding of the
///    payload; and the entry is in the log at a checkpoint signed by the
///    log ([`rekor::verify_inclusion`](super::rekor::verify_inclusion)).
///    At least one entry must verify;
/// 3. the envelope's key identifier is empty, and the signature verifies
///    under `key` over the pre-authentication encoding of the payload:
///    ECDSA P-256 with SHA-256, in DER;
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
    pending("sigstore::keyed::verify_keyed_bundle")
}
