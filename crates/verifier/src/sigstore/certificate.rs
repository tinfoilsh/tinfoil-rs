//! Bundles signed with a certificate: a short-lived Fulcio certificate that
//! binds a workload identity, or a registry-issued certificate that binds a
//! registry identity.

use ::der::asn1::ObjectIdentifier;

use super::SigstoreError;
use super::bundle::Bundle;
use super::statement::Statement;
use super::trusted_root::TrustedRoot;
use crate::instant::Instant;
use crate::stub::pending;
use crate::x509::Certificate;

/// The Fulcio extension that names the OIDC issuer (a UTF8String).
pub const OID_FULCIO_ISSUER_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
/// The older Fulcio extension that names the OIDC issuer (raw bytes).
pub const OID_FULCIO_ISSUER_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");
/// The Fulcio extension for the runner environment.
pub const OID_FULCIO_RUNNER_ENVIRONMENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.11");
/// The Fulcio extension for the source repository digest.
pub const OID_FULCIO_SOURCE_REPOSITORY_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.13");
/// The Fulcio extension for the source repository ref.
pub const OID_FULCIO_SOURCE_REPOSITORY_REF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.14");
/// The Fulcio extension for the source repository identifier.
pub const OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.15");
/// The Fulcio extension for the source repository owner identifier.
pub const OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.17");

/// The identity claims that a Fulcio certificate carries beside its subject
/// alternative name. A claim that the certificate does not carry is empty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FulcioExtensions {
    /// The OIDC issuer that authenticated the signer.
    pub issuer: String,
    /// Where the workflow ran, such as `github-hosted`.
    pub runner_environment: String,
    /// The commit that the workflow ran at.
    pub source_repository_digest: String,
    /// The ref that the workflow ran at, such as `refs/tags/v1.2.3`.
    pub source_repository_ref: String,
    /// The immutable identifier of the source repository.
    pub source_repository_identifier: String,
    /// The immutable identifier of the source repository's owner.
    pub source_repository_owner_identifier: String,
}

/// The identity that a signing certificate binds to its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningIdentity {
    /// The single URI of the subject alternative name.
    pub subject_alternative_name: String,
    /// The Fulcio claims.
    pub extensions: FulcioExtensions,
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

/// What a certificate-signed bundle proves once verified.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    /// The signing certificate.
    pub certificate: Certificate,
    /// The identity that the certificate binds. No expectation has been
    /// applied to it: the caller matches it against the identity it wants.
    pub identity: SigningIdentity,
    /// The signed statement.
    pub statement: Statement,
    /// The signed payload, exactly as signed.
    pub payload: Vec<u8>,
    /// Every time that the bundle's evidence proves, in bundle order: log
    /// entries first, then timestamps.
    pub times: Vec<VerifiedTime>,
}

impl VerifiedBundle {
    /// The earliest verified time from a transparency log, if any.
    pub fn earliest_log_time(&self) -> Option<Instant> {
        self.times
            .iter()
            .filter(|time| time.source == TimeSource::TransparencyLog)
            .map(|time| time.at)
            .min()
    }
}

/// Reads the identity of a signing certificate.
///
/// The subject alternative name is critical and holds exactly one name, a
/// URI. Each Fulcio claim that is present is a DER UTF8String with nothing
/// after it; the issuer is read from the newer extension, and from the
/// older raw-bytes extension only when the newer one is absent. When both
/// are present they must agree.
pub fn signing_identity(certificate: &Certificate) -> Result<SigningIdentity, SigstoreError> {
    pending("sigstore::certificate::signing_identity")
}

/// Verifies a bundle signed with a Fulcio certificate.
///
/// `artifact_digest` is the SHA-256 that the signed statement must name.
/// In order, with the first failure returned:
///
/// 1. the bundle carries a certificate, not a key hint; the certificate
///    parses and its key is ECDSA P-256 or P-384; the envelope's payload
///    type is the in-toto statement type and the envelope's key identifier
///    is empty (an identifier that names the certificate's key in another
///    notation is not accepted either);
/// 2. log entries. An entry whose log the trusted root does not list is
///    skipped. Every other entry must verify: its kind is `dsse` 0.0.1 or
///    `hashedrekord` 0.0.2; it is bound to this envelope and certificate
///    ([`rekor::verify_body_binding`](super::rekor::verify_body_binding));
///    with an inclusion promise, the signed entry timestamp verifies under
///    the log's key and the log's key is trusted at the integrated time,
///    and the integrated time becomes a verified time; with an inclusion
///    proof, the entry is in the log
///    ([`rekor::verify_inclusion`](super::rekor::verify_inclusion)). An
///    integrated time is never used unless its signed entry timestamp
///    verified. At least one entry must verify;
/// 3. timestamps. Each RFC 3161 timestamp over the signature that verifies
///    ([`timestamp::verify_signature_timestamps`](super::timestamp::verify_signature_timestamps))
///    is a verified time;
/// 4. there is at least one verified time;
/// 5. at every verified time, the certificate chains to a certificate
///    authority of the trusted root that is trusted at that time, with the
///    code-signing purpose on the whole path
///    ([`verify_chain`](crate::x509::verify_chain));
/// 6. the certificate's embedded timestamps verify
///    ([`sct::verify_scts`](super::sct::verify_scts));
/// 7. the envelope has one signature, and it verifies under the
///    certificate's key over the pre-authentication encoding of the
///    payload: ECDSA in DER with the hash of the key's curve;
/// 8. the payload decodes as a statement
///    ([`Statement::from_payload`]) and one of its subjects has
///    `artifact_digest` as its SHA-256 digest, compared as bytes after
///    decoding the subject's hex in either case;
/// 9. the certificate's identity is read ([`signing_identity`]).
///
/// The caller applies its expectations to the returned identity and
/// statement. No clock is involved: the trusted root is consulted at the
/// verified times only.
pub fn verify_fulcio_bundle(
    root: &TrustedRoot,
    bundle: &Bundle,
    artifact_digest: &[u8; 32],
) -> Result<VerifiedBundle, SigstoreError> {
    pending("sigstore::certificate::verify_fulcio_bundle")
}

/// Verifies a bundle signed with a certificate that `issuer` issued, where
/// the caller has already established trust in `issuer` and checked the
/// certificate's profile.
///
/// The bundle has the approval layout
/// ([`keyed::check_approval_layout`](super::keyed::check_approval_layout)).
/// The steps are those of [`verify_fulcio_bundle`] with these differences:
/// the only certificate authority is `issuer`, trusted at any time; an
/// integrated time is never a verified time, so at least one RFC 3161
/// timestamp over the signature must verify; embedded certificate
/// timestamps are not required; and the issuer claim of the returned
/// identity is empty.
pub fn verify_certified_bundle(
    root: &TrustedRoot,
    bundle: &Bundle,
    issuer: &Certificate,
    artifact_digest: &[u8; 32],
) -> Result<VerifiedBundle, SigstoreError> {
    pending("sigstore::certificate::verify_certified_bundle")
}
