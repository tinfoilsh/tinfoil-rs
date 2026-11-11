//! Bundles signed with a certificate: a short-lived Fulcio certificate that
//! binds a workload identity, or a registry-issued certificate that binds a
//! registry identity.

use ::der::asn1::ObjectIdentifier;

use ::der::Decode;
use ::der::asn1::Utf8StringRef;

use super::SigstoreError;
use super::bundle::Bundle;
pub use super::evidence::{TimeSource, VerifiedTime};
use super::evidence::{statement_for_digest, verify_envelope_signature, verify_log_entries};
use super::rekor::EntrySigner;
use super::sct::verify_scts;
use super::statement::Statement;
use super::timestamp::verify_signature_timestamps;
use super::trusted_root::TrustedRoot;
use crate::instant::Instant;
use crate::x509::{Certificate, KeyAlgorithm, KeyPurpose, verify_chain};

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

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// Reads the identity of a signing certificate.
///
/// The subject alternative name holds exactly one name, a URI. Each Fulcio
/// claim that is present is a DER UTF8String with nothing after it; the
/// issuer is read from the newer extension, and from the older raw-bytes
/// extension (UTF-8 text) only when the newer one is absent. When both are
/// present they must agree.
pub fn signing_identity(certificate: &Certificate) -> Result<SigningIdentity, SigstoreError> {
    let (uris, others) = certificate.subject_alternative_uris()?;
    let [subject_alternative_name] = uris.as_slice() else {
        return Err(error(
            "signing certificate must name exactly one URI as its subject alternative name",
        ));
    };
    if others {
        return Err(error(
            "signing certificate names more than a URI as its subject alternative name",
        ));
    }
    let claim = |oid: ObjectIdentifier| -> Result<String, SigstoreError> {
        let Some(extension) = certificate.extension(oid) else {
            return Ok(String::new());
        };
        Utf8StringRef::from_der(extension.value)
            .map(|text| text.as_str().to_string())
            .map_err(|_| {
                error(format!(
                    "signing certificate claim {oid} is not a UTF8String"
                ))
            })
    };
    let mut issuer = claim(OID_FULCIO_ISSUER_V2)?;
    if let Some(older) = certificate.extension(OID_FULCIO_ISSUER_V1) {
        let older = std::str::from_utf8(older.value)
            .map_err(|_| error("signing certificate issuer claim is not text"))?;
        if certificate.extension(OID_FULCIO_ISSUER_V2).is_none() {
            issuer = older.to_string();
        } else if issuer != older {
            return Err(error("signing certificate states two different issuers"));
        }
    }
    Ok(SigningIdentity {
        subject_alternative_name: subject_alternative_name.clone(),
        extensions: FulcioExtensions {
            issuer,
            runner_environment: claim(OID_FULCIO_RUNNER_ENVIRONMENT)?,
            source_repository_digest: claim(OID_FULCIO_SOURCE_REPOSITORY_DIGEST)?,
            source_repository_ref: claim(OID_FULCIO_SOURCE_REPOSITORY_REF)?,
            source_repository_identifier: claim(OID_FULCIO_SOURCE_REPOSITORY_IDENTIFIER)?,
            source_repository_owner_identifier: claim(
                OID_FULCIO_SOURCE_REPOSITORY_OWNER_IDENTIFIER,
            )?,
        },
    })
}

/// The signing certificate of a bundle, which must be an ECDSA P-256 or
/// P-384 certificate.
fn signing_certificate(bundle: &Bundle) -> Result<Certificate, SigstoreError> {
    let der = bundle
        .certificate_der()
        .ok_or_else(|| error("bundle is not signed with a certificate"))?;
    let certificate = Certificate::from_der(der)?;
    match certificate.public_key()?.algorithm() {
        KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => Ok(certificate),
        other => Err(error(format!(
            "a {other:?} certificate cannot sign a bundle"
        ))),
    }
}

/// Verifies a bundle signed with a Fulcio certificate.
///
/// `artifact_digest` is the SHA-256 that the signed statement must name.
/// In order, with the first failure returned:
///
/// 1. the bundle carries a certificate, not a key hint; the certificate
///    parses and its key is ECDSA P-256 or P-384;
/// 2. log entries. Every entry, whatever its log, is the record of this
///    envelope and certificate: `dsse` 0.0.1 or `hashedrekord` 0.0.2
///    ([`rekor::verify_body_binding`](super::rekor::verify_body_binding)).
///    An entry whose log the trusted root does not list is then skipped.
///    An entry with a signed entry timestamp is skipped unless that
///    timestamp verifies under the log's key and the log's key is trusted
///    at the integrated time; when it verifies, the integrated time becomes
///    a verified time, once per log. An entry with an inclusion proof must
///    be in the log
///    ([`rekor::verify_inclusion`](super::rekor::verify_inclusion)), and an
///    entry that states an integrated time must state one within the
///    certificate's validity. An integrated time is never a verified time
///    unless its signed entry timestamp verified. At least one entry must
///    verify;
/// 3. timestamps. Each RFC 3161 timestamp over the signature that verifies
///    ([`timestamp::verify_signature_timestamps`](super::timestamp::verify_signature_timestamps))
///    is a verified time; one that does not verify is ignored;
/// 4. there is at least one verified time;
/// 5. the certificate's identity is read ([`signing_identity`]);
/// 6. at every verified time, the certificate chains to a certificate
///    authority of the trusted root that is trusted at that time, with the
///    code-signing purpose on the whole path
///    ([`verify_chain`]);
/// 7. the certificate's embedded timestamps verify for the issuer on the
///    path of the last verified time
///    ([`sct::verify_scts`](super::sct::verify_scts));
/// 8. the envelope's key identifier is empty or the SSH fingerprint of the
///    certificate's key, and the signature verifies under that key over the
///    pre-authentication encoding of the payload: ECDSA in DER, with
///    SHA-256 for a P-256 key and with SHA-384 or SHA-256 for a P-384 key;
/// 9. the envelope's payload type is the in-toto statement type, the
///    payload decodes as a statement ([`Statement::from_payload`]), every
///    subject digest is hex, and one of its subjects has `artifact_digest`
///    as its SHA-256 digest, compared as bytes after decoding the subject's
///    hex in either case.
///
/// The caller applies its expectations to the returned identity and
/// statement. No clock is involved: the trusted root is consulted at the
/// verified times only.
pub fn verify_fulcio_bundle(
    root: &TrustedRoot,
    bundle: &Bundle,
    artifact_digest: &[u8; 32],
) -> Result<VerifiedBundle, SigstoreError> {
    let certificate = signing_certificate(bundle)?;
    let evidence = verify_log_entries(root, bundle, EntrySigner::Certificate(&certificate), true)?;
    if evidence.verified_logs == 0 {
        return Err(error(
            "not enough verified log entries from transparency log",
        ));
    }
    let mut times = evidence.times;
    times.extend(
        verify_signature_timestamps(root, bundle)?
            .into_iter()
            .map(|at| VerifiedTime {
                source: TimeSource::TimestampAuthority,
                at,
            }),
    );
    if times.is_empty() {
        return Err(error(
            "threshold not met for verified signed and log entry integrated timestamps",
        ));
    }
    let identity = signing_identity(&certificate)?;

    let mut issuers: Vec<Certificate> = Vec::new();
    for time in &times {
        let path = root
            .certificate_authorities()
            .iter()
            .filter(|authority| authority.valid_for.contains(time.at))
            .find_map(|authority| {
                verify_chain(
                    &certificate,
                    &authority.intermediates,
                    std::slice::from_ref(&authority.root),
                    time.at,
                    KeyPurpose::CodeSigning,
                )
                .ok()
            })
            .ok_or_else(|| error("leaf certificate verification failed"))?;
        issuers = path
            .get(1)
            .map(|issuer| (*issuer).clone())
            .into_iter()
            .collect();
    }
    verify_scts(root, &certificate, &issuers)
        .map_err(|cause| cause.within("failed to verify signed certificate timestamp"))?;

    verify_envelope_signature(&bundle.envelope, &certificate.public_key()?)?;
    let statement = statement_for_digest(&bundle.envelope, artifact_digest)?;
    Ok(VerifiedBundle {
        certificate,
        identity,
        statement,
        payload: bundle.envelope.payload.clone(),
        times,
    })
}

/// Verifies a bundle signed with a certificate that `issuer` issued, where
/// the caller has already established trust in `issuer` and checked the
/// certificate's profile.
///
/// The caller has checked that the bundle has the approval layout
/// ([`keyed::check_approval_layout`](super::keyed::check_approval_layout)).
/// The steps are those of [`verify_fulcio_bundle`] with these differences:
/// the only certificate authority is `issuer`, trusted at any time, with no
/// intermediates; an integrated time is never a verified time, so at least
/// one RFC 3161 timestamp over the signature must verify, and the verified
/// times are those of the timestamps, in bundle order; embedded certificate
/// timestamps are not required; and the certificate must carry no issuer
/// claim, so the issuer of the returned identity is empty.
pub fn verify_certified_bundle(
    root: &TrustedRoot,
    bundle: &Bundle,
    issuer: &Certificate,
    artifact_digest: &[u8; 32],
) -> Result<VerifiedBundle, SigstoreError> {
    let certificate = signing_certificate(bundle)?;
    let evidence = verify_log_entries(root, bundle, EntrySigner::Certificate(&certificate), false)?;
    if evidence.verified_logs == 0 {
        return Err(error(
            "not enough verified log entries from transparency log",
        ));
    }
    let times: Vec<VerifiedTime> = verify_signature_timestamps(root, bundle)?
        .into_iter()
        .map(|at| VerifiedTime {
            source: TimeSource::TimestampAuthority,
            at,
        })
        .collect();
    if times.is_empty() {
        return Err(error("threshold not met for verified signed timestamps"));
    }
    let identity = signing_identity(&certificate)?;
    for time in &times {
        verify_chain(
            &certificate,
            &[],
            std::slice::from_ref(issuer),
            time.at,
            KeyPurpose::CodeSigning,
        )
        .map_err(|cause| error(format!("leaf certificate verification failed: {cause}")))?;
    }
    verify_envelope_signature(&bundle.envelope, &certificate.public_key()?)?;
    let statement = statement_for_digest(&bundle.envelope, artifact_digest)?;
    if !identity.extensions.issuer.is_empty() {
        return Err(error(
            "a registry signing certificate must carry no issuer claim",
        ));
    }
    Ok(VerifiedBundle {
        certificate,
        identity,
        statement,
        payload: bundle.envelope.payload.clone(),
        times,
    })
}
