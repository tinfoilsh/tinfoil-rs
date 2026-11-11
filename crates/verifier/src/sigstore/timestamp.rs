//! RFC 3161 timestamps: a timestamp authority's signed statement that some
//! bytes existed at a time.
//!
//! Two uses: the timestamp over a bundle's signature, which dates the
//! signature for certificate validity, and the timestamp inside an approval
//! statement, which is what bounds the approval's age.

use ::der::asn1::{BitString, Int, ObjectIdentifier, OctetString, OctetStringRef};
use ::der::{Decode, Encode, Sequence, Tag, Tagged};
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::attr::Attributes;
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::SigstoreError;
use super::bundle::Bundle;
use super::trusted_root::TrustedRoot;
use crate::instant::Instant;
use crate::stub::pending;
use crate::x509::der::{Fraction, parse_generalized_time};
use crate::x509::{Certificate, EcdsaHash, SignatureScheme};

/// The largest timestamp response that is read, in bytes.
pub const MAX_TIMESTAMP_SIZE: usize = 64 << 10;

/// The policy under which the Sigstore timestamp authority issues
/// timestamps.
pub const SIGSTORE_TIMESTAMP_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.2");

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// The `status` of a response that grants the request as asked.
const STATUS_GRANTED: u8 = 0;
/// The only version of `TSTInfo`.
const TST_INFO_VERSION: u8 = 1;

#[derive(Clone, Debug, Sequence)]
struct PkiStatusInfo {
    status: u8,
    #[asn1(optional = "true")]
    status_string: Option<Vec<String>>,
    #[asn1(optional = "true")]
    fail_info: Option<BitString>,
}

#[derive(Clone, Debug, Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<::der::Any>,
}

#[derive(Clone, Debug, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

#[derive(Clone, Debug, Sequence)]
struct Accuracy {
    #[asn1(optional = "true")]
    seconds: Option<u64>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "IMPLICIT")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    micros: Option<u16>,
}

#[derive(Clone, Debug, Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    /// A GeneralizedTime, read by hand because it may carry a fraction.
    gen_time: ::der::Any,
    #[asn1(optional = "true")]
    accuracy: Option<Accuracy>,
    #[asn1(default = "default_false")]
    ordering: bool,
    #[asn1(optional = "true")]
    nonce: Option<Int>,
    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    tsa: Option<GeneralName>,
    #[asn1(context_specific = "1", optional = "true", tag_mode = "IMPLICIT")]
    extensions: Option<Extensions>,
}

fn default_false() -> bool {
    false
}

fn error(message: impl Into<String>) -> SigstoreError {
    SigstoreError::new(message)
}

/// The bounds within which an approval's timestamp must fall for the
/// approval to count at the time of appraisal. Both ends are inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppraisalWindow {
    /// The oldest acceptable instant: the appraisal time less the greatest
    /// age.
    pub earliest: Instant,
    /// The newest acceptable instant: the appraisal time plus the allowed
    /// clock skew.
    pub latest: Instant,
}

impl AppraisalWindow {
    /// Checks that `at` is not before the window ("too old") and not after
    /// it ("in the future").
    pub fn check(&self, at: Instant) -> Result<(), SigstoreError> {
        if at < self.earliest {
            return Err(error("approval is too old"));
        }
        if at > self.latest {
            return Err(error("timestamp is in the future"));
        }
        Ok(())
    }
}

/// A decoded timestamp response. Nothing in it is authenticated until
/// [`ParsedTimestamp::verify_signer`] has accepted a trusted signer.
#[derive(Debug, Clone)]
pub struct ParsedTimestamp {
    /// The time that the authority states, `genTime`.
    pub gen_time: Instant,
    /// The policy under which the timestamp was issued.
    pub policy: ObjectIdentifier,
    /// The hash algorithm of the message imprint.
    pub hash_algorithm: ObjectIdentifier,
    /// The hash that the timestamp covers.
    pub hashed_message: Vec<u8>,
    tst_info_der: Vec<u8>,
    signed_data: SignedData,
}

/// Decodes a DER `TimeStampResp`.
///
/// Rules, each an error when broken:
///
/// - 1 to [`MAX_TIMESTAMP_SIZE`] bytes of canonical DER with nothing after
///   it;
/// - the status is `granted`: a rejection, a grant with modifications and a
///   response without a token are all errors;
/// - the token is CMS SignedData whose content is a `TSTInfo`;
/// - the `TSTInfo` has version 1, and its `genTime` is a GeneralizedTime
///   in UTC, optionally with a fraction of a second
///   ([`parse_generalized_time`]).
pub fn parse_response(response: &[u8]) -> Result<ParsedTimestamp, SigstoreError> {
    if response.is_empty() || response.len() > MAX_TIMESTAMP_SIZE {
        return Err(error("timestamp response size is outside allowed bounds"));
    }
    let parsing = |cause: ::der::Error| error(format!("parsing timestamp response: {cause}"));
    let response = TimeStampResp::from_der(response).map_err(parsing)?;
    if response.status.status != STATUS_GRANTED {
        return Err(error(format!(
            "timestamp request was not granted (status {})",
            response.status.status
        )));
    }
    let token = response
        .time_stamp_token
        .ok_or_else(|| error("timestamp response has no token"))?;
    let content_info = ContentInfo::from_der(&token.to_der().map_err(parsing)?).map_err(parsing)?;
    if content_info.content_type != OID_SIGNED_DATA {
        return Err(error("timestamp token is not CMS SignedData"));
    }
    let signed_data =
        SignedData::from_der(&content_info.content.to_der().map_err(parsing)?).map_err(parsing)?;
    if signed_data.encap_content_info.econtent_type != OID_TST_INFO {
        return Err(error("timestamp token content is not a TSTInfo"));
    }
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| error("timestamp token has no content"))?
        .decode_as::<OctetStringRef<'_>>()
        .map_err(parsing)?
        .as_bytes()
        .to_vec();
    let tst_info = TstInfo::from_der(&tst_info_der).map_err(parsing)?;
    if tst_info.version != TST_INFO_VERSION {
        return Err(error(format!(
            "timestamp info has version {}, want {TST_INFO_VERSION}",
            tst_info.version
        )));
    }
    if tst_info.gen_time.tag() != Tag::GeneralizedTime {
        return Err(error("timestamp time is not a GeneralizedTime"));
    }
    let gen_time = parse_generalized_time(tst_info.gen_time.value(), Fraction::Allowed)?;
    Ok(ParsedTimestamp {
        gen_time,
        policy: tst_info.policy,
        hash_algorithm: tst_info.message_imprint.hash_algorithm.oid,
        hashed_message: tst_info.message_imprint.hashed_message.as_bytes().to_vec(),
        tst_info_der,
        signed_data,
    })
}

impl ParsedTimestamp {
    /// Checks that the timestamp covers `input`: the message imprint is the
    /// SHA-256 of `input`. An imprint under any other hash is an error.
    pub fn check_imprint(&self, input: &[u8]) -> Result<(), SigstoreError> {
        if self.hash_algorithm != OID_SHA256 || self.hashed_message[..] != Sha256::digest(input)[..]
        {
            return Err(error("timestamp does not cover the expected bytes"));
        }
        Ok(())
    }

    /// Verifies that `signer` signed the timestamp.
    ///
    /// In order: the token has exactly one signer; its signed attributes
    /// are present, say that the content is a `TSTInfo`, and carry the
    /// digest of the token's `TSTInfo`; the signer is identified as
    /// `signer`, by issuer and serial number or by subject key identifier;
    /// the signature over the signed attributes verifies under `signer`'s
    /// key, as ECDSA over the signer's digest algorithm (SHA-256, SHA-384
    /// or SHA-512).
    ///
    /// Certificates embedded in the token are not consulted: only a
    /// certificate that the caller already trusts can be `signer`. Whether
    /// `signer` chains to a trusted root, may sign timestamps, and was
    /// valid at the stated time is checked by [`verify_timestamp`].
    pub fn verify_signer(&self, signer: &Certificate) -> Result<(), SigstoreError> {
        let mut signers = self.signed_data.signer_infos.0.iter();
        let (Some(info), None) = (signers.next(), signers.next()) else {
            return Err(error("timestamp token must have exactly one signer"));
        };
        let signed_attributes = info
            .signed_attrs
            .as_ref()
            .ok_or_else(|| error("timestamp token has no signed attributes"))?;

        let content_type: ObjectIdentifier = attribute(signed_attributes, OID_CONTENT_TYPE)?
            .decode_as()
            .map_err(|_| error("timestamp content-type attribute is malformed"))?;
        if content_type != OID_TST_INFO {
            return Err(error("timestamp content-type attribute is not TSTInfo"));
        }
        let message_digest: OctetStringRef<'_> = attribute(signed_attributes, OID_MESSAGE_DIGEST)?
            .decode_as()
            .map_err(|_| error("timestamp message-digest attribute is malformed"))?;
        let digest_algorithm = digest_of(info.digest_alg.oid)?;
        if message_digest.as_bytes() != hash(digest_algorithm, &self.tst_info_der) {
            return Err(error(
                "timestamp message-digest attribute does not match the timestamp info",
            ));
        }

        if !identifies(&info.sid, signer) {
            return Err(error("timestamp signer is not the trusted certificate"));
        }

        // The signature covers the attributes as a SET OF, not under the
        // context tag that they carry inside the signer info.
        let signed_bytes = signed_attributes
            .to_der()
            .map_err(|cause| error(format!("encoding signed attributes: {cause}")))?;
        signer
            .public_key()?
            .verify(
                SignatureScheme::EcdsaDer(digest_algorithm),
                &signed_bytes,
                info.signature.as_bytes(),
            )
            .map_err(|cause| error(format!("timestamp token: {cause}")))
    }
}

/// The single value of a signed attribute.
fn attribute(attributes: &Attributes, oid: ObjectIdentifier) -> Result<&::der::Any, SigstoreError> {
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.oid == oid)
        .ok_or_else(|| error(format!("timestamp signed attribute {oid} is missing")))?;
    let mut values = attribute.values.iter();
    match (values.next(), values.next()) {
        (Some(value), None) => Ok(value),
        _ => Err(error(format!(
            "timestamp signed attribute {oid} must have exactly one value"
        ))),
    }
}

/// Whether a signer identifier names `certificate`.
fn identifies(identifier: &SignerIdentifier, certificate: &Certificate) -> bool {
    match identifier {
        SignerIdentifier::IssuerAndSerialNumber(named) => {
            let parsed = certificate.parsed();
            named.issuer == parsed.tbs_certificate.issuer
                && named.serial_number == parsed.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(named) => certificate
            .extension(OID_SUBJECT_KEY_IDENTIFIER)
            .and_then(|extension| OctetStringRef::from_der(extension.value).ok())
            .is_some_and(|own| own.as_bytes() == named.0.as_bytes()),
    }
}

fn digest_of(oid: ObjectIdentifier) -> Result<EcdsaHash, SigstoreError> {
    if oid == OID_SHA256 {
        Ok(EcdsaHash::Sha256)
    } else if oid == OID_SHA384 {
        Ok(EcdsaHash::Sha384)
    } else if oid == OID_SHA512 {
        Ok(EcdsaHash::Sha512)
    } else {
        Err(error(format!(
            "unsupported timestamp digest algorithm {oid}"
        )))
    }
}

fn hash(algorithm: EcdsaHash, data: &[u8]) -> Vec<u8> {
    match algorithm {
        EcdsaHash::Sha256 => Sha256::digest(data).to_vec(),
        EcdsaHash::Sha384 => Sha384::digest(data).to_vec(),
        EcdsaHash::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// Authenticates a timestamp response over `input` against the timestamp
/// authorities of a trusted root, and returns the authenticated time.
///
/// In order:
///
/// 1. the response decodes ([`parse_response`]) and covers `input`
///    ([`ParsedTimestamp::check_imprint`]);
/// 2. with `policy` given, the timestamp was issued under that policy;
/// 3. one authority of the trusted root authenticates it. For an
///    authority to do so: the stated time is within the authority's period
///    ([`ValidFor`](super::trusted_root::ValidFor)); the authority's
///    signing certificate signed the token
///    ([`ParsedTimestamp::verify_signer`]); the signing certificate is not
///    a CA and carries exactly one extended key usage, time stamping,
///    marked critical; and it chains to the authority's root at the stated
///    time with the time-stamping purpose
///    ([`verify_chain`](crate::x509::verify_chain)). Authorities are tried
///    in order and the first that authenticates the timestamp decides.
///
/// The appraisal time plays no part here: a caller that bounds the age of
/// the timestamp applies an [`AppraisalWindow`] to the result.
pub fn verify_timestamp(
    root: &TrustedRoot,
    response: &[u8],
    input: &[u8],
    policy: Option<ObjectIdentifier>,
) -> Result<Instant, SigstoreError> {
    pending("sigstore::timestamp::verify_timestamp")
}

/// Authenticates the RFC 3161 timestamps of a bundle, which cover the
/// bundle's DSSE signature, and returns the authenticated times in bundle
/// order.
///
/// Each timestamp is verified with [`verify_timestamp`] over the signature
/// bytes, without a policy requirement. A timestamp that does not verify is
/// skipped; the caller decides how many it needs.
pub fn verify_signature_timestamps(
    root: &TrustedRoot,
    bundle: &Bundle,
) -> Result<Vec<Instant>, SigstoreError> {
    pending("sigstore::timestamp::verify_signature_timestamps")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::decode_hex;
    use crate::sigstore::testutil;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    /// The staging bundle's timestamp response, the signature that it
    /// covers, and the staging authority's signing certificate.
    fn staging() -> (Vec<u8>, Vec<u8>, Certificate) {
        let mut bundle = testutil::bundle(testutil::REKOR_V2_BUNDLE);
        let mut chain = testutil::timestamp_authority(testutil::STAGING_TRUSTED_ROOT);
        (
            bundle.timestamps.remove(0),
            bundle.envelope.signature,
            chain.remove(0),
        )
    }

    #[test]
    fn accuracy_uses_implicit_tags() {
        // seconds 1, millis [0] 999, micros [1] 999
        let encoded = decode_hex("300b020101800203e7810203e7").unwrap();
        let accuracy = Accuracy::from_der(&encoded).unwrap();
        assert_eq!(
            (accuracy.seconds, accuracy.millis, accuracy.micros),
            (Some(1), Some(999), Some(999))
        );
    }

    #[test]
    fn a_staging_timestamp_decodes() {
        let (response, _, _) = staging();
        let timestamp = parse_response(&response).unwrap();
        assert_eq!(timestamp.gen_time, at("2026-05-13T19:23:33Z"));
        assert_eq!(timestamp.gen_time.unix_seconds(), 1_778_700_213);
        assert_eq!(timestamp.hash_algorithm, OID_SHA256);
        assert_eq!(timestamp.hashed_message.len(), 32);
    }

    #[test]
    fn a_timestamp_covers_only_the_bytes_that_it_hashed() {
        let (response, mut signature, _) = staging();
        let timestamp = parse_response(&response).unwrap();
        timestamp.check_imprint(&signature).unwrap();
        signature[10] ^= 1;
        let error = timestamp.check_imprint(&signature).unwrap_err();
        assert!(error.to_string().contains("does not cover"), "{error}");
    }

    #[test]
    fn a_staging_timestamp_verifies_under_the_staging_authority() {
        let (response, _, signer) = staging();
        parse_response(&response)
            .unwrap()
            .verify_signer(&signer)
            .unwrap();
    }

    #[test]
    fn a_tampered_token_does_not_verify() {
        let (mut response, _, signer) = staging();
        // The last byte is inside the CMS signature value.
        let last = response.len() - 1;
        response[last] ^= 1;
        let timestamp = parse_response(&response).unwrap();
        assert!(timestamp.verify_signer(&signer).is_err());
    }

    #[test]
    fn a_changed_timestamp_info_does_not_match_its_digest() {
        let (response, _, signer) = staging();
        let mut timestamp = parse_response(&response).unwrap();
        let last = timestamp.tst_info_der.len() - 1;
        timestamp.tst_info_der[last] ^= 1;
        let error = timestamp.verify_signer(&signer).unwrap_err();
        assert!(error.to_string().contains("message-digest"), "{error}");
    }

    #[test]
    fn another_authority_is_not_the_signer() {
        // The production trusted root lists the production authority, not
        // the staging authority that issued this token.
        let (response, _, _) = staging();
        let mut production = testutil::timestamp_authority(testutil::PRODUCTION_TRUSTED_ROOT);
        let error = parse_response(&response)
            .unwrap()
            .verify_signer(&production.remove(0))
            .unwrap_err();
        assert!(
            error.to_string().contains("not the trusted certificate"),
            "{error}"
        );
    }

    #[test]
    fn a_response_outside_the_size_bounds_is_rejected() {
        assert!(parse_response(&[]).is_err());
        assert!(parse_response(&vec![0x30; MAX_TIMESTAMP_SIZE + 1]).is_err());
    }

    #[test]
    fn a_response_with_trailing_data_or_no_token_is_rejected() {
        let (mut response, _, _) = staging();
        response.push(0);
        assert!(parse_response(&response).is_err());
        // TimeStampResp { PKIStatusInfo { status 0 } }
        let error = parse_response(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]).unwrap_err();
        assert!(error.to_string().contains("no token"), "{error}");
        // A bare token, without the response around it.
        let (response, _, _) = staging();
        let wrapped = TimeStampResp::from_der(&response).unwrap();
        let token = wrapped.time_stamp_token.unwrap().to_der().unwrap();
        assert!(parse_response(&token).is_err());
    }

    #[test]
    fn only_a_granted_response_is_accepted() {
        let (response, _, _) = staging();
        let granted = TimeStampResp::from_der(&response).unwrap();
        for status in [1u8, 2, 3, 4, 5] {
            let mut changed = granted.clone();
            changed.status.status = status;
            let error = parse_response(&changed.to_der().unwrap()).unwrap_err();
            assert!(error.to_string().contains("not granted"), "{error}");
        }
    }

    #[test]
    fn a_window_includes_both_of_its_ends() {
        let window = AppraisalWindow {
            earliest: at("2026-05-06T19:23:33Z"),
            latest: at("2026-05-13T19:28:33Z"),
        };
        window.check(window.earliest).unwrap();
        window.check(window.latest).unwrap();
        let too_old = window
            .check(at("2026-05-06T19:23:32.999999999Z"))
            .unwrap_err();
        assert_eq!(too_old.to_string(), "approval is too old");
        let future = window
            .check(at("2026-05-13T19:28:33.000000001Z"))
            .unwrap_err();
        assert_eq!(future.to_string(), "timestamp is in the future");
    }
}
