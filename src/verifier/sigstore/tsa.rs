//! RFC 3161 timestamp verification.
//!
//! Rekor v2 (rekor-tiles) entries carry no signed `integratedTime`, so the
//! only observer timestamp binding the signature to a point in time is the
//! RFC 3161 token in `verificationMaterial.timestampVerificationData`. This
//! module verifies such tokens against the trust root's timestamp authorities:
//!
//! 1. The token is a granted `TimeStampResp` (or bare `TimeStampToken`)
//!    wrapping CMS `SignedData` whose content is `TSTInfo`.
//! 2. `TSTInfo.messageImprint` is the hash of the bundle signature.
//! 3. The CMS `messageDigest` attribute is the hash of the `TSTInfo` bytes and
//!    the CMS signature over the signed attributes verifies under the trusted
//!    TSA leaf certificate (certificates embedded in the token are ignored).
//! 4. The TSA chain is valid at `genTime` (issuer signatures, timestamping
//!    EKU on the leaf) and `genTime` falls within the authority's validity
//!    window from the trust root.
//!
//! Adapted from sigstore-rust `sigstore-tsa` (Apache 2.0 License).

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::{BitString, GeneralizedTime, Int, ObjectIdentifier, OctetString, OctetStringRef};
use der::{Decode, Encode, Sequence};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, SubjectKeyIdentifier};
use x509_cert::ext::Extensions;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use super::fulcio;
use super::trust::TimestampAuthority;
use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const MAX_TIMESTAMPS: usize = 32;

// RFC 3161 §2.4.2 (status) and §2.4.2 (TSTInfo). Only the fields verification
// needs are interpreted; the rest are parsed for structural validity.

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
    time_stamp_token: Option<der::Any>,
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
    #[asn1(context_specific = "0", optional = "true")]
    millis: Option<u16>,
    #[asn1(context_specific = "1", optional = "true")]
    micros: Option<u16>,
}

#[derive(Clone, Debug, Sequence)]
struct TstInfo {
    version: u8,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: Int,
    gen_time: GeneralizedTime,
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

fn err(msg: impl Into<String>) -> Error {
    Error::SigstoreVerification(msg.into())
}

/// Verify the RFC 3161 timestamps in the bundle's `timestampVerificationData`
/// against `signature` (the bundle's DSSE/message signature bytes) and the
/// trusted authorities. Returns the signing times (Unix seconds) of the
/// timestamps that verified, plus the error for each one that did not.
///
/// Like sigstore-go, a timestamp that fails to verify is skipped rather than
/// fatal: the caller decides whether enough observer timestamps remain. Every
/// returned time must still be checked against the certificate validity.
pub fn verify_timestamps(
    bundle: &serde_json::Value,
    signature: &[u8],
    authorities: &[TimestampAuthority],
) -> Result<(Vec<u64>, Vec<Error>)> {
    let timestamps = bundle
        .get("verificationMaterial")
        .and_then(|vm| vm.get("timestampVerificationData"))
        .and_then(|tvd| tvd.get("rfc3161Timestamps"))
        .and_then(|ts| ts.as_array())
        .map(|ts| ts.as_slice())
        .unwrap_or_default();

    // Bound the work an attacker-controlled bundle can demand (sigstore-go
    // caps this too).
    if timestamps.len() > MAX_TIMESTAMPS {
        return Err(err(format!(
            "Too many RFC 3161 timestamps: {} > {MAX_TIMESTAMPS}",
            timestamps.len()
        )));
    }

    let mut times = Vec::new();
    let mut errors = Vec::new();
    for ts in timestamps {
        let verified = ts
            .get("signedTimestamp")
            .and_then(|s| s.as_str())
            .ok_or_else(|| err("RFC 3161 timestamp missing signedTimestamp"))
            .and_then(|b64| {
                decode_b64(b64)
                    .map_err(|e| err(format!("Failed to decode RFC 3161 timestamp: {e}")))
            })
            .and_then(|token| verify_timestamp(&token, signature, authorities));
        match verified {
            Ok(t) => times.push(t),
            Err(e) => errors.push(e),
        }
    }
    Ok((times, errors))
}

/// Verify one DER-encoded RFC 3161 token; returns its `genTime` as Unix seconds.
pub fn verify_timestamp(
    token: &[u8],
    signature: &[u8],
    authorities: &[TimestampAuthority],
) -> Result<u64> {
    let (tst_info, tst_info_der, signed_data) = parse_token(token)?;

    let imprint = &tst_info.message_imprint;
    if hash_with(&imprint.hash_algorithm.oid, signature)? != imprint.hashed_message.as_bytes() {
        return Err(err(
            "RFC 3161 timestamp message imprint does not match the bundle signature",
        ));
    }
    let gen_time = tst_info.gen_time.to_unix_duration().as_secs();

    let signer_infos = &signed_data.signer_infos.0;
    if signer_infos.len() != 1 {
        return Err(err(format!(
            "RFC 3161 timestamp must have exactly 1 signer, got {}",
            signer_infos.len()
        )));
    }
    let signer = signer_infos.get(0).expect("length checked");
    let signed_attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| err("RFC 3161 timestamp has no signed attributes"))?;

    // RFC 5652 §11.1/§11.2: content-type must name TSTInfo, message-digest
    // must be the digest of the encapsulated TSTInfo.
    let content_type: ObjectIdentifier = attribute_value(signed_attrs, &OID_CONTENT_TYPE)?
        .decode_as()
        .map_err(|e| err(format!("Invalid CMS content-type attribute: {e}")))?;
    if content_type != OID_TST_INFO {
        return Err(err("CMS content-type attribute is not TSTInfo"));
    }
    let message_digest: OctetStringRef = attribute_value(signed_attrs, &OID_MESSAGE_DIGEST)?
        .decode_as()
        .map_err(|e| err(format!("Invalid CMS message-digest attribute: {e}")))?;
    if hash_with(&signer.digest_alg.oid, &tst_info_der)? != message_digest.as_bytes() {
        return Err(err("CMS message-digest attribute does not match TSTInfo"));
    }

    // The signature covers the signed attributes re-encoded as a plain SET OF
    // (RFC 5652 §5.4), not the [0] IMPLICIT form they appear in on the wire.
    let signed_attrs_der = signed_attrs
        .to_der()
        .map_err(|e| err(format!("Failed to re-encode CMS signed attributes: {e}")))?;

    let mut last_err = err("No timestamp authority in the trust root");
    for authority in authorities {
        match verify_with_authority(authority, signer, &signed_attrs_der, gen_time) {
            Ok(()) => return Ok(gen_time),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn verify_with_authority(
    authority: &TimestampAuthority,
    signer: &cms::signed_data::SignerInfo,
    signed_attrs_der: &[u8],
    gen_time: u64,
) -> Result<()> {
    if authority.valid_from.is_some_and(|from| gen_time < from)
        || authority.valid_until.is_some_and(|until| gen_time > until)
    {
        return Err(err(format!(
            "Timestamp {gen_time} is outside the timestamp authority's validity window"
        )));
    }

    let chain: Vec<Certificate> = authority
        .cert_chain_der
        .iter()
        .map(|der| {
            Certificate::from_der(der)
                .map_err(|e| err(format!("Failed to parse TSA certificate: {e}")))
        })
        .collect::<Result<_>>()?;
    let leaf = chain
        .first()
        .ok_or_else(|| err("Timestamp authority has an empty certificate chain"))?;

    // Only the trust root's leaf may sign; certificates embedded in the token
    // are untrusted input and never consulted.
    if !signer_matches(&signer.sid, leaf) {
        return Err(err("Timestamp signer is not the trusted TSA certificate"));
    }

    for cert in &chain {
        let validity = &cert.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        if gen_time < not_before || gen_time > not_after {
            return Err(err(format!(
                "Timestamp {gen_time} is outside TSA certificate validity [{not_before}, {not_after}]"
            )));
        }
    }

    // RFC 3161 §2.3: the TSA signing cert is an end-entity cert whose single
    // extended key usage is id-kp-timeStamping, marked critical.
    if matches!(
        leaf.tbs_certificate.get::<BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    ) {
        return Err(err("TSA signing certificate must not be a CA"));
    }
    match leaf
        .tbs_certificate
        .get::<ExtendedKeyUsage>()
        .map_err(|e| err(format!("Failed to parse TSA EKU: {e}")))?
    {
        Some((true, eku)) if eku.0.as_slice() == [OID_KP_TIME_STAMPING] => {}
        _ => {
            return Err(err(
                "TSA certificate must have exactly one critical EKU: timeStamping",
            ))
        }
    }

    if chain.len() == 1 {
        fulcio::verify_issued_by(leaf, leaf, "TSA certificate")?;
    } else {
        fulcio::verify_against_chain(leaf, &authority.cert_chain_der[1..])?;
    }

    verify_cms_signature(
        leaf,
        &signer.digest_alg.oid,
        signed_attrs_der,
        signer.signature.as_bytes(),
    )
}

fn parse_token(token: &[u8]) -> Result<(TstInfo, Vec<u8>, SignedData)> {
    // Sigstore bundles carry a full TimeStampResp; accept a bare token too.
    let content_info = match TimeStampResp::from_der(token) {
        Ok(resp) => {
            if resp.status.status > 1 {
                return Err(err(format!(
                    "RFC 3161 timestamp request was not granted (status {})",
                    resp.status.status
                )));
            }
            let token_any = resp
                .time_stamp_token
                .ok_or_else(|| err("TimeStampResp has no timeStampToken"))?;
            ContentInfo::from_der(
                &token_any
                    .to_der()
                    .map_err(|e| err(format!("Failed to re-encode timeStampToken: {e}")))?,
            )
        }
        Err(_) => ContentInfo::from_der(token),
    }
    .map_err(|e| err(format!("Failed to parse RFC 3161 timestamp token: {e}")))?;

    if content_info.content_type != OID_SIGNED_DATA {
        return Err(err("RFC 3161 token is not CMS SignedData"));
    }
    let signed_data = SignedData::from_der(
        &content_info
            .content
            .to_der()
            .map_err(|e| err(format!("Failed to re-encode SignedData: {e}")))?,
    )
    .map_err(|e| err(format!("Failed to parse CMS SignedData: {e}")))?;

    if signed_data.encap_content_info.econtent_type != OID_TST_INFO {
        return Err(err("CMS SignedData content is not TSTInfo"));
    }
    let tst_info_der = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| err("CMS SignedData has no TSTInfo content"))?
        .value()
        .to_vec();
    let tst_info = TstInfo::from_der(&tst_info_der)
        .map_err(|e| err(format!("Failed to parse TSTInfo: {e}")))?;

    Ok((tst_info, tst_info_der, signed_data))
}

fn attribute_value<'a>(attrs: &'a Attributes, oid: &ObjectIdentifier) -> Result<&'a der::Any> {
    let attr = attrs
        .iter()
        .find(|a| &a.oid == oid)
        .ok_or_else(|| err(format!("CMS signed attribute {oid} missing")))?;
    if attr.values.len() != 1 {
        return Err(err(format!(
            "CMS signed attribute {oid} must have exactly 1 value"
        )));
    }
    Ok(attr.values.get(0).expect("length checked"))
}

fn signer_matches(sid: &SignerIdentifier, cert: &Certificate) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            ias.issuer == cert.tbs_certificate.issuer
                && ias.serial_number == cert.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => matches!(
            cert.tbs_certificate.get::<SubjectKeyIdentifier>(),
            Ok(Some((_, cert_ski))) if &cert_ski == ski
        ),
    }
}

fn hash_with(oid: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match *oid {
        OID_SHA256 => Sha256::digest(data).to_vec(),
        OID_SHA384 => Sha384::digest(data).to_vec(),
        OID_SHA512 => Sha512::digest(data).to_vec(),
        _ => return Err(err(format!("Unsupported RFC 3161 digest algorithm {oid}"))),
    })
}

/// ECDSA (P-256/P-384, DER signature) over `digest_oid(message)` with the certificate's key.
fn verify_cms_signature(
    cert: &Certificate,
    digest_oid: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let digest = hash_with(digest_oid, message)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let key_bytes = spki.subject_public_key.raw_bytes();
    let curve: Option<ObjectIdentifier> = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as().ok());

    let ok = match curve {
        Some(OID_SECP256R1) => {
            use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
            VerifyingKey::from_sec1_bytes(key_bytes)
                .and_then(|k| Signature::from_der(signature).map(|s| (k, s)))
                .is_ok_and(|(k, s)| k.verify_prehash(&digest, &s).is_ok())
        }
        Some(OID_SECP384R1) => {
            use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
            VerifyingKey::from_sec1_bytes(key_bytes)
                .and_then(|k| Signature::from_der(signature).map(|s| (k, s)))
                .is_ok_and(|(k, s)| k.verify_prehash(&digest, &s).is_ok())
        }
        _ => return Err(err("TSA certificate uses an unsupported key type")),
    };
    if !ok {
        return Err(err("RFC 3161 timestamp CMS signature did not verify"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::sigstore::trust;

    const BUNDLE: &str = include_str!("../../../assets/rekor2_dsse_test_bundle.json");
    const TRUSTED_ROOT: &str = include_str!("../../../assets/rekor2_test_trusted_root.json");

    fn bundle() -> serde_json::Value {
        serde_json::from_str(BUNDLE).unwrap()
    }

    fn dsse_signature(bundle: &serde_json::Value) -> Vec<u8> {
        decode_b64(
            bundle["dsseEnvelope"]["signatures"][0]["sig"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    fn authorities() -> Vec<TimestampAuthority> {
        trust::load_timestamp_authorities_from_json(TRUSTED_ROOT).unwrap()
    }

    fn verify(
        b: &serde_json::Value,
        sig: &[u8],
        tsas: &[TimestampAuthority],
    ) -> (Vec<u64>, Vec<String>) {
        let (times, errors) = verify_timestamps(b, sig, tsas).unwrap();
        (times, errors.iter().map(|e| e.to_string()).collect())
    }

    #[test]
    fn verifies_staging_timestamp() {
        let b = bundle();
        let (times, errors) = verify(&b, &dsse_signature(&b), &authorities());
        assert_eq!(times, vec![1778700213]); // 2026-05-13T19:23:33Z, from the token
        assert!(errors.is_empty());
    }

    #[test]
    fn skips_imprint_mismatch() {
        let b = bundle();
        let mut sig = dsse_signature(&b);
        sig[10] ^= 0x01;
        let (times, errors) = verify(&b, &sig, &authorities());
        assert!(times.is_empty());
        assert!(errors[0].contains("message imprint"), "{errors:?}");
    }

    #[test]
    fn skips_tampered_token() {
        let mut b = bundle();
        let ts = &mut b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
            [0]["signedTimestamp"];
        let mut raw = decode_b64(ts.as_str().unwrap()).unwrap();
        let last = raw.len() - 1; // inside the CMS signature value
        raw[last] ^= 0x01;
        *ts = serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            raw,
        ));
        let (times, errors) = verify(&b, &dsse_signature(&b), &authorities());
        assert!(times.is_empty());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn skips_untrusted_authority() {
        // The embedded production root trusts timestamp.sigstore.dev, not the
        // staging TSA that issued this token.
        let b = bundle();
        let prod = trust::load_timestamp_authorities().unwrap();
        let (times, errors) = verify(&b, &dsse_signature(&b), &prod);
        assert!(times.is_empty());
        assert!(errors[0].contains("not the trusted TSA"), "{errors:?}");
    }

    #[test]
    fn skips_time_outside_authority_window() {
        let b = bundle();
        let mut tsas = authorities();
        tsas[0].valid_until = Some(1778700212);
        let (times, errors) = verify(&b, &dsse_signature(&b), &tsas);
        assert!(times.is_empty());
        assert!(errors[0].contains("validity window"), "{errors:?}");
    }

    #[test]
    fn invalid_extra_timestamp_does_not_hide_valid_one() {
        let mut b = bundle();
        let list = b["verificationMaterial"]["timestampVerificationData"]["rfc3161Timestamps"]
            .as_array_mut()
            .unwrap();
        list.push(serde_json::json!({"signedTimestamp": "AAAA"}));
        let (times, errors) = verify(&b, &dsse_signature(&b), &authorities());
        assert_eq!(times, vec![1778700213]);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn no_timestamps_is_empty_not_error() {
        let mut b = bundle();
        b["verificationMaterial"]["timestampVerificationData"] = serde_json::json!({});
        let (times, errors) = verify(&b, &dsse_signature(&b), &authorities());
        assert!(times.is_empty() && errors.is_empty());
    }
}
