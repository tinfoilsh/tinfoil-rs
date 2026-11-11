//! X.509 certificates.

use ::der::asn1::ObjectIdentifier;
use ::der::{Decode, Encode, Tag, Tagged};
use x509_cert::time::Time;

use super::der::{bit_string, first_element_of_sequence};
use super::extension::{self, AlternativeNames};
use super::key::{EcdsaHash, PublicKey, SignatureScheme};
use super::{MAX_CERTIFICATE_SIZE, X509Error};
use crate::instant::Instant;

/// `ecdsa-with-SHA256`.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384`.
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `ecdsa-with-SHA512`.
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
/// `id-RSASSA-PSS`.
const OID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
/// `id-mgf1`.
const OID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
/// `id-sha384`.
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// The subject or the issuer name of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameField {
    /// The subject.
    Subject,
    /// The issuer.
    Issuer,
}

/// One extension of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'a> {
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// The contents of the extension's OCTET STRING: the DER of the
    /// extension's own value.
    pub value: &'a [u8],
}

/// The basic constraints of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the certificate may issue certificates.
    pub ca: bool,
    /// The longest chain of CA certificates that may follow this one.
    pub path_len: Option<u8>,
}

/// The key usage bits that the verifier reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage {
    /// `digitalSignature`.
    pub digital_signature: bool,
    /// `nonRepudiation`.
    pub content_commitment: bool,
    /// `keyCertSign`.
    pub key_cert_sign: bool,
    /// `cRLSign`.
    pub crl_sign: bool,
    /// Whether any other of the nine defined bits is set.
    pub other: bool,
}

impl KeyUsage {
    /// Whether none of the nine defined bits is set. Such an extension
    /// restricts nothing: it is treated like an absent one.
    pub fn is_empty(&self) -> bool {
        !(self.digital_signature
            || self.content_commitment
            || self.key_cert_sign
            || self.crl_sign
            || self.other)
    }
}

/// A parsed certificate together with the bytes it was parsed from.
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    not_before: Instant,
    not_after: Instant,
    parsed: x509_cert::Certificate,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Certificate({} bytes)", self.der.len())
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Certificate {}

impl Certificate {
    /// Parses a DER certificate.
    ///
    /// Rules, each an error when broken:
    ///
    /// - at most [`MAX_CERTIFICATE_SIZE`] bytes;
    /// - canonical DER with nothing after it: the certificate re-encodes to
    ///   exactly the input;
    /// - the inner and outer signature algorithms are identical;
    /// - the signature bit string has no unused bits;
    /// - the validity times are in the forms of
    ///   [`parse_utc_time`](super::der::parse_utc_time) and
    ///   [`parse_generalized_time`](super::der::parse_generalized_time)
    ///   without a fraction;
    /// - version 3 when extensions are present, and no extension twice;
    /// - the serial number is not negative;
    /// - every value of the subject and issuer names is a string of an
    ///   accepted type whose contents fit the type
    ///   ([`check_name`](super::extension::check_name));
    /// - a key of a kind that [`PublicKey`] knows (ECDSA, Ed25519, RSA) is
    ///   one that it accepts; keys of other kinds are left unparsed;
    /// - a unique identifier has no unused bits that are set;
    /// - every extension that this module knows is well formed, and a
    ///   certificate with name constraints, policy mappings, policy
    ///   constraints or an any-policy inhibitor is refused
    ///   ([`check_extension`](super::extension::check_extension)).
    ///
    /// The signature is not verified here.
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        if der.len() > MAX_CERTIFICATE_SIZE {
            return Err(X509Error::new(format!(
                "certificate is {} bytes, more than the {MAX_CERTIFICATE_SIZE} allowed",
                der.len()
            )));
        }
        let parsed = x509_cert::Certificate::from_der(der)?;
        if parsed.to_der()? != der {
            return Err(X509Error::new(
                "certificate is not in canonical DER: it does not re-encode to itself",
            ));
        }
        if parsed.signature_algorithm != parsed.tbs_certificate.signature {
            return Err(X509Error::new(
                "certificate signature algorithm differs between the signed and unsigned parts",
            ));
        }
        if parsed.signature.unused_bits() != 0 {
            return Err(X509Error::new("certificate signature has unused bits"));
        }
        let tbs_certificate = &parsed.tbs_certificate;
        if let Some(extensions) = &tbs_certificate.extensions {
            if tbs_certificate.version != x509_cert::certificate::Version::V3 {
                return Err(X509Error::new(
                    "certificate carries extensions but is not version 3",
                ));
            }
            // A lookup by identifier returns the first match, so a second
            // extension with the same identifier would never be read.
            let mut seen: Vec<&ObjectIdentifier> = Vec::with_capacity(extensions.len());
            for extension in extensions {
                if seen.contains(&&extension.extn_id) {
                    return Err(X509Error::new(format!(
                        "certificate carries extension {} twice",
                        extension.extn_id
                    )));
                }
                seen.push(&extension.extn_id);
            }
        }
        // The serial number INTEGER is two's complement: a set high bit in
        // its first byte makes it negative.
        if tbs_certificate
            .serial_number
            .as_bytes()
            .first()
            .is_some_and(|first| first & 0x80 != 0)
        {
            return Err(X509Error::new("certificate serial number is negative"));
        }
        let tbs = first_element_of_sequence(der)?.to_vec();
        let subject = parsed.tbs_certificate.subject.to_der()?;
        let issuer = parsed.tbs_certificate.issuer.to_der()?;
        extension::check_name(&subject).map_err(|error| error.within("subject"))?;
        extension::check_name(&issuer).map_err(|error| error.within("issuer"))?;
        let spki = &tbs_certificate.subject_public_key_info;
        if PublicKey::is_known_algorithm(spki.algorithm.oid) {
            PublicKey::from_spki_der(&spki.to_der()?)
                .map_err(|error| error.within("certificate public key"))?;
        } else {
            // The key is not parsed, but its bit string is still read.
            bit_string(&bit_string_content(&spki.subject_public_key)?)?;
        }
        for unique_id in [
            &tbs_certificate.issuer_unique_id,
            &tbs_certificate.subject_unique_id,
        ]
        .into_iter()
        .flatten()
        {
            bit_string(&bit_string_content(unique_id)?)
                .map_err(|error| error.within("unique identifier"))?;
        }
        for extension in tbs_certificate.extensions.iter().flatten() {
            extension::check_extension(
                extension.extn_id,
                extension.critical,
                extension.extn_value.as_bytes(),
            )?;
        }
        let not_before = instant_of(&parsed.tbs_certificate.validity.not_before)?;
        let not_after = instant_of(&parsed.tbs_certificate.validity.not_after)?;
        Ok(Self {
            der: der.to_vec(),
            tbs,
            subject,
            issuer,
            not_before,
            not_after,
            parsed,
        })
    }

    /// The DER that the certificate was parsed from.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The encoded `tbsCertificate`, exactly as it appears in the
    /// certificate: the bytes that the issuer signed.
    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs
    }

    /// The encoded subject name.
    pub fn subject_der(&self) -> &[u8] {
        &self.subject
    }

    /// The encoded issuer name.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer
    }

    /// The content of the serial number INTEGER, big-endian, without the
    /// sign padding.
    pub fn serial(&self) -> &[u8] {
        self.parsed.tbs_certificate.serial_number.as_bytes()
    }

    /// The certificate's version: 1, 2 or 3.
    pub fn version(&self) -> u8 {
        match self.parsed.tbs_certificate.version {
            x509_cert::certificate::Version::V1 => 1,
            x509_cert::certificate::Version::V2 => 2,
            x509_cert::certificate::Version::V3 => 3,
        }
    }

    /// The first instant at which the certificate is valid.
    pub fn not_before(&self) -> Instant {
        self.not_before
    }

    /// The last instant at which the certificate is valid.
    pub fn not_after(&self) -> Instant {
        self.not_after
    }

    /// Whether `at` is within the certificate's validity, both ends
    /// included.
    pub fn is_valid_at(&self, at: Instant) -> bool {
        self.not_before <= at && at <= self.not_after
    }

    /// The encoded SubjectPublicKeyInfo.
    pub fn spki_der(&self) -> Result<Vec<u8>, X509Error> {
        Ok(self
            .parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()?)
    }

    /// The certificate's public key. Keys that [`PublicKey`] does not
    /// support are an error.
    pub fn public_key(&self) -> Result<PublicKey, X509Error> {
        PublicKey::from_spki_der(&self.spki_der()?)
    }

    /// The object identifier of the signature algorithm.
    pub fn signature_algorithm(&self) -> ObjectIdentifier {
        self.parsed.signature_algorithm.oid
    }

    /// The signature value.
    pub fn signature(&self) -> &[u8] {
        self.parsed.signature.raw_bytes()
    }

    /// The extension with the given identifier, if the certificate has it.
    pub fn extension(&self, oid: ObjectIdentifier) -> Option<Extension<'_>> {
        self.extensions()
            .find(|(id, _)| *id == oid)
            .map(|(_, ext)| ext)
    }

    /// Every extension with its identifier, in certificate order.
    pub fn extensions(&self) -> impl Iterator<Item = (ObjectIdentifier, Extension<'_>)> {
        self.parsed
            .tbs_certificate
            .extensions
            .iter()
            .flatten()
            .map(|extension| {
                (
                    extension.extn_id,
                    Extension {
                        critical: extension.critical,
                        value: extension.extn_value.as_bytes(),
                    },
                )
            })
    }

    /// The values of one attribute of the subject or issuer name, in name
    /// order. A value is a UTF8String, PrintableString, IA5String or
    /// TeletexString; any other string type is an error.
    pub fn name_attribute(
        &self,
        field: NameField,
        attribute: ObjectIdentifier,
    ) -> Result<Vec<String>, X509Error> {
        let name = match field {
            NameField::Subject => &self.parsed.tbs_certificate.subject,
            NameField::Issuer => &self.parsed.tbs_certificate.issuer,
        };
        let mut values = Vec::new();
        for relative_name in name.0.iter() {
            for pair in relative_name.0.iter() {
                if pair.oid == attribute {
                    values.push(directory_string(&pair.value)?);
                }
            }
        }
        Ok(values)
    }

    /// Verifies the certificate's signature under `issuer_key`, over the
    /// encoded `tbsCertificate` as it appears in the certificate.
    ///
    /// Accepted signature algorithms: ECDSA with SHA-256, SHA-384 or SHA-512
    /// and no parameters, and RSASSA-PSS with SHA-384, MGF1 with SHA-384 and
    /// a salt of 48 bytes. Names are not compared here; a chain walk
    /// compares them.
    pub fn verify_signed_by(&self, issuer_key: &PublicKey) -> Result<(), X509Error> {
        let scheme = signature_scheme(&self.parsed.signature_algorithm)?;
        issuer_key.verify(scheme, &self.tbs, self.signature())
    }

    /// The basic constraints extension, if present. Parsing has already
    /// rejected a malformed one.
    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>, X509Error> {
        self.extension(extension::OID_BASIC_CONSTRAINTS)
            .map(|found| extension::basic_constraints(found.value))
            .transpose()
    }

    /// The key usage extension, if present. An extension with unused bits
    /// set is malformed; trailing zero bits are accepted.
    pub fn key_usage(&self) -> Result<Option<KeyUsage>, X509Error> {
        self.extension(extension::OID_KEY_USAGE)
            .map(|found| extension::key_usage(found.value))
            .transpose()
    }

    /// The purposes of the extended key usage extension, if present. The
    /// list may be empty.
    pub fn extended_key_usage(&self) -> Result<Option<Vec<ObjectIdentifier>>, X509Error> {
        self.extension(extension::OID_EXTENDED_KEY_USAGE)
            .map(|found| extension::extended_key_usage(found.value))
            .transpose()
    }

    /// The URIs of the subject alternative name, in order, and whether the
    /// extension carries names of any other kind. A certificate without the
    /// extension has no URIs and no other names.
    ///
    /// A URI is printable ASCII in a narrow form: a scheme, no spaces,
    /// well-formed percent escapes and, when it has an authority, a plain
    /// host name with an optional numeric port. Parsing has already
    /// rejected a certificate whose URI is outside that form.
    pub fn subject_alternative_uris(&self) -> Result<(Vec<String>, bool), X509Error> {
        let names = self.alternative_names()?.unwrap_or_default();
        let others = names.other_supported > 0 || names.unsupported > 0;
        Ok((names.uris, others))
    }

    /// The decoded subject alternative name, if present.
    pub(super) fn alternative_names(&self) -> Result<Option<AlternativeNames>, X509Error> {
        self.extension(extension::OID_SUBJECT_ALT_NAME)
            .map(|found| extension::subject_alternative_names(found.value))
            .transpose()
    }

    /// The URIs of the CRL distribution points extension, in order: for
    /// each distribution point with a full name, the URIs at the front of
    /// that name. A certificate without the extension has none.
    pub fn crl_distribution_uris(&self) -> Result<Vec<String>, X509Error> {
        self.extension(extension::OID_CRL_DISTRIBUTION_POINTS)
            .map(|found| extension::crl_distribution_uris(found.value))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    /// The parsed form, for the modules that read fields this type does not
    /// expose.
    pub(crate) fn parsed(&self) -> &x509_cert::Certificate {
        &self.parsed
    }
}

/// The scheme of a certificate or revocation list signature, from its
/// algorithm identifier: ECDSA with SHA-256, SHA-384 or SHA-512 and no
/// parameters, or RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a salt of
/// 48 bytes.
pub(super) fn signature_scheme(
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
) -> Result<SignatureScheme, X509Error> {
    if algorithm.oid == OID_RSASSA_PSS {
        check_pss_parameters(algorithm)?;
        return Ok(SignatureScheme::RsaPssSha384);
    }
    let hash = if algorithm.oid == OID_ECDSA_SHA256 {
        EcdsaHash::Sha256
    } else if algorithm.oid == OID_ECDSA_SHA384 {
        EcdsaHash::Sha384
    } else if algorithm.oid == OID_ECDSA_SHA512 {
        EcdsaHash::Sha512
    } else {
        return Err(X509Error::new(format!(
            "unsupported signature algorithm {}",
            algorithm.oid
        )));
    };
    if algorithm.parameters.is_some() {
        return Err(X509Error::new(
            "ECDSA signature algorithm carries parameters",
        ));
    }
    Ok(SignatureScheme::EcdsaDer(hash))
}

/// The contents octets of a BIT STRING: the count of unused bits, then the
/// bytes.
fn bit_string_content(bits: &::der::asn1::BitString) -> Result<Vec<u8>, X509Error> {
    let mut content = Vec::with_capacity(bits.raw_bytes().len().saturating_add(1));
    content.push(bits.unused_bits());
    content.extend_from_slice(bits.raw_bytes());
    Ok(content)
}

fn instant_of(time: &Time) -> Result<Instant, X509Error> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs())
        .map_err(|_| X509Error::new("certificate time is out of range"))?;
    Instant::from_unix(seconds, 0).ok_or_else(|| X509Error::new("certificate time is out of range"))
}

/// Requires RSASSA-PSS parameters of SHA-384, MGF1 with SHA-384 and a
/// 48-byte salt.
fn check_pss_parameters(
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
) -> Result<(), X509Error> {
    let parameters = algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| X509Error::new("RSASSA-PSS parameters are absent"))?;
    let encoded = parameters.to_der()?;
    let parameters = rsa::pkcs1::RsaPssParams::from_der(&encoded)
        .map_err(|error| X509Error::new(format!("RSASSA-PSS parameters: {error}")))?;
    if parameters.hash.oid != OID_SHA384 {
        return Err(X509Error::new("RSASSA-PSS hash is not SHA-384"));
    }
    if parameters.mask_gen.oid != OID_MGF1
        || parameters.mask_gen.parameters.as_ref().map(|hash| hash.oid) != Some(OID_SHA384)
    {
        return Err(X509Error::new(
            "RSASSA-PSS mask generation is not MGF1 with SHA-384",
        ));
    }
    if usize::from(parameters.salt_len) != super::key::RSA_PSS_SALT_LEN {
        return Err(X509Error::new(format!(
            "RSASSA-PSS salt length is {}, want {}",
            parameters.salt_len,
            super::key::RSA_PSS_SALT_LEN
        )));
    }
    Ok(())
}

/// Decodes a name attribute value by its string type.
fn directory_string(value: &::der::Any) -> Result<String, X509Error> {
    use ::der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    let text = match value.tag() {
        Tag::Utf8String => Utf8StringRef::try_from(value)?.as_str().to_string(),
        Tag::PrintableString => PrintableStringRef::try_from(value)?.as_str().to_string(),
        Tag::Ia5String => Ia5StringRef::try_from(value)?.as_str().to_string(),
        Tag::TeletexString => TeletexStringRef::try_from(value)?.as_str().to_string(),
        other => {
            return Err(X509Error::new(format!(
                "unsupported name attribute type {other}"
            )));
        }
    };
    Ok(text)
}

#[cfg(test)]
pub(crate) mod testdata {
    use super::Certificate;
    use crate::x509::der::pem_certificates;

    /// A Sigstore signing certificate issued in December 2023, with one
    /// embedded signed certificate timestamp.
    pub const FULCIO_LEAF_PEM: &str =
        include_str!("../../tests/data/sigstore/fulcio_leaf_with_sct.pem");
    /// The intermediate CA that issued [`FULCIO_LEAF_PEM`].
    pub const FULCIO_INTERMEDIATE_PEM: &str =
        include_str!("../../tests/data/sigstore/fulcio_intermediate.pem");

    pub fn certificate(pem: &str) -> Certificate {
        let der = pem_certificates(pem.as_bytes()).unwrap().remove(0);
        Certificate::from_der(&der).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;
    use crate::x509::der::pem_certificates;

    const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
    const OID_ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
    const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

    #[test]
    fn a_certificate_exposes_what_it_was_parsed_from() {
        let der = pem_certificates(FULCIO_LEAF_PEM.as_bytes())
            .unwrap()
            .remove(0);
        let leaf = Certificate::from_der(&der).unwrap();
        assert_eq!(leaf.der(), der);
        assert!(
            der.windows(leaf.tbs_der().len())
                .any(|w| w == leaf.tbs_der())
        );
        assert_eq!(leaf.not_before().to_rfc3339(), "2023-12-13T05:50:55Z");
        assert_eq!(leaf.not_after().to_rfc3339(), "2023-12-13T06:00:55Z");
        assert!(leaf.is_valid_at(leaf.not_before()));
        assert!(leaf.is_valid_at(leaf.not_after()));
        assert!(!leaf.is_valid_at(Instant::UNIX_EPOCH));
        assert_eq!(leaf.serial().len(), 20);
        assert_eq!(leaf.signature_algorithm(), OID_ECDSA_SHA384);
    }

    #[test]
    fn names_compare_as_bytes_and_decode_by_attribute() {
        let leaf = certificate(FULCIO_LEAF_PEM);
        let intermediate = certificate(FULCIO_INTERMEDIATE_PEM);
        assert_eq!(leaf.issuer_der(), intermediate.subject_der());
        assert_ne!(leaf.subject_der(), intermediate.subject_der());
        assert_eq!(
            intermediate
                .name_attribute(NameField::Subject, OID_COMMON_NAME)
                .unwrap(),
            ["sigstore-intermediate"]
        );
        assert_eq!(
            leaf.name_attribute(NameField::Issuer, OID_ORGANIZATION)
                .unwrap(),
            ["sigstore.dev"]
        );
        assert!(
            leaf.name_attribute(NameField::Subject, OID_COMMON_NAME)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn extensions_are_found_by_identifier() {
        let leaf = certificate(FULCIO_LEAF_PEM);
        let san = leaf.extension(OID_SUBJECT_ALT_NAME).unwrap();
        assert!(san.critical);
        assert_eq!(san.value.first(), Some(&0x30));
        assert!(leaf.extension(OID_COMMON_NAME).is_none());
        assert_eq!(leaf.extensions().count(), 8);
    }

    #[test]
    fn a_signature_verifies_under_the_issuer_key_only() {
        let leaf = certificate(FULCIO_LEAF_PEM);
        let intermediate = certificate(FULCIO_INTERMEDIATE_PEM);
        leaf.verify_signed_by(&intermediate.public_key().unwrap())
            .unwrap();
        assert!(leaf.verify_signed_by(&leaf.public_key().unwrap()).is_err());
    }

    #[test]
    fn a_changed_certificate_does_not_verify() {
        let intermediate = certificate(FULCIO_INTERMEDIATE_PEM);
        let mut der = certificate(FULCIO_LEAF_PEM).der().to_vec();
        // A byte of the serial number, inside the signed part.
        der[20] ^= 1;
        let changed = Certificate::from_der(&der).unwrap();
        assert!(
            changed
                .verify_signed_by(&intermediate.public_key().unwrap())
                .is_err()
        );
    }

    #[test]
    fn trailing_data_and_oversize_are_rejected() {
        let mut der = certificate(FULCIO_LEAF_PEM).der().to_vec();
        der.push(0);
        assert!(Certificate::from_der(&der).is_err());
        assert!(Certificate::from_der(&vec![0x30; MAX_CERTIFICATE_SIZE + 1]).is_err());
        assert!(Certificate::from_der(&[]).is_err());
    }

    /// The leaf certificate after a change to its parsed form, encoded
    /// again. Its signature no longer verifies, which parsing does not check.
    fn changed_leaf(change: impl FnOnce(&mut x509_cert::Certificate)) -> Vec<u8> {
        let mut parsed =
            x509_cert::Certificate::from_der(certificate(FULCIO_LEAF_PEM).der()).unwrap();
        change(&mut parsed);
        parsed.to_der().unwrap()
    }

    #[test]
    fn an_extension_may_appear_only_once() {
        assert!(Certificate::from_der(&changed_leaf(|_| {})).is_ok());
        let der = changed_leaf(|certificate| {
            let extensions = certificate.tbs_certificate.extensions.as_mut().unwrap();
            let first = extensions[0].clone();
            extensions.push(first);
        });
        let error = Certificate::from_der(&der).unwrap_err();
        assert!(error.to_string().contains("twice"), "{error}");
    }

    #[test]
    fn extensions_need_version_3() {
        for version in [
            x509_cert::certificate::Version::V1,
            x509_cert::certificate::Version::V2,
        ] {
            let der = changed_leaf(|certificate| certificate.tbs_certificate.version = version);
            let error = Certificate::from_der(&der).unwrap_err();
            assert!(error.to_string().contains("not version 3"), "{error}");
        }
        // Without extensions, an older version is not an error of form.
        let der = changed_leaf(|certificate| {
            certificate.tbs_certificate.version = x509_cert::certificate::Version::V1;
            certificate.tbs_certificate.extensions = None;
        });
        assert!(Certificate::from_der(&der).is_ok());
    }

    #[test]
    fn a_negative_serial_number_is_rejected() {
        let mut der = certificate(FULCIO_LEAF_PEM).der().to_vec();
        // The serial number is the 20-byte INTEGER at offset 13; set its
        // sign bit.
        assert_eq!(&der[13..15], [0x02, 0x14]);
        assert!(der[15] < 0x80);
        der[15] |= 0x80;
        let error = Certificate::from_der(&der).unwrap_err();
        assert!(error.to_string().contains("serial"), "{error}");
    }

    #[test]
    fn a_non_minimal_length_is_rejected() {
        let der = certificate(FULCIO_LEAF_PEM).der().to_vec();
        // The outer header is 30 82 hh ll; widen it to 30 83 00 hh ll.
        assert_eq!(&der[..2], [0x30, 0x82]);
        let mut widened = vec![0x30, 0x83, 0x00];
        widened.extend_from_slice(&der[2..]);
        assert!(Certificate::from_der(&widened).is_err());
    }
}
