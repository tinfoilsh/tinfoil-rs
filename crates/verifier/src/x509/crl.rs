//! Certificate revocation lists.

use ::der::Decode;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::certificate::signature_scheme;
use super::chain::check_may_sign;
use super::der::{
    DerReader, Fraction, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID,
    TAG_SEQUENCE, bit_string, boolean, check_integer, parse_generalized_time, parse_utc_time,
    single_element,
};
use super::extension::{self, object_identifier};
use super::{Certificate, X509Error};
use crate::instant::Instant;

/// The largest revocation list that is parsed, in bytes.
pub const MAX_CRL_SIZE: usize = 4 << 20;

const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_LIST_EXTENSIONS: u8 = 0xa0;

/// `id-ce-cRLNumber`.
const OID_CRL_NUMBER: ::der::asn1::ObjectIdentifier =
    ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.20");
/// `id-ce-cRLReasons`.
const OID_REASON_CODE: ::der::asn1::ObjectIdentifier =
    ::der::asn1::ObjectIdentifier::new_unwrap("2.5.29.21");

/// A parsed certificate revocation list. Parsing establishes its form only;
/// [`Crl::verify_issued_by`] establishes who issued it and
/// [`Crl::check_validity`] that it is current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    der: Vec<u8>,
    tbs: Vec<u8>,
    issuer_der: Vec<u8>,
    this_update: Instant,
    next_update: Instant,
    revoked_serials: Vec<Vec<u8>>,
    signature_algorithm: Vec<u8>,
    signature: Vec<u8>,
}

fn error(message: impl Into<String>) -> X509Error {
    X509Error::new(message)
}

fn time(reader: &mut DerReader<'_>) -> Result<Instant, X509Error> {
    let element = reader.element()?;
    match element.tag {
        TAG_UTC_TIME => parse_utc_time(element.content),
        TAG_GENERALIZED_TIME => parse_generalized_time(element.content, Fraction::Forbidden),
        _ => Err(error("revocation list time is not a UTCTime or GeneralizedTime")),
    }
}

/// One extension of a list or of an entry: its identifier, whether it is
/// critical, and the contents of its value.
fn list_extension<'a>(
    extensions: &mut DerReader<'a>,
) -> Result<(::der::asn1::ObjectIdentifier, bool, &'a [u8]), X509Error> {
    let mut fields = extensions.expect(TAG_SEQUENCE)?.reader();
    let oid = object_identifier(fields.expect(TAG_OID)?.content)?;
    let critical = match fields.optional(TAG_BOOLEAN)? {
        Some(flag) => boolean(flag.content)?,
        None => false,
    };
    let value = fields.expect(TAG_OCTET_STRING)?.content;
    fields.finish()?;
    Ok((oid, critical, value))
}

/// The magnitude of a serial number: its INTEGER contents without leading
/// zero bytes.
fn magnitude(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(serial.len());
    serial.get(start..).unwrap_or_default()
}

impl Crl {
    /// Parses a DER `CertificateList`.
    ///
    /// Rules, each an error when broken:
    ///
    /// - at most [`MAX_CRL_SIZE`] bytes of canonical DER with nothing after
    ///   it, and nothing unread inside it;
    /// - version 2;
    /// - the inner and outer signature algorithms are identical;
    /// - the issuer name has the form that certificates require
    ///   ([`check_name`](super::extension::check_name));
    /// - `nextUpdate` is present, and `thisUpdate` is not after it; both
    ///   are UTCTime or GeneralizedTime in the forms of
    ///   [`parse_utc_time`](super::der::parse_utc_time) and
    ///   [`parse_generalized_time`](super::der::parse_generalized_time)
    ///   without a fraction;
    /// - an entry is a serial number, a revocation time and optional
    ///   extensions, none of them critical: a critical certificate issuer
    ///   extension would mean that the list covers other issuers'
    ///   certificates. A reason code is an ENUMERATED;
    /// - no critical list extension other than the CRL number; in
    ///   particular a delta CRL indicator or an issuing distribution point
    ///   rejects, because such a list does not speak for every certificate
    ///   of its issuer. An authority key identifier is well formed and not
    ///   critical, and a CRL number is an INTEGER;
    /// - the signature bit string has no unused bits.
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        if der.len() > MAX_CRL_SIZE {
            return Err(error(format!(
                "revocation list is {} bytes, more than the {MAX_CRL_SIZE} allowed",
                der.len()
            )));
        }
        let outer = single_element(der)?;
        if outer.tag != TAG_SEQUENCE {
            return Err(error("revocation list is not a DER SEQUENCE"));
        }
        let mut outer_fields = outer.reader();
        let tbs = outer_fields.expect(TAG_SEQUENCE)?;
        let outer_algorithm = outer_fields.expect(TAG_SEQUENCE)?;
        let signature = outer_fields.expect(TAG_BIT_STRING)?;
        outer_fields.finish()?;
        let (unused, signature) = bit_string(signature.content)?;
        if unused != 0 {
            return Err(error("revocation list signature has unused bits"));
        }

        let mut fields = tbs.reader();
        let version = fields
            .optional(TAG_INTEGER)?
            .ok_or_else(|| error("revocation list states no version"))?;
        if version.content != [1] {
            return Err(error("revocation list is not version 2"));
        }
        let inner_algorithm = fields.expect(TAG_SEQUENCE)?;
        if inner_algorithm.encoded != outer_algorithm.encoded {
            return Err(error(
                "revocation list signature algorithm differs between the signed and unsigned parts",
            ));
        }
        AlgorithmIdentifierOwned::from_der(inner_algorithm.encoded)?;
        let issuer = fields.expect(TAG_SEQUENCE)?;
        extension::check_name(issuer.encoded).map_err(|cause| cause.within("issuer"))?;
        let this_update = time(&mut fields)?;
        if !matches!(
            fields.peek_tag(),
            Some(TAG_UTC_TIME | TAG_GENERALIZED_TIME)
        ) {
            return Err(error("revocation list states no next update"));
        }
        let next_update = time(&mut fields)?;
        if this_update > next_update {
            return Err(error("revocation list ends before it starts"));
        }

        let mut revoked_serials = Vec::new();
        if let Some(entries) = fields.optional(TAG_SEQUENCE)? {
            let mut entries = entries.reader();
            while !entries.is_empty() {
                let mut entry = entries.expect(TAG_SEQUENCE)?.reader();
                let serial = entry.expect(TAG_INTEGER)?.content;
                check_integer(serial)?;
                time(&mut entry)?;
                if let Some(extensions) = entry.optional(TAG_SEQUENCE)? {
                    let mut extensions = extensions.reader();
                    while !extensions.is_empty() {
                        let (oid, critical, value) = list_extension(&mut extensions)?;
                        if critical {
                            return Err(error(format!(
                                "revocation list entry has a critical extension {oid}"
                            )));
                        }
                        if oid == OID_REASON_CODE {
                            let reason = single_element(value)?;
                            if reason.tag != TAG_ENUMERATED {
                                return Err(error("malformed revocation reason"));
                            }
                            check_integer(reason.content)?;
                        }
                    }
                }
                entry.finish()?;
                revoked_serials.push(serial.to_vec());
            }
        }
        if let Some(wrapper) = fields.optional(TAG_LIST_EXTENSIONS)? {
            let mut wrapped = wrapper.reader();
            let mut extensions = wrapped.expect(TAG_SEQUENCE)?.reader();
            wrapped.finish()?;
            while !extensions.is_empty() {
                let (oid, critical, value) = list_extension(&mut extensions)?;
                if oid == OID_CRL_NUMBER {
                    let number = single_element(value)?;
                    if number.tag != TAG_INTEGER {
                        return Err(error("malformed CRL number"));
                    }
                    check_integer(number.content)?;
                } else if oid == extension::OID_AUTHORITY_KEY_IDENTIFIER {
                    extension::check_extension(oid, critical, value)?;
                } else if critical {
                    return Err(error(format!(
                        "revocation list has a critical extension {oid}"
                    )));
                }
            }
        }
        fields.finish()?;

        Ok(Self {
            der: der.to_vec(),
            tbs: tbs.encoded.to_vec(),
            issuer_der: issuer.encoded.to_vec(),
            this_update,
            next_update,
            revoked_serials,
            signature_algorithm: inner_algorithm.encoded.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// The DER that the list was parsed from.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The encoded issuer name.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer_der
    }

    /// The start of the list's validity.
    pub fn this_update(&self) -> Instant {
        self.this_update
    }

    /// The end of the list's validity.
    pub fn next_update(&self) -> Instant {
        self.next_update
    }

    /// Checks that `at` is within the list's validity: not before
    /// `thisUpdate` and not after `nextUpdate`.
    pub fn check_validity(&self, at: Instant) -> Result<(), X509Error> {
        if at < self.this_update {
            return Err(error(format!(
                "revocation list is not valid until {}",
                self.this_update.to_rfc3339()
            )));
        }
        if at > self.next_update {
            return Err(error(format!(
                "revocation list expired at {}",
                self.next_update.to_rfc3339()
            )));
        }
        Ok(())
    }

    /// Checks that the list was issued by `issuer`: the list's issuer name
    /// equals the certificate's subject name byte for byte; the certificate
    /// is an authority (a version 3 certificate has basic constraints, and
    /// basic constraints have `cA` set); a key usage extension with any bit
    /// set includes CRL signing; and the signature verifies under the
    /// certificate's key over the encoded `tbsCertList` as it appears in
    /// the list, with the algorithms that certificate signatures accept.
    pub fn verify_issued_by(&self, issuer: &Certificate) -> Result<(), X509Error> {
        if self.issuer_der != issuer.subject_der() {
            return Err(error(
                "revocation list issuer is not the subject of the certificate",
            ));
        }
        check_may_sign(issuer)?;
        if issuer
            .key_usage()?
            .is_some_and(|usage| !usage.is_empty() && !usage.crl_sign)
        {
            return Err(error("issuer's key usage does not permit CRL signing"));
        }
        let algorithm = AlgorithmIdentifierOwned::from_der(&self.signature_algorithm)?;
        issuer
            .public_key()?
            .verify(signature_scheme(&algorithm)?, &self.tbs, &self.signature)
    }

    /// Whether the list revokes the certificate with this serial number.
    /// `serial` is the content of the serial number INTEGER, as
    /// [`Certificate::serial`] returns it; leading zero bytes do not
    /// matter.
    ///
    /// A list answers only for certificates of its own issuer; the caller
    /// has checked that with [`Crl::verify_issued_by`] against the
    /// certificate's issuer.
    pub fn is_revoked(&self, serial: &[u8]) -> bool {
        self.revoked_serials
            .iter()
            .any(|revoked| magnitude(revoked) == magnitude(serial))
    }
}
