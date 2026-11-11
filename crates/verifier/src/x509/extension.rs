//! The certificate extensions that the verifier reads, and the checks of
//! form that every certificate must pass before it is used.
//!
//! A certificate is rejected at parse time when an extension that this
//! module knows is malformed, so that no later step has to decide what a
//! malformed extension means.

use ::der::asn1::ObjectIdentifier;

use super::X509Error;
use super::certificate::{BasicConstraints, KeyUsage};
use super::der::{
    DerReader, TAG_BIT_STRING, TAG_BOOLEAN, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE,
    TAG_SET, bit_string, boolean, check_integer, check_object_identifier, single_element,
};

/// `id-ce-subjectKeyIdentifier`.
pub const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
/// `id-ce-keyUsage`.
pub const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
/// `id-ce-subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
/// `id-ce-basicConstraints`.
pub const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-ce-nameConstraints`.
pub const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
/// `id-ce-cRLDistributionPoints`.
pub const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");
/// `id-ce-certificatePolicies`.
pub const OID_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
/// `id-ce-policyMappings`.
pub const OID_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.33");
/// `id-ce-authorityKeyIdentifier`.
pub const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.35");
/// `id-ce-policyConstraints`.
pub const OID_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.36");
/// `id-ce-extKeyUsage`.
pub const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
/// `id-ce-inhibitAnyPolicy`.
pub const OID_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.54");
/// `id-pe-authorityInfoAccess`.
pub const OID_AUTHORITY_INFO_ACCESS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");

/// The context tag of an `rfc822Name` in a GeneralName.
const NAME_EMAIL: u8 = 0x81;
/// The context tag of a `dNSName` in a GeneralName.
const NAME_DNS: u8 = 0x82;
/// The context tag of a `uniformResourceIdentifier` in a GeneralName.
const NAME_URI: u8 = 0x86;
/// The context tag of an `iPAddress` in a GeneralName.
const NAME_IP: u8 = 0x87;

/// The names of a subject alternative name extension.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlternativeNames {
    /// The URIs, in order.
    pub uris: Vec<String>,
    /// How many names are e-mail addresses, DNS names or IP addresses.
    pub other_supported: usize,
    /// How many names are of any other kind.
    pub unsupported: usize,
}

fn error(message: impl Into<String>) -> X509Error {
    X509Error::new(message)
}

/// Decodes the contents of an OBJECT IDENTIFIER, which must pass
/// [`check_object_identifier`]: sub-identifiers in their shortest form,
/// none above 2^31 - 1. An identifier that the decoder does not support is
/// an error too: fewer than three or more than 39 content bytes, or a
/// sub-identifier of 2^28 or more in some positions.
pub fn object_identifier(content: &[u8]) -> Result<ObjectIdentifier, X509Error> {
    check_object_identifier(content)?;
    ObjectIdentifier::from_bytes(content).map_err(|_| error("unsupported OBJECT IDENTIFIER"))
}

/// Decodes a basic constraints extension value.
///
/// `SEQUENCE { cA BOOLEAN OPTIONAL, pathLenConstraint INTEGER OPTIONAL }`,
/// with a path length that is not negative and is below 2^63. A path
/// length above 255 is reported as 255, which no path can reach.
pub fn basic_constraints(value: &[u8]) -> Result<BasicConstraints, X509Error> {
    let invalid = || error("invalid basic constraints");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut fields = sequence.reader();
    let ca = match fields.optional(TAG_BOOLEAN).map_err(|_| invalid())? {
        Some(flag) => boolean(flag.content).map_err(|_| invalid())?,
        None => false,
    };
    let path_len = match fields.optional(TAG_INTEGER).map_err(|_| invalid())? {
        Some(integer) => {
            check_integer(integer.content).map_err(|_| invalid())?;
            if integer
                .content
                .first()
                .is_some_and(|first| first & 0x80 != 0)
            {
                return Err(invalid());
            }
            let magnitude: Vec<u8> = integer
                .content
                .iter()
                .copied()
                .skip_while(|byte| *byte == 0)
                .collect();
            // A path length must fit a signed 64-bit integer.
            let fits = match magnitude.as_slice() {
                [first, rest @ ..] if rest.len() == 7 => first & 0x80 == 0,
                other => other.len() < 8,
            };
            if !fits {
                return Err(invalid());
            }
            Some(match magnitude.as_slice() {
                [] => 0,
                [value] => *value,
                _ => u8::MAX,
            })
        }
        None => None,
    };
    fields.finish().map_err(|_| invalid())?;
    Ok(BasicConstraints { ca, path_len })
}

/// Decodes a key usage extension value: a BIT STRING whose unused bits are
/// zero. Trailing zero bits are accepted.
pub fn key_usage(value: &[u8]) -> Result<KeyUsage, X509Error> {
    let invalid = || error("invalid key usage");
    let element = single_element(value).map_err(|_| invalid())?;
    if element.tag != TAG_BIT_STRING {
        return Err(invalid());
    }
    let (_, bytes) = bit_string(element.content).map_err(|_| invalid())?;
    let bit = |index: usize| {
        bytes
            .get(index / 8)
            .is_some_and(|byte| byte & (0x80u8 >> (index % 8)) != 0)
    };
    Ok(KeyUsage {
        digital_signature: bit(0),
        content_commitment: bit(1),
        key_cert_sign: bit(5),
        crl_sign: bit(6),
        other: bit(2) || bit(3) || bit(4) || bit(7) || bit(8),
    })
}

/// Decodes an extended key usage extension value: a SEQUENCE of OBJECT
/// IDENTIFIERs, which may be empty.
pub fn extended_key_usage(value: &[u8]) -> Result<Vec<ObjectIdentifier>, X509Error> {
    let invalid = || error("invalid extended key usages");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut purposes = Vec::new();
    let mut items = sequence.reader();
    while !items.is_empty() {
        let item = items.expect(TAG_OID).map_err(|_| invalid())?;
        purposes.push(object_identifier(item.content).map_err(|_| invalid())?);
    }
    Ok(purposes)
}

/// Whether `uri` is a URI in the narrow form that is accepted in a subject
/// alternative name: printable ASCII without spaces, a scheme, well-formed
/// percent escapes, and, when an authority follows the scheme, a host of
/// letters, digits, `-` and `.` without empty labels and an optional
/// numeric port.
fn is_plain_uri(uri: &[u8]) -> bool {
    if !uri.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return false;
    }
    let mut escapes = uri.iter();
    while let Some(byte) = escapes.next() {
        if *byte == b'%' {
            let digits = (escapes.next(), escapes.next());
            let (Some(high), Some(low)) = digits else {
                return false;
            };
            if !high.is_ascii_hexdigit() || !low.is_ascii_hexdigit() {
                return false;
            }
        }
    }
    let Some(colon) = uri.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let (scheme, rest) = uri.split_at(colon);
    let scheme_ok = scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return false;
    }
    let Some(after_slashes) = rest.strip_prefix(b"://") else {
        return true;
    };
    let end = after_slashes
        .iter()
        .position(|byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(after_slashes.len());
    let (authority, _) = after_slashes.split_at(end);
    if authority.is_empty() {
        return true;
    }
    let (host, port) = match authority.iter().rposition(|byte| *byte == b':') {
        Some(at) => {
            let (host, port) = authority.split_at(at);
            (host, port.get(1..).unwrap_or_default())
        }
        None => (authority, &[][..]),
    };
    port.iter().all(u8::is_ascii_digit)
        && !host.is_empty()
        && host.split(|byte| *byte == b'.').all(|label| {
            !label.is_empty()
                && label
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

/// Decodes a subject alternative name extension value.
///
/// A SEQUENCE of GeneralNames. E-mail addresses, DNS names and URIs are
/// ASCII; an IP address has 4 or 16 bytes and is not an IPv4 address in
/// IPv6 form; a URI has the narrow form described at [`is_plain_uri`].
/// Names of other kinds are counted and not interpreted.
pub fn subject_alternative_names(value: &[u8]) -> Result<AlternativeNames, X509Error> {
    let invalid = || error("invalid subject alternative names");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut names = AlternativeNames::default();
    let mut items = sequence.reader();
    while !items.is_empty() {
        let name = items.element().map_err(|_| invalid())?;
        match name.tag {
            NAME_EMAIL | NAME_DNS => {
                if !name.content.is_ascii() {
                    return Err(error("subject alternative name is not ASCII"));
                }
                names.other_supported = names.other_supported.saturating_add(1);
            }
            NAME_URI => {
                if !is_plain_uri(name.content) {
                    return Err(error("subject alternative name URI is malformed"));
                }
                let uri = std::str::from_utf8(name.content)
                    .map_err(|_| error("subject alternative name URI is malformed"))?;
                names.uris.push(uri.to_string());
            }
            NAME_IP => {
                const MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
                let acceptable = match name.content.len() {
                    4 => true,
                    16 => !name.content.starts_with(&MAPPED_PREFIX),
                    _ => false,
                };
                if !acceptable {
                    return Err(error("subject alternative name IP address is malformed"));
                }
                names.other_supported = names.other_supported.saturating_add(1);
            }
            _ => names.unsupported = names.unsupported.saturating_add(1),
        }
    }
    Ok(names)
}

/// The URIs of a CRL distribution points extension value, in order.
///
/// Each distribution point may name its location by a full name; the URIs
/// at the front of that name are returned, and reading of a name stops at
/// its first entry of another kind. A location given relative to the CRL
/// issuer is an error.
pub fn crl_distribution_uris(value: &[u8]) -> Result<Vec<String>, X509Error> {
    const DISTRIBUTION_POINT_NAME: u8 = 0xa0;
    const FULL_NAME: u8 = 0xa0;
    let invalid = || error("invalid CRL distribution points");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut uris = Vec::new();
    let mut points = sequence.reader();
    while !points.is_empty() {
        let mut point = points.expect(TAG_SEQUENCE).map_err(|_| invalid())?.reader();
        let Some(name) = point
            .optional(DISTRIBUTION_POINT_NAME)
            .map_err(|_| invalid())?
        else {
            // The rest of the point is walked for its form only.
            check_elements(point).map_err(|_| invalid())?;
            continue;
        };
        check_elements(point).map_err(|_| invalid())?;
        let mut choice = name.reader();
        let full_name = choice.expect(FULL_NAME).map_err(|_| invalid())?;
        choice.finish().map_err(|_| invalid())?;
        let mut entries = full_name.reader();
        let mut reading = true;
        while !entries.is_empty() {
            let entry = entries.element().map_err(|_| invalid())?;
            if reading && entry.tag == NAME_URI {
                let uri = std::str::from_utf8(entry.content)
                    .ok()
                    .filter(|uri| uri.is_ascii())
                    .ok_or_else(invalid)?;
                uris.push(uri.to_string());
            } else {
                reading = false;
            }
        }
    }
    Ok(uris)
}

/// Requires that what is left in `reader` is a run of well-formed elements.
fn check_elements(mut reader: DerReader<'_>) -> Result<(), X509Error> {
    while !reader.is_empty() {
        reader.element()?;
    }
    Ok(())
}

fn check_authority_key_identifier(value: &[u8]) -> Result<(), X509Error> {
    let invalid = || error("invalid authority key identifier");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    check_elements(sequence.reader()).map_err(|_| invalid())
}

fn check_subject_key_identifier(value: &[u8]) -> Result<(), X509Error> {
    match single_element(value) {
        Ok(element) if element.tag == TAG_OCTET_STRING => Ok(()),
        _ => Err(error("invalid subject key identifier")),
    }
}

fn check_certificate_policies(value: &[u8]) -> Result<(), X509Error> {
    let invalid = || error("invalid certificate policies");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut policies = sequence.reader();
    while !policies.is_empty() {
        let mut policy = policies
            .expect(TAG_SEQUENCE)
            .map_err(|_| invalid())?
            .reader();
        let identifier = policy.expect(TAG_OID).map_err(|_| invalid())?;
        object_identifier(identifier.content).map_err(|_| invalid())?;
        if seen.contains(&identifier.content) {
            return Err(invalid());
        }
        seen.push(identifier.content);
        check_elements(policy).map_err(|_| invalid())?;
    }
    Ok(())
}

fn check_authority_info_access(value: &[u8]) -> Result<(), X509Error> {
    let invalid = || error("invalid authority info access");
    let sequence = single_element(value).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut descriptions = sequence.reader();
    while !descriptions.is_empty() {
        let mut description = descriptions
            .expect(TAG_SEQUENCE)
            .map_err(|_| invalid())?
            .reader();
        let method = description.expect(TAG_OID).map_err(|_| invalid())?;
        object_identifier(method.content).map_err(|_| invalid())?;
        description.element().map_err(|_| invalid())?;
        description.finish().map_err(|_| invalid())?;
    }
    Ok(())
}

/// Checks the form of one certificate extension.
///
/// Extensions that this module knows must be well formed, and some may not
/// be critical (the key identifiers and the authority info access). Name
/// constraints, policy mappings, policy constraints and the any-policy
/// inhibitor change which paths are valid in ways that path verification
/// here does not implement, so a certificate that carries one is rejected
/// outright. Any other extension is left to its reader.
pub fn check_extension(
    oid: ObjectIdentifier,
    critical: bool,
    value: &[u8],
) -> Result<(), X509Error> {
    let not_critical = |what: &str| {
        if critical {
            Err(error(format!("{what} is marked critical")))
        } else {
            Ok(())
        }
    };
    if oid == OID_KEY_USAGE {
        key_usage(value).map(|_| ())
    } else if oid == OID_BASIC_CONSTRAINTS {
        basic_constraints(value).map(|_| ())
    } else if oid == OID_EXTENDED_KEY_USAGE {
        extended_key_usage(value).map(|_| ())
    } else if oid == OID_SUBJECT_ALT_NAME {
        subject_alternative_names(value).map(|_| ())
    } else if oid == OID_CRL_DISTRIBUTION_POINTS {
        crl_distribution_uris(value).map(|_| ())
    } else if oid == OID_AUTHORITY_KEY_IDENTIFIER {
        not_critical("authority key identifier")?;
        check_authority_key_identifier(value)
    } else if oid == OID_SUBJECT_KEY_IDENTIFIER {
        not_critical("subject key identifier")?;
        check_subject_key_identifier(value)
    } else if oid == OID_CERTIFICATE_POLICIES {
        check_certificate_policies(value)
    } else if oid == OID_AUTHORITY_INFO_ACCESS {
        not_critical("authority info access")?;
        check_authority_info_access(value)
    } else if oid == OID_NAME_CONSTRAINTS
        || oid == OID_POLICY_MAPPINGS
        || oid == OID_POLICY_CONSTRAINTS
        || oid == OID_INHIBIT_ANY_POLICY
    {
        Err(error(format!(
            "certificate carries extension {oid}, which is not supported"
        )))
    } else {
        Ok(())
    }
}

/// Whether a critical extension with this identifier is one that path
/// verification processes. `names` is the decoded subject alternative
/// name, when the certificate has one: that extension counts as processed
/// only when it carries a name of a kind that is read.
pub fn is_processed(oid: ObjectIdentifier, names: Option<&AlternativeNames>) -> bool {
    if oid == OID_SUBJECT_ALT_NAME {
        return names.is_some_and(|names| !names.uris.is_empty() || names.other_supported > 0);
    }
    oid == OID_KEY_USAGE
        || oid == OID_BASIC_CONSTRAINTS
        || oid == OID_EXTENDED_KEY_USAGE
        || oid == OID_CRL_DISTRIBUTION_POINTS
        || oid == OID_CERTIFICATE_POLICIES
}

/// Whether `byte` may appear in a PrintableString. The asterisk and the
/// ampersand are outside the standard set and are tolerated, because
/// certificates in use carry them.
fn is_printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'\''
                | b'('
                | b')'
                | b'+'
                | b','
                | b'-'
                | b'.'
                | b'/'
                | b' '
                | b':'
                | b'='
                | b'?'
                | b'*'
                | b'&'
        )
}

/// Checks the form of an encoded name: a SEQUENCE of SETs of
/// attribute-and-value SEQUENCEs, where every value is a string of one of
/// the types below with contents that fit its type.
///
/// Accepted value types: UTF8String, PrintableString, IA5String,
/// TeletexString, NumericString and BMPString. A value of any other type is
/// an error.
pub fn check_name(name: &[u8]) -> Result<(), X509Error> {
    const TAG_UTF8_STRING: u8 = 0x0c;
    const TAG_NUMERIC_STRING: u8 = 0x12;
    const TAG_PRINTABLE_STRING: u8 = 0x13;
    const TAG_TELETEX_STRING: u8 = 0x14;
    const TAG_IA5_STRING: u8 = 0x16;
    const TAG_BMP_STRING: u8 = 0x1e;
    let invalid = || error("invalid name");
    let sequence = single_element(name).map_err(|_| invalid())?;
    if sequence.tag != TAG_SEQUENCE {
        return Err(invalid());
    }
    let mut relative_names = sequence.reader();
    while !relative_names.is_empty() {
        let mut attributes = relative_names
            .expect(TAG_SET)
            .map_err(|_| invalid())?
            .reader();
        while !attributes.is_empty() {
            let mut attribute = attributes
                .expect(TAG_SEQUENCE)
                .map_err(|_| invalid())?
                .reader();
            let kind = attribute.expect(TAG_OID).map_err(|_| invalid())?;
            object_identifier(kind.content).map_err(|_| invalid())?;
            let value = attribute.element().map_err(|_| invalid())?;
            attribute.finish().map_err(|_| invalid())?;
            let content = value.content;
            let fits = match value.tag {
                TAG_UTF8_STRING => std::str::from_utf8(content).is_ok(),
                TAG_PRINTABLE_STRING => content.iter().all(|byte| is_printable(*byte)),
                TAG_IA5_STRING => content.is_ascii(),
                TAG_TELETEX_STRING => true,
                TAG_NUMERIC_STRING => content
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b' '),
                TAG_BMP_STRING => {
                    let (units, odd) = content.as_chunks::<2>();
                    odd.is_empty()
                        && units.iter().all(|unit| {
                            let point = u16::from_be_bytes(*unit);
                            !(point == 0xfffe
                                || point == 0xffff
                                || (0xfdd0..=0xfdef).contains(&point)
                                || (0xd800..=0xdfff).contains(&point))
                        })
                }
                _ => false,
            };
            if !fits {
                return Err(error("name attribute value is not an acceptable string"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_constraints_read_the_flag_and_the_path_length() {
        let read = |value: &[u8]| basic_constraints(value).map(|bc| (bc.ca, bc.path_len));
        assert_eq!(read(&[0x30, 0x00]).unwrap(), (false, None));
        assert_eq!(read(&[0x30, 0x03, 0x01, 0x01, 0xff]).unwrap(), (true, None));
        assert_eq!(
            read(&[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00]).unwrap(),
            (true, Some(0))
        );
        assert_eq!(
            read(&[0x30, 0x03, 0x01, 0x01, 0x00]).unwrap(),
            (false, None)
        );
        assert_eq!(
            read(&[0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x01, 0x00]).unwrap(),
            (true, Some(255))
        );
        // The largest path length that is read, and the first beyond it.
        let mut wide = vec![0x30, 0x0a, 0x02, 0x08, 0x7f];
        wide.extend_from_slice(&[0xff; 7]);
        assert_eq!(read(&wide).unwrap(), (false, Some(255)));
        let mut too_wide = vec![0x30, 0x0b, 0x02, 0x09, 0x00, 0x80];
        too_wide.extend_from_slice(&[0x00; 7]);
        assert!(read(&too_wide).is_err());
        for bad in [
            &[0x30, 0x03, 0x01, 0x01, 0x01][..],
            &[0x30, 0x03, 0x02, 0x01, 0xff],
            &[0x30, 0x04, 0x02, 0x02, 0x00, 0x01],
            &[0x30, 0x02, 0x05, 0x00],
            &[0x30, 0x00, 0x00],
            &[0x31, 0x00],
            &[],
        ] {
            assert!(read(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn key_usage_reads_named_bits_and_rejects_set_padding() {
        // keyCertSign and cRLSign, with one unused bit.
        let usage = key_usage(&[0x03, 0x02, 0x01, 0x06]).unwrap();
        assert!(usage.key_cert_sign && usage.crl_sign);
        assert!(!usage.digital_signature && !usage.other);
        // The same bits with trailing zero bits spelled out.
        assert_eq!(key_usage(&[0x03, 0x02, 0x00, 0x06]).unwrap(), usage);
        let signing = key_usage(&[0x03, 0x02, 0x07, 0x80]).unwrap();
        assert!(signing.digital_signature && !signing.is_empty());
        // decipherOnly is the ninth bit.
        assert!(key_usage(&[0x03, 0x03, 0x07, 0x00, 0x80]).unwrap().other);
        assert!(key_usage(&[0x03, 0x02, 0x00, 0x00]).unwrap().is_empty());
        for bad in [
            &[0x03, 0x02, 0x01, 0x07][..],
            &[0x03, 0x02, 0x08, 0x00],
            &[0x03, 0x00],
            &[0x04, 0x02, 0x01, 0x06],
            &[0x03, 0x02, 0x01, 0x06, 0x00],
        ] {
            assert!(key_usage(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn extended_key_usage_lists_purposes() {
        let code_signing = [
            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03,
        ];
        assert_eq!(
            extended_key_usage(&code_signing).unwrap(),
            [ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3")]
        );
        assert!(extended_key_usage(&[0x30, 0x00]).unwrap().is_empty());
        assert!(extended_key_usage(&[0x30, 0x02, 0x05, 0x00]).is_err());
        // A sub-identifier with a padding octet.
        assert!(extended_key_usage(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x80, 0x01]).is_err());
        // A sub-identifier that never ends.
        assert!(extended_key_usage(&[0x30, 0x04, 0x06, 0x02, 0x2b, 0x81]).is_err());
    }

    fn general_names(names: &[(u8, &[u8])]) -> Vec<u8> {
        let mut content = Vec::new();
        for (tag, value) in names {
            super::super::der::push_element(&mut content, *tag, value);
        }
        let mut out = Vec::new();
        super::super::der::push_element(&mut out, TAG_SEQUENCE, &content);
        out
    }

    #[test]
    fn alternative_names_are_sorted_by_kind() {
        let value = general_names(&[
            (
                NAME_URI,
                b"https://github.com/o/r/.github/workflows/w.yml@refs/tags/v1",
            ),
            (NAME_DNS, b"example.com"),
            (0xa0, &[0x06, 0x01, 0x2a]),
            (NAME_IP, &[10, 0, 0, 1]),
        ]);
        let names = subject_alternative_names(&value).unwrap();
        assert_eq!(names.uris.len(), 1);
        assert_eq!(names.other_supported, 2);
        assert_eq!(names.unsupported, 1);
        assert!(is_processed(OID_SUBJECT_ALT_NAME, Some(&names)));

        let other_only = subject_alternative_names(&general_names(&[(0xa0, &[0x05, 0x00])]));
        assert!(!is_processed(
            OID_SUBJECT_ALT_NAME,
            other_only.ok().as_ref()
        ));
        assert!(!is_processed(OID_SUBJECT_ALT_NAME, None));
    }

    #[test]
    fn a_uri_outside_the_narrow_form_is_rejected() {
        for good in [
            &b"https://github.com/o/r/.github/workflows/w.yml@refs/heads/main"[..],
            b"https://registry.tinfoil.sh/scopes/public",
            b"mailto:someone@example.com",
            b"https://host:8443/a%20b",
            b"urn:x",
            b"file:///path",
        ] {
            assert!(is_plain_uri(good), "{}", String::from_utf8_lossy(good));
        }
        for bad in [
            &b"https://github.com/a b"[..],
            b"https://github.com/a%zz",
            b"https://github.com/a%2",
            b"https://github..com/",
            b"https://github.com./",
            b"https://user@github.com/",
            b"https://[::1]/",
            b"https://host:port/",
            b"//github.com/x",
            b"relative/path",
            b"1https://x",
            b"https://github.com/\x7f",
            b"https://g\xc3\xa9.com/",
            b"",
        ] {
            assert!(!is_plain_uri(bad), "{}", String::from_utf8_lossy(bad));
            assert!(subject_alternative_names(&general_names(&[(NAME_URI, bad)])).is_err());
        }
    }

    #[test]
    fn malformed_alternative_names_are_rejected() {
        let cases = [
            general_names(&[(NAME_DNS, b"caf\xc3\xa9.example")]),
            general_names(&[(NAME_EMAIL, b"\xff@example.com")]),
            general_names(&[(NAME_IP, &[1, 2, 3])]),
            general_names(&[(
                NAME_IP,
                &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
            )]),
            vec![0x31, 0x00],
            vec![0x30, 0x02, 0x82],
        ];
        for value in cases {
            assert!(subject_alternative_names(&value).is_err(), "{value:02x?}");
        }
        let mut trailing = general_names(&[(NAME_DNS, b"a")]);
        trailing.push(0);
        assert!(subject_alternative_names(&trailing).is_err());
    }

    #[test]
    fn distribution_point_uris_come_from_full_names() {
        // SEQUENCE { SEQUENCE { [0] { [0] { [6] "http://a/crl" } } } }
        let uri = b"http://a/crl";
        let full_name = general_names(&[(NAME_URI, uri)]);
        let mut name = Vec::new();
        super::super::der::push_element(&mut name, 0xa0, &full_name[2..]);
        let mut point_name = Vec::new();
        super::super::der::push_element(&mut point_name, 0xa0, &name);
        let mut point = Vec::new();
        super::super::der::push_element(&mut point, TAG_SEQUENCE, &point_name);
        let mut value = Vec::new();
        super::super::der::push_element(&mut value, TAG_SEQUENCE, &point);
        assert_eq!(crl_distribution_uris(&value).unwrap(), ["http://a/crl"]);

        // A point without a name contributes nothing.
        assert!(
            crl_distribution_uris(&[0x30, 0x02, 0x30, 0x00])
                .unwrap()
                .is_empty()
        );
        // A name relative to the CRL issuer is not read.
        assert!(crl_distribution_uris(&[0x30, 0x06, 0x30, 0x04, 0xa0, 0x02, 0xa1, 0x00]).is_err());
        assert!(crl_distribution_uris(&[0x31, 0x00]).is_err());
    }

    #[test]
    fn known_extensions_are_checked_and_unsupported_ones_refused() {
        assert!(check_extension(OID_KEY_USAGE, true, &[0x03, 0x02, 0x01, 0x06]).is_ok());
        assert!(check_extension(OID_KEY_USAGE, true, &[0x03, 0x02, 0x01, 0x07]).is_err());
        assert!(check_extension(OID_SUBJECT_KEY_IDENTIFIER, false, &[0x04, 0x01, 0xaa]).is_ok());
        assert!(check_extension(OID_SUBJECT_KEY_IDENTIFIER, true, &[0x04, 0x01, 0xaa]).is_err());
        assert!(check_extension(OID_SUBJECT_KEY_IDENTIFIER, false, &[0x05, 0x00]).is_err());
        assert!(
            check_extension(
                OID_AUTHORITY_KEY_IDENTIFIER,
                false,
                &[0x30, 0x03, 0x80, 0x01, 0xaa]
            )
            .is_ok()
        );
        assert!(check_extension(OID_AUTHORITY_KEY_IDENTIFIER, true, &[0x30, 0x00]).is_err());
        assert!(check_extension(OID_AUTHORITY_INFO_ACCESS, true, &[0x30, 0x00]).is_err());
        for refused in [
            OID_NAME_CONSTRAINTS,
            OID_POLICY_MAPPINGS,
            OID_POLICY_CONSTRAINTS,
            OID_INHIBIT_ANY_POLICY,
        ] {
            assert!(check_extension(refused, false, &[0x30, 0x00]).is_err());
        }
        // An extension that this module does not know is not interpreted.
        let unknown = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
        assert!(check_extension(unknown, false, &[0xff]).is_ok());
        // Policies: each identifier once.
        let policy = [0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04];
        assert!(check_extension(OID_CERTIFICATE_POLICIES, false, &policy).is_ok());
        let twice = [
            0x30, 0x0e, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x30, 0x05, 0x06, 0x03, 0x2a,
            0x03, 0x04,
        ];
        assert!(check_extension(OID_CERTIFICATE_POLICIES, false, &twice).is_err());
    }

    #[test]
    fn name_values_must_fit_their_string_type() {
        let name = |tag: u8, value: &[u8]| {
            let mut attribute = vec![0x06, 0x03, 0x55, 0x04, 0x03];
            super::super::der::push_element(&mut attribute, tag, value);
            let mut sequence = Vec::new();
            super::super::der::push_element(&mut sequence, TAG_SEQUENCE, &attribute);
            let mut set = Vec::new();
            super::super::der::push_element(&mut set, TAG_SET, &sequence);
            let mut out = Vec::new();
            super::super::der::push_element(&mut out, TAG_SEQUENCE, &set);
            out
        };
        assert!(check_name(&[0x30, 0x00]).is_ok());
        assert!(check_name(&name(0x0c, "caf\u{e9}".as_bytes())).is_ok());
        assert!(check_name(&name(0x13, b"Intel SGX Root CA")).is_ok());
        assert!(check_name(&name(0x16, b"a@b")).is_ok());
        assert!(check_name(&name(0x14, &[0xe9])).is_ok());
        assert!(check_name(&name(0x1e, &[0x00, 0x41])).is_ok());
        assert!(check_name(&name(0x0c, &[0xff])).is_err());
        assert!(check_name(&name(0x13, b"a@b")).is_err());
        assert!(check_name(&name(0x16, &[0x80])).is_err());
        assert!(check_name(&name(0x12, b"12a")).is_err());
        assert!(check_name(&name(0x1e, &[0x00])).is_err());
        assert!(check_name(&name(0x1e, &[0xd8, 0x00])).is_err());
        assert!(check_name(&name(0x02, &[0x01])).is_err());
        assert!(check_name(&[0x31, 0x00]).is_err());
    }
}
