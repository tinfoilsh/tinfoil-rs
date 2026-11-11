//! DER and PEM helpers on top of the `der` crate.
//!
//! The `der` crate already rejects indefinite lengths, non-minimal lengths
//! and integers, BOOLEAN values other than `00` and `FF`, and data after a
//! value. The helpers here add what it leaves open: times in exactly one
//! form, the GeneralizedTime fraction where a schema allows one, PEM with
//! nothing but blocks, and ECDSA signature conversion.

use ::der::{Decode, Header, Reader, SliceReader, Tag};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::X509Error;
use crate::instant::{Civil, Instant};

/// One block of a PEM file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// The label of the `BEGIN` and `END` lines, such as `CERTIFICATE`.
    pub label: String,
    /// The decoded contents.
    pub contents: Vec<u8>,
}

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";
const PEM_DASHES: &str = "-----";

/// Decodes every block of a PEM file.
///
/// The text is ASCII and consists of blocks and whitespace only: no text
/// before, between or after blocks. A block is a `-----BEGIN <label>-----`
/// line, base64 lines, and the matching `-----END <label>-----` line, with
/// LF or CRLF line ends. Headers inside a block are an error. The base64 of
/// a block, with its line ends removed, must be the canonical padded
/// encoding of the contents. An empty file yields no blocks.
pub fn pem_blocks(text: &[u8]) -> Result<Vec<PemBlock>, X509Error> {
    let text = std::str::from_utf8(text)
        .ok()
        .filter(|text| text.is_ascii())
        .ok_or_else(|| X509Error::new("PEM text is not ASCII"))?;
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let label = line
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_DASHES))
            .ok_or_else(|| X509Error::new("PEM carries text outside a block"))?;
        if label.is_empty() || label.contains('-') {
            return Err(X509Error::new("PEM block has a malformed label"));
        }
        let mut encoded = String::new();
        let mut closed = false;
        for line in lines.by_ref() {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix(PEM_END) {
                if rest.strip_suffix(PEM_DASHES) != Some(label) {
                    return Err(X509Error::new("PEM block ends with a different label"));
                }
                closed = true;
                break;
            }
            if line.is_empty() || line.contains(':') || line.contains(' ') {
                return Err(X509Error::new("PEM block carries a header or a blank line"));
            }
            encoded.push_str(line);
        }
        if !closed {
            return Err(X509Error::new("PEM block has no END line"));
        }
        let contents = STANDARD
            .decode(encoded.as_bytes())
            .map_err(|error| X509Error::new(format!("PEM block base64: {error}")))?;
        if STANDARD.encode(&contents) != encoded {
            return Err(X509Error::new("PEM block base64 is not canonical"));
        }
        blocks.push(PemBlock {
            label: label.to_string(),
            contents,
        });
    }
    Ok(blocks)
}

/// The contents of every block of a PEM file, each of which must be a
/// non-empty `CERTIFICATE` block. The rules of [`pem_blocks`] apply.
pub fn pem_certificates(text: &[u8]) -> Result<Vec<Vec<u8>>, X509Error> {
    pem_blocks(text)?
        .into_iter()
        .map(|block| {
            if block.label != "CERTIFICATE" {
                return Err(X509Error::new(format!(
                    "PEM carries a {:?} block, want CERTIFICATE",
                    block.label
                )));
            }
            if block.contents.is_empty() {
                return Err(X509Error::new("PEM carries an empty CERTIFICATE block"));
            }
            Ok(block.contents)
        })
        .collect()
}

/// The encoding of the first element of a DER SEQUENCE: its tag, length and
/// contents. The SEQUENCE must span `der` exactly.
///
/// This is how the signed part of a certificate, a revocation list or a
/// signed response is taken as the bytes that were signed, without
/// re-encoding.
pub fn first_element_of_sequence(der: &[u8]) -> Result<&[u8], X509Error> {
    let mut reader = SliceReader::new(der)?;
    let header = Header::decode(&mut reader)?;
    if header.tag != Tag::Sequence {
        return Err(X509Error::new("expected a DER SEQUENCE"));
    }
    if reader.remaining_len() != header.length {
        return Err(X509Error::new("DER SEQUENCE does not span its input"));
    }
    Ok(reader.tlv_bytes()?)
}

/// Whether a GeneralizedTime may carry a fraction of a second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fraction {
    /// No fraction: the form of certificates and revocation lists.
    Forbidden,
    /// An optional fraction: the form of an RFC 3161 `genTime`.
    Allowed,
}

/// Decodes the contents of a UTCTime: exactly `YYMMDDHHMMSSZ`. Years 50 to
/// 99 are in the 1900s and years 00 to 49 in the 2000s. A time without
/// seconds, with a numeric zone or with a date that does not exist is an
/// error.
pub fn parse_utc_time(contents: &[u8]) -> Result<Instant, X509Error> {
    let invalid = || X509Error::new("malformed UTCTime");
    let mut fields = TimeFields { bytes: contents };
    let short_year = fields.two_digits().ok_or_else(invalid)?;
    let year = if short_year >= 50 {
        1900u16.checked_add(short_year.into())
    } else {
        2000u16.checked_add(short_year.into())
    }
    .ok_or_else(invalid)?;
    let instant = fields.rest_of_time(year, Fraction::Forbidden);
    instant.ok_or_else(invalid)
}

/// Decodes the contents of a GeneralizedTime: `YYYYMMDDHHMMSSZ`, or with
/// [`Fraction::Allowed`] also `YYYYMMDDHHMMSS.fZ` where the fraction has
/// one to nine digits and does not end in zero. A numeric zone, a missing
/// `Z` or a date that does not exist is an error.
pub fn parse_generalized_time(contents: &[u8], fraction: Fraction) -> Result<Instant, X509Error> {
    let invalid = || X509Error::new("malformed GeneralizedTime");
    let mut fields = TimeFields { bytes: contents };
    let century = fields.two_digits().ok_or_else(invalid)?;
    let short_year = fields.two_digits().ok_or_else(invalid)?;
    let year = u16::from(century)
        .checked_mul(100)
        .and_then(|year| year.checked_add(short_year.into()))
        .ok_or_else(invalid)?;
    fields.rest_of_time(year, fraction).ok_or_else(invalid)
}

/// The undecoded remainder of a time value.
struct TimeFields<'a> {
    bytes: &'a [u8],
}

impl TimeFields<'_> {
    fn two_digits(&mut self) -> Option<u8> {
        let (digits, rest) = self.bytes.split_first_chunk::<2>()?;
        self.bytes = rest;
        let [tens, ones] = *digits;
        if !tens.is_ascii_digit() || !ones.is_ascii_digit() {
            return None;
        }
        tens.wrapping_sub(b'0')
            .checked_mul(10)?
            .checked_add(ones.wrapping_sub(b'0'))
    }

    /// Month to second, the optional fraction, and the final `Z`.
    fn rest_of_time(&mut self, year: u16, fraction: Fraction) -> Option<Instant> {
        let month = self.two_digits()?;
        let day = self.two_digits()?;
        let hour = self.two_digits()?;
        let minute = self.two_digits()?;
        let second = self.two_digits()?;
        let mut nanos = 0u32;
        if let Some(rest) = self.bytes.strip_prefix(b".") {
            if fraction == Fraction::Forbidden {
                return None;
            }
            let digits = rest.strip_suffix(b"Z")?;
            if digits.is_empty() || digits.len() > 9 || digits.last() == Some(&b'0') {
                return None;
            }
            let mut scale = 100_000_000u32;
            for digit in digits {
                if !digit.is_ascii_digit() {
                    return None;
                }
                let value = u32::from(digit.wrapping_sub(b'0'));
                nanos = nanos.checked_add(value.checked_mul(scale)?)?;
                scale /= 10;
            }
            self.bytes = b"Z";
        }
        if self.bytes != b"Z" {
            return None;
        }
        Instant::from_civil(Civil {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanos,
        })
    }
}

/// One DER element: its tag byte, its contents, and its whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// The identifier octet: class, constructed bit and tag number.
    pub tag: u8,
    /// The contents octets.
    pub content: &'a [u8],
    /// The identifier, length and contents octets together.
    pub encoded: &'a [u8],
}

impl<'a> Element<'a> {
    /// A reader over the contents, for a constructed element.
    pub fn reader(&self) -> DerReader<'a> {
        DerReader::new(self.content)
    }
}

/// The tag of a universal BOOLEAN.
pub const TAG_BOOLEAN: u8 = 0x01;
/// The tag of a universal INTEGER.
pub const TAG_INTEGER: u8 = 0x02;
/// The tag of a universal BIT STRING.
pub const TAG_BIT_STRING: u8 = 0x03;
/// The tag of a universal OCTET STRING.
pub const TAG_OCTET_STRING: u8 = 0x04;
/// The tag of a universal OBJECT IDENTIFIER.
pub const TAG_OID: u8 = 0x06;
/// The tag of a universal SEQUENCE.
pub const TAG_SEQUENCE: u8 = 0x30;
/// The tag of a universal SET.
pub const TAG_SET: u8 = 0x31;

/// Reads DER elements from the front of a byte string, one at a time.
///
/// Only what DER allows is read: a single identifier octet (tag numbers
/// below 31), and a definite length in its shortest form. What an element
/// contains is the caller's to check.
#[derive(Debug, Clone, Copy)]
pub struct DerReader<'a> {
    rest: &'a [u8],
}

impl<'a> DerReader<'a> {
    /// A reader over `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Whether nothing is left to read.
    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The identifier octet of the next element, if there is one.
    pub fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads the next element, whatever its tag.
    pub fn element(&mut self) -> Result<Element<'a>, X509Error> {
        let malformed = || X509Error::new("malformed DER element");
        let input = self.rest;
        let (&tag, after_tag) = input.split_first().ok_or_else(malformed)?;
        if tag & 0x1f == 0x1f {
            return Err(X509Error::new("DER tag numbers above 30 are not supported"));
        }
        let (&first, after_first) = after_tag.split_first().ok_or_else(malformed)?;
        let (length, after_length) = if first < 0x80 {
            (usize::from(first), after_first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 {
                return Err(X509Error::new("DER length is indefinite"));
            }
            if count > 4 {
                return Err(X509Error::new("DER length is too large"));
            }
            let (digits, after_digits) =
                after_first.split_at_checked(count).ok_or_else(malformed)?;
            let mut length = 0usize;
            for digit in digits {
                length = length
                    .checked_mul(256)
                    .and_then(|length| length.checked_add(usize::from(*digit)))
                    .ok_or_else(malformed)?;
            }
            let minimal =
                digits.first().is_some_and(|digit| *digit != 0) && (count > 1 || length >= 0x80);
            if !minimal {
                return Err(X509Error::new("DER length is not in its shortest form"));
            }
            (length, after_digits)
        };
        let (content, rest) = after_length
            .split_at_checked(length)
            .ok_or_else(malformed)?;
        let encoded_len = input.len().checked_sub(rest.len()).ok_or_else(malformed)?;
        let encoded = input.get(..encoded_len).ok_or_else(malformed)?;
        self.rest = rest;
        Ok(Element {
            tag,
            content,
            encoded,
        })
    }

    /// Reads the next element, which must have the given tag.
    pub fn expect(&mut self, tag: u8) -> Result<Element<'a>, X509Error> {
        let element = self.element()?;
        if element.tag != tag {
            return Err(X509Error::new(format!(
                "DER element has tag {:#04x}, want {tag:#04x}",
                element.tag
            )));
        }
        Ok(element)
    }

    /// Reads the next element if it has the given tag.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>, X509Error> {
        if self.peek_tag() == Some(tag) {
            self.element().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Requires that nothing is left to read.
    pub fn finish(self) -> Result<(), X509Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(X509Error::new("DER value is followed by further data"))
        }
    }
}

/// Reads the single DER element that spans `der` exactly.
pub fn single_element(der: &[u8]) -> Result<Element<'_>, X509Error> {
    let mut reader = DerReader::new(der);
    let element = reader.element()?;
    reader.finish()?;
    Ok(element)
}

/// Checks the contents of an INTEGER: not empty, and in its shortest
/// two's-complement form.
pub fn check_integer(content: &[u8]) -> Result<(), X509Error> {
    let minimal = match content {
        [] => false,
        [_] => true,
        [0x00, second, ..] => second & 0x80 != 0,
        [0xff, second, ..] => second & 0x80 == 0,
        _ => true,
    };
    if minimal {
        Ok(())
    } else {
        Err(X509Error::new("DER INTEGER is not in its shortest form"))
    }
}

/// The value of a BOOLEAN from its contents: exactly `00` or `FF`.
pub fn boolean(content: &[u8]) -> Result<bool, X509Error> {
    match content {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(X509Error::new("DER BOOLEAN is not 00 or FF")),
    }
}

/// Splits the contents of a BIT STRING into its count of unused bits and
/// its bytes. The count is at most seven, is zero for an empty string, and
/// the unused bits themselves are zero.
pub fn bit_string(content: &[u8]) -> Result<(u8, &[u8]), X509Error> {
    let malformed = || X509Error::new("malformed DER BIT STRING");
    let (&unused, bytes) = content.split_first().ok_or_else(malformed)?;
    if unused > 7 {
        return Err(malformed());
    }
    match bytes.last() {
        None if unused != 0 => Err(malformed()),
        Some(last) if last.trailing_zeros() < u32::from(unused) => Err(X509Error::new(
            "DER BIT STRING has unused bits that are set",
        )),
        _ => Ok((unused, bytes)),
    }
}

/// Checks that an OBJECT IDENTIFIER's contents are in the shortest form:
/// not empty, no sub-identifier that starts with a padding octet, and a
/// last sub-identifier that ends.
pub fn check_object_identifier(content: &[u8]) -> Result<(), X509Error> {
    let mut at_start = true;
    for byte in content {
        if at_start && *byte == 0x80 {
            return Err(X509Error::new(
                "DER OBJECT IDENTIFIER is not in its shortest form",
            ));
        }
        at_start = byte & 0x80 == 0;
    }
    if content.is_empty() || !at_start {
        return Err(X509Error::new("malformed DER OBJECT IDENTIFIER"));
    }
    Ok(())
}

/// Checks every OBJECT IDENTIFIER inside a DER value, at any depth of its
/// constructed elements ([`check_object_identifier`]).
///
/// A decoder that keeps an identifier as the bytes it read does not notice
/// a padded sub-identifier, and an identifier in two spellings would then
/// compare as two identifiers. This walk rules the second spelling out for
/// a whole value at once. It does not look inside primitive elements, such
/// as an OCTET STRING that wraps a further value, and it uses no recursion.
pub fn check_object_identifiers(der: &[u8]) -> Result<(), X509Error> {
    let mut pending = vec![DerReader::new(der)];
    while let Some(mut reader) = pending.pop() {
        while !reader.is_empty() {
            let element = reader.element()?;
            if element.tag == TAG_OID {
                check_object_identifier(element.content)?;
            } else if element.tag & 0x20 != 0 {
                pending.push(element.reader());
            }
        }
    }
    Ok(())
}

/// The magnitude of one integer of an ECDSA signature: positive, in its
/// shortest form, and no wider than `field_len` bytes.
fn ecdsa_integer(content: &[u8], field_len: usize) -> Result<&[u8], X509Error> {
    check_integer(content)?;
    let magnitude = match content {
        [first, ..] if first & 0x80 != 0 => {
            return Err(X509Error::new("ECDSA signature integer is negative"));
        }
        [0x00, rest @ ..] => rest,
        other => other,
    };
    if magnitude.is_empty() {
        return Err(X509Error::new("ECDSA signature integer is zero"));
    }
    if magnitude.len() > field_len {
        return Err(X509Error::new("ECDSA signature integer is too wide"));
    }
    Ok(magnitude)
}

/// Converts a DER ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`) to
/// the fixed-width form: `r` then `s`, each big-endian and left-padded to
/// `field_len` bytes.
///
/// The DER must be canonical: minimal lengths, minimal positive integers, no
/// data after the sequence. An integer that is zero, negative or wider than
/// `field_len` is an error.
pub fn ecdsa_der_to_raw(der: &[u8], field_len: usize) -> Result<Vec<u8>, X509Error> {
    let mut integers = single_element(der)
        .ok()
        .filter(|sequence| sequence.tag == TAG_SEQUENCE)
        .ok_or_else(|| X509Error::new("ECDSA signature is not one DER SEQUENCE"))?
        .reader();
    let r = ecdsa_integer(integers.expect(TAG_INTEGER)?.content, field_len)?;
    let s = ecdsa_integer(integers.expect(TAG_INTEGER)?.content, field_len)?;
    integers.finish()?;
    let mut raw = Vec::with_capacity(field_len.saturating_mul(2));
    for magnitude in [r, s] {
        let padding = field_len.saturating_sub(magnitude.len());
        raw.resize(raw.len().saturating_add(padding), 0);
        raw.extend_from_slice(magnitude);
    }
    Ok(raw)
}

/// Appends a DER element with the given tag and contents.
pub(crate) fn push_element(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let length = content.len();
    if length < 0x80 {
        // Below 128, so the conversion keeps every bit.
        out.push(u8::try_from(length).unwrap_or(0x7f));
    } else {
        let bytes = length.to_be_bytes();
        let significant: Vec<u8> = bytes
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
        out.extend_from_slice(&significant);
    }
    out.extend_from_slice(content);
}

/// Converts a fixed-width ECDSA signature (`r` then `s`, each `raw.len() / 2`
/// bytes, big-endian) to canonical DER. An odd length, an empty input or a
/// zero integer is an error.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, X509Error> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(X509Error::new(
            "fixed-width ECDSA signature has an odd or zero length",
        ));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut integers = Vec::with_capacity(raw.len().saturating_add(6));
    for half in [r, s] {
        let start = half
            .iter()
            .position(|byte| *byte != 0)
            .ok_or_else(|| X509Error::new("ECDSA signature integer is zero"))?;
        let magnitude = half.get(start..).unwrap_or_default();
        let mut content = Vec::with_capacity(magnitude.len().saturating_add(1));
        if magnitude.first().is_some_and(|first| first & 0x80 != 0) {
            content.push(0);
        }
        content.extend_from_slice(magnitude);
        push_element(&mut integers, TAG_INTEGER, &content);
    }
    let mut der = Vec::with_capacity(integers.len().saturating_add(4));
    push_element(&mut der, TAG_SEQUENCE, &integers);
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Instant {
        Instant::parse_rfc3339(text).unwrap()
    }

    #[test]
    fn utc_time_has_one_form() {
        assert_eq!(
            parse_utc_time(b"260513192333Z").unwrap(),
            at("2026-05-13T19:23:33Z")
        );
        assert_eq!(
            parse_utc_time(b"500101000000Z").unwrap(),
            at("1950-01-01T00:00:00Z")
        );
        assert_eq!(
            parse_utc_time(b"491231235959Z").unwrap(),
            at("2049-12-31T23:59:59Z")
        );
        for bad in [
            &b"2605131923Z"[..],
            b"260513192333",
            b"260513192333+0000",
            b"260513192333z",
            b"260230000000Z",
            b"261301000000Z",
            b"260513246000Z",
            b"260513192360Z",
            b"260513192333.5Z",
            b"20260513192333Z",
            b"2605131923 3Z",
            b"",
        ] {
            assert!(parse_utc_time(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn generalized_time_takes_a_fraction_only_where_allowed() {
        assert_eq!(
            parse_generalized_time(b"20260513192333Z", Fraction::Forbidden).unwrap(),
            at("2026-05-13T19:23:33Z")
        );
        assert_eq!(
            parse_generalized_time(b"20260513192333.25Z", Fraction::Allowed).unwrap(),
            at("2026-05-13T19:23:33.25Z")
        );
        assert_eq!(
            parse_generalized_time(b"20260513192333.000000001Z", Fraction::Allowed).unwrap(),
            at("2026-05-13T19:23:33.000000001Z")
        );
        assert!(parse_generalized_time(b"20260513192333.25Z", Fraction::Forbidden).is_err());
        for bad in [
            &b"20260513192333.Z"[..],
            b"20260513192333.250Z",
            b"20260513192333.0Z",
            b"20260513192333.1234567891Z",
            b"20260513192333,25Z",
            b"20260513192333.2a5Z",
            b"20260513192333.25",
            b"20260513192333",
            b"20260513192333+0100",
            b"202605131923Z",
            b"20260230000000Z",
            b"260513192333Z",
        ] {
            assert!(
                parse_generalized_time(bad, Fraction::Allowed).is_err(),
                "{bad:?}"
            );
        }
    }

    const BLOCK: &str = "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n";

    #[test]
    fn pem_blocks_decode_in_order() {
        let text =
            format!("{BLOCK}\n-----BEGIN PUBLIC KEY-----\r\n/w==\r\n-----END PUBLIC KEY-----\r\n");
        let blocks = pem_blocks(text.as_bytes()).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].contents, [1, 2, 3, 4]);
        assert_eq!(blocks[1].label, "PUBLIC KEY");
        assert_eq!(blocks[1].contents, [0xff]);
        assert!(pem_blocks(b"").unwrap().is_empty());
        assert!(pem_blocks(b"\n \n").unwrap().is_empty());
    }

    #[test]
    fn pem_base64_may_span_lines() {
        let text = "-----BEGIN X-----\nAQID\nBA==\n-----END X-----";
        assert_eq!(
            pem_blocks(text.as_bytes()).unwrap()[0].contents,
            [1, 2, 3, 4]
        );
    }

    #[test]
    fn pem_with_anything_but_blocks_is_rejected() {
        let cases = [
            format!("garbage\n{BLOCK}"),
            format!("{BLOCK}garbage\n"),
            format!("{BLOCK}\0"),
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n".to_string(),
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END PUBLIC KEY-----\n".to_string(),
            "-----BEGIN CERTIFICATE-----\nProc-Type: 4\n\nAQIDBA==\n-----END CERTIFICATE-----\n"
                .to_string(),
            "-----BEGIN CERTIFICATE-----\nAQIDBA=\n-----END CERTIFICATE-----\n".to_string(),
            "-----BEGIN CERTIFICATE-----\nAQIDBB==\n-----END CERTIFICATE-----\n".to_string(),
            "-----BEGIN CERTIFICATE-----\nAQ ID\n-----END CERTIFICATE-----\n".to_string(),
            "-----BEGIN -----\nAQIDBA==\n-----END -----\n".to_string(),
            "-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\u{e9}".to_string(),
        ];
        for text in cases {
            assert!(pem_blocks(text.as_bytes()).is_err(), "{text:?}");
        }
    }

    #[test]
    fn pem_certificates_requires_certificate_blocks() {
        assert_eq!(
            pem_certificates(BLOCK.as_bytes()).unwrap(),
            [vec![1, 2, 3, 4]]
        );
        assert!(pem_certificates(b"-----BEGIN X-----\nAQ==\n-----END X-----\n").is_err());
        assert!(
            pem_certificates(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").is_err()
        );
    }

    #[test]
    fn the_first_element_of_a_sequence_is_returned_as_encoded() {
        // SEQUENCE { SEQUENCE { INTEGER 5 }, NULL }
        let der = [0x30, 0x07, 0x30, 0x03, 0x02, 0x01, 0x05, 0x05, 0x00];
        assert_eq!(
            first_element_of_sequence(&der).unwrap(),
            [0x30, 0x03, 0x02, 0x01, 0x05]
        );
        let mut trailing = der.to_vec();
        trailing.push(0);
        assert!(first_element_of_sequence(&trailing).is_err());
        assert!(first_element_of_sequence(&[0x31, 0x02, 0x05, 0x00]).is_err());
        assert!(first_element_of_sequence(&[0x30, 0x00]).is_err());
        assert!(first_element_of_sequence(&[0x30, 0x80, 0x05, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn der_lengths_must_be_definite_and_shortest() {
        let read = |bytes: &[u8]| DerReader::new(bytes).element().map(|e| e.content.to_vec());
        assert_eq!(read(&[0x04, 0x01, 0xaa]).unwrap(), [0xaa]);
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend_from_slice(&[7; 128]);
        assert_eq!(read(&long).unwrap().len(), 128);
        for bad in [
            &[0x04, 0x80, 0x00, 0x00][..],
            &[0x04, 0x81, 0x01, 0xaa],
            &[0x04, 0x82, 0x00, 0x80],
            &[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa],
            &[0x04, 0x02, 0xaa],
            &[0x1f, 0x01, 0x00],
            &[0x04],
            &[],
        ] {
            assert!(read(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn a_reader_walks_elements_and_reports_what_is_left() {
        let der = [0x30, 0x06, 0x02, 0x01, 0x05, 0x01, 0x01, 0xff];
        let sequence = single_element(&der).unwrap();
        assert_eq!(sequence.tag, TAG_SEQUENCE);
        assert_eq!(sequence.encoded, der);
        let mut reader = sequence.reader();
        assert!(reader.optional(TAG_OID).unwrap().is_none());
        assert_eq!(reader.expect(TAG_INTEGER).unwrap().content, [5]);
        assert!(reader.finish().is_err());
        assert!({ reader }.expect(TAG_INTEGER).is_err());
        assert!(boolean(reader.expect(TAG_BOOLEAN).unwrap().content).unwrap());
        reader.finish().unwrap();
        assert!(single_element(&[0x05, 0x00, 0x00]).is_err());
    }

    #[test]
    fn primitive_contents_have_one_form() {
        assert!(check_integer(&[0x00]).is_ok());
        assert!(check_integer(&[0x00, 0x80]).is_ok());
        assert!(check_integer(&[0xff, 0x7f]).is_ok());
        assert!(check_integer(&[]).is_err());
        assert!(check_integer(&[0x00, 0x7f]).is_err());
        assert!(check_integer(&[0xff, 0x80]).is_err());
        assert!(!boolean(&[0x00]).unwrap());
        assert!(boolean(&[0x01]).is_err());
        assert!(boolean(&[]).is_err());
        assert_eq!(bit_string(&[0x00]).unwrap(), (0, &[][..]));
        assert_eq!(bit_string(&[0x01, 0x06]).unwrap(), (1, &[0x06][..]));
        assert_eq!(bit_string(&[0x07, 0x80]).unwrap(), (7, &[0x80][..]));
        for bad in [
            &[][..],
            &[0x01],
            &[0x08, 0x00],
            &[0x01, 0x01],
            &[0x07, 0xc0],
        ] {
            assert!(bit_string(bad).is_err(), "{bad:02x?}");
        }
    }

    #[test]
    fn object_identifiers_are_checked_at_any_depth() {
        check_object_identifier(&[0x2a, 0x86, 0x48]).unwrap();
        assert!(check_object_identifier(&[0x2a, 0x80, 0x48]).is_err());
        assert!(check_object_identifier(&[0x80, 0x2a]).is_err());
        assert!(check_object_identifier(&[0x2a, 0x86]).is_err());
        assert!(check_object_identifier(&[]).is_err());

        // SEQUENCE { [0] { SET { OID 1.2.3 } }, OCTET STRING { OID, padded } }
        let good = [
            0x30, 0x0e, 0xa0, 0x06, 0x31, 0x04, 0x06, 0x02, 0x2a, 0x03, 0x04, 0x04, 0x06, 0x02,
            0x80, 0x03,
        ];
        check_object_identifiers(&good).unwrap();
        let mut padded = good;
        padded[8] = 0x80;
        assert!(check_object_identifiers(&padded).is_err());
        // An element that does not parse is an error, whatever its tag.
        assert!(check_object_identifiers(&[0x30, 0x03, 0x04, 0x05, 0x00]).is_err());
        check_object_identifiers(&[]).unwrap();
        // Depth costs no stack.
        let mut deep = vec![0x05, 0x00];
        for _ in 0..2000 {
            let mut outer = Vec::new();
            push_element(&mut outer, TAG_SEQUENCE, &deep);
            deep = outer;
        }
        check_object_identifiers(&deep).unwrap();
    }

    #[test]
    fn an_ecdsa_signature_converts_between_its_two_forms() {
        // r = 1, s = 0x80 (needs a sign byte in DER).
        let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80];
        let raw = ecdsa_der_to_raw(&der, 4).unwrap();
        assert_eq!(raw, [0, 0, 0, 1, 0, 0, 0, 0x80]);
        assert_eq!(ecdsa_raw_to_der(&raw).unwrap(), der);
        // A full-width pair round-trips, with a long-form length for wide
        // curves.
        let wide = [0xffu8; 132];
        let der = ecdsa_raw_to_der(&wide).unwrap();
        assert_eq!(&der[..3], [0x30, 0x81, 0x8a]);
        assert_eq!(ecdsa_der_to_raw(&der, 66).unwrap(), wide);
    }

    #[test]
    fn a_non_canonical_ecdsa_signature_is_rejected() {
        let cases: [&[u8]; 12] = [
            // A needless leading zero on r.
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01],
            // A negative r.
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
            // A zero s.
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00],
            // An empty integer.
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01],
            // Data after the sequence.
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
            // Data after s, inside the sequence.
            &[0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00],
            // A long-form length where the short form fits.
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            // An indefinite length.
            &[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00],
            // One integer only.
            &[0x30, 0x03, 0x02, 0x01, 0x01],
            // Not a sequence.
            &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            // An integer wider than the field.
            &[0x30, 0x08, 0x02, 0x03, 0x01, 0x00, 0x00, 0x02, 0x01, 0x01],
            &[],
        ];
        for der in cases {
            assert!(ecdsa_der_to_raw(der, 2).is_err(), "{der:02x?}");
        }
        assert!(ecdsa_raw_to_der(&[]).is_err());
        assert!(ecdsa_raw_to_der(&[1, 2, 3]).is_err());
        assert!(ecdsa_raw_to_der(&[0, 0, 0, 1]).is_err());
        assert!(ecdsa_raw_to_der(&[0, 1, 0, 0]).is_err());
    }
}
