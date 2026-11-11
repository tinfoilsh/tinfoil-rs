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
use crate::stub::pending;

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

/// Converts a DER ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`) to
/// the fixed-width form: `r` then `s`, each big-endian and left-padded to
/// `field_len` bytes.
///
/// The DER must be canonical: minimal lengths, minimal positive integers, no
/// data after the sequence. An integer that is zero, negative or wider than
/// `field_len` is an error.
pub fn ecdsa_der_to_raw(der: &[u8], field_len: usize) -> Result<Vec<u8>, X509Error> {
    pending("x509::der::ecdsa_der_to_raw")
}

/// Converts a fixed-width ECDSA signature (`r` then `s`, each `raw.len() / 2`
/// bytes, big-endian) to canonical DER. An odd length, an empty input or a
/// zero integer is an error.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, X509Error> {
    pending("x509::der::ecdsa_raw_to_der")
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
}
