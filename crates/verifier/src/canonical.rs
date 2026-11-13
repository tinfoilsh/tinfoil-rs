//! Decoding of the binary fields of attestation material.
//!
//! Every byte string has exactly one accepted text form: lowercase hex of a
//! stated length, or padded standard base64 that re-encodes to itself. Two
//! documents that differ in their text therefore never decode to the same
//! content.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// A field whose text is not the one accepted encoding of a byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError {
    message: String,
}

impl CanonicalError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CanonicalError {}

/// Whether `s` consists of lowercase hex digits only. The length is not
/// checked, so an odd number of digits passes.
pub fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Encodes `bytes` as lowercase hex.
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a').and_then(|n| n.checked_add(10)),
        b'A'..=b'F' => digit.checked_sub(b'A').and_then(|n| n.checked_add(10)),
        _ => None,
    }
}

/// Decodes hex digits of either case, or returns `None` for an odd length or
/// a character that is not a hex digit.
pub fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|[high, low]| Some((nibble(*high)? << 4) | nibble(*low)?))
        .collect()
}

/// Decodes the lowercase hex field `name`, which must hold exactly
/// `want_len` bytes.
pub fn decode_lower_hex(
    name: &str,
    value: &str,
    want_len: usize,
) -> Result<Vec<u8>, CanonicalError> {
    if !is_lower_hex(value) {
        return Err(CanonicalError::new(format!("{name} is not lowercase hex")));
    }
    let Some(bytes) = decode_hex(value) else {
        return Err(CanonicalError::new(format!(
            "{name} is not hex: odd number of digits"
        )));
    };
    if bytes.len() != want_len {
        return Err(CanonicalError::new(format!(
            "{name} must be {want_len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Decodes the base64 field `name`: the standard alphabet, padded, in its
/// one canonical form.
///
/// Line breaks are not part of that form. They are set aside before decoding
/// and caught by the comparison with the re-encoded bytes, which is also what
/// rules out any other spelling of the same content.
pub fn decode_base64(name: &str, value: &str) -> Result<Vec<u8>, CanonicalError> {
    let decoded = if value.contains(['\r', '\n']) {
        let joined: String = value
            .chars()
            .filter(|c| !matches!(c, '\r' | '\n'))
            .collect();
        STANDARD.decode(joined)
    } else {
        STANDARD.decode(value)
    };
    let bytes =
        decoded.map_err(|error| CanonicalError::new(format!("decoding {name}: {error}")))?;
    if STANDARD.encode(&bytes) != value {
        return Err(CanonicalError::new(format!(
            "{name} is not canonical base64"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_lower_hex_accepts_one_form() {
        let ok: [(&str, &str, usize, &[u8]); 3] = [
            ("valid", "00ff10ab", 4, &[0x00, 0xff, 0x10, 0xab]),
            ("valid 32 bytes", &"a5".repeat(32), 32, &[0xa5; 32]),
            ("empty with zero length", "", 0, &[]),
        ];
        for (name, value, want_len, want) in ok {
            assert_eq!(
                decode_lower_hex("field", value, want_len).unwrap(),
                want,
                "{name}"
            );
        }

        let rejected = [
            (
                "empty with nonzero length",
                "",
                32,
                "field must be 32 bytes, got 0",
            ),
            ("too short", "aabb", 3, "field must be 3 bytes, got 2"),
            ("too long", "aabbccdd", 3, "field must be 3 bytes, got 4"),
            ("uppercase", "AABB", 2, "field is not lowercase hex"),
            ("mixed case", "aAbb", 2, "field is not lowercase hex"),
            ("non-hex letter", "aagg", 2, "field is not lowercase hex"),
            ("0x prefix", "0xaabb", 3, "field is not lowercase hex"),
            ("leading space", " aabb", 2, "field is not lowercase hex"),
            (
                "trailing newline",
                "aabb\n",
                2,
                "field is not lowercase hex",
            ),
            (
                "embedded newline",
                "aa\nbb",
                2,
                "field is not lowercase hex",
            ),
            (
                "fullwidth digits",
                "\u{ff10}\u{ff10}",
                1,
                "field is not lowercase hex",
            ),
            // An odd length passes the character class but does not decode.
            ("odd length", "abc", 1, "field is not hex"),
            ("single character", "a", 0, "field is not hex"),
        ];
        for (name, value, want_len, want) in rejected {
            let error = decode_lower_hex("field", value, want_len).unwrap_err();
            assert!(error.to_string().contains(want), "{name}: {error}");
        }
    }

    /// Bytes that differ from run to run without a random source.
    fn sample(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(151).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn decode_lower_hex_round_trips() {
        for len in 0..=64 {
            let bytes = sample(len, 7);
            let text = encode_lower_hex(&bytes);
            assert_eq!(text.len(), len * 2);
            assert_eq!(decode_lower_hex("field", &text, len).unwrap(), bytes);
        }
        assert_eq!(encode_lower_hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
    }

    #[test]
    fn decode_hex_accepts_either_case() {
        assert_eq!(decode_hex("00fFAb"), Some(vec![0x00, 0xff, 0xab]));
        assert_eq!(decode_hex(""), Some(vec![]));
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("\u{e9}"), None);
    }

    #[test]
    fn decode_base64_accepts_one_form() {
        let ok: [(&str, &str, &[u8]); 5] = [
            ("empty", "", b""),
            ("no padding needed", "YWJj", b"abc"),
            ("one pad", "YWI=", b"ab"),
            ("two pads", "YQ==", b"a"),
            ("plus and slash", "+/+/", &[0xfb, 0xff, 0xbf]),
        ];
        for (name, value, want) in ok {
            assert_eq!(decode_base64("field", value).unwrap(), want, "{name}");
        }

        let rejected = [
            ("missing padding", "YQ", "decoding field"),
            ("extra padding", "YQ===", "decoding field"),
            ("padding in middle", "YQ==YWJj", "decoding field"),
            // Non-zero trailing bits would give "YR==" and "YQ==" the same
            // decoding.
            ("nonzero padding bits", "YR==", "decoding field"),
            ("url-safe alphabet", "-_-_", "decoding field"),
            ("space", "YW Jj", "decoding field"),
            ("invalid character", "YW*j", "decoding field"),
            // Line breaks decode to the same bytes; the round trip rejects them.
            (
                "embedded newline",
                "YW\nJj",
                "field is not canonical base64",
            ),
            (
                "embedded carriage return",
                "YW\rJj",
                "field is not canonical base64",
            ),
            (
                "trailing newline",
                "YWJj\n",
                "field is not canonical base64",
            ),
            ("leading CRLF", "\r\nYWJj", "field is not canonical base64"),
            ("only newlines", "\n\n", "field is not canonical base64"),
        ];
        for (name, value, want) in rejected {
            let error = decode_base64("field", value).unwrap_err();
            assert!(error.to_string().contains(want), "{name}: {error}");
        }
    }

    #[test]
    fn decode_base64_round_trips() {
        for len in 0..=64 {
            let bytes = sample(len, 3);
            let text = STANDARD.encode(&bytes);
            assert_eq!(
                decode_base64("field", &text).unwrap(),
                bytes,
                "length {len}"
            );
        }
    }

    #[test]
    fn every_other_spelling_of_a_base64_string_is_rejected() {
        // Each variant would decode to the same bytes under a lenient decoder.
        let canonical = "YWI=";
        assert_eq!(decode_base64("field", canonical).unwrap(), b"ab");
        for variant in [
            "YWI", "YWJ=", "YWI==", "YW I=", "YWI=\n", "\nYWI=", "YWI\n=",
        ] {
            assert!(decode_base64("field", variant).is_err(), "{variant:?}");
        }
    }
}
