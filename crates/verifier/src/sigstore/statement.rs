//! The in-toto statement inside a DSSE envelope, and the encodings derived
//! from it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::SigstoreError;
use super::wire::Members;
use crate::canonical::encode_lower_hex;
use crate::json::{self, Value};
use crate::x509::{KeyAlgorithm, PublicKey};

/// The `_type` of an in-toto v1 statement.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The DSSE payload type of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The digest algorithm of statement subjects.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// The largest approval statement that is read, in bytes. The bound is
/// applied by the readers of approval statements, not by
/// [`Statement::from_payload`].
pub const MAX_STATEMENT_SIZE: usize = 128 << 10;
/// The most subjects in a statement.
pub const MAX_SUBJECTS: usize = 1024;
/// The most digests of one subject.
pub const MAX_SUBJECT_DIGESTS: usize = 32;

/// A decoded in-toto statement.
#[derive(Debug, PartialEq, Eq)]
pub struct Statement {
    /// The statement type.
    pub statement_type: String,
    /// The subjects, in order.
    pub subjects: Vec<Subject>,
    /// The predicate type.
    pub predicate_type: String,
    /// The predicate: a JSON object, with number literals as signed.
    pub predicate: Value,
}

/// One subject of a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The subject's name; empty when absent.
    pub name: String,
    /// The subject's digests by algorithm, as written in the statement.
    pub digest: BTreeMap<String, String>,
}

impl Statement {
    /// Decodes a statement from a DSSE payload.
    ///
    /// The payload is strict JSON: an object with the members `_type`,
    /// `subject`, `predicateType` and `predicate` only. A subject is an
    /// object with `name` and `digest` only, and a digest maps algorithm
    /// names to strings. `null` reads as absent. Rules, each an error when
    /// broken:
    ///
    /// - there are at most [`MAX_SUBJECTS`] subjects, each with at most
    ///   [`MAX_SUBJECT_DIGESTS`] digests;
    /// - `predicate`, when present, is an object. Its members are not
    ///   interpreted here and keep their number literals, so that an
    ///   integer above 2^53 reaches the predicate's own decoder unchanged.
    ///   An absent predicate reads as an empty object.
    ///
    /// The statement type is decoded and not judged: a caller that needs a
    /// particular `_type` compares it. An empty `subject` array is accepted
    /// here; the verification functions require the subject that they
    /// check.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SigstoreError> {
        let error = |message: String| SigstoreError::new(message);
        let value =
            json::parse(payload).map_err(|cause| error(format!("parsing statement: {cause}")))?;
        let statement = Members::required(
            Some(&value),
            "statement",
            &["_type", "subject", "predicateType", "predicate"],
        )?;
        let subject_values = statement.array("subject")?;
        if subject_values.len() > MAX_SUBJECTS {
            return Err(error(format!(
                "statement has {} subjects, more than the {MAX_SUBJECTS} allowed",
                subject_values.len()
            )));
        }
        let mut subjects = Vec::with_capacity(subject_values.len());
        for value in subject_values {
            let subject = Members::required(Some(value), "subject", &["name", "digest"])?;
            let mut digest = BTreeMap::new();
            if let Some(Value::Object(digests)) = subject.get("digest") {
                if digests.len() > MAX_SUBJECT_DIGESTS {
                    return Err(error(format!(
                        "subject has {} digests, more than the {MAX_SUBJECT_DIGESTS} allowed",
                        digests.len()
                    )));
                }
                for (algorithm, value) in digests.iter() {
                    let value = match value {
                        Value::String(value) => value.clone(),
                        Value::Null => String::new(),
                        other => {
                            return Err(error(format!(
                                "subject digest {algorithm:?}: cannot decode JSON {} as a string",
                                other.kind()
                            )));
                        }
                    };
                    digest.insert(algorithm.to_string(), value);
                }
            } else if let Some(other) = subject.get("digest") {
                return Err(error(format!(
                    "subject digest: cannot decode JSON {} as an object",
                    other.kind()
                )));
            }
            subjects.push(Subject {
                name: subject.string("name")?.unwrap_or_default().to_string(),
                digest,
            });
        }
        let predicate = match statement.get("predicate") {
            None => json::parse(b"{}").map_err(|cause| error(cause.to_string()))?,
            Some(Value::Object(_)) => predicate_of(payload)?,
            Some(other) => {
                return Err(error(format!(
                    "statement predicate: cannot decode JSON {} as an object",
                    other.kind()
                )));
            }
        };
        Ok(Self {
            statement_type: statement.string("_type")?.unwrap_or_default().to_string(),
            subjects,
            predicate_type: statement
                .string("predicateType")?
                .unwrap_or_default()
                .to_string(),
            predicate,
        })
    }

    /// The SHA-256 digest of the first subject, as written.
    pub fn first_subject_digest(&self) -> Option<&str> {
        self.subjects
            .first()
            .and_then(|subject| subject.digest.get(DIGEST_ALGORITHM))
            .map(String::as_str)
    }
}

/// The DSSE pre-authentication encoding: what a DSSE signature covers.
///
/// `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`, with lengths
/// in decimal.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        payload
            .len()
            .saturating_add(payload_type.len())
            .saturating_add(32),
    );
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type.as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

/// The reference that identifies a signed statement independently of its
/// signature and log evidence: `sha256:` and the lowercase hex SHA-256 of
/// the pre-authentication encoding of the payload as an in-toto statement.
pub fn endorsement_reference(payload: &[u8]) -> String {
    let digest = Sha256::digest(pae(PAYLOAD_TYPE, payload));
    format!("sha256:{}", encode_lower_hex(&digest))
}

/// The hint that names an approval signing key: the padded standard base64
/// of the SHA-256 of its SubjectPublicKeyInfo. Only ECDSA P-256 keys sign
/// approvals; any other key is an error.
pub fn key_hint(key: &PublicKey) -> Result<String, SigstoreError> {
    if key.algorithm() != KeyAlgorithm::EcdsaP256 {
        return Err(SigstoreError::new("approval requires an ECDSA P-256 key"));
    }
    Ok(STANDARD.encode(key.spki_sha256()))
}

/// A JSON value built from strings, for canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Canonical<'a> {
    /// A string.
    String(&'a str),
    /// An array, in order.
    Array(Vec<Canonical<'a>>),
    /// An object. Member order does not matter; a repeated name is an error
    /// at encoding.
    Object(Vec<(&'a str, Canonical<'a>)>),
}

/// The bytes that an approval's inner timestamp covers: `domain` followed by
/// the RFC 8785 canonical JSON encoding of `core`.
///
/// Canonical encoding sorts object members by the UTF-16 code units of
/// their names, writes no whitespace, and escapes in strings only the
/// quotation mark, the backslash, and control characters below U+0020 (the
/// two-character forms for backspace, tab, line feed, form feed and
/// carriage return, and `u00XX` in lowercase hex after a backslash
/// otherwise). A repeated member name, or nesting deeper than
/// [`MAX_CANONICAL_DEPTH`], is an error.
pub fn timestamp_input(domain: &str, core: &Canonical<'_>) -> Result<Vec<u8>, SigstoreError> {
    let mut out = domain.as_bytes().to_vec();
    write_canonical(&mut out, core, 0)?;
    Ok(out)
}

/// The deepest nesting of a [`Canonical`] value that is encoded.
pub const MAX_CANONICAL_DEPTH: usize = 32;

fn write_canonical(
    out: &mut Vec<u8>,
    value: &Canonical<'_>,
    depth: usize,
) -> Result<(), SigstoreError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(SigstoreError::new("canonical value is nested too deeply"));
    }
    let deeper = depth.saturating_add(1);
    match value {
        Canonical::String(text) => write_canonical_string(out, text),
        Canonical::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(out, item, deeper)?;
            }
            out.push(b']');
        }
        Canonical::Object(members) => {
            let mut sorted: Vec<&(&str, Canonical<'_>)> = members.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            if sorted.windows(2).any(|pair| match pair {
                [(a, _), (b, _)] => a == b,
                _ => false,
            }) {
                return Err(SigstoreError::new("canonical object repeats a member name"));
            }
            out.push(b'{');
            for (index, (name, member)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_string(out, name);
                out.push(b':');
                write_canonical(out, member, deeper)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_canonical_string(out: &mut Vec<u8>, text: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    const BACKSLASH: u8 = 0x5c;
    out.push(b'"');
    for byte in text.bytes() {
        let short = match byte {
            b'"' => Some(b'"'),
            BACKSLASH => Some(BACKSLASH),
            0x08 => Some(b'b'),
            0x09 => Some(b't'),
            0x0a => Some(b'n'),
            0x0c => Some(b'f'),
            0x0d => Some(b'r'),
            _ => None,
        };
        match (short, byte) {
            (Some(letter), _) => out.extend_from_slice(&[BACKSLASH, letter]),
            (None, control @ 0x00..=0x1f) => {
                out.extend_from_slice(&[BACKSLASH, b'u', b'0', b'0']);
                for nibble in [control >> 4, control & 0x0f] {
                    out.push(HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'));
                }
            }
            (None, other) => out.push(other),
        }
    }
    out.push(b'"');
}

/// The `predicate` member of a statement, parsed on its own so that it can
/// be owned apart from the rest of the statement.
fn predicate_of(payload: &[u8]) -> Result<Value, SigstoreError> {
    let value = json::parse(payload)
        .map_err(|cause| SigstoreError::new(format!("parsing statement: {cause}")))?;
    let Value::Object(_) = &value else {
        return Err(SigstoreError::new("statement is not an object"));
    };
    let mut value = value;
    let Value::Object(object) = &mut value else {
        return Err(SigstoreError::new("statement is not an object"));
    };
    std::mem::take(object)
        .into_members()
        .into_iter()
        .find(|(name, _)| name == "predicate")
        .map(|(_, predicate)| predicate)
        .ok_or_else(|| SigstoreError::new("statement has no predicate"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pre_authentication_encoding_states_both_lengths() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
    }

    #[test]
    fn a_reference_is_the_hash_of_the_encoded_payload() {
        let reference = endorsement_reference(b"{}");
        let expected = Sha256::digest(b"DSSEv1 28 application/vnd.in-toto+json 2 {}");
        assert_eq!(reference, format!("sha256:{}", encode_lower_hex(&expected)));
    }

    #[test]
    fn a_key_hint_is_the_base64_hash_of_the_key() {
        let key = PublicKey::from_pem(
            "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcadRPBdmNf1LPWYcY9AZ2Crrqxsy\n\
nqzLE7k3kahjPxIM42bgZbze0GnT/EmGqe1w6So5AhmXci8By8Azt8gAhw==\n\
-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        let hint = key_hint(&key).unwrap();
        assert_eq!(hint, STANDARD.encode(Sha256::digest(key.spki_der())));
        assert_eq!(hint.len(), 44);
    }

    #[test]
    fn only_p256_keys_have_a_hint() {
        let log = crate::sigstore::testutil::log(
            crate::sigstore::testutil::STAGING_TRUSTED_ROOT,
            &crate::sigstore::testutil::b64("09OnDKEw7/hpZiYVPoTRzRbglHk0sylsUovegnRUlJY="),
        );
        assert_eq!(log.key.algorithm(), KeyAlgorithm::Ed25519);
        assert!(key_hint(&log.key).is_err());
    }
}
