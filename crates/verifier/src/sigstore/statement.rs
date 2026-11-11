//! The in-toto statement inside a DSSE envelope, and the encodings derived
//! from it.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::SigstoreError;
use crate::canonical::encode_lower_hex;
use crate::json::Value;
use crate::stub::pending;
use crate::x509::{KeyAlgorithm, PublicKey};

/// The `_type` of an in-toto v1 statement.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// The DSSE payload type of an in-toto statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The digest algorithm of statement subjects.
pub const DIGEST_ALGORITHM: &str = "sha256";
/// The largest statement that is read, in bytes.
pub const MAX_STATEMENT_SIZE: usize = 128 << 10;

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
    /// - `_type` is [`STATEMENT_TYPE`];
    /// - `predicate` is an object. Its members are not interpreted here and
    ///   keep their number literals, so that an integer above 2^53 reaches
    ///   the predicate's own decoder unchanged.
    ///
    /// An empty `subject` array is accepted here; the verification
    /// functions require the subject that they check.
    pub fn from_payload(payload: &[u8]) -> Result<Self, SigstoreError> {
        pending("sigstore::statement::Statement::from_payload")
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
/// their names, writes no whitespace, and escapes in strings only `"`,
/// `\`, and control characters below U+0020 (the short forms `\b`, `\t`,
/// `\n`, `\f`, `\r` where they exist, `\u00XX` in lowercase hex otherwise).
pub fn timestamp_input(domain: &str, core: &Canonical<'_>) -> Result<Vec<u8>, SigstoreError> {
    pending("sigstore::statement::timestamp_input")
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
