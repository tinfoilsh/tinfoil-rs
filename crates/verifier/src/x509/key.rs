//! Public keys and signature verification.
//!
//! One type covers every key that the verifier meets: transparency-log and
//! pinned approval keys (ECDSA P-256, Ed25519), certificate keys (ECDSA
//! P-256 and P-384), and the AMD signing keys (RSA). A key is parsed from
//! its SubjectPublicKeyInfo and keeps those bytes, because key identifiers
//! are hashes of them.

use ::der::Decode;
use ::der::asn1::ObjectIdentifier;
use ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::spki::SubjectPublicKeyInfoRef;

use super::X509Error;
use super::der::pem_blocks;

/// `id-ecPublicKey`.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// The NIST P-256 curve, `prime256v1`.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// The NIST P-384 curve.
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `id-Ed25519`.
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `rsaEncryption`.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The salt length of every RSA-PSS signature that the verifier accepts.
pub const RSA_PSS_SALT_LEN: usize = 48;

/// The smallest RSA modulus that is accepted, in bits. Smaller keys can be
/// factored and are rejected when the key is parsed.
pub const RSA_MIN_MODULUS_BITS: usize = 1024;

/// The largest RSA modulus, in bits, that a public key may have.
pub const RSA_MAX_MODULUS_BITS: usize = 4096;

/// The kind of a [`PublicKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA on the NIST P-256 curve.
    EcdsaP256,
    /// ECDSA on the NIST P-384 curve.
    EcdsaP384,
    /// Ed25519.
    Ed25519,
    /// RSA.
    Rsa,
}

/// The hash of an ECDSA signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaHash {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

/// How a signature was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// ECDSA over the given hash, with the signature in canonical DER.
    EcdsaDer(EcdsaHash),
    /// ECDSA over the given hash, with the signature as `r` then `s`, each
    /// big-endian at the width of the curve.
    EcdsaRaw(EcdsaHash),
    /// Ed25519 over the message itself, with a 64-byte signature.
    Ed25519,
    /// RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a salt of
    /// [`RSA_PSS_SALT_LEN`] bytes.
    RsaPssSha384,
}

#[derive(Clone)]
enum Key {
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Rsa(rsa::RsaPublicKey),
}

/// A public key that can verify signatures.
#[derive(Clone)]
pub struct PublicKey {
    spki_der: Vec<u8>,
    key: Key,
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:?})", self.algorithm())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.spki_der == other.spki_der
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    /// Parses a DER SubjectPublicKeyInfo.
    ///
    /// Accepted keys: ECDSA on P-256 or P-384 with a named curve and an
    /// uncompressed point, Ed25519 without parameters, and RSA
    /// (`rsaEncryption`) with a modulus of [`RSA_MIN_MODULUS_BITS`] to [`RSA_MAX_MODULUS_BITS`]
    /// bits. The DER must be canonical with nothing after it, and the key
    /// bit string must have no unused bits.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, X509Error> {
        let spki = SubjectPublicKeyInfoRef::from_der(der)?;
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| X509Error::new("public key bit string has unused bits"))?;
        let algorithm = spki.algorithm.oid;
        let key = if algorithm == OID_EC_PUBLIC_KEY {
            let curve: ObjectIdentifier = spki
                .algorithm
                .parameters
                .ok_or_else(|| X509Error::new("EC public key names no curve"))?
                .decode_as()
                .map_err(|_| X509Error::new("EC public key does not use a named curve"))?;
            if bits.first() != Some(&0x04) {
                return Err(X509Error::new("EC public key is not an uncompressed point"));
            }
            if curve == OID_SECP256R1 {
                Key::EcdsaP256(
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(bits)
                        .map_err(|_| X509Error::new("invalid P-256 public key"))?,
                )
            } else if curve == OID_SECP384R1 {
                Key::EcdsaP384(
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(bits)
                        .map_err(|_| X509Error::new("invalid P-384 public key"))?,
                )
            } else {
                return Err(X509Error::new(format!("unsupported EC curve {curve}")));
            }
        } else if algorithm == OID_ED25519 {
            if spki.algorithm.parameters.is_some() {
                return Err(X509Error::new("Ed25519 public key carries parameters"));
            }
            let bytes: &[u8; 32] = bits
                .try_into()
                .map_err(|_| X509Error::new("Ed25519 public key is not 32 bytes"))?;
            Key::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(bytes)
                    .map_err(|_| X509Error::new("invalid Ed25519 public key"))?,
            )
        } else if algorithm == OID_RSA_ENCRYPTION {
            let key = rsa::RsaPublicKey::from_public_key_der(der)
                .map_err(|_| X509Error::new("invalid RSA public key"))?;
            let bits = key.n().bits();
            if bits < RSA_MIN_MODULUS_BITS {
                return Err(X509Error::new(format!(
                    "RSA public key has {bits} bits, fewer than the {RSA_MIN_MODULUS_BITS} required"
                )));
            }
            if bits > RSA_MAX_MODULUS_BITS {
                return Err(X509Error::new(format!(
                    "RSA public key has {bits} bits, more than the {RSA_MAX_MODULUS_BITS} allowed"
                )));
            }
            Key::Rsa(key)
        } else {
            return Err(X509Error::new(format!(
                "unsupported public key algorithm {algorithm}"
            )));
        };
        Ok(Self {
            spki_der: der.to_vec(),
            key,
        })
    }

    /// Whether `algorithm` is the identifier of a kind of key that this type
    /// parses.
    pub(super) fn is_known_algorithm(algorithm: ObjectIdentifier) -> bool {
        algorithm == OID_EC_PUBLIC_KEY
            || algorithm == OID_ED25519
            || algorithm == OID_RSA_ENCRYPTION
    }

    /// Parses a PEM file that holds exactly one `PUBLIC KEY` block. The
    /// rules of [`pem_blocks`] and [`PublicKey::from_spki_der`] apply.
    pub fn from_pem(pem: &str) -> Result<Self, X509Error> {
        let mut blocks = pem_blocks(pem.as_bytes())?;
        let (Some(block), true) = (blocks.pop(), blocks.is_empty()) else {
            return Err(X509Error::new("expected exactly one PEM block"));
        };
        if block.label != "PUBLIC KEY" {
            return Err(X509Error::new(format!(
                "PEM carries a {:?} block, want PUBLIC KEY",
                block.label
            )));
        }
        Self::from_spki_der(&block.contents)
    }

    /// The DER SubjectPublicKeyInfo that the key was parsed from.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// SHA-256 of the DER SubjectPublicKeyInfo.
    pub fn spki_sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.spki_der).into()
    }

    /// The kind of the key.
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self.key {
            Key::EcdsaP256(_) => KeyAlgorithm::EcdsaP256,
            Key::EcdsaP384(_) => KeyAlgorithm::EcdsaP384,
            Key::Ed25519(_) => KeyAlgorithm::Ed25519,
            Key::Rsa(_) => KeyAlgorithm::Rsa,
        }
    }

    /// Verifies `signature` over `message`.
    ///
    /// The scheme must fit the key: an ECDSA scheme with an ECDSA key (any
    /// of the three hashes with either curve), [`SignatureScheme::Ed25519`]
    /// with an Ed25519 key, [`SignatureScheme::RsaPssSha384`] with an RSA
    /// key. Any other pairing is an error, as is a signature that is
    /// malformed for the scheme or does not verify.
    pub fn verify(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), X509Error> {
        let failed = || X509Error::new("signature does not verify");
        let malformed = || X509Error::new("malformed signature");
        match (&self.key, scheme) {
            (Key::EcdsaP256(key), SignatureScheme::EcdsaDer(hash)) => {
                let signature =
                    p256::ecdsa::Signature::from_der(signature).map_err(|_| malformed())?;
                key.verify_prehash(&digest(hash, message), &signature)
                    .map_err(|_| failed())
            }
            (Key::EcdsaP256(key), SignatureScheme::EcdsaRaw(hash)) => {
                let signature =
                    p256::ecdsa::Signature::from_slice(signature).map_err(|_| malformed())?;
                key.verify_prehash(&digest(hash, message), &signature)
                    .map_err(|_| failed())
            }
            (Key::EcdsaP384(key), SignatureScheme::EcdsaDer(hash)) => {
                let signature =
                    p384::ecdsa::Signature::from_der(signature).map_err(|_| malformed())?;
                key.verify_prehash(&digest(hash, message), &signature)
                    .map_err(|_| failed())
            }
            (Key::EcdsaP384(key), SignatureScheme::EcdsaRaw(hash)) => {
                let signature =
                    p384::ecdsa::Signature::from_slice(signature).map_err(|_| malformed())?;
                key.verify_prehash(&digest(hash, message), &signature)
                    .map_err(|_| failed())
            }
            (Key::Ed25519(key), SignatureScheme::Ed25519) => {
                let bytes: &[u8; 64] = signature.try_into().map_err(|_| malformed())?;
                let signature = ed25519_dalek::Signature::from_bytes(bytes);
                ed25519_dalek::Verifier::verify(key, message, &signature).map_err(|_| failed())
            }
            (Key::Rsa(key), SignatureScheme::RsaPssSha384) => {
                let key = rsa::pss::VerifyingKey::<Sha384>::new_with_salt_len(
                    key.clone(),
                    RSA_PSS_SALT_LEN,
                );
                let signature =
                    rsa::pss::Signature::try_from(signature).map_err(|_| malformed())?;
                rsa::signature::Verifier::verify(&key, message, &signature).map_err(|_| failed())
            }
            _ => Err(X509Error::new(format!(
                "a {:?} key cannot verify a {scheme:?} signature",
                self.algorithm()
            ))),
        }
    }
}

fn digest(hash: EcdsaHash, message: &[u8]) -> Vec<u8> {
    match hash {
        EcdsaHash::Sha256 => Sha256::digest(message).to_vec(),
        EcdsaHash::Sha384 => Sha384::digest(message).to_vec(),
        EcdsaHash::Sha512 => Sha512::digest(message).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNK\n\
AaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==\n\
-----END PUBLIC KEY-----\n";

    fn p256_spki() -> Vec<u8> {
        pem_blocks(P256_KEY_PEM.as_bytes())
            .unwrap()
            .remove(0)
            .contents
    }

    #[test]
    fn a_p256_key_parses_from_pem_and_keeps_its_encoding() {
        let key = PublicKey::from_pem(P256_KEY_PEM).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::EcdsaP256);
        assert_eq!(key.spki_der(), p256_spki());
        assert_eq!(key, PublicKey::from_spki_der(&p256_spki()).unwrap());
        assert_eq!(format!("{key:?}"), "PublicKey(EcdsaP256)");
    }

    #[test]
    fn a_key_with_trailing_data_is_rejected() {
        let mut der = p256_spki();
        der.push(0);
        assert!(PublicKey::from_spki_der(&der).is_err());
    }

    #[test]
    fn a_compressed_point_is_rejected() {
        let der = p256_spki();
        // Rebuild the SubjectPublicKeyInfo around the 33-byte compressed
        // form of the same point.
        let point = &der[der.len() - 65..];
        let mut compressed = vec![0x02 | (point[64] & 1)];
        compressed.extend_from_slice(&point[1..33]);
        let mut spki = vec![0x30, 0x39];
        spki.extend_from_slice(&der[2..23]);
        spki.extend_from_slice(&[0x03, 0x22, 0x00]);
        spki.extend_from_slice(&compressed);
        assert!(p256::ecdsa::VerifyingKey::from_sec1_bytes(&compressed).is_ok());
        let error = PublicKey::from_spki_der(&spki).unwrap_err();
        assert!(error.to_string().contains("uncompressed"), "{error}");
    }

    #[test]
    fn an_unknown_algorithm_is_rejected() {
        // SubjectPublicKeyInfo { { sha1WithRSAEncryption }, BIT STRING 00 }
        let der = [
            0x30, 0x11, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
            0x05, 0x03, 0x02, 0x00, 0x00,
        ];
        let error = PublicKey::from_spki_der(&der).unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }

    /// A DER header: the tag, then the length in its shortest form.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            len @ 0..=0x7f => out.push(len as u8),
            len @ 0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
            len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    /// The SubjectPublicKeyInfo of an RSA key whose modulus has `bits` bits
    /// and whose exponent is 65537. The modulus is not a product of two
    /// primes; parsing does not need it to be.
    fn rsa_spki(bits: usize) -> Vec<u8> {
        let mut modulus = vec![0xff; bits / 8];
        modulus.insert(0, 0x00);
        let mut key = tlv(0x02, &modulus);
        key.extend_from_slice(&tlv(0x02, &[0x01, 0x00, 0x01]));
        let mut bit_string = vec![0x00];
        bit_string.extend_from_slice(&tlv(0x30, &key));
        let rsa_encryption = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ];
        let mut spki = tlv(0x30, &rsa_encryption);
        spki.extend_from_slice(&tlv(0x03, &bit_string));
        tlv(0x30, &spki)
    }

    #[test]
    fn an_rsa_key_below_the_minimum_size_is_rejected() {
        for bits in [512, 768, 1016] {
            let error = PublicKey::from_spki_der(&rsa_spki(bits)).unwrap_err();
            assert!(error.to_string().contains("fewer than"), "{bits}: {error}");
        }
        for bits in [1024, 2048, 4096] {
            let key = PublicKey::from_spki_der(&rsa_spki(bits)).unwrap();
            assert_eq!(key.algorithm(), KeyAlgorithm::Rsa);
        }
        assert!(PublicKey::from_spki_der(&rsa_spki(8192)).is_err());
    }

    #[test]
    fn pem_must_hold_one_public_key_block() {
        assert!(PublicKey::from_pem("").is_err());
        assert!(PublicKey::from_pem(&format!("{P256_KEY_PEM}{P256_KEY_PEM}")).is_err());
        let relabelled = P256_KEY_PEM.replace("PUBLIC KEY", "CERTIFICATE");
        assert!(PublicKey::from_pem(&relabelled).is_err());
    }

    #[test]
    fn a_scheme_that_does_not_fit_the_key_is_an_error() {
        let key = PublicKey::from_pem(P256_KEY_PEM).unwrap();
        let error = key
            .verify(SignatureScheme::Ed25519, b"message", &[0; 64])
            .unwrap_err();
        assert!(error.to_string().contains("cannot verify"), "{error}");
        assert!(
            key.verify(SignatureScheme::RsaPssSha384, b"message", &[0; 64])
                .is_err()
        );
    }

    #[test]
    fn a_malformed_ecdsa_signature_is_rejected() {
        let key = PublicKey::from_pem(P256_KEY_PEM).unwrap();
        let der = SignatureScheme::EcdsaDer(EcdsaHash::Sha256);
        assert!(key.verify(der, b"message", &[]).is_err());
        assert!(key.verify(der, b"message", &[0x30, 0x00]).is_err());
        // A non-minimal INTEGER: r is encoded with a needless leading zero.
        let padded = [0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01];
        assert!(key.verify(der, b"message", &padded).is_err());
        let raw = SignatureScheme::EcdsaRaw(EcdsaHash::Sha256);
        assert!(key.verify(raw, b"message", &[1; 63]).is_err());
        assert!(key.verify(raw, b"message", &[0; 64]).is_err());
    }
}
