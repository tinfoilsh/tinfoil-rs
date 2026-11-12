//! The fingerprint that pins a TLS connection to an attested key.

use crate::canonical;
use crate::error::{Error, UsageError};
use crate::x509::Certificate;

/// The SHA-256 of the SubjectPublicKeyInfo of a DER certificate, as
/// lowercase hex: the form in which
/// [`Verification::tls_public_key_fp`](crate::Verification::tls_public_key_fp)
/// reports the endorsed TLS key.
///
/// The certificate is read strictly, and its key must be one that this
/// crate can use: ECDSA on P-256 or P-384, Ed25519, or RSA of 1,024 to
/// 4,096 bits. A certificate that carries any other key has no
/// fingerprint here.
///
/// The certificate's signature is not verified: a fingerprint only says
/// which key a certificate carries.
///
/// # Errors
///
/// [`Error::Usage`] when `cert_der` is not one well-formed X.509
/// certificate, or carries a key of another kind.
pub fn cert_pubkey_fp(cert_der: &[u8]) -> Result<String, Error> {
    // Parsing leaves a key of a kind that the crate does not know
    // unread, so the key itself is read before it is hashed.
    let key = Certificate::from_der(cert_der)
        .and_then(|certificate| certificate.public_key())
        .map_err(|cause| UsageError::new(format!("parsing certificate: {cause}")))?;
    Ok(canonical::encode_lower_hex(&key.spki_sha256()))
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::x509::der::pem_blocks;

    fn embedded_certificate() -> Vec<u8> {
        let mut blocks = pem_blocks(crate::trust::INTEL_SGX_ROOT_CA_PEM).unwrap();
        blocks.remove(0).contents
    }

    #[test]
    fn the_fingerprint_is_the_hash_of_the_certificate_key() {
        let der = embedded_certificate();
        let spki = Certificate::from_der(&der).unwrap().spki_der().unwrap();
        let want = canonical::encode_lower_hex(&Sha256::digest(&spki));
        let got = cert_pubkey_fp(&der).unwrap();
        assert_eq!(got, want);
        assert_eq!(got.len(), 64);
        // The key's own fingerprint, computed from the key alone.
        let key = crate::x509::PublicKey::from_spki_der(&spki).unwrap();
        assert_eq!(got, canonical::encode_lower_hex(&key.spki_sha256()));
    }

    /// A well-formed certificate that carries an X25519 key.
    const X25519_CERTIFICATE_HEX: &str = "308201373081eaa00302010202143aebe21019855815060f74f52ce55383edf63173300506032b6570301a3118301606035504030c0f756e737570706f72746564206b6579301e170d3236313131323233333131325a170d3336313130393233333131325a301a3118301606035504030c0f756e737570706f72746564206b6579302a300506032b656e032100796be2b6737179fdd3b83dc8b6ed94695c31ada23dbc8cba4dde41077c005619a3423040301d0603551d0e041604148a2b7fa43f0b705dfd1b3b48a194daa2c1adc3ef301f0603551d230418301680146ebe67b004a5b929914eb5a5425f3c7c731cd1b6300506032b65700341009765338e85944394511edb80cfb5773216b2a1f96571d56aeaf6c513ac64a0871b21ca8e5c025fb1cc14d1a5cc0c89d64bdae1d85f99cf52afe3c21ee9045c03";

    #[test]
    fn a_certificate_with_a_key_of_another_kind_has_no_fingerprint() {
        let der = canonical::decode_hex(X25519_CERTIFICATE_HEX).unwrap();
        // The certificate itself is well formed; only its key is of a kind
        // that cannot be used.
        let certificate = Certificate::from_der(&der).unwrap();
        assert!(certificate.public_key().is_err());
        let error = cert_pubkey_fp(&der).unwrap_err();
        assert!(matches!(error, Error::Usage(_)), "{error}");
        assert!(error.to_string().contains("unsupported"), "{error}");
    }

    #[test]
    fn bytes_that_are_not_a_certificate_are_a_usage_error() {
        let mut truncated = embedded_certificate();
        truncated.pop();
        for input in [&[][..], b"not a certificate", &truncated] {
            let error = cert_pubkey_fp(input).unwrap_err();
            assert!(matches!(error, Error::Usage(_)), "{error}");
        }
    }
}
