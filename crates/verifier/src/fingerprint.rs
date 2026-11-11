//! The fingerprint that pins a TLS connection to an attested key.

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::error::{Error, UsageError};
use crate::x509::Certificate;

/// The SHA-256 of the SubjectPublicKeyInfo of a DER certificate, as
/// lowercase hex: the form in which
/// [`Verification::tls_public_key_fp`](crate::Verification::tls_public_key_fp)
/// reports the endorsed TLS key. The key may be of any type.
///
/// The certificate's signature is not verified: a fingerprint only says
/// which key a certificate carries.
///
/// # Errors
///
/// [`Error::Usage`] when `cert_der` is not one well-formed X.509
/// certificate.
pub fn cert_pubkey_fp(cert_der: &[u8]) -> Result<String, Error> {
    let spki = Certificate::from_der(cert_der)
        .and_then(|certificate| certificate.spki_der())
        .map_err(|cause| UsageError::new(format!("parsing certificate: {cause}")))?;
    Ok(canonical::encode_lower_hex(&Sha256::digest(spki)))
}

#[cfg(test)]
mod tests {
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
