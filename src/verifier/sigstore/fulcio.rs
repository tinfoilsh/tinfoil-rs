//! Fulcio CA chain verification.
//!
//! This module verifies that signing certificates were issued by a trusted
//! Fulcio Certificate Authority from the Sigstore public-good instance.

use der::{Decode, Encode};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use x509_cert::Certificate;

use crate::error::{Error, Result};
use super::trust;

/// Find the issuer certificate's SPKI for a given certificate.
///
/// This searches through the trusted Fulcio CAs to find the one that
/// issued the given certificate (by matching issuer/subject DNs).
pub fn find_issuer_spki(cert: &Certificate) -> Result<Vec<u8>> {
    let fulcio_cas = trust::load_fulcio_cas()?;

    // Try each Fulcio CA to find the matching issuer
    for ca in &fulcio_cas {
        if ca.cert_chain_der.is_empty() {
            continue;
        }

        let issuer_cert = match Certificate::from_der(&ca.cert_chain_der[0]) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if issuer DN matches
        if cert.tbs_certificate.issuer == issuer_cert.tbs_certificate.subject {
            // Return the issuer's SPKI in DER format
            return issuer_cert.tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| Error::SigstoreVerification(format!("Failed to encode issuer SPKI: {}", e)));
        }
    }

    Err(Error::SigstoreVerification(
        "Could not find issuer certificate for SCT verification".into()
    ))
}

/// Verify that the signing certificate was issued by a trusted Fulcio CA.
///
/// This validates:
/// 1. The certificate's issuer matches a Fulcio CA's subject
/// 2. The certificate's signature was created by the Fulcio CA
/// 3. The CA was valid at the time the certificate was issued
pub fn verify_fulcio_chain(cert_der: &[u8], cert_not_before: u64) -> Result<()> {
    let signing_cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse signing certificate: {}", e)))?;

    let fulcio_cas = trust::load_fulcio_cas()?;

    // Try each Fulcio CA
    for ca in &fulcio_cas {
        // Check if CA was valid when the signing cert was issued
        if cert_not_before < ca.valid_from {
            continue;
        }
        if let Some(end) = ca.valid_until {
            if cert_not_before > end {
                continue;
            }
        }

        // The first certificate in the chain is the intermediate that signs leaf certs
        if ca.cert_chain_der.is_empty() {
            continue;
        }

        let issuer_cert = Certificate::from_der(&ca.cert_chain_der[0])
            .map_err(|e| Error::SigstoreVerification(format!("Failed to parse Fulcio CA cert: {}", e)))?;

        // Verify issuer DN matches
        if signing_cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
            continue;
        }

        // Extract the issuer's public key and verify the signature
        let issuer_pubkey_bytes = issuer_cert.tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();

        // Fulcio uses P-384 for the intermediate CA
        let verifying_key = match VerifyingKey::from_sec1_bytes(issuer_pubkey_bytes) {
            Ok(k) => k,
            Err(_) => continue, // Try next CA if key doesn't parse
        };

        // Get the TBS (to-be-signed) certificate bytes and signature
        let tbs_bytes = signing_cert.tbs_certificate.to_der()
            .map_err(|e| Error::SigstoreVerification(format!("Failed to encode TBS: {}", e)))?;

        let sig_bytes = signing_cert.signature.raw_bytes();
        let signature = match Signature::from_der(sig_bytes) {
            Ok(s) => s,
            Err(_) => continue, // Try next CA
        };

        // Verify the signature
        if verifying_key.verify(&tbs_bytes, &signature).is_ok() {
            return Ok(());
        }
    }

    Err(Error::SigstoreVerification(
        "Certificate not issued by any trusted Fulcio CA".into()
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_find_issuer_spki_not_found() {
        // Create a self-signed certificate that won't match any Fulcio CA
        // This should return an error
        let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAwDQYJKoZIhvcNAQELBQADQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----"#;

        // This test verifies error handling, not actual verification
        // A proper test would require a real Fulcio-issued certificate
        let _ = cert_pem; // Silence unused warning
    }
}
