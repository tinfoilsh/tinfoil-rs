//! Fulcio CA chain verification.
//!
//! This module verifies that signing certificates were issued by a trusted
//! Fulcio Certificate Authority from the Sigstore public-good instance.

use der::{Decode, Encode};
use x509_cert::Certificate;

use super::trust;
use crate::error::{Error, Result};

/// OID for P-256 curve (secp256r1): 1.2.840.10045.3.1.7
const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";
/// OID for P-384 curve (secp384r1): 1.3.132.0.34
const OID_SECP384R1: &str = "1.3.132.0.34";

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
            return issuer_cert
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| {
                    Error::SigstoreVerification(format!("Failed to encode issuer SPKI: {}", e))
                });
        }
    }

    Err(Error::SigstoreVerification(
        "Could not find issuer certificate for SCT verification".into(),
    ))
}

/// Verify that the signing certificate was issued by a trusted Fulcio CA.
///
/// This validates:
/// 1. The certificate's issuer matches a Fulcio CA's subject
/// 2. The certificate's signature was created by the Fulcio CA
/// 3. The CA was valid at the time the certificate was issued
pub fn verify_fulcio_chain(cert_der: &[u8], cert_not_before: u64) -> Result<()> {
    let signing_cert = Certificate::from_der(cert_der).map_err(|e| {
        Error::SigstoreVerification(format!("Failed to parse signing certificate: {}", e))
    })?;

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

        let issuer_cert = Certificate::from_der(&ca.cert_chain_der[0]).map_err(|e| {
            Error::SigstoreVerification(format!("Failed to parse Fulcio CA cert: {}", e))
        })?;

        // Verify issuer DN matches
        if signing_cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
            continue;
        }

        // Get the TBS (to-be-signed) certificate bytes and signature
        let tbs_bytes = signing_cert
            .tbs_certificate
            .to_der()
            .map_err(|e| Error::SigstoreVerification(format!("Failed to encode TBS: {}", e)))?;
        let sig_bytes = signing_cert.signature.raw_bytes();

        // Determine the issuer's key curve from SPKI algorithm parameters
        let issuer_spki = &issuer_cert.tbs_certificate.subject_public_key_info;
        let issuer_pubkey_bytes = issuer_spki.subject_public_key.raw_bytes();

        let curve_oid = issuer_spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
            .map(|oid| oid.to_string());

        // Dispatch to the correct verifier based on curve
        let verified = match curve_oid.as_deref() {
            Some(OID_SECP256R1) => verify_ecdsa_p256(&tbs_bytes, sig_bytes, issuer_pubkey_bytes),
            Some(OID_SECP384R1) => verify_ecdsa_p384(&tbs_bytes, sig_bytes, issuer_pubkey_bytes),
            _ => continue, // Unsupported curve, try next CA
        };

        if verified {
            return Ok(());
        }
    }

    Err(Error::SigstoreVerification(
        "Certificate not issued by any trusted Fulcio CA".into(),
    ))
}

/// Verify ECDSA P-256 signature over TBS certificate bytes.
fn verify_ecdsa_p256(tbs_bytes: &[u8], sig_bytes: &[u8], pubkey_bytes: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let Some(key) = VerifyingKey::from_sec1_bytes(pubkey_bytes).ok() else {
        return false;
    };
    let Some(sig) = Signature::from_der(sig_bytes).ok() else {
        return false;
    };
    key.verify(tbs_bytes, &sig).is_ok()
}

/// Verify ECDSA P-384 signature over TBS certificate bytes.
fn verify_ecdsa_p384(tbs_bytes: &[u8], sig_bytes: &[u8], pubkey_bytes: &[u8]) -> bool {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let Some(key) = VerifyingKey::from_sec1_bytes(pubkey_bytes).ok() else {
        return false;
    };
    let Some(sig) = Signature::from_der(sig_bytes).ok() else {
        return false;
    };
    key.verify(tbs_bytes, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AMD Genoa ASK certificate - a valid certificate that is definitely not
    /// issued by any Fulcio CA, so it should trigger the "not found" error.
    fn get_non_fulcio_certificate_der() -> Vec<u8> {
        let pem = r#"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"#;
        let parsed = pem::parse(pem).expect("Failed to parse PEM");
        parsed.into_contents()
    }

    #[test]
    fn test_find_issuer_spki_not_found() {
        let cert_der = get_non_fulcio_certificate_der();
        let cert = Certificate::from_der(&cert_der).expect("Failed to parse certificate");

        let result = find_issuer_spki(&cert);

        assert!(
            result.is_err(),
            "Non-Fulcio certificate should not find issuer"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Could not find issuer certificate"),
            "Error should mention missing issuer, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_verify_fulcio_chain_not_issued_by_fulcio() {
        let cert_der = get_non_fulcio_certificate_der();

        // Use a timestamp within the certificate's validity period
        let cert_not_before = 1667222028; // 2022-10-31, when the cert was issued

        let result = verify_fulcio_chain(&cert_der, cert_not_before);

        assert!(
            result.is_err(),
            "Non-Fulcio certificate should fail verification"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("not issued by any trusted Fulcio CA"),
            "Error should mention untrusted CA, got: {}",
            err_msg
        );
    }
}
