//! TLS certificate fingerprint computation and pinning
//!
//! Tinfoil computes fingerprints by hashing the full SPKI (SubjectPublicKeyInfo)
//! DER encoding, not just the raw public key bytes.

use rustls::pki_types::CertificateDer;
use sha2::{Sha256, Digest};
use der::Encode;
use std::sync::Arc;

use crate::error::{Error, Result};

/// Compute SHA256 fingerprint of a certificate's public key
/// 
/// This hashes the full SPKI (SubjectPublicKeyInfo) in DER format,
/// which matches how Tinfoil and OpenSSL compute public key fingerprints.
pub fn cert_pubkey_fingerprint(cert_der: &CertificateDer<'_>) -> Result<String> {
    use x509_cert::Certificate;
    use der::Decode;
    
    // Parse the X.509 certificate
    let cert = Certificate::from_der(cert_der.as_ref())
        .map_err(|e| Error::Tls(format!("Failed to parse certificate: {}", e)))?;
    
    // Encode the full SPKI to DER
    // This includes: algorithm identifier + public key bits
    let spki_der = cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Tls(format!("Failed to encode SPKI: {}", e)))?;
    
    // Hash the SPKI DER
    let hash = Sha256::digest(&spki_der);
    
    Ok(hex::encode(hash))
}

/// Custom certificate verifier that pins to a specific public key fingerprint
/// 
/// This verifier:
/// 1. First validates the certificate chain normally (CA signatures, expiry, etc.)
/// 2. Then checks that the server cert's SPKI fingerprint matches the pinned value
#[derive(Debug)]
pub struct PinnedCertVerifier {
    /// The expected SPKI fingerprint (hex-encoded SHA256)
    pinned_fingerprint: String,
    /// Standard certificate verifier for chain validation
    inner: Arc<rustls::client::WebPkiServerVerifier>,
}

impl PinnedCertVerifier {
    /// Create a new pinned verifier
    pub fn new(pinned_fingerprint: String) -> Result<Self> {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        
        let inner = rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .map_err(|e| Error::Tls(format!("Failed to build verifier: {}", e)))?;
        
        Ok(Self {
            pinned_fingerprint,
            inner,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // First, do standard certificate chain validation
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        
        // Then verify the fingerprint matches our pinned value
        let actual_fingerprint = cert_pubkey_fingerprint(end_entity)
            .map_err(|e| rustls::Error::General(format!("Fingerprint computation failed: {}", e)))?;
        
        if actual_fingerprint != self.pinned_fingerprint {
            return Err(rustls::Error::General(format!(
                "Certificate fingerprint mismatch: expected {}, got {}",
                self.pinned_fingerprint, actual_fingerprint
            )));
        }
        
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Create a reqwest client with certificate pinning
/// 
/// This client will reject any connection where the server's certificate
/// public key fingerprint doesn't match the pinned value.
pub fn create_pinned_client(pinned_fingerprint: &str) -> Result<reqwest::Client> {
    // Ensure crypto provider is installed
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    
    // Create pinned verifier
    let verifier = PinnedCertVerifier::new(pinned_fingerprint.to_string())?;
    
    // Build rustls config with our custom verifier
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    
    // Build reqwest client with this config
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| Error::Tls(format!("Failed to build HTTP client: {}", e)))?;
    
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AMD Genoa ASK certificate in DER format (first cert from genoa_cert_chain.pem).
    /// This is used to test fingerprint computation with a real certificate.
    fn get_test_certificate_der() -> Vec<u8> {
        let pem = r#"-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----"#;
        let parsed = pem::parse(pem).expect("Failed to parse PEM");
        parsed.into_contents()
    }

    #[test]
    fn test_cert_pubkey_fingerprint_computes_valid_hash() {
        let cert_der = get_test_certificate_der();
        let cert = CertificateDer::from(cert_der);

        let result = cert_pubkey_fingerprint(&cert);
        assert!(result.is_ok(), "Fingerprint computation should succeed");

        let fingerprint = result.unwrap();

        // SHA256 fingerprint should be 64 hex characters
        assert_eq!(fingerprint.len(), 64, "Fingerprint should be 64 hex chars");

        // Should be lowercase hex only
        assert!(
            fingerprint.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "Fingerprint should be lowercase hex"
        );
    }

    #[test]
    fn test_cert_pubkey_fingerprint_is_deterministic() {
        let cert_der = get_test_certificate_der();

        let cert1 = CertificateDer::from(cert_der.clone());
        let cert2 = CertificateDer::from(cert_der);

        let fp1 = cert_pubkey_fingerprint(&cert1).unwrap();
        let fp2 = cert_pubkey_fingerprint(&cert2).unwrap();

        assert_eq!(fp1, fp2, "Same certificate should produce same fingerprint");
    }

    #[test]
    fn test_cert_pubkey_fingerprint_invalid_der() {
        let invalid_der = vec![0x00, 0x01, 0x02, 0x03];
        let cert = CertificateDer::from(invalid_der);

        let result = cert_pubkey_fingerprint(&cert);
        assert!(result.is_err(), "Invalid DER should fail");
        assert!(result.unwrap_err().to_string().contains("Failed to parse certificate"));
    }

    #[test]
    fn test_pinned_cert_verifier_creation() {
        // Ensure crypto provider is installed for test
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let fingerprint = "0".repeat(64); // Valid format but won't match any real cert
        let result = PinnedCertVerifier::new(fingerprint);
        assert!(result.is_ok(), "Creating PinnedCertVerifier with valid fingerprint should succeed");
    }
}
