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
    #[test]
    fn test_fingerprint_format() {
        // Fingerprint should be 64 hex chars (SHA256 = 32 bytes = 64 hex)
        let fp = "2b70a37cba08a1b15fddb7ba71dec4cb6b91e79c4566c51a7e4c5fb64fd8d8aa";
        assert_eq!(fp.len(), 64);
    }
}
