//! Secure client with attestation verification and TLS certificate pinning
//!
//! After verification, ALL requests are made through a TLS connection that
//! validates the server certificate fingerprint matches the attested value.

use crate::api::{ChatMessage, ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse, Tool};
use crate::attestation::{self, types::{GroundTruth, Measurement}};
use crate::error::{Error, Result};
use crate::tls;

/// Default models
pub const DEFAULT_CHAT_MODEL: &str = "qwen3-coder-480b";
pub const DEFAULT_EMBED_MODEL: &str = "nomic-embed-text";

/// Secure client for Tinfoil inference with hardware attestation
/// 
/// The client performs attestation verification on first use:
/// 1. Fetches attestation document from enclave
/// 2. Verifies AMD SEV-SNP or Intel TDX hardware signature
/// 3. Extracts measurement and TLS public key fingerprint
/// 4. Creates a pinned HTTP client that validates the fingerprint on EVERY connection
///
/// After verification, ALL API requests use the pinned client, ensuring
/// that data only goes to the verified enclave.
pub struct SecureClient {
    /// Enclave hostname
    host: String,
    
    /// API key for authentication
    api_key: String,
    
    /// Expected measurement (optional, for additional validation)
    expected_measurement: Option<Measurement>,
    
    /// Verified ground truth
    ground_truth: Option<GroundTruth>,
    
    /// Pinned HTTP client (used after verification)
    /// This client validates cert fingerprint on every connection
    pinned_client: Option<reqwest::Client>,
}

impl SecureClient {
    /// Create a new client for the given enclave host
    pub fn new(host: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            api_key: api_key.into(),
            expected_measurement: None,
            ground_truth: None,
            pinned_client: None,
        }
    }
    
    /// Create a client with a pinned expected measurement
    pub fn with_measurement(
        host: impl Into<String>,
        api_key: impl Into<String>,
        measurement: Measurement,
    ) -> Self {
        Self {
            host: host.into(),
            api_key: api_key.into(),
            expected_measurement: Some(measurement),
            ground_truth: None,
            pinned_client: None,
        }
    }
    
    /// Create a verified client using router discovery with fallback.
    ///
    /// This function:
    /// 1. Fetches available routers from the discovery endpoint
    /// 2. Tries each router until one verifies successfully
    /// 3. Falls back to default router if all routers fail
    pub async fn new_default_client(api_key: impl Into<String>) -> Result<Self> {
        let api_key = api_key.into();

        let routers = match crate::discovery::fetch_routers().await {
            Ok(r) => r,
            Err(_) => {
                // Fall back to default router
                return Ok(Self::new(crate::discovery::DEFAULT_ROUTER, api_key));
            }
        };

        for router in routers {
            let mut client = Self::new(&router, api_key.clone());
            if client.verify().await.is_ok() {
                return Ok(client);
            }
        }

        // Fall back to default router
        Ok(Self::new(crate::discovery::DEFAULT_ROUTER, api_key))
    }

    /// Get the enclave hostname
    pub fn host(&self) -> &str {
        &self.host
    }
    
    /// Check if the client has been verified
    pub fn is_verified(&self) -> bool {
        self.ground_truth.is_some() && self.pinned_client.is_some()
    }
    
    /// Get the ground truth after verification
    pub fn ground_truth(&self) -> Option<&GroundTruth> {
        self.ground_truth.as_ref()
    }

    /// Get the ground truth as a JSON string
    pub fn ground_truth_json(&self) -> Result<String> {
        let gt = self.ground_truth.as_ref().ok_or(Error::NotVerified)?;
        serde_json::to_string(gt).map_err(Error::Json)
    }

    /// Verify the enclave attestation and set up TLS pinning
    /// 
    /// This performs full verification:
    /// 1. Fetch attestation document
    /// 2. Verify hardware signature (AMD/Intel)
    /// 3. Compare measurements if expected value provided
    /// 4. Verify TLS certificate matches attestation
    /// 5. Create pinned HTTP client for all future requests
    pub async fn verify(&mut self) -> Result<&GroundTruth> {
        // 1. Fetch attestation from enclave
        let doc = attestation::fetch(&self.host).await?;
        
        // 2. Verify hardware attestation with full cert chain
        let verification = attestation::verify_full(&doc).await?;
        
        // 3. Compare measurements if we have an expected value
        if let Some(expected) = &self.expected_measurement {
            expected.equals(&verification.measurement)
                .map_err(|_| Error::MeasurementMismatch {
                    expected: expected.fingerprint(),
                    actual: verification.measurement.fingerprint(),
                })?;
        }
        
        // 4. Verify TLS certificate matches attestation (one-time check)
        self.verify_tls_binding(&verification.tls_public_key_fp).await?;
        
        // 5. Create pinned HTTP client for all future requests
        // This client will validate the cert fingerprint on EVERY connection
        let pinned = tls::create_pinned_client(&verification.tls_public_key_fp)?;
        self.pinned_client = Some(pinned);
        
        // 6. Store ground truth with fingerprints
        let code_measurement = self.expected_measurement
            .clone()
            .unwrap_or_else(|| verification.measurement.clone());
        let enclave_measurement = verification.measurement;

        // Compute fingerprints for the target type (enclave's type)
        let target_type = &enclave_measurement.type_;
        let code_fingerprint = code_measurement.fingerprint_for_target(target_type);
        let enclave_fingerprint = enclave_measurement.fingerprint();

        self.ground_truth = Some(GroundTruth {
            tls_public_key: Some(verification.tls_public_key_fp.clone()),
            hpke_public_key: verification.hpke_public_key.clone(),
            code_measurement,
            enclave_measurement,
            code_fingerprint,
            enclave_fingerprint,
        });
        
        Ok(self.ground_truth.as_ref().unwrap())
    }
    
    /// Verify TLS certificate matches the attested public key (initial check)
    async fn verify_tls_binding(&self, expected_fingerprint: &str) -> Result<()> {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        
        // Connect to the server
        let addr = format!("{}:443", self.host);
        let stream = TcpStream::connect(&addr).await
            .map_err(|e| Error::Tls(format!("Failed to connect: {}", e)))?;
        
        // Setup TLS with default verifier
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        let connector = TlsConnector::from(Arc::new(config));
        let server_name: ServerName<'_> = self.host.clone().try_into()
            .map_err(|_| Error::Tls("Invalid server name".into()))?;
        
        let tls_stream = connector.connect(server_name, stream).await
            .map_err(|e| Error::Tls(format!("TLS handshake failed: {}", e)))?;
        
        // Get the peer certificate
        let (_, conn) = tls_stream.get_ref();
        let certs = conn.peer_certificates()
            .ok_or_else(|| Error::Tls("No peer certificates".into()))?;
        
        if certs.is_empty() {
            return Err(Error::Tls("Empty certificate chain".into()));
        }
        
        // Compute fingerprint of the server's certificate public key
        let actual_fingerprint = tls::cert_pubkey_fingerprint(&certs[0])?;
        
        // Compare with expected
        if actual_fingerprint != expected_fingerprint {
            return Err(Error::CertificateMismatch);
        }
        
        Ok(())
    }
    
    /// Get the HTTP client, ensuring verification has been done
    fn get_client(&self) -> Result<&reqwest::Client> {
        self.pinned_client.as_ref().ok_or(Error::NotVerified)
    }
    
    /// Ensure client is verified, verify if needed
    async fn ensure_verified(&mut self) -> Result<()> {
        if !self.is_verified() {
            self.verify().await?;
        }
        Ok(())
    }
    
    /// Make a chat completion request
    pub async fn chat(&mut self, messages: Vec<ChatMessage>) -> Result<ChatResponse> {
        self.chat_with_model(DEFAULT_CHAT_MODEL, messages, None).await
    }
    
    /// Make a chat completion request with tools
    pub async fn chat_with_tools(
        &mut self,
        messages: Vec<ChatMessage>,
        tools: Vec<Tool>,
    ) -> Result<ChatResponse> {
        self.chat_with_model(DEFAULT_CHAT_MODEL, messages, Some(tools)).await
    }
    
    /// Make a chat completion request with a specific model
    pub async fn chat_with_model(
        &mut self,
        model: &str,
        messages: Vec<ChatMessage>,
        tools: Option<Vec<Tool>>,
    ) -> Result<ChatResponse> {
        self.ensure_verified().await?;
        
        let mut request = ChatRequest::new(model, messages);
        if let Some(t) = tools {
            request = request.with_tools(t);
        }
        
        let url = format!("https://{}/v1/chat/completions", self.host);
        
        // Use the PINNED client - this validates cert fingerprint on every connection
        let client = self.get_client()?;
        
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api { status, message: body });
        }
        
        let chat_response: ChatResponse = response.json().await?;
        Ok(chat_response)
    }
    
    /// Generate an embedding for the given text
    pub async fn embed(&mut self, text: &str) -> Result<Vec<f32>> {
        self.ensure_verified().await?;
        
        let request = EmbeddingRequest::new(text);
        let url = format!("https://{}/v1/embeddings", self.host);
        
        // Use the PINNED client - this validates cert fingerprint on every connection
        let client = self.get_client()?;
        
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;
        
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Api { status, message: body });
        }
        
        let embed_response: EmbeddingResponse = response.json().await?;
        
        embed_response
            .embedding()
            .map(|e| e.to_vec())
            .ok_or(Error::NoEmbedding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_client_creation() {
        let client = SecureClient::new("inference.tinfoil.sh", "test-key");
        assert_eq!(client.host(), "inference.tinfoil.sh");
        assert!(!client.is_verified());
    }
    
    #[test]
    fn test_not_verified_error() {
        let client = SecureClient::new("inference.tinfoil.sh", "test-key");
        assert!(client.get_client().is_err());
    }
}
