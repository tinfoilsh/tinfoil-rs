//! Secure client with attestation verification and TLS certificate pinning
//!
//! After verification, ALL requests are made through a TLS connection that
//! validates the server certificate fingerprint matches the attested value.

use crate::api::{ChatMessage, ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse, Tool};
use crate::error::{Error, Result};
use crate::verifier::attestation::{self, types::{AttestationDocument, GroundTruth, Measurement}};
use crate::verifier::sigstore;
use crate::verifier::tls;

use crate::constants::DEFAULT_CHAT_MODEL;

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
    
    /// GitHub repository for code provenance verification
    repo: String,
    
    /// API key for authentication
    api_key: String,
    
    /// Pinned code measurement (skips Sigstore verification when provided)
    pinned_measurement: Option<Measurement>,
    
    /// Verified ground truth
    ground_truth: Option<GroundTruth>,
    
    /// Pinned HTTP client (used after verification)
    /// This client validates cert fingerprint on every connection
    pinned_client: Option<reqwest::Client>,
}

impl SecureClient {
    /// Create a new client for the given enclave host and repository.
    ///
    /// The `repo` parameter specifies the GitHub repository used for
    /// Sigstore code provenance verification (e.g., "tinfoilsh/confidential-model-router").
    pub fn new(host: impl Into<String>, repo: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            repo: repo.into(),
            api_key: api_key.into(),
            pinned_measurement: None,
            ground_truth: None,
            pinned_client: None,
        }
    }
    
    /// Create a client with a pinned code measurement.
    ///
    /// When a pinned measurement is provided, Sigstore verification is skipped
    /// and the pinned value is compared directly against the enclave's measurement.
    pub fn with_measurement(
        host: impl Into<String>,
        api_key: impl Into<String>,
        measurement: Measurement,
    ) -> Self {
        Self {
            host: host.into(),
            repo: String::new(),
            api_key: api_key.into(),
            pinned_measurement: Some(measurement),
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

        let repo = crate::constants::DEFAULT_REPO;

        let routers = match crate::discovery::fetch_routers().await {
            Ok(r) => r,
            Err(_) => {
                // Fall back to default router, but still verify it
                let mut client = Self::new(crate::constants::DEFAULT_ROUTER, repo, api_key);
                client.verify().await?;
                return Ok(client);
            }
        };

        for router in routers {
            let mut client = Self::new(&router, repo, api_key.clone());
            if client.verify().await.is_ok() {
                return Ok(client);
            }
        }

        // Fall back to default router, but still verify it
        let mut client = Self::new(crate::constants::DEFAULT_ROUTER, repo, api_key);
        client.verify().await?;
        Ok(client)
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

    /// Verify the enclave attestation and set up TLS pinning.
    /// 
    /// This performs full three-step verification:
    /// 1. Sigstore verification: verify code provenance via GitHub + Sigstore
    /// 2. Hardware attestation: verify AMD SEV-SNP report and certificate chain
    /// 3. Measurement comparison: ensure enclave runs the expected code
    /// 4. TLS binding: pin all future connections to the attested certificate
    pub async fn verify(&mut self) -> Result<&GroundTruth> {
        // 1. Obtain code measurement (Sigstore verification or pinned value)
        let code_measurement = if let Some(pinned) = &self.pinned_measurement {
            pinned.clone()
        } else {
            sigstore::verify_repo(&self.repo).await?
        };
        
        // 2. Fetch and verify hardware attestation
        let doc = attestation::fetch(&self.host).await?;
        let verification = attestation::verify_full(&doc).await?;
        
        // 3. Compare code measurement against enclave measurement
        code_measurement.equals(&verification.measurement)
            .map_err(|_| Error::MeasurementMismatch {
                expected: code_measurement.fingerprint(),
                actual: verification.measurement.fingerprint(),
            })?;
        
        // 4. Verify TLS certificate matches attestation (one-time check)
        self.verify_tls_binding(
            &verification.tls_public_key_fp,
            verification.hpke_public_key.as_deref(),
            &doc,
        ).await?;
        
        // 5. Create pinned HTTP client for all future requests
        let pinned = tls::create_pinned_client(&verification.tls_public_key_fp)?;
        self.pinned_client = Some(pinned);
        
        // 6. Store ground truth
        let enclave_measurement = verification.measurement;
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
    
    /// Verify TLS certificate matches the attested public key and SAN bindings.
    ///
    /// This performs three checks on the server's TLS certificate:
    /// 1. SPKI fingerprint matches the attested value (from report_data)
    /// 2. HPKE public key in SANs matches the attested value (dcode `.hpke.` entries)
    /// 3. Attestation document hash in SANs matches the actual document (dcode `.hatt.` entries)
    ///
    /// Checks 2 and 3 match the JS and Go (VerifyFromBundle) reference implementations.
    async fn verify_tls_binding(
        &self,
        expected_fingerprint: &str,
        expected_hpke_key: Option<&str>,
        attestation_doc: &AttestationDocument,
    ) -> Result<()> {
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        use rustls::pki_types::ServerName;
        use std::sync::Arc;
        use der::Decode;
        use x509_cert::Certificate;
        use x509_cert::ext::pkix::SubjectAltName;
        
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
        
        // Check 1: SPKI fingerprint matches attested value
        let actual_fingerprint = tls::cert_pubkey_fingerprint(&certs[0])?;
        if actual_fingerprint != expected_fingerprint {
            return Err(Error::CertificateMismatch);
        }

        // Parse the certificate for SAN inspection
        let cert = Certificate::from_der(certs[0].as_ref())
            .map_err(|e| Error::Tls(format!("Failed to parse certificate for SAN check: {}", e)))?;

        // Extract DNS SANs from the certificate
        let dns_sans: Vec<String> = match cert.tbs_certificate.get::<SubjectAltName>() {
            Ok(Some((_, san))) => {
                san.0.iter().filter_map(|name| {
                    if let x509_cert::ext::pkix::name::GeneralName::DnsName(dns) = name {
                        Some(dns.to_string())
                    } else {
                        None
                    }
                }).collect()
            }
            _ => Vec::new(),
        };

        let san_refs: Vec<&str> = dns_sans.iter().map(|s| s.as_str()).collect();

        // Check 2: HPKE public key in SANs matches attested value
        // Go hard-errors if .hpke. SANs are missing — we do the same.
        if let Some(expected_hpke) = expected_hpke_key {
            // Only verify if the HPKE key is non-zero (some attestations may not include it)
            let is_all_zeros = expected_hpke.chars().all(|c| c == '0');
            if !is_all_zeros {
                let hpke_bytes = crate::verifier::dcode::decode_from_sans(&san_refs, "hpke")
                    .ok_or_else(|| Error::Tls(
                        "Certificate SANs do not contain HPKE key (.hpke. entries)".into()
                    ))?;
                let actual_hpke = hex::encode(&hpke_bytes);
                if actual_hpke != expected_hpke {
                    return Err(Error::Tls(format!(
                        "HPKE key mismatch: certificate SAN has {}, attestation has {}",
                        actual_hpke, expected_hpke
                    )));
                }
            }
        }

        // Check 3: Attestation document hash in SANs matches actual document
        // Go hard-errors if .hatt. SANs are missing — we do the same.
        let hash_bytes = crate::verifier::dcode::decode_from_sans(&san_refs, "hatt")
            .ok_or_else(|| Error::Tls(
                "Certificate SANs do not contain attestation hash (.hatt. entries)".into()
            ))?;
        let actual_hash = String::from_utf8(hash_bytes)
            .map_err(|_| Error::Tls("Invalid UTF-8 in attestation hash SAN".into()))?;
        let expected_hash = attestation_doc.hash();
        if actual_hash != expected_hash {
            return Err(Error::Tls(format!(
                "Attestation hash mismatch: certificate SAN has {}, computed {}",
                actual_hash, expected_hash
            )));
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

    /// Send a POST request with automatic re-verification on certificate errors.
    ///
    /// If the request fails with a connection error (e.g. TLS certificate rotation),
    /// performs full re-attestation and retries the request once. If re-verification
    /// fails, the original connection error is returned. This matches the Go SDK's
    /// `reVerifyingTransport` behavior.
    async fn send_with_reverify(
        &mut self,
        url: &str,
        body: &(impl serde::Serialize + Sync),
    ) -> Result<reqwest::Response> {
        self.ensure_verified().await?;

        // First attempt
        let first_err = match self.try_send(url, body).await {
            Ok(resp) => return Ok(resp),
            Err(e) => e,
        };

        // Only retry on connection errors (TLS handshake failures from cert rotation)
        let should_retry = matches!(&first_err, Error::Http(e) if e.is_connect());
        if !should_retry {
            return Err(first_err);
        }

        // Re-verify: full attestation cycle. If this fails, return the original error.
        if self.verify().await.is_err() {
            return Err(first_err);
        }

        // Retry once with the new pinned client
        self.try_send(url, body).await
    }

    /// Send a single POST request using the current pinned client.
    async fn try_send(
        &self,
        url: &str,
        body: &(impl serde::Serialize + Sync),
    ) -> Result<reqwest::Response> {
        let client = self.get_client()?;
        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
            .await?;
        Ok(response)
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
        let mut request = ChatRequest::new(model, messages);
        if let Some(t) = tools {
            request = request.with_tools(t);
        }
        
        let url = format!("https://{}/v1/chat/completions", self.host);
        
        let response = self.send_with_reverify(&url, &request).await?;
        
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
        let request = EmbeddingRequest::new(text);
        let url = format!("https://{}/v1/embeddings", self.host);
        
        let response = self.send_with_reverify(&url, &request).await?;
        
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
        let client = SecureClient::new("inference.tinfoil.sh", "tinfoilsh/confidential-model-router", "test-key");
        assert_eq!(client.host(), "inference.tinfoil.sh");
        assert!(!client.is_verified());
    }
    
    #[test]
    fn test_not_verified_error() {
        let client = SecureClient::new("inference.tinfoil.sh", "tinfoilsh/confidential-model-router", "test-key");
        assert!(client.get_client().is_err());
    }
}
