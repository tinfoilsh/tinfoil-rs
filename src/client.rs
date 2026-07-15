//! Secure client with attestation verification and TLS certificate pinning
//!
//! After verification, ALL requests are made through a TLS connection that
//! validates the server certificate fingerprint matches the attested value.

use std::sync::Arc;

use async_openai::config::OpenAIConfig;
use async_openai::middleware::{retry::OpenAIRetryLayer, ReqwestService};
use tower::Layer;

use crate::error::{Error, Result};
use crate::user_cache_secret::{SharedUserCacheSecret, UserCacheSecret, UserCacheSecretService};
use crate::verifier::attestation::{self, types::{AttestationDocument, GroundTruth, Measurement}};
use crate::verifier::sigstore;
use crate::verifier::tls;

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
    pinned_client: Option<tls::HostBoundPinnedClient>,

    /// Test-only base-URL override so unit tests can point the request
    /// paths at a local plain-HTTP server. Production always talks
    /// `https://{host}`.
    #[cfg(test)]
    pub(crate) base_url_override: Option<String>,
}

impl SecureClient {
    /// Create a new client for the given enclave host and repository.
    ///
    /// The `repo` parameter specifies the GitHub repository used for
    /// Sigstore code provenance verification (e.g., "tinfoilsh/confidential-model-router").
    pub fn new(host: impl Into<String>, repo: impl Into<String>, api_key: impl Into<String>) -> Self {
        crate::ensure_crypto_provider();
        Self {
            host: host.into(),
            repo: repo.into(),
            api_key: api_key.into(),
            pinned_measurement: None,
            ground_truth: None,
            pinned_client: None,
            #[cfg(test)]
            base_url_override: None,
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
        crate::ensure_crypto_provider();
        Self {
            host: host.into(),
            repo: String::new(),
            api_key: api_key.into(),
            pinned_measurement: Some(measurement),
            ground_truth: None,
            pinned_client: None,
            #[cfg(test)]
            base_url_override: None,
        }
    }
    
    /// Create a verified client using router discovery with fallback.
    ///
    /// This function:
    /// 1. Fetches available routers from the discovery endpoint
    /// 2. Tries each router until one verifies successfully
    /// 3. Falls back to default router if all routers fail
    pub async fn new_default_client(api_key: impl Into<String>) -> Result<Self> {
        // Install the rustls crypto provider before any HTTP client is
        // built — `fetch_routers` constructs a reqwest::Client and would
        // panic with "No process-level CryptoProvider available" otherwise.
        crate::ensure_crypto_provider();
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
        let gt = self.ground_truth.as_ref().ok_or(Error::Configuration("Client not verified - call verify() first".into()))?;
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
        // Clear prior trust state so a failure leaves the client unverified
        self.pinned_client = None;
        self.ground_truth = None;

        // 1. Obtain code measurement (Sigstore verification or pinned value)
        let (code_measurement, digest) = if let Some(pinned) = &self.pinned_measurement {
            (pinned.clone(), "pinned_no_digest".to_string())
        } else {
            let result = sigstore::verify_repo(&self.repo).await?;
            (result.measurement, result.digest)
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
        let verified_origin = reqwest::Url::parse(&self.base_url())
            .map_err(|e| Error::Configuration(format!("Invalid enclave origin: {e}")))?;
        let pinned = tls::create_host_bound_pinned_client(
            &verification.tls_public_key_fp,
            verified_origin,
        )?;
        self.pinned_client = Some(pinned);
        
        // 6. Store ground truth
        let enclave_measurement = verification.measurement;
        let target_type = &enclave_measurement.type_;
        let code_fingerprint = code_measurement.fingerprint_for_target(target_type);
        let enclave_fingerprint = enclave_measurement.fingerprint();

        self.ground_truth = Some(GroundTruth {
            digest,
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
        
        // Crypto provider is installed at every public entry point via
        // `ensure_crypto_provider()`; this branch only runs from those
        // paths, so it's already set up.
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
        
        // Check 0: TLS public key must be ECDSA
        let peer_cert = Certificate::from_der(certs[0].as_ref())
            .map_err(|e| Error::Tls(format!("Failed to parse peer certificate: {}", e)))?;
        let peer_key_algo = &peer_cert.tbs_certificate.subject_public_key_info.algorithm.oid;
        const OID_EC_PUBLIC_KEY: const_oid::ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
        if *peer_key_algo != OID_EC_PUBLIC_KEY {
            return Err(Error::Tls(format!(
                "TLS peer certificate key is not ECDSA (algorithm OID: {})",
                peer_key_algo
            )));
        }

        // Check 1: SPKI fingerprint matches attested value
        let actual_fingerprint = tls::cert_pubkey_fingerprint(&certs[0])?;
        if actual_fingerprint != expected_fingerprint {
            return Err(Error::CertificateMismatch);
        }

        // Extract DNS SANs from the certificate (already parsed as peer_cert above)
        let dns_sans: Vec<String> = match peer_cert.tbs_certificate.get::<SubjectAltName>() {
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
    
    /// Returns an HTTP client pinned and bound to the verified enclave origin.
    ///
    /// Initial requests and redirects to any other scheme, host, or port are
    /// rejected before transmission.
    pub fn http_client(&self) -> Result<&tls::OriginBoundClient> {
        self.pinned_client
            .as_ref()
            .map(|client| &client.exposed)
            .ok_or(Error::Configuration(
                "Client not verified - call verify() first".into(),
            ))
    }

    pub(crate) fn pinned_http_client(&self) -> Result<&reqwest::Client> {
        self.pinned_client
            .as_ref()
            .map(|client| &client.transport)
            .ok_or(Error::Configuration(
                "Client not verified - call verify() first".into(),
            ))
    }

    /// Returns the base URL for API requests to this enclave.
    pub fn base_url(&self) -> String {
        #[cfg(test)]
        if let Some(url) = &self.base_url_override {
            return url.clone();
        }
        format!("https://{}", self.host)
    }

    /// Returns the API key used for authentication.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }
}

/// OpenAI-compatible client backed by a verified Tinfoil enclave.
///
/// This wraps [`async_openai::Client`] with the enclave's TLS-pinned transport,
/// matching the Go SDK's pattern where `tinfoil.Client` embeds `*openai.Client`.
///
/// All OpenAI methods are available via [`Deref`](std::ops::Deref) — call
/// `.chat()`, `.embeddings()`, `.audio()` etc. directly on this client.
///
/// # Example
/// ```rust,ignore
/// use tinfoil::Client;
/// use async_openai::types::CreateChatCompletionRequestArgs;
///
/// let client = Client::new("inference.tinfoil.sh", "tinfoilsh/confidential-model-router", "api-key").await?;
///
/// let request = CreateChatCompletionRequestArgs::default()
///     .model("model-name")
///     .messages(vec![/* ... */])
///     .build()?;
///
/// // Streaming
/// let mut stream = client.chat().create_stream(request.clone()).await?;
///
/// // Non-streaming
/// let response = client.chat().create(request).await?;
/// ```
pub struct Client {
    openai: async_openai::Client<OpenAIConfig>,
    secure: SecureClient,
    /// Shared prompt-cache-secret source: the injection stack baked into
    /// `openai` and the relaxed chat path both read through this cell, so
    /// [`with_user_cache_secret`](Self::with_user_cache_secret) can swap
    /// the source without rebuilding anything — the two request paths can
    /// never observe different secrets.
    user_cache_secret: Arc<SharedUserCacheSecret>,
}

impl Client {
    /// Create a new attested OpenAI client for the given enclave.
    ///
    /// This performs full attestation verification before returning:
    /// Sigstore code provenance, hardware attestation, measurement comparison,
    /// and TLS certificate pinning.
    pub async fn new(
        enclave: impl Into<String>,
        repo: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        let api_key = api_key.into();
        let mut secure = SecureClient::new(enclave, repo, &api_key);
        secure.verify().await?;
        Self::from_secure_client(secure, &api_key)
    }

    /// Create an attested OpenAI client using router discovery.
    ///
    /// Discovers available routers, verifies the first one that passes
    /// attestation, and returns a ready-to-use client.
    ///
    /// The API key is read from the `TINFOIL_API_KEY` environment variable.
    /// To pass an API key explicitly, use [`Client::new_default_with_api_key`].
    pub async fn new_default() -> Result<Self> {
        let api_key = std::env::var("TINFOIL_API_KEY").map_err(|_| {
            Error::Configuration(
                "TINFOIL_API_KEY environment variable is not set. \
                 Set it or use Client::new_default_with_api_key()."
                    .to_string(),
            )
        })?;
        Self::new_default_with_api_key(api_key).await
    }

    /// Create an attested OpenAI client using router discovery with an
    /// explicit API key.
    ///
    /// Discovers available routers, verifies the first one that passes
    /// attestation, and returns a ready-to-use client.
    pub async fn new_default_with_api_key(api_key: impl Into<String>) -> Result<Self> {
        let api_key = api_key.into();
        let secure = SecureClient::new_default_client(&api_key).await?;
        Self::from_secure_client(secure, &api_key)
    }

    /// Create from an already-verified `SecureClient`.
    fn from_secure_client(secure: SecureClient, api_key: &str) -> Result<Self> {
        let user_cache_secret = Arc::new(SharedUserCacheSecret::new(UserCacheSecret::deferred()));
        let openai = Self::build_openai(&secure, api_key, &user_cache_secret)?;

        Ok(Self {
            openai,
            secure,
            user_cache_secret,
        })
    }

    /// Build the OpenAI client on the pinned transport.
    ///
    /// The execution stack mirrors async-openai's default (retry → reqwest)
    /// with the user-cache-secret layer in between: the field is injected
    /// into the body before the request enters the pinned TLS connection, so
    /// the secret is only ever visible to the verified enclave, and retries
    /// replay the injected body rather than the caller's original.
    fn build_openai(
        secure: &SecureClient,
        api_key: &str,
        user_cache_secret: &Arc<SharedUserCacheSecret>,
    ) -> Result<async_openai::Client<OpenAIConfig>> {
        let http = secure.pinned_http_client()?.clone();
        let config = OpenAIConfig::new()
            .with_api_key(api_key)
            .with_api_base(format!("{}/v1", secure.base_url()));

        let stack = OpenAIRetryLayer::default().layer(UserCacheSecretService::new(
            Arc::clone(user_cache_secret),
            ReqwestService::new(http.clone()),
        ));

        Ok(async_openai::Client::with_config(config)
            .with_http_client(http)
            .with_http_service(stack))
    }

    /// Re-verify the enclave attestation (e.g. after certificate rotation).
    ///
    /// On success, the underlying OpenAI client is replaced with one backed
    /// by the new pinned transport.
    pub async fn verify(&mut self) -> Result<&GroundTruth> {
        self.secure.verify().await?;

        self.openai =
            Self::build_openai(&self.secure, self.secure.api_key(), &self.user_cache_secret)?;

        Ok(self.secure.ground_truth().unwrap())
    }

    /// Pin the prompt-cache secret for this client (e.g. one stable value
    /// per end user), taking precedence over the `TINFOIL_USER_CACHE_SECRET`
    /// environment variable and the generated secret. Use one stable value
    /// per end user: a server holding many end users' conversations should
    /// instead set the `user_cache_secret` field per request, which always
    /// wins over the client-level secret:
    ///
    /// ```rust,ignore
    /// let body = client.chat_relaxed().request()
    ///     .model("model-name")
    ///     .set("user_cache_secret", per_user_secret)
    ///     .build();
    /// ```
    ///
    /// An empty string is treated as unset and restores default resolution.
    pub fn with_user_cache_secret(self, secret: impl Into<String>) -> Self {
        // Swap the source inside the shared cell. The injection stack and
        // the relaxed path read through the same cell on every request, so
        // the new choice — including an empty reset to defaults — takes
        // effect immediately on both paths, unconditionally: no fallible
        // stack rebuild is involved that could leave one path injecting a
        // stale secret.
        self.user_cache_secret
            .replace(UserCacheSecret::explicit(secret.into()));
        self
    }

    /// Snapshot of the client-level user-cache-secret source, shared with
    /// the relaxed chat path (which posts through the pinned reqwest client
    /// directly).
    pub(crate) fn user_cache_secret(&self) -> Arc<UserCacheSecret> {
        self.user_cache_secret.current()
    }

    /// Returns the underlying `SecureClient` for low-level access.
    pub fn secure_client(&self) -> &SecureClient {
        &self.secure
    }

    /// Returns the enclave hostname.
    pub fn enclave(&self) -> &str {
        self.secure.host()
    }

    /// Returns the GitHub repository used for code provenance verification.
    pub fn repo(&self) -> &str {
        &self.secure.repo
    }

    /// Returns an origin-bound pinned HTTP client for raw requests.
    ///
    /// Raw callers must add `user_cache_secret` to eligible request bodies
    /// themselves when prompt-cache scoping is required.
    pub fn http_client(&self) -> Result<&tls::OriginBoundClient> {
        self.secure.http_client()
    }

    /// Shortcut for `client.audio().transcription().create(request)`.
    ///
    /// One of the three first-class shortcuts on [`Client`], one per
    /// flagship API surface:
    /// chat → [`chat_relaxed`](Self::chat_relaxed),
    /// embeddings → [`embed_batch`](Self::embed_batch),
    /// audio → [`transcribe`](Self::transcribe).
    pub async fn transcribe(
        &self,
        request: async_openai::types::audio::CreateTranscriptionRequest,
    ) -> std::result::Result<
        async_openai::types::audio::CreateTranscriptionResponseJson,
        async_openai::error::OpenAIError,
    > {
        self.openai.audio().transcription().create(request).await
    }

    /// Embed a batch of strings, preserving input order in the returned
    /// `Vec<Vec<f32>>`.
    pub async fn embed_batch<I, S>(
        &self,
        model: impl Into<String>,
        inputs: I,
    ) -> std::result::Result<Vec<Vec<f32>>, async_openai::error::OpenAIError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        use async_openai::types::embeddings::{CreateEmbeddingRequestArgs, EmbeddingInput};

        let inputs: Vec<String> = inputs.into_iter().map(Into::into).collect();
        let request = CreateEmbeddingRequestArgs::default()
            .model(model.into())
            .input(EmbeddingInput::StringArray(inputs))
            .build()?;
        let mut response = self.openai.embeddings().create(request).await?;
        // Preserve input order even if a router returns retry results out of order.
        response.data.sort_by_key(|d| d.index);
        Ok(response.data.into_iter().map(|d| d.embedding).collect())
    }
}

/// Deref to the inner `async_openai::Client`, exposing all OpenAI methods directly.
/// This mirrors Go's struct embedding where `tinfoil.Client` promotes `*openai.Client`.
impl std::ops::Deref for Client {
    type Target = async_openai::Client<OpenAIConfig>;

    fn deref(&self) -> &Self::Target {
        &self.openai
    }
}

#[cfg(test)]
impl Client {
    /// Test-only client wired to an unpinned transport and an arbitrary
    /// base URL (e.g. a local plain-HTTP server), skipping attestation.
    /// Exercises the production `from_secure_client` construction path.
    pub(crate) fn test_client(base_url: impl Into<String>) -> Self {
        crate::ensure_crypto_provider();
        let transport = reqwest::Client::new();
        let exposed = tls::OriginBoundClient::unbound_for_test(transport.clone());
        let secure = SecureClient {
            host: "enclave.test.invalid".to_string(),
            repo: "org/repo".to_string(),
            api_key: "test-key".to_string(),
            pinned_measurement: None,
            ground_truth: None,
            pinned_client: Some(tls::HostBoundPinnedClient { transport, exposed }),
            base_url_override: Some(base_url.into()),
        };
        Self::from_secure_client(secure, "test-key")
            .expect("a verified transport must yield a client")
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
        assert!(client.http_client().is_err());
    }

    /// The closest thing this crate has to pinning the transport stack: a
    /// constructed client must build the injection stack (retry → user cache
    /// secret → pinned reqwest) without error, and `with_user_cache_secret`
    /// must replace the source — including an empty reset to defaults.
    /// (End-to-end wire coverage of typed and relaxed request paths lives in
    /// `relaxed::tests::end_to_end_through_the_tinfoil_client`.)
    #[test]
    fn test_with_user_cache_secret_pins_and_resets() {
        let client = Client::test_client("http://127.0.0.1:9");

        let client = client.with_user_cache_secret("s1");
        assert_eq!(client.user_cache_secret().get(), Some("s1"));

        // An explicit empty secret restores default resolution.
        let client = client.with_user_cache_secret("");
        assert!(matches!(
            &*client.user_cache_secret(),
            UserCacheSecret::Deferred(_)
        ));
    }

}
