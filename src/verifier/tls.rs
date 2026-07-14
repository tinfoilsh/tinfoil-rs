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
    expected_server_name: Option<rustls::pki_types::ServerName<'static>>,
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
            expected_server_name: None,
            inner,
        })
    }

    fn with_server_name(
        mut self,
        expected_server_name: rustls::pki_types::ServerName<'static>,
    ) -> Self {
        self.expected_server_name = Some(expected_server_name);
        self
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
        if let Some(expected) = &self.expected_server_name {
            if server_name != expected {
                return Err(rustls::Error::General(
                    "request origin is not the verified enclave origin".to_string(),
                ));
            }
        }

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
    build_pinned_client(pinned_fingerprint, None, None)
}

#[derive(Clone)]
pub(crate) struct HostBoundPinnedClient {
    pub(crate) transport: reqwest::Client,
    pub(crate) exposed: OriginBoundClient,
}

/// HTTP client that rejects requests outside one verified enclave origin.
#[derive(Clone)]
pub struct OriginBoundClient {
    inner: reqwest_middleware::ClientWithMiddleware,
}

impl OriginBoundClient {
    #[cfg(test)]
    pub(crate) fn unbound_for_test(transport: reqwest::Client) -> Self {
        Self {
            inner: reqwest_middleware::ClientBuilder::new(transport).build(),
        }
    }

    fn wrap(
        &self,
        inner: reqwest_middleware::RequestBuilder,
    ) -> OriginBoundRequestBuilder {
        OriginBoundRequestBuilder {
            inner,
            client: self.clone(),
        }
    }

    pub fn get<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.get(url))
    }

    pub fn post<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.post(url))
    }

    pub fn put<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.put(url))
    }

    pub fn patch<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.patch(url))
    }

    pub fn delete<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.delete(url))
    }

    pub fn head<U: reqwest::IntoUrl>(&self, url: U) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.head(url))
    }

    pub fn request<U: reqwest::IntoUrl>(
        &self,
        method: reqwest::Method,
        url: U,
    ) -> OriginBoundRequestBuilder {
        self.wrap(self.inner.request(method, url))
    }

    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.inner.execute(request).await
    }
}

/// Request builder that preserves origin binding through request construction.
#[must_use = "OriginBoundRequestBuilder does nothing until it is sent"]
pub struct OriginBoundRequestBuilder {
    inner: reqwest_middleware::RequestBuilder,
    client: OriginBoundClient,
}

impl OriginBoundRequestBuilder {
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        reqwest::header::HeaderName: TryFrom<K>,
        <reqwest::header::HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        reqwest::header::HeaderValue: TryFrom<V>,
        <reqwest::header::HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            inner: self.inner.header(key, value),
            ..self
        }
    }

    pub fn headers(self, headers: reqwest::header::HeaderMap) -> Self {
        Self {
            inner: self.inner.headers(headers),
            ..self
        }
    }

    pub fn version(self, version: reqwest::Version) -> Self {
        Self {
            inner: self.inner.version(version),
            ..self
        }
    }

    pub fn basic_auth<U, P>(self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        Self {
            inner: self.inner.basic_auth(username, password),
            ..self
        }
    }

    pub fn bearer_auth<T: std::fmt::Display>(self, token: T) -> Self {
        Self {
            inner: self.inner.bearer_auth(token),
            ..self
        }
    }

    pub fn body<T: Into<reqwest::Body>>(self, body: T) -> Self {
        Self {
            inner: self.inner.body(body),
            ..self
        }
    }

    pub fn timeout(self, timeout: std::time::Duration) -> Self {
        Self {
            inner: self.inner.timeout(timeout),
            ..self
        }
    }

    pub fn multipart(self, multipart: reqwest::multipart::Form) -> Self {
        Self {
            inner: self.inner.multipart(multipart),
            ..self
        }
    }

    pub fn query<T: serde::Serialize + ?Sized>(self, query: &T) -> Self {
        Self {
            inner: self.inner.query(query),
            ..self
        }
    }

    pub fn json<T: serde::Serialize + ?Sized>(self, json: &T) -> Self {
        Self {
            inner: self.inner.json(json),
            ..self
        }
    }

    pub fn build(self) -> reqwest::Result<reqwest::Request> {
        self.inner.build()
    }

    pub fn build_split(self) -> (OriginBoundClient, reqwest::Result<reqwest::Request>) {
        let (_, request) = self.inner.build_split();
        (self.client, request)
    }

    pub fn with_extension<T: Send + Sync + Clone + 'static>(self, extension: T) -> Self {
        Self {
            inner: self.inner.with_extension(extension),
            ..self
        }
    }

    pub fn extensions(&mut self) -> &mut http::Extensions {
        self.inner.extensions()
    }

    pub async fn send(self) -> reqwest_middleware::Result<reqwest::Response> {
        self.inner.send().await
    }

    pub fn try_clone(&self) -> Option<Self> {
        self.inner.try_clone().map(|inner| Self {
            inner,
            client: self.client.clone(),
        })
    }
}

impl std::fmt::Debug for OriginBoundRequestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

struct OriginBindingMiddleware {
    expected_origin: String,
}

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for OriginBindingMiddleware {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        if !request_origin_matches(&self.expected_origin, request.url()) {
            return Err(reqwest_middleware::Error::middleware(
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "request origin is outside the verified enclave origin",
                ),
            ));
        }
        next.run(request, extensions).await
    }
}

pub(crate) fn create_host_bound_pinned_client(
    pinned_fingerprint: &str,
    expected_origin: reqwest::Url,
) -> Result<HostBoundPinnedClient> {
    let expected_server_name = server_name_from_origin(&expected_origin)?;
    let expected_origin = expected_origin.origin().ascii_serialization();
    let redirect_origin = expected_origin.clone();
    let redirect_policy = reqwest::redirect::Policy::custom(move |attempt| {
        if request_origin_matches(&redirect_origin, attempt.url()) {
            attempt.follow()
        } else {
            attempt.error("redirect target is outside the verified enclave origin")
        }
    });
    let transport = build_pinned_client(
        pinned_fingerprint,
        Some(expected_server_name),
        Some(redirect_policy),
    )?;
    let exposed_transport = transport.clone();
    let exposed = reqwest_middleware::ClientBuilder::new(exposed_transport)
        .with(OriginBindingMiddleware { expected_origin })
        .build();
    Ok(HostBoundPinnedClient {
        transport,
        exposed: OriginBoundClient { inner: exposed },
    })
}

fn request_origin_matches(expected_origin: &str, request_url: &reqwest::Url) -> bool {
    request_url.origin().ascii_serialization() == expected_origin
}

fn server_name_from_origin(
    expected_origin: &reqwest::Url,
) -> Result<rustls::pki_types::ServerName<'static>> {
    let host = expected_origin
        .host_str()
        .ok_or_else(|| Error::Configuration("Verified enclave origin has no host".to_string()))?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| {
        Error::Configuration("Verified enclave origin has an invalid host".to_string())
    })
}

fn build_pinned_client(
    pinned_fingerprint: &str,
    expected_server_name: Option<rustls::pki_types::ServerName<'static>>,
    redirect_policy: Option<reqwest::redirect::Policy>,
) -> Result<reqwest::Client> {
    crate::ensure_crypto_provider();

    // Create pinned verifier
    let mut verifier = PinnedCertVerifier::new(pinned_fingerprint.to_string())?;
    if let Some(expected) = expected_server_name {
        verifier = verifier.with_server_name(expected);
    }
    
    // Build rustls config with our custom verifier
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    
    // Build reqwest client with this config
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .https_only(true);
    if let Some(policy) = redirect_policy {
        builder = builder.redirect(policy);
    }
    let client = builder
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

    #[tokio::test]
    async fn test_pinned_client_rejects_http() {
        let fp = "0".repeat(64);
        let client = create_pinned_client(&fp).expect("Failed to create client");
        let result = client.get("http://example.com").send().await;
        assert!(result.is_err(), "HTTP request should be rejected by https_only");
    }

    #[test]
    fn test_pinned_cert_verifier_creation() {
        crate::ensure_crypto_provider();

        let fingerprint = "0".repeat(64); // Valid format but won't match any real cert
        let result = PinnedCertVerifier::new(fingerprint);
        assert!(result.is_ok(), "Creating PinnedCertVerifier with valid fingerprint should succeed");
    }

    #[test]
    fn test_origin_server_name_supports_dns_and_ip_addresses() {
        for (origin, expected) in [
            ("https://enclave.example", "enclave.example"),
            ("https://127.0.0.1", "127.0.0.1"),
            ("https://[2001:db8::1]", "2001:db8::1"),
        ] {
            let origin = reqwest::Url::parse(origin).unwrap();
            let expected = rustls::pki_types::ServerName::try_from(expected.to_string()).unwrap();
            assert_eq!(server_name_from_origin(&origin).unwrap(), expected);
        }
    }

    #[test]
    fn test_origin_binding_normalizes_default_ports() {
        for (expected, equivalent, different_port) in [
            (
                "https://enclave.example",
                "https://enclave.example:443/custom?x=1",
                "https://enclave.example:8443",
            ),
            (
                "https://127.0.0.1",
                "https://127.0.0.1:443/custom?x=1",
                "https://127.0.0.1:8443",
            ),
            (
                "https://[2001:db8::1]",
                "https://[2001:db8::1]:443/custom?x=1",
                "https://[2001:db8::1]:8443",
            ),
        ] {
            let expected = reqwest::Url::parse(expected)
                .unwrap()
                .origin()
                .ascii_serialization();
            assert!(request_origin_matches(
                &expected,
                &reqwest::Url::parse(equivalent).unwrap()
            ));
            assert!(!request_origin_matches(
                &expected,
                &reqwest::Url::parse(different_port).unwrap()
            ));
        }
    }

    #[tokio::test]
    async fn test_host_bound_client_rejects_initial_alternate_port() {
        let fingerprint = "0".repeat(64);
        let client = create_host_bound_pinned_client(
            &fingerprint,
            reqwest::Url::parse("https://127.0.0.1").unwrap(),
        )
        .unwrap();

        let error = client
            .exposed
            .get("https://127.0.0.1:9/v1/models")
            .send()
            .await
            .unwrap_err();
        assert!(error.is_middleware());
        assert!(error
            .to_string()
            .contains("outside the verified enclave origin"));
    }

    #[tokio::test]
    async fn test_request_builder_split_preserves_origin_binding() {
        let fingerprint = "0".repeat(64);
        let client = create_host_bound_pinned_client(
            &fingerprint,
            reqwest::Url::parse("https://127.0.0.1").unwrap(),
        )
        .unwrap();

        let (client, request) = client
            .exposed
            .post("https://127.0.0.1/v1/chat/completions")
            .query(&[("stream", "false")])
            .json(&serde_json::json!({"model": "m"}))
            .build_split();
        let mut request = request.unwrap();
        *request.url_mut() = reqwest::Url::parse("https://127.0.0.1:9/v1/chat/completions").unwrap();

        let error = client.execute(request).await.unwrap_err();
        assert!(error.is_middleware());
        assert!(error
            .to_string()
            .contains("outside the verified enclave origin"));
    }
}
