//! EHBP proxy transport.
//!
//! In proxy mode the SDK sends requests to a caller-operated proxy
//! instead of the enclave. Bodies are sealed with EHBP to the enclave's
//! attested HPKE key before they leave the process via the released
//! `tinfoil-ehbp` client, which streams arbitrary request bodies
//! (JSON, SSE, multipart uploads) through a fresh HPKE context per
//! attempt, so the proxy can authenticate users, add its own API key,
//! and read usage-metric headers without ever seeing plaintext. The
//! `X-Tinfoil-Enclave-Url` header tells the proxy which verified
//! enclave to forward to.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};

use async_openai::error::OpenAIError;
use async_openai::middleware::HttpRequestFactory;

use crate::error::{Error, Result};

/// Header telling the proxy which enclave to forward the request to.
pub(crate) const ENCLAVE_URL_HEADER: &str = "x-tinfoil-enclave-url";

type RefreshFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;
type RefreshFn = dyn Fn() -> RefreshFuture + Send + Sync;

struct EhbpChannel {
    client: Option<tinfoil_ehbp::Client>,
    public_key: Option<String>,
    generation: u64,
}

/// Verified EHBP proxy configuration, shared by the typed async-openai
/// stack and the relaxed chat path.
///
/// The sealing channel lives behind a shared cell so trust changes
/// propagate to every clone of this handle, including transports
/// already baked into an OpenAI service stack: [`revoke`](Self::revoke)
/// makes them all fail closed, and [`rekey`](Self::rekey) points them
/// all at a freshly attested HPKE key.
#[derive(Clone)]
pub(crate) struct EhbpProxy {
    /// Proxy origin plus optional path prefix, without a trailing slash.
    base_url: String,
    /// Verified enclave URL forwarded via `X-Tinfoil-Enclave-Url`.
    enclave_url: String,
    http: reqwest::Client,
    channel: Arc<RwLock<EhbpChannel>>,
    refresh: Arc<RwLock<Option<Arc<RefreshFn>>>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl EhbpProxy {
    pub(crate) fn new(
        proxy_url: &str,
        enclave_url: String,
        hpke_public_key_hex: &str,
    ) -> Result<Self> {
        crate::ensure_crypto_provider();
        let base_url = proxy_url.trim_end_matches('/').to_string();
        validate_proxy_url(&base_url)?;
        // Redirects are disabled so a sealed body is never replayed to an
        // origin the caller didn't name.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                Error::Configuration(format!("failed to build proxy HTTP client: {err}"))
            })?;
        let proxy = Self {
            base_url,
            enclave_url,
            http,
            channel: Arc::new(RwLock::new(EhbpChannel {
                client: None,
                public_key: None,
                generation: 0,
            })),
            refresh: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        proxy.rekey(hpke_public_key_hex)?;
        Ok(proxy)
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Replace the sealing channel with one bound to a freshly attested
    /// HPKE key. Every clone of this handle picks the new key up on its
    /// next request.
    pub(crate) fn rekey(&self, hpke_public_key_hex: &str) -> Result<()> {
        let channel = tinfoil_ehbp::Client::with_public_key_hex_and_http_client(
            &self.base_url,
            hpke_public_key_hex,
            self.http.clone(),
        )
        .map_err(map_ehbp_error)?;
        let mut state = self.channel.write().unwrap_or_else(PoisonError::into_inner);
        state.client = Some(channel);
        state.public_key = Some(hpke_public_key_hex.to_owned());
        state.generation = state.generation.wrapping_add(1);
        Ok(())
    }

    pub(crate) fn set_refresher<F, Fut>(&self, refresh: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        *self.refresh.write().unwrap_or_else(PoisonError::into_inner) =
            Some(Arc::new(move || Box::pin(refresh())));
    }

    /// Drop the sealing channel so every clone of this handle fails
    /// closed until [`rekey`](Self::rekey) restores trust.
    pub(crate) fn revoke(&self) {
        let mut state = self.channel.write().unwrap_or_else(PoisonError::into_inner);
        state.client = None;
        state.public_key = None;
        state.generation = state.generation.wrapping_add(1);
    }

    pub(crate) fn is_active(&self) -> bool {
        self.channel
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .client
            .is_some()
    }

    fn generation(&self) -> u64 {
        self.channel
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .generation
    }

    async fn refresh_after_mismatch(&self, seen_generation: u64) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        if self.generation() != seen_generation {
            return Ok(());
        }

        let refresh = self
            .refresh
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                Error::EhbpKeyMismatch(
                    "EHBP key rotated; re-run verify() before retrying the request".into(),
                )
            })?;
        let hpke_public_key = match refresh().await {
            Ok(key) => key,
            Err(err) => {
                self.revoke();
                return Err(err);
            }
        };

        if self.generation() == seen_generation {
            let key_changed = self
                .channel
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .public_key
                .as_deref()
                != Some(&hpke_public_key);
            if !key_changed {
                self.revoke();
                return Err(Error::EhbpKeyMismatch(
                    "attestation returned the previously rejected HPKE key".into(),
                ));
            }
            if let Err(err) = self.rekey(&hpke_public_key) {
                self.revoke();
                return Err(err);
            }
        }
        Ok(())
    }

    /// Seal a request body to the attested enclave key and send it
    /// through the proxy; the response is authenticated and decrypted
    /// before it is returned. Bodyless requests pass through unencrypted
    /// per SPEC §7.4; any request that carries a body (buffered,
    /// streaming, or multipart) is sealed, and an encrypted exchange
    /// never falls back to plaintext.
    pub(crate) async fn send(&self, mut request: reqwest::Request) -> Result<reqwest::Response> {
        let body_is_empty = request
            .body()
            .is_none_or(|body| body.as_bytes().is_some_and(<[u8]>::is_empty));
        if body_is_empty
            && request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION)
        {
            return Err(Error::Ehbp(
                "authenticated bodyless requests cannot use the EHBP proxy because their \
                 responses would not be encrypted"
                    .into(),
            ));
        }
        request.headers_mut().insert(
            ENCLAVE_URL_HEADER,
            reqwest::header::HeaderValue::from_str(&self.enclave_url)
                .map_err(|err| Error::Ehbp(format!("invalid enclave URL header: {err}")))?,
        );
        let channel = self
            .channel
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .client
            .clone()
            .ok_or_else(|| {
                Error::Ehbp(
                    "EHBP transport has been revoked; re-run verify() before sending requests"
                        .into(),
                )
            })?;
        channel.execute(request).await.map_err(map_ehbp_error)
    }

    pub(crate) async fn send_replayable<F>(&self, build: F) -> Result<reqwest::Response>
    where
        F: Fn() -> Result<reqwest::Request>,
    {
        let generation = self.generation();
        let first_attempt = self.send(build()?).await;
        self.retry_after_mismatch(generation, first_attempt, || async {
            self.send(build()?).await
        })
        .await
    }

    async fn retry_after_mismatch<F, Fut>(
        &self,
        seen_generation: u64,
        first_attempt: Result<reqwest::Response>,
        retry: F,
    ) -> Result<reqwest::Response>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<reqwest::Response>>,
    {
        match first_attempt {
            Ok(response) => Ok(response),
            Err(Error::EhbpKeyMismatch(_)) => {
                self.refresh_after_mismatch(seen_generation).await?;
                retry().await
            }
            Err(err) => Err(err),
        }
    }
}

/// EHBP only protects request and response bodies; headers, including
/// the proxy's bearer token, ride on the transport, so prefer https://
/// proxy URLs. Cleartext http:// is accepted for caller-operated
/// proxies, but non-HTTP schemes and URLs with embedded credentials are
/// rejected.
fn validate_proxy_url(base_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|err| Error::Configuration(format!("invalid proxy URL: {err}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Configuration(format!(
            "proxy URL must use http:// or https://, got {}://",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Configuration(
            "proxy URL must not include credentials".into(),
        ));
    }
    if url.host_str().is_none() || url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Configuration(
            "proxy URL must be an absolute HTTP URL without a query or fragment".into(),
        ));
    }
    Ok(())
}

/// Key-configuration mismatches surface typed so callers can re-verify
/// and retry; transport-level reqwest failures keep their identity for
/// retry classification; everything else is an EHBP failure.
fn map_ehbp_error(err: tinfoil_ehbp::Error) -> Error {
    match err {
        tinfoil_ehbp::Error::KeyConfigMismatch(title) => Error::EhbpKeyMismatch(title),
        tinfoil_ehbp::Error::Http(inner) => Error::Http(inner),
        other => Error::Ehbp(other.to_string()),
    }
}

/// Tower transport for the async-openai stack: rebuilds the request from
/// the factory (so every retry reseals with a fresh HPKE context, which
/// the protocol requires), sends it through the proxy, and decrypts the
/// response.
#[derive(Clone)]
pub(crate) struct EhbpTransport {
    proxy: EhbpProxy,
}

impl EhbpTransport {
    pub(crate) fn new(proxy: EhbpProxy) -> Self {
        Self { proxy }
    }
}

impl tower::Service<HttpRequestFactory> for EhbpTransport {
    type Response = reqwest::Response;
    type Error = OpenAIError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<reqwest::Response, OpenAIError>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, factory: HttpRequestFactory) -> Self::Future {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let request = factory.build().await?;
            let generation = proxy.generation();
            let first_attempt = proxy.send(request).await;
            proxy
                .retry_after_mismatch(generation, first_attempt, || async {
                    let request = factory.build().await?;
                    proxy.send(request).await
                })
                .await
                .map_err(into_openai_error)
        })
    }
}

/// Preserve transport-level reqwest errors so the retry layer's
/// classification keeps working; everything else is boxed.
fn into_openai_error(err: Error) -> OpenAIError {
    match err {
        Error::Api(inner) => inner,
        Error::Http(inner) => OpenAIError::Reqwest(inner),
        other => OpenAIError::Boxed(Box::new(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use crate::test_support::ehbp::{encrypt_response_chunks, TestEnclave};
    use async_openai::error::OpenAIError;
    use futures_util::StreamExt;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TEST_ENCLAVE_URL: &str = "https://enclave.test.invalid";
    const RESPONSE_NONCE: [u8; 32] = [5u8; 32];

    #[test]
    fn proxy_url_policy_rejects_malformed_and_credentialed_urls() {
        assert!(validate_proxy_url("https://proxy.example.com").is_ok());
        assert!(validate_proxy_url("http://proxy.example.com").is_ok());
        assert!(validate_proxy_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_proxy_url("http://[::1]:8080").is_ok());
        assert!(matches!(
            validate_proxy_url("ftp://proxy.example.com"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            validate_proxy_url("proxy.example.com"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            validate_proxy_url(&["https://user", ":xxxxx@", "proxy.example.com"].concat()),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            validate_proxy_url("https://user@proxy.example.com"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            validate_proxy_url("https://proxy.example.com?route=enclave"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            validate_proxy_url("https://proxy.example.com/#fragment"),
            Err(Error::Configuration(_))
        ));
    }

    #[tokio::test]
    async fn authenticated_bodyless_requests_fail_before_transmission() {
        let enclave = TestEnclave::generate();
        let proxy = EhbpProxy::new(
            "http://127.0.0.1:9",
            TEST_ENCLAVE_URL.to_string(),
            &enclave.public_key_hex(),
        )
        .unwrap();
        let request = proxy
            .http()
            .get("http://127.0.0.1:9/v1/models")
            .bearer_auth("secret")
            .build()
            .unwrap();

        let err = proxy.send(request).await.unwrap_err();
        assert!(matches!(&err, Error::Ehbp(msg) if msg.contains("bodyless")));
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    async fn read_more(socket: &mut TcpStream, rest: &mut Vec<u8>) {
        let mut tmp = [0u8; 4096];
        let n = socket.read(&mut tmp).await.unwrap();
        assert!(n > 0, "connection closed before body was complete");
        rest.extend_from_slice(&tmp[..n]);
    }

    fn header_value(head: &str, name: &str) -> Option<String> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    /// Minimal HTTP/1.1 request reader for the mock server: returns the
    /// raw header block and the decoded (de-chunked) body bytes.
    async fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let head_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            let mut tmp = [0u8; 4096];
            let n = socket.read(&mut tmp).await.unwrap();
            assert!(n > 0, "connection closed before headers were complete");
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut rest = buf[head_end..].to_vec();

        if header_value(&head, "transfer-encoding")
            .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
        {
            let mut body = Vec::new();
            let mut offset = 0usize;
            loop {
                let line_end = loop {
                    if let Some(pos) = find_subslice(&rest[offset..], b"\r\n") {
                        break offset + pos;
                    }
                    read_more(socket, &mut rest).await;
                };
                let size_hex = std::str::from_utf8(&rest[offset..line_end]).unwrap().trim();
                let size = usize::from_str_radix(size_hex, 16).unwrap();
                offset = line_end + 2;
                if size == 0 {
                    break;
                }
                while rest.len() < offset + size + 2 {
                    read_more(socket, &mut rest).await;
                }
                body.extend_from_slice(&rest[offset..offset + size]);
                offset += size + 2;
            }
            (head, body)
        } else if let Some(len) = header_value(&head, "content-length") {
            let len: usize = len.parse().unwrap();
            while rest.len() < len {
                read_more(socket, &mut rest).await;
            }
            rest.truncate(len);
            (head, rest)
        } else {
            (head, Vec::new())
        }
    }

    async fn write_response(socket: &mut TcpStream, status_line: &str, headers: &str, body: &[u8]) {
        let head = format!(
            "{status_line}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(body).await.unwrap();
    }

    /// Full typed-path round trip: the async-openai client sends an
    /// encrypted chat completion through the mock proxy, the "enclave"
    /// decrypts it with an independent HPKE receiver, and the encrypted
    /// reply decodes into the typed response.
    #[tokio::test]
    async fn typed_chat_completion_round_trips_through_encoded_proxy_prefix() {
        use async_openai::types::chat::{
            ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
        };

        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;

            assert!(head.starts_with("POST /%70roxy/v1/chat/completions"));
            assert_eq!(
                header_value(&head, ENCLAVE_URL_HEADER).as_deref(),
                Some(TEST_ENCLAVE_URL)
            );
            assert_eq!(
                header_value(&head, "authorization").as_deref(),
                Some("Bearer test-key")
            );
            // The wire body must be ciphertext: the prompt never appears.
            assert!(find_subslice(&body, b"Say this is a test").is_none());

            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (plaintext, secret, enc) = enclave.open_request(&enc_hex, &body);
            let request: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(request["model"], "gpt-oss-120b");
            assert_eq!(request["messages"][0]["content"], "Say this is a test");

            let reply = serde_json::to_vec(&json!({
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 1,
                "model": "gpt-oss-120b",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello from the enclave"},
                    "finish_reason": "stop",
                    "logprobs": null
                }],
                "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9}
            }))
            .unwrap();
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &[&reply]);
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                &format!(
                    "Content-Type: application/json\r\nEhbp-Response-Nonce: {}\r\n",
                    hex::encode(RESPONSE_NONCE)
                ),
                &encrypted,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}/%70roxy"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let request = CreateChatCompletionRequestArgs::default()
            .model("gpt-oss-120b")
            .messages(vec![ChatCompletionRequestUserMessageArgs::default()
                .content("Say this is a test")
                .build()
                .unwrap()
                .into()])
            .build()
            .unwrap();

        let response = client.chat().create(request).await.unwrap();
        assert_eq!(
            response.choices[0].message.content.as_deref(),
            Some("hello from the enclave")
        );
        server.await.unwrap();
    }

    /// Multipart uploads stream through the proxy sealed and remain
    /// replayable across key rotation: the audio bytes never appear on
    /// either wire attempt, and the refreshed enclave-side receiver
    /// recovers the form fields from the retried multipart body.
    #[tokio::test]
    async fn multipart_transcription_retries_after_key_rotation() {
        let old_enclave = TestEnclave::generate();
        let new_enclave = TestEnclave::generate();
        let public_key_hex = old_enclave.public_key_hex();
        let new_public_key_hex = new_enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (_, body) = read_request(&mut socket).await;
            assert!(find_subslice(&body, b"audio-plaintext-marker").is_none());
            write_response(
                &mut socket,
                "HTTP/1.1 422 Unprocessable Entity",
                "Content-Type: application/problem+json\r\n",
                format!(
                    r#"{{"type":"{}","title":"rotate key"}}"#,
                    tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE
                )
                .as_bytes(),
            )
            .await;

            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;

            assert!(head.starts_with("POST /v1/audio/transcriptions"));
            assert!(find_subslice(&body, b"audio-plaintext-marker").is_none());

            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (plaintext, secret, enc) = new_enclave.open_request(&enc_hex, &body);
            let form = String::from_utf8_lossy(&plaintext);
            assert!(form.contains("name=\"model\""));
            assert!(form.contains("gpt-oss-120b"));
            assert!(form.contains("filename=\"sample.wav\""));
            assert!(form.contains("audio-plaintext-marker"));

            let reply =
                br#"{"text":"hello","logprobs":null,"usage":{"type":"duration","seconds":1.0}}"#;
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &[reply]);
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                &format!(
                    "Content-Type: application/json\r\nEhbp-Response-Nonce: {}\r\n",
                    hex::encode(RESPONSE_NONCE)
                ),
                &encrypted,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        client
            .secure_client()
            .ehbp_proxy()
            .unwrap()
            .set_refresher(move || {
                let key = new_public_key_hex.clone();
                async move { Ok(key) }
            });
        let request = async_openai::types::audio::CreateTranscriptionRequestArgs::default()
            .file(async_openai::types::audio::AudioInput::from_vec_u8(
                "sample.wav".to_string(),
                b"audio-plaintext-marker".to_vec(),
            ))
            .model("gpt-oss-120b")
            .build()
            .unwrap();

        let response = client.transcribe(request).await.unwrap();
        assert_eq!(response.text, "hello");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn transport_refreshes_when_generation_changes_during_factory_build() {
        use tower::Service;

        let old_enclave = TestEnclave::generate();
        let selected_enclave = TestEnclave::generate();
        let refreshed_enclave = TestEnclave::generate();
        let selected_public_key_hex = selected_enclave.public_key_hex();
        let refreshed_public_key_hex = refreshed_enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (plaintext, _, _) = selected_enclave.open_request(&enc_hex, &body);
            assert_eq!(plaintext, br#"{"attempt":"test"}"#);
            write_response(
                &mut socket,
                "HTTP/1.1 422 Unprocessable Entity",
                "Content-Type: application/problem+json\r\n",
                format!(
                    r#"{{"type":"{}","title":"reject selected key"}}"#,
                    tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE
                )
                .as_bytes(),
            )
            .await;

            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (plaintext, secret, enc) = refreshed_enclave.open_request(&enc_hex, &body);
            assert_eq!(plaintext, br#"{"attempt":"test"}"#);
            let encrypted =
                encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &[b"refreshed"]);
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                &format!(
                    "Content-Type: application/json\r\nEhbp-Response-Nonce: {}\r\n",
                    hex::encode(RESPONSE_NONCE)
                ),
                &encrypted,
            )
            .await;
        });

        let proxy = EhbpProxy::new(
            &format!("http://{addr}"),
            TEST_ENCLAVE_URL.to_string(),
            &old_enclave.public_key_hex(),
        )
        .unwrap();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let refresher_calls = Arc::clone(&refreshes);
        proxy.set_refresher(move || {
            let key = refreshed_public_key_hex.clone();
            let refresher_calls = Arc::clone(&refresher_calls);
            async move {
                refresher_calls.fetch_add(1, Ordering::Relaxed);
                Ok(key)
            }
        });

        let factory_proxy = proxy.clone();
        let builds = Arc::new(AtomicUsize::new(0));
        let factory_builds = Arc::clone(&builds);
        let factory = HttpRequestFactory::new(move || {
            let proxy = factory_proxy.clone();
            let selected_public_key_hex = selected_public_key_hex.clone();
            let factory_builds = Arc::clone(&factory_builds);
            async move {
                if factory_builds.fetch_add(1, Ordering::Relaxed) == 0 {
                    tokio::task::yield_now().await;
                    proxy
                        .rekey(&selected_public_key_hex)
                        .map_err(into_openai_error)?;
                }
                reqwest::Client::new()
                    .post(format!("http://{addr}/v1/chat/completions"))
                    .body(r#"{"attempt":"test"}"#)
                    .build()
                    .map_err(OpenAIError::Reqwest)
            }
        });

        let response = EhbpTransport::new(proxy).call(factory).await.unwrap();
        assert_eq!(response.bytes().await.unwrap(), "refreshed");
        assert_eq!(refreshes.load(Ordering::Relaxed), 1);
        assert_eq!(builds.load(Ordering::Relaxed), 2);
        server.await.unwrap();
    }

    /// Streaming through the relaxed path: an encrypted SSE body split
    /// across several AEAD chunks decrypts into ordered deltas.
    #[tokio::test]
    async fn relaxed_stream_decrypts_chunked_sse_through_proxy() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, _body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (secret, enc) = enclave.export_secret(&enc_hex);

            let events = [
                "data: {\"choices\":[{\"delta\":{\"content\":\"hel\"},\"index\":0}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"index\":0}]}\n\n",
                "data: [DONE]\n\n",
            ];
            let chunks: Vec<&[u8]> = events.iter().map(|e| e.as_bytes()).collect();
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &chunks);
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                &format!(
                    "Content-Type: text/event-stream\r\nEhbp-Response-Nonce: {}\r\n",
                    hex::encode(RESPONSE_NONCE)
                ),
                &encrypted,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();
        let mut stream = client.chat_relaxed().create_stream(body).await.unwrap();

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            if let Some(delta) = chunk.unwrap().delta_content() {
                content.push_str(delta);
            }
        }
        assert_eq!(content, "hello");
        server.await.unwrap();
    }

    /// Plaintext non-success responses can originate from an intermediary
    /// and pass through for ordinary HTTP API error handling.
    #[tokio::test]
    async fn plaintext_error_responses_pass_through() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut socket).await;
            write_response(
                &mut socket,
                "HTTP/1.1 401 Unauthorized",
                "Content-Type: application/json\r\n",
                br#"{"error":{"message":"proxy rejected credentials"}}"#,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();

        let err = client.chat_relaxed().create(body).await.unwrap_err();
        match &err {
            Error::Api(OpenAIError::ApiError(api)) => {
                assert_eq!(api.status_code, reqwest::StatusCode::UNAUTHORIZED);
                assert_eq!(api.api_error.message, "proxy rejected credentials");
            }
            other => panic!("expected API error passthrough, got {other:?}"),
        }
    }

    /// A success response without a nonce on an encrypted exchange is a
    /// body-substitution attempt and must fail closed.
    #[tokio::test]
    async fn missing_nonce_on_success_fails_closed() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut socket).await;
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                "Content-Type: application/json\r\n",
                br#"{"choices":[{"message":{"content":"forged"}}]}"#,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();

        let err = client.chat_relaxed().create(body).await.unwrap_err();
        assert!(matches!(&err, Error::Ehbp(msg) if msg.contains("Ehbp-Response-Nonce")));
    }

    /// A 422 problem+json key-config reply surfaces as the typed
    /// mismatch error so callers know to re-verify and retry.
    #[tokio::test]
    async fn key_config_mismatch_surfaces_typed_error() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut socket).await;
            let problem = format!(
                r#"{{"type":"{}","title":"rotate key"}}"#,
                tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE
            );
            write_response(
                &mut socket,
                "HTTP/1.1 422 Unprocessable Entity",
                "Content-Type: application/problem+json\r\n",
                problem.as_bytes(),
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();

        let err = client.chat_relaxed().create(body).await.unwrap_err();
        assert!(matches!(&err, Error::EhbpKeyMismatch(_)));
    }

    #[tokio::test]
    async fn key_mismatch_does_not_replay_without_an_attested_key_change() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut socket).await;
            let problem = format!(
                r#"{{"type":"{}","title":"rotate key"}}"#,
                tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE
            );
            write_response(
                &mut socket,
                "HTTP/1.1 422 Unprocessable Entity",
                "Content-Type: application/problem+json\r\n",
                problem.as_bytes(),
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &public_key_hex,
        );
        let proxy = client.secure_client().ehbp_proxy().unwrap().clone();
        proxy.set_refresher(move || {
            let key = public_key_hex.clone();
            async move { Ok(key) }
        });
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();

        let err = client.chat_relaxed().create(body).await.unwrap_err();
        assert!(
            matches!(&err, Error::EhbpKeyMismatch(message) if message.contains("previously rejected"))
        );
        assert!(!proxy.is_active());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unusable_refreshed_key_revokes_the_channel() {
        let enclave = TestEnclave::generate();
        let proxy = EhbpProxy::new(
            "http://127.0.0.1:9",
            TEST_ENCLAVE_URL.to_string(),
            &enclave.public_key_hex(),
        )
        .unwrap();
        let generation = proxy.generation();
        proxy.set_refresher(|| async { Ok("not-a-valid-hpke-key".to_string()) });

        let err = proxy.refresh_after_mismatch(generation).await.unwrap_err();

        assert!(matches!(err, Error::Ehbp(_)));
        assert!(!proxy.is_active());
    }

    /// Trust changes propagate through the shared channel to transports
    /// already baked into the client: revoking fails every request
    /// closed before it touches the network, and re-keying makes the
    /// same client seal follow-up requests to the new enclave key.
    #[tokio::test]
    async fn revoke_and_rekey_propagate_to_existing_transports() {
        let old_enclave = TestEnclave::generate();
        let new_enclave = TestEnclave::generate();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let new_public_key_hex = new_enclave.public_key_hex();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            // Only the freshly installed key can open the request.
            let (plaintext, secret, enc) = new_enclave.open_request(&enc_hex, &body);
            let request: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(request["model"], "gpt-oss-120b");

            let reply = serde_json::to_vec(&json!({
                "choices": [{"message": {"role": "assistant", "content": "rekeyed"}, "index": 0}]
            }))
            .unwrap();
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &[&reply]);
            write_response(
                &mut socket,
                "HTTP/1.1 200 OK",
                &format!(
                    "Content-Type: application/json\r\nEhbp-Response-Nonce: {}\r\n",
                    hex::encode(RESPONSE_NONCE)
                ),
                &encrypted,
            )
            .await;
        });

        let client = Client::test_client_with_ehbp(
            format!("http://{addr}"),
            TEST_ENCLAVE_URL,
            &old_enclave.public_key_hex(),
        );
        let body = client
            .chat_relaxed()
            .request()
            .model("gpt-oss-120b")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();

        let proxy = client.secure_client().ehbp_proxy().unwrap().clone();
        proxy.revoke();
        let err = client
            .chat_relaxed()
            .create(body.clone())
            .await
            .unwrap_err();
        assert!(matches!(&err, Error::Ehbp(msg) if msg.contains("revoked")));

        proxy.rekey(&new_public_key_hex).unwrap();
        let response = client.chat_relaxed().create(body).await.unwrap();
        assert_eq!(response.content(), Some("rekeyed"));
        server.await.unwrap();
    }
}
