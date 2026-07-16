//! EHBP proxy transport.
//!
//! In proxy mode the SDK sends requests to a caller-operated proxy
//! instead of the enclave. Bodies are sealed with EHBP to the enclave's
//! attested HPKE key before they leave the process, so the proxy can
//! authenticate users, add its own API key, and read usage-metric
//! headers without ever seeing plaintext. The `X-Tinfoil-Enclave-Url`
//! header tells the proxy which verified enclave to forward to.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_openai::error::OpenAIError;
use async_openai::middleware::HttpRequestFactory;
use bytes::Bytes;

use crate::ehbp::{self, EhbpIdentity, ResponseContext};
use crate::error::{Error, Result};

/// Verified EHBP proxy configuration, shared by the typed async-openai
/// stack and the relaxed chat path.
#[derive(Clone)]
pub(crate) struct EhbpProxy {
    /// Proxy origin plus optional path prefix, without a trailing slash.
    base_url: String,
    /// Verified enclave URL forwarded via `X-Tinfoil-Enclave-Url`.
    enclave_url: String,
    identity: Arc<EhbpIdentity>,
    http: reqwest::Client,
}

impl EhbpProxy {
    pub(crate) fn new(
        proxy_url: &str,
        enclave_url: String,
        hpke_public_key_hex: &str,
    ) -> Result<Self> {
        crate::ensure_crypto_provider();
        let base_url = proxy_url.trim_end_matches('/').to_string();
        require_secure_proxy_url(&base_url)?;
        let identity = Arc::new(EhbpIdentity::from_public_key_hex(hpke_public_key_hex)?);
        // Redirects are disabled so a sealed body is never replayed to an
        // origin the caller didn't name.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| {
                Error::Configuration(format!("failed to build proxy HTTP client: {err}"))
            })?;
        Ok(Self {
            base_url,
            enclave_url,
            identity,
            http,
        })
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Seal a request and send it, enforcing the response side of the
    /// protocol. Encrypted exchange plus a success status requires a
    /// response nonce; plaintext error bodies pass through for
    /// diagnostics only (SPEC §5.3/§5.4).
    pub(crate) async fn send(&self, mut request: reqwest::Request) -> Result<reqwest::Response> {
        let context = self.seal_request(&mut request)?;
        let response = self.http.execute(request).await?;
        Self::open_response(response, context)
    }

    /// Seal an outbound request body in place. Returns the context needed
    /// to decrypt the response when the body was encrypted.
    ///
    /// Bodyless requests (GET etc.) pass through unencrypted per SPEC
    /// §7.4. A request with a body the SDK cannot buffer (multipart
    /// uploads) fails closed rather than silently sending plaintext
    /// through the proxy.
    fn seal_request(&self, request: &mut reqwest::Request) -> Result<Option<ResponseContext>> {
        request.headers_mut().insert(
            ehbp::ENCLAVE_URL_HEADER,
            reqwest::header::HeaderValue::from_str(&self.enclave_url)
                .map_err(|err| Error::Ehbp(format!("invalid enclave URL header: {err}")))?,
        );

        let plaintext = match request.body() {
            None => return Ok(None),
            Some(body) => body.as_bytes().ok_or_else(|| {
                Error::Ehbp(
                    "streaming request bodies cannot be sealed for the proxy; \
                     use a direct enclave connection for uploads"
                        .into(),
                )
            })?,
        };

        let Some(encrypted) = self.identity.encrypt_request_body(plaintext)? else {
            return Ok(None);
        };

        request.headers_mut().insert(
            ehbp::ENCAPSULATED_KEY_HEADER,
            reqwest::header::HeaderValue::from_str(&encrypted.encapsulated_key_hex)
                .map_err(|err| Error::Ehbp(format!("invalid encapsulated key header: {err}")))?,
        );
        // SPEC §4.1: encrypted bodies use chunked transfer encoding without
        // a Content-Length; a stream body makes reqwest do exactly that.
        request
            .headers_mut()
            .remove(reqwest::header::CONTENT_LENGTH);
        *request.body_mut() = Some(chunked_body(encrypted.body));
        Ok(Some(encrypted.context))
    }

    fn open_response(
        response: reqwest::Response,
        context: Option<ResponseContext>,
    ) -> Result<reqwest::Response> {
        let Some(context) = context else {
            return Ok(response);
        };
        if ehbp::is_encrypted_response(&response) {
            ehbp::decrypt_response(response, &context)
        } else if !response.status().is_success() {
            // Unauthenticated plaintext, surfaced only as an error body
            // (proxy auth failures, EHBP problem details).
            Ok(response)
        } else {
            Err(Error::Ehbp(
                "missing response nonce on an encrypted exchange".into(),
            ))
        }
    }
}

/// EHBP only protects request and response bodies; headers, including the
/// proxy's bearer token, ride on the transport. Cleartext HTTP is
/// therefore only acceptable toward a loopback development proxy.
fn require_secure_proxy_url(base_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|err| Error::Configuration(format!("invalid proxy URL: {err}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if loopback {
                Ok(())
            } else {
                Err(Error::Configuration(
                    "proxy URL must use https:// so authentication headers are \
                     not sent in cleartext (http:// is allowed only for loopback)"
                        .into(),
                ))
            }
        }
        other => Err(Error::Configuration(format!(
            "proxy URL must use https://, got {other}://"
        ))),
    }
}

fn chunked_body(body: Vec<u8>) -> reqwest::Body {
    reqwest::Body::wrap_stream(futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(Bytes::from(body))
    }))
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
            proxy.send(request).await.map_err(into_openai_error)
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
    use crate::ehbp::test_support::{encrypt_response_chunks, TestEnclave};
    use futures_util::StreamExt;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TEST_ENCLAVE_URL: &str = "https://enclave.test.invalid";
    const RESPONSE_NONCE: [u8; 32] = [5u8; 32];

    #[test]
    fn proxy_url_policy_rejects_cleartext_except_loopback() {
        assert!(require_secure_proxy_url("https://proxy.example.com").is_ok());
        assert!(require_secure_proxy_url("http://127.0.0.1:8080").is_ok());
        assert!(require_secure_proxy_url("http://[::1]:8080").is_ok());
        assert!(require_secure_proxy_url("http://localhost:8080").is_ok());
        assert!(matches!(
            require_secure_proxy_url("http://proxy.example.com"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            require_secure_proxy_url("ftp://proxy.example.com"),
            Err(Error::Configuration(_))
        ));
        assert!(matches!(
            require_secure_proxy_url("proxy.example.com"),
            Err(Error::Configuration(_))
        ));
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
    async fn typed_chat_completion_round_trips_through_ehbp_proxy() {
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

            assert!(head.starts_with("POST /v1/chat/completions"));
            assert_eq!(
                header_value(&head, ehbp::ENCLAVE_URL_HEADER).as_deref(),
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
            format!("http://{addr}"),
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

    /// Plaintext error bodies (proxy auth failures) pass through so the
    /// caller sees the API error instead of a decryption failure.
    #[tokio::test]
    async fn plaintext_error_responses_surface_as_api_errors() {
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
        assert!(err.is_api());
        assert!(err.to_string().contains("proxy rejected credentials"));
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
        assert!(matches!(&err, Error::Ehbp(msg) if msg.contains("missing response nonce")));
    }
}
