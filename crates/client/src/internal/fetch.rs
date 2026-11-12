//! Fetches raw attestation documents. It parses nothing: verification
//! belongs to the verifier.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, ClientBuilder, Url};

use crate::error::{Error, ErrorKind};
use crate::internal::sdkinfo;
use crate::internal::transport::base_url::authority_url;
use crate::verifier::NONCE_SIZE;

/// The path of an enclave's attestation endpoint.
pub(crate) const ATTESTATION_PATH: &str = "/.well-known/tinfoil-attestation";

/// The bound on one document fetch, from the request to the last byte of
/// the body.
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest attestation document that is read. A document of exactly
/// this size is accepted; one byte more is refused.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 32 << 20;

/// Where the attestation document of `host` is fetched with `nonce`:
/// `https://<host>/.well-known/tinfoil-attestation?nonce=<lowercase hex>`,
/// or, through a relay,
/// `https://<relay>/.well-known/tinfoil-attestation?nonce=<hex>&enclave=<host, query-escaped>`.
///
/// `host` and `relay` are each a host with an optional port, not a URL: a
/// value that carries a scheme, a path, a query or user information is
/// refused, and so is an empty one. The error is a configuration error,
/// and nothing has been sent.
pub(crate) fn document_url(
    host: &str,
    relay: Option<&str>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Url, Error> {
    let mut url = authority_url(host)?;
    let mut query = format!("nonce={}", lower_hex(nonce));
    if let Some(relay) = relay {
        url = authority_url(relay)?;
        query.push_str("&enclave=");
        query.push_str(&query_escape(host));
    }
    url.set_path(ATTESTATION_PATH);
    url.set_query(Some(&query));
    Ok(url)
}

/// Fetches the attestation document of `host` for `nonce` and returns the
/// response body as received.
///
/// - The request carries the `Tinfoil-SDK` and `Tinfoil-SDK-Version`
///   headers and nothing of the caller's: no credential, no cookie.
/// - It goes out on a connection of its own, never a pooled one, so that a
///   fetch after a rollout cannot land on a replica that is draining.
/// - Redirects are not followed: a `3xx` is an error status like any
///   other.
/// - The fetch ends after [`FETCH_TIMEOUT`], whatever the caller's own
///   deadline is.
/// - The body is read as a stream, and the read stops once it exceeds
///   [`MAX_DOCUMENT_BYTES`].
///
/// Every failure is a network error (a connection failure, a timeout, a
/// status above 299, an oversized body), except an invalid `host` or
/// `relay`, which is a configuration error raised before anything is sent.
///
/// Dropping the future closes the connection and leaves nothing behind.
pub(crate) async fn document(
    host: &str,
    relay: Option<&str>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, Error> {
    let url = document_url(host, relay, nonce)?;
    let client = plain_client()?;
    get_bounded(
        &client,
        url,
        MAX_DOCUMENT_BYTES,
        FETCH_TIMEOUT,
        "attestation document",
    )
    .await
}

/// A `reqwest` client for material that is not attested yet: documents,
/// the router list, the gateway catalog.
///
/// - Certificates are checked in the standard way against the root
///   certificates that are compiled in, on the `ring` provider. The
///   operating system's trust store and `SSL_CERT_FILE` are not read, so
///   the result does not depend on the machine.
/// - Only `https://` URLs are requested.
/// - Redirects are not followed, and no connection is kept for reuse.
/// - A forward proxy named by `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`
///   is used, as `reqwest` does by default. The material proves itself
///   once it is verified, so a proxy can only make the fetch fail.
pub(crate) fn plain_client() -> Result<Client, Error> {
    client_builder()?
        .https_only(true)
        .build()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
}

/// The settings that every client for unattested material shares.
fn client_builder() -> Result<ClientBuilder, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0))
}

/// Sends a `GET` for `url` with the SDK headers and returns the body.
///
/// `timeout` bounds the request and the read of the body together. A
/// status above 299 is an error. The body is refused once it exceeds
/// `limit` bytes: at once when the response declares a longer one, and
/// otherwise as soon as the bytes read pass the limit. `what` names the
/// material in the errors. Every failure is a network error.
pub(crate) async fn get_bounded(
    client: &Client,
    url: Url,
    limit: usize,
    timeout: Duration,
    what: &'static str,
) -> Result<Vec<u8>, Error> {
    let host = url.host_str().unwrap_or_default().to_owned();
    let fetch = async {
        let mut response = client
            .get(url)
            .header(sdkinfo::SDK_NAME_HEADER, sdkinfo::NAME)
            .header(sdkinfo::SDK_VERSION_HEADER, sdkinfo::VERSION)
            .send()
            .await
            .map_err(from_reqwest)?;
        let status = response.status();
        if status.as_u16() > 299 {
            return Err(Error::network(format!(
                "fetching the {what} from {host}: HTTP {status}"
            )));
        }
        let too_large = || Error::network(format!("the {what} from {host} exceeds {limit} bytes"));
        let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
        if response
            .content_length()
            .is_some_and(|length| length > limit_u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(from_reqwest)? {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    match tokio::time::timeout(timeout, fetch).await {
        Ok(result) => result,
        Err(_) => Err(Error::network(format!(
            "fetching the {what} from {host} took longer than {} seconds",
            timeout.as_secs()
        ))
        .timed_out()),
    }
}

/// A `reqwest` failure as a network error, marked when it is a timeout.
fn from_reqwest(error: reqwest::Error) -> Error {
    let timeout = error.is_timeout();
    let error = Error::wrap(ErrorKind::Network, error);
    if timeout { error.timed_out() } else { error }
}

/// `bytes` as lowercase hexadecimal, the form of the nonce in a fetch URL.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

/// `text` as the value of a query parameter: letters, digits and `-_.~`
/// stay, and every other byte becomes `%XX`.
fn query_escape(text: &str) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
            continue;
        }
        out.push('%');
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;

    const NONCE: [u8; NONCE_SIZE] = [0xab; NONCE_SIZE];

    /// A local HTTP server that answers every request with `response` and
    /// records what it received. With `response` empty it never answers.
    struct Server {
        url: Url,
        accepted: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
    }

    async fn serve(response: Vec<u8>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (count, seen) = (Arc::clone(&accepted), Arc::clone(&requests));
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let (response, seen) = (response.clone(), Arc::clone(&seen));
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    seen.lock()
                        .await
                        .push(String::from_utf8_lossy(&request).into_owned());
                    if response.is_empty() {
                        std::future::pending::<()>().await;
                    }
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let url = Url::parse(&format!(
            "http://{address}/.well-known/tinfoil-attestation?nonce=00"
        ))
        .expect("url");
        Server {
            url,
            accepted,
            requests,
        }
    }

    fn ok(body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// The production client, allowed to speak plain HTTP to the local
    /// server and kept away from any proxy of the test machine.
    fn local_client() -> Client {
        client_builder()
            .expect("builder")
            .no_proxy()
            .build()
            .expect("client")
    }

    async fn get(server: &Server, limit: usize) -> Result<Vec<u8>, Error> {
        get_bounded(
            &local_client(),
            server.url.clone(),
            limit,
            FETCH_TIMEOUT,
            "document",
        )
        .await
    }

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(lower_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(lower_hex(&[]), "");
    }

    #[test]
    fn the_document_url_carries_the_nonce_in_lowercase_hex() {
        let url = document_url("enclave.example.com", None, &NONCE).expect("url");
        assert_eq!(
            url.as_str(),
            format!(
                "https://enclave.example.com/.well-known/tinfoil-attestation?nonce={}",
                "ab".repeat(NONCE_SIZE)
            )
        );
        let url = document_url("Enclave.Example.com:8443", None, &NONCE).expect("url");
        assert_eq!(url.host_str(), Some("enclave.example.com"));
        assert_eq!(url.port(), Some(8443));
    }

    #[test]
    fn a_relay_is_asked_for_the_enclave_by_its_escaped_host() {
        let url = document_url(
            "replica-1.example.com:8443",
            Some("gateway.example.com"),
            &NONCE,
        )
        .expect("url");
        assert_eq!(
            url.as_str(),
            format!(
                "https://gateway.example.com/.well-known/tinfoil-attestation?nonce={}&enclave=replica-1.example.com%3A8443",
                "ab".repeat(NONCE_SIZE)
            )
        );
        let url = document_url(
            "[2001:db8::1]:443",
            Some("gateway.example.com:9000"),
            &NONCE,
        )
        .expect("url");
        assert_eq!(url.port(), Some(9000));
        assert!(
            url.query()
                .is_some_and(|q| q.ends_with("&enclave=%5B2001%3Adb8%3A%3A1%5D%3A443"))
        );
    }

    #[test]
    fn a_host_or_relay_that_is_not_an_authority_is_refused_before_any_io() {
        for (host, relay) in [
            ("", None),
            ("https://enclave.example.com", None),
            ("enclave.example.com/path", None),
            ("user:pw@enclave.example.com", None),
            ("enclave.example.com?x=1", None),
            ("enclave.example.com&enclave=evil.example", None),
            ("enclave.example.com", Some("")),
            ("enclave.example.com", Some("gateway.example.com/x")),
            ("enclave.example.com", Some("user@gateway.example.com")),
            ("enclave.example.com#x", Some("gateway.example.com")),
        ] {
            let error = document_url(host, relay, &NONCE).expect_err(host);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{host:?} {relay:?}");
        }
    }

    #[tokio::test]
    async fn the_body_is_returned_as_received() {
        let server = serve(ok(b"{\"format\":\"x\"}")).await;
        assert_eq!(
            get(&server, 1024).await.expect("body"),
            b"{\"format\":\"x\"}"
        );
    }

    #[tokio::test]
    async fn the_request_carries_the_sdk_headers_and_no_credential() {
        let server = serve(ok(b"{}")).await;
        get(&server, 1024).await.expect("body");
        let requests = server.requests.lock().await;
        let request = requests.first().expect("one request").to_ascii_lowercase();
        assert!(request.starts_with("get /.well-known/tinfoil-attestation?nonce=00 http/1.1\r\n"));
        assert!(
            request.contains("\r\ntinfoil-sdk: tinfoil-rs\r\n"),
            "{request}"
        );
        assert!(
            request.contains(&format!(
                "\r\ntinfoil-sdk-version: {}\r\n",
                sdkinfo::VERSION
            )),
            "{request}"
        );
        for header in ["authorization:", "cookie:", "proxy-authorization:"] {
            assert!(!request.contains(header), "{request}");
        }
    }

    #[tokio::test]
    async fn a_status_above_299_is_a_network_error() {
        for status in [
            "300 Multiple Choices",
            "404 Not Found",
            "429 Too Many Requests",
            "503 Service Unavailable",
        ] {
            let response =
                format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}");
            let server = serve(response.into_bytes()).await;
            let error = get(&server, 1024).await.expect_err(status);
            assert_eq!(error.kind(), ErrorKind::Network, "{status}");
            assert!(!error.is_timeout());
            assert!(error.to_string().contains(status), "{error}");
        }
    }

    #[tokio::test]
    async fn any_2xx_status_is_accepted() {
        let server = serve(b"HTTP/1.1 203 Non-Authoritative Information\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".to_vec()).await;
        assert_eq!(get(&server, 1024).await.expect("body"), b"{}");
    }

    #[tokio::test]
    async fn a_redirect_is_an_error_and_is_not_followed() {
        let target = serve(ok(b"{}")).await;
        let response = format!(
            "HTTP/1.1 302 Found\r\nlocation: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            target.url
        );
        let server = serve(response.into_bytes()).await;
        let error = get(&server, 1024).await.expect_err("a redirect");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.to_string().contains("302"), "{error}");
        assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_body_of_exactly_the_limit_is_accepted_and_one_byte_more_is_refused() {
        let server = serve(ok(&[b'a'; 64])).await;
        assert_eq!(get(&server, 64).await.expect("at the limit").len(), 64);
        let error = get(&server, 63).await.expect_err("over the limit");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.to_string().contains("exceeds 63 bytes"), "{error}");
    }

    #[tokio::test]
    async fn a_body_without_a_declared_length_is_bounded_while_it_is_read() {
        let mut response = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&[b'a'; 4096]);
        let server = serve(response).await;
        assert_eq!(get(&server, 4096).await.expect("at the limit").len(), 4096);
        let error = get(&server, 4095).await.expect_err("over the limit");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.to_string().contains("exceeds 4095 bytes"), "{error}");
    }

    #[tokio::test]
    async fn a_declared_length_over_the_limit_is_refused_without_reading_the_body() {
        // The server declares far more than it ever sends.
        let server = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 1000000\r\n\r\n".to_vec()).await;
        let error = get(&server, 1024).await.expect_err("over the limit");
        assert!(error.to_string().contains("exceeds 1024 bytes"), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_answers_is_a_timeout_after_thirty_seconds() {
        let server = serve(Vec::new()).await;
        let started = tokio::time::Instant::now();
        let error = get(&server, 1024).await.expect_err("no answer");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.is_timeout());
        assert_eq!(started.elapsed(), FETCH_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_stalls_is_a_timeout_too() {
        let server = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc".to_vec()).await;
        let error = get(&server, 1024).await.expect_err("a stalled body");
        assert!(error.is_timeout(), "{error}");
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_network_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let url = Url::parse(&format!("http://{address}/")).expect("url");
        let error = get_bounded(&local_client(), url, 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("nothing listens");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(std::error::Error::source(&error).is_some());
    }

    #[tokio::test]
    async fn each_fetch_opens_a_connection_of_its_own() {
        let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}".to_vec();
        let server = serve(response).await;
        let client = local_client();
        for _ in 0..3 {
            get_bounded(&client, server.url.clone(), 1024, FETCH_TIMEOUT, "document")
                .await
                .expect("body");
        }
        assert_eq!(server.accepted.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn the_client_for_unattested_material_refuses_plain_http() {
        let server = serve(ok(b"{}")).await;
        let client = plain_client().expect("client");
        let error = get_bounded(&client, server.url.clone(), 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("plain HTTP");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
    }
}
