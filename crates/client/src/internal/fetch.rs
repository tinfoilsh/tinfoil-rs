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

/// How many requests one fetch of unattested material makes at most: the
/// first, and one for each redirect that it follows.
pub(crate) const MAX_REQUESTS: usize = 10;

/// Where the attestation document of `host` is fetched with `nonce`:
/// `https://<host>/.well-known/tinfoil-attestation?nonce=<lowercase hex>`.
///
/// `host` is a host with an optional port, not a URL: a value that carries
/// a scheme, a path, a query or user information is refused, and so is an
/// empty one. The error is a configuration error, and nothing has been
/// sent.
pub(crate) fn document_url(host: &str, nonce: &[u8; NONCE_SIZE]) -> Result<Url, Error> {
    let mut url = authority_url(host)?;
    url.set_path(ATTESTATION_PATH);
    url.set_query(Some(&format!("nonce={}", lower_hex(nonce))));
    Ok(url)
}

/// Fetches the attestation document of `host` for `nonce` and returns the
/// response body as received.
///
/// - The request carries the `Tinfoil-SDK` and `Tinfoil-SDK-Version`
///   headers and nothing of the caller's: no credential, no cookie.
/// - It goes out on a connection of its own, never a pooled one, so that a
///   fetch after a rollout cannot land on a replica that is draining.
/// - Redirects are followed, to `https://` URLs only and for at most
///   [`MAX_REQUESTS`] requests in all. The document proves itself once it
///   is verified, so a redirect cannot make an untrusted document pass; it
///   can only fail the fetch.
/// - The fetch ends after [`FETCH_TIMEOUT`], redirects included, whatever
///   the caller's own deadline is.
/// - The body of the final response is read as a stream, and the read
///   stops once it exceeds [`MAX_DOCUMENT_BYTES`].
///
/// Every failure is a network error (a connection failure, a timeout, a
/// status above 299, an oversized body), except an invalid `host`, which
/// is a configuration error raised before anything is sent.
///
/// Dropping the future closes the connection and leaves nothing behind.
pub(crate) async fn document(host: &str, nonce: &[u8; NONCE_SIZE]) -> Result<Vec<u8>, Error> {
    document_through(host, nonce, None).await
}

/// [`document`], with `proxy` in place of the environment's proxy settings
/// when there is one. Only tests pass one.
async fn document_through(
    host: &str,
    nonce: &[u8; NONCE_SIZE],
    proxy: Option<reqwest::Proxy>,
) -> Result<Vec<u8>, Error> {
    let url = document_url(host, nonce)?;
    let client = client_for(&url, true, proxy)?;
    get_bounded(
        &client,
        url,
        MAX_DOCUMENT_BYTES,
        FETCH_TIMEOUT,
        "attestation document",
    )
    .await
}

/// A `reqwest` client for material that is not attested yet: documents
/// and the router list.
///
/// - Certificates are checked in the standard way against the root
///   certificates that are compiled in, on the `ring` provider. The
///   operating system's trust store and `SSL_CERT_FILE` are not read, so
///   the result does not depend on the machine.
/// - Only `https://` URLs are requested.
/// - Redirects are followed under the rule of [`redirect_policy`], and no
///   connection is kept for reuse.
/// - A forward proxy named by `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`
///   is used, as `reqwest` does by default. The material proves itself
///   once it is verified, so a proxy can only make the fetch fail.
///
/// `reqwest` applies the environment's proxy to every host that `NO_PROXY`
/// does not name, a loopback host included. A request whose URL is known
/// takes its client from [`plain_client_for`], which keeps a loopback host
/// away from the proxy.
#[cfg(test)]
pub(crate) fn plain_client() -> Result<Client, Error> {
    client_builder(true)?
        .https_only(true)
        .build()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
}

/// The client of [`plain_client`] for a fetch that starts at `url`: when
/// [`never_proxied`] holds for `url`, the client connects directly whatever
/// the environment says. A redirect cannot leave the kind of host that the
/// client was chosen for (see [`redirect_policy`]).
pub(crate) fn plain_client_for(url: &Url) -> Result<Client, Error> {
    client_for(url, true, None)
}

/// [`plain_client_for`], with the rule of [`redirect_policy`] that
/// `https_only` selects, and with `proxy` in place of the environment's
/// proxy settings when there is one. Only tests pass the last two.
fn client_for(url: &Url, https_only: bool, proxy: Option<reqwest::Proxy>) -> Result<Client, Error> {
    let builder = client_builder(https_only)?.https_only(https_only);
    route(builder, never_proxied(url), proxy)
        .build()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
}

/// `builder` with its proxy settings: none when `direct`, otherwise
/// `proxy`, and without one the environment's, which is `reqwest`'s
/// default.
pub(crate) fn route(
    builder: ClientBuilder,
    direct: bool,
    proxy: Option<reqwest::Proxy>,
) -> ClientBuilder {
    match (direct, proxy) {
        (true, _) => builder.no_proxy(),
        (false, Some(proxy)) => builder.proxy(proxy),
        (false, None) => builder,
    }
}

/// Whether a request to `url` never goes through a proxy from the
/// environment: its host is the name `localhost`, or a loopback IP address
/// (`127.0.0.0/8`, `::1`, or an IPv4 loopback address mapped into IPv6).
///
/// The name is matched whole: a subdomain of `localhost` and `localhost.`
/// with a trailing dot are proxied like any other name. A URL holds its
/// host in lowercase, so the spelling of the caller does not matter.
pub(crate) fn never_proxied(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(name)) => name == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        None => false,
    }
}

/// The redirect rule for unattested material. A redirect is followed
/// unless:
///
/// - its target is not an `https://` URL, when `https_only` is set, as it
///   always is outside this module's own tests: a redirect never moves a
///   fetch to plaintext;
/// - it leads from a host that is [`never_proxied`] to one that is not, or
///   the other way: the client was built for one kind, with or without
///   the environment's proxy;
/// - [`MAX_REQUESTS`] requests have already been made in the chain.
///
/// A redirect that is not followed fails the fetch. The target may be on
/// another host. Its URL is the `Location` as the server gave it, resolved
/// against the request's URL; nothing of the request's query is carried
/// over unless the server repeats it.
fn redirect_policy(https_only: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if https_only && attempt.url().scheme() != "https" {
            attempt.error("refusing a redirect to a URL that is not HTTPS")
        } else if attempt
            .previous()
            .last()
            .is_some_and(|from| never_proxied(from) != never_proxied(attempt.url()))
        {
            attempt.error("refusing a redirect between a loopback host and another host")
        } else if attempt.previous().len() >= MAX_REQUESTS {
            attempt.error("stopped after too many redirects")
        } else {
            attempt.follow()
        }
    })
}

/// The settings that every client for unattested material shares.
/// `https_only` is that of [`redirect_policy`].
fn client_builder(https_only: bool) -> Result<ClientBuilder, Error> {
    Ok(tls_builder()?
        .redirect(redirect_policy(https_only))
        .pool_max_idle_per_host(0))
}

/// A client builder with the certificate checks that every client of this
/// crate starts from: the standard checks against the root certificates
/// that are compiled in, on the `ring` provider. Its connections offer the
/// protocols of [`alpn_protocols`].
pub(crate) fn tls_builder() -> Result<ClientBuilder, Error> {
    tls_builder_with(compiled_in_roots())
}

/// [`tls_builder`] with `roots` as the root certificates. Only tests pass
/// other roots than the compiled-in ones.
pub(crate) fn tls_builder_with(roots: rustls::RootCertStore) -> Result<ClientBuilder, Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = alpn_protocols();
    Ok(Client::builder().tls_backend_preconfigured(tls))
}

/// The protocols that every TLS connection of this crate offers, in order
/// of preference: HTTP/2, then HTTP/1.1. A TLS configuration that is handed
/// to `reqwest` ready-made is used as it is, so each one sets these itself.
pub(crate) fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// The root certificates that are compiled into the crate: the only ones
/// that any client of this crate trusts.
pub(crate) fn compiled_in_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Sends a `GET` for `url` with the SDK headers and returns the body.
///
/// `timeout` bounds the whole fetch: every request of a redirect chain and
/// the read of the final body together. A final status above 299 is an
/// error, a redirect that was not followed included. The body is refused once it exceeds
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    use super::*;

    const NONCE: [u8; NONCE_SIZE] = [0xab; NONCE_SIZE];

    /// What the local server does with one request.
    enum Reply {
        /// Send these bytes and close.
        Send(Vec<u8>),
        /// Send these bytes after this much of Tokio's time.
        SendAfter(Duration, Vec<u8>),
        /// Never answer.
        Hang,
    }

    /// A local HTTP server that records what it received.
    struct Server {
        url: Url,
        accepted: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<String>>>,
    }

    /// A server that answers every request with `response`, or never
    /// answers when `response` is empty.
    async fn serve(response: Vec<u8>) -> Server {
        serve_with(move |_| {
            if response.is_empty() {
                Reply::Hang
            } else {
                Reply::Send(response.clone())
            }
        })
        .await
    }

    /// A server that answers each request with what `handler` returns for
    /// the request's path and query.
    async fn serve_with(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (count, seen) = (Arc::clone(&accepted), Arc::clone(&requests));
        let handler = Arc::new(handler);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let (handler, seen) = (Arc::clone(&handler), Arc::clone(&seen));
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request).into_owned();
                    let target = request.split(' ').nth(1).unwrap_or_default().to_owned();
                    seen.lock().await.push(request);
                    let response = match handler(&target) {
                        Reply::Send(response) => response,
                        Reply::SendAfter(delay, response) => {
                            tokio::time::sleep(delay).await;
                            response
                        }
                        Reply::Hang => std::future::pending().await,
                    };
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

    fn redirect(location: &str) -> Vec<u8> {
        format!("HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .into_bytes()
    }

    /// A server whose `/hop/<n>` redirects to `/hop/<n - 1>` after `delay`,
    /// down to `/hop/0`, which answers with `body`. Its URL is the first
    /// hop of a chain with `redirects` redirects.
    async fn chain(redirects: usize, delay: Duration, body: &'static [u8]) -> Server {
        let mut server = serve_with(move |target| {
            let hop: usize = target
                .strip_prefix("/hop/")
                .and_then(|n| n.parse().ok())
                .expect("a hop");
            let response = if hop == 0 {
                ok(body)
            } else {
                redirect(&format!("/hop/{}", hop - 1))
            };
            Reply::SendAfter(delay, response)
        })
        .await;
        server.url = server.url.join(&format!("/hop/{redirects}")).expect("url");
        server
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
        client_builder(false)
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

    #[tokio::test]
    async fn a_fetch_offers_http2_then_http1() {
        use crate::internal::transport::tls::testing::made::{KEY_A, LEAF_A};
        use crate::internal::transport::tls::testing::{Handler, Protocols, full, serve};

        let handler: Handler = Arc::new(|_| Box::pin(async { hyper::Response::new(full("{}")) }));
        let server = serve(&LEAF_A, &KEY_A, Protocols::Both, handler).await;
        let url = Url::parse(&format!("https://127.0.0.1:{}/", server.port)).expect("url");
        // The client trusts only the compiled-in roots, so the handshake
        // with the local server fails; what it offered is on record by
        // then.
        let client = plain_client_for(&url).expect("client");
        let error = get_bounded(&client, url, 1024, Duration::from_secs(10), "document")
            .await
            .expect_err("an untrusted server");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(server.offered(), [["h2", "http/1.1"]]);
    }

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(lower_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(lower_hex(&[]), "");
    }

    #[test]
    fn the_document_url_carries_the_nonce_in_lowercase_hex() {
        let url = document_url("enclave.example.com", &NONCE).expect("url");
        assert_eq!(
            url.as_str(),
            format!(
                "https://enclave.example.com/.well-known/tinfoil-attestation?nonce={}",
                "ab".repeat(NONCE_SIZE)
            )
        );
        let url = document_url("Enclave.Example.com:8443", &NONCE).expect("url");
        assert_eq!(url.host_str(), Some("enclave.example.com"));
        assert_eq!(url.port(), Some(8443));
    }

    #[test]
    fn a_host_that_is_not_an_authority_is_refused_before_any_io() {
        for host in [
            "",
            "https://enclave.example.com",
            "enclave.example.com/path",
            "user:pw@enclave.example.com",
            "enclave.example.com?x=1",
            "enclave.example.com&enclave=evil.example",
            "enclave.example.com#x",
        ] {
            let error = document_url(host, &NONCE).expect_err(host);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{host:?}");
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
            "304 Not Modified",
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
    async fn redirects_are_followed_while_the_chain_stays_within_ten_requests() {
        let server = chain(MAX_REQUESTS - 1, Duration::ZERO, b"{\"hops\":9}").await;
        assert_eq!(get(&server, 1024).await.expect("body"), b"{\"hops\":9}");
        assert_eq!(server.accepted.load(Ordering::SeqCst), MAX_REQUESTS);
    }

    #[tokio::test]
    async fn the_redirect_after_the_tenth_request_is_refused() {
        let server = chain(MAX_REQUESTS, Duration::ZERO, b"{}").await;
        let error = get(&server, 1024).await.expect_err("too many redirects");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(!error.is_timeout());
        // Ten requests were made, and the last hop was never asked for.
        assert_eq!(server.accepted.load(Ordering::SeqCst), MAX_REQUESTS);
        let requests = server.requests.lock().await;
        assert!(!requests.iter().any(|r| r.starts_with("GET /hop/0 ")));
    }

    #[tokio::test]
    async fn a_redirect_may_lead_to_another_host_and_keeps_the_sdk_headers() {
        let target = serve(ok(b"{\"from\":\"target\"}")).await;
        let location = target.url.to_string();
        let server = serve_with(move |_| Reply::Send(redirect(&location))).await;
        assert_eq!(
            get(&server, 1024).await.expect("body"),
            b"{\"from\":\"target\"}"
        );
        let requests = target.requests.lock().await;
        let request = requests.first().expect("one request").to_ascii_lowercase();
        assert!(
            request.contains("\r\ntinfoil-sdk: tinfoil-rs\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_redirect_target_is_the_location_as_given_without_the_requests_query() {
        let server = serve_with(|target| {
            if target.starts_with("/.well-known/") {
                Reply::Send(redirect("/moved"))
            } else {
                Reply::Send(ok(b"{}"))
            }
        })
        .await;
        get(&server, 1024).await.expect("body");
        let requests = server.requests.lock().await;
        assert!(
            requests
                .last()
                .is_some_and(|r| r.starts_with("GET /moved HTTP/1.1"))
        );
    }

    #[tokio::test]
    async fn a_redirect_to_plain_http_is_refused_and_its_target_is_not_contacted() {
        let target = serve(ok(b"{}")).await;
        let location = target.url.to_string();
        let server = serve_with(move |_| Reply::Send(redirect(&location))).await;
        // The production redirect rule, on a client that may still start
        // from the local plain-HTTP server.
        let client = client_builder(true)
            .expect("builder")
            .no_proxy()
            .build()
            .expect("client");
        let error = get_bounded(&client, server.url.clone(), 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("a downgrade");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_size_bound_applies_to_the_response_at_the_end_of_a_redirect_chain() {
        static BODY: [u8; 64] = [b'a'; 64];
        let server = chain(3, Duration::ZERO, &BODY).await;
        assert_eq!(get(&server, 64).await.expect("at the limit").len(), 64);
        let error = get(&server, 63).await.expect_err("over the limit");
        assert!(error.to_string().contains("exceeds 63 bytes"), "{error}");
    }

    #[tokio::test]
    async fn the_timeout_covers_a_whole_redirect_chain_and_not_each_request() {
        // Real time, because paused time cannot be trusted to wait for
        // socket I/O between two timers.
        let timeout = Duration::from_millis(1000);
        let client = local_client();
        let fetch =
            |server: &Server| get_bounded(&client, server.url.clone(), 1024, timeout, "document");

        // Each of the six requests takes a quarter of the bound; together
        // they take one and a half times the bound.
        let server = chain(5, Duration::from_millis(250), b"{}").await;
        let error = fetch(&server).await.expect_err("too slow in all");
        assert!(error.is_timeout(), "{error}");
        assert!(server.accepted.load(Ordering::SeqCst) > 1);

        // A chain of two quick requests fits.
        let server = chain(1, Duration::from_millis(50), b"{}").await;
        assert_eq!(fetch(&server).await.expect("body"), b"{}");
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

    /// A listener that stands for a forward proxy: it counts connections,
    /// records the first line of each request and answers `502`.
    async fn proxy() -> (reqwest::Proxy, Server) {
        let server = serve(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\n\r\n".to_vec()).await;
        let origin = server.url.origin().ascii_serialization();
        (reqwest::Proxy::all(origin).expect("proxy"), server)
    }

    #[test]
    fn only_localhost_and_loopback_addresses_are_never_proxied() {
        for (url, expected) in [
            ("https://localhost/", true),
            ("https://LOCALHOST:8443/", true),
            ("http://127.0.0.1:8080/", true),
            ("https://127.9.9.9/", true),
            ("https://[::1]/", true),
            ("https://[::ffff:127.0.0.1]/", true),
            ("https://localhost./", false),
            ("https://app.localhost/", false),
            ("https://localhost.example.com/", false),
            ("https://enclave.example.com/", false),
            ("https://10.0.0.1/", false),
            ("https://128.0.0.1/", false),
            ("https://[::2]/", false),
            ("https://[::ffff:10.0.0.1]/", false),
        ] {
            let parsed = Url::parse(url).expect("url");
            assert_eq!(never_proxied(&parsed), expected, "{url}");
        }
    }

    #[tokio::test]
    async fn a_loopback_fetch_connects_directly_whatever_the_proxy_settings() {
        let (proxy, listener) = proxy().await;
        let server = serve(ok(b"{}")).await;
        let client = client_for(&server.url, false, Some(proxy)).expect("client");
        let body = get_bounded(&client, server.url.clone(), 1024, FETCH_TIMEOUT, "document")
            .await
            .expect("fetched directly");
        assert_eq!(body, b"{}");
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_document_of_a_loopback_host_is_fetched_directly_whatever_the_proxy_settings() {
        let (proxy, listener) = proxy().await;
        // The server closes every connection, so the fetch fails once it
        // has connected; what matters is where it connected.
        let server = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let host = server.local_addr().expect("address").to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((socket, _)) = server.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        let error = document_through(&host, &NONCE, Some(proxy))
            .await
            .expect_err("no TLS");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_document_of_another_host_is_fetched_through_the_proxy() {
        let (proxy, listener) = proxy().await;
        let error = document_through("enclave.example.com", &NONCE, Some(proxy))
            .await
            .expect_err("the proxy refuses the tunnel");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 1);
        let requests = listener.requests.lock().await;
        assert!(
            requests[0].starts_with("CONNECT enclave.example.com:443 HTTP/1.1"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_fetch_from_another_host_goes_through_the_proxy() {
        let (proxy, listener) = proxy().await;
        let url = Url::parse("http://enclave.example.com/document").expect("url");
        let client = client_for(&url, false, Some(proxy)).expect("client");
        let error = get_bounded(&client, url, 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("the proxy's answer");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 1);
        let requests = listener.requests.lock().await;
        assert!(
            requests[0].starts_with("GET http://enclave.example.com/document HTTP/1.1"),
            "{requests:?}"
        );
    }

    #[tokio::test]
    async fn a_redirect_from_a_loopback_host_to_another_host_is_refused() {
        let (proxy, listener) = proxy().await;
        let server =
            serve_with(|_| Reply::Send(redirect("http://enclave.example.com/document"))).await;
        let client = client_for(&server.url, false, Some(proxy)).expect("client");
        let error = get_bounded(&client, server.url.clone(), 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("a redirect to another kind of host");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_redirect_from_another_host_to_a_loopback_host_is_refused() {
        // The proxy answers for the other host, with a redirect to a local
        // server that must not be contacted through it or at all.
        let target = serve(ok(b"{}")).await;
        let location = target.url.to_string();
        let listener = serve_with(move |_| Reply::Send(redirect(&location))).await;
        let origin = listener.url.origin().ascii_serialization();
        let proxy = reqwest::Proxy::all(origin).expect("proxy");
        let url = Url::parse("http://enclave.example.com/document").expect("url");
        let client = client_for(&url, false, Some(proxy)).expect("client");
        let error = get_bounded(&client, url, 1024, FETCH_TIMEOUT, "document")
            .await
            .expect_err("a redirect to another kind of host");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(listener.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(target.accepted.load(Ordering::SeqCst), 0);
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
