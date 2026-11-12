//! The TLS mode against a local TLS server on loopback, whose certificates
//! come from a certificate authority that only these tests trust.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Method, Request, Response, StatusCode, Url};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{HandshakeKind, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::{TlsMode, leaf_fingerprint, provider};
use crate::error::ErrorKind;
use crate::internal::enclave::Enclave;
use crate::internal::testing::{Record, Script, Step, tokio_clock};
use crate::internal::transport::{Failure, KeyFailure, Mode, RoundTrip, Transport};

const CA: &[u8] = include_bytes!("tls_testdata/ca.pem");
const KEY_A: &[u8] = include_bytes!("tls_testdata/key_a.pem");
const KEY_B: &[u8] = include_bytes!("tls_testdata/key_b.pem");
/// Key A, for 127.0.0.1, under the trusted authority.
const LEAF_A: &[u8] = include_bytes!("tls_testdata/leaf_a.pem");
/// Key B, for 127.0.0.1, under the trusted authority.
const LEAF_B: &[u8] = include_bytes!("tls_testdata/leaf_b.pem");
/// Key A, for 127.0.0.1, under an authority that nothing trusts.
const LEAF_A_OTHER_CA: &[u8] = include_bytes!("tls_testdata/leaf_a_other_ca.pem");
/// Key A, under the trusted authority, for another name.
const LEAF_A_WRONG_NAME: &[u8] = include_bytes!("tls_testdata/leaf_a_wrong_name.pem");
/// Key A, for 127.0.0.1, under the trusted authority, expired in 2020.
const LEAF_A_EXPIRED: &[u8] = include_bytes!("tls_testdata/leaf_a_expired.pem");

const HOUR: Duration = Duration::from_secs(3600);

fn certificate(pem: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem).unwrap()
}

fn fingerprint(pem: &[u8]) -> String {
    leaf_fingerprint(&certificate(pem)).unwrap()
}

fn mode() -> TlsMode {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(CA)).unwrap();
    TlsMode::with_roots(roots)
}

/// What the local server answers to one request.
#[derive(Clone)]
struct Reply {
    status: &'static str,
    headers: &'static str,
    close: bool,
}

const OK: Reply = Reply {
    status: "200 OK",
    headers: "",
    close: false,
};

/// A local TLS server that records what it saw.
struct Server {
    port: u16,
    /// TCP connections accepted.
    accepted: Arc<AtomicUsize>,
    /// The kind of each completed TLS handshake.
    handshakes: Arc<Mutex<Vec<Option<HandshakeKind>>>>,
    /// The request line of each request received.
    requests: Arc<Mutex<Vec<String>>>,
    /// Connections that the client closed.
    closed: Arc<AtomicUsize>,
}

impl Server {
    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("https://127.0.0.1:{}{path}", self.port)).unwrap()
    }
    fn get(&self, path: &str) -> Request {
        Request::new(Method::GET, self.url(path))
    }
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
    fn handshakes(&self) -> Vec<Option<HandshakeKind>> {
        self.handshakes.lock().unwrap().clone()
    }
}

/// A server that presents `leaf` with `key` and answers every request with
/// `reply`. The response body is the request's path.
async fn serve(leaf: &[u8], key: &[u8], reply: Reply) -> Server {
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate(leaf)],
            PrivateKeyDer::from_pem_slice(key).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = Server {
        port: listener.local_addr().unwrap().port(),
        accepted: Arc::default(),
        handshakes: Arc::default(),
        requests: Arc::default(),
        closed: Arc::default(),
    };
    let (accepted, handshakes, requests, closed) = (
        Arc::clone(&server.accepted),
        Arc::clone(&server.handshakes),
        Arc::clone(&server.requests),
        Arc::clone(&server.closed),
    );
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            accepted.fetch_add(1, Ordering::SeqCst);
            let (acceptor, reply) = (acceptor.clone(), reply.clone());
            let (handshakes, requests, closed) = (
                Arc::clone(&handshakes),
                Arc::clone(&requests),
                Arc::clone(&closed),
            );
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                handshakes
                    .lock()
                    .unwrap()
                    .push(stream.get_ref().1.handshake_kind());
                loop {
                    let mut head = Vec::new();
                    let mut buffer = [0u8; 4096];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => {
                                closed.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                            Ok(n) => head.extend_from_slice(&buffer[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let line = head.lines().next().unwrap_or_default().to_owned();
                    let path = line.split(' ').nth(1).unwrap_or_default().to_owned();
                    requests.lock().unwrap().push(line);
                    let connection = if reply.close {
                        "connection: close\r\n"
                    } else {
                        ""
                    };
                    let response = format!(
                        "HTTP/1.1 {}\r\n{}{connection}content-length: {}\r\n\r\n{path}",
                        reply.status,
                        reply.headers,
                        path.len()
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    if reply.close {
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
            });
        }
    });
    server
}

fn evidence(name: &'static str, pinned_leaf: &[u8]) -> Record {
    Record {
        name,
        tls: Some(fingerprint(pinned_leaf)),
        hpke: None,
        expires: Some((tokio_clock())() + HOUR),
    }
}

/// A binding pinned to the key of `pinned_leaf`.
fn bound_to(pinned_leaf: &[u8]) -> Arc<dyn RoundTrip> {
    mode().bind(&evidence("pinned", pinned_leaf)).unwrap()
}

/// The longest that a test waits for the local server, on real time. A
/// request that hangs fails its test instead of stalling the run.
const PATIENCE: Duration = Duration::from_secs(10);

/// Sending with a limit.
trait Guarded {
    async fn send(&self, request: Request) -> Result<Response, Failure>;
}

impl<T: RoundTrip + ?Sized> Guarded for T {
    async fn send(&self, request: Request) -> Result<Response, Failure> {
        tokio::time::timeout(PATIENCE, self.round_trip(request))
            .await
            .expect("the request neither succeeded nor failed in time")
    }
}

/// Reading a body with a limit.
trait GuardedBody {
    async fn body(self) -> reqwest::Result<String>;
}

impl GuardedBody for Response {
    async fn body(self) -> reqwest::Result<String> {
        tokio::time::timeout(PATIENCE, self.text())
            .await
            .expect("the body did not arrive in time")
    }
}

/// Waits until `condition` holds; fails the test if it never does.
async fn eventually(condition: impl Fn() -> bool, what: &str) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never happened: {what}");
}

// What the pin is.

#[test]
fn the_fingerprint_is_the_one_that_the_verifier_crate_computes() {
    for leaf in [
        LEAF_A,
        LEAF_B,
        LEAF_A_OTHER_CA,
        LEAF_A_WRONG_NAME,
        LEAF_A_EXPIRED,
    ] {
        let certificate = certificate(leaf);
        assert_eq!(
            leaf_fingerprint(&certificate).unwrap(),
            crate::verifier::cert_pubkey_fp(&certificate).unwrap()
        );
    }
    // The fixtures hold two keys.
    assert_eq!(fingerprint(LEAF_A), fingerprint(LEAF_A_EXPIRED));
    assert_eq!(fingerprint(LEAF_A), fingerprint(LEAF_A_WRONG_NAME));
    assert_eq!(fingerprint(LEAF_A), fingerprint(LEAF_A_OTHER_CA));
    assert_ne!(fingerprint(LEAF_A), fingerprint(LEAF_B));
    assert_eq!(fingerprint(LEAF_A).len(), 64);
}

#[test]
fn the_authority_that_issued_the_leaf_does_not_carry_the_leafs_key() {
    assert!(leaf_fingerprint(&certificate(CA)).is_err() || fingerprint(CA) != fingerprint(LEAF_A));
}

// Binding.

#[test]
fn evidence_without_a_tls_key_cannot_be_bound() {
    let mut keyless = evidence("keyless", LEAF_A);
    keyless.tls = None;
    let error = mode().bind(&keyless).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(
        error.to_string().contains("endorses no \"tls\" key"),
        "{error}"
    );
}

#[test]
fn an_empty_fingerprint_cannot_be_bound() {
    let mut empty = evidence("empty", LEAF_A);
    empty.tls = Some(String::new());
    let error = mode().bind(&empty).err().unwrap();
    assert_eq!(error.kind(), ErrorKind::Configuration);
}

// Requests that the mode refuses before anything else.

#[test]
fn a_plaintext_request_and_a_host_header_are_refused_before_any_io() {
    let mode = mode();
    let validate = |request: &Request| Mode::<Record>::validate_request(&mode, request);

    let https = Request::new(
        Method::POST,
        Url::parse("https://enclave.example.com/v1").unwrap(),
    );
    assert!(validate(&https).is_ok());

    for url in [
        "http://enclave.example.com/",
        "http://127.0.0.1/",
        "ws://enclave.example.com/",
    ] {
        let plaintext = Request::new(Method::GET, Url::parse(url).unwrap());
        let error = validate(&plaintext).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Configuration, "{url}");
        assert!(
            error.to_string().contains("requires an HTTPS request"),
            "{error}"
        );
    }

    let mut with_host = Request::new(
        Method::GET,
        Url::parse("https://enclave.example.com/").unwrap(),
    );
    with_host
        .headers_mut()
        .insert("host", HeaderValue::from_static("other.example.com"));
    let error = validate(&with_host).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Configuration);
    assert!(error.to_string().contains("Host header"), "{error}");
}

#[tokio::test]
async fn a_binding_sends_no_plaintext_request_even_when_asked_directly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let request = Request::new(
        Method::GET,
        Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
    );
    let failure = bound_to(LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.key, KeyFailure::None);
    // Nothing connected.
    let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
    assert!(accepted.is_err());
}

// The certificate checks.

#[tokio::test]
async fn a_server_that_holds_the_attested_key_is_reached() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    let response = bound_to(LEAF_A)
        .send(server.get("/v1/models"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body().await.unwrap(), "/v1/models");
    assert_eq!(server.requests(), ["GET /v1/models HTTP/1.1"]);
}

#[tokio::test]
async fn a_valid_certificate_for_the_right_name_with_another_key_is_refused_as_a_key_failure() {
    // The server's certificate passes every standard check; only the pin
    // tells it apart.
    let server = serve(LEAF_B, KEY_B, OK).await;
    let failure = bound_to(LEAF_A)
        .send(server.get("/secret"))
        .await
        .unwrap_err();
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    assert!(
        failure
            .error
            .to_string()
            .contains("does not carry the attested key"),
        "{}",
        failure.error
    );
    assert!(std::error::Error::source(&failure.error).is_some());
    // The handshake failed, so no request was sent.
    assert!(server.requests().is_empty());

    // The same server is reached by a binding to its own key.
    assert!(bound_to(LEAF_B).send(server.get("/")).await.is_ok());
}

#[tokio::test]
async fn the_attested_key_does_not_excuse_a_certificate_that_fails_the_standard_checks() {
    for (leaf, why) in [
        (LEAF_A_OTHER_CA, "UnknownIssuer"),
        (LEAF_A_WRONG_NAME, "NotValidForName"),
        (LEAF_A_EXPIRED, "Expired"),
    ] {
        let server = serve(leaf, KEY_A, OK).await;
        // The pin matches: the server does hold key A.
        let failure = bound_to(leaf)
            .send(server.get("/secret"))
            .await
            .unwrap_err();
        assert_eq!(failure.error.kind(), ErrorKind::Attestation, "{why}");
        assert_eq!(failure.key, KeyFailure::PeerLacksKey, "{why}");
        assert!(failure.error.to_string().contains(why), "{}", failure.error);
        assert!(server.requests().is_empty(), "{why}");
    }
}

#[tokio::test]
async fn a_fingerprint_that_is_not_a_digest_matches_no_server() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    for fingerprint in [
        "not-a-fingerprint".to_owned(),
        fingerprint(LEAF_A).to_uppercase(),
    ] {
        let mut evidence = evidence("odd", LEAF_A);
        evidence.tls = Some(fingerprint);
        let bound = mode().bind(&evidence).unwrap();
        let failure = bound.send(server.get("/")).await.unwrap_err();
        assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_connection_failure_is_a_network_error_and_not_a_key_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let request = Request::new(
        Method::GET,
        Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap(),
    );
    let failure = bound_to(LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    assert_eq!(failure.key, KeyFailure::None);
}

#[tokio::test]
async fn a_request_that_exceeds_its_own_timeout_is_a_network_timeout() {
    // A listener that accepts and then says nothing.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut request = Request::new(
        Method::GET,
        Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap(),
    );
    *request.timeout_mut() = Some(Duration::from_millis(100));
    let failure = bound_to(LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    assert!(failure.error.is_timeout());
    assert_eq!(failure.key, KeyFailure::None);
    drop(listener);
}

// Connections.

#[tokio::test]
async fn sequential_requests_on_one_binding_share_one_connection() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    let bound = bound_to(LEAF_A);
    for i in 0..8 {
        let response = bound.send(server.get(&format!("/{i}"))).await.unwrap();
        // The body is read to the end, which returns the connection to
        // the pool.
        assert_eq!(response.body().await.unwrap(), format!("/{i}"));
    }
    assert_eq!(server.requests().len(), 8);
    assert_eq!(server.accepted(), 1);
    assert_eq!(server.handshakes(), [Some(HandshakeKind::Full)]);
}

#[tokio::test]
async fn every_new_connection_makes_a_full_handshake_and_none_is_resumed() {
    // The server closes after each response, so each request needs a new
    // connection; it offers session resumption, as servers do.
    let server = serve(LEAF_A, KEY_A, Reply { close: true, ..OK }).await;
    let bound = bound_to(LEAF_A);
    for _ in 0..4 {
        let response = bound.send(server.get("/")).await.unwrap();
        response.body().await.unwrap();
    }
    assert_eq!(server.accepted(), 4);
    assert_eq!(server.handshakes(), [Some(HandshakeKind::Full); 4]);
}

#[tokio::test]
async fn a_redirect_is_returned_to_the_caller_and_not_followed() {
    let server = serve(
        LEAF_A,
        KEY_A,
        Reply {
            status: "302 Found",
            headers: "location: /elsewhere\r\n",
            close: false,
        },
    )
    .await;
    let response = bound_to(LEAF_A).send(server.get("/start")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/elsewhere")
    );
    response.body().await.unwrap();
    assert_eq!(server.requests(), ["GET /start HTTP/1.1"]);
}

#[tokio::test]
async fn a_new_binding_opens_its_own_connection_and_the_old_one_is_closed_with_its_binding() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    let mode = mode();

    let first = mode.bind(&evidence("first", LEAF_A)).unwrap();
    first
        .send(server.get("/1"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 1);

    // A second binding to the same key does not borrow the idle connection.
    let second = mode.bind(&evidence("second", LEAF_A)).unwrap();
    second
        .send(server.get("/2"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 2);

    // Retiring the first binding closes its idle connection.
    assert_eq!(server.closed.load(Ordering::SeqCst), 0);
    drop(first);
    eventually(
        || server.closed.load(Ordering::SeqCst) == 1,
        "the retired binding's connection closes",
    )
    .await;

    // The second binding keeps using its own.
    second
        .send(server.get("/3"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 2);
}

// With the state machine.

struct Fixture {
    script: Arc<Script>,
    transport: Transport<Record>,
}

/// A transport in the TLS mode whose verifications yield `evidence` in
/// order.
async fn transport(evidence: Vec<Record>) -> Fixture {
    let script = Script::new(evidence.into_iter().map(|e| Step::Ready(Ok(e))));
    let enclave = Enclave::from_source("127.0.0.1", script.source(), None, tokio_clock());
    let transport = Transport::connect(enclave, Arc::new(mode()), true)
        .await
        .unwrap();
    Fixture { script, transport }
}

#[tokio::test]
async fn a_key_failure_makes_the_transport_verify_again_and_the_request_then_succeeds() {
    // The enclave rotated to key B after the first verification.
    let server = serve(LEAF_B, KEY_B, OK).await;
    let f = transport(vec![evidence("before", LEAF_A), evidence("after", LEAF_B)]).await;

    let failure = f.transport.send(server.get("/secret")).await.unwrap_err();
    assert_eq!(failure.key, KeyFailure::Rejected);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    assert!(server.requests().is_empty());
    assert_eq!(f.script.calls(), 1);

    // The same request again: the enclave is verified first, and the
    // request goes out under the new key.
    let response = f.transport.send(server.get("/secret")).await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/secret");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.transport.current().name, "after");
    assert_eq!(server.requests(), ["GET /secret HTTP/1.1"]);
}

#[tokio::test]
async fn a_key_failure_that_a_new_verification_does_not_cure_fails_again_without_sending() {
    let server = serve(LEAF_B, KEY_B, OK).await;
    let f = transport(vec![evidence("first", LEAF_A), evidence("second", LEAF_A)]).await;
    for _ in 0..2 {
        let failure = f.transport.send(server.get("/secret")).await.unwrap_err();
        assert_eq!(failure.key, KeyFailure::Rejected);
    }
    assert_eq!(f.script.calls(), 2);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_new_verification_moves_requests_to_a_new_connection() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    let f = transport(vec![evidence("first", LEAF_A), evidence("second", LEAF_A)]).await;

    for path in ["/1", "/2"] {
        f.transport
            .send(server.get(path))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
    }
    assert_eq!(server.accepted(), 1);

    f.transport.reverify().await.unwrap();
    for path in ["/3", "/4"] {
        f.transport
            .send(server.get(path))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
    }
    assert_eq!(server.accepted(), 2);
    assert_eq!(server.requests().len(), 4);
    // The first binding was retired, and its connection with it.
    eventually(
        || server.closed.load(Ordering::SeqCst) == 1,
        "the replaced binding's connection closes",
    )
    .await;
}

#[tokio::test]
async fn a_response_still_being_read_survives_the_replacement_of_its_binding() {
    let server = serve(LEAF_A, KEY_A, OK).await;
    let f = transport(vec![evidence("first", LEAF_A), evidence("second", LEAF_A)]).await;

    let response = f.transport.send(server.get("/in-flight")).await.unwrap();
    f.transport.reverify().await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/in-flight");
}
