//! The TLS mode against a local TLS server on loopback, whose certificates
//! are made when the tests run, under a certificate authority that only
//! these tests trust.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Method, Request, Response, StatusCode, Url};
use rustls::HandshakeKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use super::{TlsMode, leaf_fingerprint};
use crate::error::{Error, ErrorKind};
use crate::internal::enclave::Enclave;
use crate::internal::testing::{Record, Script, Step, tokio_clock};
use crate::internal::transport::{Failure, KeyFailure, Mode, RoundTrip, Transport};

use crate::internal::transport::tls::testing::made::{
    CA, KEY_A, KEY_B, LEAF_A, LEAF_A_ADDRESS_ONLY, LEAF_A_EXPIRED, LEAF_A_NAMES_ONLY,
    LEAF_A_OTHER_ADDRESS, LEAF_A_OTHER_CA, LEAF_A_WRONG_NAME, LEAF_B,
};
use crate::internal::transport::tls::testing::{
    Handler, Protocols, Seen, Server, certificate, full, roots,
};

const HOUR: Duration = Duration::from_secs(3600);

fn fingerprint(der: &[u8]) -> String {
    leaf_fingerprint(&certificate(der)).unwrap()
}

fn mode() -> TlsMode {
    TlsMode::for_test(roots(), None)
}

/// What the local server answers to a request. The body of the response is
/// the request's path.
#[derive(Clone, Default)]
struct Reply {
    /// The status; 200 when zero.
    status: u16,
    headers: Vec<(&'static str, &'static str)>,
    /// Close the connection after the response.
    close: bool,
    /// Answer only once this is signalled.
    gate: Option<Arc<Notify>>,
}

fn ok() -> Reply {
    Reply::default()
}

fn respond(reply: Reply) -> Handler {
    Arc::new(move |seen: Seen| {
        let reply = reply.clone();
        Box::pin(async move {
            if let Some(gate) = &reply.gate {
                gate.notified().await;
            }
            let mut response = hyper::Response::builder().status(if reply.status == 0 {
                200
            } else {
                reply.status
            });
            for (name, value) in &reply.headers {
                response = response.header(*name, *value);
            }
            if reply.close {
                response = response.header("connection", "close");
            }
            response.body(full(seen.target)).unwrap()
        })
    })
}

/// A server for both protocols that presents `leaf` with `key`.
async fn serve(leaf: &[u8], key: &[u8], reply: Reply) -> Arc<Server> {
    serve_on(Protocols::Both, leaf, key, reply).await
}

async fn serve_on(protocols: Protocols, leaf: &[u8], key: &[u8], reply: Reply) -> Arc<Server> {
    super::testing::serve(leaf, key, protocols, respond(reply)).await
}

fn url(server: &Server, path: &str) -> Url {
    Url::parse(&format!("https://127.0.0.1:{}{path}", server.port)).unwrap()
}

fn get(server: &Server, path: &str) -> Request {
    Request::new(Method::GET, url(server, path))
}

/// A request for the server by a name that is not a loopback name, so that
/// a configured proxy applies to it. Only a proxy that connects to the
/// server on its own can deliver it.
fn get_by_name(server: &Server, path: &str) -> Request {
    let url = format!("https://enclave.test:{}{path}", server.port);
    Request::new(Method::GET, Url::parse(&url).unwrap())
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
        &LEAF_A,
        &LEAF_B,
        &LEAF_A_OTHER_CA,
        &LEAF_A_WRONG_NAME,
        &LEAF_A_EXPIRED,
    ] {
        let certificate = certificate(leaf);
        assert_eq!(
            leaf_fingerprint(&certificate).unwrap(),
            crate::verifier::cert_pubkey_fp(&certificate).unwrap()
        );
    }
    // The fixtures hold two keys.
    assert_eq!(fingerprint(&LEAF_A), fingerprint(&LEAF_A_EXPIRED));
    assert_eq!(fingerprint(&LEAF_A), fingerprint(&LEAF_A_WRONG_NAME));
    assert_eq!(fingerprint(&LEAF_A), fingerprint(&LEAF_A_OTHER_CA));
    assert_ne!(fingerprint(&LEAF_A), fingerprint(&LEAF_B));
    assert_eq!(fingerprint(&LEAF_A).len(), 64);
}

#[test]
fn the_authority_that_issued_the_leaf_does_not_carry_the_leafs_key() {
    assert!(
        leaf_fingerprint(&certificate(&CA)).is_err() || fingerprint(&CA) != fingerprint(&LEAF_A)
    );
}

// Binding.

#[test]
fn evidence_without_a_tls_key_cannot_be_bound() {
    let mut keyless = evidence("keyless", &LEAF_A);
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
    let mut empty = evidence("empty", &LEAF_A);
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
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.key, KeyFailure::None);
    // Nothing connected.
    let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
    assert!(accepted.is_err());
}

// The certificate checks.

#[tokio::test]
async fn a_server_that_holds_the_attested_key_is_reached() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let response = bound_to(&LEAF_A)
        .send(get(&server, "/v1/models"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body().await.unwrap(), "/v1/models");
    assert_eq!(server.requests(), ["GET /v1/models"]);
}

#[tokio::test]
async fn a_valid_certificate_for_the_right_name_with_another_key_is_refused_as_a_key_failure() {
    // The server's certificate passes every standard check; only the pin
    // tells it apart.
    let server = serve(&LEAF_B, &KEY_B, ok()).await;
    let failure = bound_to(&LEAF_A)
        .send(get(&server, "/secret"))
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

    // The refused connection is over, and the server knows it.
    eventually(|| server.closed() == 1, "the refused connection ends").await;
    assert_eq!(server.accepted(), 1);

    // The same server is reached by a binding to its own key.
    assert!(bound_to(&LEAF_B).send(get(&server, "/")).await.is_ok());
}

#[tokio::test]
async fn the_attested_key_does_not_excuse_a_certificate_that_fails_the_standard_checks() {
    for (leaf, why) in [
        (&LEAF_A_OTHER_CA, "UnknownIssuer"),
        (&LEAF_A_WRONG_NAME, "NotValidForName"),
        (&LEAF_A_EXPIRED, "Expired"),
    ] {
        let server = serve(leaf, &KEY_A, ok()).await;
        // The pin matches: the server does hold key A.
        let failure = bound_to(leaf)
            .send(get(&server, "/secret"))
            .await
            .unwrap_err();
        assert_eq!(failure.error.kind(), ErrorKind::Attestation, "{why}");
        assert_eq!(failure.key, KeyFailure::PeerLacksKey, "{why}");
        assert!(failure.error.to_string().contains(why), "{}", failure.error);
        assert!(server.requests().is_empty(), "{why}");
    }
}

#[tokio::test]
async fn a_server_that_speaks_tls_1_2_only_is_pinned_like_any_other() {
    // The server holds key A and offers nothing later than TLS 1.2.
    let server = serve_on(Protocols::BothOverTls12, &LEAF_A, &KEY_A, ok()).await;
    let response = bound_to(&LEAF_A)
        .send(get(&server, "/v1/models"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body().await.unwrap(), "/v1/models");
    assert_eq!(server.versions(), [Some(rustls::ProtocolVersion::TLSv1_2)]);

    // Another key under the same version: refused in the handshake, as a
    // key failure, before any request.
    let server = serve_on(Protocols::BothOverTls12, &LEAF_B, &KEY_B, ok()).await;
    let failure = bound_to(&LEAF_A)
        .send(get(&server, "/secret"))
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
    assert!(server.requests().is_empty());

    // And the standard checks still come first under that version.
    let server = serve_on(Protocols::BothOverTls12, &LEAF_A_EXPIRED, &KEY_A, ok()).await;
    let failure = bound_to(&LEAF_A_EXPIRED)
        .send(get(&server, "/secret"))
        .await
        .unwrap_err();
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert!(
        failure.error.to_string().contains("Expired"),
        "{}",
        failure.error
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_host_that_is_an_ip_address_is_checked_against_the_addresses_of_the_certificate() {
    // The requests of these tests name the server by its address.
    // A certificate for that address and for no name: reached.
    let server = serve(&LEAF_A_ADDRESS_ONLY, &KEY_A, ok()).await;
    let bound = bound_to(&LEAF_A_ADDRESS_ONLY);
    let response = bound.send(get(&server, "/by-address")).await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/by-address");
    // The same server by a name that the certificate does not carry.
    let by_name = Request::new(
        Method::GET,
        Url::parse(&format!("https://localhost:{}/by-name", server.port)).unwrap(),
    );
    let failure = bound.send(by_name).await.unwrap_err();
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert!(
        failure.error.to_string().contains("NotValidForName"),
        "{}",
        failure.error
    );
    assert_eq!(server.requests(), ["GET /by-address"]);

    // The pin matches in each case below: the server does hold key A. The
    // certificate is for another address, or carries the address only as
    // the text of a DNS name, which is not an address.
    for leaf in [&LEAF_A_OTHER_ADDRESS, &LEAF_A_NAMES_ONLY] {
        let server = serve(leaf, &KEY_A, ok()).await;
        let failure = bound_to(leaf)
            .send(get(&server, "/secret"))
            .await
            .unwrap_err();
        assert_eq!(failure.key, KeyFailure::PeerLacksKey);
        assert_eq!(failure.error.kind(), ErrorKind::Attestation);
        assert!(
            failure.error.to_string().contains("NotValidForName"),
            "{}",
            failure.error
        );
        assert!(server.requests().is_empty());
    }

    // A pin to another key refuses the address-only certificate too.
    let server = serve(&LEAF_A_ADDRESS_ONLY, &KEY_A, ok()).await;
    let failure = bound_to(&LEAF_B)
        .send(get(&server, "/secret"))
        .await
        .unwrap_err();
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert!(
        failure
            .error
            .to_string()
            .contains("does not carry the attested key"),
        "{}",
        failure.error
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_fingerprint_that_is_not_a_digest_matches_no_server() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    for fingerprint in [
        "not-a-fingerprint".to_owned(),
        fingerprint(&LEAF_A).to_uppercase(),
    ] {
        let mut evidence = evidence("odd", &LEAF_A);
        evidence.tls = Some(fingerprint);
        let bound = mode().bind(&evidence).unwrap();
        let failure = bound.send(get(&server, "/")).await.unwrap_err();
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
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    assert_eq!(failure.key, KeyFailure::None);
}

/// What `error` and every error behind it show, as text and in `Debug`.
fn everything_shown(error: &Error) -> String {
    let mut shown = format!("{error} {error:?}");
    let mut source = std::error::Error::source(error);
    while let Some(error) = source {
        shown.push_str(&format!(" {error} {error:?}"));
        source = error.source();
    }
    shown
}

#[tokio::test]
async fn no_failure_repeats_the_url_of_the_request() {
    const TARGET: &str = "/v1/models?key=hunter2";
    let named = |error: &Error| {
        let shown = everything_shown(error);
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("/v1/models"), "{shown}");
    };

    // A connection that fails.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let closed = Url::parse(&format!("https://127.0.0.1:{port}{TARGET}")).unwrap();
    let failure = bound_to(&LEAF_A)
        .send(Request::new(Method::GET, closed))
        .await
        .unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    named(&failure.error);

    // A certificate that is refused, by the pin and by a standard check.
    for (served, key) in [(&LEAF_B, &KEY_B), (&LEAF_A_EXPIRED, &KEY_A)] {
        let server = serve(served, key, ok()).await;
        let failure = bound_to(&LEAF_A)
            .send(get(&server, TARGET))
            .await
            .unwrap_err();
        assert_eq!(failure.key, KeyFailure::PeerLacksKey);
        named(&failure.error);
    }

    // A deadline: the listener accepts and then says nothing.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let silent = Url::parse(&format!("https://127.0.0.1:{port}{TARGET}")).unwrap();
    let mut request = Request::new(Method::GET, silent);
    *request.timeout_mut() = Some(Duration::from_millis(100));
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
    assert!(failure.error.is_timeout());
    named(&failure.error);
    drop(listener);

    // A plaintext request, which the binding refuses by itself.
    let plain = Url::parse(&format!("http://127.0.0.1:{port}{TARGET}")).unwrap();
    let failure = bound_to(&LEAF_A)
        .send(Request::new(Method::GET, plain))
        .await
        .unwrap_err();
    named(&failure.error);
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
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    assert!(failure.error.is_timeout());
    assert_eq!(failure.key, KeyFailure::None);
    drop(listener);
}

// Protocols.

fn h2() -> Option<String> {
    Some("h2".to_owned())
}

fn http1() -> Option<String> {
    Some("http/1.1".to_owned())
}

#[tokio::test]
async fn a_connection_offers_http2_then_http1_and_uses_the_one_that_the_server_picks() {
    let both = serve(&LEAF_A, &KEY_A, ok()).await;
    let old = serve_on(Protocols::Http1Only, &LEAF_A, &KEY_A, ok()).await;
    let bound = bound_to(&LEAF_A);

    for (server, version, picked) in [
        (&both, reqwest::Version::HTTP_2, h2()),
        (&old, reqwest::Version::HTTP_11, http1()),
    ] {
        let response = bound.send(get(server, "/")).await.unwrap();
        assert_eq!(response.version(), version);
        response.body().await.unwrap();
        assert_eq!(server.offered(), [["h2", "http/1.1"]]);
        assert_eq!(server.handshakes(), [(Some(HandshakeKind::Full), picked)]);
        assert_eq!(server.seen()[0].version, version);
    }
}

#[tokio::test]
async fn the_server_is_asked_for_the_host_of_the_url_under_either_protocol() {
    for protocols in [Protocols::Both, Protocols::Http1Only] {
        let server = serve_on(protocols, &LEAF_A, &KEY_A, ok()).await;
        let response = bound_to(&LEAF_A).send(get(&server, "/")).await.unwrap();
        response.body().await.unwrap();
        let seen = server.seen();
        assert_eq!(
            seen[0].authority.as_deref(),
            Some(format!("127.0.0.1:{}", server.port).as_str()),
            "{protocols:?}"
        );
    }
}

#[tokio::test]
async fn headers_that_belong_to_one_connection_are_not_sent_over_http2() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let mut request = get(&server, "/");
    for (name, value) in [
        ("connection", "x-hop, keep-alive"),
        ("x-hop", "1"),
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("te", "gzip"),
        ("x-end-to-end", "kept"),
    ] {
        request
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    let response = bound_to(&LEAF_A).send(request).await.unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    response.body().await.unwrap();

    let seen = server.seen();
    let headers = &seen[0].headers;
    for name in [
        "connection",
        "x-hop",
        "keep-alive",
        "proxy-connection",
        "te",
        "host",
    ] {
        assert!(!headers.contains_key(name), "{name} was sent");
    }
    assert_eq!(headers["x-end-to-end"], "kept");
}

// Connections.

#[tokio::test]
async fn sequential_requests_over_http1_share_one_connection() {
    let server = serve_on(Protocols::Http1Only, &LEAF_A, &KEY_A, ok()).await;
    let bound = bound_to(&LEAF_A);
    for i in 0..8 {
        let response = bound.send(get(&server, &format!("/{i}"))).await.unwrap();
        // The body is read to the end, which returns the connection to
        // the pool.
        assert_eq!(response.body().await.unwrap(), format!("/{i}"));
    }
    assert_eq!(server.requests().len(), 8);
    assert_eq!(server.accepted(), 1);
    assert_eq!(server.handshakes(), [(Some(HandshakeKind::Full), http1())]);
}

#[tokio::test]
async fn concurrent_requests_over_http2_share_one_connection_that_was_checked_once() {
    // After the first request, no request is answered until all eight have
    // arrived, so they are in flight together.
    let gate = Arc::new(Notify::new());
    let server = serve(
        &LEAF_A,
        &KEY_A,
        Reply {
            gate: Some(Arc::clone(&gate)),
            ..ok()
        },
    )
    .await;
    let bound = bound_to(&LEAF_A);

    // The first request opens the connection, and learns that it speaks
    // HTTP/2. (Requests that all start before any connection exists each
    // open one, every one of them checked.)
    gate.notify_one();
    let first = bound.send(get(&server, "/first")).await.unwrap();
    first.body().await.unwrap();
    assert_eq!(server.accepted(), 1);

    let mut requests = Vec::new();
    for i in 0..8 {
        let (bound, request) = (Arc::clone(&bound), get(&server, &format!("/{i}")));
        requests.push(tokio::spawn(async move {
            bound.send(request).await.unwrap().body().await.unwrap()
        }));
    }
    eventually(|| server.seen().len() == 9, "all requests arrive").await;
    assert_eq!(server.accepted(), 1);
    gate.notify_waiters();
    for (i, request) in requests.into_iter().enumerate() {
        let body = tokio::time::timeout(PATIENCE, request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, format!("/{i}"));
    }

    assert_eq!(server.accepted(), 1);
    assert_eq!(server.handshakes(), [(Some(HandshakeKind::Full), h2())]);
    assert!(server.seen().iter().all(|seen| seen.connection == 0));
}

#[tokio::test]
async fn every_new_connection_makes_a_full_handshake_and_none_is_resumed() {
    // The server closes after each response, so each request needs a new
    // connection; it offers session resumption, as servers do.
    let server = serve_on(
        Protocols::Http1Only,
        &LEAF_A,
        &KEY_A,
        Reply {
            close: true,
            ..ok()
        },
    )
    .await;
    let bound = bound_to(&LEAF_A);
    for _ in 0..4 {
        let response = bound.send(get(&server, "/")).await.unwrap();
        response.body().await.unwrap();
    }
    assert_eq!(server.accepted(), 4);
    assert_eq!(
        server.handshakes(),
        vec![(Some(HandshakeKind::Full), http1()); 4]
    );
}

#[tokio::test]
async fn a_redirect_is_returned_to_the_caller_and_not_followed() {
    for protocols in [Protocols::Both, Protocols::Http1Only] {
        let server = serve_on(
            protocols,
            &LEAF_A,
            &KEY_A,
            Reply {
                status: 302,
                headers: vec![("location", "/elsewhere")],
                ..ok()
            },
        )
        .await;
        let response = bound_to(&LEAF_A)
            .send(get(&server, "/start"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok()),
            Some("/elsewhere")
        );
        response.body().await.unwrap();
        assert_eq!(server.requests(), ["GET /start"]);
    }
}

#[tokio::test]
async fn a_retired_binding_finishes_its_streams_and_carries_no_new_one() {
    // Over HTTP/2 a retired connection could still take new streams; it
    // must not.
    let gate = Arc::new(Notify::new());
    let server = serve(
        &LEAF_A,
        &KEY_A,
        Reply {
            gate: Some(Arc::clone(&gate)),
            ..ok()
        },
    )
    .await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;
    let start = |path: &'static str| {
        let (transport, request) = (f.transport.clone(), get(&server, path));
        tokio::spawn(async move { transport.send(request).await.unwrap().body().await.unwrap() })
    };

    // The first binding's connection, opened by a request that is let
    // through, and then two streams in flight on it.
    gate.notify_one();
    assert_eq!(start("/open").await.unwrap(), "/open");
    let mut in_flight = vec![start("/a"), start("/b")];
    eventually(|| server.seen().len() == 3, "both requests arrive").await;
    assert_eq!(server.accepted(), 1);

    // A new verification replaces the binding while they wait. The later
    // requests start one after the other, so that the second finds the
    // connection that the first opened.
    f.transport.reverify().await.unwrap();
    for (path, arrived) in [("/c", 4), ("/d", 5)] {
        in_flight.push(start(path));
        eventually(|| server.seen().len() == arrived, "a later request arrives").await;
    }

    // The later requests opened one connection of their own, and nothing
    // new went onto the retired one.
    assert_eq!(server.accepted(), 2);
    for seen in server.seen() {
        let expected = usize::from(seen.target == "/c" || seen.target == "/d");
        assert_eq!(seen.connection, expected, "{}", seen.target);
        assert_eq!(seen.version, reqwest::Version::HTTP_2);
    }

    // The streams that were in flight finish on the old connection.
    gate.notify_waiters();
    for (request, path) in in_flight.into_iter().zip(["/a", "/b", "/c", "/d"]) {
        let body = tokio::time::timeout(PATIENCE, request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, path);
    }
    // And the old connection ends once they are done.
    eventually(|| server.closed() == 1, "the retired connection closes").await;
}

#[tokio::test]
async fn a_new_binding_opens_its_own_connection_and_the_old_one_is_closed_with_its_binding() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let mode = mode();

    let first = mode.bind(&evidence("first", &LEAF_A)).unwrap();
    first
        .send(get(&server, "/1"))
        .await
        .unwrap()
        .body()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 1);

    // A second binding to the same key does not borrow the idle connection.
    let second = mode.bind(&evidence("second", &LEAF_A)).unwrap();
    second
        .send(get(&server, "/2"))
        .await
        .unwrap()
        .body()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 2);

    // Retiring the first binding closes its idle connection.
    assert_eq!(server.closed(), 0);
    drop(first);
    eventually(
        || server.closed() == 1,
        "the retired binding's connection closes",
    )
    .await;

    // The second binding keeps using its own.
    second
        .send(get(&server, "/3"))
        .await
        .unwrap()
        .body()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 2);
}

// Proxies.

/// A listener that stands in for a forward proxy: it counts the
/// connections that reach it and answers none.
async fn silent_proxy() -> (reqwest::Proxy, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&connections);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            held.push(socket);
        }
    });
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap();
    (proxy, connections)
}

/// A forward proxy that answers each `CONNECT` by opening a tunnel to the
/// local server on `port`, whatever host the client named, and records the
/// request lines that it received.
async fn tunnel_proxy(port: u16) -> (reqwest::Proxy, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&lines);
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match client.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buffer[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                log.lock()
                    .unwrap()
                    .push(head.lines().next().unwrap_or_default().to_owned());
                let Ok(mut upstream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                else {
                    return;
                };
                if client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    let proxy = reqwest::Proxy::all(format!("http://{address}")).unwrap();
    (proxy, lines)
}

#[tokio::test]
async fn a_connection_through_a_proxys_tunnel_is_pinned_like_a_direct_one() {
    // The server holds key A.
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let (proxy, lines) = tunnel_proxy(server.port).await;
    let mode = TlsMode::for_test(roots(), Some(proxy));
    let connect = format!("CONNECT enclave.test:{} HTTP/1.1", server.port);

    // Pinned to key A: the request goes through the tunnel and arrives.
    let pinned = mode.bind(&evidence("pinned", &LEAF_A)).unwrap();
    let response = pinned
        .send(get_by_name(&server, "/tunnelled"))
        .await
        .unwrap();
    // Inside the tunnel the connection is HTTP/2, as a direct one is.
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.body().await.unwrap(), "/tunnelled");
    assert_eq!(*lines.lock().unwrap(), std::slice::from_ref(&connect));
    assert_eq!(server.requests(), ["GET /tunnelled"]);

    // Pinned to key B: the tunnel opens, the handshake inside it presents
    // a certificate that is valid for the name, and the pin refuses it.
    let other = mode.bind(&evidence("other", &LEAF_B)).unwrap();
    let failure = other
        .send(get_by_name(&server, "/secret"))
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
    assert_eq!(*lines.lock().unwrap(), [connect.clone(), connect]);
    // Nothing was sent to the server by the refused client.
    assert_eq!(server.requests(), ["GET /tunnelled"]);
}

#[tokio::test]
async fn a_forward_proxy_that_is_reached_over_tls_is_held_to_the_pin_and_fails_closed() {
    // The enclave holds key A. The proxy is an HTTPS server of its own,
    // with a certificate that passes every standard check and another key.
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let proxy = serve(&LEAF_B, &KEY_B, ok()).await;
    let through = reqwest::Proxy::all(format!("https://127.0.0.1:{}", proxy.port)).unwrap();
    let mode = TlsMode::for_test(roots(), Some(through));
    let pinned = mode.bind(&evidence("pinned", &LEAF_A)).unwrap();

    // Every TLS connection of a binding is pinned, the one to the proxy
    // included, and the proxy does not hold the attested key: the request
    // fails as a key failure, and the proxy is told nothing, not even the
    // name of the host.
    let failure = pinned
        .send(get_by_name(&server, "/v1/models?key=hunter2"))
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
    assert!(!everything_shown(&failure.error).contains("hunter2"));
    assert_eq!(proxy.accepted(), 1);
    assert!(proxy.requests().is_empty());
    assert_eq!(server.accepted(), 0);

    // A loopback request does not use the proxy, and arrives.
    let response = pinned.send(get(&server, "/direct")).await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/direct");
    assert_eq!(proxy.accepted(), 1);
}

#[tokio::test]
async fn a_request_to_a_loopback_host_never_goes_through_a_configured_proxy() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let (proxy, connections) = silent_proxy().await;
    let bound = TlsMode::for_test(roots(), Some(proxy))
        .bind(&evidence("pinned", &LEAF_A))
        .unwrap();

    // Loopback by address and by name: both reach the server directly.
    let by_address = bound.send(get(&server, "/direct")).await.unwrap();
    assert_eq!(by_address.body().await.unwrap(), "/direct");
    let by_name = Url::parse(&format!("https://localhost:{}/named", server.port)).unwrap();
    // The name resolves to this machine; whether the server is reached
    // over the address family that it resolves to first does not matter
    // here, only that the proxy is not asked.
    let _ = bound.send(Request::new(Method::GET, by_name)).await;
    assert_eq!(connections.load(Ordering::SeqCst), 0);

    // The proxy is in use for every other host: a request elsewhere asks
    // it for a tunnel.
    let mut elsewhere = Request::new(Method::GET, Url::parse("https://enclave.invalid/").unwrap());
    *elsewhere.timeout_mut() = Some(Duration::from_millis(500));
    assert!(bound.send(elsewhere).await.is_err());
    assert_eq!(connections.load(Ordering::SeqCst), 1);
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
    let server = serve(&LEAF_B, &KEY_B, ok()).await;
    let f = transport(vec![
        evidence("before", &LEAF_A),
        evidence("after", &LEAF_B),
    ])
    .await;

    let failure = f.transport.send(get(&server, "/secret")).await.unwrap_err();
    assert_eq!(failure.key, KeyFailure::Rejected);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    assert!(server.requests().is_empty());
    assert_eq!(f.script.calls(), 1);

    // The same request again: the enclave is verified first, and the
    // request goes out under the new key.
    let response = f.transport.send(get(&server, "/secret")).await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/secret");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.transport.current().name, "after");
    assert_eq!(server.requests(), ["GET /secret"]);
}

#[tokio::test]
async fn a_key_failure_that_a_new_verification_does_not_cure_fails_again_without_sending() {
    let server = serve(&LEAF_B, &KEY_B, ok()).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;
    for _ in 0..2 {
        let failure = f.transport.send(get(&server, "/secret")).await.unwrap_err();
        assert_eq!(failure.key, KeyFailure::Rejected);
    }
    assert_eq!(f.script.calls(), 2);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_new_verification_moves_requests_to_a_new_connection() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;

    for path in ["/1", "/2"] {
        f.transport
            .send(get(&server, path))
            .await
            .unwrap()
            .body()
            .await
            .unwrap();
    }
    assert_eq!(server.accepted(), 1);

    f.transport.reverify().await.unwrap();
    for path in ["/3", "/4"] {
        f.transport
            .send(get(&server, path))
            .await
            .unwrap()
            .body()
            .await
            .unwrap();
    }
    assert_eq!(server.accepted(), 2);
    assert_eq!(server.requests().len(), 4);
    // The first binding was retired, and its connection with it.
    eventually(
        || server.closed() == 1,
        "the replaced binding's connection closes",
    )
    .await;
}

#[tokio::test]
async fn a_response_still_being_read_survives_the_replacement_of_its_binding() {
    let server = serve(&LEAF_A, &KEY_A, ok()).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;

    let response = f.transport.send(get(&server, "/in-flight")).await.unwrap();
    f.transport.reverify().await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/in-flight");
}
