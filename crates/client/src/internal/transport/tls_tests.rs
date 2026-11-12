//! The TLS mode against a local TLS server on loopback, whose certificates
//! are made when the tests run, under a certificate authority that only
//! these tests trust.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Method, Request, Response, StatusCode, Url};
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

/// The certificates of these tests, made when the tests run: a
/// certificate authority that only these tests trust, two server keys, and
/// server certificates for them. The keys are fixed numbers, good for
/// nothing but telling two keys apart.
mod made {
    use std::str::FromStr;
    use std::sync::LazyLock;

    use der::asn1::{BitString, GeneralizedTime, Ia5String, OctetString, UtcTime};
    use der::oid::{AssociatedOid, ObjectIdentifier};
    use der::{Decode, Encode};
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, SigningKey};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::{BasicConstraints, SubjectAltName};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};
    use x509_cert::{Certificate, TbsCertificate, Version};

    const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

    /// Seconds since the Unix epoch.
    const YEAR_2020: u64 = 1_577_836_800;
    const YEAR_2100: u64 = 4_102_444_800;
    const DAY: u64 = 86_400;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn time(unix: u64) -> Time {
        let since_epoch = std::time::Duration::from_secs(unix);
        // Dates from 2050 on must use the long form.
        match UtcTime::from_unix_duration(since_epoch) {
            Ok(utc) => Time::UtcTime(utc),
            Err(_) => Time::GeneralTime(GeneralizedTime::from_unix_duration(since_epoch).unwrap()),
        }
    }

    fn extension<T: AssociatedOid + Encode>(critical: bool, value: &T) -> Extension {
        Extension {
            extn_id: T::OID,
            critical,
            extn_value: OctetString::new(value.to_der().unwrap()).unwrap(),
        }
    }

    /// A certificate for `subject_key`, signed by `issuer_key`.
    fn certificate(
        subject: &str,
        subject_key: &SigningKey,
        issuer: &str,
        issuer_key: &SigningKey,
        (not_before, not_after): (u64, u64),
        extensions: Vec<Extension>,
    ) -> Vec<u8> {
        let algorithm = AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        };
        let public_key = subject_key.verifying_key().to_public_key_der().unwrap();
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::from(7u32),
            signature: algorithm.clone(),
            issuer: Name::from_str(issuer).unwrap(),
            validity: Validity {
                not_before: time(not_before),
                not_after: time(not_after),
            },
            subject: Name::from_str(subject).unwrap(),
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key.as_bytes())
                .unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let signature: DerSignature = issuer_key.sign(&tbs_certificate.to_der().unwrap());
        Certificate {
            tbs_certificate,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    fn authority(name: &str, key: &SigningKey) -> Vec<u8> {
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        certificate(
            name,
            key,
            name,
            key,
            (YEAR_2020, YEAR_2100),
            vec![extension(true, &constraints)],
        )
    }

    fn leaf(
        key: &SigningKey,
        issuer: &str,
        issuer_key: &SigningKey,
        names: Vec<GeneralName>,
        validity: (u64, u64),
    ) -> Vec<u8> {
        let constraints = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        certificate(
            "CN=test server",
            key,
            issuer,
            issuer_key,
            validity,
            vec![
                extension(true, &constraints),
                extension(false, &SubjectAltName(names)),
            ],
        )
    }

    /// The names of the local server: its address, `localhost`, and the
    /// name that the tests reach it by through a proxy.
    fn local() -> Vec<GeneralName> {
        vec![
            GeneralName::IpAddress(OctetString::new([127, 0, 0, 1]).unwrap()),
            GeneralName::DnsName(Ia5String::new("localhost").unwrap()),
            GeneralName::DnsName(Ia5String::new("enclave.test").unwrap()),
        ]
    }

    const TRUSTED: &str = "CN=Test CA";
    const UNTRUSTED: &str = "CN=Another Test CA";
    static TRUSTED_KEY: LazyLock<SigningKey> = LazyLock::new(|| key(1));
    static UNTRUSTED_KEY: LazyLock<SigningKey> = LazyLock::new(|| key(2));
    static SERVER_KEY_A: LazyLock<SigningKey> = LazyLock::new(|| key(3));
    static SERVER_KEY_B: LazyLock<SigningKey> = LazyLock::new(|| key(4));
    const LONG: (u64, u64) = (YEAR_2020, YEAR_2100);

    /// The authority that the tests trust.
    pub(super) static CA: LazyLock<Vec<u8>> = LazyLock::new(|| authority(TRUSTED, &TRUSTED_KEY));
    /// Key A, in the form that a TLS server loads.
    pub(super) static KEY_A: LazyLock<Vec<u8>> =
        LazyLock::new(|| SERVER_KEY_A.to_pkcs8_der().unwrap().as_bytes().to_vec());
    /// Key B, in the form that a TLS server loads.
    pub(super) static KEY_B: LazyLock<Vec<u8>> =
        LazyLock::new(|| SERVER_KEY_B.to_pkcs8_der().unwrap().as_bytes().to_vec());
    /// Key A, for 127.0.0.1, under the trusted authority.
    pub(super) static LEAF_A: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, local(), LONG));
    /// Key B, for 127.0.0.1, under the trusted authority.
    pub(super) static LEAF_B: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_B, TRUSTED, &TRUSTED_KEY, local(), LONG));
    /// Key A, for 127.0.0.1, under an authority that nothing trusts.
    pub(super) static LEAF_A_OTHER_CA: LazyLock<Vec<u8>> =
        LazyLock::new(|| leaf(&SERVER_KEY_A, UNTRUSTED, &UNTRUSTED_KEY, local(), LONG));
    /// Key A, under the trusted authority, for another name.
    pub(super) static LEAF_A_WRONG_NAME: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let other = GeneralName::DnsName(Ia5String::new("other.example").unwrap());
        leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, vec![other], LONG)
    });
    /// Key A, for 127.0.0.1, under the trusted authority, expired in 2020.
    pub(super) static LEAF_A_EXPIRED: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let one_day = (YEAR_2020, YEAR_2020 + DAY);
        leaf(&SERVER_KEY_A, TRUSTED, &TRUSTED_KEY, local(), one_day)
    });
}

use made::{CA, KEY_A, KEY_B, LEAF_A, LEAF_A_EXPIRED, LEAF_A_OTHER_CA, LEAF_A_WRONG_NAME, LEAF_B};

const HOUR: Duration = Duration::from_secs(3600);

fn certificate(der: &[u8]) -> CertificateDer<'static> {
    CertificateDer::from(der.to_vec())
}

fn fingerprint(der: &[u8]) -> String {
    leaf_fingerprint(&certificate(der)).unwrap()
}

fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(certificate(&CA)).unwrap();
    roots
}

fn mode() -> TlsMode {
    TlsMode::for_test(roots(), None)
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
    /// A request for the server by a name that is not a loopback name, so
    /// that a configured proxy applies to it. Only a proxy that connects to
    /// the server on its own can deliver it.
    fn get_by_name(&self, path: &str) -> Request {
        let url = format!("https://enclave.test:{}{path}", self.port);
        Request::new(Method::GET, Url::parse(&url).unwrap())
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
            PrivateKeyDer::Pkcs8(key.to_vec().into()),
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
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let response = bound_to(&LEAF_A)
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
    let server = serve(&LEAF_B, &KEY_B, OK).await;
    let failure = bound_to(&LEAF_A)
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
    assert!(bound_to(&LEAF_B).send(server.get("/")).await.is_ok());
}

#[tokio::test]
async fn the_attested_key_does_not_excuse_a_certificate_that_fails_the_standard_checks() {
    for (leaf, why) in [
        (&LEAF_A_OTHER_CA, "UnknownIssuer"),
        (&LEAF_A_WRONG_NAME, "NotValidForName"),
        (&LEAF_A_EXPIRED, "Expired"),
    ] {
        let server = serve(leaf, &KEY_A, OK).await;
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
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    for fingerprint in [
        "not-a-fingerprint".to_owned(),
        fingerprint(&LEAF_A).to_uppercase(),
    ] {
        let mut evidence = evidence("odd", &LEAF_A);
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
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
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
    let failure = bound_to(&LEAF_A).send(request).await.unwrap_err();
    assert_eq!(failure.error.kind(), ErrorKind::Network);
    assert!(failure.error.is_timeout());
    assert_eq!(failure.key, KeyFailure::None);
    drop(listener);
}

// Connections.

#[tokio::test]
async fn sequential_requests_on_one_binding_share_one_connection() {
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let bound = bound_to(&LEAF_A);
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
    let server = serve(&LEAF_A, &KEY_A, Reply { close: true, ..OK }).await;
    let bound = bound_to(&LEAF_A);
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
        &LEAF_A,
        &KEY_A,
        Reply {
            status: "302 Found",
            headers: "location: /elsewhere\r\n",
            close: false,
        },
    )
    .await;
    let response = bound_to(&LEAF_A).send(server.get("/start")).await.unwrap();
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
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let mode = mode();

    let first = mode.bind(&evidence("first", &LEAF_A)).unwrap();
    first
        .send(server.get("/1"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(server.accepted(), 1);

    // A second binding to the same key does not borrow the idle connection.
    let second = mode.bind(&evidence("second", &LEAF_A)).unwrap();
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
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let (proxy, lines) = tunnel_proxy(server.port).await;
    let mode = TlsMode::for_test(roots(), Some(proxy));
    let connect = format!("CONNECT enclave.test:{} HTTP/1.1", server.port);

    // Pinned to key A: the request goes through the tunnel and arrives.
    let pinned = mode.bind(&evidence("pinned", &LEAF_A)).unwrap();
    let response = pinned.send(server.get_by_name("/tunnelled")).await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/tunnelled");
    assert_eq!(*lines.lock().unwrap(), std::slice::from_ref(&connect));
    assert_eq!(server.requests(), ["GET /tunnelled HTTP/1.1"]);

    // Pinned to key B: the tunnel opens, the handshake inside it presents
    // a certificate that is valid for the name, and the pin refuses it.
    let other = mode.bind(&evidence("other", &LEAF_B)).unwrap();
    let failure = other.send(server.get_by_name("/secret")).await.unwrap_err();
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
    assert_eq!(server.requests(), ["GET /tunnelled HTTP/1.1"]);
}

#[tokio::test]
async fn a_request_to_a_loopback_host_never_goes_through_a_configured_proxy() {
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let (proxy, connections) = silent_proxy().await;
    let bound = TlsMode::for_test(roots(), Some(proxy))
        .bind(&evidence("pinned", &LEAF_A))
        .unwrap();

    // Loopback by address and by name: both reach the server directly.
    let by_address = bound.send(server.get("/direct")).await.unwrap();
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
    let server = serve(&LEAF_B, &KEY_B, OK).await;
    let f = transport(vec![
        evidence("before", &LEAF_A),
        evidence("after", &LEAF_B),
    ])
    .await;

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
    let server = serve(&LEAF_B, &KEY_B, OK).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;
    for _ in 0..2 {
        let failure = f.transport.send(server.get("/secret")).await.unwrap_err();
        assert_eq!(failure.key, KeyFailure::Rejected);
    }
    assert_eq!(f.script.calls(), 2);
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn a_new_verification_moves_requests_to_a_new_connection() {
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;

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
    let server = serve(&LEAF_A, &KEY_A, OK).await;
    let f = transport(vec![
        evidence("first", &LEAF_A),
        evidence("second", &LEAF_A),
    ])
    .await;

    let response = f.transport.send(server.get("/in-flight")).await.unwrap();
    f.transport.reverify().await.unwrap();
    assert_eq!(response.body().await.unwrap(), "/in-flight");
}
