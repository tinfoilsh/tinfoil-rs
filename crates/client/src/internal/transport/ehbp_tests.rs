//! The EHBP mode against a local server that holds an HPKE key and plays
//! the enclave's side of the protocol: it opens sealed request bodies,
//! answers a body that it cannot open with the key-configuration problem,
//! and seals its responses frame by frame. A test's reply can also leave
//! the protocol: answer in plaintext, damage a frame, or send a bad nonce.

use std::error::Error as StdError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, Serializable, setup_receiver};
use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Method, Request, Response, Url};
use tinfoil_ehbp::Code;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use super::{EhbpMode, check_request};
use crate::error::ErrorKind;
use crate::internal::enclave::Enclave;
use crate::internal::fetch::lower_hex;
use crate::internal::testing::{Record, Script, Step, tokio_clock};
use crate::internal::transport::{Failure, KeyFailure, Mode, RoundTrip, Transport};

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;

/// Bounds a wait that a regression would turn into a hang.
const PATIENCE: Duration = Duration::from_secs(20);

// The enclave's side of the protocol.

/// An HPKE key pair.
#[derive(Clone)]
struct Key {
    private: PrivateKey,
    public_hex: String,
}

fn key(seed: u8) -> Key {
    let (private, public) = Kem::derive_keypair(&[seed; 32]);
    Key {
        private,
        public_hex: lower_hex(&public.to_bytes()),
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "hex of odd length");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Seals the frames of one response.
struct Sealer {
    cipher: Aes256Gcm,
    nonce_base: [u8; 12],
    sequence: u64,
    nonce_hex: String,
}

impl Sealer {
    /// `plaintext` as the next frame: a length and the ciphertext.
    fn frame(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = tinfoil_ehbp::compute_nonce(&self.nonce_base, self.sequence);
        self.sequence += 1;
        let sealed = self.cipher.encrypt(&nonce.into(), plaintext).expect("seal");
        let mut frame = u32::try_from(sealed.len())
            .expect("length")
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(&sealed);
        frame
    }
}

/// What the server made of a request body.
enum Opened {
    /// The request was not sealed.
    Plain(Vec<u8>),
    /// The body, opened, and the sealer for the response.
    Sealed(Vec<u8>, Box<Sealer>),
    /// The body was sealed to another key.
    Mismatch,
}

fn open(key: &Key, encapsulated: Option<&str>, wire: &[u8]) -> Opened {
    let Some(encapsulated) = encapsulated else {
        return Opened::Plain(wire.to_vec());
    };
    let encapsulated = unhex(encapsulated);
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&encapsulated).expect("enc");
    let Ok(mut context) = setup_receiver::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &key.private,
        &encapped,
        tinfoil_ehbp::HPKE_REQUEST_INFO,
    ) else {
        return Opened::Mismatch;
    };
    let mut body = Vec::new();
    let mut rest = wire;
    while !rest.is_empty() {
        let (length, tail) = rest.split_at(4);
        let length = u32::from_be_bytes(length.try_into().expect("length")) as usize;
        let (sealed, tail) = tail.split_at(length);
        match context.open(sealed, &[]) {
            Ok(plaintext) => body.extend_from_slice(&plaintext),
            Err(_) => return Opened::Mismatch,
        }
        rest = tail;
    }
    let mut secret = [0u8; tinfoil_ehbp::EXPORT_LENGTH];
    context
        .export(tinfoil_ehbp::EXPORT_LABEL, &mut secret)
        .expect("export");
    let mut nonce = [0u8; tinfoil_ehbp::RESPONSE_NONCE_LENGTH];
    getrandom::fill(&mut nonce).expect("random");
    let material =
        tinfoil_ehbp::derive_response_keys(&secret, &encapsulated, &nonce).expect("derive");
    Opened::Sealed(
        body,
        Box::new(Sealer {
            cipher: Aes256Gcm::new_from_slice(&material.key).expect("key"),
            nonce_base: material.nonce_base,
            sequence: 0,
            nonce_hex: lower_hex(&nonce),
        }),
    )
}

// The server.

/// One request as the server received it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    /// The headers, with their names in lowercase.
    headers: Vec<(String, String)>,
    /// The body as it was on the wire.
    wire: Vec<u8>,
    /// The body after opening; the wire body of a request that was not
    /// sealed.
    body: Vec<u8>,
    sealed: bool,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(have, _)| have == name)
            .map(|(_, value)| value.as_str())
    }
}

/// One step of a response body.
enum Part {
    /// A frame with this plaintext.
    Data(Vec<u8>),
    /// A frame with this plaintext and one bit of its ciphertext flipped.
    Tampered(Vec<u8>),
    /// A frame with this plaintext, without its last byte.
    Cut(Vec<u8>),
    /// Send nothing until the notify is signalled.
    Wait(Arc<Notify>),
}

fn data(text: &str) -> Part {
    Part::Data(text.as_bytes().to_vec())
}

/// What the response to a sealed request says about its sealing.
enum NonceHeader {
    /// The nonce that the body is sealed under.
    Honest,
    /// No nonce, and the body in plaintext.
    Absent,
    /// This value instead of the nonce.
    Invalid(&'static str),
    /// The nonce, twice.
    Repeated,
}

/// The application's answer to one request.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    parts: Vec<Part>,
    nonce: NonceHeader,
    /// Send nothing, the status line included, until this is signalled.
    hold: Option<Arc<Notify>>,
}

impl Reply {
    fn parts(parts: Vec<Part>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            parts,
            nonce: NonceHeader::Honest,
            hold: None,
        }
    }
    /// An answer that never starts.
    fn never(gate: &Arc<Notify>) -> Self {
        let mut reply = Self::ok("never");
        reply.hold = Some(Arc::clone(gate));
        reply
    }
    fn ok(body: &str) -> Self {
        Self::parts(vec![data(body)])
    }
    fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
    fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }
    fn nonce(mut self, nonce: NonceHeader) -> Self {
        self.nonce = nonce;
        self
    }
    /// The same answer, never sealed and without a nonce: what a proxy in
    /// front of the enclave would send.
    fn plaintext(self) -> Self {
        self.nonce(NonceHeader::Absent)
    }
    /// The enclave's answer to a body that it cannot open.
    fn key_mismatch() -> Self {
        Self::ok(&format!(
            r#"{{"type":"{}","title":"failed to decrypt request"}}"#,
            tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE
        ))
        .status(422)
        .header("content-type", tinfoil_ehbp::PROBLEM_JSON_MEDIA_TYPE)
        .plaintext()
    }
}

struct Server {
    url: Url,
    /// How many connections the server has accepted.
    accepted: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
    fn url(&self, path: &str) -> Url {
        self.url.join(path).expect("url")
    }
}

type App = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

/// A server that holds `key` and answers each request that it can open
/// with what `app` returns for it.
async fn serve(key: &Key, app: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (count, log) = (Arc::clone(&accepted), Arc::clone(&seen));
    let app: App = Arc::new(app);
    let key = key.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(connection(
                socket,
                key.clone(),
                Arc::clone(&app),
                Arc::clone(&log),
            ));
        }
    });
    Server {
        url: Url::parse(&format!("http://{address}/")).expect("url"),
        accepted,
        seen,
    }
}

/// Serves the requests of one connection until the client closes it.
async fn connection(
    socket: TcpStream,
    key: Key,
    app: App,
    log: Arc<Mutex<Vec<Seen>>>,
) -> Option<()> {
    let mut socket = BufReader::new(socket);
    loop {
        let (method, target, headers) = read_head(&mut socket).await?;
        let wire = read_body(&mut socket, &headers).await?;
        let encapsulated = headers
            .iter()
            .find(|(name, _)| name == "ehbp-encapsulated-key")
            .map(|(_, value)| value.as_str());
        let (body, sealer, mismatch) = match open(&key, encapsulated, &wire) {
            Opened::Plain(body) => (body, None, false),
            Opened::Sealed(body, sealer) => (body, Some(*sealer), false),
            Opened::Mismatch => (Vec::new(), None, true),
        };
        let seen = Seen {
            method,
            target,
            headers,
            wire,
            body,
            sealed: sealer.is_some(),
        };
        log.lock().unwrap().push(seen.clone());
        let reply = if mismatch {
            Reply::key_mismatch()
        } else {
            app(&seen)
        };
        write_reply(&mut socket, reply, sealer).await?;
    }
}

async fn read_line(socket: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    if socket.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    Some(line.trim_end().to_owned())
}

async fn read_head(
    socket: &mut BufReader<TcpStream>,
) -> Option<(String, String, Vec<(String, String)>)> {
    let request_line = read_line(socket).await?;
    let mut words = request_line.split(' ');
    let method = words.next()?.to_owned();
    let target = words.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let line = read_line(socket).await?;
        if line.is_empty() {
            return Some((method, target, headers));
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
    }
}

async fn read_body(
    socket: &mut BufReader<TcpStream>,
    headers: &[(String, String)],
) -> Option<Vec<u8>> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(have, _)| have == name)
            .map(|(_, value)| value.as_str())
    };
    let mut body = Vec::new();
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        loop {
            let size = usize::from_str_radix(&read_line(socket).await?, 16).ok()?;
            let mut chunk = vec![0u8; size];
            socket.read_exact(&mut chunk).await.ok()?;
            body.extend_from_slice(&chunk);
            read_line(socket).await?;
            if size == 0 {
                break;
            }
        }
    } else if let Some(length) = header("content-length") {
        body = vec![0u8; length.parse().ok()?];
        socket.read_exact(&mut body).await.ok()?;
    }
    Some(body)
}

/// Writes `reply` with a chunked body, one chunk for each part, each
/// flushed before the next part is looked at.
async fn write_reply(
    socket: &mut BufReader<TcpStream>,
    reply: Reply,
    sealer: Option<Sealer>,
) -> Option<()> {
    if let Some(hold) = &reply.hold {
        hold.notified().await;
    }
    // A response is sealed only if the request was, and the reply keeps to
    // the protocol.
    let mut sealer = sealer.filter(|_| !matches!(reply.nonce, NonceHeader::Absent));
    let mut head = format!("HTTP/1.1 {} Status\r\n", reply.status);
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(sealer) = &sealer {
        let honest = sealer.nonce_hex.as_str();
        let values = match reply.nonce {
            NonceHeader::Honest | NonceHeader::Absent => vec![honest],
            NonceHeader::Invalid(value) => vec![value],
            NonceHeader::Repeated => vec![honest, honest],
        };
        for value in values {
            head.push_str(&format!("Ehbp-Response-Nonce: {value}\r\n"));
        }
    }
    head.push_str("transfer-encoding: chunked\r\n\r\n");
    socket.write_all(head.as_bytes()).await.ok()?;
    socket.flush().await.ok()?;
    for part in reply.parts {
        let bytes = match (part, sealer.as_mut()) {
            (Part::Wait(gate), _) => {
                gate.notified().await;
                continue;
            }
            (Part::Data(plain) | Part::Tampered(plain) | Part::Cut(plain), None) => plain,
            (Part::Data(plain), Some(sealer)) => sealer.frame(&plain),
            (Part::Tampered(plain), Some(sealer)) => {
                let mut frame = sealer.frame(&plain);
                *frame.last_mut().expect("a frame") ^= 1;
                frame
            }
            (Part::Cut(plain), Some(sealer)) => {
                let mut frame = sealer.frame(&plain);
                frame.pop();
                frame
            }
        };
        let mut chunk = format!("{:x}\r\n", bytes.len()).into_bytes();
        chunk.extend_from_slice(&bytes);
        chunk.extend_from_slice(b"\r\n");
        socket.write_all(&chunk).await.ok()?;
        socket.flush().await.ok()?;
    }
    socket.write_all(b"0\r\n\r\n").await.ok()?;
    socket.flush().await.ok()
}

// The client's side.

/// The mode. Every server of these tests is on a loopback address, which
/// no proxy of the test machine applies to.
fn mode() -> EhbpMode {
    EhbpMode::new().expect("mode")
}

fn evidence(name: &'static str, hpke: Option<&str>) -> Record {
    Record {
        name,
        tls: Some("tls".to_owned()),
        hpke: hpke.map(str::to_owned),
        expires: None,
    }
}

fn bind(mode: &EhbpMode, hpke: Option<&str>) -> Result<Arc<dyn RoundTrip>, crate::Error> {
    mode.bind(&evidence("a", hpke))
}

/// A transport bound to `key`.
fn bound(key: &Key) -> Arc<dyn RoundTrip> {
    bind(&mode(), Some(&key.public_hex)).expect("bound")
}

fn get(url: Url) -> Request {
    Request::new(Method::GET, url)
}

fn post(url: Url, body: impl Into<reqwest::Body>) -> Request {
    let mut request = Request::new(Method::POST, url);
    *request.body_mut() = Some(body.into());
    request
}

fn with_header(mut request: Request, name: &str, value: &str) -> Request {
    request.headers_mut().insert(
        HeaderName::from_bytes(name.as_bytes()).expect("name"),
        HeaderValue::from_str(value).expect("value"),
    );
    request
}

async fn text(response: Response) -> String {
    response.text().await.expect("a body")
}

async fn next_chunk(response: &mut Response) -> Result<Option<String>, reqwest::Error> {
    let chunk = tokio::time::timeout(PATIENCE, response.chunk())
        .await
        .expect("the body made no progress")?;
    Ok(chunk.map(|bytes| String::from_utf8(bytes.to_vec()).expect("text")))
}

/// The protocol's error code in the sources of `error`.
fn code_of(error: &(dyn StdError + 'static)) -> Option<Code> {
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(found) = error.downcast_ref::<tinfoil_ehbp::Error>() {
            return found.code();
        }
        next = error.source();
    }
    None
}

/// A failed request that says nothing about the keys.
fn ordinary(result: Result<Response, Failure>, kind: ErrorKind) -> crate::Error {
    let failure = result.expect_err("a failure");
    assert_eq!(failure.key, KeyFailure::None, "{}", failure.error);
    assert_eq!(failure.error.kind(), kind, "{}", failure.error);
    failure.error
}

/// A transport whose verifications return `records` in order, each valid
/// for an hour, connected on the first.
async fn transport(records: Vec<Record>) -> (Arc<Script>, Transport<Record>) {
    let clock = tokio_clock();
    let script = Script::new(records.into_iter().map(|mut record| {
        record.expires = Some(clock() + Duration::from_secs(3600));
        Step::Ready(Ok(record))
    }));
    let enclave = Enclave::from_source("enclave.example.com", script.source(), None, clock);
    let transport = Transport::connect(enclave, Arc::new(mode()), true)
        .await
        .expect("connected");
    (script, transport)
}

// Binding.

#[test]
fn evidence_without_an_hpke_key_cannot_be_bound() {
    let error = bind(&mode(), None).err().expect("no key");
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(
        error.to_string().contains("endorses no HPKE key"),
        "{error}"
    );
    assert!(
        error.to_string().contains("use the TLS transport mode"),
        "{error}"
    );
}

#[test]
fn an_hpke_key_that_is_not_32_bytes_of_hexadecimal_cannot_be_bound() {
    let good = key(1).public_hex;
    for bad in [
        String::new(),
        "zz".repeat(32),
        "01".repeat(31),
        "01".repeat(33),
        good[1..].to_owned(),
        format!("0x{}", &good[2..]),
        format!(" {good}"),
    ] {
        let error = bind(&mode(), Some(&bad)).err().expect("a malformed key");
        assert_eq!(error.kind(), ErrorKind::Attestation, "{bad:?}");
        assert!(
            error.to_string().contains("HPKE public key"),
            "{bad:?}: {error}"
        );
        assert_eq!(
            code_of(&error),
            Some(Code::InvalidKeyConfig),
            "{bad:?}: {error}"
        );
    }
}

#[test]
fn an_hpke_key_binds_in_either_case_of_hexadecimal() {
    let key = key(1).public_hex;
    assert!(bind(&mode(), Some(&key)).is_ok());
    assert!(bind(&mode(), Some(&key.to_uppercase())).is_ok());
}

// Request checks.

fn example(method: Method, url: &str) -> Request {
    Request::new(method, Url::parse(url).expect("url"))
}

fn refusal(request: &Request) -> String {
    let error = check_request(request).expect_err("refused");
    assert_eq!(error.kind(), ErrorKind::Configuration, "{error}");
    error.to_string()
}

#[test]
fn a_request_whose_traffic_would_continue_outside_its_bodies_is_refused() {
    let connect = example(Method::CONNECT, "https://enclave.example.com/");
    assert!(refusal(&connect).contains("CONNECT tunnel"));

    let upgrade = with_header(
        example(Method::GET, "https://enclave.example.com/v1/realtime"),
        "Upgrade",
        "websocket",
    );
    assert!(refusal(&upgrade).contains("protocol upgrade"));

    let empty = with_header(
        example(Method::GET, "https://enclave.example.com/v1/realtime"),
        "upgrade",
        "",
    );
    assert!(refusal(&empty).contains("protocol upgrade"));
}

#[test]
fn each_header_that_the_transport_sets_is_refused_whatever_its_spelling() {
    for name in [
        "Host",
        "host",
        "Content-Length",
        "CONTENT-LENGTH",
        "Transfer-Encoding",
        "transfer-encoding",
        "Ehbp-Encapsulated-Key",
        "EHBP-ENCAPSULATED-KEY",
        "Ehbp-Response-Nonce",
        "ehbp-response-nonce",
        "Ehbp-Anything-Else",
        "ehbp-",
    ] {
        let request = with_header(
            example(Method::POST, "https://enclave.example.com/v1/chat"),
            name,
            "1",
        );
        let message = refusal(&request);
        assert!(
            message.contains(&format!("`{}`", name.to_ascii_lowercase())),
            "{name}: {message}"
        );
    }
}

#[test]
fn a_reserved_header_is_found_among_other_headers() {
    let mut request = example(Method::POST, "https://enclave.example.com/v1/chat");
    for (name, value) in [
        ("authorization", "Bearer token"),
        ("content-type", "application/json"),
        ("ehbp-encapsulated-key", "00"),
        ("x-request-id", "1"),
    ] {
        request = with_header(request, name, value);
    }
    assert!(refusal(&request).contains("`ehbp-encapsulated-key`"));
}

#[test]
fn a_url_with_credentials_is_refused_without_being_repeated() {
    for url in [
        "https://user:hunter2@enclave.example.com/v1/models",
        "https://hunter2@enclave.example.com/v1/models",
        "https://:hunter2@enclave.example.com/v1/models",
    ] {
        let message = refusal(&example(Method::GET, url));
        assert!(message.contains("credentials"), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("enclave.example.com"), "{message}");
    }
}

#[test]
fn only_https_and_loopback_http_urls_are_accepted() {
    for url in [
        "http://enclave.example.com/v1/models",
        "http://10.0.0.1/v1/models",
        "http://localhost.example.com/",
        "ftp://enclave.example.com/",
        "ws://127.0.0.1/",
    ] {
        let message = refusal(&example(Method::GET, url));
        assert!(message.contains("loopback"), "{url}: {message}");
        assert!(!message.contains("example.com"), "{url}: {message}");
    }
}

#[test]
fn ordinary_requests_pass_the_checks() {
    for url in [
        "https://enclave.example.com/v1/models?limit=2",
        "https://proxy.example.com:8443/v1/models",
        "http://127.0.0.1:8080/v1/models",
        "http://localhost/v1/models",
        "http://[::1]:8080/v1/models",
    ] {
        check_request(&example(Method::GET, url)).expect(url);
    }
    let mut request = post(
        Url::parse("https://enclave.example.com/v1/chat").unwrap(),
        "{}",
    );
    for (name, value) in [
        ("authorization", "Bearer token"),
        ("content-type", "application/json"),
        ("x-tinfoil-enclave-url", "https://enclave.example.com"),
        ("connection", "keep-alive"),
    ] {
        request = with_header(request, name, value);
    }
    check_request(&request).expect("accepted");
}

#[tokio::test]
async fn a_refused_request_is_not_sent_and_starts_no_verification() {
    // The server holds another key than the evidence, so the first request
    // invalidates the verification: a request that passed the checks after
    // it would have to verify again.
    let (attested, held) = (key(1), key(2));
    let server = serve(&held, |_| Reply::ok("unreachable")).await;
    let (script, transport) = transport(vec![evidence("a", Some(&attested.public_hex))]).await;
    let rejected = transport
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect_err("rejected");
    assert_eq!(rejected.key, KeyFailure::Rejected);
    assert_eq!((script.calls(), server.seen().len()), (1, 1));

    let mut refused = vec![
        Request::new(Method::CONNECT, server.url("/")),
        with_header(get(server.url("/v1/realtime")), "upgrade", "websocket"),
        get(Url::parse("http://enclave.example.com/v1/models").unwrap()),
    ];
    let mut with_credentials = server.url("/v1/models");
    with_credentials.set_username("user").unwrap();
    refused.push(get(with_credentials));
    for name in [
        "host",
        "content-length",
        "transfer-encoding",
        "ehbp-encapsulated-key",
        "ehbp-response-nonce",
        "ehbp-other",
    ] {
        refused.push(with_header(post(server.url("/v1/chat"), "{}"), name, "1"));
    }
    for request in refused {
        let what = format!("{} {:?}", request.method(), request.headers());
        let error = ordinary(
            transport.round_trip(request).await,
            ErrorKind::Configuration,
        );
        assert!(!error.to_string().contains("not implemented"), "{what}");
        assert_eq!(script.calls(), 1, "{what}: verified");
        assert_eq!(server.seen().len(), 1, "{what}: sent");
        assert_eq!(server.accepted(), 1, "{what}: connected");
    }
}

// Sealed exchanges.

#[tokio::test]
async fn a_json_body_is_sealed_on_the_wire_and_the_response_is_opened() {
    let key = key(1);
    let server = serve(&key, |seen| {
        let body = String::from_utf8(seen.body.clone()).expect("text");
        Reply::ok(&format!(r#"{{"echo":{body}}}"#))
            .status(201)
            .header("content-type", "application/json")
            .header("x-served-by", "enclave")
    })
    .await;
    let secret = r#"{"prompt":"a secret prompt"}"#;
    let request = with_header(
        with_header(
            post(server.url("/v1/chat?stream=false"), secret),
            "content-type",
            "application/json",
        ),
        "authorization",
        "Bearer token",
    );

    let response = bound(&key).round_trip(request).await.expect("a response");
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["x-served-by"], "enclave");
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(
        response.url().as_str(),
        server.url("/v1/chat?stream=false").as_str()
    );
    assert_eq!(
        text(response).await,
        r#"{"echo":{"prompt":"a secret prompt"}}"#
    );

    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    let seen = &seen[0];
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        ("POST", "/v1/chat?stream=false")
    );
    assert!(seen.sealed);
    assert_eq!(seen.body, secret.as_bytes());
    // The headers travel as they are; only the body is sealed.
    assert_eq!(seen.header("authorization"), Some("Bearer token"));
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.header("ehbp-encapsulated-key").map(str::len), Some(64));
    assert_eq!(seen.header("transfer-encoding"), Some("chunked"));
    assert_eq!(seen.header("content-length"), None);
    let wire = String::from_utf8_lossy(&seen.wire);
    assert!(!wire.contains("secret"), "the body is readable on the wire");
    // One frame: a length, the body and the 16 bytes of its tag.
    assert_eq!(seen.wire.len(), 4 + secret.len() + 16);
}

#[tokio::test]
async fn a_body_longer_than_a_frame_is_sealed_in_several() {
    let key = key(1);
    let server = serve(&key, |seen| Reply::ok(&seen.body.len().to_string())).await;
    let body = vec![b'x'; 3 * tinfoil_ehbp::REQUEST_FRAME_SIZE + 5];

    let response = bound(&key)
        .round_trip(post(server.url("/upload"), body.clone()))
        .await
        .expect("a response");
    assert_eq!(text(response).await, body.len().to_string());
    let seen = &server.seen()[0];
    assert_eq!(seen.body, body);
    assert_eq!(seen.wire.len(), body.len() + 4 * (4 + 16));
}

#[tokio::test]
async fn a_streamed_request_body_is_sealed_frame_by_frame() {
    let key = key(1);
    let server = serve(&key, |_| Reply::ok("done")).await;
    let parts = ["part one, ", "part two"].map(Ok::<_, std::io::Error>);
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(parts));

    let response = bound(&key)
        .round_trip(post(server.url("/upload"), body))
        .await
        .expect("a response");
    assert_eq!(text(response).await, "done");
    let seen = &server.seen()[0];
    assert!(seen.sealed);
    assert_eq!(seen.body, b"part one, part two");
    assert_eq!(seen.wire.len(), seen.body.len() + 2 * (4 + 16));
}

#[tokio::test]
async fn each_request_is_sealed_under_a_fresh_context() {
    let key = key(1);
    let server = serve(&key, |_| Reply::ok("ok")).await;
    let bound = bound(&key);
    for _ in 0..2 {
        let response = bound.round_trip(post(server.url("/"), "same body")).await;
        text(response.expect("a response")).await;
    }
    let seen = server.seen();
    assert_ne!(
        seen[0].header("ehbp-encapsulated-key"),
        seen[1].header("ehbp-encapsulated-key")
    );
    assert_ne!(seen[0].wire, seen[1].wire);
}

#[tokio::test]
async fn a_request_without_a_body_is_sent_and_answered_in_plaintext() {
    let key = key(1);
    let server = serve(&key, |seen| {
        Reply::ok(if seen.sealed { "sealed" } else { "plain" })
    })
    .await;
    let bound = bound(&key);

    let requests = [
        get(server.url("/v1/models")),
        post(server.url("/v1/models"), ""),
        post(server.url("/v1/models"), Vec::new()),
    ];
    for request in requests {
        let response = bound.round_trip(request).await.expect("a response");
        assert_eq!(response.status(), 200);
        assert_eq!(text(response).await, "plain");
    }
    for seen in server.seen() {
        assert!(!seen.sealed);
        assert_eq!(seen.header("ehbp-encapsulated-key"), None);
        assert!(seen.wire.is_empty());
    }
}

#[tokio::test]
async fn a_streamed_response_is_delivered_frame_by_frame_as_it_arrives() {
    let key = key(1);
    let release = Arc::new(Notify::new());
    let gate = Arc::clone(&release);
    let server = serve(&key, move |_| {
        Reply::parts(vec![
            data("data: one\n\n"),
            Part::Wait(Arc::clone(&gate)),
            data("data: two\n\n"),
            data("data: [DONE]\n\n"),
        ])
        .header("content-type", "text/event-stream")
    })
    .await;

    let mut response = tokio::time::timeout(
        PATIENCE,
        bound(&key).round_trip(post(server.url("/v1/chat"), r#"{"stream":true}"#)),
    )
    .await
    .expect("the response waited for its whole body")
    .expect("a response");
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    // The server sends nothing after the first event until it is released,
    // which happens only here, after the first event has been read.
    assert_eq!(
        next_chunk(&mut response).await.expect("first"),
        Some("data: one\n\n".to_owned())
    );
    release.notify_one();
    assert_eq!(
        next_chunk(&mut response).await.expect("second"),
        Some("data: two\n\n".to_owned())
    );
    assert_eq!(
        next_chunk(&mut response).await.expect("third"),
        Some("data: [DONE]\n\n".to_owned())
    );
    assert_eq!(next_chunk(&mut response).await.expect("end"), None);
}

#[tokio::test]
async fn a_sealed_error_response_is_opened_whatever_its_status() {
    let key = key(1);
    let server = serve(&key, |_| Reply::ok("model not found").status(404)).await;
    let response = bound(&key)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect("a response");
    assert_eq!(response.status(), 404);
    assert_eq!(text(response).await, "model not found");
}

// Streams that produce no data.

fn empty_stream() -> reqwest::Body {
    let nothing = [Ok::<_, std::io::Error>(""), Ok("")];
    reqwest::Body::wrap_stream(futures_util::stream::iter(nothing))
}

#[tokio::test]
async fn a_success_to_an_empty_streamed_body_is_refused() {
    let key = key(1);
    for status in [200, 204, 299] {
        let server = serve(&key, move |_| Reply::ok("forged answer").status(status)).await;
        let result = bound(&key)
            .round_trip(post(server.url("/v1/chat"), empty_stream()))
            .await;
        let error = ordinary(result, ErrorKind::Attestation);
        assert!(error.to_string().contains("produced no data"), "{error}");
        assert!(!error.to_string().contains("forged"), "{error}");

        // Nothing was sealed: the request went out without a body.
        let seen = &server.seen()[0];
        assert!(!seen.sealed);
        assert_eq!(seen.header("ehbp-encapsulated-key"), None);
        assert!(seen.wire.is_empty());
    }
}

#[tokio::test]
async fn a_response_nonce_to_an_empty_streamed_body_is_refused() {
    let key = key(1);
    let server = serve(&key, |_| {
        Reply::ok("unopened")
            .status(500)
            .header("Ehbp-Response-Nonce", &"00".repeat(32))
    })
    .await;
    let result = bound(&key)
        .round_trip(post(server.url("/v1/chat"), empty_stream()))
        .await;
    ordinary(result, ErrorKind::Attestation);
}

#[tokio::test]
async fn an_error_to_an_empty_streamed_body_passes_through() {
    let key = key(1);
    let long = format!(
        r#"{{"type":"about:blank","detail":"{}"}}"#,
        "x".repeat(100_000)
    );
    let mismatch = format!(r#"{{"type":"{}"}}"#, tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE);
    let answers = [
        (404, "text/plain", "not found".to_owned()),
        (302, "text/plain", String::new()),
        (
            422,
            "application/json",
            r#"{"detail":"invalid"}"#.to_owned(),
        ),
        (
            422,
            "application/problem+json",
            r#"{"type":"about:blank"}"#.to_owned(),
        ),
        (422, "application/problem+json", "not json".to_owned()),
        // The key-configuration problem under another status or media
        // type.
        (400, "application/problem+json", mismatch.clone()),
        (422, "application/json", mismatch),
        // Longer than a problem that is read.
        (422, "application/problem+json", long),
    ];
    for (status, media_type, body) in answers {
        let answer = body.clone();
        let server = serve(&key, move |_| {
            Reply::ok(&answer)
                .status(status)
                .header("content-type", media_type)
                .header("x-served-by", "proxy")
        })
        .await;
        let response = bound(&key)
            .round_trip(post(server.url("/v1/chat?n=1"), empty_stream()))
            .await
            .expect("an ordinary response");
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["x-served-by"], "proxy");
        assert_eq!(response.url().as_str(), server.url("/v1/chat?n=1").as_str());
        assert_eq!(text(response).await, body, "{status} {media_type}");
    }
}

#[tokio::test]
async fn the_key_configuration_problem_to_an_empty_streamed_body_is_a_key_failure() {
    let key = key(1);
    let server = serve(&key, |_| Reply::key_mismatch()).await;
    let failure = bound(&key)
        .round_trip(post(server.url("/v1/chat"), empty_stream()))
        .await
        .expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
}

#[tokio::test]
async fn a_problem_that_is_no_key_failure_keeps_its_body_after_a_streamed_request() {
    let key = key(1);
    let server = serve(&key, |_| {
        Reply::parts(vec![
            data(r#"{"type":"about:blank","#),
            data(r#""title":"invalid"}"#),
        ])
        .status(422)
        .header("content-type", "application/problem+json")
        .plaintext()
    })
    .await;
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter([Ok::<_, std::io::Error>(
        "data",
    )]));
    let response = bound(&key)
        .round_trip(post(server.url("/v1/chat"), body))
        .await
        .expect("an ordinary response");
    assert!(server.seen()[0].sealed);
    assert_eq!(response.status(), 422);
    assert_eq!(
        text(response).await,
        r#"{"type":"about:blank","title":"invalid"}"#
    );
}

// Responses that are not sealed.

#[tokio::test]
async fn a_plaintext_success_to_a_sealed_request_is_refused() {
    let key = key(1);
    for status in [200, 201, 204, 299] {
        let server = serve(&key, move |_| {
            Reply::ok("forged answer").status(status).plaintext()
        })
        .await;
        let result = bound(&key)
            .round_trip(post(server.url("/v1/chat"), "{}"))
            .await;
        let error = ordinary(result, ErrorKind::Attestation);
        assert_eq!(
            code_of(&error),
            Some(Code::MissingResponseNonce),
            "{status}: {error}"
        );
        assert!(!error.to_string().contains("forged"), "{error}");
        assert_eq!(server.seen().len(), 1);
    }
}

#[tokio::test]
async fn a_plaintext_error_to_a_sealed_request_passes_through() {
    let key = key(1);
    for status in [302, 400, 401, 429, 500, 502] {
        let server = serve(&key, move |_| {
            Reply::ok("bad gateway").status(status).plaintext()
        })
        .await;
        let response = bound(&key)
            .round_trip(post(server.url("/v1/chat"), "{}"))
            .await
            .expect("a response");
        assert_eq!(response.status(), status);
        assert_eq!(text(response).await, "bad gateway");
    }
}

#[tokio::test]
async fn a_response_with_a_bad_nonce_is_refused_whatever_its_status() {
    let key = key(1);
    let nonces: [(fn() -> NonceHeader, Code); 4] = [
        (|| NonceHeader::Invalid("abcd"), Code::InvalidResponseNonce),
        (
            || NonceHeader::Invalid("not hexadecimal"),
            Code::InvalidResponseNonce,
        ),
        (|| NonceHeader::Invalid(""), Code::InvalidResponseNonce),
        (|| NonceHeader::Repeated, Code::DuplicateResponseNonce),
    ];
    for (nonce, code) in nonces {
        for status in [200, 500] {
            let server = serve(&key, move |_| {
                Reply::ok("answer").status(status).nonce(nonce())
            })
            .await;
            let result = bound(&key)
                .round_trip(post(server.url("/v1/chat"), "{}"))
                .await;
            let error = ordinary(result, ErrorKind::Attestation);
            assert_eq!(code_of(&error), Some(code), "{status}: {error}");
        }
    }
}

#[tokio::test]
async fn a_tampered_frame_fails_the_body_and_releases_nothing_after_it() {
    let key = key(1);
    let server = serve(&key, |_| {
        Reply::parts(vec![
            data("authentic"),
            Part::Tampered(b"tampered".to_vec()),
            data("after"),
        ])
    })
    .await;
    let mut response = bound(&key)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect("a response");
    assert_eq!(
        next_chunk(&mut response).await.expect("the first frame"),
        Some("authentic".to_owned())
    );
    let error = next_chunk(&mut response).await.expect_err("tampered");
    assert_eq!(code_of(&error), Some(Code::AeadDecryptFailed), "{error:?}");
    // The stream has ended: the frame after the tampered one never
    // arrives.
    let after = next_chunk(&mut response).await;
    assert!(!matches!(after, Ok(Some(_))), "{after:?}");
}

#[tokio::test]
async fn a_tampered_first_frame_releases_no_plaintext() {
    let key = key(1);
    let server = serve(&key, |_| {
        Reply::parts(vec![Part::Tampered(b"tampered".to_vec())])
    })
    .await;
    let response = bound(&key)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect("a response");
    let error = response.bytes().await.expect_err("tampered");
    assert_eq!(code_of(&error), Some(Code::AeadDecryptFailed), "{error:?}");
}

#[tokio::test]
async fn a_body_that_ends_inside_a_frame_is_an_error_not_a_short_body() {
    let key = key(1);
    let server = serve(&key, |_| {
        Reply::parts(vec![data("whole"), Part::Cut(b"cut short".to_vec())])
    })
    .await;
    let mut response = bound(&key)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect("a response");
    assert_eq!(
        next_chunk(&mut response).await.expect("the first frame"),
        Some("whole".to_owned())
    );
    let error = next_chunk(&mut response).await.expect_err("truncated");
    assert_eq!(code_of(&error), Some(Code::FramingTruncated), "{error:?}");
}

// Key rejection.

#[tokio::test]
async fn a_body_sealed_to_a_key_that_the_peer_lacks_is_a_key_failure() {
    let (attested, held) = (key(1), key(2));
    let server = serve(&held, |_| Reply::ok("unreachable")).await;
    let failure = bound(&attested)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    assert_eq!(code_of(&failure.error), Some(Code::KeyConfigMismatch));
    assert!(
        failure
            .error
            .to_string()
            .contains("does not hold the HPKE key"),
        "{}",
        failure.error
    );
}

#[tokio::test]
async fn only_the_key_configuration_problem_is_a_key_failure() {
    let key = key(1);
    let problem = tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE;
    let mismatch = format!(r#"{{"type":"{problem}"}}"#);
    // The status, the media type and the problem type, each wrong in turn.
    let others: [(u16, &str, String); 6] = [
        (400, "application/problem+json", mismatch.clone()),
        (500, "application/problem+json", mismatch.clone()),
        (422, "application/json", mismatch.clone()),
        (422, "text/plain", mismatch.clone()),
        (
            422,
            "application/problem+json",
            r#"{"type":"about:blank"}"#.to_owned(),
        ),
        (422, "application/problem+json", "not json".to_owned()),
    ];
    for (status, media_type, body) in others {
        let answer = body.clone();
        let server = serve(&key, move |_| {
            Reply::ok(&answer)
                .status(status)
                .header("content-type", media_type)
                .plaintext()
        })
        .await;
        let response = bound(&key)
            .round_trip(post(server.url("/v1/chat"), "{}"))
            .await
            .expect("an ordinary response");
        assert_eq!(response.status(), status);
        assert_eq!(text(response).await, body, "{status} {media_type}");
    }

    // All three right, with parameters on the media type.
    let server = serve(&key, move |_| {
        Reply::ok(&mismatch)
            .status(422)
            .header("content-type", "Application/Problem+JSON; charset=utf-8")
            .plaintext()
    })
    .await;
    let failure = bound(&key)
        .round_trip(post(server.url("/v1/chat"), "{}"))
        .await
        .expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::PeerLacksKey);

    // A request without a body was sealed to no key, so no answer to it
    // says anything about one.
    let response = bound(&key)
        .round_trip(get(server.url("/v1/models")))
        .await
        .expect("an ordinary response");
    assert_eq!(response.status(), 422);
}

#[tokio::test]
async fn a_rejected_request_succeeds_once_more_under_a_new_verification() {
    let (old, new) = (key(1), key(2));
    let server = serve(&new, |seen| {
        Reply::ok(&format!("opened {}", String::from_utf8_lossy(&seen.body)))
    })
    .await;
    let (script, transport) = transport(vec![
        evidence("old", Some(&old.public_hex)),
        evidence("new", Some(&new.public_hex)),
    ])
    .await;
    let request = post(server.url("/v1/chat"), "the body");
    let replay = request.try_clone().expect("a body held in memory");

    let failure = transport.round_trip(request).await.expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::Rejected);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    // The rejection alone verifies nothing.
    assert_eq!(script.calls(), 1);

    let response = transport.round_trip(replay).await.expect("a response");
    assert_eq!(text(response).await, "opened the body");
    assert_eq!(script.calls(), 2);
    assert_eq!(transport.current().name, "new");

    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    assert!(
        !seen[0].sealed,
        "the server opened a body sealed to the old key"
    );
    assert!(seen[1].sealed);
    // The replay went out on a connection of the new binding.
    assert_eq!(server.accepted(), 2);

    // The new verification stays: the next request needs no other.
    let response = transport
        .round_trip(post(server.url("/v1/chat"), "next"))
        .await
        .expect("a response");
    assert_eq!(text(response).await, "opened next");
    assert_eq!((script.calls(), server.accepted()), (2, 2));
}

// The carrier.

#[tokio::test]
async fn a_redirect_is_returned_and_not_followed() {
    let key = key(1);
    let server = serve(&key, |seen| {
        Reply::ok("")
            .status(if seen.method == "GET" { 302 } else { 307 })
            .header("location", "/elsewhere")
    })
    .await;
    let bound = bound(&key);

    for (request, status) in [
        (get(server.url("/v1/models")), 302),
        (post(server.url("/v1/chat"), "{}"), 307),
    ] {
        let response = bound.round_trip(request).await.expect("a response");
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["location"], "/elsewhere");
        text(response).await;
    }
    let targets: Vec<String> = server.seen().into_iter().map(|seen| seen.target).collect();
    assert_eq!(targets, ["/v1/models", "/v1/chat"]);
}

#[tokio::test]
async fn connections_are_reused_within_a_binding_and_not_across_bindings() {
    let key = key(1);
    let server = serve(&key, |_| Reply::ok("ok")).await;
    let mode = mode();
    let first = bind(&mode, Some(&key.public_hex)).expect("bound");
    for request in [
        post(server.url("/a"), "{}"),
        get(server.url("/b")),
        post(server.url("/c"), "{}"),
    ] {
        text(first.round_trip(request).await.expect("a response")).await;
    }
    assert_eq!(server.accepted(), 1);

    // A binding to the same key, as after a new verification.
    let second = bind(&mode, Some(&key.public_hex)).expect("bound");
    for _ in 0..2 {
        text(
            second
                .round_trip(get(server.url("/d")))
                .await
                .expect("a response"),
        )
        .await;
    }
    assert_eq!(server.accepted(), 2);

    // The first binding still has its own connection.
    text(
        first
            .round_trip(get(server.url("/e")))
            .await
            .expect("a response"),
    )
    .await;
    assert_eq!(server.accepted(), 2);
    assert_eq!(server.seen().len(), 6);
}

#[tokio::test]
async fn dropping_a_response_in_the_middle_of_its_body_leaves_the_binding_usable() {
    let key = key(1);
    let never = Arc::new(Notify::new());
    let gate = Arc::clone(&never);
    let server = serve(&key, move |seen| {
        if seen.target == "/stream" {
            Reply::parts(vec![
                data("first"),
                Part::Wait(Arc::clone(&gate)),
                data("never"),
            ])
        } else {
            Reply::ok("whole")
        }
    })
    .await;
    let bound = bound(&key);

    let mut response = bound
        .round_trip(post(server.url("/stream"), "{}"))
        .await
        .expect("a response");
    assert_eq!(
        next_chunk(&mut response).await.expect("first"),
        Some("first".to_owned())
    );
    drop(response);

    for _ in 0..2 {
        let response =
            tokio::time::timeout(PATIENCE, bound.round_trip(post(server.url("/next"), "{}")))
                .await
                .expect("the binding is stuck")
                .expect("a response");
        assert_eq!(text(response).await, "whole");
    }
    // The abandoned connection is not reused; the one after it is.
    assert_eq!(server.accepted(), 2);
}

#[tokio::test]
async fn dropping_a_request_before_its_response_leaves_the_binding_usable() {
    let key = key(1);
    let arrived = Arc::new(Notify::new());
    let never = Arc::new(Notify::new());
    let (signal, gate) = (Arc::clone(&arrived), Arc::clone(&never));
    let server = serve(&key, move |seen| {
        if seen.target == "/slow" {
            signal.notify_one();
            Reply::never(&gate)
        } else {
            Reply::ok("whole")
        }
    })
    .await;
    let bound = bound(&key);

    // The request is dropped while it waits for a response that the server
    // has not started.
    let slow = bound.round_trip(post(server.url("/slow"), "{}"));
    tokio::select! {
        result = slow => panic!("the server never answers: {result:?}"),
        () = arrived.notified() => {}
    }

    for _ in 0..2 {
        let response =
            tokio::time::timeout(PATIENCE, bound.round_trip(post(server.url("/next"), "{}")))
                .await
                .expect("the binding is stuck")
                .expect("a response");
        assert_eq!(text(response).await, "whole");
    }
    assert_eq!(server.accepted(), 2);
}

/// A listener that stands for a forward proxy: it answers every request
/// with `502`, and its server records what it received.
async fn proxy() -> (reqwest::Proxy, Server) {
    let listener = serve(&key(9), |_| Reply::ok("").status(502)).await;
    let origin = listener.url.origin().ascii_serialization();
    (reqwest::Proxy::all(origin).expect("proxy"), listener)
}

#[tokio::test]
async fn a_loopback_request_connects_directly_whatever_the_proxy_settings() {
    let key = key(1);
    let (proxy, listener) = proxy().await;
    let server = serve(&key, |_| Reply::ok("direct")).await;
    let mode = EhbpMode { proxy: Some(proxy) };
    let bound = bind(&mode, Some(&key.public_hex)).expect("bound");

    for request in [
        get(server.url("/v1/models?key=secret")),
        with_header(
            post(server.url("/v1/chat"), "{}"),
            "authorization",
            "Bearer token",
        ),
    ] {
        let response = bound.round_trip(request).await.expect("a response");
        assert_eq!(text(response).await, "direct");
    }
    assert_eq!(server.seen().len(), 2);
    assert_eq!(listener.accepted(), 0, "{:?}", listener.seen());
}

#[tokio::test]
async fn a_request_to_another_host_goes_through_the_proxy() {
    let key = key(1);
    let (proxy, listener) = proxy().await;
    let mode = EhbpMode { proxy: Some(proxy) };
    let bound = bind(&mode, Some(&key.public_hex)).expect("bound");

    // The proxy refuses the tunnel, so nothing leaves the machine.
    let url = Url::parse("https://enclave.example.com/v1/models").unwrap();
    let result = bound.round_trip(get(url)).await;
    ordinary(result, ErrorKind::Network);
    assert_eq!(listener.accepted(), 1);
    let seen = &listener.seen()[0];
    assert_eq!(
        (seen.method.as_str(), seen.target.as_str()),
        ("CONNECT", "enclave.example.com:443")
    );
}

#[tokio::test]
async fn a_connection_failure_is_a_network_error_that_does_not_repeat_the_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let url = Url::parse(&format!("http://{address}/v1/chat?key=hunter2")).unwrap();

    let result = bound(&key(1)).round_trip(post(url, "{}")).await;
    let error = ordinary(result, ErrorKind::Network);
    assert!(!error.is_timeout());
    assert!(
        !format!("{error} {error:?}").contains("hunter2"),
        "{error:?}"
    );
}

// Time is paused, and advances by itself to the request's deadline once
// nothing else can run: the server never answers.
#[tokio::test(start_paused = true)]
async fn a_request_timeout_is_a_network_error_marked_as_a_timeout() {
    let key = key(1);
    let never = Arc::new(Notify::new());
    let gate = Arc::clone(&never);
    let server = serve(&key, move |_| Reply::never(&gate)).await;
    let mut request = post(server.url("/v1/chat"), "{}");
    *request.timeout_mut() = Some(Duration::from_secs(5));
    let result = bound(&key).round_trip(request).await;
    let error = ordinary(result, ErrorKind::Network);
    assert!(error.is_timeout(), "{error:?}");
}
