//! The whole client on evidence that a test can build: first on a mode
//! that answers from a script, under Tokio's paused time, and then on the
//! two real modes against local servers.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, Request, Response, Url};
use tokio::sync::Notify;

use super::{AttestedClient, Settings};
use crate::error::{Error, ErrorKind};
use crate::internal::enclave::{Config, Enclave, Fetch};
use crate::internal::testing::{EPOCH, Record, Script, Step, record, tokio_clock};
use crate::internal::transport::{Failure, Mode, RoundTrip, Transport};
use crate::internal::{BoxFuture, Clock};
use crate::options::{Secret, TransportMode};
use crate::request::{Execute, RequestBuilder, into_url};

const HOUR: Duration = Duration::from_secs(3600);
const ENCLAVE: &str = "enclave.example.com";

/// The longest that a test waits, on Tokio's time. With real sockets it
/// turns a hang into a failure; under paused time it is reached only when
/// nothing else can make progress, which is a hang too.
const PATIENCE: Duration = Duration::from_secs(20);

async fn soon<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("the operation neither succeeded nor failed in time")
}

type Client = Arc<AttestedClient<Record>>;

fn start(client: &Client, method: Method, url: &str) -> RequestBuilder {
    let executor: Arc<dyn Execute> = client.clone();
    RequestBuilder::new(executor, method, into_url(url))
}

fn get(client: &Client, url: &str) -> RequestBuilder {
    start(client, Method::GET, url)
}

fn post(client: &Client, url: &str) -> RequestBuilder {
    start(client, Method::POST, url)
}

/// A body that is a stream of `chunks`.
fn stream(chunks: &[&'static str]) -> reqwest::Body {
    let chunks: Vec<_> = chunks.iter().map(|c| Ok::<_, std::io::Error>(*c)).collect();
    reqwest::Body::wrap_stream(futures_util::stream::iter(chunks))
}

fn settings() -> Settings {
    Settings {
        mode: TransportMode::Tls,
        base_url: None,
        secret: None,
        timeout: None,
    }
}

fn with_timeout(timeout: Duration) -> Settings {
    Settings {
        timeout: Some(timeout),
        ..settings()
    }
}

/// The chain of earlier attempts behind `error`, itself first.
fn attempts(error: &Error) -> Vec<String> {
    std::iter::successors(Some(error), |error| error.earlier_attempt())
        .map(Error::to_string)
        .collect()
}

// The scripted mode.

/// One request as a binding of the scripted mode received it.
#[derive(Clone, Debug)]
struct Sent {
    /// The name of the evidence that the binding was made for.
    binding: &'static str,
    method: Method,
    url: Url,
    headers: HeaderMap,
    /// The body, when it is held in memory.
    body: Option<Vec<u8>>,
    streamed: bool,
    timeout: Option<Duration>,
}

impl Sent {
    fn text(&self) -> &str {
        std::str::from_utf8(self.body.as_deref().unwrap_or_default()).unwrap()
    }
}

/// What a binding of the scripted mode answers.
enum Answer {
    /// A response with this body.
    Text(&'static str),
    /// The peer does not hold the binding's keys.
    LacksKey,
    /// A failure that says nothing about the keys.
    Fail(Error),
    /// No answer, ever.
    Never,
    /// The answer, after this much time.
    After(Duration, Box<Answer>),
    /// A response whose body delivers this text and then never ends.
    Stalling(&'static str),
    /// A response whose body delivers this text and then fails with the
    /// sealed-body protocol's error for a frame that does not open.
    Tampered(&'static str),
}

type Answers = Arc<dyn Fn(&Sent) -> Answer + Send + Sync>;

struct Scripted {
    answers: Answers,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl Mode<Record> for Scripted {
    fn validate_request(&self, request: &Request) -> Result<(), Error> {
        if request.method() == Method::CONNECT {
            return Err(Error::configuration("the mode cannot protect CONNECT"));
        }
        Ok(())
    }

    fn bind(&self, evidence: &Record) -> Result<Arc<dyn RoundTrip>, Error> {
        Ok(Arc::new(Binding {
            name: evidence.name,
            answers: Arc::clone(&self.answers),
            sent: Arc::clone(&self.sent),
        }))
    }
}

struct Binding {
    name: &'static str,
    answers: Answers,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl RoundTrip for Binding {
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        let sent = Sent {
            binding: self.name,
            method: request.method().clone(),
            url: request.url().clone(),
            headers: request.headers().clone(),
            body: request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .map(<[u8]>::to_vec),
            streamed: request.body().is_some_and(|b| b.as_bytes().is_none()),
            timeout: request.timeout().copied(),
        };
        let mut answer = (self.answers)(&sent);
        self.sent.lock().unwrap().push(sent);
        Box::pin(async move {
            loop {
                match answer {
                    Answer::Text(text) => return Ok(Response::from(http::Response::new(text))),
                    Answer::LacksKey => {
                        return Err(Failure::peer_lacks_key(Error::attestation(
                            "the peer does not hold the attested key",
                        )));
                    }
                    Answer::Fail(error) => return Err(error.into()),
                    Answer::Never => std::future::pending::<()>().await,
                    Answer::After(delay, then) => {
                        tokio::time::sleep(delay).await;
                        answer = *then;
                    }
                    Answer::Stalling(text) => {
                        let body = futures_util::stream::iter([Ok::<_, std::io::Error>(text)])
                            .chain(futures_util::stream::pending());
                        return Ok(Response::from(http::Response::new(
                            reqwest::Body::wrap_stream(body),
                        )));
                    }
                    Answer::Tampered(text) => {
                        let body = futures_util::stream::iter([
                            Ok(text),
                            Err(tinfoil_ehbp::Error::Coded(
                                tinfoil_ehbp::Code::AeadDecryptFailed,
                                "frame 1".to_owned(),
                            )),
                        ]);
                        return Ok(Response::from(http::Response::new(
                            reqwest::Body::wrap_stream(body),
                        )));
                    }
                }
            }
        })
    }
}

/// A client on the scripted mode.
struct Fake {
    script: Arc<Script>,
    client: Client,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl Fake {
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
    fn bindings(&self) -> Vec<&'static str> {
        self.sent().iter().map(|sent| sent.binding).collect()
    }
}

/// A client for [`ENCLAVE`] whose verifications play `steps` (the first
/// connects it) and whose bindings answer with `answers`.
async fn fake(
    steps: Vec<Step>,
    settings: Settings,
    answers: impl Fn(&Sent) -> Answer + Send + Sync + 'static,
) -> Fake {
    let script = Script::new(steps);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mode = Scripted {
        answers: Arc::new(answers),
        sent: Arc::clone(&sent),
    };
    let enclave = Enclave::from_source(ENCLAVE, script.source(), None, tokio_clock());
    let transport = Transport::connect(enclave, Arc::new(mode), true)
        .await
        .expect("connected");
    let client = Arc::new(AttestedClient::new(transport, settings).expect("a client"));
    Fake {
        script,
        client,
        sent,
    }
}

fn ready(name: &'static str) -> Step {
    Step::Ready(Ok(record(name, &tokio_clock(), HOUR)))
}

/// Evidence for a later verification. The evidence is made when the script
/// is, so it is given a life that outlasts the test's own steps in time.
fn later(name: &'static str) -> Step {
    Step::Ready(Ok(record(name, &tokio_clock(), 100 * HOUR)))
}

/// Evidence named `name`, once `gate` is signalled.
fn gated(name: &'static str, gate: &Arc<Notify>) -> Step {
    // The evidence is made when the script is, so it is given a long life.
    Step::Gated(
        Arc::clone(gate),
        Ok(record(name, &tokio_clock(), 10 * HOUR)),
    )
}

/// Lets the tasks that are ready run, without moving the paused time.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

// The accessors.

#[tokio::test(start_paused = true)]
async fn the_client_reports_its_route_and_its_last_verification() {
    let f = fake(vec![ready("first"), later("second")], settings(), |_| {
        Answer::Text("ok")
    })
    .await;
    assert_eq!(f.client.enclave(), ENCLAVE);
    assert_eq!(f.client.repo(), None);
    assert_eq!(f.client.transport_mode(), TransportMode::Tls);
    assert_eq!(f.client.base_url().as_str(), "https://enclave.example.com/");
    assert_eq!(
        f.client.openai_url().as_str(),
        "https://enclave.example.com/v1/"
    );
    assert_eq!(f.client.current().name, "first");
    assert_eq!(f.client.ensure_verified().await.unwrap().name, "first");
    assert_eq!(f.script.calls(), 1);
    assert_eq!(f.client.reverify().await.unwrap().name, "second");
    assert_eq!(f.client.current().name, "second");
}

#[tokio::test(start_paused = true)]
async fn a_base_url_replaces_the_enclaves_origin_for_both_urls() {
    let base = Url::parse("https://enclave.example.com/prefix/").unwrap();
    let f = fake(
        vec![ready("first")],
        Settings {
            base_url: Some(base.clone()),
            ..settings()
        },
        |_| Answer::Text("ok"),
    )
    .await;
    assert_eq!(f.client.base_url(), &base);
    assert_eq!(f.client.openai_url(), &base);
}

#[tokio::test(start_paused = true)]
async fn a_pinned_client_takes_no_base_url_on_another_origin() {
    let script = Script::new([ready("first")]);
    let mode = Scripted {
        answers: Arc::new(|_| Answer::Text("ok")),
        sent: Arc::default(),
    };
    let enclave = Enclave::from_source(ENCLAVE, script.source(), None, tokio_clock());
    let transport = Transport::connect(enclave, Arc::new(mode), true)
        .await
        .unwrap();
    let proxy = || Some(Url::parse("https://proxy.example.com/").unwrap());
    let error = AttestedClient::new(
        transport.clone(),
        Settings {
            base_url: proxy(),
            ..settings()
        },
    )
    .err()
    .expect("a proxy needs sealed bodies");
    assert_eq!(error.kind(), ErrorKind::Configuration);
    assert!(error.to_string().contains("TransportMode::Ehbp"), "{error}");

    AttestedClient::new(
        transport,
        Settings {
            mode: TransportMode::Ehbp,
            base_url: proxy(),
            ..settings()
        },
    )
    .expect("the sealed mode goes through a proxy");
}

// The origin restriction.

#[tokio::test(start_paused = true)]
async fn a_request_to_another_origin_is_refused_and_starts_no_verification() {
    let f = fake(vec![ready("first")], settings(), |_| Answer::Text("ok")).await;
    // The verification has expired, so a request that got past the guard
    // would start one.
    tokio::time::advance(2 * HOUR).await;
    for url in [
        "https://evil.example.com/v1/models",
        "https://sub.enclave.example.com/",
        "https://enclave.example.com.evil.example/",
        "https://enclave.example.com:8443/",
        "http://enclave.example.com/",
        "http://enclave.example.com:443/",
        "https://enclave.example.com@evil.example/",
        "https://evil.example/https://enclave.example.com/",
        "ftp://enclave.example.com/",
    ] {
        let error = get(&f.client, url)
            .header("authorization", "Bearer secret")
            .send()
            .await
            .expect_err(url);
        assert_eq!(error.kind(), ErrorKind::Configuration, "{url}: {error}");
        assert!(error.to_string().contains("refusing to send"), "{error}");
        assert!(!error.to_string().contains("secret"), "{error}");
    }
    assert_eq!(f.script.calls(), 1);
    assert!(f.sent().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_request_to_the_clients_origin_passes_whatever_its_spelling_or_path() {
    let f = fake(vec![ready("first")], settings(), |_| Answer::Text("ok")).await;
    for url in [
        "https://enclave.example.com/",
        "https://enclave.example.com:443/v1/models",
        "HTTPS://ENCLAVE.example.COM/anything/else?x=1",
    ] {
        get(&f.client, url).send().await.expect(url);
    }
    assert_eq!(f.sent().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn with_a_proxy_both_the_proxy_and_the_enclave_are_the_clients_origins() {
    let f = fake(
        vec![ready("first")],
        Settings {
            mode: TransportMode::Ehbp,
            base_url: Some(Url::parse("https://proxy.example.com/tinfoil/").unwrap()),
            ..settings()
        },
        |_| Answer::Text("ok"),
    )
    .await;
    // The path of the base URL is where requests are meant to go, and not
    // a limit on where they may go.
    for url in [
        "https://proxy.example.com/tinfoil/v1/models",
        "https://proxy.example.com/elsewhere",
        "https://enclave.example.com/v1/models",
    ] {
        get(&f.client, url).send().await.expect(url);
    }
    let error = get(&f.client, "https://other.example.com/tinfoil/")
        .send()
        .await
        .expect_err("another origin");
    assert_eq!(error.kind(), ErrorKind::Configuration);
    assert_eq!(f.sent().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_request_that_the_mode_cannot_protect_starts_no_verification() {
    let f = fake(vec![ready("first")], settings(), |_| Answer::Text("ok")).await;
    tokio::time::advance(2 * HOUR).await;
    let error = start(&f.client, Method::CONNECT, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("refused");
    assert_eq!(error.kind(), ErrorKind::Configuration);
    assert_eq!(f.script.calls(), 1);
}

// The enclave header.

#[tokio::test(start_paused = true)]
async fn requests_through_a_proxy_name_the_enclave_and_others_do_not() {
    let proxied = fake(
        vec![ready("first")],
        Settings {
            mode: TransportMode::Ehbp,
            base_url: Some(Url::parse("https://proxy.example.com/").unwrap()),
            ..settings()
        },
        |_| Answer::Text("ok"),
    )
    .await;
    get(&proxied.client, "https://proxy.example.com/a")
        .send()
        .await
        .unwrap();
    // A value from the caller is replaced.
    get(&proxied.client, "https://proxy.example.com/b")
        .header("X-Tinfoil-Enclave-Url", "https://evil.example.com")
        .send()
        .await
        .unwrap();
    for sent in proxied.sent() {
        let values: Vec<_> = sent
            .headers
            .get_all("x-tinfoil-enclave-url")
            .iter()
            .collect();
        assert_eq!(values, ["https://enclave.example.com"], "{}", sent.url);
    }

    let direct = fake(vec![ready("first")], settings(), |_| Answer::Text("ok")).await;
    get(&direct.client, "https://enclave.example.com/a")
        .send()
        .await
        .unwrap();
    assert!(
        !direct.sent()[0]
            .headers
            .contains_key("x-tinfoil-enclave-url")
    );
}

// The replay.

#[tokio::test(start_paused = true)]
async fn a_key_rejection_is_healed_by_one_replay_under_a_new_verification() {
    let f = fake(
        vec![ready("before"), later("after")],
        settings(),
        |sent| match sent.binding {
            "before" => Answer::LacksKey,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    let response = post(&f.client, "https://enclave.example.com/v1/x")
        .header("x-request", "1")
        .body("payload")
        .send()
        .await
        .expect("healed");
    assert_eq!(response.text().await.unwrap(), "ok");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.bindings(), ["before", "after"]);
    // The replay is the same request.
    let sent = f.sent();
    assert_eq!(sent[1].text(), "payload");
    assert_eq!(sent[1].headers.get("x-request").unwrap(), "1");
    assert_eq!(sent[1].method, Method::POST);
    assert_eq!(f.client.current().name, "after");
}

#[tokio::test(start_paused = true)]
async fn a_request_without_a_body_is_replayed_too() {
    let f = fake(
        vec![ready("before"), later("after")],
        settings(),
        |sent| match sent.binding {
            "before" => Answer::LacksKey,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("healed");
    assert_eq!(f.bindings(), ["before", "after"]);
}

#[tokio::test(start_paused = true)]
async fn a_streamed_body_is_not_replayed_and_the_rejection_is_reported() {
    let f = fake(
        vec![ready("before"), later("after")],
        settings(),
        |sent| match sent.binding {
            "before" => Answer::LacksKey,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    let error = post(&f.client, "https://enclave.example.com/v1/x")
        .body(stream(&["pay", "load"]))
        .send()
        .await
        .expect_err("a stream cannot be sent again");
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert_eq!(
        attempts(&error),
        [
            "attestation error: cannot send the request again after the enclave's key changed: \
             its body is a stream, which cannot be replayed",
            "attestation error: the peer does not hold the attested key",
        ]
    );
    // Nothing was sent again, and nothing was verified for a replay.
    assert_eq!(f.bindings(), ["before"]);
    assert_eq!(f.script.calls(), 1);

    // The rejection stands: the next request verifies first.
    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("under the new verification");
    assert_eq!(f.bindings(), ["before", "after"]);
    assert_eq!(f.script.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn there_is_one_replay_and_its_failure_carries_the_rejection() {
    // The new verification's keys are rejected as well.
    let f = fake(
        vec![ready("first"), later("second"), later("third")],
        settings(),
        |sent| match sent.binding {
            "third" => Answer::Text("ok"),
            _ => Answer::LacksKey,
        },
    )
    .await;
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("the replay failed");
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert_eq!(attempts(&error).len(), 2);
    assert_eq!(f.bindings(), ["first", "second"]);
    assert_eq!(f.script.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_replay_whose_verification_fails_reports_every_attempt() {
    let f = fake(
        vec![
            ready("first"),
            Step::Ready(Err(Error::network("fetch 1"))),
            Step::Ready(Err(Error::attestation("fetch 2"))),
        ],
        settings(),
        |_| Answer::LacksKey,
    )
    .await;
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("no new verification");
    assert_eq!(
        attempts(&error),
        [
            "attestation error: fetch 2",
            "network error: fetch 1",
            "attestation error: the peer does not hold the attested key",
        ]
    );
    assert_eq!(f.bindings(), ["first"]);
}

#[tokio::test(start_paused = true)]
async fn a_failure_that_is_no_key_rejection_is_not_replayed() {
    let f = fake(vec![ready("first"), later("second")], settings(), |_| {
        Answer::Fail(Error::network("connection reset"))
    })
    .await;
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("failed");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(error.earlier_attempt().is_none());
    assert_eq!(f.bindings(), ["first"]);
    assert_eq!(f.script.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_replay_layer_trusts_only_a_rejection_that_the_transport_vouches_for() {
    use crate::internal::transport::KeyFailure;
    use crate::internal::transport::replay::with_replay;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Claims(KeyFailure, Arc<AtomicUsize>);
    impl RoundTrip for Claims {
        fn round_trip(&self, _: Request) -> BoxFuture<Result<Response, Failure>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            let key = self.0;
            Box::pin(async move {
                Err(Failure {
                    error: Error::attestation("claimed"),
                    key,
                })
            })
        }
    }
    let request = || Request::new(Method::GET, Url::parse("https://e.example/").unwrap());
    for (claim, sends) in [
        (KeyFailure::None, 1),
        (KeyFailure::PeerLacksKey, 1),
        (KeyFailure::Rejected, 2),
    ] {
        let count = Arc::new(AtomicUsize::new(0));
        let chain = with_replay(Arc::new(Claims(claim, Arc::clone(&count))));
        let failure = chain.round_trip(request()).await.unwrap_err();
        assert_eq!(count.load(Ordering::SeqCst), sends, "{claim:?}");
        if claim == KeyFailure::Rejected {
            // The failed replay asks for no further replay.
            assert_eq!(failure.key, KeyFailure::None);
        } else {
            assert_eq!(failure.key, claim);
        }
    }
}

// The cache secret.

fn with_secret(secret: &str) -> Settings {
    Settings {
        secret: Some(Secret::new(secret)),
        ..settings()
    }
}

#[tokio::test(start_paused = true)]
async fn the_secret_is_added_to_the_bodies_that_carry_it_and_to_no_other() {
    let f = fake(vec![ready("first")], with_secret("s3cret"), |_| {
        Answer::Text("ok")
    })
    .await;
    let cases = [
        (
            "https://enclave.example.com/v1/chat/completions",
            r#"{"model":"m","seed":12345678901234567890}"#,
            r#"{"model":"m","seed":12345678901234567890,"user_cache_secret":"s3cret"}"#,
        ),
        (
            "https://enclave.example.com/v1/responses?stream=true",
            r#"{"user_cache_secret":""}"#,
            r#"{"user_cache_secret":"s3cret"}"#,
        ),
        (
            "https://enclave.example.com/v1/completions",
            r#"{"user_cache_secret":"per-user"}"#,
            r#"{"user_cache_secret":"per-user"}"#,
        ),
        (
            "https://enclave.example.com/v1/chat/completions",
            "not json",
            "not json",
        ),
        (
            "https://enclave.example.com/v1/embeddings",
            r#"{"model":"m"}"#,
            r#"{"model":"m"}"#,
        ),
    ];
    for (url, body, _) in cases {
        post(&f.client, url).body(body).send().await.expect(url);
    }
    let sent = f.sent();
    for (sent, (url, _, expected)) in sent.iter().zip(cases) {
        assert_eq!(sent.text(), expected, "{url}");
    }
}

#[tokio::test(start_paused = true)]
async fn without_the_option_no_body_is_changed() {
    let f = fake(vec![ready("first")], settings(), |_| Answer::Text("ok")).await;
    post(&f.client, "https://enclave.example.com/v1/chat/completions")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(f.sent()[0].text(), "{}");
}

#[tokio::test(start_paused = true)]
async fn a_streamed_body_is_read_and_gets_the_secret_too() {
    let f = fake(vec![ready("first")], with_secret("s3cret"), |_| {
        Answer::Text("ok")
    })
    .await;
    let url = "https://enclave.example.com/v1/chat/completions";
    post(&f.client, url)
        .body(stream(&[r#"{"mod"#, r#"el":"m"}"#]))
        .send()
        .await
        .unwrap();
    post(&f.client, url)
        .body(stream(&["not ", "json"]))
        .send()
        .await
        .unwrap();
    // A stream to another endpoint stays a stream.
    post(&f.client, "https://enclave.example.com/v1/files")
        .body(stream(&["{}"]))
        .send()
        .await
        .unwrap();
    let sent = f.sent();
    assert_eq!(
        sent[0].text(),
        r#"{"model":"m","user_cache_secret":"s3cret"}"#
    );
    assert_eq!(sent[1].text(), "not json");
    assert!(sent[2].streamed);
}

#[tokio::test(start_paused = true)]
async fn a_streamed_body_that_fails_is_a_network_error_and_nothing_is_sent() {
    let f = fake(vec![ready("first")], with_secret("s3cret"), |_| {
        Answer::Text("ok")
    })
    .await;
    let broken = futures_util::stream::iter([
        Ok("{"),
        Err(std::io::Error::other("the caller's stream broke")),
    ]);
    let error = post(&f.client, "https://enclave.example.com/v1/chat/completions")
        .body(reqwest::Body::wrap_stream(broken))
        .send()
        .await
        .expect_err("the body could not be read");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(f.sent().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_declared_length_follows_the_body_and_a_replay_carries_the_secret() {
    let f = fake(
        vec![ready("before"), later("after")],
        with_secret("s3cret"),
        |sent| match sent.binding {
            "before" => Answer::LacksKey,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    post(&f.client, "https://enclave.example.com/v1/chat/completions")
        .header("content-length", "2")
        .body("{}")
        .send()
        .await
        .expect("healed");
    let expected = r#"{"user_cache_secret":"s3cret"}"#;
    for sent in f.sent() {
        assert_eq!(sent.text(), expected, "{}", sent.binding);
        assert_eq!(
            sent.headers.get("content-length"),
            Some(&HeaderValue::from(expected.len()))
        );
    }
    assert_eq!(f.bindings(), ["before", "after"]);
}

// Freshness.

#[tokio::test(start_paused = true)]
async fn a_request_at_the_freshness_deadline_verifies_first_and_one_before_it_does_not() {
    let f = fake(vec![ready("first"), later("second")], settings(), |_| {
        Answer::Text("ok")
    })
    .await;
    let url = "https://enclave.example.com/";
    tokio::time::advance(HOUR - Duration::from_micros(1)).await;
    get(&f.client, url).send().await.unwrap();
    assert_eq!(f.script.calls(), 1);

    tokio::time::advance(Duration::from_micros(1)).await;
    get(&f.client, url).send().await.unwrap();
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.bindings(), ["first", "second"]);

    // The new verification serves the requests that follow.
    get(&f.client, url).send().await.unwrap();
    assert_eq!(f.script.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_failed_reverification_fails_the_request_and_sends_nothing() {
    let f = fake(
        vec![
            ready("first"),
            Step::Ready(Err(Error::network("unreachable"))),
            Step::Ready(Err(Error::network("still unreachable"))),
            later("later"),
        ],
        settings(),
        |_| Answer::Text("ok"),
    )
    .await;
    tokio::time::advance(HOUR).await;
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("not verified");
    assert_eq!(error.kind(), ErrorKind::Network);
    assert!(f.sent().is_empty());
    // The last verification is still what the client reports.
    assert_eq!(f.client.current().name, "first");

    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("verified by the next request");
    assert_eq!(f.bindings(), ["later"]);
}

// Concurrency.

#[tokio::test(start_paused = true)]
async fn requests_that_are_rejected_together_share_one_verification() {
    let gate = Arc::new(Notify::new());
    let f = fake(
        vec![ready("before"), gated("after", &gate)],
        settings(),
        |sent| match sent.binding {
            // Slow enough for every request to be under way before the
            // first rejection.
            "before" => Answer::After(Duration::from_secs(1), Box::new(Answer::LacksKey)),
            _ => Answer::Text("ok"),
        },
    )
    .await;
    let requests: Vec<_> = (0..8)
        .map(|_| {
            let client = Arc::clone(&f.client);
            tokio::spawn(async move {
                post(&client, "https://enclave.example.com/v1/x")
                    .body("payload")
                    .send()
                    .await
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_secs(2)).await;
    // Every request was rejected and now waits for the one verification.
    assert_eq!(f.bindings(), ["before"; 8]);
    assert_eq!(f.script.calls(), 2);
    gate.notify_one();
    for request in requests {
        soon(request).await.unwrap().expect("healed");
    }
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.sent().len(), 16);
    assert!(f.bindings()[8..].iter().all(|name| *name == "after"));
}

#[tokio::test(start_paused = true)]
async fn a_late_rejection_of_a_replaced_verification_starts_no_new_one() {
    // One request is answered slowly by the old binding, and is rejected
    // only after another request has already brought a new verification.
    let f = fake(
        vec![ready("before"), later("after"), later("unneeded")],
        settings(),
        |sent| match (sent.binding, sent.url.path()) {
            ("before", "/slow") => {
                Answer::After(Duration::from_secs(5), Box::new(Answer::LacksKey))
            }
            ("before", _) => Answer::LacksKey,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    let slow = {
        let client = Arc::clone(&f.client);
        tokio::spawn(async move {
            get(&client, "https://enclave.example.com/slow")
                .send()
                .await
        })
    };
    settle().await;
    get(&f.client, "https://enclave.example.com/fast")
        .send()
        .await
        .expect("healed");
    assert_eq!(f.script.calls(), 2);
    soon(slow)
        .await
        .unwrap()
        .expect("replayed under the newer verification");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.client.current().name, "after");
}

// Deadlines.

fn assert_deadline(error: &Error) {
    assert_eq!(error.kind(), ErrorKind::Network, "{error}");
    assert!(error.is_timeout(), "{error}");
}

#[tokio::test(start_paused = true)]
async fn a_response_that_does_not_arrive_within_the_clients_timeout_is_a_timeout() {
    let f = fake(
        vec![ready("first")],
        with_timeout(Duration::from_secs(5)),
        |sent| match sent.url.path() {
            "/never" => Answer::Never,
            _ => Answer::After(Duration::from_millis(4_999), Box::new(Answer::Text("ok"))),
        },
    )
    .await;
    let started = tokio::time::Instant::now();
    let error = get(&f.client, "https://enclave.example.com/never")
        .send()
        .await
        .expect_err("no response");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(5));

    // Just inside the deadline is in time.
    get(&f.client, "https://enclave.example.com/slow")
        .send()
        .await
        .expect("in time");
}

#[tokio::test(start_paused = true)]
async fn a_requests_own_timeout_replaces_the_clients_in_either_direction() {
    let f = fake(
        vec![ready("first")],
        with_timeout(Duration::from_secs(5)),
        |sent| match sent.url.path() {
            "/never" => Answer::Never,
            _ => Answer::After(Duration::from_secs(60), Box::new(Answer::Text("ok"))),
        },
    )
    .await;
    let started = tokio::time::Instant::now();
    let error = get(&f.client, "https://enclave.example.com/never")
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .expect_err("no response");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(2));

    get(&f.client, "https://enclave.example.com/slow")
        .timeout(Duration::from_secs(61))
        .send()
        .await
        .expect("the longer deadline of the request applies");

    // The layers below never apply a deadline of their own.
    assert!(f.sent().iter().all(|sent| sent.timeout.is_none()));
}

#[tokio::test(start_paused = true)]
async fn without_a_timeout_a_slow_response_is_waited_for() {
    let f = fake(vec![ready("first")], settings(), |_| {
        Answer::After(Duration::from_secs(1_800), Box::new(Answer::Text("ok")))
    })
    .await;
    let response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("no deadline");
    assert_eq!(response.text().await.unwrap(), "ok");
}

#[tokio::test(start_paused = true)]
async fn the_deadline_covers_the_wait_for_a_verification() {
    let gate = Arc::new(Notify::new());
    let f = fake(
        vec![ready("first"), gated("stuck", &gate), later("third")],
        with_timeout(Duration::from_secs(5)),
        |_| Answer::Text("ok"),
    )
    .await;
    tokio::time::advance(HOUR).await;
    let started = tokio::time::Instant::now();
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("the verification did not finish");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(f.script.calls(), 2);
    assert!(f.sent().is_empty());

    // Nobody waits for the verification any more, so it was dropped, and
    // the next request starts one.
    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("verified again");
    assert_eq!(f.script.calls(), 3);
    assert_eq!(f.client.current().name, "third");
}

#[tokio::test(start_paused = true)]
async fn the_deadline_covers_the_verification_and_the_replay_after_a_rejection() {
    let f = fake(
        vec![
            ready("before"),
            Step::After(
                Duration::from_secs(3),
                Ok(record("after", &tokio_clock(), HOUR)),
            ),
        ],
        with_timeout(Duration::from_secs(5)),
        |sent| match sent.binding {
            "before" => Answer::After(Duration::from_secs(1), Box::new(Answer::LacksKey)),
            _ => Answer::Never,
        },
    )
    .await;
    let started = tokio::time::Instant::now();
    let error = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect_err("out of time during the replay");
    assert_deadline(&error);
    // One deadline from the start, not one for each attempt.
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(f.bindings(), ["before", "after"]);
}

#[tokio::test(start_paused = true)]
async fn the_deadline_covers_the_read_of_the_body_counted_from_the_send() {
    let f = fake(
        vec![ready("first")],
        with_timeout(Duration::from_secs(5)),
        |_| {
            Answer::After(
                Duration::from_secs(3),
                Box::new(Answer::Stalling("partial")),
            )
        },
    )
    .await;
    let started = tokio::time::Instant::now();
    let mut response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("the head arrived in time");
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert_eq!(response.chunk().await.unwrap().unwrap(), "partial");

    let failed = response.chunk().await.expect_err("the body stalled");
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert!(failed.is_timeout(), "{failed:?}");
    let error = Error::from_reqwest(&failed).expect("the client's error");
    assert_deadline(error);
    // Nothing is read after the failure.
    assert!(response.chunk().await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn data_that_arrives_after_the_deadline_is_not_delivered() {
    let f = fake(
        vec![ready("first")],
        with_timeout(Duration::from_secs(5)),
        |_| Answer::Text("complete"),
    )
    .await;
    let response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .unwrap();
    // The caller comes back to the body too late.
    tokio::time::advance(Duration::from_secs(6)).await;
    let failed = response.text().await.expect_err("past the deadline");
    assert_deadline(Error::from_reqwest(&failed).expect("the client's error"));
}

#[tokio::test(start_paused = true)]
async fn a_requests_own_timeout_covers_the_body_and_no_timeout_leaves_it_alone() {
    let f = fake(vec![ready("first")], settings(), |_| {
        Answer::Stalling("partial")
    })
    .await;
    let started = tokio::time::Instant::now();
    let mut response = get(&f.client, "https://enclave.example.com/")
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "partial");
    let failed = response.chunk().await.expect_err("the body stalled");
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    assert_deadline(Error::from_reqwest(&failed).expect("the client's error"));

    // Without any timeout, a stalled body is waited for.
    let mut response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "partial");
    let waited = tokio::time::timeout(Duration::from_secs(86_400), response.chunk()).await;
    assert!(waited.is_err(), "the read ended by itself");
}

#[tokio::test(start_paused = true)]
async fn ensure_verified_and_reverify_end_at_the_clients_timeout() {
    let gate = Arc::new(Notify::new());
    let f = fake(
        vec![ready("first"), gated("stuck", &gate), gated("stuck", &gate)],
        with_timeout(Duration::from_secs(5)),
        |_| Answer::Text("ok"),
    )
    .await;
    let started = tokio::time::Instant::now();
    let error = f.client.reverify().await.expect_err("stuck");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(f.client.current().name, "first");

    tokio::time::advance(HOUR).await;
    let started = tokio::time::Instant::now();
    let error = f.client.ensure_verified().await.expect_err("stuck");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(f.script.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_callers_deadline_ends_its_wait_for_a_verification_that_another_caller_started() {
    let gate = Arc::new(Notify::new());
    let f = fake(
        vec![ready("first"), gated("second", &gate)],
        with_timeout(Duration::from_secs(5)),
        |_| Answer::Text("ok"),
    )
    .await;
    tokio::time::advance(HOUR).await;
    // A request with a long deadline of its own starts the verification.
    let patient = {
        let client = Arc::clone(&f.client);
        tokio::spawn(async move {
            get(&client, "https://enclave.example.com/")
                .timeout(Duration::from_secs(600))
                .send()
                .await
        })
    };
    settle().await;
    assert_eq!(f.script.calls(), 2);

    // A second caller joins it and gives up at the client's timeout.
    let started = tokio::time::Instant::now();
    let error = f.client.ensure_verified().await.expect_err("out of time");
    assert_deadline(&error);
    assert_eq!(started.elapsed(), Duration::from_secs(5));

    // The verification went on for the first caller.
    gate.notify_one();
    soon(patient).await.unwrap().expect("verified and sent");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.client.current().name, "second");
}

// Cancellation.

#[tokio::test(start_paused = true)]
async fn dropping_a_request_leaves_the_client_usable_whatever_it_was_waiting_for() {
    let gate = Arc::new(Notify::new());
    let f = fake(
        vec![ready("first"), gated("abandoned", &gate), later("third")],
        settings(),
        |sent| match sent.url.path() {
            "/never" => Answer::Never,
            _ => Answer::Text("ok"),
        },
    )
    .await;
    // Dropped while the response is awaited.
    let waiting = tokio::spawn({
        let client = Arc::clone(&f.client);
        async move {
            get(&client, "https://enclave.example.com/never")
                .send()
                .await
        }
    });
    settle().await;
    assert_eq!(f.sent().len(), 1);
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("usable");

    // Dropped while a verification is awaited.
    tokio::time::advance(HOUR).await;
    let waiting = tokio::spawn({
        let client = Arc::clone(&f.client);
        async move { get(&client, "https://enclave.example.com/").send().await }
    });
    settle().await;
    assert_eq!(f.script.calls(), 2);
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    // Nothing half-finished was published.
    assert_eq!(f.client.current().name, "first");
    get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .expect("usable");
    assert_eq!(f.script.calls(), 3);
    assert_eq!(f.client.current().name, "third");
}

// Body failures.

#[tokio::test(start_paused = true)]
async fn a_sealed_body_that_stops_authenticating_is_an_attestation_error_for_the_reader() {
    let f = fake(vec![ready("first")], settings(), |_| {
        Answer::Tampered("authentic")
    })
    .await;
    let mut response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "authentic");
    let failed = response.chunk().await.expect_err("the frame did not open");
    let error = Error::from_reqwest(&failed).expect("the client's error");
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(!error.is_timeout());
    assert!(error.to_string().contains("AEAD_DECRYPT_FAILED"), "{error}");
    assert!(response.chunk().await.unwrap().is_none());

    // The same through the methods that read a whole body.
    let response = get(&f.client, "https://enclave.example.com/")
        .send()
        .await
        .unwrap();
    let failed = response.bytes().await.expect_err("the frame did not open");
    assert_eq!(
        Error::from_reqwest(&failed).map(Error::kind),
        Some(ErrorKind::Attestation)
    );
}

#[tokio::test]
async fn an_error_that_no_client_made_carries_no_client_error() {
    let response = Response::from(http::Response::new("not json"));
    let failed = response.json::<u32>().await.expect_err("not a number");
    assert!(Error::from_reqwest(&failed).is_none());
}

// The option checks, shared by the builder and the enclave.

mod options {
    use super::*;
    use crate::EnclaveHttpClient;
    use crate::internal::system_clock;
    use crate::verifier::Verifier;

    fn refusing_fetch() -> Fetch {
        Arc::new(|_, _, _| Box::pin(async { panic!("the checks do no I/O") }))
    }

    fn config(host: &str, repo: Option<&str>, verifier: Option<Arc<Verifier>>) -> Config {
        Config {
            host: host.to_owned(),
            relay: None,
            repo: repo.map(str::to_owned),
            verifier,
            verification_check: None,
        }
    }

    #[test]
    fn the_builder_and_the_enclave_refuse_the_same_hosts_pins_and_verifiers_alike() {
        let authorizing = || {
            let verifier = Verifier::builder().config_authorizer(|_| Ok(())).build();
            Arc::new(verifier.expect("a verifier"))
        };
        type Case = (&'static str, Option<&'static str>, Option<Arc<Verifier>>);
        let cases: Vec<Case> = vec![
            ("https://enclave.example.com", Some("owner/name"), None),
            ("enclave.example.com/v1", Some("owner/name"), None),
            ("user@enclave.example.com", Some("owner/name"), None),
            ("127.1", Some("owner/name"), None),
            ("enclave.example.com", Some(""), None),
            ("enclave.example.com", Some("not a reference"), None),
            (
                "enclave.example.com",
                Some("owner/name"),
                Some(authorizing()),
            ),
        ];
        for (host, repo, verifier) in cases {
            let mut builder = EnclaveHttpClient::builder(host, repo);
            if let Some(verifier) = &verifier {
                builder = builder.verifier(Arc::clone(verifier));
            }
            let from_builder = builder.prepare().err().expect(host);
            let from_enclave = Enclave::with_fetch(
                config(host, repo, verifier),
                system_clock(),
                refusing_fetch(),
            )
            .err()
            .expect(host);
            assert_eq!(from_builder.kind(), ErrorKind::Configuration);
            assert_eq!(from_builder.to_string(), from_enclave.to_string());
        }
    }

    #[test]
    fn the_verifier_that_was_checked_is_the_one_that_the_enclave_verifies_with() {
        // The default verifier is built once, by the check.
        let (checked, _) = EnclaveHttpClient::builder("enclave.example.com", Some("owner/name"))
            .prepare()
            .unwrap();
        let built = Arc::clone(checked.verifier());
        let enclave = Enclave::from_checked(checked, system_clock(), refusing_fetch());
        assert!(Arc::ptr_eq(enclave.verifier().unwrap(), &built));

        // A configured verifier is used as it is.
        let configured = Arc::new(Verifier::new());
        let (checked, _) = EnclaveHttpClient::builder("enclave.example.com", None)
            .verifier(Arc::clone(&configured))
            .prepare()
            .unwrap();
        let enclave = Enclave::from_checked(checked, system_clock(), refusing_fetch());
        assert!(Arc::ptr_eq(enclave.verifier().unwrap(), &configured));
    }

    #[test]
    fn the_checks_run_in_the_documented_order() {
        let refusal = |builder: crate::EnclaveHttpClientBuilder| {
            let error = builder.prepare().err().expect("refused");
            assert_eq!(error.kind(), ErrorKind::Configuration);
            error.to_string()
        };
        let builder = EnclaveHttpClient::builder;
        // An empty host, before the base URL.
        let message = refusal(builder("", Some("")).base_url("ftp://proxy.example/"));
        assert!(message.contains("enclave host is required"), "{message}");
        // The base URL, before a host that is no host.
        let message = refusal(
            builder("https://enclave.example.com", Some("")).base_url("ftp://proxy.example/"),
        );
        assert!(message.contains("invalid base URL"), "{message}");
        // The other options, before a host that is no host.
        let message =
            refusal(builder("https://enclave.example.com", Some("")).timeout(Duration::ZERO));
        assert!(message.contains("timeout is zero"), "{message}");
        // The host, before the pin.
        let message = refusal(builder("https://enclave.example.com", Some("")));
        assert!(message.contains("host with an optional port"), "{message}");
        // The pin, before the proxy rule of the pinned mode.
        let message =
            refusal(builder("enclave.example.com", Some("")).base_url("https://proxy.example/"));
        assert!(message.contains("repository pin is empty"), "{message}");
        let message = refusal(
            builder("enclave.example.com", Some("owner/name")).base_url("https://proxy.example/"),
        );
        assert!(message.contains("TransportMode::Ehbp"), "{message}");
    }

    #[test]
    fn options_that_pass_every_check_yield_the_clients_settings() {
        let (checked, settings) =
            EnclaveHttpClient::builder("enclave.example.com:8443", Some("owner/name@v1.2.3"))
                .transport_mode(TransportMode::Ehbp)
                .base_url("https://proxy.example.com/tinfoil")
                .user_cache_secret("opaque")
                .timeout(Duration::from_secs(1))
                .prepare()
                .unwrap();
        assert_eq!(checked.host(), "enclave.example.com:8443");
        assert_eq!(settings.mode, TransportMode::Ehbp);
        assert_eq!(
            settings.base_url.as_ref().map(Url::as_str),
            Some("https://proxy.example.com/tinfoil/")
        );
        assert_eq!(settings.secret.as_ref().map(Secret::expose), Some("opaque"));
        assert_eq!(settings.timeout, Some(Duration::from_secs(1)));

        let (_, settings) = EnclaveHttpClient::builder("enclave.example.com", None)
            .prepare()
            .unwrap();
        assert_eq!(settings.mode, TransportMode::Tls);
        assert!(settings.base_url.is_none() && settings.secret.is_none());
        assert!(settings.timeout.is_none());

        for accepted in [
            EnclaveHttpClient::builder("enclave.example.com", Some("owner/name"))
                .base_url("https://enclave.example.com/api/"),
            EnclaveHttpClient::builder("enclave.example.com", Some("owner/name"))
                .transport_mode(TransportMode::Ehbp)
                .base_url("http://localhost:8080/"),
        ] {
            accepted.prepare().expect("accepted");
        }
    }

    // Connecting, with the document fetch replaced.

    fn checked() -> (crate::internal::enclave::Checked, Settings) {
        EnclaveHttpClient::builder("enclave.example.com", Some("owner/name"))
            .timeout(Duration::from_secs(5))
            .prepare()
            .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn connecting_fails_with_the_verifiers_rejection_after_one_retry() {
        let fetched = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&fetched);
        let fetch: Fetch = Arc::new(move |host, relay, nonce| {
            log.lock().unwrap().push((host, relay, nonce));
            Box::pin(async { Ok(b"not an attestation document".to_vec()) })
        });
        let (checked, settings) = checked();
        let error = AttestedClient::connect(checked, settings, system_clock(), fetch)
            .await
            .err()
            .expect("no client");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        let source = std::error::Error::source(&error).expect("the verifier's error");
        assert!(source.is::<crate::verifier::Error>());
        assert_eq!(
            error.earlier_attempt().map(Error::kind),
            Some(ErrorKind::Attestation)
        );
        let fetched = fetched.lock().unwrap();
        assert_eq!(fetched.len(), 2);
        assert_eq!(fetched[0].0, "enclave.example.com");
        assert_eq!(fetched[0].1, None);
        assert_ne!(fetched[0].2, fetched[1].2);
    }

    #[tokio::test(start_paused = true)]
    async fn connecting_ends_at_the_timeout() {
        let fetch: Fetch = Arc::new(|_, _, _| Box::pin(std::future::pending()));
        let (checked, settings) = checked();
        let started = tokio::time::Instant::now();
        let error = AttestedClient::connect(checked, settings, system_clock(), fetch)
            .await
            .err()
            .expect("no client");
        assert_deadline(&error);
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }
}

// The real modes, against local servers.

/// A clock that a test sets.
fn manual_clock() -> (Clock, Arc<Mutex<SystemTime>>) {
    let now = Arc::new(Mutex::new(SystemTime::UNIX_EPOCH + EPOCH));
    let read = Arc::clone(&now);
    (Arc::new(move || *read.lock().unwrap()), now)
}

mod over_tls {
    use super::*;
    use crate::internal::transport::tls::tests::{
        self as tls, OK, Server, made::KEY_A, made::LEAF_A, made::LEAF_B, serve,
    };

    /// A client in the TLS mode for `server`, whose verifications yield
    /// `evidence` in order.
    async fn client(
        server: &Server,
        evidence: Vec<Record>,
        settings: Settings,
    ) -> (Arc<Script>, Client) {
        let script = Script::new(evidence.into_iter().map(|e| Step::Ready(Ok(e))));
        let host = format!("127.0.0.1:{}", server.port);
        let enclave = Enclave::from_source(&host, script.source(), None, tokio_clock());
        let transport = soon(Transport::connect(enclave, Arc::new(tls::mode()), true))
            .await
            .expect("connected");
        let client = Arc::new(AttestedClient::new(transport, settings).expect("a client"));
        (script, client)
    }

    fn url(client: &Client, path: &str) -> String {
        client.base_url().join(path).unwrap().to_string()
    }

    #[tokio::test]
    async fn a_request_reaches_the_enclave_over_a_pinned_connection() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let (script, client) = client(&server, vec![tls::evidence("a", &LEAF_A)], settings()).await;
        assert_eq!(
            client.base_url().as_str(),
            format!("https://127.0.0.1:{}/", server.port)
        );
        for path in ["hello", "v1/models"] {
            let response = soon(get(&client, &url(&client, path)).send())
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(response.content_length(), Some(path.len() as u64 + 1));
            assert_eq!(soon(response.text()).await.unwrap(), format!("/{path}"));
        }
        assert_eq!(
            server.requests(),
            ["GET /hello HTTP/1.1", "GET /v1/models HTTP/1.1"]
        );
        // One verification, one connection.
        assert_eq!(script.calls(), 1);
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn a_base_url_on_the_enclaves_origin_is_where_requests_go() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let base = Url::parse(&format!("https://127.0.0.1:{}/api/", server.port)).unwrap();
        let (_, client) = client(
            &server,
            vec![tls::evidence("a", &LEAF_A)],
            Settings {
                base_url: Some(base),
                ..settings()
            },
        )
        .await;
        let response = soon(get(&client, &url(&client, "v1/models")).send())
            .await
            .unwrap();
        assert_eq!(soon(response.text()).await.unwrap(), "/api/v1/models");
    }

    #[tokio::test]
    async fn a_request_to_another_server_is_refused_and_never_connects() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        // Another server with the very same certificate and key.
        let other = serve(&LEAF_A, &KEY_A, OK).await;
        let (_, client) = client(&server, vec![tls::evidence("a", &LEAF_A)], settings()).await;
        let error = soon(
            get(&client, other.url("/steal").as_str())
                .bearer_auth("api-key")
                .send(),
        )
        .await
        .expect_err("another origin");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert_eq!(other.accepted(), 0);
        assert_eq!(server.accepted(), 0);
    }

    #[tokio::test]
    async fn a_host_header_is_refused_before_anything_is_sent() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let (_, client) = client(&server, vec![tls::evidence("a", &LEAF_A)], settings()).await;
        let error = soon(
            get(&client, &url(&client, "x"))
                .header("Host", "other.example")
                .send(),
        )
        .await
        .expect_err("the header belongs to the client");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert_eq!(server.accepted(), 0);
    }

    #[tokio::test]
    async fn a_new_certificate_key_is_healed_by_one_replay() {
        // The enclave holds key A; the first verification endorsed key B.
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let (script, client) = client(
            &server,
            vec![
                tls::evidence("before", &LEAF_B),
                tls::evidence("after", &LEAF_A),
            ],
            settings(),
        )
        .await;
        let response = soon(get(&client, &url(&client, "secret")).send())
            .await
            .expect("healed");
        assert_eq!(soon(response.text()).await.unwrap(), "/secret");
        assert_eq!(script.calls(), 2);
        assert_eq!(client.current().name, "after");
        // The request reached the server once: the first attempt ended in
        // the handshake.
        assert_eq!(server.requests(), ["GET /secret HTTP/1.1"]);
    }

    #[tokio::test]
    async fn a_new_certificate_key_is_reported_for_a_streamed_body_and_healed_for_the_next_request()
    {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let (script, client) = client(
            &server,
            vec![
                tls::evidence("before", &LEAF_B),
                tls::evidence("after", &LEAF_A),
            ],
            settings(),
        )
        .await;
        let error = soon(
            post(&client, &url(&client, "upload"))
                .body(stream(&["pay", "load"]))
                .send(),
        )
        .await
        .expect_err("a stream cannot be sent again");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(error.to_string().contains("cannot be replayed"), "{error}");
        let rejection = error.earlier_attempt().expect("the rejection");
        assert_eq!(rejection.kind(), ErrorKind::Attestation);
        assert!(rejection.to_string().contains("certificate"), "{rejection}");
        assert!(server.requests().is_empty());
        assert_eq!(script.calls(), 1);

        let response = soon(get(&client, &url(&client, "next")).send())
            .await
            .expect("verified again first");
        assert_eq!(soon(response.text()).await.unwrap(), "/next");
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test]
    async fn a_key_that_no_verification_explains_fails_after_one_replay() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let (script, client) = client(
            &server,
            vec![
                tls::evidence("first", &LEAF_B),
                tls::evidence("second", &LEAF_B),
                tls::evidence("third", &LEAF_B),
            ],
            settings(),
        )
        .await;
        let error = soon(get(&client, &url(&client, "secret")).send())
            .await
            .expect_err("the server never holds the attested key");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(error.earlier_attempt().is_some());
        assert_eq!(script.calls(), 2);
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn concurrent_requests_during_a_rotation_share_one_verification() {
        let server = serve(&LEAF_A, &KEY_A, OK).await;
        let gate = Arc::new(Notify::new());
        let script = Script::new([
            Step::Ready(Ok(tls::evidence("before", &LEAF_B))),
            Step::Gated(Arc::clone(&gate), Ok(tls::evidence("after", &LEAF_A))),
        ]);
        let host = format!("127.0.0.1:{}", server.port);
        let enclave = Enclave::from_source(&host, script.source(), None, tokio_clock());
        let transport = soon(Transport::connect(enclave, Arc::new(tls::mode()), true))
            .await
            .unwrap();
        let client: Client = Arc::new(AttestedClient::new(transport, settings()).unwrap());

        let requests: Vec<_> = (0..6)
            .map(|n| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    let response = get(&client, &url(&client, &format!("r{n}"))).send().await?;
                    Ok::<_, Error>(response.text().await.expect("a body"))
                })
            })
            .collect();
        // The second verification starts once the first handshake has been
        // refused; the others join it.
        tls::eventually(|| script.calls() == 2, "the rotation is noticed").await;
        gate.notify_one();
        for (n, request) in requests.into_iter().enumerate() {
            let body = soon(request).await.unwrap().expect("healed");
            assert_eq!(body, format!("/r{n}"));
        }
        assert_eq!(script.calls(), 2);
        assert_eq!(server.requests().len(), 6);
    }
}

mod over_ehbp {
    use super::*;
    use crate::internal::transport::ehbp::tests::{
        self as ehbp, Key, Part, Reply, Seen, Server, data, key, serve,
    };

    /// Evidence that endorses `key`, valid for an hour on `clock`.
    fn evidence(name: &'static str, key: &Key, clock: &Clock) -> Record {
        let mut evidence = ehbp::evidence(name, Some(&key.public_hex));
        evidence.expires = Some(clock() + HOUR);
        evidence
    }

    /// A client in the EHBP mode that reaches its enclave through
    /// `server`, as through a proxy.
    async fn client_on(
        server: &Server,
        steps: Vec<Step>,
        clock: Clock,
        settings: Settings,
    ) -> (Arc<Script>, Client) {
        let script = Script::new(steps);
        let enclave = Enclave::from_source(ENCLAVE, script.source(), None, clock);
        let transport = soon(Transport::connect(enclave, Arc::new(ehbp::mode()), true))
            .await
            .expect("connected");
        let settings = Settings {
            mode: TransportMode::Ehbp,
            base_url: Some(server.url.clone()),
            ..settings
        };
        let client = Arc::new(AttestedClient::new(transport, settings).expect("a client"));
        (script, client)
    }

    async fn client(server: &Server, keys: &[&Key], settings: Settings) -> (Arc<Script>, Client) {
        let clock = tokio_clock();
        let steps = keys
            .iter()
            .map(|key| Step::Ready(Ok(evidence("e", key, &clock))))
            .collect();
        client_on(server, steps, clock, settings).await
    }

    fn url(client: &Client, path: &str) -> String {
        client.base_url().join(path).unwrap().to_string()
    }

    fn echo(seen: &Seen) -> Reply {
        Reply::ok(&format!("echo:{}", String::from_utf8_lossy(&seen.body)))
    }

    #[tokio::test]
    async fn a_request_is_sealed_names_the_enclave_and_its_response_is_opened() {
        let held = key(1);
        let server = serve(&held, echo).await;
        let (script, client) = client(&server, &[&held], settings()).await;
        assert_eq!(client.base_url(), &server.url);
        assert_eq!(client.enclave(), ENCLAVE);

        let response = soon(
            post(&client, &url(&client, "v1/x"))
                .bearer_auth("api-key")
                .json(&serde_json::json!({"prompt": "private"}))
                .send(),
        )
        .await
        .expect("sent");
        assert_eq!(
            soon(response.text()).await.unwrap(),
            r#"echo:{"prompt":"private"}"#
        );
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].sealed);
        assert_eq!(seen[0].target, "/v1/x");
        assert!(!String::from_utf8_lossy(&seen[0].wire).contains("private"));
        assert_eq!(
            seen[0].header("x-tinfoil-enclave-url"),
            Some("https://enclave.example.com")
        );
        assert_eq!(seen[0].header("authorization"), Some("Bearer api-key"));
        assert_eq!(script.calls(), 1);
    }

    #[tokio::test]
    async fn the_cache_secret_is_sealed_with_the_body() {
        let held = key(1);
        let server = serve(&held, echo).await;
        let (_, client) = client(
            &server,
            &[&held],
            Settings {
                secret: Some(Secret::new("s3cret-scope")),
                ..settings()
            },
        )
        .await;
        soon(
            post(&client, &url(&client, "v1/chat/completions"))
                .json(&serde_json::json!({"model": "m"}))
                .send(),
        )
        .await
        .expect("sent");
        soon(
            post(&client, &url(&client, "v1/embeddings"))
                .json(&serde_json::json!({"model": "m"}))
                .send(),
        )
        .await
        .expect("sent");
        let seen = server.seen();
        assert_eq!(
            String::from_utf8_lossy(&seen[0].body),
            r#"{"model":"m","user_cache_secret":"s3cret-scope"}"#
        );
        assert!(seen[0].sealed);
        assert!(!String::from_utf8_lossy(&seen[0].wire).contains("s3cret-scope"));
        assert!(
            seen[0]
                .headers
                .iter()
                .all(|(_, value)| !value.contains("s3cret-scope"))
        );
        assert_eq!(String::from_utf8_lossy(&seen[1].body), r#"{"model":"m"}"#);
    }

    #[tokio::test]
    async fn headers_that_belong_to_the_client_are_refused_before_anything_is_sent() {
        let held = key(1);
        let server = serve(&held, echo).await;
        let (script, client) = client(&server, &[&held], settings()).await;
        for name in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Ehbp-Encapsulated-Key",
            "ehbp-response-nonce",
            "Upgrade",
        ] {
            let error = soon(
                post(&client, &url(&client, "v1/x"))
                    .header(name, "1")
                    .body("payload")
                    .send(),
            )
            .await
            .expect_err(name);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{name}: {error}");
        }
        assert_eq!(server.accepted(), 0);
        assert_eq!(script.calls(), 1);
    }

    #[tokio::test]
    async fn a_request_to_another_server_is_refused_and_never_connects() {
        let held = key(1);
        let server = serve(&held, echo).await;
        let other = serve(&held, echo).await;
        let (_, client) = client(&server, &[&held], settings()).await;
        let error = soon(
            post(&client, other.url("/steal").as_str())
                .bearer_auth("api-key")
                .body("payload")
                .send(),
        )
        .await
        .expect_err("another origin");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert_eq!(other.accepted(), 0);
    }

    #[tokio::test]
    async fn a_new_hpke_key_is_healed_by_one_replay() {
        // The enclave holds key 2; the first verification endorsed key 1.
        let (stale, held) = (key(1), key(2));
        let server = serve(&held, echo).await;
        let (script, client) = client(
            &server,
            &[&stale, &held],
            Settings {
                secret: Some(Secret::new("scope")),
                ..settings()
            },
        )
        .await;
        let response = soon(
            post(&client, &url(&client, "v1/chat/completions"))
                .body(r#"{"n":1}"#)
                .send(),
        )
        .await
        .expect("healed");
        assert_eq!(
            soon(response.text()).await.unwrap(),
            r#"echo:{"n":1,"user_cache_secret":"scope"}"#
        );
        assert_eq!(script.calls(), 2);
        // The first attempt could not be opened; the replay could.
        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        assert!(!seen[0].sealed && seen[0].body.is_empty());
        assert!(seen[1].sealed);
        for seen in &seen {
            assert_eq!(
                seen.header("x-tinfoil-enclave-url"),
                Some("https://enclave.example.com")
            );
        }
    }

    #[tokio::test]
    async fn a_new_hpke_key_is_reported_for_a_streamed_body_and_healed_for_the_next_request() {
        let (stale, held) = (key(1), key(2));
        let server = serve(&held, echo).await;
        let (script, client) = client(&server, &[&stale, &held], settings()).await;
        let error = soon(
            post(&client, &url(&client, "v1/upload"))
                .body(stream(&["pay", "load"]))
                .send(),
        )
        .await
        .expect_err("a stream cannot be sent again");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(error.to_string().contains("cannot be replayed"), "{error}");
        let rejection = error.earlier_attempt().expect("the rejection");
        assert!(rejection.to_string().contains("HPKE key"), "{rejection}");
        assert_eq!(server.seen().len(), 1);
        assert_eq!(script.calls(), 1);

        let response = soon(post(&client, &url(&client, "v1/x")).body("again").send())
            .await
            .expect("verified again first");
        assert_eq!(soon(response.text()).await.unwrap(), "echo:again");
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test]
    async fn concurrent_requests_during_a_rotation_share_one_verification() {
        let (stale, held) = (key(1), key(2));
        let server = serve(&held, echo).await;
        let clock = tokio_clock();
        let gate = Arc::new(Notify::new());
        let steps = vec![
            Step::Ready(Ok(evidence("before", &stale, &clock))),
            Step::Gated(Arc::clone(&gate), Ok(evidence("after", &held, &clock))),
        ];
        let (script, client) = client_on(&server, steps, clock, settings()).await;
        let requests: Vec<_> = (0..6)
            .map(|n| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    let response = post(&client, &url(&client, "v1/x"))
                        .body(format!("r{n}"))
                        .send()
                        .await?;
                    Ok::<_, Error>(response.text().await.expect("a body"))
                })
            })
            .collect();
        // Every first attempt is refused before the gate opens.
        for _ in 0..500 {
            if server.seen().len() == 6 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.seen().len(), 6);
        gate.notify_one();
        for (n, request) in requests.into_iter().enumerate() {
            assert_eq!(
                soon(request).await.unwrap().expect("healed"),
                format!("echo:r{n}")
            );
        }
        assert_eq!(script.calls(), 2);
        assert_eq!(server.seen().len(), 12);
    }

    #[tokio::test]
    async fn a_verification_that_expired_between_requests_is_renewed_before_the_next() {
        let held = key(1);
        let server = serve(&held, echo).await;
        let (clock, now) = manual_clock();
        let mut renewed = evidence("second", &held, &clock);
        renewed.expires = Some(clock() + 3 * HOUR);
        let steps = vec![
            Step::Ready(Ok(evidence("first", &held, &clock))),
            Step::Ready(Ok(renewed)),
        ];
        let (script, client) = client_on(&server, steps, clock, settings()).await;
        let response = soon(post(&client, &url(&client, "a")).body("one").send())
            .await
            .expect("under the first verification");
        assert_eq!(soon(response.text()).await.unwrap(), "echo:one");
        assert_eq!(script.calls(), 1);

        // One microsecond before the deadline nothing is renewed.
        *now.lock().unwrap() += HOUR - Duration::from_micros(1);
        let response = soon(post(&client, &url(&client, "b")).body("two").send())
            .await
            .expect("still valid");
        assert_eq!(soon(response.text()).await.unwrap(), "echo:two");
        assert_eq!((script.calls(), client.current().name), (1, "first"));

        // At the deadline the next request verifies before it is sent.
        *now.lock().unwrap() += Duration::from_micros(1);
        let response = soon(post(&client, &url(&client, "c")).body("three").send())
            .await
            .expect("under the renewed verification");
        assert_eq!(soon(response.text()).await.unwrap(), "echo:three");
        assert_eq!((script.calls(), client.current().name), (2, "second"));
        // A new verification binds anew: its requests take a connection of
        // their own.
        assert_eq!(server.accepted(), 2);
        assert_eq!(server.seen().len(), 3);
    }

    #[tokio::test]
    async fn a_tampered_or_truncated_frame_is_an_attestation_error_for_the_reader() {
        let held = key(1);
        let server = serve(&held, |seen: &Seen| match seen.target.as_str() {
            "/tampered" => {
                Reply::parts(vec![data("authentic"), Part::Tampered(b"forged".to_vec())])
            }
            _ => Reply::parts(vec![data("authentic"), Part::Cut(b"shortened".to_vec())]),
        })
        .await;
        let (_, client) = client(&server, &[&held], settings()).await;
        for (path, code) in [
            ("tampered", "AEAD_DECRYPT_FAILED"),
            ("truncated", "FRAMING_TRUNCATED"),
        ] {
            let mut response = soon(post(&client, &url(&client, path)).body("x").send())
                .await
                .expect("the head is fine");
            let first = soon(response.chunk()).await.unwrap().unwrap();
            assert_eq!(first, "authentic", "{path}");
            let failed = soon(response.chunk()).await.expect_err(path);
            let error = Error::from_reqwest(&failed).expect("the client's error");
            assert_eq!(error.kind(), ErrorKind::Attestation, "{path}: {error}");
            assert!(error.to_string().contains(code), "{path}: {error}");
            assert!(!error.to_string().contains("127.0.0.1"), "{error}");
        }
    }

    #[tokio::test]
    async fn a_response_that_does_not_start_in_time_is_a_timeout() {
        let held = key(1);
        let gate = Arc::new(Notify::new());
        let hold = Arc::clone(&gate);
        let server = serve(&held, move |_: &Seen| Reply::never(&hold)).await;
        let (_, client) = client(&server, &[&held], with_timeout(Duration::from_millis(300))).await;
        let error = soon(post(&client, &url(&client, "slow")).body("x").send())
            .await
            .expect_err("no response");
        assert_deadline(&error);
        assert_eq!(server.seen().len(), 1);
        gate.notify_one();
    }

    #[tokio::test]
    async fn a_sealed_body_that_stalls_past_the_deadline_fails_the_read_as_a_timeout() {
        let held = key(1);
        let gate = Arc::new(Notify::new());
        let hold = Arc::clone(&gate);
        let server = serve(&held, move |_: &Seen| {
            Reply::parts(vec![
                data("first"),
                Part::Wait(Arc::clone(&hold)),
                data("late"),
            ])
        })
        .await;
        let (_, client) = client(&server, &[&held], settings()).await;
        let mut response = soon(
            post(&client, &url(&client, "stream"))
                .timeout(Duration::from_millis(400))
                .body("x")
                .send(),
        )
        .await
        .expect("the head arrived");
        assert_eq!(soon(response.chunk()).await.unwrap().unwrap(), "first");
        let failed = soon(response.chunk()).await.expect_err("stalled");
        assert!(failed.is_timeout());
        assert_deadline(Error::from_reqwest(&failed).expect("the client's error"));
        gate.notify_one();
    }

    #[tokio::test]
    async fn dropping_a_request_in_flight_leaves_the_client_usable() {
        let held = key(1);
        let gate = Arc::new(Notify::new());
        let hold = Arc::clone(&gate);
        let server = serve(&held, move |seen: &Seen| match seen.target.as_str() {
            "/held" => Reply::never(&hold),
            _ => echo(seen),
        })
        .await;
        let (script, client) = client(&server, &[&held], settings()).await;
        let in_flight = tokio::spawn({
            let client = Arc::clone(&client);
            async move { post(&client, &url(&client, "held")).body("x").send().await }
        });
        for _ in 0..500 {
            if !server.seen().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(server.seen().len(), 1);
        in_flight.abort();
        assert!(soon(in_flight).await.unwrap_err().is_cancelled());

        let response = soon(post(&client, &url(&client, "next")).body("y").send())
            .await
            .expect("usable");
        assert_eq!(soon(response.text()).await.unwrap(), "echo:y");
        assert_eq!(script.calls(), 1);
        gate.notify_one();
    }
}
