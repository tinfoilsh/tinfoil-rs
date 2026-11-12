//! The `async_openai` client over an attested client: on a scripted mode
//! under Tokio's paused time, for what is sent how often, and on the two
//! real modes against local servers, for what is on the wire.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_openai::config::OpenAIConfig;
use async_openai::error::OpenAIError;
use async_openai::types::audio::{AudioInput, CreateTranscriptionRequestArgs};
use async_openai::types::chat::{
    ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequest,
    CreateChatCompletionRequestArgs,
};
use async_openai::types::embeddings::CreateEmbeddingRequestArgs;
use async_openai::types::responses::CreateResponseArgs;
use futures_util::StreamExt;
use reqwest::header::HeaderMap;
use reqwest::{Request, Response, Url};

use super::{Sender, openai_client};
use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::attested::{AttestedClient, Settings};
use crate::internal::enclave::Enclave;
use crate::internal::testing::{Record, Script, Step, record, tokio_clock};
use crate::internal::transport::{Failure, Mode, RoundTrip, Transport};
use crate::openai::relaxed::RelaxedChat;
use crate::openai::retry::Waits;
use crate::options::{Secret, TransportMode};
use crate::request::Execute;

type OpenAI = async_openai::Client<OpenAIConfig>;

const HOUR: Duration = Duration::from_secs(3600);

/// Runs a test under paused time with a limit: when nothing in the test
/// can make progress any more, Tokio moves its clock to this limit, and
/// the test fails instead of hanging.
async fn unstuck<T>(test: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(1_000 * 86_400), test)
        .await
        .expect("the test can make no progress")
}

/// Bounds a wait on a local server, so that a hang fails the test.
const PATIENCE: Duration = Duration::from_secs(20);

async fn soon<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(PATIENCE, future)
        .await
        .expect("the operation neither succeeded nor failed in time")
}

/// An `async_openai` client over an attested client, with what a relaxed
/// chat handle is made from.
struct Kit {
    openai: OpenAI,
    sender: Sender,
    http: Arc<dyn Execute>,
    api_base: Url,
    config: OpenAIConfig,
}

impl Kit {
    fn new(client: AttestedClient<Record>, mode: TransportMode) -> Self {
        let api_base = client.openai_url().clone();
        let waits = Waits {
            timeout: client.timeout(),
            clock: tokio_clock(),
        };
        let http: Arc<dyn Execute> = Arc::new(client);
        let (openai, sender) =
            openai_client(config(), &api_base, Arc::clone(&http), mode, waits).unwrap();
        Self {
            openai,
            sender,
            http,
            api_base,
            config: config(),
        }
    }

    fn relaxed(&self) -> RelaxedChat<'_> {
        RelaxedChat {
            sender: self.sender.clone(),
            http: Arc::clone(&self.http),
            api_base: &self.api_base,
            config: &self.config,
        }
    }
}

impl std::ops::Deref for Kit {
    type Target = OpenAI;

    fn deref(&self) -> &OpenAI {
        &self.openai
    }
}

/// A configuration as a caller would write one. It names no API base, and
/// its key is not a real one.
fn config() -> OpenAIConfig {
    OpenAIConfig::new()
        .with_api_base("https://unused.invalid/v1")
        .with_api_key("test-key")
        .with_org_id("org-1")
        .with_project_id("proj-1")
}

fn chat_request() -> CreateChatCompletionRequest {
    CreateChatCompletionRequestArgs::default()
        .model("m")
        .messages([ChatCompletionRequestUserMessageArgs::default()
            .content("private prompt")
            .build()
            .unwrap()
            .into()])
        .build()
        .unwrap()
}

/// The same request, asking for a stream. With the `openai-byot` feature
/// `async_openai` leaves the member to the caller.
fn streaming_chat_request() -> CreateChatCompletionRequest {
    let mut request = chat_request();
    request.stream = Some(true);
    request
}

const CHAT_RESPONSE: &str = r#"{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#;

const TRANSCRIPTION_RESPONSE: &str =
    r#"{"text":"hello","usage":{"type":"duration","seconds":1.5}}"#;

const EMBEDDING_RESPONSE: &str = r#"{"object":"list","model":"m","data":[{"index":0,"object":"embedding","embedding":[0.5,0.25]}],"usage":{"prompt_tokens":1,"total_tokens":1}}"#;

fn chunk(text: &str) -> String {
    format!(
        r#"data: {{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{{"index":0,"delta":{{"content":"{text}"}},"finish_reason":null}}]}}"#
    ) + "\n\n"
}

/// The client error inside a failed call.
fn client_error(error: &OpenAIError) -> &Error {
    Error::from_openai(error).unwrap_or_else(|| panic!("no client error in {error:?}"))
}

// On a scripted mode.

/// One request as a binding received it.
#[derive(Clone, Debug)]
struct Sent {
    binding: &'static str,
    url: Url,
    headers: HeaderMap,
    /// The body, when it is held in memory.
    body: Option<String>,
    streamed: bool,
}

/// What a binding answers.
enum Answer {
    Respond(u16, &'static str),
    RespondWith(u16, &'static str, &'static str, &'static str),
    /// This response as it is.
    Whole(Response),
    LacksKey,
    Fail(Error),
    /// A response whose body delivers this text and then breaks.
    Broken(&'static str),
}

type Answers = Arc<dyn Fn(&Sent, usize) -> Answer + Send + Sync>;

struct Scripted {
    answers: Answers,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl Mode<Record> for Scripted {
    fn validate_request(&self, _: &Request) -> Result<(), Error> {
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
            url: request.url().clone(),
            headers: request.headers().clone(),
            body: request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .map(|body| String::from_utf8_lossy(body).into_owned()),
            streamed: request.body().is_some_and(|b| b.as_bytes().is_none()),
        };
        let mut log = self.sent.lock().unwrap();
        let answer = (self.answers)(&sent, log.len());
        log.push(sent);
        Box::pin(async move {
            let respond = |status: u16, body: &'static str| {
                let response = http::Response::builder().status(status).body(body);
                Response::from(response.unwrap())
            };
            match answer {
                Answer::Respond(status, body) => Ok(respond(status, body)),
                Answer::RespondWith(status, name, value, body) => {
                    let response = http::Response::builder()
                        .status(status)
                        .header(name, value)
                        .body(body);
                    Ok(Response::from(response.unwrap()))
                }
                Answer::Whole(response) => Ok(response),
                Answer::LacksKey => Err(Failure::peer_lacks_key(Error::attestation(
                    "the peer does not hold the attested key",
                ))),
                Answer::Fail(error) => Err(error.into()),
                Answer::Broken(text) => {
                    let body = futures_util::stream::iter([
                        Ok(text),
                        Err(std::io::Error::other("connection reset")),
                    ]);
                    Ok(Response::from(http::Response::new(
                        reqwest::Body::wrap_stream(body),
                    )))
                }
            }
        })
    }
}

struct Fake {
    script: Arc<Script>,
    openai: Kit,
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

/// An `async_openai` client over a client for `enclave.example.com` whose
/// verifications play `steps` and whose bindings answer with `answers`,
/// which is given each request and how many came before it.
async fn fake(
    steps: Vec<Step>,
    secret: Option<&str>,
    answers: impl Fn(&Sent, usize) -> Answer + Send + Sync + 'static,
) -> Fake {
    fake_within(None, steps, secret, answers).await
}

/// As [`fake`], with the `timeout` option.
async fn fake_within(
    timeout: Option<Duration>,
    steps: Vec<Step>,
    secret: Option<&str>,
    answers: impl Fn(&Sent, usize) -> Answer + Send + Sync + 'static,
) -> Fake {
    let script = Script::new(steps);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mode = Scripted {
        answers: Arc::new(answers),
        sent: Arc::clone(&sent),
    };
    let enclave = Enclave::from_source("enclave.example.com", script.source(), None, tokio_clock());
    let transport = Transport::connect(enclave, Arc::new(mode), true)
        .await
        .unwrap();
    let client = AttestedClient::new(
        transport,
        Settings {
            mode: TransportMode::Tls,
            base_url: None,
            secret: secret.map(Secret::new),
            timeout,
        },
    )
    .unwrap();
    let openai = Kit::new(client, TransportMode::Tls);
    Fake {
        script,
        openai,
        sent,
    }
}

fn ready(name: &'static str) -> Step {
    Step::Ready(Ok(record(name, &tokio_clock(), HOUR)))
}

fn later(name: &'static str) -> Step {
    Step::Ready(Ok(record(name, &tokio_clock(), 100 * HOUR)))
}

fn transcription() -> async_openai::types::audio::CreateTranscriptionRequest {
    CreateTranscriptionRequestArgs::default()
        .file(AudioInput::from_vec_u8(
            "speech.wav".to_owned(),
            b"RIFF-private-audio".to_vec(),
        ))
        .model("whisper")
        .build()
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_call_goes_to_the_attested_api_base_with_the_callers_credentials() {
    unstuck(async {
        let f = fake(vec![ready("first")], Some("scope"), |_, _| {
            Answer::Respond(200, CHAT_RESPONSE)
        })
        .await;
        let response = f.openai.chat().create(chat_request()).await.unwrap();
        assert_eq!(response.id, "c1");
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        // The base that the configuration named is not used.
        assert_eq!(
            sent[0].url.as_str(),
            "https://enclave.example.com/v1/chat/completions"
        );
        assert_eq!(sent[0].headers["authorization"], "Bearer test-key");
        assert_eq!(sent[0].headers["openai-organization"], "org-1");
        assert_eq!(sent[0].headers["openai-project"], "proj-1");
        // The request passed the client's layers: it carries the secret.
        let body: serde_json::Value =
            serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["user_cache_secret"], "scope");
        assert_eq!(body["model"], "m");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_rate_limit_or_a_server_error_is_tried_three_times_in_all() {
    unstuck(async {
        const LIMITED: &str = r#"{"error":{"message":"slow down","type":"rate_limit"}}"#;
        const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;
        for (status, body) in [(429, LIMITED), (500, BROKEN), (503, BROKEN)] {
            // Always failing: three attempts, then the API's error.
            let f = fake(vec![ready("first")], None, move |_, _| {
                Answer::Respond(status, body)
            })
            .await;
            let error = f.openai.chat().create(chat_request()).await.unwrap_err();
            assert!(matches!(error, OpenAIError::ApiError(_)), "{error:?}");
            assert!(Error::from_openai(&error).is_none());
            assert_eq!(f.sent().len(), 3, "{status}");

            // Failing twice: the third attempt answers.
            let f = fake(vec![ready("first")], None, move |_, before| {
                if before < 2 {
                    Answer::Respond(status, body)
                } else {
                    Answer::Respond(200, CHAT_RESPONSE)
                }
            })
            .await;
            f.openai.chat().create(chat_request()).await.unwrap();
            assert_eq!(f.sent().len(), 3, "{status}");
        }
    })
    .await
}

/// A response that fails with `status` and one header, and then, on the
/// next attempt, a success. Returns how long the call took and how many
/// requests were sent.
async fn retried_after(
    timeout: Option<Duration>,
    status: u16,
    header: (&'static str, &'static str),
) -> (Duration, usize, Result<(), OpenAIError>) {
    const LIMITED: &str = r#"{"error":{"message":"slow down","type":"rate_limit"}}"#;
    let f = fake_within(timeout, vec![ready("first")], None, move |_, before| {
        if before == 0 {
            Answer::RespondWith(status, header.0, header.1, LIMITED)
        } else {
            Answer::Respond(200, CHAT_RESPONSE)
        }
    })
    .await;
    let started = tokio::time::Instant::now();
    let result = f.openai.chat().create(chat_request()).await.map(|_| ());
    (started.elapsed(), f.sent().len(), result)
}

/// The backoff before the first retry: half a second, less up to a
/// quarter.
fn assert_first_backoff(waited: Duration) {
    assert!(
        waited > Duration::from_millis(375) && waited <= Duration::from_millis(500),
        "{waited:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_retry_waits_for_its_backoff_or_for_what_the_response_asks_within_the_limit() {
    unstuck(async {
        const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(500, BROKEN)
        })
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap_err();
        let waited = started.elapsed();
        assert!(
            waited > Duration::from_millis(375 + 750) && waited <= Duration::from_millis(1500),
            "{waited:?}"
        );

        for status in [429, 503] {
            // Seconds, with or without a fraction, and milliseconds.
            let (waited, sent, result) = retried_after(None, status, ("retry-after", "7")).await;
            assert_eq!((waited, sent), (Duration::from_secs(7), 2));
            result.unwrap();
            let (waited, sent, _) = retried_after(None, status, ("retry-after", "1.5")).await;
            assert_eq!((waited, sent), (Duration::from_millis(1500), 2));
            let (waited, sent, _) = retried_after(None, status, ("retry-after-ms", "250")).await;
            assert_eq!((waited, sent), (Duration::from_millis(250), 2));
            // The longest wait that is obeyed.
            let (waited, sent, _) = retried_after(None, status, ("retry-after", "120")).await;
            assert_eq!((waited, sent), (Duration::from_secs(120), 2));
            // No wait at all.
            let (waited, sent, _) = retried_after(None, status, ("retry-after", "0")).await;
            assert_eq!((waited, sent), (Duration::ZERO, 2));
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_response_that_asks_for_too_long_a_wait_ends_the_call_at_once() {
    unstuck(async {
        // The clock of the tests starts at this instant, so these are
        // three minutes and a century ahead.
        const SOON: &str = "Fri, 15 Jan 2027 08:03:00 GMT";
        const FAR: &str = "Thu, 15 Jan 2126 08:00:00 GMT";
        for header in [
            ("retry-after", "121"),
            ("retry-after", "120.001"),
            ("retry-after", "4000000000"),
            ("retry-after", "18446744073709551616"),
            ("retry-after", "1e400"),
            ("retry-after", "inf"),
            ("retry-after-ms", "120001"),
            ("retry-after-ms", "99999999999999999999999"),
            ("retry-after", SOON),
            ("retry-after", FAR),
        ] {
            // A server error is returned as the response that it was.
            let (waited, sent, result) = retried_after(None, 503, header).await;
            assert_eq!((waited, sent), (Duration::ZERO, 1), "{header:?}");
            match result {
                Err(OpenAIError::ApiError(error)) => assert_eq!(error.status_code, 503),
                other => panic!("{header:?}: {other:?}"),
            }
            // A rate limit is the API's error.
            let (waited, sent, result) = retried_after(None, 429, header).await;
            assert_eq!((waited, sent), (Duration::ZERO, 1), "{header:?}");
            match result {
                Err(OpenAIError::ApiError(error)) => {
                    assert_eq!(error.status_code, 429);
                    assert_eq!(error.api_error.message, "slow down");
                }
                other => panic!("{header:?}: {other:?}"),
            }
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_wait_never_outlasts_the_timeout_option() {
    unstuck(async {
        let five = Some(Duration::from_secs(5));
        // Within the timeout: obeyed.
        let (waited, sent, result) = retried_after(five, 503, ("retry-after", "5")).await;
        assert_eq!((waited, sent), (Duration::from_secs(5), 2));
        result.unwrap();
        // Beyond it, though within the fixed limit: the call ends.
        for header in [
            ("retry-after", "6"),
            ("retry-after", "4000000000"),
            ("retry-after-ms", "5001"),
            ("retry-after", "Fri, 15 Jan 2027 08:00:06 GMT"),
        ] {
            let (waited, sent, result) = retried_after(five, 503, header).await;
            assert_eq!((waited, sent), (Duration::ZERO, 1), "{header:?}");
            assert!(
                matches!(result, Err(OpenAIError::ApiError(_))),
                "{header:?}"
            );
        }
        // The backoff is cut to the timeout.
        let brief = Some(Duration::from_millis(100));
        let (waited, sent, _) = retried_after(brief, 503, ("x-unrelated", "1")).await;
        assert_eq!(sent, 2);
        assert!(
            waited > Duration::from_millis(75) && waited <= Duration::from_millis(100),
            "{waited:?}"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_wait_that_cannot_be_read_is_the_backoff() {
    unstuck(async {
        for header in [
            ("retry-after", "-1"),
            ("retry-after", "-4000000000"),
            ("retry-after", "-inf"),
            ("retry-after", "nan"),
            ("retry-after", "soon"),
            ("retry-after", "7 seconds"),
            ("retry-after", "0x10"),
            ("retry-after", ""),
            ("retry-after-ms", "-5"),
            ("retry-after-ms", "Fri, 15 Jan 2027 08:01:00 GMT"),
            // Not in the preferred format of an HTTP date.
            ("retry-after", "Friday, 15-Jan-27 08:01:00 GMT"),
            ("retry-after", "Fri, 15 Jan 2027 08:01:00 PST"),
        ] {
            let (waited, sent, result) = retried_after(None, 503, header).await;
            assert_eq!(sent, 2, "{header:?}");
            assert_first_backoff(waited);
            result.unwrap();
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_date_is_waited_for_and_a_date_in_the_past_is_no_wait() {
    unstuck(async {
        // The clock of the tests starts at 2027-01-15 08:00:00 UTC.
        let (waited, sent, result) =
            retried_after(None, 429, ("retry-after", "Fri, 15 Jan 2027 08:01:30 GMT")).await;
        assert_eq!((waited, sent), (Duration::from_secs(90), 2));
        result.unwrap();
        for past in [
            "Fri, 15 Jan 2027 08:00:00 GMT",
            "Fri, 15 Jan 2027 07:59:59 GMT",
            "Thu, 01 Jan 1970 00:00:00 GMT",
        ] {
            let (waited, sent, _) = retried_after(None, 503, ("retry-after", past)).await;
            assert_eq!((waited, sent), (Duration::ZERO, 2), "{past}");
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn milliseconds_are_preferred_and_a_bad_value_falls_through_to_the_seconds() {
    unstuck(async {
        const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;
        let both = |ms: &'static str, seconds: &'static str| async move {
            let f = fake(vec![ready("first")], None, move |_, before| {
                if before == 0 {
                    let response = http::Response::builder()
                        .status(503)
                        .header("retry-after", seconds)
                        .header("retry-after-ms", ms)
                        .body(BROKEN);
                    Answer::Whole(Response::from(response.unwrap()))
                } else {
                    Answer::Respond(200, CHAT_RESPONSE)
                }
            })
            .await;
            let started = tokio::time::Instant::now();
            let result = f.openai.chat().create(chat_request()).await.map(|_| ());
            (started.elapsed(), f.sent().len(), result.is_ok())
        };
        assert_eq!(
            both("300", "9").await,
            (Duration::from_millis(300), 2, true)
        );
        assert_eq!(both("-1", "9").await, (Duration::from_secs(9), 2, true));
        assert_eq!(both("soon", "9").await, (Duration::from_secs(9), 2, true));
        // Too long in the preferred header: the other is not consulted.
        assert_eq!(both("120001", "1").await, (Duration::ZERO, 1, false));
        assert_eq!(
            both("1", "4000000000").await,
            (Duration::from_millis(1), 2, true)
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn every_wait_of_a_call_is_bounded_and_the_last_attempt_waits_for_nothing() {
    unstuck(async {
        const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;
        // Each response asks for the longest wait that is obeyed.
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::RespondWith(503, "retry-after", "120", BROKEN)
        })
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(240));
        assert_eq!(f.sent().len(), 3);

        // The last response asks for too long a wait, which changes
        // nothing: no attempt would follow it.
        let f = fake(vec![ready("first")], None, |_, before| {
            let wait = if before < 2 { "1" } else { "4000000000" };
            Answer::RespondWith(503, "retry-after", wait, BROKEN)
        })
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(f.sent().len(), 3);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_request_obeys_the_same_bounds_on_its_waits() {
    unstuck(async {
        let relaxed = |timeout: Option<Duration>, wait: &'static str| async move {
            let f = fake_within(timeout, vec![ready("first")], None, move |_, before| {
                if before == 0 {
                    Answer::RespondWith(503, "retry-after", wait, BROKEN)
                } else {
                    Answer::Respond(200, CHAT_RESPONSE)
                }
            })
            .await;
            let started = tokio::time::Instant::now();
            let result = f.openai.relaxed().create(serde_json::json!({})).await;
            (started.elapsed(), f.sent().len(), result.is_ok())
        };
        assert_eq!(relaxed(None, "7").await, (Duration::from_secs(7), 2, true));
        assert_eq!(
            relaxed(None, "4000000000").await,
            (Duration::ZERO, 1, false)
        );
        assert_eq!(relaxed(None, "-3").await.1, 2);
        let five = Some(Duration::from_secs(5));
        assert_eq!(relaxed(five, "6").await, (Duration::ZERO, 1, false));

        // And a relaxed stream, before it starts.
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::RespondWith(503, "retry-after", "4000000000", BROKEN)
        })
        .await;
        let started = tokio::time::Instant::now();
        let result = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        assert!(matches!(result, Err(OpenAIError::ApiError(_))));
        assert_eq!((started.elapsed(), f.sent().len()), (Duration::ZERO, 1));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn other_statuses_are_reported_after_one_attempt() {
    unstuck(async {
        const REFUSED: &str = r#"{"error":{"message":"no","type":"invalid_request_error"}}"#;
        const NO_QUOTA: &str = r#"{"error":{"message":"pay","type":"insufficient_quota"}}"#;
        for (status, body) in [
            (400, REFUSED),
            (401, REFUSED),
            (404, REFUSED),
            (408, REFUSED),
            (409, REFUSED),
            (422, REFUSED),
            (429, NO_QUOTA),
        ] {
            let f = fake(vec![ready("first")], None, move |_, _| {
                Answer::Respond(status, body)
            })
            .await;
            let error = f.openai.chat().create(chat_request()).await.unwrap_err();
            assert!(matches!(error, OpenAIError::ApiError(_)), "{error:?}");
            assert_eq!(f.sent().len(), 1, "{status}");
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_failure_of_the_client_is_reported_once_and_found_in_the_openai_error() {
    unstuck(async {
        for (kind, timeout) in [
            (ErrorKind::Network, false),
            (ErrorKind::Network, true),
            (ErrorKind::Attestation, false),
            (ErrorKind::Configuration, false),
        ] {
            let f = fake(vec![ready("first"), later("second")], None, move |_, _| {
                let error = match kind {
                    ErrorKind::Network => Error::network("connection refused"),
                    ErrorKind::Attestation => Error::attestation("unsealed response"),
                    _ => Error::configuration("refused request"),
                };
                Answer::Fail(if timeout { error.timed_out() } else { error })
            })
            .await;
            let started = tokio::time::Instant::now();
            let error = f.openai.chat().create(chat_request()).await.unwrap_err();
            assert!(matches!(error, OpenAIError::Boxed(_)), "{error:?}");
            let found = client_error(&error);
            assert_eq!(found.kind(), kind);
            assert_eq!(found.is_timeout(), timeout);
            assert_eq!(f.sent().len(), 1, "{kind}");
            assert_eq!(f.script.calls(), 1);
            // No backoff was waited for.
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_verification_that_fails_is_reported_once_and_nothing_is_sent() {
    unstuck(async {
        let f = fake(
            vec![
                ready("first"),
                Step::Ready(Err(Error::attestation("document rejected"))),
                Step::Ready(Err(Error::attestation("document rejected again"))),
                later("unused"),
            ],
            None,
            |_, _| Answer::Respond(200, CHAT_RESPONSE),
        )
        .await;
        tokio::time::advance(HOUR).await;
        let error = f.openai.chat().create(chat_request()).await.unwrap_err();
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Attestation);
        assert!(found.earlier_attempt().is_some());
        assert!(f.sent().is_empty());
        // The verification's own retry, and no further one.
        assert_eq!(f.script.calls(), 3);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_api_base_on_another_origin_is_refused_by_the_client_underneath() {
    unstuck(async {
        // Were the API base ever one of another origin, the client's
        // origin restriction would refuse every call.
        let script = Script::new([ready("first")]);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mode = Scripted {
            answers: Arc::new(|_, _| Answer::Respond(200, CHAT_RESPONSE)),
            sent: Arc::clone(&sent),
        };
        let enclave =
            Enclave::from_source("enclave.example.com", script.source(), None, tokio_clock());
        let transport = Transport::connect(enclave, Arc::new(mode), true)
            .await
            .unwrap();
        let client = AttestedClient::new(
            transport,
            Settings {
                mode: TransportMode::Tls,
                base_url: None,
                secret: None,
                timeout: None,
            },
        )
        .unwrap();
        let elsewhere = Url::parse("https://evil.example.com/v1/").unwrap();
        let waits = Waits {
            timeout: None,
            clock: tokio_clock(),
        };
        let openai = openai_client(
            config(),
            &elsewhere,
            Arc::new(client),
            TransportMode::Tls,
            waits,
        )
        .unwrap()
        .0;
        let error = openai.chat().create(chat_request()).await.unwrap_err();
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Configuration);
        assert!(found.to_string().contains("refusing to send"), "{found}");
        assert!(sent.lock().unwrap().is_empty());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_key_rejection_is_healed_below_the_openai_client_with_one_more_send() {
    unstuck(async {
        let f = fake(
            vec![ready("before"), later("after")],
            Some("scope"),
            |sent, _| match sent.binding {
                "before" => Answer::LacksKey,
                _ => Answer::Respond(200, CHAT_RESPONSE),
            },
        )
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap();
        assert_eq!(f.bindings(), ["before", "after"]);
        assert_eq!(f.script.calls(), 2);
        assert_eq!(started.elapsed(), Duration::ZERO);
        let sent = f.sent();
        assert_eq!(sent[0].body, sent[1].body);
        assert!(sent[1].body.as_deref().unwrap().contains("scope"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_upload_is_built_again_once_after_a_key_rejection() {
    unstuck(async {
        let f = fake(
            vec![ready("before"), later("after")],
            None,
            |sent, _| match sent.binding {
                "before" => Answer::LacksKey,
                _ => Answer::Respond(200, TRANSCRIPTION_RESPONSE),
            },
        )
        .await;
        let raw = f
            .openai
            .audio()
            .transcription()
            .create_raw(transcription())
            .await
            .unwrap();
        assert_eq!(raw.as_ref(), TRANSCRIPTION_RESPONSE.as_bytes());
        let sent = f.sent();
        assert_eq!(f.bindings(), ["before", "after"]);
        assert_eq!(f.script.calls(), 2);
        for sent in &sent {
            assert!(sent.streamed, "an upload is a stream");
            let content_type = sent.headers["content-type"].to_str().unwrap();
            assert!(content_type.starts_with("multipart/form-data; boundary="));
            assert_eq!(
                sent.url.as_str(),
                "https://enclave.example.com/v1/audio/transcriptions"
            );
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_upload_whose_second_send_is_rejected_too_is_reported_with_both_rejections() {
    unstuck(async {
        let f = fake(
            vec![ready("first"), later("second"), later("third")],
            None,
            |_, _| Answer::LacksKey,
        )
        .await;
        let error = f
            .openai
            .audio()
            .transcription()
            .create_raw(transcription())
            .await
            .unwrap_err();
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Attestation);
        let attempts: Vec<String> = std::iter::successors(Some(found), |e| e.earlier_attempt())
            .map(Error::to_string)
            .collect();
        assert_eq!(attempts.len(), 3, "{attempts:?}");
        assert!(attempts[0].contains("cannot be replayed"), "{attempts:?}");
        // Two sends, two verifications after the first, and no more.
        assert_eq!(f.bindings(), ["first", "second"]);
        assert_eq!(f.script.calls(), 2);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_body_that_fails_while_it_is_read_carries_the_clients_error() {
    unstuck(async {
        // A deadline on the client ends the read of a response.
        let script = Script::new([ready("first")]);
        struct Stalling;
        impl Mode<Record> for Stalling {
            fn validate_request(&self, _: &Request) -> Result<(), Error> {
                Ok(())
            }
            fn bind(&self, _: &Record) -> Result<Arc<dyn RoundTrip>, Error> {
                Ok(Arc::new(Stalling))
            }
        }
        impl RoundTrip for Stalling {
            fn round_trip(&self, _: Request) -> BoxFuture<Result<Response, Failure>> {
                Box::pin(async {
                    let body = futures_util::stream::iter([Ok::<_, std::io::Error>(chunk("a"))])
                        .chain(futures_util::stream::pending());
                    Ok(Response::from(http::Response::new(
                        reqwest::Body::wrap_stream(body),
                    )))
                })
            }
        }
        let enclave =
            Enclave::from_source("enclave.example.com", script.source(), None, tokio_clock());
        let transport = Transport::connect(enclave, Arc::new(Stalling), true)
            .await
            .unwrap();
        let client = AttestedClient::new(
            transport,
            Settings {
                mode: TransportMode::Tls,
                base_url: None,
                secret: None,
                timeout: Some(Duration::from_secs(5)),
            },
        )
        .unwrap();
        let openai = Kit::new(client, TransportMode::Tls);

        // Read whole: the call fails at the deadline.
        let started = tokio::time::Instant::now();
        let error = openai.chat().create(chat_request()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Network);
        assert!(found.is_timeout());

        // Read as a stream: the events before the deadline arrive.
        let mut stream = openai
            .chat()
            .create_stream(streaming_chat_request())
            .await
            .unwrap();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.choices[0].delta.content.as_deref(), Some("a"));
        // The stream ends in an error at the deadline. `async_openai`
        // keeps the message of that error only, so the client's error is
        // not found in it.
        let started = tokio::time::Instant::now();
        let error = stream.next().await.unwrap().unwrap_err();
        assert!(started.elapsed() <= Duration::from_secs(5));
        assert_unclassified_stream_error(&error);
        assert!(stream.next().await.is_none());

        // A relaxed stream over the same response keeps the client's
        // error.
        let mut stream = openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await
            .unwrap();
        stream.next().await.unwrap().unwrap();
        let error = stream.next().await.unwrap().unwrap_err();
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Network);
        assert!(found.is_timeout());
        assert!(stream.next().await.is_none());
    })
    .await
}

/// A typed stream reports a failed read as a stream error that holds the
/// message of the failure and no client error.
fn assert_unclassified_stream_error(error: &OpenAIError) {
    match error {
        OpenAIError::StreamError(inner) => assert!(
            matches!(**inner, async_openai::error::StreamError::EventStream(_)),
            "{inner:?}"
        ),
        other => panic!("{other:?}"),
    }
    assert!(Error::from_openai(error).is_none());
}

#[tokio::test(start_paused = true)]
async fn a_typed_stream_whose_connection_breaks_ends_in_an_error() {
    unstuck(async {
        const EVENT: &str = "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"},\"finish_reason\":null}]}\n\n";
        let f = fake(vec![ready("first")], None, |_, _| Answer::Broken(EVENT)).await;
        let mut stream = f
            .openai
            .chat()
            .create_stream(streaming_chat_request())
            .await
            .unwrap();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.choices[0].delta.content.as_deref(), Some("a"));
        let error = stream.next().await.unwrap().unwrap_err();
        assert_unclassified_stream_error(&error);
        assert!(stream.next().await.is_none());
        // Nothing is tried again once a stream has started.
        assert_eq!(f.sent().len(), 1);

        // A relaxed stream keeps the client's error.
        let mut stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await
            .unwrap();
        stream.next().await.unwrap().unwrap();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(client_error(&error).kind(), ErrorKind::Network);
        assert!(stream.next().await.is_none());
    })
    .await
}

// The relaxed chat handle.

const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;

#[tokio::test(start_paused = true)]
async fn a_relaxed_request_goes_the_way_of_a_typed_one_and_never_asks_for_a_stream() {
    unstuck(async {
        let f = fake(vec![ready("first")], Some("scope"), |_, _| {
            Answer::Respond(200, CHAT_RESPONSE)
        })
        .await;
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "web_search_options": {},
            "structured_outputs": {"regex": "a+"},
            "seed": 12345678901234567890u64,
        });
        let response = f.openai.relaxed().create(body).await.unwrap();
        assert_eq!(response.content(), Some("hello"));
        let sent = f.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].url.as_str(),
            "https://enclave.example.com/v1/chat/completions"
        );
        assert_eq!(sent[0].headers["authorization"], "Bearer test-key");
        assert_eq!(sent[0].headers["openai-organization"], "org-1");
        assert_eq!(sent[0].headers["content-type"], "application/json");
        let body: serde_json::Value =
            serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["stream"], false);
        assert_eq!(body["user_cache_secret"], "scope");
        // What the typed request has no member for is sent as it is.
        assert_eq!(body["structured_outputs"]["regex"], "a+");
        assert_eq!(body["web_search_options"], serde_json::json!({}));
        assert!(
            sent[0]
                .body
                .as_deref()
                .unwrap()
                .contains("12345678901234567890")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_response_may_be_anything_that_is_json() {
    unstuck(async {
        // What a typed response refuses: a finish reason outside the known
        // set, members that it does not know, and members that are missing.
        const ODD: &str = r#"{"choices":[{"message":{"content":null,"reasoning_content":"thinking","tool_calls":[{"id":"t1","function":{"name":"f","arguments":"{\"a\":1}"}}]},"finish_reason":"tool_use_pending"}],"usage":{"prompt_tokens":1},"vendor":{"x":1}}"#;
        let f = fake(vec![ready("first")], None, |_, _| Answer::Respond(200, ODD)).await;
        let typed = f.openai.chat().create(chat_request()).await;
        assert!(matches!(typed, Err(OpenAIError::JSONDeserialize(..))), "{typed:?}");

        let response = f.openai.relaxed().create(serde_json::json!({})).await.unwrap();
        assert_eq!(response.finish_reason(), Some("tool_use_pending"));
        assert_eq!(response.content(), None);
        assert_eq!(response.id(), None);
        assert_eq!(response.model(), None);
        assert_eq!(response.typed_tool_calls().len(), 1);
        assert_eq!(
            response.raw()["choices"][0]["message"]["reasoning_content"],
            "thinking"
        );
        assert_eq!(response.raw()["vendor"]["x"], 1);

        for body in ["{}", "[]", "null", "7"] {
            let f = fake(vec![ready("first")], None, move |_, _| {
                Answer::Respond(200, body)
            })
            .await;
            let response = f.openai.relaxed().create(serde_json::json!({})).await.unwrap();
            assert_eq!(response.content(), None, "{body}");
            assert_eq!(response.choices_len(), 0, "{body}");
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_request_is_retried_and_its_errors_are_read_as_those_of_a_typed_one() {
    unstuck(async {
        // Retried like a typed call.
        let f = fake(vec![ready("first")], None, |_, before| {
            if before < 2 {
                Answer::Respond(503, BROKEN)
            } else {
                Answer::Respond(200, CHAT_RESPONSE)
            }
        })
        .await;
        f.openai.relaxed().create(serde_json::json!({})).await.unwrap();
        assert_eq!(f.sent().len(), 3);

        // The API's error object.
        const REFUSED: &str = r#"{"error":{"message":"no such model","type":"invalid_request_error","param":null,"code":"model_unavailable"}}"#;
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(404, REFUSED)
        })
        .await;
        match f.openai.relaxed().create(serde_json::json!({})).await {
            Err(OpenAIError::ApiError(error)) => {
                assert_eq!(error.status_code, 404);
                assert_eq!(error.api_error.message, "no such model");
                assert_eq!(error.api_error.code.as_deref(), Some("model_unavailable"));
                assert_eq!(error.api_error.param, None);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(f.sent().len(), 1);

        // A server error need not be JSON: its text is the message.
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(502, "bad gateway")
        })
        .await;
        match f.openai.relaxed().create(serde_json::json!({})).await {
            Err(OpenAIError::ApiError(error)) => {
                assert_eq!(error.status_code, 502);
                assert_eq!(error.api_error.message, "bad gateway");
                assert_eq!(error.api_error.code, None);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(f.sent().len(), 3);

        // Any other error status must carry the error object, and a
        // success must be JSON.
        for (status, body) in [(400, "plain text"), (200, "not json")] {
            let f = fake(vec![ready("first")], None, move |_, _| {
                Answer::Respond(status, body)
            })
            .await;
            match f.openai.relaxed().create(serde_json::json!({})).await {
                Err(OpenAIError::JSONDeserialize(_, text)) => assert_eq!(text, body),
                other => panic!("{other:?}"),
            }
            assert_eq!(f.sent().len(), 1);
        }
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_request_reports_a_failure_of_the_client_once_and_is_replayed_after_a_rotation() {
    unstuck(async {
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Fail(Error::attestation("unsealed response"))
        })
        .await;
        for stream in [false, true] {
            let relaxed = f.openai.relaxed();
            let error = if stream {
                relaxed.create_stream(serde_json::json!({})).await.err()
            } else {
                relaxed.create(serde_json::json!({})).await.err()
            }
            .expect("failed");
            assert_eq!(client_error(&error).kind(), ErrorKind::Attestation);
        }
        assert_eq!(f.sent().len(), 2);

        let f = fake(
            vec![ready("before"), later("after")],
            None,
            |sent, _| match sent.binding {
                "before" => Answer::LacksKey,
                _ => Answer::Respond(200, CHAT_RESPONSE),
            },
        )
        .await;
        f.openai
            .relaxed()
            .create(serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(f.bindings(), ["before", "after"]);
    })
    .await
}

/// The chunks of a relaxed stream, and the error that ended it.
async fn collected(
    mut stream: crate::openai::relaxed::RelaxedStream,
) -> (
    Vec<crate::openai::relaxed::RelaxedStreamChunk>,
    Option<OpenAIError>,
) {
    let mut chunks = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => chunks.push(chunk),
            Err(error) => {
                assert!(stream.next().await.is_none(), "an item after the error");
                return (chunks, Some(error));
            }
        }
    }
    (chunks, None)
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_stream_passes_on_every_event_and_ends_at_done() {
    unstuck(async {
        const EVENTS: &str = "data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"hm\"}}]}\n\n\
            data: {\"type\":\"web_search_call\",\"status\":\"in_progress\"}\n\n\
            : keep-alive\n\n\
            data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\r\n\r\n\
            data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"odd_reason\"}]}\n\n\
            data: {\"choices\":[],\"usage\":{\"total_tokens\":3}}\n\n\
            data: [DONE]\n\n\
            data: {\"after\":true}\n\n";
        let f = fake(vec![ready("first")], Some("scope"), |_, _| {
            Answer::Respond(200, EVENTS)
        })
        .await;
        let stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({"model": "m", "stream": false}))
            .await
            .unwrap();
        let (chunks, error) = collected(stream).await;
        assert!(error.is_none(), "{error:?}");
        assert_eq!(chunks.len(), 5);
        assert_eq!(
            chunks[0].raw()["choices"][0]["delta"]["reasoning_content"],
            "hm"
        );
        assert!(chunks[1].is_vendor_event());
        assert_eq!(chunks[1].event_type(), Some("web_search_call"));
        assert_eq!(chunks[2].delta_content(), Some("hel"));
        assert_eq!(chunks[3].finish_reason(), Some("odd_reason"));
        assert_eq!(chunks[4].raw()["usage"]["total_tokens"], 3);
        assert_eq!(chunks[4].delta_content(), None);

        let sent = f.sent();
        let body: serde_json::Value =
            serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["stream"], true);
        assert_eq!(body["user_cache_secret"], "scope");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_stream_without_done_ends_after_a_complete_event_and_fails_inside_one() {
    unstuck(async {
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(200, "data: {\"n\":1}\n\ndata: {\"n\":2}\n\n")
        })
        .await;
        let stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        let (chunks, error) = collected(stream.unwrap()).await;
        assert_eq!(chunks.len(), 2);
        assert!(error.is_none(), "{error:?}");

        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(200, "data: {\"n\":1}\n\ndata: {\"n\":2}")
        })
        .await;
        let stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        let (chunks, error) = collected(stream.unwrap()).await;
        assert_eq!(chunks.len(), 1);
        assert!(
            matches!(error, Some(OpenAIError::StreamError(_))),
            "{error:?}"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_relaxed_stream_is_retried_before_it_starts_and_never_after() {
    unstuck(async {
        // An error status is retried like any call, and then reported.
        let f = fake(vec![ready("first")], None, |_, before| {
            if before < 2 {
                Answer::Respond(500, BROKEN)
            } else {
                Answer::Respond(200, "data: {\"n\":1}\n\ndata: [DONE]\n\n")
            }
        })
        .await;
        let stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        assert_eq!(collected(stream.unwrap()).await.0.len(), 1);
        assert_eq!(f.sent().len(), 3);

        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(401, r#"{"error":{"message":"no key","type":"auth"}}"#)
        })
        .await;
        let refused = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        assert!(matches!(refused.err(), Some(OpenAIError::ApiError(_))));
        assert_eq!(f.sent().len(), 1);

        // A stream that breaks after it started is not sent again, and the
        // failure carries the client's error.
        let f = fake(vec![ready("first"), later("second")], None, |_, _| {
            Answer::Broken("data: {\"n\":1}\n\ndata: {\"n\":")
        })
        .await;
        let stream = f
            .openai
            .relaxed()
            .create_stream(serde_json::json!({}))
            .await;
        let (chunks, error) = collected(stream.unwrap()).await;
        assert_eq!(chunks.len(), 1);
        let error = error.expect("the stream broke");
        assert_eq!(client_error(&error).kind(), ErrorKind::Network);
        assert_eq!(f.sent().len(), 1);
    })
    .await
}

// The helpers.

#[tokio::test(start_paused = true)]
async fn a_batch_of_embeddings_comes_back_in_the_order_of_the_inputs() {
    unstuck(async {
        const SHUFFLED: &str = r#"{"object":"list","model":"m","data":[{"index":2,"object":"embedding","embedding":[2.0]},{"index":0,"object":"embedding","embedding":[0.0]},{"index":1,"object":"embedding","embedding":[1.0]}],"usage":{"prompt_tokens":1,"total_tokens":1}}"#;
        let f = fake(vec![ready("first")], Some("scope"), |_, _| {
            Answer::Respond(200, SHUFFLED)
        })
        .await;
        let inputs = ["a", "b", "c"].map(str::to_owned).to_vec();
        let vectors = crate::openai::embed_batch(&f.openai, "m".to_owned(), inputs)
            .await
            .unwrap();
        assert_eq!(vectors, [[0.0], [1.0], [2.0]]);
        let sent = f.sent();
        assert_eq!(
            sent[0].url.as_str(),
            "https://enclave.example.com/v1/embeddings"
        );
        let body: serde_json::Value =
            serde_json::from_str(sent[0].body.as_deref().unwrap()).unwrap();
        assert_eq!(body["input"], serde_json::json!(["a", "b", "c"]));
        assert_eq!(body["model"], "m");
        assert!(body.get("user_cache_secret").is_none());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn embeddings_that_do_not_match_the_inputs_one_to_one_are_refused() {
    unstuck(async {
        const TWO: &str = r#"{"object":"list","model":"m","data":[{"index":0,"object":"embedding","embedding":[0.0]},{"index":1,"object":"embedding","embedding":[1.0]}],"usage":{"prompt_tokens":1,"total_tokens":1}}"#;
        const REPEATED: &str = r#"{"object":"list","model":"m","data":[{"index":0,"object":"embedding","embedding":[0.0]},{"index":0,"object":"embedding","embedding":[1.0]}],"usage":{"prompt_tokens":1,"total_tokens":1}}"#;
        const OFFSET: &str = r#"{"object":"list","model":"m","data":[{"index":1,"object":"embedding","embedding":[0.0]},{"index":2,"object":"embedding","embedding":[1.0]}],"usage":{"prompt_tokens":1,"total_tokens":1}}"#;
        for (body, inputs) in [(TWO, 3), (TWO, 1), (REPEATED, 2), (OFFSET, 2)] {
            let f = fake(vec![ready("first")], None, move |_, _| {
                Answer::Respond(200, body)
            })
            .await;
            let inputs = vec!["x".to_owned(); inputs];
            let error = crate::openai::embed_batch(&f.openai, "m".to_owned(), inputs)
                .await
                .unwrap_err();
            assert!(matches!(error, OpenAIError::InvalidArgument(_)), "{error:?}");
        }
        let f = fake(vec![ready("first")], None, |_, _| Answer::Respond(200, TWO)).await;
        let inputs = vec!["x".to_owned(); 2];
        crate::openai::embed_batch(&f.openai, "m".to_owned(), inputs)
            .await
            .unwrap();
    })
    .await
}

// On the real modes.

mod over_ehbp {
    use super::*;
    use crate::internal::transport::ehbp::tests::{self as ehbp, Reply, Seen, key, serve};

    /// An `async_openai` client that reaches its enclave through a local
    /// server, as through a proxy, in the EHBP mode.
    async fn client(server: &ehbp::Server, hpke: &str) -> Kit {
        let clock = tokio_clock();
        let mut evidence = ehbp::evidence("e", Some(hpke));
        evidence.expires = Some(clock() + HOUR);
        let script = Script::new([Step::Ready(Ok(evidence))]);
        let enclave = Enclave::from_source("enclave.example.com", script.source(), None, clock);
        let transport = soon(Transport::connect(enclave, Arc::new(ehbp::mode()), true))
            .await
            .unwrap();
        let client = AttestedClient::new(
            transport,
            Settings {
                mode: TransportMode::Ehbp,
                base_url: Some(server.url.join("v1/").unwrap()),
                secret: Some(Secret::new("s3cret-scope")),
                timeout: None,
            },
        )
        .unwrap();
        Kit::new(client, TransportMode::Ehbp)
    }

    /// What every request of the attested chain shows on the wire: a
    /// sealed body and the header that names the enclave to the proxy.
    fn assert_attested(seen: &Seen, target: &str) {
        assert_eq!(seen.target, target);
        assert!(seen.sealed, "{target}: the body was not sealed");
        assert_eq!(
            seen.header("x-tinfoil-enclave-url"),
            Some("https://enclave.example.com"),
            "{target}"
        );
        assert_eq!(seen.header("authorization"), Some("Bearer test-key"));
    }

    fn app(seen: &Seen) -> Reply {
        match seen.target.as_str() {
            "/v1/chat/completions"
                if String::from_utf8_lossy(&seen.body).contains("\"stream\":true") =>
            {
                Reply::parts(vec![
                    ehbp::data(&chunk("one")),
                    ehbp::data(&chunk("two")),
                    ehbp::data("data: [DONE]\n\n"),
                ])
                .header("content-type", "text/event-stream")
            }
            "/v1/chat/completions" => Reply::ok(CHAT_RESPONSE),
            "/v1/embeddings" => Reply::ok(EMBEDDING_RESPONSE),
            "/v1/audio/transcriptions" => Reply::ok(TRANSCRIPTION_RESPONSE),
            _ => Reply::ok("{}"),
        }
    }

    #[tokio::test]
    async fn a_chat_completion_is_sealed_and_carries_the_cache_secret() {
        let held = key(1);
        let server = serve(&held, app).await;
        let openai = client(&server, &held.public_hex).await;
        let response = soon(openai.chat().create(chat_request())).await.unwrap();
        assert_eq!(
            response.choices[0].message.content.as_deref(),
            Some("hello")
        );
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert_attested(&seen[0], "/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["user_cache_secret"], "s3cret-scope");
        let wire = String::from_utf8_lossy(&seen[0].wire);
        assert!(!wire.contains("private prompt") && !wire.contains("s3cret-scope"));
    }

    #[tokio::test]
    async fn a_streamed_chat_completion_is_sealed_both_ways() {
        let held = key(1);
        let server = serve(&held, app).await;
        let openai = client(&server, &held.public_hex).await;
        let mut stream = soon(openai.chat().create_stream(streaming_chat_request()))
            .await
            .unwrap();
        let mut text = String::new();
        while let Some(event) = soon(stream.next()).await {
            text.push_str(event.unwrap().choices[0].delta.content.as_deref().unwrap());
        }
        assert_eq!(text, "onetwo");
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert_attested(&seen[0], "/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["stream"], true);
        assert_eq!(body["user_cache_secret"], "s3cret-scope");
    }

    #[tokio::test]
    async fn a_stream_whose_sealed_body_stops_authenticating_ends_in_an_error() {
        let held = key(1);
        let server = serve(&held, |_| {
            Reply::parts(vec![
                ehbp::data(&chunk("one")),
                ehbp::Part::Tampered(chunk("forged").into_bytes()),
                ehbp::data(&chunk("three")),
                ehbp::data("data: [DONE]\n\n"),
            ])
            .header("content-type", "text/event-stream")
        })
        .await;
        let openai = client(&server, &held.public_hex).await;

        // Typed: the authentic event arrives, then the stream ends in an
        // error and delivers nothing of the forged frame or after it. The
        // error holds a message only, which does not name the cause.
        let mut stream = soon(openai.chat().create_stream(streaming_chat_request()))
            .await
            .unwrap();
        let first = soon(stream.next()).await.unwrap().unwrap();
        assert_eq!(first.choices[0].delta.content.as_deref(), Some("one"));
        let error = soon(stream.next()).await.unwrap().unwrap_err();
        assert_unclassified_stream_error(&error);
        assert!(soon(stream.next()).await.is_none());

        // Relaxed: the same, and the error is the client's.
        let mut stream = soon(openai.relaxed().create_stream(serde_json::json!({})))
            .await
            .unwrap();
        let first = soon(stream.next()).await.unwrap().unwrap();
        assert!(first.raw().to_string().contains("one"));
        let error = soon(stream.next()).await.unwrap().unwrap_err();
        assert_eq!(client_error(&error).kind(), ErrorKind::Attestation);
        assert!(soon(stream.next()).await.is_none());
    }

    #[tokio::test]
    async fn an_embedding_request_is_sealed_and_gets_no_cache_secret() {
        let held = key(1);
        let server = serve(&held, app).await;
        let openai = client(&server, &held.public_hex).await;
        let request = CreateEmbeddingRequestArgs::default()
            .model("m")
            .input("private text")
            .build()
            .unwrap();
        let response = soon(openai.embeddings().create(request)).await.unwrap();
        assert_eq!(response.data[0].embedding, [0.5, 0.25]);
        let seen = server.seen();
        assert_attested(&seen[0], "/v1/embeddings");
        let body = String::from_utf8_lossy(&seen[0].body);
        assert!(body.contains("private text") && !body.contains("user_cache_secret"));
    }

    #[tokio::test]
    async fn an_upload_is_sealed() {
        let held = key(1);
        let server = serve(&held, app).await;
        let openai = client(&server, &held.public_hex).await;
        let raw = soon(openai.audio().transcription().create_raw(transcription()))
            .await
            .unwrap();
        assert_eq!(raw.as_ref(), TRANSCRIPTION_RESPONSE.as_bytes());
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert_attested(&seen[0], "/v1/audio/transcriptions");
        assert!(String::from_utf8_lossy(&seen[0].body).contains("RIFF-private-audio"));
        assert!(!String::from_utf8_lossy(&seen[0].wire).contains("RIFF-private-audio"));
        let content_type = seen[0].header("content-type").unwrap();
        assert!(content_type.starts_with("multipart/form-data; boundary="));
    }

    #[tokio::test]
    async fn a_responses_request_is_sealed_and_carries_the_cache_secret() {
        let held = key(1);
        let server = serve(&held, app).await;
        let openai = client(&server, &held.public_hex).await;
        let request = CreateResponseArgs::default()
            .model("m")
            .input("private input")
            .build()
            .unwrap();
        // The local server's answer is not a response object; what the
        // request looked like on the wire is what is checked.
        let _ = soon(openai.responses().create(request)).await;
        let seen = server.seen();
        assert_eq!(seen.len(), 1);
        assert_attested(&seen[0], "/v1/responses");
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["user_cache_secret"], "s3cret-scope");
    }

    #[tokio::test]
    async fn a_relaxed_request_and_a_relaxed_stream_are_sealed_and_carry_the_cache_secret() {
        let held = key(1);
        let server = serve(&held, app).await;
        let kit = client(&server, &held.public_hex).await;
        let body = || serde_json::json!({"model": "m", "private": "relaxed prompt"});

        let response = soon(kit.relaxed().create(body())).await.unwrap();
        assert_eq!(response.content(), Some("hello"));

        let stream = soon(kit.relaxed().create_stream(body())).await.unwrap();
        let (chunks, error) = soon(collected(stream)).await;
        assert!(error.is_none(), "{error:?}");
        let text: String = chunks.iter().filter_map(|c| c.delta_content()).collect();
        assert_eq!(text, "onetwo");

        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        for (seen, stream) in seen.iter().zip([false, true]) {
            assert_attested(seen, "/v1/chat/completions");
            let body: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            assert_eq!(body["stream"], stream);
            assert_eq!(body["user_cache_secret"], "s3cret-scope");
            assert!(!String::from_utf8_lossy(&seen.wire).contains("relaxed prompt"));
        }
    }

    #[tokio::test]
    async fn a_typed_transcription_and_a_batch_of_embeddings_are_sealed() {
        let held = key(1);
        let server = serve(&held, app).await;
        let kit = client(&server, &held.public_hex).await;

        // What `transcribe` does.
        let transcript = soon(kit.audio().transcription().create(transcription()))
            .await
            .unwrap();
        assert_eq!(transcript.text, "hello");

        let vectors = soon(crate::openai::embed_batch(
            &kit,
            "m".to_owned(),
            vec!["private text".to_owned()],
        ))
        .await
        .unwrap();
        assert_eq!(vectors, [[0.5, 0.25]]);

        let seen = server.seen();
        assert_attested(&seen[0], "/v1/audio/transcriptions");
        assert!(String::from_utf8_lossy(&seen[0].body).contains("RIFF-private-audio"));
        assert!(!String::from_utf8_lossy(&seen[0].wire).contains("RIFF-private-audio"));
        assert_attested(&seen[1], "/v1/embeddings");
        assert!(!String::from_utf8_lossy(&seen[1].wire).contains("private text"));
    }

    #[tokio::test]
    async fn an_image_and_an_audio_clip_from_the_helpers_are_sealed_in_a_chat_request() {
        use crate::multimodal::{ImageUrlExt, InputAudioExt};
        use async_openai::types::chat::{
            ChatCompletionRequestMessageContentPartAudio,
            ChatCompletionRequestMessageContentPartImage,
            ChatCompletionRequestUserMessageContentPart, ImageUrl, InputAudio, InputAudioFormat,
        };

        let held = key(1);
        let server = serve(&held, app).await;
        let kit = client(&server, &held.public_hex).await;
        let image = ImageUrl::from_bytes(b"private-pixels", "image/png");
        let audio = InputAudio::from_bytes(b"private-samples", InputAudioFormat::Wav);
        let parts = vec![
            ChatCompletionRequestUserMessageContentPart::ImageUrl(
                ChatCompletionRequestMessageContentPartImage {
                    image_url: image,
                    prompt_cache_breakpoint: None,
                },
            ),
            ChatCompletionRequestUserMessageContentPart::InputAudio(
                ChatCompletionRequestMessageContentPartAudio {
                    input_audio: audio,
                    prompt_cache_breakpoint: None,
                },
            ),
        ];
        let request = CreateChatCompletionRequestArgs::default()
            .model("m")
            .messages([ChatCompletionRequestUserMessageArgs::default()
                .content(parts)
                .build()
                .unwrap()
                .into()])
            .build()
            .unwrap();
        soon(kit.chat().create(request)).await.unwrap();

        let seen = server.seen();
        assert_attested(&seen[0], "/v1/chat/completions");
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        let content = &body["messages"][0]["content"];
        // base64 of the bytes that were given.
        assert_eq!(
            content[0]["image_url"]["url"],
            "data:image/png;base64,cHJpdmF0ZS1waXhlbHM="
        );
        assert_eq!(content[1]["input_audio"]["data"], "cHJpdmF0ZS1zYW1wbGVz");
        assert_eq!(content[1]["input_audio"]["format"], "wav");
        let wire = String::from_utf8_lossy(&seen[0].wire);
        assert!(!wire.contains("cHJpdmF0ZS1waXhlbHM") && !wire.contains("cHJpdmF0ZS1zYW1wbGVz"));
    }

    #[tokio::test]
    async fn an_upload_is_sent_again_under_the_new_key_after_a_rotation() {
        // The enclave holds key 2; the first verification endorsed key 1.
        let (stale, held) = (key(1), key(2));
        let server = serve(&held, app).await;
        let clock = tokio_clock();
        let steps = [&stale, &held].map(|key| {
            let mut evidence = ehbp::evidence("e", Some(&key.public_hex));
            evidence.expires = Some(clock() + HOUR);
            Step::Ready(Ok(evidence))
        });
        let script = Script::new(steps);
        let enclave = Enclave::from_source("enclave.example.com", script.source(), None, clock);
        let transport = soon(Transport::connect(enclave, Arc::new(ehbp::mode()), true))
            .await
            .unwrap();
        let client = AttestedClient::new(
            transport,
            Settings {
                mode: TransportMode::Ehbp,
                base_url: Some(server.url.join("v1/").unwrap()),
                secret: None,
                timeout: None,
            },
        )
        .unwrap();
        let openai = Kit::new(client, TransportMode::Ehbp);

        let raw = soon(openai.audio().transcription().create_raw(transcription()))
            .await
            .expect("sent again");
        assert_eq!(raw.as_ref(), TRANSCRIPTION_RESPONSE.as_bytes());
        assert_eq!(script.calls(), 2);
        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        assert!(!seen[0].sealed && seen[1].sealed);
        assert!(String::from_utf8_lossy(&seen[1].body).contains("RIFF-private-audio"));
    }
}

mod over_tls {
    use super::*;
    use crate::internal::transport::tls::testing::made::{KEY_A, LEAF_A};
    use crate::internal::transport::tls::testing::{
        Handler, Protocols, Seen, Server, certificate, full, roots, serve,
    };
    use crate::internal::transport::tls::{TlsMode, leaf_fingerprint};

    /// A server whose certificate only the test's TLS mode trusts: a
    /// request that did not go through the attested client could not
    /// complete its handshake.
    async fn server() -> Arc<Server> {
        let handler: Handler = Arc::new(|seen: Seen| {
            Box::pin(async move {
                let streaming = String::from_utf8_lossy(&seen.body).contains("\"stream\":true");
                let body = match seen.target.as_str() {
                    "/v1/chat/completions" if streaming => {
                        chunk("one") + &chunk("two") + "data: [DONE]\n\n"
                    }
                    "/v1/chat/completions" => CHAT_RESPONSE.to_owned(),
                    "/v1/embeddings" => EMBEDDING_RESPONSE.to_owned(),
                    _ => TRANSCRIPTION_RESPONSE.to_owned(),
                };
                let content_type = if streaming {
                    "text/event-stream"
                } else {
                    "application/json"
                };
                hyper::Response::builder()
                    .header("content-type", content_type)
                    .body(full(body))
                    .unwrap()
            })
        });
        serve(&LEAF_A, &KEY_A, Protocols::Both, handler).await
    }

    async fn client(server: &Server) -> Kit {
        let evidence = Record {
            name: "e",
            tls: Some(leaf_fingerprint(&certificate(&LEAF_A)).unwrap()),
            hpke: None,
            expires: Some((tokio_clock())() + HOUR),
        };
        let script = Script::new([Step::Ready(Ok(evidence))]);
        let host = format!("127.0.0.1:{}", server.port);
        let enclave = Enclave::from_source(&host, script.source(), None, tokio_clock());
        let mode = TlsMode::for_test(roots(), None);
        let transport = soon(Transport::connect(enclave, Arc::new(mode), true))
            .await
            .unwrap();
        let client = AttestedClient::new(
            transport,
            Settings {
                mode: TransportMode::Tls,
                base_url: None,
                secret: Some(Secret::new("s3cret-scope")),
                timeout: None,
            },
        )
        .unwrap();
        Kit::new(client, TransportMode::Tls)
    }

    #[tokio::test]
    async fn every_kind_of_call_reaches_the_pinned_server_through_the_client() {
        let server = server().await;
        let openai = client(&server).await;

        let response = soon(openai.chat().create(chat_request())).await.unwrap();
        assert_eq!(response.id, "c1");

        let mut stream = soon(openai.chat().create_stream(streaming_chat_request()))
            .await
            .unwrap();
        let mut text = String::new();
        while let Some(event) = soon(stream.next()).await {
            text.push_str(event.unwrap().choices[0].delta.content.as_deref().unwrap());
        }
        assert_eq!(text, "onetwo");

        let request = CreateEmbeddingRequestArgs::default()
            .model("m")
            .input("text")
            .build()
            .unwrap();
        soon(openai.embeddings().create(request)).await.unwrap();

        soon(openai.audio().transcription().create_raw(transcription()))
            .await
            .unwrap();

        let seen = server.seen();
        let targets: Vec<&str> = seen.iter().map(|seen| seen.target.as_str()).collect();
        assert_eq!(
            targets,
            [
                "/v1/chat/completions",
                "/v1/chat/completions",
                "/v1/embeddings",
                "/v1/audio/transcriptions"
            ]
        );
        for seen in &seen {
            assert_eq!(seen.headers["authorization"], "Bearer test-key");
        }
        // The chat bodies passed the client's layers.
        for chat in &seen[..2] {
            let body: serde_json::Value = serde_json::from_slice(&chat.body).unwrap();
            assert_eq!(body["user_cache_secret"], "s3cret-scope");
        }
        assert!(String::from_utf8_lossy(&seen[3].body).contains("RIFF-private-audio"));
        // One pinned connection carried them all.
        assert_eq!(server.accepted(), 1);
    }

    #[tokio::test]
    async fn a_relaxed_request_and_a_relaxed_stream_reach_the_pinned_server() {
        let server = server().await;
        let kit = client(&server).await;
        let response = soon(kit.relaxed().create(serde_json::json!({"model": "m"})))
            .await
            .unwrap();
        assert_eq!(response.id(), Some("c1"));
        let stream = soon(
            kit.relaxed()
                .create_stream(serde_json::json!({"model": "m"})),
        )
        .await
        .unwrap();
        let (chunks, error) = soon(collected(stream)).await;
        assert!(error.is_none(), "{error:?}");
        assert_eq!(chunks.len(), 2);

        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        for (seen, stream) in seen.iter().zip([false, true]) {
            assert_eq!(seen.target, "/v1/chat/completions");
            assert_eq!(seen.headers["authorization"], "Bearer test-key");
            let body: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            assert_eq!(body["stream"], stream);
            assert_eq!(body["user_cache_secret"], "s3cret-scope");
        }
    }
}
