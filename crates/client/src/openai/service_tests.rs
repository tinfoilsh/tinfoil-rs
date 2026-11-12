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

use super::openai_client;
use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::attested::{AttestedClient, Settings};
use crate::internal::enclave::Enclave;
use crate::internal::testing::{Record, Script, Step, record, tokio_clock};
use crate::internal::transport::{Failure, Mode, RoundTrip, Transport};
use crate::options::{Secret, TransportMode};

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

const CHAT_RESPONSE: &str = r#"{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}"#;

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
    LacksKey,
    Fail(Error),
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
                Answer::LacksKey => Err(Failure::peer_lacks_key(Error::attestation(
                    "the peer does not hold the attested key",
                ))),
                Answer::Fail(error) => Err(error.into()),
            }
        })
    }
}

struct Fake {
    script: Arc<Script>,
    openai: OpenAI,
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
            timeout: None,
        },
    )
    .unwrap();
    let api_base = client.openai_url().clone();
    let openai = openai_client(config(), &api_base, Arc::new(client), TransportMode::Tls).unwrap();
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

#[tokio::test(start_paused = true)]
async fn a_retry_waits_for_its_backoff_or_for_what_the_response_asks() {
    unstuck(async {
        const BROKEN: &str = r#"{"error":{"message":"broken","type":"server_error"}}"#;
        let f = fake(vec![ready("first")], None, |_, _| {
            Answer::Respond(500, BROKEN)
        })
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_millis(100 + 200));

        let f = fake(vec![ready("first")], None, |_, before| {
            if before == 0 {
                Answer::RespondWith(503, "retry-after", "7", BROKEN)
            } else {
                Answer::Respond(200, CHAT_RESPONSE)
            }
        })
        .await;
        let started = tokio::time::Instant::now();
        f.openai.chat().create(chat_request()).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_secs(7));
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
        let openai =
            openai_client(config(), &elsewhere, Arc::new(client), TransportMode::Tls).unwrap();
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
                _ => Answer::Respond(200, r#"{"text":"hello"}"#),
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
        assert_eq!(raw.as_ref(), br#"{"text":"hello"}"#);
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
        let api_base = client.openai_url().clone();
        let openai =
            openai_client(config(), &api_base, Arc::new(client), TransportMode::Tls).unwrap();

        // Read whole: the call fails at the deadline.
        let started = tokio::time::Instant::now();
        let error = openai.chat().create(chat_request()).await.unwrap_err();
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        let found = client_error(&error);
        assert_eq!(found.kind(), ErrorKind::Network);
        assert!(found.is_timeout());

        // Read as a stream: the events before the deadline arrive.
        let mut stream = openai.chat().create_stream(chat_request()).await.unwrap();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.choices[0].delta.content.as_deref(), Some("a"));
        assert!(stream.next().await.unwrap().is_err());
    })
    .await
}

// On the real modes.

mod over_ehbp {
    use super::*;
    use crate::internal::transport::ehbp::tests::{self as ehbp, Reply, Seen, key, serve};

    /// An `async_openai` client that reaches its enclave through a local
    /// server, as through a proxy, in the EHBP mode.
    async fn client(server: &ehbp::Server, hpke: &str) -> OpenAI {
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
        let api_base = client.openai_url().clone();
        openai_client(config(), &api_base, Arc::new(client), TransportMode::Ehbp).unwrap()
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
            "/v1/audio/transcriptions" => Reply::ok(r#"{"text":"hello"}"#),
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
        let mut stream = soon(openai.chat().create_stream(chat_request()))
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
        assert_eq!(raw.as_ref(), br#"{"text":"hello"}"#);
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
        let api_base = client.openai_url().clone();
        let openai =
            openai_client(config(), &api_base, Arc::new(client), TransportMode::Ehbp).unwrap();

        let raw = soon(openai.audio().transcription().create_raw(transcription()))
            .await
            .expect("sent again");
        assert_eq!(raw.as_ref(), br#"{"text":"hello"}"#);
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
                    _ => r#"{"text":"hello"}"#.to_owned(),
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

    async fn client(server: &Server) -> OpenAI {
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
        let api_base = client.openai_url().clone();
        openai_client(config(), &api_base, Arc::new(client), TransportMode::Tls).unwrap()
    }

    #[tokio::test]
    async fn every_kind_of_call_reaches_the_pinned_server_through_the_client() {
        let server = server().await;
        let openai = client(&server).await;

        let response = soon(openai.chat().create(chat_request())).await.unwrap();
        assert_eq!(response.id, "c1");

        let mut stream = soon(openai.chat().create_stream(chat_request()))
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
}
