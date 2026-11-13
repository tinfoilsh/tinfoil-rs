//! The public surface of the crate, as a consumer sees it.
//!
//! Every public name is imported from the crate root and every signature is
//! used once, so that a change to a name, a parameter or a return type
//! fails to compile here. The async methods are used in functions that are
//! compiled and never run; the test bodies check the trait implementations
//! that the clients promise and the few values that need no network.

// The signatures are spelled out in full because they are what the test
// pins, and a helper outside a test function fails its test by panicking.
#![allow(clippy::expect_used, clippy::type_complexity)]

use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tinfoil::reqwest::header::{HeaderMap, HeaderValue};
use tinfoil::reqwest::{Method, Request, Response, Url};
use tinfoil::verifier::{BoxError, Verification, Verifier};
use tinfoil::{
    EnclaveHttpClient, EnclaveHttpClientBuilder, Error, ErrorKind, RequestBuilder,
    RouterHttpClient, RouterHttpClientBuilder, TransportMode, VERSION,
};

fn handle<T: Clone + Send + Sync + std::fmt::Debug + 'static>() {}
fn send<T: Send>(value: T) -> T {
    value
}
fn check(_: &Verification) -> Result<(), BoxError> {
    Ok(())
}

#[test]
fn the_version_and_the_enums_read_as_documented() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));

    assert_eq!(TransportMode::default(), TransportMode::Tls);
    let _: fn(&TransportMode) -> &'static str = TransportMode::as_str;
    assert_eq!(
        [
            TransportMode::Tls.to_string(),
            TransportMode::Ehbp.to_string()
        ],
        ["tls", "ehbp"]
    );

    let _: fn(&ErrorKind) -> &'static str = ErrorKind::as_str;
    assert_eq!(
        [
            ErrorKind::Configuration.to_string(),
            ErrorKind::Network.to_string(),
            ErrorKind::Attestation.to_string(),
        ],
        ["configuration", "network", "attestation"]
    );
}

#[test]
fn the_error_has_a_kind_a_timeout_flag_and_a_source() {
    let _: fn(&Error) -> ErrorKind = Error::kind;
    let _: fn(&Error) -> bool = Error::is_timeout;
    let _: for<'a> fn(&'a Error) -> Option<&'a Error> = Error::earlier_attempt;
    let _: for<'a> fn(&'a tinfoil::reqwest::Error) -> Option<&'a Error> = Error::from_reqwest;
    let _: for<'a> fn(&'a Error) -> Option<&'a (dyn StdError + 'static)> = StdError::source;
    fn shared<T: StdError + Clone + Send + Sync + 'static>() {}
    shared::<Error>();
}

#[test]
fn the_http_clients_are_handles() {
    handle::<EnclaveHttpClient>();
    handle::<RouterHttpClient>();
    handle::<EnclaveHttpClientBuilder>();
    handle::<RouterHttpClientBuilder>();
}

#[test]
fn the_accessors_have_their_signatures() {
    let _: for<'a> fn(&'a EnclaveHttpClient) -> &'a Url = EnclaveHttpClient::base_url;
    let _: for<'a> fn(&'a EnclaveHttpClient) -> &'a str = EnclaveHttpClient::enclave;
    let _: for<'a> fn(&'a EnclaveHttpClient) -> Option<&'a str> = EnclaveHttpClient::repo;
    let _: fn(&EnclaveHttpClient) -> TransportMode = EnclaveHttpClient::transport_mode;
    let _: fn(&EnclaveHttpClient) -> Arc<Verification> = EnclaveHttpClient::current;

    let _: for<'a> fn(&'a RouterHttpClient) -> &'a Url = RouterHttpClient::base_url;
    let _: for<'a> fn(&'a RouterHttpClient) -> &'a str = RouterHttpClient::enclave;
    let _: for<'a> fn(&'a RouterHttpClient) -> &'a str = RouterHttpClient::repo;
    let _: fn(&RouterHttpClient) -> TransportMode = RouterHttpClient::transport_mode;
    let _: fn(&RouterHttpClient) -> Arc<Verification> = RouterHttpClient::current;
    let _: fn() -> RouterHttpClientBuilder = RouterHttpClient::builder;
}

#[test]
fn a_builder_does_no_io_and_prints_no_secret() {
    let builder = EnclaveHttpClient::builder("enclave.example.com", Some("org/repo"))
        .transport_mode(TransportMode::Ehbp)
        .base_url("https://user:hunter2@proxy.example.com/")
        .verifier(Verifier::new())
        .verification_check(check)
        .user_cache_secret("cache-scope-value")
        .timeout(Duration::from_secs(30));
    let printed = format!("{builder:?}");
    assert!(!printed.contains("cache-scope-value"), "{printed}");
    assert!(!printed.contains("hunter2"), "{printed}");
}

/// The enclave client, as a caller writes it.
async fn enclave_client(verifier: Arc<Verifier>) -> Result<(), Box<dyn StdError>> {
    let client: EnclaveHttpClient = send(EnclaveHttpClient::connect(
        "enclave.example.com",
        Some("org/repo"),
    ))
    .await?;

    let builder: EnclaveHttpClientBuilder =
        EnclaveHttpClient::builder(String::from("enclave.example.com"), Some("org/repo@v1.2.3"))
            .transport_mode(TransportMode::Ehbp)
            .base_url("https://proxy.example.com/")
            .verifier(verifier)
            .verification_check(|verified: &Verification| {
                if verified.code_tag().is_empty() {
                    return Err("untagged release".into());
                }
                Ok(())
            })
            .user_cache_secret("opaque-random-value")
            .timeout(Duration::from_secs(30));
    let configured: EnclaveHttpClient = send(builder.connect()).await?;

    let unpinned: EnclaveHttpClient =
        send(EnclaveHttpClient::connect("enclave.example.com", None)).await?;
    let _: Option<&str> = unpinned.repo();

    let current: Arc<Verification> = configured.current();
    let valid: Arc<Verification> = send(configured.ensure_verified()).await?;
    let renewed: Arc<Verification> = send(configured.reverify()).await?;
    let _ = (current, valid, renewed);

    let url: Url = client.base_url().join("v1/x")?;
    let mut headers = HeaderMap::new();
    headers.insert("x-trace", HeaderValue::from_static("1"));
    let request: RequestBuilder = client
        .post(url.clone())
        .header("x-one", "1")
        .headers(headers)
        .bearer_auth("token")
        .query(&[("page", "2")])
        .json(&serde_json::json!({"k": "v"}))
        .timeout(Duration::from_secs(5));
    let copy: Option<RequestBuilder> = request.try_clone();
    let response: Response = send(request.send()).await?;
    let _ = (copy, response.status());

    let _: RequestBuilder = client.get(url.as_str());
    let _: RequestBuilder = client.put(url.clone()).body("text");
    let _: RequestBuilder = client.patch(url.clone()).body(vec![1u8, 2, 3]);
    let _: RequestBuilder = client.delete(url.clone());
    let _: RequestBuilder = client.head(url.clone());
    let built: Request = client.request(Method::OPTIONS, url).build()?;
    let _: Response = send(client.execute(built)).await?;
    Ok(())
}

/// The router client, as a caller writes it.
async fn router_client() -> Result<(), Error> {
    let client: RouterHttpClient = send(RouterHttpClient::connect()).await?;
    let configured: RouterHttpClient = send(
        RouterHttpClient::builder()
            .transport_mode(TransportMode::Ehbp)
            .base_url("https://proxy.example.com/")
            .verifier(Arc::new(Verifier::new()))
            .verification_check(check)
            .user_cache_secret("opaque-random-value")
            .timeout(Duration::from_secs(30))
            .connect(),
    )
    .await?;
    let _: Arc<Verification> = send(configured.ensure_verified()).await?;
    let _: Arc<Verification> = send(configured.reverify()).await?;
    let _: Response = client.get(client.base_url().clone()).send().await?;
    let request = Request::new(Method::GET, client.base_url().clone());
    let _: Response = send(client.execute(request)).await?;
    match client.reverify().await {
        Err(error) if error.is_timeout() => {}
        Err(error) => match error.kind() {
            ErrorKind::Configuration | ErrorKind::Network | ErrorKind::Attestation => {}
            _ => {}
        },
        Ok(_) => {}
    }
    Ok(())
}

/// The message of the error that `connect` returns for a builder. Every
/// host here ends in `.invalid`, which never resolves, so a refusal cannot
/// be a failed connection.
async fn enclave_refusal(builder: EnclaveHttpClientBuilder) -> String {
    let error = builder.connect().await.expect_err("no client");
    assert_eq!(error.kind(), ErrorKind::Configuration, "{error}");
    error.to_string()
}

async fn router_refusal(builder: RouterHttpClientBuilder) -> String {
    let error = builder.connect().await.expect_err("no client");
    assert_eq!(error.kind(), ErrorKind::Configuration, "{error}");
    error.to_string()
}

#[tokio::test]
async fn an_enclave_client_checks_its_options_before_any_io() {
    let builder = || EnclaveHttpClient::builder("enclave.invalid", Some("owner/name"));
    let ehbp = || builder().transport_mode(TransportMode::Ehbp);
    let cases: Vec<(EnclaveHttpClientBuilder, &str)> = vec![
        (
            EnclaveHttpClient::builder("", Some("owner/name")),
            "enclave host",
        ),
        (
            EnclaveHttpClient::builder("https://enclave.invalid", Some("owner/name")),
            "enclave host",
        ),
        (
            EnclaveHttpClient::builder("enclave.invalid/v1", Some("owner/name")),
            "enclave host",
        ),
        (ehbp().base_url(""), "invalid base URL"),
        (ehbp().base_url("proxy.invalid"), "invalid base URL"),
        (
            ehbp().base_url("http://proxy.invalid/"),
            "HTTP is allowed only",
        ),
        (
            ehbp().base_url("https://user:hunter2@proxy.invalid/"),
            "user name",
        ),
        (
            ehbp().base_url("https://proxy.invalid/?key=1"),
            "query string",
        ),
        (
            builder().user_cache_secret(""),
            "user cache secret is empty",
        ),
        (builder().timeout(Duration::ZERO), "timeout is zero"),
        (
            EnclaveHttpClient::builder("enclave.invalid", Some("")),
            "repository pin is empty",
        ),
        (
            EnclaveHttpClient::builder("enclave.invalid", Some("not a reference")),
            "",
        ),
        // A proxy needs sealed bodies: the default mode pins connections.
        (
            builder().base_url("https://proxy.invalid/"),
            "requires TransportMode::Ehbp",
        ),
        (
            builder()
                .transport_mode(TransportMode::Tls)
                .base_url("https://enclave.invalid:8443/"),
            "requires TransportMode::Ehbp",
        ),
    ];
    for (builder, reason) in cases {
        let message = enclave_refusal(builder).await;
        assert!(message.contains(reason), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }
}

#[tokio::test]
async fn an_enclave_client_reports_its_options_in_the_documented_order() {
    // Each builder is wrong in two ways; the earlier check answers.
    let message =
        enclave_refusal(EnclaveHttpClient::builder("", Some("")).base_url("ftp://proxy.invalid/"))
            .await;
    assert!(message.contains("enclave host"), "{message}");

    let message = enclave_refusal(
        EnclaveHttpClient::builder("enclave.invalid", Some(""))
            .base_url("ftp://proxy.invalid/")
            .timeout(Duration::ZERO),
    )
    .await;
    assert!(message.contains("invalid base URL"), "{message}");

    let message = enclave_refusal(
        EnclaveHttpClient::builder("enclave.invalid", Some("")).timeout(Duration::ZERO),
    )
    .await;
    assert!(message.contains("timeout is zero"), "{message}");

    let message = enclave_refusal(
        EnclaveHttpClient::builder("enclave.invalid", Some("")).base_url("https://proxy.invalid/"),
    )
    .await;
    assert!(message.contains("repository pin is empty"), "{message}");
}

/// A local server that accepts connections, counts them, and answers each
/// with `answer` (nothing, if it is empty) without ever speaking TLS. It
/// keeps every connection open.
async fn plain_server(answer: &'static [u8]) -> (String, Arc<AtomicUsize>) {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a local port");
    let host = format!(
        "127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        let mut open = Vec::new();
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let _ = socket.write_all(answer).await;
            open.push(socket);
        }
    });
    (host, accepted)
}

/// Bounds a wait on the local server, so that a hang fails the test.
const PATIENCE: Duration = Duration::from_secs(20);

#[tokio::test]
async fn an_enclave_that_serves_no_attestation_document_is_a_network_error_after_one_retry() {
    // The retry comes one second after the first failure, on real time:
    // the public constructor has no other clock.
    let (host, accepted) = plain_server(b"HTTP/1.1 200 OK\r\n\r\nnot a TLS server").await;
    for mode in [TransportMode::Tls, TransportMode::Ehbp] {
        let before = accepted.load(Ordering::SeqCst);
        let connect = EnclaveHttpClient::builder(host.as_str(), Some("owner/name"))
            .transport_mode(mode)
            .connect();
        let error = tokio::time::timeout(PATIENCE, connect)
            .await
            .expect("connect neither succeeded nor failed in time")
            .expect_err("no client");
        assert_eq!(error.kind(), ErrorKind::Network, "{error}");
        assert!(!error.is_timeout(), "{error}");
        assert!(error.source().is_some());
        let first = error.earlier_attempt().expect("the first attempt");
        assert_eq!(first.kind(), ErrorKind::Network);
        assert_eq!(accepted.load(Ordering::SeqCst) - before, 2, "{mode}");
    }
}

#[tokio::test]
async fn connecting_to_an_enclave_that_never_answers_ends_at_the_timeout() {
    let (host, accepted) = plain_server(b"").await;
    let started = std::time::Instant::now();
    let connect = EnclaveHttpClient::builder(host.as_str(), None)
        .timeout(Duration::from_millis(300))
        .connect();
    let error = tokio::time::timeout(PATIENCE, connect)
        .await
        .expect("connect neither succeeded nor failed in time")
        .expect_err("no client");
    assert_eq!(error.kind(), ErrorKind::Network, "{error}");
    assert!(error.is_timeout(), "{error}");
    // Well before the bound on fetching a document, and before any retry.
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_router_client_checks_its_options_before_any_io() {
    let ehbp = || RouterHttpClient::builder().transport_mode(TransportMode::Ehbp);
    let cases: Vec<(RouterHttpClientBuilder, &str)> = vec![
        (ehbp().base_url(""), "invalid base URL"),
        (
            ehbp().base_url("http://proxy.invalid/"),
            "HTTP is allowed only",
        ),
        (
            ehbp().base_url("https://user:hunter2@proxy.invalid/"),
            "user name",
        ),
        // The router is not known before discovery, so any base URL is a
        // proxy, and the default mode cannot go through one.
        (
            RouterHttpClient::builder().base_url("https://proxy.invalid/"),
            "requires TransportMode::Ehbp",
        ),
        (
            RouterHttpClient::builder().user_cache_secret(""),
            "user cache secret is empty",
        ),
        (
            RouterHttpClient::builder().timeout(Duration::ZERO),
            "timeout is zero",
        ),
    ];
    for (builder, reason) in cases {
        let message = router_refusal(builder).await;
        assert!(message.contains(reason), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
    }
}

#[tokio::test]
async fn an_empty_repository_pin_is_refused_before_any_io() {
    // `.invalid` never resolves, so a connection attempt could not pass
    // for the refusal.
    let error = EnclaveHttpClient::connect("enclave.invalid", Some(""))
        .await
        .expect_err("an empty pin is refused");
    assert_eq!(error.kind(), ErrorKind::Configuration);
    assert!(
        error.to_string().contains("repository pin is empty"),
        "{error}"
    );

    let error = EnclaveHttpClient::builder("enclave.invalid", Some(""))
        .connect()
        .await
        .expect_err("an empty pin is refused");
    assert!(
        error.to_string().contains("repository pin is empty"),
        "{error}"
    );
}

#[test]
fn the_callers_of_the_async_surface_compile() {
    // The functions above are compiled, which is the check; they are not
    // run, because they would open connections.
    let _ = enclave_client;
    let _ = router_client;
}

#[cfg(feature = "openai")]
mod openai {
    use super::*;

    use futures_core::Stream;
    use serde_json::{Value, json};
    use tinfoil::async_openai::config::OpenAIConfig;
    use tinfoil::async_openai::error::OpenAIError;
    use tinfoil::audio::{CreateTranscriptionRequest, CreateTranscriptionResponseJson};
    use tinfoil::chat::{ImageUrl, InputAudio, InputAudioFormat};
    use tinfoil::embeddings::CreateEmbeddingRequestArgs;
    use tinfoil::multimodal::{ImageUrlExt, InputAudioExt};
    use tinfoil::sse::{EventStream, parse_event_stream};
    use tinfoil::{
        Client, EnclaveOpenAIClient, EnclaveOpenAIClientBuilder, RelaxedChat,
        RelaxedChatRequestBuilder, RelaxedResponse, RelaxedStream, RelaxedStreamChunk,
        RelaxedToolCall, RouterOpenAIClient, RouterOpenAIClientBuilder,
    };

    type OpenAI = tinfoil::async_openai::Client<OpenAIConfig>;

    fn derefs<T: std::ops::Deref<Target = OpenAI>>() {}

    #[test]
    fn the_openai_clients_are_handles_that_deref_to_async_openai() {
        handle::<Client>();
        handle::<EnclaveOpenAIClient>();
        handle::<RouterOpenAIClient>();
        handle::<EnclaveOpenAIClientBuilder>();
        handle::<RouterOpenAIClientBuilder>();
        derefs::<Client>();
        derefs::<EnclaveOpenAIClient>();
        derefs::<RouterOpenAIClient>();

        let _: for<'a> fn(&'a Client) -> &'a RouterHttpClient = Client::http_client;
        let _: for<'a> fn(&'a Client) -> &'a Url = Client::base_url;
        let _: for<'a> fn(&'a EnclaveOpenAIClient) -> &'a EnclaveHttpClient =
            EnclaveOpenAIClient::http_client;
        let _: for<'a> fn(&'a RouterOpenAIClient) -> &'a RouterHttpClient =
            RouterOpenAIClient::http_client;
        let _: for<'a> fn(&'a Client) -> RelaxedChat<'a> = Client::chat_relaxed;
        let _: for<'a> fn(&'a EnclaveOpenAIClient) -> RelaxedChat<'a> =
            EnclaveOpenAIClient::chat_relaxed;
        let _: for<'a> fn(&'a RouterOpenAIClient) -> RelaxedChat<'a> =
            RouterOpenAIClient::chat_relaxed;
        let _: for<'a> fn(&'a OpenAIError) -> Option<&'a Error> = Error::from_openai;
    }

    #[tokio::test]
    async fn an_empty_repository_pin_is_refused_by_the_openai_client() {
        let error = EnclaveOpenAIClient::connect("enclave.invalid", Some(""), OpenAIConfig::new())
            .await
            .expect_err("an empty pin is refused");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert!(
            error.to_string().contains("repository pin is empty"),
            "{error}"
        );
    }

    #[test]
    fn an_openai_builder_prints_no_api_key() {
        let config = OpenAIConfig::new().with_api_key("sk-secret-key");
        let builder = EnclaveOpenAIClient::builder("enclave.example.com", Some("org/repo"), config)
            .transport_mode(TransportMode::Tls)
            .base_url("https://enclave.example.com/api/")
            .verifier(Verifier::new())
            .verification_check(check)
            .user_cache_secret("cache-scope-value")
            .timeout(Duration::from_secs(30));
        let printed = format!("{builder:?}");
        assert!(!printed.contains("sk-secret-key"), "{printed}");
        assert!(!printed.contains("cache-scope-value"), "{printed}");
    }

    #[test]
    fn the_relaxed_types_and_the_multimodal_helpers_need_no_client() {
        let body: Value = RelaxedChatRequestBuilder::new()
            .model("m")
            .messages([json!({"role": "user", "content": "hi"})])
            .push_message(json!({"role": "user", "content": "more"}))
            .web_search()
            .web_search_with_options(json!({}))
            .pii_check()
            .pii_check_with_options(json!({}))
            .structured_outputs_choice(["yes", "no"])
            .structured_outputs_regex("a+")
            .response_format_json_schema("answer", json!({"type": "object"}))
            .set("seed", 7)
            .build();
        assert_eq!(body.get("model"), Some(&json!("m")));
        let _: Value = RelaxedChatRequestBuilder::default().into();

        let response = RelaxedResponse::from_value(json!({"choices": []}));
        let _: Option<&str> = response.content();
        let _: Option<&str> = response.finish_reason();
        let _: &[Value] = response.tool_calls();
        let _: &[Value] = response.annotations();
        let _: Option<&str> = response.model();
        let _: Option<&str> = response.id();
        let _: usize = response.choices_len();
        let calls: Vec<RelaxedToolCall> = response.typed_tool_calls();
        for call in &calls {
            let _: (&Option<String>, &Option<String>, &String) =
                (&call.id, &call.function_name, &call.arguments_raw);
            let _: Result<Value, serde_json::Error> = call.arguments();
        }
        let _: &Value = response.raw();
        let _: Value = response.into_raw();

        let chunk = RelaxedStreamChunk::from_value(json!({"type": "web_search_call"}));
        let _: Option<&str> = chunk.event_type();
        let _: bool = chunk.is_vendor_event();
        let _: Option<&str> = chunk.delta_content();
        let _: &[Value] = chunk.tool_call_deltas();
        let _: &[Value] = chunk.annotation_deltas();
        let _: Option<&str> = chunk.finish_reason();
        let _: &Value = chunk.raw();
        let _: Value = chunk.into_raw();

        let image: ImageUrl = ImageUrl::from_bytes(b"abc", "image/png");
        assert!(image.url.starts_with("data:image/png;base64,"));
        let _: ImageUrl = ImageUrl::from_base64("YWJj", "image/png");
        let _: std::io::Result<ImageUrl> = ImageUrl::from_path("missing.png");
        let audio: InputAudio = InputAudio::from_bytes(b"abc", InputAudioFormat::Mp3);
        assert_eq!(audio.data, "YWJj");
        let _: std::io::Result<InputAudio> = InputAudio::from_path("missing.mp3");
    }

    /// The OpenAI clients, as a caller writes them.
    async fn openai_clients(
        key: String,
        transcription: CreateTranscriptionRequest,
    ) -> Result<(), Box<dyn StdError>> {
        // The drop-in.
        let client: Client = send(Client::connect(OpenAIConfig::new().with_api_key(&key))).await?;
        let router: &RouterHttpClient = client.http_client();
        let _: Arc<Verification> = router.ensure_verified().await?;
        let _: Response = router.get(client.base_url().join("models")?).send().await?;

        // `async_openai`'s own API, through `Deref`.
        let request = CreateEmbeddingRequestArgs::default()
            .model("nomic-embed-text")
            .input("hello")
            .build()?;
        match client.embeddings().create(request).await {
            Ok(_) => {}
            Err(error) => match Error::from_openai(&error) {
                Some(cause) => assert_ne!(cause.kind(), ErrorKind::Configuration),
                None => return Err(error.into()),
            },
        }

        // The shortcuts.
        let text: CreateTranscriptionResponseJson = send(client.transcribe(transcription)).await?;
        let vectors: Vec<Vec<f32>> =
            send(client.embed_batch("nomic-embed-text", ["a", "b"])).await?;
        let _ = (text, vectors);

        // The relaxed chat.
        let relaxed: RelaxedChat<'_> = client.chat_relaxed();
        let body: RelaxedChatRequestBuilder = relaxed.request().model("m");
        let response: RelaxedResponse = relaxed.create(body.clone()).await?;
        let stream: RelaxedStream = relaxed.create_stream(body.build()).await?;
        fn chunks(_: &impl Stream<Item = Result<RelaxedStreamChunk, OpenAIError>>) {}
        chunks(&stream);
        let _ = response;

        // A raw event stream of the caller's own.
        let raw: Response = router.get(client.base_url().clone()).send().await?;
        let events: EventStream = parse_event_stream(raw.bytes_stream());
        fn values(_: &impl Stream<Item = Result<Value, OpenAIError>>) {}
        values(&events);

        // An explicit enclave.
        let config = OpenAIConfig::new().with_api_key(&key);
        let enclave: EnclaveOpenAIClient = send(EnclaveOpenAIClient::connect(
            "enclave.example.com",
            Some("org/repo"),
            config.clone(),
        ))
        .await?;
        let _: &EnclaveHttpClient = enclave.http_client();
        let builder: EnclaveOpenAIClientBuilder =
            EnclaveOpenAIClient::builder("enclave.example.com", Some("org/repo"), config.clone())
                .transport_mode(TransportMode::Ehbp)
                .base_url("https://proxy.example.com/v1/");
        let _: EnclaveOpenAIClient = send(builder.connect()).await?;

        // The router, configured.
        let _: RouterOpenAIClient = send(RouterOpenAIClient::connect(config.clone())).await?;
        let builder: RouterOpenAIClientBuilder = RouterOpenAIClient::builder(config)
            .transport_mode(TransportMode::Tls)
            .verifier(Verifier::new())
            .verification_check(check)
            .user_cache_secret("opaque-random-value")
            .timeout(Duration::from_secs(60));
        let configured: RouterOpenAIClient = send(builder.connect()).await?;
        let _: &RouterHttpClient = configured.http_client();
        let _ = configured.chat_relaxed();
        Ok(())
    }

    /// Each `openai-*` feature adds its API family to the OpenAI clients.
    fn api_families(client: &Client) {
        // In the `openai` feature itself.
        let _ = client.chat();
        let _ = client.embeddings();
        let _ = client.audio();
        let _ = client.responses();
        #[cfg(feature = "openai-administration")]
        let _ = client.admin();
        #[cfg(feature = "openai-batches")]
        let _ = client.batches();
        #[cfg(feature = "openai-chatkit")]
        let _ = client.chatkit();
        #[cfg(feature = "openai-completions")]
        let _ = client.completions();
        #[cfg(feature = "openai-containers")]
        let _ = client.containers();
        #[cfg(feature = "openai-evals")]
        let _ = client.evals();
        #[cfg(feature = "openai-files")]
        let _ = client.files();
        #[cfg(feature = "openai-fine-tuning")]
        let _ = client.fine_tuning();
        #[cfg(feature = "openai-images")]
        let _ = client.images();
        #[cfg(feature = "openai-models")]
        let _ = client.models();
        #[cfg(feature = "openai-moderations")]
        let _ = client.moderations();
        #[cfg(feature = "openai-skills")]
        let _ = client.skills();
        #[cfg(feature = "openai-uploads")]
        let _ = client.uploads();
        #[cfg(feature = "openai-vector-stores")]
        let _ = client.vector_stores();
        #[cfg(feature = "openai-safety")]
        let _ = client.safety();
        #[cfg(feature = "openai-content-provenance-checks")]
        let _ = client.content_provenance_checks();
    }

    #[test]
    fn the_callers_of_the_openai_surface_compile() {
        let _ = openai_clients;
        let _ = api_families;
    }
}
