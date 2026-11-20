//! The OpenAI client: an `async_openai` client whose requests go through an
//! attested HTTP client.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use async_openai::config::OpenAIConfig;
use async_openai::error::OpenAIError;
use async_openai::types::audio::{CreateTranscriptionRequest, CreateTranscriptionResponseJson};
use reqwest::Url;

use crate::attested_client::AttestedHttpClient;
use crate::error::Error;
use crate::router_client::RouterHttpClient;

pub(crate) mod api_path;
pub(crate) mod relaxed;
pub(crate) mod retry;
pub(crate) mod service;

use relaxed::RelaxedChat;

/// The `async_openai` client type that [`OpenAIClient`] dereferences to.
type OpenAI = async_openai::Client<OpenAIConfig>;

/// The methods that [`OpenAIClient`] has in addition to `async_openai`'s. The type has the fields `openai` (the `async_openai`
/// client), `sender` (the service under it), `http` (the attested HTTP
/// client) and `api_base`.
macro_rules! openai_client_methods {
    ($client:ident) => {
        impl Deref for $client {
            type Target = OpenAI;

            /// The `async_openai` client, so that `client.chat()`,
            /// `client.embeddings()` and the rest of its API are called on
            /// this client directly.
            fn deref(&self) -> &OpenAI {
                &self.openai
            }
        }

        impl $client {
            /// A permissive chat-completion handle, for raw JSON requests
            /// and responses. See [`RelaxedChat`].
            pub fn chat_relaxed(&self) -> RelaxedChat<'_> {
                let http: Arc<dyn crate::request::Execute> = self.http.attested().clone();
                RelaxedChat {
                    sender: self.sender.clone(),
                    http,
                    api_base: &self.api_base,
                    config: self.openai.config(),
                }
            }

            /// Transcribes audio: a shortcut for
            /// `client.audio().transcription().create(request)`.
            pub async fn transcribe(
                &self,
                request: CreateTranscriptionRequest,
            ) -> Result<CreateTranscriptionResponseJson, OpenAIError> {
                self.openai.audio().transcription().create(request).await
            }

            /// Embeds a batch of strings with `model` and returns one
            /// vector for each input, in the order of the inputs.
            ///
            /// A response that does not hold exactly one embedding for
            /// each input is an `OpenAIError::InvalidArgument`: its
            /// vectors could not be matched to the inputs.
            pub async fn embed_batch<I, S>(
                &self,
                model: impl Into<String>,
                inputs: I,
            ) -> Result<Vec<Vec<f32>>, OpenAIError>
            where
                I: IntoIterator<Item = S>,
                S: Into<String>,
            {
                let inputs = inputs.into_iter().map(Into::into).collect();
                $crate::openai::embed_batch(&self.openai, model.into(), inputs).await
            }
        }
    };
}

/// Embeds `inputs` with `model` and returns the vectors in the order of
/// the inputs, whatever the order of the response. The response must hold
/// one embedding for each input, with the indexes `0..n`.
pub(crate) async fn embed_batch(
    openai: &OpenAI,
    model: String,
    inputs: Vec<String>,
) -> Result<Vec<Vec<f32>>, OpenAIError> {
    use async_openai::types::embeddings::{CreateEmbeddingRequestArgs, EmbeddingInput};
    let expected = inputs.len();
    let request = CreateEmbeddingRequestArgs::default()
        .model(model)
        .input(EmbeddingInput::StringArray(inputs))
        .build()?;
    let mut response = openai.embeddings().create(request).await?;
    response.data.sort_by_key(|embedding| embedding.index);
    let complete = response.data.len() == expected
        && response
            .data
            .iter()
            .enumerate()
            .all(|(position, embedding)| usize::try_from(embedding.index) == Ok(position));
    if !complete {
        return Err(OpenAIError::InvalidArgument(format!(
            "the response does not hold one embedding for each of the {expected} inputs"
        )));
    }
    Ok(response
        .data
        .into_iter()
        .map(|embedding| embedding.embedding)
        .collect())
}

/// An `async_openai` client whose requests go through one of this crate's
/// attested HTTP clients.
///
/// [`new`](Self::new) builds one over an [`EnclaveHttpClient`](crate::EnclaveHttpClient) or a
/// [`RouterHttpClient`] that is already verified, and does no network I/O;
/// the HTTP client verifies again by itself when its verification expires
/// or its key changes. [`connect`](Self::connect) is the one-line drop-in
/// for Tinfoil's recommended route: it discovers and verifies a router and
/// builds the client over it. The whole `async_openai` API is available on
/// the client through `Deref`:
///
/// ```no_run
/// use tinfoil::async_openai::config::OpenAIConfig;
/// use tinfoil::embeddings::CreateEmbeddingRequestArgs;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = tinfoil::Client::connect(OpenAIConfig::new().with_api_key("...")).await?;
/// let request = CreateEmbeddingRequestArgs::default()
///     .model("nomic-embed-text")
///     .input("hello")
///     .build()?;
/// let embeddings = client.embeddings().create(request).await?;
/// # let _ = embeddings;
/// # Ok(())
/// # }
/// ```
///
/// To choose the enclave, the transport or the verification policy, build
/// the HTTP client with its builder and pass it to [`new`](Self::new):
///
/// ```no_run
/// use tinfoil::async_openai::config::OpenAIConfig;
/// use tinfoil::{EnclaveHttpClient, OpenAIClient, OpenAIOptions, Transport, Trust};
///
/// # async fn run() -> Result<(), tinfoil::Error> {
/// let http = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("owner/name"))
///     .transport(Transport::Ehbp { proxy_url: None })
///     .connect()
///     .await?;
/// let config = OpenAIConfig::new().with_api_key("...");
/// let client = OpenAIClient::new(http, OpenAIOptions::default(), config)?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
///
/// A failed call returns `async_openai`'s `OpenAIError`. When the cause is
/// this crate's (the router no longer passes verification, for example),
/// [`Error::from_openai`] returns it. The exception is a stream of a typed
/// call that fails after it started: it ends with an
/// `OpenAIError::StreamError`, which holds a message and no cause. See
/// [`Error::from_openai`].
///
/// A call is sent again, at most twice, when the response has status
/// `429` or `5xx`; a `429` whose error is `insufficient_quota` is not. The
/// status decides: a `429` whose body is not the API's error object, is
/// larger than 1 MiB or cannot be read is tried again as well, and is the
/// call's error if the last attempt ends that way. A
/// failure of this crate's client (a refused verification, a refused
/// request, a failed connection, a deadline) is reported once and not
/// tried again. Below that, the client itself sends a request once more
/// after the enclave rejected its keys, an upload included.
///
/// The wait before the first retry is half a second and before the second
/// a second, each shortened at random by up to a quarter. A response can
/// name its own wait, in `Retry-After-Ms` (milliseconds) or `Retry-After`
/// (seconds, or a date in the form `Sun, 06 Nov 1994 08:49:37 GMT`; a
/// date in another form is ignored), and is obeyed up to two minutes, or up to
/// the `timeout` option if that is shorter. A response that asks for a
/// longer wait is not tried again: the call returns it at once, as the
/// error that it is. A value that cannot be read is ignored. In
/// [`Transport::Ehbp`](crate::Transport::Ehbp) these headers are not authenticated, which is
/// why they are bounded.
///
/// The `timeout` option bounds each request that a call sends and each
/// wait between two attempts; it is not one deadline for the whole call,
/// which has up to three attempts and two waits and so can take several
/// times the `timeout`.
///
/// `async_openai` reads response bodies into memory, so the client bounds
/// them. A body beyond its limit is not cut short: the read fails with a
/// network error of this crate, which [`Error::from_openai`] finds (except
/// in a typed stream).
///
/// | response | read into memory up to |
/// |---|---|
/// | an error response (any status outside `2xx`) of a typed or relaxed call | 1 MiB |
/// | a successful response of a typed call, streamed or not, and of `chat_relaxed().create` | 64 MiB |
/// | a stream of `chat_relaxed().create_stream` | 16 MiB per line and per event; no limit on the whole stream |
///
/// Within the 64 MiB of a typed stream, `async_openai` holds each event
/// until it ends and reads ahead of the caller, without a limit of its
/// own. To download more than 64 MiB, a file's content for example, send
/// the request through `http_client()` and read the body as a stream.
///
/// Every call of the `async_openai` API goes through the attested client,
/// streaming and multipart calls included. The API base of the
/// configuration is replaced with the attested route, so a configuration
/// that names another host, or `OPENAI_BASE_URL`, has no effect. The one
/// helper of `async_openai` that makes a request of its own is
/// `ImagesResponse::save` (feature `openai-images`), which downloads the
/// URLs of a response with a plain HTTP client: such a download is not
/// attested.
///
/// A clone of the dereferenced `async_openai` client that is given another
/// HTTP client, service or configuration no longer goes through the
/// attested client and has none of its protections.
#[derive(Clone)]
pub struct OpenAIClient {
    openai: OpenAI,
    sender: service::Sender,
    http: AttestedHttpClient,
    api_base: Url,
}

/// The drop-in name of [`OpenAIClient`]: `tinfoil::Client::connect(config)`
/// is [`OpenAIClient::connect`].
pub type Client = OpenAIClient;

/// The options of an [`OpenAIClient`]. The default keeps every default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenAIOptions {
    /// The path of the OpenAI API, joined under the HTTP client's
    /// [`base_url`](AttestedHttpClient::base_url): the proxy URL of
    /// [`Transport::Ehbp`](crate::Transport::Ehbp), or the enclave's
    /// origin. `None` selects `/v1/`.
    ///
    /// It must be an RFC 3986 absolute path: it starts with `/`, but not
    /// with `//`, and holds only path characters (letters, digits,
    /// `-._~!$&'()*+,;=:@`), `/` between segments and well-formed `%XX`
    /// escapes. A segment that is `.` or `..` is refused, percent-encoded
    /// or not, and so is a segment that holds a slash or a backslash once
    /// it is percent-decoded (`%2F` or `%5C`); the `/` between segments is
    /// what separates them. A query and a fragment are refused too. Any
    /// other escape is accepted, also
    /// one of a byte that is not UTF-8. Each mistake, an empty string among
    /// them, is a configuration error.
    pub api_path: Option<String>,
}

impl OpenAIClient {
    /// An OpenAI client that sends through `http`, an [`EnclaveHttpClient`](crate::EnclaveHttpClient)
    /// or a [`RouterHttpClient`]. It does no network I/O: the HTTP client
    /// was verified when it was created, and verifies again by itself.
    ///
    /// `config` is the caller's `async_openai` configuration: the API key,
    /// organization, project and extra headers. It is applied first; then
    /// the API base and the HTTP client are set, so that `config` cannot
    /// replace them. An API base in `config`, and `OPENAI_BASE_URL` in the
    /// environment, have no effect: set
    /// [`api_path`](OpenAIOptions::api_path) to change the API's path. The
    /// API key travels only in `config`: this crate reads no API key from
    /// the environment. (`OpenAIConfig::new()` and `OpenAIConfig::default()`
    /// themselves read `OPENAI_API_KEY`, `OPENAI_ORG_ID` and
    /// `OPENAI_PROJECT_ID`; `with_api_key` and the other setters replace
    /// what they read.)
    ///
    /// The API base is the HTTP client's
    /// [`base_url`](AttestedHttpClient::base_url) without its final `/`,
    /// followed by the API path, ending in `/`:
    /// `https://<enclave>/v1/` by default, or `https://proxy.example/relay/v1/`
    /// under the proxy URL `https://proxy.example/relay`, with or without a
    /// final `/`.
    ///
    /// # Errors
    ///
    /// A configuration error for an API path that breaks the rules of
    /// [`OpenAIOptions::api_path`].
    pub fn new(
        http: impl Into<AttestedHttpClient>,
        options: OpenAIOptions,
        config: OpenAIConfig,
    ) -> Result<Self, Error> {
        let http = http.into();
        let attested = http.attested();
        let api_base = api_path::join(attested.base_url(), options.api_path.as_deref())?;
        let executor: Arc<dyn crate::request::Execute> = attested.clone();
        let waits = retry::Waits {
            timeout: attested.timeout(),
            clock: crate::internal::system_clock(),
        };
        let (openai, sender) = service::openai_client(
            config,
            &api_base,
            executor,
            attested.transport_mode(),
            waits,
        )?;
        Ok(Self {
            openai,
            sender,
            http,
            api_base,
        })
    }

    /// Discovers and verifies Tinfoil's router and returns an OpenAI
    /// client for it: the one-line drop-in. It is
    /// [`RouterHttpClient::connect`] followed by [`new`](Self::new) with
    /// the default options.
    ///
    /// The errors and the cancel safety are those of
    /// [`RouterHttpClientBuilder::connect`](crate::RouterHttpClientBuilder::connect)
    /// with no option set.
    pub async fn connect(config: OpenAIConfig) -> Result<Self, Error> {
        let router = RouterHttpClient::connect().await?;
        Self::new(router, OpenAIOptions::default(), config)
    }

    /// The attested HTTP client that the OpenAI client sends through: its
    /// accessors, `ensure_verified`, `reverify` and raw requests. Match on
    /// it for the methods of the concrete client.
    pub fn http_client(&self) -> &AttestedHttpClient {
        &self.http
    }

    /// The URL of the OpenAI API that the client sends to, ending in `/`.
    /// Build the URLs of raw requests for
    /// [`http_client`](Self::http_client) from it.
    pub fn base_url(&self) -> &Url {
        &self.api_base
    }
}

openai_client_methods!(OpenAIClient);

impl fmt::Debug for OpenAIClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The configuration holds the API key and may hold credentials in
        // its headers: none of it is printed.
        f.debug_struct("OpenAIClient")
            .field("http", &self.http)
            .field("base_url", &self.api_base.as_str())
            .finish_non_exhaustive()
    }
}
