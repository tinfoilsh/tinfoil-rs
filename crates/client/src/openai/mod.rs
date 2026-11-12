//! The OpenAI clients: `async_openai` clients whose requests go through an
//! attested HTTP client.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use async_openai::config::OpenAIConfig;
use async_openai::error::OpenAIError;
use async_openai::types::audio::{CreateTranscriptionRequest, CreateTranscriptionResponseJson};
use reqwest::Url;

use crate::enclave_client::{EnclaveHttpClient, EnclaveHttpClientBuilder};
use crate::error::Error;
use crate::options::TransportMode;
use crate::router_client::{RouterHttpClient, RouterHttpClientBuilder};
use crate::verifier::{BoxError, Verification, Verifier};

#[cfg(feature = "unstable-gateway")]
mod gateway;
pub(crate) mod relaxed;
pub(crate) mod service;

#[cfg(feature = "unstable-gateway")]
pub use gateway::{GatewayOpenAIClient, GatewayOpenAIClientBuilder};

use relaxed::RelaxedChat;

/// The `async_openai` client type that every OpenAI client of this crate
/// dereferences to.
type OpenAI = async_openai::Client<OpenAIConfig>;

/// The methods that every OpenAI client of this crate has in addition to
/// `async_openai`'s. The type has the fields `openai` (the `async_openai`
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
                let http: Arc<dyn crate::request::Execute> = self.http.inner.clone();
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

#[cfg(feature = "unstable-gateway")]
pub(crate) use openai_client_methods;

/// An OpenAI client for Tinfoil's recommended route: the drop-in.
///
/// It is an `async_openai::Client` whose requests go through a
/// [`RouterHttpClient`]: [`connect`](Self::connect) discovers and verifies
/// Tinfoil's router before it returns, and the client verifies the router
/// again by itself when the verification expires or its key changes. The
/// whole `async_openai` API is available on it through `Deref`:
///
/// ```no_run
/// use tinfoil_next::async_openai::config::OpenAIConfig;
/// use tinfoil_next::embeddings::CreateEmbeddingRequestArgs;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = tinfoil_next::Client::connect(OpenAIConfig::new().with_api_key("...")).await?;
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
/// To choose the enclave, the transport mode or the verification policy,
/// use [`RouterOpenAIClient`] or [`EnclaveOpenAIClient`].
///
/// A failed call returns `async_openai`'s `OpenAIError`. When the cause is
/// this crate's (the router no longer passes verification, for example),
/// [`Error::from_openai`] returns it.
///
/// `async_openai` sends a call again, at most twice and after a backoff,
/// when the response has status `429` or `5xx`. A failure of this crate's
/// client (a refused verification, a refused request, a failed connection,
/// a deadline) is reported once and not tried again. Below that, the
/// client itself sends a request once more after the enclave rejected its
/// keys, an upload included.
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
pub struct Client {
    openai: OpenAI,
    sender: service::Sender,
    http: RouterHttpClient,
    api_base: Url,
}

impl Client {
    /// Discovers and verifies Tinfoil's router and returns an OpenAI
    /// client for it.
    ///
    /// `config` is the caller's `async_openai` configuration: the API key,
    /// organization, project and extra headers. It is applied first; then
    /// the API base and the HTTP client are set, so that `config` cannot
    /// replace them. The API key travels only in `config`: this crate
    /// reads no API key from the environment. (`OpenAIConfig::new()` and
    /// `OpenAIConfig::default()` themselves read `OPENAI_API_KEY`,
    /// `OPENAI_ORG_ID` and `OPENAI_PROJECT_ID`; `with_api_key` and the
    /// other setters replace what they read.)
    ///
    /// The errors and the cancel safety are those of
    /// [`RouterHttpClientBuilder::connect`] with no option set.
    pub async fn connect(config: OpenAIConfig) -> Result<Self, Error> {
        let RouterOpenAIClient {
            openai,
            sender,
            http,
            api_base,
        } = RouterOpenAIClient::connect(config).await?;
        Ok(Self {
            openai,
            sender,
            http,
            api_base,
        })
    }

    /// The attested HTTP client that the OpenAI client sends through, for
    /// raw requests to the same router.
    pub fn http_client(&self) -> &RouterHttpClient {
        &self.http
    }

    /// The URL of the OpenAI API on the route that the client chose:
    /// `https://<router>/v1/`. Build the URLs of raw requests for
    /// [`http_client`](Self::http_client) from it.
    pub fn base_url(&self) -> &Url {
        &self.api_base
    }
}

openai_client_methods!(Client);

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// An OpenAI client whose requests go through an [`EnclaveHttpClient`], to
/// its `base_url` option or, when that is unset, to the enclave's `/v1/`
/// API.
///
/// See [`Client`] for how errors, retries and `Deref` behave.
#[derive(Clone)]
pub struct EnclaveOpenAIClient {
    openai: OpenAI,
    sender: service::Sender,
    http: EnclaveHttpClient,
    api_base: Url,
}

impl EnclaveOpenAIClient {
    /// Verifies the enclave at `host` against `repo`, as
    /// [`EnclaveHttpClient::connect`] does (`None` sets no repository pin),
    /// and returns an OpenAI client over it. `config` is applied first; then the API base and the HTTP
    /// client are set, so that `config` cannot replace them.
    pub async fn connect(
        host: impl Into<String>,
        repo: Option<&str>,
        config: OpenAIConfig,
    ) -> Result<Self, Error> {
        Self::builder(host, repo, config).connect().await
    }

    /// Starts an OpenAI client for the enclave at `host`, to be configured
    /// before it connects. The builder has the options of
    /// [`EnclaveHttpClientBuilder`].
    pub fn builder(
        host: impl Into<String>,
        repo: Option<&str>,
        config: OpenAIConfig,
    ) -> EnclaveOpenAIClientBuilder {
        EnclaveOpenAIClientBuilder {
            http: EnclaveHttpClient::builder(host, repo),
            config,
        }
    }

    /// The enclave client that the OpenAI client sends through: its
    /// accessors, `ensure_verified`, `reverify` and raw requests.
    pub fn http_client(&self) -> &EnclaveHttpClient {
        &self.http
    }
}

openai_client_methods!(EnclaveOpenAIClient);

impl fmt::Debug for EnclaveOpenAIClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnclaveOpenAIClient")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// An OpenAI client whose requests go through a [`RouterHttpClient`], to
/// its `base_url` option or, when that is unset, to the router's `/v1/`
/// API. It is [`Client`] with the router client's options.
#[derive(Clone)]
pub struct RouterOpenAIClient {
    openai: OpenAI,
    sender: service::Sender,
    http: RouterHttpClient,
    api_base: Url,
}

impl RouterOpenAIClient {
    /// Discovers and verifies a router, as [`RouterHttpClient::connect`]
    /// does, and returns an OpenAI client over it. `config` is applied
    /// first; then the API base and the HTTP client are set, so that
    /// `config` cannot replace them.
    pub async fn connect(config: OpenAIConfig) -> Result<Self, Error> {
        Self::builder(config).connect().await
    }

    /// Starts a router OpenAI client to be configured before it connects.
    /// The builder has the options of [`RouterHttpClientBuilder`].
    pub fn builder(config: OpenAIConfig) -> RouterOpenAIClientBuilder {
        RouterOpenAIClientBuilder {
            http: RouterHttpClient::builder(),
            config,
        }
    }

    /// The router client that the OpenAI client sends through.
    pub fn http_client(&self) -> &RouterHttpClient {
        &self.http
    }
}

openai_client_methods!(RouterOpenAIClient);

impl fmt::Debug for RouterOpenAIClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterOpenAIClient")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// The setters that an OpenAI builder passes on to the builder of its HTTP
/// client, in the field `http`.
macro_rules! forward_route_setters {
    ($builder:ident, $http:ident) => {
        impl $builder {
            #[doc = concat!("See [`", stringify!($http), "::transport_mode`].")]
            pub fn transport_mode(mut self, mode: TransportMode) -> Self {
                self.http = self.http.transport_mode(mode);
                self
            }

            #[doc = concat!("See [`", stringify!($http), "::base_url`]. The OpenAI client then")]
            /// sends to this URL as its API base, in place of the `/v1/`
            /// API of the enclave.
            pub fn base_url(mut self, url: impl Into<String>) -> Self {
                self.http = self.http.base_url(url);
                self
            }

            #[doc = concat!("See [`", stringify!($http), "::verifier`].")]
            pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
                self.http = self.http.verifier(verifier);
                self
            }

            #[doc = concat!("See [`", stringify!($http), "::verification_check`].")]
            pub fn verification_check<F>(mut self, check: F) -> Self
            where
                F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
            {
                self.http = self.http.verification_check(check);
                self
            }

            #[doc = concat!("See [`", stringify!($http), "::user_cache_secret`].")]
            pub fn user_cache_secret(mut self, secret: impl Into<String>) -> Self {
                self.http = self.http.user_cache_secret(secret);
                self
            }

            #[doc = concat!("See [`", stringify!($http), "::timeout`]. It also bounds each")]
            /// attempt of an OpenAI call.
            pub fn timeout(mut self, timeout: Duration) -> Self {
                self.http = self.http.timeout(timeout);
                self
            }
        }

        impl fmt::Debug for $builder {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // The configuration holds the API key and may hold
                // credentials in its headers: none of it is printed.
                f.debug_struct(stringify!($builder))
                    .field("http", &self.http)
                    .finish_non_exhaustive()
            }
        }
    };
}

/// Configures an [`EnclaveOpenAIClient`] and connects it. Its `Debug`
/// output shows nothing of the OpenAI configuration.
#[derive(Clone)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct EnclaveOpenAIClientBuilder {
    http: EnclaveHttpClientBuilder,
    config: OpenAIConfig,
}

forward_route_setters!(EnclaveOpenAIClientBuilder, EnclaveHttpClientBuilder);

impl EnclaveOpenAIClientBuilder {
    /// Checks the options, verifies the enclave and returns the client, as
    /// [`EnclaveHttpClientBuilder::connect`] does, with its errors and its
    /// cancel safety.
    pub async fn connect(self) -> Result<EnclaveOpenAIClient, Error> {
        let http = self.http.connect().await?;
        let api_base = http.inner.openai_url().clone();
        let executor: Arc<dyn crate::request::Execute> = http.inner.clone();
        let (openai, sender) =
            service::openai_client(self.config, &api_base, executor, http.transport_mode())?;
        Ok(EnclaveOpenAIClient {
            openai,
            sender,
            http,
            api_base,
        })
    }
}

/// Configures a [`RouterOpenAIClient`] and connects it. Its `Debug` output
/// shows nothing of the OpenAI configuration.
#[derive(Clone)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct RouterOpenAIClientBuilder {
    http: RouterHttpClientBuilder,
    config: OpenAIConfig,
}

forward_route_setters!(RouterOpenAIClientBuilder, RouterHttpClientBuilder);

impl RouterOpenAIClientBuilder {
    /// Checks the options, discovers and verifies a router and returns the
    /// client, as [`RouterHttpClientBuilder::connect`] does, with its
    /// errors and its cancel safety.
    pub async fn connect(self) -> Result<RouterOpenAIClient, Error> {
        let http = self.http.connect().await?;
        let api_base = http.inner.openai_url().clone();
        let executor: Arc<dyn crate::request::Execute> = http.inner.clone();
        let (openai, sender) =
            service::openai_client(self.config, &api_base, executor, http.transport_mode())?;
        Ok(RouterOpenAIClient {
            openai,
            sender,
            http,
            api_base,
        })
    }
}
