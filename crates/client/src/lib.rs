//! Attested HTTP and OpenAI clients for Tinfoil enclaves.
//!
//! A Tinfoil enclave proves what code it runs with an attestation
//! document. The clients of this crate fetch that document, verify it with
//! the [`verifier`], and then bind their traffic to the keys that the
//! verified document endorses, so that requests reach that enclave and
//! nothing else. A client verifies before its constructor returns, checks
//! its options before any network I/O, verifies again by itself when the
//! verification expires or the enclave's key changes, and refuses a
//! request to any origin other than the one that it is bound to.
//!
//! # Choosing a client
//!
//! | route | HTTP client | OpenAI client |
//! |---|---|---|
//! | Tinfoil's router, discovered (recommended) | [`RouterHttpClient`] | `Client`, or `RouterOpenAIClient` to configure it |
//! | an enclave that the caller names | [`EnclaveHttpClient`] | `EnclaveOpenAIClient` |
//!
//! The OpenAI clients need the `openai` feature, which is on by default.
//!
#![cfg_attr(feature = "openai", doc = "```no_run")]
#![cfg_attr(not(feature = "openai"), doc = "```ignore")]
//! use tinfoil::async_openai::config::OpenAIConfig;
//! use tinfoil::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tinfoil::Client::connect(OpenAIConfig::new().with_api_key("...")).await?;
//! let request = CreateChatCompletionRequestArgs::default()
//!     .model("gpt-oss-120b")
//!     .messages([ChatCompletionRequestUserMessageArgs::default()
//!         .content("Hello!")
//!         .build()?
//!         .into()])
//!     .build()?;
//! let response = client.chat().create(request).await?;
//! # let _ = response;
//! # Ok(())
//! # }
//! ```
//!
//! # Shape
//!
//! - **Constructors that do I/O are named `connect`.** `connect(..)` uses
//!   the defaults; `builder(..)` returns a builder whose setters each set
//!   one option and whose `connect()` creates the client.
//! - **A client is a handle**: `Clone`, `Send` and `Sync` over shared
//!   state, with methods on `&self`. There is no `close`; dropping the
//!   last clone releases the connections, and no background task runs.
//! - **Requests use `reqwest`'s types.** The crate re-exports [`reqwest`]
//!   and, with the `openai` feature, `async_openai`, so that the types in
//!   its API are the ones that it was built with.
//! - **Cancellation is dropping the future.** Every async method says
//!   what a drop leaves behind. Deadlines are the builders' `timeout`
//!   option and [`RequestBuilder::timeout`]. There is no blocking API; the
//!   clients need a Tokio runtime.
//! - **Errors** are [`Error`] values with an [`ErrorKind`]: configuration,
//!   network or attestation. A response body is read with `reqwest`'s
//!   methods, whose error is `reqwest`'s; [`Error::from_reqwest`] returns
//!   the client's error inside it. Errors from the OpenAI API keep
//!   `async_openai`'s type; `Error::from_openai` returns the client's
//!   error inside one, except for a typed stream that fails after it
//!   started, whose error holds a message only.
//!
//! # What is protected
//!
//! In [`TransportMode::Tls`], the default, every connection is pinned to
//! the attested TLS key, which protects the whole request and response. In
//! [`TransportMode::Ehbp`], request and response bodies are sealed to the
//! attested HPKE key and stay private through a proxy; the method, URL and
//! headers are not sealed, and neither is a request without a body.
//!
//! # Limits of the protection
//!
//! - **[`TransportMode::Ehbp`] does not authenticate the end of a
//!   response.** Each part of a sealed response body is authenticated, and
//!   so is the order of the parts: the content cannot be forged, altered
//!   or reordered. Nothing marks the last part, so whoever controls the
//!   connection can end a sealed response early between two parts, or
//!   return one with no parts, and the read ends without an error. A
//!   response that is cut inside a part is an error. A caller that needs
//!   to know that a response is complete checks the response's own
//!   terminator: that the JSON document is whole, or that the final event
//!   of a stream arrived. The event-stream parser reports a stream that
//!   is cut inside an event.
//! - **In [`TransportMode::Ehbp`] a request without a body is sent as it
//!   is**, and its response is returned as it arrives, neither encrypted
//!   nor authenticated. An error response to a sealed request that is not
//!   sealed itself is passed through as received, since a proxy may
//!   refuse a request before it reaches the enclave; nothing of it is
//!   authenticated. The exceptions return no response. A `2xx` response
//!   to a sealed request that is not sealed is refused. The enclave's key
//!   rejection, a `422` with the protocol's key-configuration problem, is
//!   an attestation error, after which the client verifies again and
//!   sends the request once more if its body can be sent again. A request
//!   whose streamed body turns out to be empty goes out unsealed and is
//!   held to the rules of a sealed one: a `2xx` response and a response
//!   that claims to be sealed are attestation errors. So is the
//!   key-configuration problem in answer to such a request, but it is not
//!   a key rejection, since nothing was sealed to a key: the current
//!   verification stays in place, the client does not verify again, and
//!   the request is not sent again.
//! - **A request without a cache secret uses the prompt-cache namespace
//!   that all such requests share.** No secret is added by an enclave
//!   client whose `user_cache_secret` option is unset; to a request that
//!   is not a `POST` with a body to a path ending in `/chat/completions`,
//!   `/completions` or `/responses`; to a body that is not a single JSON
//!   object; to a body in which `user_cache_secret` appears more than
//!   once or with a value that is not a string; or, on a router client
//!   without the option, when the operating system supplies no random
//!   bytes for the secret of the process. A non-empty `user_cache_secret`
//!   string in the body is kept.
//! - **The router list is not trusted.** [`RouterHttpClient`] takes its
//!   candidates from a list that is fetched over ordinary HTTPS, and
//!   verifies each router like any other enclave before it uses it. A
//!   wrong list can only cause attempts that fail, within the fixed time
//!   that discovery may take.
//!
//! # Features
//!
//! | feature | what it adds |
//! |---|---|
//! | `openai` (default) | the OpenAI clients over `async_openai`, with its chat completion, embedding, audio and responses APIs; the relaxed chat helper; the `sse` and `multimodal` modules |
//!
//! The other API families of `async_openai` are opt-in. Each feature below
//! implies `openai` and adds the family's calls to the OpenAI clients,
//! where they go through the attested HTTP client like every other call.
//! Whether an enclave serves a family is up to the enclave.
//!
//! | feature | API family |
//! |---|---|
//! | `openai-administration` | organization administration: users, projects, API keys, audit logs |
//! | `openai-batches` | batches |
//! | `openai-byot` | the `_byot` variants of every call, which take and return the caller's own types |
//! | `openai-chatkit` | ChatKit sessions and threads |
//! | `openai-completions` | legacy text completions |
//! | `openai-containers` | containers and their files |
//! | `openai-content-provenance-checks` | content provenance checks |
//! | `openai-evals` | evals and their runs |
//! | `openai-files` | files |
//! | `openai-fine-tuning` | fine-tuning jobs |
//! | `openai-images` | image generation and editing |
//! | `openai-models` | listing and retrieving models |
//! | `openai-moderations` | moderations |
//! | `openai-safety` | safety alerts |
//! | `openai-skills` | skills |
//! | `openai-uploads` | multipart uploads |
//! | `openai-vector-stores` | vector stores |
//!
//! `async_openai`'s realtime API is not offered: it opens WebSocket
//! connections of its own, which the attested client cannot protect. Its
//! webhook verification and OpenAPI schema generation make no request and
//! are not offered either, and neither is its videos API, which
//! `async_openai` has deprecated.

// Clippy has no test exemption for this lint, unlike the other denied
// lints (see clippy.toml). Overflow in a test is a test failure.
#![cfg_attr(test, allow(clippy::arithmetic_side_effects))]

mod enclave_client;
mod error;
mod internal;
#[cfg(feature = "openai")]
mod openai;
mod options;
mod request;
mod router_client;

#[cfg(feature = "openai")]
pub mod multimodal;
#[cfg(feature = "openai")]
pub mod sse;

/// The verifier that the clients are built on: offline verification of
/// attestation documents, the verification policy and the verified facts.
pub use tinfoil_verifier as verifier;

#[cfg(feature = "openai")]
pub use async_openai;
pub use reqwest;

/// `async_openai`'s audio types.
#[cfg(feature = "openai")]
pub use async_openai::types::audio;
/// `async_openai`'s chat types.
#[cfg(feature = "openai")]
pub use async_openai::types::chat;
/// `async_openai`'s embedding types.
#[cfg(feature = "openai")]
pub use async_openai::types::embeddings;

pub use enclave_client::{EnclaveHttpClient, EnclaveHttpClientBuilder};
pub use error::{Error, ErrorKind};
#[cfg(feature = "openai")]
pub use openai::relaxed::{
    RelaxedChat, RelaxedChatRequestBuilder, RelaxedResponse, RelaxedStream, RelaxedStreamChunk,
    RelaxedToolCall,
};
#[cfg(feature = "openai")]
pub use openai::{
    Client, EnclaveOpenAIClient, EnclaveOpenAIClientBuilder, RouterOpenAIClient,
    RouterOpenAIClientBuilder,
};
pub use options::TransportMode;
pub use request::RequestBuilder;
pub use router_client::{RouterHttpClient, RouterHttpClientBuilder};
pub use tinfoil_verifier::Pin;

// Compiles the examples of the repository's README as documentation tests,
// so that they cannot drift from the API.
#[cfg(all(doctest, feature = "openai"))]
#[doc = include_str!("../../../README.md")]
struct ReadmeExamples;

// And the examples of the migration guide. Its examples of the earlier API
// are marked `ignore`.
#[cfg(all(doctest, feature = "openai"))]
#[doc = include_str!("../../../MIGRATION.md")]
struct MigrationExamples;

/// The version of this SDK.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
