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
//! # The gateway route is not implemented
//!
//! The feature `unstable-gateway`, which is off by default, is
//! experimental and **not implemented**. It adds the types and signatures
//! of the gateway route without the machinery behind them: each of its
//! functions that would perform network I/O fails with an error whose
//! message says that the function is not implemented yet. That error has
//! the kind [`ErrorKind::Configuration`], since retrying cannot help; it
//! does not mean that an option is wrong. Do not enable the feature to use
//! the gateway; everything else in the crate is complete without it.
//!
//! # Choosing a client
//!
//! | route | HTTP client | OpenAI client |
//! |---|---|---|
//! | Tinfoil's router, discovered (recommended) | [`RouterHttpClient`] | `Client`, or `RouterOpenAIClient` to configure it |
//! | an enclave that the caller names | [`EnclaveHttpClient`] | `EnclaveOpenAIClient` |
//! | Tinfoil's gateway (feature `unstable-gateway`: experimental, not implemented) | `GatewayHttpClient` | `GatewayOpenAIClient` |
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
//!   `async_openai`'s type.
//!
//! # What is protected
//!
//! In [`TransportMode::Tls`], the default, every connection is pinned to
//! the attested TLS key, which protects the whole request and response. In
//! [`TransportMode::Ehbp`], request and response bodies are sealed to the
//! attested HPKE key and stay private through a proxy; the method, URL and
//! headers are not sealed, and neither is a request without a body.
//!
//! # Features
//!
//! | feature | what it adds |
//! |---|---|
//! | `openai` (default) | the OpenAI clients over `async_openai`, with its chat completion, embedding, audio and responses APIs; the relaxed chat helper; the `sse` and `multimodal` modules |
//! | `unstable-gateway` | the types of the gateway route. Experimental and not implemented: its calls fail, and anything behind it may change or be removed in any release |
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
#[cfg(feature = "unstable-gateway")]
mod gateway_client;
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
#[cfg(feature = "unstable-gateway")]
pub use gateway_client::{
    Catalog, CatalogEntry, GatewayHttpClient, GatewayHttpClientBuilder, ModelPin,
    ReplicaVerification, fetch_catalog,
};
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
#[cfg(all(feature = "openai", feature = "unstable-gateway"))]
pub use openai::{GatewayOpenAIClient, GatewayOpenAIClientBuilder};
pub use options::TransportMode;
pub use request::RequestBuilder;
pub use router_client::{RouterHttpClient, RouterHttpClientBuilder};

// Compiles the examples of the repository's README as documentation tests,
// so that they cannot drift from the API.
#[cfg(all(doctest, feature = "openai"))]
#[doc = include_str!("../../../README.md")]
struct ReadmeExamples;

/// The version of this SDK.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
