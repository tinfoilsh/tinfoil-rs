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
//! # Status
//!
//! This version of the crate is its API without the machinery behind it:
//! the types, the signatures and their documented contracts are in place,
//! and every function that would perform network I/O (each `connect`,
//! `fetch_catalog`, the relaxed chat calls and `parse_event_stream`) fails
//! with an error whose message says that the function is not implemented
//! yet. That error has the kind [`ErrorKind::Configuration`], since
//! retrying cannot help; it does not mean that an option is wrong.
//!
//! # Choosing a client
//!
//! | route | HTTP client | OpenAI client |
//! |---|---|---|
//! | Tinfoil's router, discovered (recommended) | [`RouterHttpClient`] | `Client`, or `RouterOpenAIClient` to configure it |
//! | an enclave that the caller names | [`EnclaveHttpClient`] | `EnclaveOpenAIClient` |
//! | Tinfoil's gateway (experimental, feature `unstable-gateway`) | `GatewayHttpClient` | `GatewayOpenAIClient` |
//!
//! The OpenAI clients need the `openai` feature, which is on by default.
//!
#![cfg_attr(feature = "openai", doc = "```no_run")]
#![cfg_attr(not(feature = "openai"), doc = "```ignore")]
//! use tinfoil_next::async_openai::config::OpenAIConfig;
//! use tinfoil_next::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = tinfoil_next::Client::connect(OpenAIConfig::new().with_api_key("...")).await?;
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
//!   network or attestation. Errors from the OpenAI API keep
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
//! - `openai` (default): the OpenAI clients over `async_openai`, the
//!   relaxed chat helper, and the `sse` and `multimodal` modules.
//! - `unstable-gateway`: the gateway route. Experimental; anything behind
//!   it may change or be removed in any release.

// The bodies of this crate are placeholders, which leave their arguments
// and most internal items unused.
#![allow(dead_code, unused_variables)]
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
pub use request::{RequestBuilder, ResponseFuture};
pub use router_client::{RouterHttpClient, RouterHttpClientBuilder};

/// The version of this SDK.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
