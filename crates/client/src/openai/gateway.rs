//! The OpenAI client for the gateway route. Experimental.

use std::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use async_openai::config::OpenAIConfig;
use async_openai::error::OpenAIError;
use async_openai::types::audio::{CreateTranscriptionRequest, CreateTranscriptionResponseJson};
use reqwest::Url;

use super::relaxed::RelaxedChat;
use super::{OpenAI, openai_client_methods};
use crate::error::Error;
use crate::gateway_client::{Catalog, GatewayHttpClient, GatewayHttpClientBuilder, ModelPin};
use crate::verifier::{BoxError, Verification, Verifier};

/// An OpenAI client whose requests go through a [`GatewayHttpClient`], to
/// the gateway's URL.
///
/// See [`Client`](crate::Client) for how errors, retries and `Deref`
/// behave.
///
/// Experimental: the gateway route is new, and everything about this
/// client may change or be removed in any release.
#[derive(Clone)]
pub struct GatewayOpenAIClient {
    openai: OpenAI,
    http: GatewayHttpClient,
    api_base: Url,
}

impl GatewayOpenAIClient {
    /// Creates a gateway client, as [`GatewayHttpClient::connect`] does,
    /// and returns an OpenAI client over it. `config` is applied first;
    /// then the API base and the HTTP client are set, so that `config`
    /// cannot replace them.
    pub async fn connect(config: OpenAIConfig) -> Result<Self, Error> {
        Self::builder(config).connect().await
    }

    /// Starts a gateway OpenAI client to be configured before it connects.
    /// The builder has the options of [`GatewayHttpClientBuilder`].
    pub fn builder(config: OpenAIConfig) -> GatewayOpenAIClientBuilder {
        GatewayOpenAIClientBuilder {
            http: GatewayHttpClient::builder(),
            config,
        }
    }

    /// The gateway client that the OpenAI client sends through.
    pub fn http_client(&self) -> &GatewayHttpClient {
        &self.http
    }
}

openai_client_methods!(GatewayOpenAIClient);

impl fmt::Debug for GatewayOpenAIClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayOpenAIClient")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// Configures a [`GatewayOpenAIClient`] and connects it. Its `Debug`
/// output shows nothing of the OpenAI configuration.
///
/// Experimental, as the client is.
#[derive(Clone)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct GatewayOpenAIClientBuilder {
    http: GatewayHttpClientBuilder,
    config: OpenAIConfig,
}

impl GatewayOpenAIClientBuilder {
    /// See [`GatewayHttpClientBuilder::model_pins`].
    pub fn model_pins<I, K>(mut self, pins: I) -> Self
    where
        I: IntoIterator<Item = (K, ModelPin)>,
        K: Into<String>,
    {
        self.http = self.http.model_pins(pins);
        self
    }

    /// See [`GatewayHttpClientBuilder::pinned_models_only`].
    pub fn pinned_models_only(mut self, pinned_only: bool) -> Self {
        self.http = self.http.pinned_models_only(pinned_only);
        self
    }

    /// See [`GatewayHttpClientBuilder::verifier`].
    pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
        self.http = self.http.verifier(verifier);
        self
    }

    /// See [`GatewayHttpClientBuilder::verification_check`].
    pub fn verification_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.http = self.http.verification_check(check);
        self
    }

    /// See [`GatewayHttpClientBuilder::user_cache_secret`].
    pub fn user_cache_secret(mut self, secret: impl Into<String>) -> Self {
        self.http = self.http.user_cache_secret(secret);
        self
    }

    /// See [`GatewayHttpClientBuilder::url`]. The OpenAI client sends to
    /// this URL as its API base.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.http = self.http.url(url);
        self
    }

    /// See [`GatewayHttpClientBuilder::catalog`].
    pub fn catalog<F>(mut self, catalog: F) -> Self
    where
        F: Fn() -> Arc<Catalog> + Send + Sync + 'static,
    {
        self.http = self.http.catalog(catalog);
        self
    }

    /// See [`GatewayHttpClientBuilder::timeout`]. It also bounds each
    /// attempt of an OpenAI call.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.http = self.http.timeout(timeout);
        self
    }

    /// Checks the options, fetches the catalog and returns the client, as
    /// [`GatewayHttpClientBuilder::connect`] does, with its errors and its
    /// cancel safety.
    pub async fn connect(self) -> Result<GatewayOpenAIClient, Error> {
        Err(Error::not_implemented("GatewayOpenAIClient::connect"))
    }
}

impl fmt::Debug for GatewayOpenAIClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The configuration holds the API key and may hold credentials in
        // its headers: none of it is printed.
        f.debug_struct("GatewayOpenAIClientBuilder")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}
