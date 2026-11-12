//! The client for Tinfoil's inference gateway. Experimental.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::internal::gateway::GatewayTransport;
use crate::options::{CommonOptions, Secret};
use crate::request::http_request_methods;
use crate::verifier::{BoxError, Verification, Verifier};

/// What a gateway offers for one model: the repository that its replicas
/// claim to run and the hosts of those replicas. Untrusted: every replica
/// is verified before anything is sealed to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    /// The repository, as a bare `tinfoilsh/<name>` without a tag or a
    /// digest.
    pub repo: String,
    /// The replicas' hosts.
    pub hosts: Vec<String>,
}

/// A gateway's catalog: model names mapped to their untrusted entries.
pub type Catalog = HashMap<String, CatalogEntry>;

/// Pins a model to a repository.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ModelPin {
    /// The repository that the model's replicas must run, as
    /// `tinfoilsh/<name>[@tag][@sha256:digest]`.
    pub repo: String,
    /// The policy for this model's replicas. `None` inherits the client's
    /// verifier.
    pub verifier: Option<Arc<Verifier>>,
}

impl ModelPin {
    /// A pin to `repo` that inherits the client's verifier.
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            verifier: None,
        }
    }

    /// The same pin with a verifier of its own, which replaces the
    /// client's for this model.
    pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
        self.verifier = Some(verifier.into());
        self
    }
}

/// A gateway replica's last successful verification.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ReplicaVerification {
    /// The replica that the verification is for.
    pub host: String,
    /// The models that requests to this replica have named, sorted. They
    /// are names from requests, not attested identities.
    pub models: Vec<String>,
    /// The repository reference that the replica was verified against.
    pub reference: String,
    /// The pinned model that the reference came from, if it came from a
    /// pin.
    pub pinned_model: Option<String>,
    /// The verification. It may have expired or been rejected since.
    pub verification: Arc<Verification>,
}

/// Reads the catalog of the gateway at `host`, keeping only the models
/// whose entry names a bare `tinfoilsh/` repository, without a tag or a
/// digest, and at least one replica.
///
/// The catalog is fetched from `https://<host>/catalog` within 10 seconds
/// and is at most 2 MiB; redirects are not followed.
/// Every failure is a network error, except a `host` that yields no URL,
/// which is a configuration error.
///
/// Dropping the future closes the connection and leaves nothing behind.
///
/// **Not implemented yet.** In this version of the crate the call always
/// fails with an error that says so; the text above is the contract
/// that it will meet.
pub async fn fetch_catalog(host: &str) -> Result<Catalog, Error> {
    crate::internal::gateway::fetch_catalog(host).await
}

/// An HTTP client for Tinfoil inference through the gateway.
///
/// Each request is sealed to a verified replica of the model that it
/// names, as in [`TransportMode::Ehbp`](crate::TransportMode::Ehbp): the
/// gateway sees the method, the URL and the headers, and protocol upgrades
/// are refused. The model is read from the `model` member of a JSON body
/// or the `model` field of a multipart upload.
///
/// Unlike the other clients, this one fetches the catalog when it is
/// created but verifies no replica until a request needs one.
///
/// Experimental: the gateway route is new, and everything about this
/// client may change or be removed in any release.
#[derive(Clone)]
pub struct GatewayHttpClient {
    pub(crate) inner: Arc<GatewayTransport>,
}

impl GatewayHttpClient {
    /// Fetches the gateway's catalog and returns a client, with the
    /// default options. See [`GatewayHttpClientBuilder::connect`].
    pub async fn connect() -> Result<Self, Error> {
        Self::builder().connect().await
    }

    /// Starts a gateway client to be configured before it connects.
    pub fn builder() -> GatewayHttpClientBuilder {
        GatewayHttpClientBuilder {
            options: GatewayOptions::default(),
        }
    }

    /// The gateway's base URL, which requests are sent to. The path ends
    /// in `/`.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// The catalog's models that the client's policy serves, sorted,
    /// without verifying any replica.
    ///
    /// Only the first catalog fetch can fail it; afterwards a failed
    /// refresh keeps the last catalog. Dropping the future leaves the
    /// cached catalog as it was.
    pub async fn models(&self) -> Result<Vec<String>, Error> {
        self.inner.models().await
    }

    /// Returns a verification, valid now, of a replica that serves
    /// `model`, verifying replicas only if needed. Replicas are tried in
    /// an order that is fixed for the model, so repeated calls return the
    /// same replica while it stays valid.
    ///
    /// A model that the policy does not serve is a configuration error; a
    /// catalog entry that contradicts a pin is an attestation error; when
    /// no replica verifies, the error of the last one is returned.
    ///
    /// Dropping the future is safe: verifications that completed are kept,
    /// the one in progress follows the rules of
    /// [`EnclaveHttpClient::ensure_verified`](crate::EnclaveHttpClient::ensure_verified).
    pub async fn ensure_verified(&self, model: &str) -> Result<Arc<Verification>, Error> {
        self.inner.ensure_verified(model).await
    }

    /// The last successful verification of each replica used so far,
    /// sorted by host, without checking them: they may have expired or
    /// been rejected since.
    pub fn current(&self) -> Vec<ReplicaVerification> {
        self.inner.verifications()
    }
}

http_request_methods!(GatewayHttpClient);

impl fmt::Debug for GatewayHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayHttpClient")
            .field("base_url", &self.base_url().as_str())
            .finish_non_exhaustive()
    }
}

/// A caller's source of the catalog.
pub(crate) type CatalogSource = Arc<dyn Fn() -> Arc<Catalog> + Send + Sync + 'static>;

/// The options of the gateway route.
#[derive(Clone, Default)]
pub(crate) struct GatewayOptions {
    pub(crate) common: CommonOptions,
    pub(crate) model_pins: HashMap<String, ModelPin>,
    pub(crate) pinned_models_only: bool,
    pub(crate) url: Option<String>,
    pub(crate) catalog: Option<CatalogSource>,
}

impl fmt::Debug for GatewayOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayOptions")
            .field("common", &self.common)
            .field("model_pins", &self.model_pins)
            .field("pinned_models_only", &self.pinned_models_only)
            .field("url", &self.url.as_ref().map(|_| "[set]"))
            .field("catalog", &self.catalog.is_some())
            .finish()
    }
}

/// Configures a [`GatewayHttpClient`] and connects it.
///
/// An option is unset until its setter is called. The setters check
/// nothing: [`connect`](Self::connect) checks every option before any
/// network I/O.
///
/// Experimental, as the client is.
#[derive(Clone, Debug)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct GatewayHttpClientBuilder {
    pub(crate) options: GatewayOptions,
}

impl GatewayHttpClientBuilder {
    /// Pins models to repositories: each item is a model name and its
    /// [`ModelPin`]. A pinned model's replicas are verified against the
    /// pin's repository, with any tag or digest, under the pin's verifier
    /// or else the client's. Pins may name models that the catalog does
    /// not list. Calling this again adds to the pins and replaces a model
    /// that is named twice.
    pub fn model_pins<I, K>(mut self, pins: I) -> Self
    where
        I: IntoIterator<Item = (K, ModelPin)>,
        K: Into<String>,
    {
        self.options
            .model_pins
            .extend(pins.into_iter().map(|(model, pin)| (model.into(), pin)));
        self
    }

    /// Whether only pinned models are served. It requires at least one
    /// pin. Unset, unpinned models are served from the catalog's
    /// repository under the client's verifier.
    pub fn pinned_models_only(mut self, pinned_only: bool) -> Self {
        self.options.pinned_models_only = pinned_only;
        self
    }

    /// The policy for unpinned models, and for pins without a verifier of
    /// their own. Unset, it is `Verifier::new()`. A verifier that supplies
    /// or authorizes the config itself is refused.
    pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
        self.options.common.verifier = Some(verifier.into());
        self
    }

    /// A veto over each replica's verification, for pinned and unpinned
    /// models, as
    /// [`EnclaveHttpClientBuilder::verification_check`](crate::EnclaveHttpClientBuilder::verification_check)
    /// is. A replica that it rejects is skipped for the next replica of
    /// the model.
    pub fn verification_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.options.common.verification_check = Some(Arc::new(check));
        self
    }

    /// The default prompt-cache scope for the client's requests. Unset, it
    /// is resolved from the environment or the secret file, as
    /// [`RouterHttpClientBuilder::user_cache_secret`](crate::RouterHttpClientBuilder::user_cache_secret)
    /// describes. A non-empty `user_cache_secret` string in a request's
    /// body wins over it.
    ///
    /// The secret itself never leaves the client: the client derives a
    /// cache salt from it and the request's API key, and sends that to the
    /// replica in place of the secret. The gateway sees a cache prefix
    /// keyed on the secret, so use an opaque random value: with a
    /// guessable secret the gateway could test guesses of it, and then of
    /// the prompt.
    pub fn user_cache_secret(mut self, secret: impl Into<String>) -> Self {
        self.options.common.user_cache_secret = Some(Secret::new(secret));
        self
    }

    /// The gateway's base URL. Unset, it is Tinfoil's gateway,
    /// `https://inference-gateway.tinfoil.sh/v1/`. It must be an absolute
    /// HTTPS URL without a user name, a password, a query string or a
    /// fragment; its path is made to end in `/`.
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.options.url = Some(url.into());
        self
    }

    /// The caller's own source of the catalog, in place of the gateway's.
    /// It is called on every request and should return quickly. Unset,
    /// the client fetches the gateway's catalog when it connects and
    /// refreshes it every 10 seconds while it is used; a failed refresh
    /// keeps the last catalog.
    pub fn catalog<F>(mut self, catalog: F) -> Self
    where
        F: Fn() -> Arc<Catalog> + Send + Sync + 'static,
    {
        self.options.catalog = Some(Arc::new(catalog));
        self
    }

    /// A deadline for each operation of the client: [`connect`], each
    /// `models` and `ensure_verified`, and each request, from the call
    /// until the response body has been read. A request's own timeout
    /// replaces it for that request.
    ///
    /// [`connect`]: Self::connect
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.common.timeout = Some(timeout);
        self
    }

    /// Checks the options, fetches the catalog and returns the client.
    ///
    /// Before any network I/O, each a configuration error:
    ///
    /// 1. `url` is empty or is not an absolute HTTPS URL, or carries a user
    ///    name or password (this error does not repeat the URL), a query
    ///    string or a fragment.
    /// 2. `user_cache_secret` is empty, or `timeout` is zero.
    /// 3. `pinned_models_only` is set and there is no pin.
    /// 4. The client's verifier, or a pin's, supplies or authorizes the
    ///    config itself.
    /// 5. A pin's model name is blank, its repository is not under
    ///    `tinfoilsh/`, or its repository is not a repository reference.
    ///
    /// Then the catalog is fetched, unless the `catalog` option supplies
    /// it, so that an unreachable gateway fails here and not on the first
    /// request: a network error. No replica is verified yet.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future closes the catalog fetch. No client exists.
    /// The cache secret file, if this call created it, stays.
    ///
    /// **Not implemented yet.** In this version of the crate the call always
    /// fails with an error that says so; the text above is the contract
    /// that it will meet.
    pub async fn connect(self) -> Result<GatewayHttpClient, Error> {
        Err(Error::not_implemented("GatewayHttpClient::connect"))
    }
}
