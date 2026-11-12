//! The client for one enclave that the caller names.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::internal::attested::AttestedClient;
use crate::options::{RouteOptions, Secret, TransportMode};
use crate::request::http_request_methods;
use crate::verifier::{BoxError, Verification, Verifier};

/// An HTTP client whose requests reach only one attested enclave.
///
/// The client is verified when it is created: [`connect`] returns only
/// after the enclave's attestation passed, so a misconfigured client fails
/// there and not on its first request. It verifies again by itself when
/// the verification expires or the enclave stops holding the attested
/// keys, and it refuses a request to any other origin.
///
/// Requests are made with `reqwest`'s types: [`get`](Self::get),
/// [`post`](Self::post) and the other request methods return a
/// [`RequestBuilder`](crate::RequestBuilder), and
/// [`execute`](Self::execute) takes a `reqwest::Request`.
///
/// The client is a handle: cloning it is cheap, and every clone shares the
/// same verification and connections. It is `Send` and `Sync`. There is
/// nothing to close; dropping the last clone releases the connections.
///
/// What is protected depends on the [`TransportMode`]: in `Tls`, the whole
/// request and response; in `Ehbp`, the bodies only, and not a request
/// without a body or the response to it.
///
/// [`connect`]: EnclaveHttpClient::connect
#[derive(Clone)]
pub struct EnclaveHttpClient {
    pub(crate) inner: Arc<AttestedClient>,
}

impl EnclaveHttpClient {
    /// Verifies the enclave at `host` against `repo` and returns a client
    /// for it, with the default options.
    ///
    /// `host` is a host with an optional port, not a URL. `repo` is the
    /// repository that the enclave's code or config must come from, as
    /// `Some("owner/name[@tag][@sha256:digest]")`. `None` sets no pin: the
    /// enclave must then run a config that the verifier's own policy
    /// authorizes, which for the default verifier is one signed into the
    /// public registry. An empty string is not "no pin": `Some("")` is a
    /// configuration error.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), tinfoil_next::Error> {
    /// use tinfoil_next::EnclaveHttpClient;
    ///
    /// let pinned = EnclaveHttpClient::connect("enclave.example.com", Some("owner/name")).await?;
    /// let unpinned = EnclaveHttpClient::connect("enclave.example.com", None).await?;
    /// # let _ = (pinned, unpinned);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [`EnclaveHttpClientBuilder::connect`] for the checks, the errors
    /// and cancel safety.
    pub async fn connect(host: impl Into<String>, repo: Option<&str>) -> Result<Self, Error> {
        Self::builder(host, repo).connect().await
    }

    /// Starts a client for the enclave at `host`, verified against `repo`,
    /// to be configured before it connects. The arguments are those of
    /// [`connect`](Self::connect).
    pub fn builder(host: impl Into<String>, repo: Option<&str>) -> EnclaveHttpClientBuilder {
        EnclaveHttpClientBuilder {
            host: host.into(),
            repo: repo.map(str::to_owned),
            options: RouteOptions::default(),
        }
    }

    /// Where requests are sent: the `base_url` option, or else the
    /// enclave's own origin, `https://<host>/`. The path ends in `/`, so
    /// `base_url().join("v1/models")` stays under it.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// The host of the enclave that the client verifies. It stays the
    /// enclave's host when `base_url` is a proxy.
    pub fn enclave(&self) -> &str {
        self.inner.enclave()
    }

    /// The repository pin that the enclave is verified against, with any
    /// tag or digest. `None` when the client was created without a pin.
    pub fn repo(&self) -> Option<&str> {
        self.inner.repo()
    }

    /// The transport mode that the client was created with.
    pub fn transport_mode(&self) -> TransportMode {
        self.inner.transport_mode()
    }

    /// The last successful verification, without checking it: it may have
    /// expired or been rejected since. Use
    /// [`ensure_verified`](Self::ensure_verified) for one that is valid
    /// now. A failed re-verification does not change it.
    pub fn current(&self) -> Arc<Verification> {
        self.inner.current()
    }

    /// Returns a verification that is valid now, verifying first only if
    /// the current one has expired or was rejected. `Ok` means that
    /// requests can be sent: the TLS pin or the HPKE key is in place.
    ///
    /// A verification is one fetch of the enclave's attestation document
    /// (at most 30 seconds and 32 MiB) and its offline verification, then
    /// the `verification_check` option. A failure with a network or
    /// attestation error is tried once more after one second; a
    /// configuration error and a rejection by `verification_check` are
    /// not. Callers that need a verification at the same time share one,
    /// and its result.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::Network`]: the document could not be fetched.
    /// - [`ErrorKind::Attestation`]: the document was rejected (the source
    ///   is the verifier's error), it endorses no key that the transport
    ///   mode can use, its freshness has expired, or `verification_check`
    ///   rejected it.
    /// - A deadline from the `timeout` option is a network error whose
    ///   [`is_timeout`](Error::is_timeout) is `true`.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future is safe. The current verification stays in
    /// place and usable. A verification in progress continues for the
    /// other callers that wait for it, and is abandoned if there are none;
    /// nothing half-finished is ever published.
    ///
    /// [`ErrorKind::Network`]: crate::ErrorKind::Network
    /// [`ErrorKind::Attestation`]: crate::ErrorKind::Attestation
    pub async fn ensure_verified(&self) -> Result<Arc<Verification>, Error> {
        self.inner.ensure_verified().await
    }

    /// Verifies the enclave again even if the current verification is
    /// still valid, and returns the new verification.
    ///
    /// On success the client's traffic moves to the keys of the new
    /// verification; requests in flight finish on the connections that
    /// they started on. On failure the previous verification stays in
    /// place, and stays valid until it expires or is rejected.
    ///
    /// The errors and the cancel safety are those of
    /// [`ensure_verified`](Self::ensure_verified): a dropped `reverify`
    /// leaves the previous binding in place.
    pub async fn reverify(&self) -> Result<Arc<Verification>, Error> {
        self.inner.reverify().await
    }
}

http_request_methods!(EnclaveHttpClient);

impl fmt::Debug for EnclaveHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnclaveHttpClient")
            .field("enclave", &self.enclave())
            .field("repo", &self.repo())
            .field("base_url", &self.base_url().as_str())
            .field("transport_mode", &self.transport_mode())
            .finish_non_exhaustive()
    }
}

/// Configures an [`EnclaveHttpClient`] and connects it.
///
/// An option is unset until its setter is called; no value stands for
/// "unset". The setters check nothing: [`connect`](Self::connect) checks
/// every option before any network I/O.
///
/// The `Debug` output shows neither the user cache secret nor the base
/// URL, which has not been checked for credentials yet.
#[derive(Clone, Debug)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct EnclaveHttpClientBuilder {
    host: String,
    repo: Option<String>,
    options: RouteOptions,
}

impl EnclaveHttpClientBuilder {
    /// How the client protects its traffic. Unset, it is
    /// [`TransportMode::Tls`].
    pub fn transport_mode(mut self, mode: TransportMode) -> Self {
        self.options.transport_mode = Some(mode);
        self
    }

    /// Where requests are sent instead of `https://<host>/`: a path on the
    /// enclave's own origin, or a proxy on another origin that forwards to
    /// the enclave.
    ///
    /// A proxy requires [`TransportMode::Ehbp`], since a pinned connection
    /// cannot pass through one. Requests to a proxy carry the
    /// `X-Tinfoil-Enclave-Url` header, set to `https://<host>`, so that the
    /// proxy can forward them. The proxy sees the method, the URL and the
    /// headers of every request, an API key among them.
    ///
    /// The URL must be absolute and use HTTPS; `http://` is accepted only
    /// for `localhost` or a loopback IP address, for a local development
    /// proxy or a sidecar. It must not carry a user name, a password, a
    /// query string or a fragment. Its path is made to end in `/`.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.options.base_url = Some(url.into());
        self
    }

    /// The verification policy. Unset, it is `Verifier::new()`. A verifier
    /// can be shared by several clients: pass an `Arc<Verifier>`.
    pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
        self.options.common.verifier = Some(verifier.into());
        self
    }

    /// A veto over each verification that passed the verifier, called
    /// before the client uses the enclave's keys: when the client connects
    /// and whenever it verifies again.
    ///
    /// Return an error to reject the enclave. The verification then fails
    /// with an attestation error that has the returned error as its
    /// source, and it is not tried again. Requests wait while the check
    /// runs, so it should be fast, and it may be called from several
    /// threads at once.
    pub fn verification_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.options.common.verification_check = Some(Arc::new(check));
        self
    }

    /// The default prompt-cache scope for the client's requests: the
    /// client adds it as `user_cache_secret` to the JSON body of chat
    /// completion, completion and response requests.
    ///
    /// Only Tinfoil's router reads the member, so set it when the enclave
    /// is a router. A non-empty `user_cache_secret` string that a request's
    /// body already carries wins over it, so a server can scope the cache
    /// to each of its users. Use an opaque random value, not a user ID or
    /// an API key.
    ///
    /// Unset, this client adds nothing: it reads neither the environment
    /// nor a file.
    pub fn user_cache_secret(mut self, secret: impl Into<String>) -> Self {
        self.options.common.user_cache_secret = Some(Secret::new(secret));
        self
    }

    /// A deadline for each operation of the client: [`connect`], each
    /// [`ensure_verified`] and [`reverify`], and each request, from the
    /// call until the response body has been read. A request's own
    /// [`timeout`] replaces it for that request.
    ///
    /// Unset, there is no deadline other than the client's fixed bounds on
    /// fetching attestation material. Dropping a future is the other way
    /// to stop an operation.
    ///
    /// [`connect`]: Self::connect
    /// [`ensure_verified`]: EnclaveHttpClient::ensure_verified
    /// [`reverify`]: EnclaveHttpClient::reverify
    /// [`timeout`]: crate::RequestBuilder::timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.common.timeout = Some(timeout);
        self
    }

    /// Checks the options, verifies the enclave and returns the client.
    ///
    /// Before any network I/O, in this order, each a configuration error:
    ///
    /// 1. `host` is empty, or is not a host with an optional port.
    /// 2. `base_url` is empty, is not an absolute `http` or `https` URL, or
    ///    carries a user name or password (this error does not repeat the
    ///    URL), a query string or a fragment; or it uses `http://` for a
    ///    host other than `localhost` or a loopback IP address.
    /// 3. `user_cache_secret` is empty, or `timeout` is zero.
    /// 4. `repo` is `Some("")`, or is not a repository reference, or the
    ///    verifier cannot verify against it: a verifier with a config
    ///    authorizer takes no pin, and one with an embedded config takes
    ///    only a matching one.
    /// 5. The mode is [`TransportMode::Tls`] and `base_url` is on another
    ///    origin than the enclave: that is a proxy, which requires
    ///    [`TransportMode::Ehbp`].
    ///
    /// Then the enclave is verified, as
    /// [`ensure_verified`](EnclaveHttpClient::ensure_verified) describes,
    /// with its errors.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future stops the verification and closes its
    /// connection. No client exists and nothing is left behind.
    ///
    /// **Not implemented yet.** In this version of the crate the call always
    /// fails with an error that says so; the text above is the contract
    /// that it will meet.
    pub async fn connect(self) -> Result<EnclaveHttpClient, Error> {
        self.check()?;
        Err(Error::not_implemented("EnclaveHttpClient::connect"))
    }

    /// The checks of the options that are written so far. No I/O.
    pub(crate) fn check(&self) -> Result<(), Error> {
        crate::internal::enclave::check_pin(self.repo.as_deref())
    }
}
