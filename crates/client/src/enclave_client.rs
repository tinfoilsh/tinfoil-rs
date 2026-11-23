//! The client for one enclave that the caller names.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::fetchers::{self, AttestationFetcher};
use crate::internal::attested::{AttestedClient, Settings};
use crate::internal::transport::base_url;
use crate::internal::{enclave, system_clock};
use crate::options::{RouteOptions, Transport};
use crate::request::http_request_methods;
use crate::trust::Trust;
use crate::verifier::{BoxError, Policy, Verification, Verifier};

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
/// What is protected depends on the [`Transport`]: in `Tls`, the whole
/// request and response; in `Ehbp`, the bodies only, and not a request
/// without a body or the response to it.
///
/// The client sends request bodies as they are: it never adds or changes a
/// `user_cache_secret` member. A caller that points it at Tinfoil's router
/// and wants a scoped prompt cache sets that member in each request body.
///
/// [`connect`]: EnclaveHttpClient::connect
#[derive(Clone)]
pub struct EnclaveHttpClient {
    pub(crate) inner: Arc<AttestedClient>,
    /// What the enclave is verified under.
    trust: Arc<Trust>,
}

impl EnclaveHttpClient {
    /// Verifies the enclave at `host` under `trust` and returns a client
    /// for it, with the default options.
    ///
    /// `host` is a host with an optional port, not a URL. `trust` names
    /// who vouches for the config that the enclave runs.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), tinfoil::Error> {
    /// use tinfoil::{EnclaveHttpClient, Trust};
    ///
    /// let repo = EnclaveHttpClient::connect("enclave.example.com", Trust::repo("owner/name")).await?;
    /// let project =
    ///     EnclaveHttpClient::connect("enclave.example.com", Trust::project("org/project")).await?;
    /// # let _ = (repo, project);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// See [`EnclaveHttpClientBuilder::connect`] for the checks, the errors
    /// and cancel safety.
    pub async fn connect(host: impl Into<String>, trust: Trust) -> Result<Self, Error> {
        Self::builder(host, trust).connect().await
    }

    /// Starts a client for the enclave at `host`, verified under `trust`,
    /// to be configured before it connects. The arguments are those of
    /// [`connect`](Self::connect).
    pub fn builder(host: impl Into<String>, trust: Trust) -> EnclaveHttpClientBuilder {
        EnclaveHttpClientBuilder {
            host: host.into(),
            trust,
            options: RouteOptions::default(),
        }
    }

    /// Where requests are sent: the proxy URL of [`Transport::Ehbp`], or
    /// else the enclave's own origin, `https://<host>/`. The path ends in
    /// `/`, so `base_url().join("v1/models")` stays under it.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// The host of the enclave that the client verifies. It stays the
    /// enclave's host when requests go through a proxy.
    pub fn enclave(&self) -> &str {
        self.inner.enclave()
    }

    /// The trust that the enclave is verified under: the argument that the
    /// client was created with.
    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    /// The last successful verification, without checking it: it may have
    /// expired or been discarded since. Use
    /// [`ensure_verified`](Self::ensure_verified) for one that is valid
    /// now. A failed re-verification does not change it.
    pub fn current(&self) -> Arc<Verification> {
        self.inner.current()
    }

    /// Returns a verification that is valid now, verifying first only if
    /// the current one has expired or was discarded. `Ok` means that
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
    ///   [`is_timeout`](Error::is_timeout) is `true`. It ends this call's
    ///   wait; a verification that other callers also wait for goes on
    ///   for them.
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
    /// they started on.
    ///
    /// On failure the error is returned, and what happens to the previous
    /// verification depends on its kind:
    ///
    /// - [`ErrorKind::Attestation`]: the previous verification is
    ///   discarded, even if it is still fresh, and its idle connections are
    ///   closed. No request that starts afterwards is sent under it: the
    ///   next request, or [`ensure_verified`](Self::ensure_verified),
    ///   verifies the enclave again, and fails without sending anything if
    ///   that verification fails too. Requests in flight finish.
    /// - [`ErrorKind::Network`], including a deadline from the `timeout`
    ///   option, or [`ErrorKind::Configuration`]: the previous verification
    ///   stays in place, and stays valid until it expires or is discarded.
    ///
    /// The errors are those of [`ensure_verified`](Self::ensure_verified),
    /// and so is the cancel safety: dropping `reverify`, or its deadline
    /// from the `timeout` option, ends only this call's wait. A
    /// verification that other callers still wait for goes on, and if it
    /// fails with an attestation error, it discards the previous
    /// verification as above. A verification that every caller dropped
    /// leaves the previous verification in place.
    ///
    /// [`ErrorKind::Attestation`]: crate::ErrorKind::Attestation
    /// [`ErrorKind::Network`]: crate::ErrorKind::Network
    /// [`ErrorKind::Configuration`]: crate::ErrorKind::Configuration
    pub async fn reverify(&self) -> Result<Arc<Verification>, Error> {
        self.inner.reverify().await
    }
}

http_request_methods!(EnclaveHttpClient);

impl EnclaveHttpClient {
    /// The attested client that requests go through.
    pub(crate) fn attested(&self) -> &Arc<AttestedClient> {
        &self.inner
    }
}

impl fmt::Debug for EnclaveHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnclaveHttpClient")
            .field("enclave", &self.enclave())
            .field("trust", &self.trust())
            .field("base_url", &self.base_url().as_str())
            .field("transport", &self.inner.transport_mode())
            .finish_non_exhaustive()
    }
}

/// Configures an [`EnclaveHttpClient`] and connects it.
///
/// An option is unset until its setter is called; no value stands for
/// "unset". The setters check nothing: [`connect`](Self::connect) checks
/// every option before any network I/O.
///
/// The `Debug` output does not show the proxy URL, which has not been
/// checked for credentials yet.
#[derive(Clone, Debug)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct EnclaveHttpClientBuilder {
    host: String,
    trust: Trust,
    options: RouteOptions,
}

impl EnclaveHttpClientBuilder {
    /// How the client protects its traffic, and whether it goes through a
    /// proxy. Unset, it is [`Transport::Tls`]. See [`Transport::Ehbp`] for
    /// the rules of a proxy URL.
    pub fn transport(mut self, transport: Transport) -> Self {
        self.options.transport = transport;
        self
    }

    /// The verification policy that applies on top of the trust argument.
    /// Unset, it is [`Policy::default()`], which keeps every default. The
    /// client builds its verifier from the trust argument and the policy.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.options.common.policy = policy;
        self
    }

    /// A veto over each verification that passed the trust argument and the
    /// policy, called
    /// before the client uses the enclave's keys: when the client connects
    /// and whenever it verifies again.
    ///
    /// Return an error to reject the enclave. The verification then fails
    /// with an attestation error that has the returned error as its
    /// source, and it is not tried again. Requests wait while the check
    /// runs, so it should be fast, and it may be called from several
    /// threads at once.
    ///
    /// A check that panics rejects the enclave in the same way: the panic
    /// is caught, and the verification fails with an attestation error
    /// for every caller that waited for it. The client stays usable, and
    /// the next verification calls the check again, with whatever state
    /// the panic left in what the check captured. (A program built with
    /// `panic = "abort"` aborts instead.)
    pub fn verification_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.options.common.verification_check = Some(Arc::new(check));
        self
    }

    /// A deadline for each operation of the client: [`connect`], each
    /// [`ensure_verified`] and [`reverify`], and each request, from the
    /// call until the response body has been read. A request's own
    /// [`timeout`] replaces it for that request.
    ///
    /// For a request the deadline is one instant. It includes the wait for
    /// a verification that the request needs, also one that another
    /// request started, and a replay. A response that is read as a stream
    /// must be read to its end before the deadline: a read after it fails,
    /// whether or not data is still arriving.
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

    /// How the client obtains attestation documents, in place of fetching
    /// them directly from the enclave: an [`AttestationRelay`], or any
    /// [`AttestationFetcher`], such as an async closure. It is used for
    /// every verification: when the client connects, and whenever it
    /// verifies again after an expiry or a key rotation. Whatever it returns is verified as a
    /// directly fetched document is.
    ///
    /// [`AttestationRelay`]: crate::AttestationRelay
    /// [`AttestationFetcher`]: crate::AttestationFetcher
    pub fn fetch_attestation(mut self, fetcher: impl AttestationFetcher) -> Self {
        self.options.common.attestation_fetcher = Some(Arc::new(fetcher));
        self
    }

    /// Checks the options, verifies the enclave and returns the client.
    ///
    /// Before any network I/O, in this order, each a configuration error:
    ///
    /// 1. `host` is empty.
    /// 2. The proxy URL of [`Transport::Ehbp`] is empty, is not an absolute
    ///    `http` or `https` URL, or carries a user name or password (this
    ///    error does not repeat the URL), a query string or a fragment; or
    ///    it uses `http://` for a host other than `localhost` or a loopback
    ///    IP address.
    /// 3. `timeout` is zero.
    /// 4. The trust argument lacks a field that its variant requires: an
    ///    empty repository or project, in either part of
    ///    [`Trust::EitherPin`] too, or registry IDs of
    ///    [`Trust::ProjectPin`] that are an empty list.
    /// 5. The verifier cannot be built from the trust argument and the
    ///    policy: a value that the verifier refuses, such as empty signing
    ///    keys, a malformed registry ID or embedded config, or a freshness
    ///    bound out of range. The verifier's usage error is the source.
    /// 6. `host` is not a host with an optional port; a part of the pin
    ///    that the trust argument sets is `Some("")`, or is not a
    ///    reference, or the verifier cannot verify against it.
    /// 7. The proxy URL is on the enclave's own origin, which is no proxy:
    ///    leave it unset to connect directly.
    ///
    /// Then the enclave is verified, as
    /// [`ensure_verified`](EnclaveHttpClient::ensure_verified) describes,
    /// with its errors. The transport is the option and nothing else: an
    /// enclave whose attestation endorses no key for it fails the
    /// verification with an attestation error; the client does not fall
    /// back to the other transport.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future stops the verification and closes its
    /// connection. No client exists and nothing is left behind.
    pub async fn connect(self) -> Result<EnclaveHttpClient, Error> {
        let fetch = fetchers::attestation_fetch(self.options.common.attestation_fetcher.clone());
        let (checked, settings, trust) = self.prepare()?;
        let inner = AttestedClient::connect(checked, settings, system_clock(), fetch).await?;
        Ok(EnclaveHttpClient {
            inner: Arc::new(inner),
            trust: Arc::new(trust),
        })
    }

    /// Checks the options, in the order that `connect` documents, and
    /// returns what a client is made from, and the trust argument. It does
    /// no I/O. The verifier is built from the trust argument and the
    /// policy; the host and the pin are checked by
    /// [`enclave::Config::check`].
    pub(crate) fn prepare(self) -> Result<(enclave::Checked, Settings, Trust), Error> {
        if self.host.is_empty() {
            return Err(Error::configuration("an enclave host is required"));
        }
        let base_url = self.options.checked_proxy_url()?;
        self.options.common.check()?;
        let mode = self.options.mode();
        let common = self.options.common;
        let (config, pin) = self.trust.verifier_inputs()?;
        let verifier = Verifier::new(config, common.policy).map_err(enclave::from_verifier)?;
        let checked = enclave::Config {
            host: self.host,
            pin,
            verifier: Some(Arc::new(verifier)),
            verification_check: common.verification_check,
        }
        .check()?;
        if let Some(proxy_url) = &base_url {
            base_url::refuse_enclave_origin(proxy_url, checked.host())?;
        }
        Ok((
            checked,
            Settings {
                mode,
                base_url,
                // An enclave client adds no cache secret.
                secret: None,
                timeout: common.timeout,
            },
            self.trust,
        ))
    }
}
