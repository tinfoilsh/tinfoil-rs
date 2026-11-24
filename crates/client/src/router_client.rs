//! The client for Tinfoil's router, which it discovers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::fetchers::{self, AttestationFetcher, RouterListFetcher};
use crate::internal::attested::{AttestedClient, Settings, mode_for};
use crate::internal::enclave::{self, Enclave};
use crate::internal::{cachesecret, router, system_clock};
use crate::options::{RouteOptions, Secret, Transport};
use crate::request::http_request_methods;
use crate::verifier::{BoxError, ConfigTrust, Policy, VerificationReport, VerifiedFacts, Verifier};

/// An HTTP client whose requests reach only the attested router that it
/// discovered.
///
/// Tinfoil's router serves the inference API for every model. The client
/// finds one when it is created: it tries the routers of Tinfoil's
/// published list in a random order, takes the first that passes
/// verification, and otherwise
/// `inference.tinfoil.sh`. From then on it behaves as an
/// [`EnclaveHttpClient`](crate::EnclaveHttpClient) for that router: it
/// verifies the same router again when the verification expires or the
/// router stops holding the attested keys, and refuses a request to any
/// other origin. It does not discover again; a new client does.
///
/// The client is a cheap-to-clone handle, `Send` and `Sync`, with nothing
/// to close.
#[derive(Clone)]
pub struct RouterHttpClient {
    pub(crate) inner: Arc<AttestedClient>,
}

impl RouterHttpClient {
    /// Discovers and verifies a router, and returns a client for it, with
    /// the default options. See [`RouterHttpClientBuilder::connect`].
    pub async fn connect() -> Result<Self, Error> {
        Self::builder().connect().await
    }

    /// Starts a router client to be configured before it connects.
    pub fn builder() -> RouterHttpClientBuilder {
        RouterHttpClientBuilder {
            options: RouteOptions::default(),
            router_list_fetcher: None,
        }
    }

    /// Where requests are sent: the proxy URL of [`Transport::Ehbp`], or
    /// else the
    /// router's own origin, `https://<router>/`. The path ends in `/`.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// The host of the router that the client discovered and verifies. It
    /// stays the router's host when requests go through a proxy.
    pub fn enclave(&self) -> &str {
        self.inner.enclave()
    }

    /// The outcome of the most recent attempt to verify the router that the
    /// client chose, without I/O: the attempt's report if it passed, and
    /// otherwise the error that the client reported for it. It describes
    /// the chosen router only; the attempts that discovery made on other
    /// routers are told only to the `on_verification_attempt` observer,
    /// which is not told of a host that discovery refused, never reached or
    /// abandoned at its deadline. See
    /// [`EnclaveHttpClient::last_verification_attempt`](crate::EnclaveHttpClient::last_verification_attempt).
    pub fn last_verification_attempt(&self) -> Result<VerificationReport, Error> {
        self.inner.last_verification_attempt()
    }

    /// The report of the verification of the chosen router that the
    /// client's requests are bound to now, without I/O, or `None` when
    /// there is none: once it has expired or a failure has discarded it.
    /// See
    /// [`EnclaveHttpClient::current_verification`](crate::EnclaveHttpClient::current_verification).
    pub fn current_verification(&self) -> Option<VerificationReport> {
        self.inner.current_verification()
    }

    /// Returns the report of a verification of the router that is valid
    /// now, verifying first only if the current one has expired or was
    /// discarded. The behaviour, the errors and the cancel safety are those
    /// of
    /// [`EnclaveHttpClient::ensure_verified`](crate::EnclaveHttpClient::ensure_verified).
    pub async fn ensure_verified(&self) -> Result<VerificationReport, Error> {
        self.inner.ensure_verified().await
    }

    /// Verifies the router again even if the current verification is still
    /// valid. It verifies the same router host and does not run discovery
    /// again. The behaviour, the errors and the cancel safety are those of
    /// [`EnclaveHttpClient::reverify`](crate::EnclaveHttpClient::reverify):
    /// a failure with an attestation error discards the previous
    /// verification, so that the next request verifies the router again; a
    /// failure with a network or a configuration error leaves it in place.
    /// A dropped `reverify` ends only its own wait.
    pub async fn reverify(&self) -> Result<VerificationReport, Error> {
        self.inner.reverify().await
    }
}

http_request_methods!(RouterHttpClient);

impl RouterHttpClient {
    /// The attested client that requests go through.
    pub(crate) fn attested(&self) -> &Arc<AttestedClient> {
        &self.inner
    }
}

impl fmt::Debug for RouterHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterHttpClient")
            .field("enclave", &self.enclave())
            .field("base_url", &self.base_url().as_str())
            .field("transport", &self.inner.transport_mode())
            .finish_non_exhaustive()
    }
}

/// Configures a [`RouterHttpClient`] and connects it.
///
/// An option is unset until its setter is called. The setters check
/// nothing: [`connect`](Self::connect) checks every option before any
/// network I/O. The `Debug` output shows neither the user cache secret nor
/// the unchecked proxy URL.
#[derive(Clone)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct RouterHttpClientBuilder {
    options: RouteOptions,
    router_list_fetcher: Option<Arc<dyn RouterListFetcher>>,
}

impl fmt::Debug for RouterHttpClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterHttpClientBuilder")
            .field("options", &self.options)
            .field("router_list_fetcher", &self.router_list_fetcher.is_some())
            .finish()
    }
}

impl RouterHttpClientBuilder {
    /// How the client protects its traffic, and whether it goes through a
    /// proxy. Unset, it is [`Transport::Tls`].
    ///
    /// A proxy URL of [`Transport::Ehbp`] forwards requests to the router
    /// that discovery chooses, which the `X-Tinfoil-Enclave-Url` header
    /// names to it. The rules for the URL are those of
    /// [`Transport::Ehbp`].
    pub fn transport(mut self, transport: Transport) -> Self {
        self.options.transport = transport;
        self
    }

    /// The verification policy that applies on top of the router's fixed
    /// trust. Unset, it is [`Policy::default()`], which keeps every
    /// default.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.options.common.policy = policy;
        self
    }

    /// A veto over each verification that passed the policy: for each
    /// router that discovery tries, and whenever the client verifies its
    /// router again.
    ///
    /// Return an error to reject the router. During discovery the client
    /// then moves on to the next router. Afterwards the verification fails
    /// with an attestation error that has the returned error as its
    /// source, and it is not tried again. Requests wait while the check
    /// runs, and it may be called from several threads at once.
    ///
    /// A check that panics rejects the router in the same way: the panic
    /// is caught, and the verification fails with an attestation error
    /// for every caller that waited for it. The client stays usable, and
    /// the next verification calls the check again, with whatever state
    /// the panic left in what the check captured. (A program built with
    /// `panic = "abort"` aborts instead.)
    pub fn verification_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&VerifiedFacts) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.options.common.verification_check = Some(Arc::new(check));
        self
    }

    /// An observer of each attempt to verify a router, called once for
    /// every attempt after its outcome is decided, with the host of the
    /// router that the attempt verified: each router that discovery tries,
    /// the fallback router included, and the chosen router whenever the
    /// client verifies it again. Otherwise as
    /// [`EnclaveHttpClientBuilder::on_verification_attempt`](crate::EnclaveHttpClientBuilder::on_verification_attempt).
    /// A probe that discovery abandons when its 30 seconds run out has no
    /// outcome and is not told.
    pub fn on_verification_attempt<F>(mut self, observer: F) -> Self
    where
        F: Fn(&str, Result<&VerificationReport, &Error>) + Send + Sync + 'static,
    {
        self.options.common.on_verification_attempt = Some(Arc::new(observer));
        self
    }

    /// The default prompt-cache scope for the client's requests: the
    /// client adds it as `user_cache_secret` to the JSON body of chat
    /// completion, completion and response requests. A non-empty
    /// `user_cache_secret` string that a request's body already carries
    /// wins over it. Use an opaque random value, not a user ID or an API
    /// key.
    ///
    /// Unset, the client uses a random secret that is generated in memory
    /// once per process and that every router client in the process
    /// shares; requests from different processes therefore share no
    /// prompt cache. The client never reads the secret from the
    /// environment or from a file: to keep a secret that stays the same
    /// across processes or machines, generate and store it in the
    /// application, and pass it here.
    pub fn user_cache_secret(mut self, secret: impl Into<String>) -> Self {
        self.options.common.user_cache_secret = Some(Secret::new(secret));
        self
    }

    /// A deadline for each operation of the client: [`connect`], each
    /// `ensure_verified` and `reverify`, and each request, from the call
    /// until the response body has been read. A request's own timeout
    /// replaces it for that request. Unset, there is no deadline other
    /// than the client's fixed bounds: 30 seconds for discovery and 30
    /// seconds for each fetch of attestation material.
    ///
    /// [`connect`]: Self::connect
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.common.timeout = Some(timeout);
        self
    }

    /// How the client obtains attestation documents, in place of fetching
    /// them directly from the enclave: an [`AttestationRelay`], or any
    /// [`AttestationFetcher`], such as an async closure. It is used for
    /// every verification: for each router that discovery tries, for the
    /// fallback router, and whenever the client verifies its router again. Whatever it returns is verified as a
    /// directly fetched document is.
    ///
    /// [`AttestationRelay`]: crate::AttestationRelay
    /// [`AttestationFetcher`]: crate::AttestationFetcher
    pub fn fetch_attestation(mut self, fetcher: impl AttestationFetcher) -> Self {
        self.options.common.attestation_fetcher = Some(Arc::new(fetcher));
        self
    }

    /// How the client obtains its candidate routers, in place of fetching
    /// Tinfoil's list from `https://atc.tinfoil.sh/routers`: a
    /// [`RouterListRelay`], or any [`RouterListFetcher`], such as an async
    /// closure. Discovery still runs: the list only proposes routers, each
    /// of which is verified before it is used, and an error counts as an
    /// empty list, after which the client falls back to
    /// `inference.tinfoil.sh`. See [`RouterListFetcher`] for what the list
    /// source is trusted with.
    ///
    /// [`RouterListRelay`]: crate::RouterListRelay
    /// [`RouterListFetcher`]: crate::RouterListFetcher
    pub fn fetch_router_list(mut self, fetcher: impl RouterListFetcher) -> Self {
        self.router_list_fetcher = Some(Arc::new(fetcher));
        self
    }

    /// Checks the options, discovers and verifies a router, and returns
    /// the client.
    ///
    /// Before any network I/O, in this order, each a configuration error:
    ///
    /// 1. The proxy URL of [`Transport::Ehbp`] is invalid, by the rules of
    ///    [`EnclaveHttpClientBuilder::connect`](crate::EnclaveHttpClientBuilder::connect).
    /// 2. `user_cache_secret` is empty, or `timeout` is zero.
    /// 3. The verifier cannot be built from the policy. The verifier's
    ///    usage error is the source.
    ///
    /// Then discovery runs, for at most 30 seconds in all. The router list
    /// is fetched; a list that cannot be fetched or read counts as empty.
    /// Its routers are tried one at a time, in a random order, each
    /// with a single verification, and the first that passes,
    /// `verification_check` included, becomes the client's router. A
    /// router that fails, for whatever reason, is skipped. When none
    /// passes, or the 30 seconds run out, the client verifies
    /// `inference.tinfoil.sh`, and a failure of that verification is the
    /// error returned, as
    /// [`ensure_verified`](RouterHttpClient::ensure_verified) reports it.
    ///
    /// The client keeps the router that it chose: it verifies that router
    /// again when it must, and never discovers another. Every `connect`
    /// discovers anew. The `timeout` option bounds the whole call.
    ///
    /// The user cache secret is resolved last, once the client is certain
    /// to be created; resolving it does no I/O. Without a non-empty
    /// `user_cache_secret` option, the client uses the secret that is
    /// generated once per process; when the operating system's random
    /// number generator fails to supply it, the error is of
    /// [`ErrorKind::Random`](crate::ErrorKind::Random), and its source is
    /// the generator's `getrandom::Error`.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future stops discovery and closes its connections. No
    /// client exists.
    pub async fn connect(self) -> Result<RouterHttpClient, Error> {
        let fetch = fetchers::attestation_fetch(self.options.common.attestation_fetcher.clone());
        let list_fetcher = self.router_list_fetcher.clone();
        let (fallback, settings) = self.prepare()?;
        let mode = mode_for(settings.mode)?;
        // Every router is verified under the policy that was checked, and
        // against the router pin.
        let verifier = Arc::clone(fallback.verifier());
        let check = fallback.verification_check().cloned();
        let observer = fallback.on_verification_attempt().cloned();
        let enclave_for = move |host: &str| {
            let checked = enclave::Config {
                host: host.to_owned(),
                pin: router::router_pin(),
                verifier: Some(Arc::clone(&verifier)),
                verification_check: check.clone(),
                on_verification_attempt: observer.clone(),
            }
            .check()?;
            Ok(Enclave::from_checked(
                checked,
                system_clock(),
                Arc::clone(&fetch),
            ))
        };
        let list = async move {
            match list_fetcher {
                Some(fetcher) => fetchers::router_list(fetcher).await,
                None => router::router_list().await,
            }
        };
        let inner =
            router::connect(list, enclave_for, mode, settings, cachesecret::resolve).await?;
        Ok(RouterHttpClient {
            inner: Arc::new(inner),
        })
    }

    /// Checks the options, in the order that `connect` documents, and
    /// returns the checked description of the fallback router, which holds
    /// the verifier for every router, and what the client is made from. It
    /// does no I/O.
    pub(crate) fn prepare(self) -> Result<(enclave::Checked, Settings), Error> {
        let base_url = self.options.checked_proxy_url()?;
        let mode = self.options.mode();
        self.options.common.check()?;
        let common = self.options.common;
        let verifier = Verifier::new(ConfigTrust::PublicRegistry, common.policy)
            .map_err(enclave::from_verifier)?;
        let fallback = enclave::Config {
            host: router::FALLBACK_ROUTER.to_owned(),
            pin: router::router_pin(),
            verifier: Some(Arc::new(verifier)),
            verification_check: common.verification_check,
            on_verification_attempt: common.on_verification_attempt,
        }
        .check()?;
        Ok((
            fallback,
            Settings {
                mode,
                base_url,
                secret: common.user_cache_secret,
                timeout: common.timeout,
            },
        ))
    }
}
