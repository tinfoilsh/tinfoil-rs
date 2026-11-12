//! The client for Tinfoil's router, which it discovers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::internal::attested::{AttestedClient, Settings, mode_for};
use crate::internal::enclave::{self, Enclave};
use crate::internal::{cachesecret, router, system_clock};
use crate::options::{RouteOptions, Secret, TransportMode};
use crate::request::http_request_methods;
use crate::verifier::{BoxError, Verification, Verifier};

/// An HTTP client whose requests reach only the attested router that it
/// discovered.
///
/// Tinfoil's router serves the inference API for every model. The client
/// finds one when it is created: it takes the first router of Tinfoil's
/// published list that passes verification, and otherwise
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
        }
    }

    /// Where requests are sent: the `base_url` option, or else the
    /// router's own origin, `https://<router>/`. The path ends in `/`.
    pub fn base_url(&self) -> &Url {
        self.inner.base_url()
    }

    /// The host of the router that the client discovered and verifies. It
    /// stays the router's host when `base_url` is a proxy.
    pub fn enclave(&self) -> &str {
        self.inner.enclave()
    }

    /// The repository that the router is verified against. A router is
    /// always pinned to Tinfoil's router repository.
    pub fn repo(&self) -> &str {
        self.inner
            .repo()
            .unwrap_or(crate::internal::router::ROUTER_REPO)
    }

    /// The transport mode that the client was created with.
    pub fn transport_mode(&self) -> TransportMode {
        self.inner.transport_mode()
    }

    /// The last successful verification of the router, without checking
    /// it: it may have expired or been rejected since.
    pub fn current(&self) -> Arc<Verification> {
        self.inner.current()
    }

    /// Returns a verification of the router that is valid now, verifying
    /// first only if the current one has expired or was rejected. The
    /// behaviour, the errors and the cancel safety are those of
    /// [`EnclaveHttpClient::ensure_verified`](crate::EnclaveHttpClient::ensure_verified).
    pub async fn ensure_verified(&self) -> Result<Arc<Verification>, Error> {
        self.inner.ensure_verified().await
    }

    /// Verifies the router again even if the current verification is still
    /// valid. The behaviour, the errors and the cancel safety are those of
    /// [`EnclaveHttpClient::reverify`](crate::EnclaveHttpClient::reverify):
    /// a dropped or failed `reverify` leaves the previous binding in place.
    pub async fn reverify(&self) -> Result<Arc<Verification>, Error> {
        self.inner.reverify().await
    }
}

http_request_methods!(RouterHttpClient);

impl fmt::Debug for RouterHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterHttpClient")
            .field("enclave", &self.enclave())
            .field("repo", &self.repo())
            .field("base_url", &self.base_url().as_str())
            .field("transport_mode", &self.transport_mode())
            .finish_non_exhaustive()
    }
}

/// Configures a [`RouterHttpClient`] and connects it.
///
/// An option is unset until its setter is called. The setters check
/// nothing: [`connect`](Self::connect) checks every option before any
/// network I/O. The `Debug` output shows neither the user cache secret nor
/// the unchecked base URL.
#[derive(Clone, Debug)]
#[must_use = "a builder does nothing until `connect` is called"]
pub struct RouterHttpClientBuilder {
    options: RouteOptions,
}

impl RouterHttpClientBuilder {
    /// How the client protects its traffic. Unset, it is
    /// [`TransportMode::Tls`].
    pub fn transport_mode(mut self, mode: TransportMode) -> Self {
        self.options.transport_mode = Some(mode);
        self
    }

    /// A proxy that forwards requests to the router that discovery
    /// chooses. It requires [`TransportMode::Ehbp`]: the router is not
    /// known before discovery, so a base URL cannot name its origin.
    ///
    /// Requests carry the `X-Tinfoil-Enclave-Url` header so that the proxy
    /// can forward them, and the proxy sees the method, the URL and the
    /// headers of every request. The rules for the URL are those of
    /// [`EnclaveHttpClientBuilder::base_url`](crate::EnclaveHttpClientBuilder::base_url).
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.options.base_url = Some(url.into());
        self
    }

    /// The verification policy for the router. Unset, it is
    /// `Verifier::new()`. A verifier that supplies or authorizes the
    /// config itself is refused: it needs an explicit enclave.
    pub fn verifier(mut self, verifier: impl Into<Arc<Verifier>>) -> Self {
        self.options.common.verifier = Some(verifier.into());
        self
    }

    /// A veto over each verification that passed the verifier: for each
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
        F: Fn(&Verification) -> Result<(), BoxError> + Send + Sync + 'static,
    {
        self.options.common.verification_check = Some(Arc::new(check));
        self
    }

    /// The default prompt-cache scope for the client's requests: the
    /// client adds it as `user_cache_secret` to the JSON body of chat
    /// completion, completion and response requests. A non-empty
    /// `user_cache_secret` string that a request's body already carries
    /// wins over it. Use an opaque random value, not a user ID or an API
    /// key.
    ///
    /// Unset, the client takes the secret from the
    /// `TINFOIL_USER_CACHE_SECRET` environment variable, and otherwise
    /// from the file `~/.tinfoil/user_cache_secret`, which it creates with
    /// a random secret on first use (mode `0600`, in a directory of mode
    /// `0700`) and which the other Tinfoil SDKs on the machine share. This
    /// is the only place where a client reads the environment or the file
    /// system.
    ///
    /// A stored secret is used only if the file system shows that it is
    /// the user's own. The file or its directory is left untouched and
    /// not used when it is a symbolic link or not a regular file or
    /// directory, when the file is larger than 4 KiB or holds no secret,
    /// and, on Unix, when either belongs to another user or grants any
    /// access to the group or to others. The client then uses a random
    /// secret that lasts for the process, so its requests are still
    /// scoped, but share no cache with other processes; `connect` does
    /// not fail. Restore the modes `0700` and `0600`, or remove the file,
    /// to get a stored secret again.
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

    /// Checks the options, discovers and verifies a router, and returns
    /// the client.
    ///
    /// Before any network I/O, in this order, each a configuration error:
    ///
    /// 1. `base_url` is invalid, by the rules of
    ///    [`EnclaveHttpClientBuilder::connect`](crate::EnclaveHttpClientBuilder::connect).
    /// 2. `base_url` is set and the mode is [`TransportMode::Tls`].
    /// 3. `user_cache_secret` is empty, or `timeout` is zero.
    /// 4. The verifier supplies or authorizes the config itself
    ///    (`Verifier::caller_authorizes_config`).
    ///
    /// Then discovery runs, for at most 30 seconds in all. The router list
    /// is fetched; a list that cannot be fetched or read counts as empty.
    /// Its routers are tried one at a time, in the order of the list, each
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
    /// to be created; resolving it never fails. Unless the option or the
    /// environment supplies the secret, this reads or creates one small
    /// file in the home directory, synchronously.
    ///
    /// # Cancel safety
    ///
    /// Dropping the future stops discovery and closes its connections. No
    /// client exists. The cache secret file, if this call created it,
    /// stays.
    pub async fn connect(self) -> Result<RouterHttpClient, Error> {
        let (fallback, settings) = self.prepare()?;
        let mode = mode_for(settings.mode)?;
        // Every router is verified under the policy that was checked, and
        // against the router repository.
        let verifier = Arc::clone(fallback.verifier());
        let check = fallback.verification_check().cloned();
        let enclave_for = move |host: &str| {
            let checked = enclave::Config {
                host: host.to_owned(),
                repo: Some(router::ROUTER_REPO.to_owned()),
                verifier: Some(Arc::clone(&verifier)),
                verification_check: check.clone(),
            }
            .check()?;
            Ok(Enclave::from_checked(
                checked,
                system_clock(),
                enclave::network_fetch(),
            ))
        };
        let inner = router::connect(
            router::router_list(),
            enclave_for,
            mode,
            settings,
            cachesecret::resolve,
        )
        .await?;
        Ok(RouterHttpClient {
            inner: Arc::new(inner),
        })
    }

    /// Checks the options, in the order that `connect` documents, and
    /// returns the checked description of the fallback router, which holds
    /// the verifier for every router, and what the client is made from. It
    /// does no I/O.
    pub(crate) fn prepare(self) -> Result<(enclave::Checked, Settings), Error> {
        let base_url = self.options.checked_base_url()?;
        let mode = self.options.mode();
        if base_url.is_some() && mode == TransportMode::Tls {
            return Err(Error::configuration(
                "a base URL is a proxy when the router is discovered, which requires TransportMode::Ehbp",
            ));
        }
        self.options.common.check()?;
        let common = self.options.common;
        if common
            .verifier
            .as_ref()
            .is_some_and(|verifier| verifier.caller_authorizes_config())
        {
            return Err(Error::configuration(
                "a verifier that supplies or authorizes the config requires an explicit enclave",
            ));
        }
        let fallback = enclave::Config {
            host: router::FALLBACK_ROUTER.to_owned(),
            repo: Some(router::ROUTER_REPO.to_owned()),
            verifier: common.verifier,
            verification_check: common.verification_check,
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
