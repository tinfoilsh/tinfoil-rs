//! What the enclave and router clients share: the verified enclave and the
//! chain that their requests go through.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, Request, Url};
use tokio::time::Instant;

use crate::error::Error;
use crate::internal::body::{self, DEADLINE_PASSED};
use crate::internal::enclave::{Checked, Enclave, Evidence, Fetch};
use crate::internal::transport::base_url::{self, authority_url};
use crate::internal::transport::cachesecret::with_cache_secret;
use crate::internal::transport::ehbp::EhbpMode;
use crate::internal::transport::header::with_enclave_url;
use crate::internal::transport::origin::with_origin_restriction;
use crate::internal::transport::replay::with_replay;
use crate::internal::transport::tls::TlsMode;
use crate::internal::transport::{Mode, RoundTrip, Transport};
use crate::internal::{Clock, fetch};
use crate::options::{Secret, TransportMode};
use crate::request::{Execute, ResponseFuture};
use crate::verifier::Verification;

#[cfg(test)]
#[path = "attested_tests.rs"]
mod tests;

/// The state behind an `EnclaveHttpClient` or a `RouterHttpClient`.
///
/// The clients hold verifications of the type [`Verification`]. The type
/// parameter exists so that the tests can run the whole client on evidence
/// that they can build.
pub(crate) struct AttestedClient<V = Verification> {
    /// The verified enclave and the transport bound to its keys.
    transport: Transport<V>,
    /// The request chain, from the origin restriction inward.
    chain: Arc<dyn RoundTrip>,
    /// Collects the parts of a request; it never sends.
    parts: reqwest::Client,
    mode: TransportMode,
    /// Where requests go: the `base_url` option, or the enclave's origin
    /// with the path `/`.
    base_url: Url,
    /// Where an OpenAI client sends: the `base_url` option, or the
    /// enclave's origin with the path `/v1/`.
    openai_url: Url,
    /// The `timeout` option.
    timeout: Option<Duration>,
}

/// What a client is assembled from, once the options have passed their
/// checks.
pub(crate) struct Settings {
    pub(crate) mode: TransportMode,
    /// The `base_url` option, checked ([`base_url::validate`]).
    pub(crate) base_url: Option<Url>,
    pub(crate) secret: Option<Secret>,
    pub(crate) timeout: Option<Duration>,
}

impl AttestedClient<Verification> {
    /// Verifies the enclave of `checked` and returns the client for it:
    /// the transport in the mode of `settings`, with the verification's
    /// one retry, within the `timeout` of `settings`.
    ///
    /// The mode is the option alone. A verification never changes it: a
    /// document that endorses no key for the mode is an attestation error.
    ///
    /// Dropping the future abandons the verification and keeps nothing.
    pub(crate) async fn connect(
        checked: Checked,
        settings: Settings,
        clock: Clock,
        fetch: Fetch,
    ) -> Result<Self, Error> {
        let mode: Arc<dyn Mode<Verification>> = match settings.mode {
            TransportMode::Tls => Arc::new(TlsMode::new()),
            TransportMode::Ehbp => Arc::new(EhbpMode::new()?),
        };
        let enclave = Enclave::from_checked(checked, clock, fetch);
        let transport = within(settings.timeout, Transport::connect(enclave, mode, true)).await?;
        Self::new(transport, settings)
    }
}

impl<V: Evidence> AttestedClient<V> {
    /// Assembles a client around a transport that already holds a
    /// verification. In order, each a configuration error:
    ///
    /// 1. in the TLS mode, a base URL off the enclave's origin;
    /// 2. an enclave host that yields no origin.
    ///
    /// The chain is, from the caller inward: origin restriction, cache
    /// secret, one replay after a key rejection, the enclave header for a
    /// proxy, the transport.
    pub(crate) fn new(transport: Transport<V>, settings: Settings) -> Result<Self, Error> {
        let Settings {
            mode,
            base_url,
            secret,
            timeout,
        } = settings;
        let host = transport.enclave().host().to_owned();
        if let (TransportMode::Tls, Some(base_url)) = (mode, &base_url) {
            base_url::validate_for_tls(base_url, &host)?;
        }
        let origin = authority_url(&host)?;

        let chain: Arc<dyn RoundTrip> = Arc::new(transport.clone());
        let chain = with_enclave_url(chain, &host, base_url.as_ref())?;
        let chain = with_replay(chain);
        let chain = with_cache_secret(chain, secret);
        let chain = with_origin_restriction(chain, Some(&host), base_url.as_ref())?;

        let openai_url = match &base_url {
            Some(base_url) => base_url.clone(),
            None => origin
                .join("v1/")
                .map_err(|_| Error::configuration("the enclave host yields no URL"))?,
        };
        let parts = fetch::tls_builder()?
            .build()
            .map_err(|error| Error::wrap(crate::ErrorKind::Configuration, error))?;
        Ok(Self {
            transport,
            chain,
            parts,
            mode,
            base_url: base_url.unwrap_or(origin),
            openai_url,
            timeout,
        })
    }

    pub(crate) fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub(crate) fn openai_url(&self) -> &Url {
        &self.openai_url
    }

    pub(crate) fn enclave(&self) -> &str {
        self.transport.enclave().host()
    }

    pub(crate) fn repo(&self) -> Option<&str> {
        self.transport.enclave().repo()
    }

    pub(crate) fn transport_mode(&self) -> TransportMode {
        self.mode
    }

    pub(crate) fn current(&self) -> Arc<V> {
        self.transport.current()
    }

    /// As [`Transport::ensure_verified`], within the `timeout` option.
    ///
    /// The deadline ends this caller's wait, also for a verification that
    /// another caller started. The verification itself goes on for the
    /// callers that still wait for it, and is dropped with the last one.
    pub(crate) async fn ensure_verified(&self) -> Result<Arc<V>, Error> {
        within(self.timeout, self.transport.ensure_verified()).await
    }

    /// As [`Transport::reverify`], within the `timeout` option, as
    /// [`ensure_verified`](Self::ensure_verified) applies it.
    pub(crate) async fn reverify(&self) -> Result<Arc<V>, Error> {
        within(self.timeout, self.transport.reverify()).await
    }
}

/// `operation`, ended with a network error that is marked as a timeout if
/// it has not finished after `timeout`. Without a timeout it runs as it
/// is. The operation is dropped when its time is up.
async fn within<T>(
    timeout: Option<Duration>,
    operation: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    match timeout {
        Some(timeout) => match tokio::time::timeout(timeout, operation).await {
            Ok(result) => result,
            Err(_) => Err(Error::deadline(DEADLINE_PASSED)),
        },
        None => operation.await,
    }
}

impl<V: Evidence> Execute for AttestedClient<V> {
    /// Sends `request` through the chain, within the request's own timeout
    /// or else the `timeout` option.
    ///
    /// The deadline is one instant, counted from the first poll of the
    /// returned future. It covers everything that the request waits for:
    /// a verification, the first attempt, a verification after a key
    /// rejection, the replay, and then the read of the response body,
    /// which fails once the instant has passed ([`body::guard`]). The
    /// layers below see a request without a timeout, so no attempt gets a
    /// deadline of its own.
    ///
    /// Whatever the outcome, the body of the response is guarded, so that
    /// a failed read carries a classified error.
    fn execute(&self, mut request: Request) -> ResponseFuture {
        let timeout = request.timeout_mut().take().or(self.timeout);
        let chain = Arc::clone(&self.chain);
        ResponseFuture::new(async move {
            // A timeout too long to add to the present is no deadline.
            let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
            let sent = chain.round_trip(request);
            let response = match deadline {
                Some(deadline) => match tokio::time::timeout_at(deadline, sent).await {
                    Ok(result) => result,
                    Err(_) => return Err(Error::deadline(DEADLINE_PASSED)),
                },
                None => sent.await,
            };
            let response = response.map_err(|failure| failure.error)?;
            Ok(body::guard(response, deadline))
        })
    }

    fn start(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.parts.request(method, url)
    }
}
