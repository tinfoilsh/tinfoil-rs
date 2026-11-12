//! What the enclave and router clients share: the verified enclave and the
//! chain that their requests go through.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, Request, Url};

use crate::error::Error;
use crate::internal::transport::{RoundTrip, Transport};
use crate::options::{Secret, TransportMode};
use crate::request::{Execute, ResponseFuture};
use crate::verifier::Verification;

/// The state behind an `EnclaveHttpClient` or a `RouterHttpClient`.
pub(crate) struct AttestedClient {
    /// The verified enclave and the transport bound to its keys.
    transport: Arc<Transport>,
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

impl AttestedClient {
    /// Assembles a client around a transport that already holds a
    /// verification. In order, each a configuration error:
    ///
    /// 1. in the TLS mode, a base URL off the enclave's origin;
    /// 2. an enclave host that yields no origin.
    ///
    /// The chain is, from the caller inward: origin restriction, cache
    /// secret, one replay after a key rejection, the enclave header for a
    /// proxy, the transport.
    pub(crate) fn new(
        transport: Transport,
        mode: TransportMode,
        base_url: Option<Url>,
        secret: Option<Secret>,
        timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        Err(Error::not_implemented("the attested client"))
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

    pub(crate) fn repo(&self) -> &str {
        self.transport.enclave().repo()
    }

    pub(crate) fn transport_mode(&self) -> TransportMode {
        self.mode
    }

    pub(crate) fn current(&self) -> Arc<Verification> {
        self.transport.current()
    }

    /// As [`Transport::ensure_verified`], within the `timeout` option.
    pub(crate) async fn ensure_verified(&self) -> Result<Arc<Verification>, Error> {
        self.transport.ensure_verified().await
    }

    /// As [`Transport::reverify`], within the `timeout` option.
    pub(crate) async fn reverify(&self) -> Result<Arc<Verification>, Error> {
        self.transport.reverify().await
    }
}

impl Execute for AttestedClient {
    /// Sends `request` through the chain, within the request's own timeout
    /// or else the `timeout` option.
    fn execute(&self, request: Request) -> ResponseFuture {
        ResponseFuture::new(self.chain.round_trip(request))
    }

    fn start(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.parts.request(method, url)
    }
}
