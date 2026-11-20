//! How a client obtains attestation documents and the router list: the
//! `fetch_attestation` and `fetch_router_list` options, and the relays that
//! implement the relay protocol for a URL.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use reqwest::Url;

use crate::error::{Error, ErrorKind};
use crate::internal::enclave::Fetch;
use crate::internal::transport::base_url::{self, authority_url};
use crate::internal::{fetch, router};
use crate::verifier::{BoxError, NONCE_SIZE};

/// The future that a fetcher returns.
pub type FetchFuture<T> = Pin<Box<dyn Future<Output = Result<T, BoxError>> + Send + 'static>>;

/// Obtains the attestation document of an enclave for a challenge nonce, in
/// place of the client's direct fetch from the enclave.
///
/// The client verifies whatever a fetcher returns as it verifies a document
/// that it fetched itself, so a fetcher is not trusted: it can make
/// verification fail, but it cannot make an enclave pass that would not
/// pass otherwise.
///
/// A client calls the fetcher for every verification: when it is created,
/// whenever it verifies again after an expiry or a key rotation, and, on
/// the router route, for each router that discovery tries and for the
/// fallback. `host` is the enclave's host, with an optional port, and
/// `nonce` is the fresh challenge that the document must answer. The
/// client drops the returned future after 30 seconds, which is a network
/// error that is marked as a timeout; it is not dropped when one caller
/// stops waiting, since one verification can serve many requests. The
/// fetcher may be called from several threads at once.
///
/// An error that the future returns is reported as a network error that has
/// it as its source, unless it is this crate's [`Error`], which keeps its
/// kind. A configuration error is not retried.
///
/// A closure `Fn(String, [u8; NONCE_SIZE]) -> F`, where `F` is a future
/// that returns `Result<Vec<u8>, BoxError>`, is a fetcher:
///
/// ```no_run
/// use tinfoil::{EnclaveHttpClient, Trust};
///
/// # async fn run() -> Result<(), tinfoil::Error> {
/// let client = EnclaveHttpClient::builder("enclave.example.com", Trust::repo("owner/name"))
///     .fetch_attestation(|host: String, nonce: [u8; 32]| async move {
///         // Obtain the document of `host` for `nonce`, by any means.
///         # let _ = (host, nonce);
///         Ok::<Vec<u8>, tinfoil::verifier::BoxError>(Vec::new())
///     })
///     .connect()
///     .await?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
pub trait AttestationFetcher: Send + Sync + 'static {
    /// Fetches the attestation document of `host` for `nonce`.
    fn fetch_attestation(&self, host: String, nonce: [u8; NONCE_SIZE]) -> FetchFuture<Vec<u8>>;
}

impl<F, Fut> AttestationFetcher for F
where
    F: Fn(String, [u8; NONCE_SIZE]) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<u8>, BoxError>> + Send + 'static,
{
    fn fetch_attestation(&self, host: String, nonce: [u8; NONCE_SIZE]) -> FetchFuture<Vec<u8>> {
        Box::pin(self(host, nonce))
    }
}

/// Obtains the candidate routers for router discovery, in place of the
/// client's fetch from `https://atc.tinfoil.sh/routers`.
///
/// The list is not trusted: it only proposes hosts, and discovery verifies
/// each one before it uses it, tries them for at most 30 seconds in all,
/// and falls back to `inference.tinfoil.sh` when none passes. An error
/// counts as an empty list.
///
/// An attestation document does not name the host that serves it, so the
/// list source is trusted not to name a host that would relay another
/// router's attestation: with [`Transport::Ehbp`](crate::Transport::Ehbp),
/// such a host would receive the request headers, an API key among them,
/// although not the sealed bodies.
///
/// A closure `Fn() -> F`, where `F` is a future that returns
/// `Result<Vec<String>, BoxError>`, is a fetcher.
pub trait RouterListFetcher: Send + Sync + 'static {
    /// Fetches the hosts of the candidate routers.
    fn fetch_router_list(&self) -> FetchFuture<Vec<String>>;
}

impl<F, Fut> RouterListFetcher for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<String>, BoxError>> + Send + 'static,
{
    fn fetch_router_list(&self) -> FetchFuture<Vec<String>> {
        Box::pin(self())
    }
}

/// An [`AttestationFetcher`] that fetches documents through a relay, such
/// as an endpoint on the application's own origin that forwards each
/// request to the enclave that it names. A client in a browser-like
/// environment, or one that should not reveal its IP address to enclaves,
/// then reaches only that origin.
///
/// It sends `GET <url>/.well-known/tinfoil-attestation?nonce=<nonce>&enclave=<host>`,
/// where `nonce` is the challenge in lowercase hex and `host` is encoded as
/// a query value, with the SDK identity headers that a direct fetch sends,
/// and takes the body of a `2xx` response as the document. It applies the
/// bounds of a direct fetch: 30 seconds, 32 MiB, and no redirect to a URL
/// that is not HTTPS. The relay is not trusted; see
/// [`AttestationFetcher`].
#[derive(Clone)]
pub struct AttestationRelay {
    url: Url,
}

impl AttestationRelay {
    /// A relay at `url`. Its path, if any, is where the relay is mounted:
    /// the request path joins under it, whether or not it ends in `/`.
    ///
    /// # Errors
    ///
    /// A configuration error for a URL that breaks the rules of a proxy URL
    /// (see [`Transport::Ehbp`](crate::Transport::Ehbp)): it must use
    /// HTTPS, or HTTP only to `localhost` or a loopback IP address, and it
    /// must not carry user information, a query or a fragment, even an
    /// empty one. The error does not repeat the URL.
    pub fn new(url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            url: base_url::validate_as(url.as_ref(), "attestation relay URL")?,
        })
    }

    /// The URL that the relay was built from, with its path ending in `/`.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Where the document of `host` for `nonce` is fetched.
    pub(crate) fn document_url(&self, host: &str, nonce: &[u8; NONCE_SIZE]) -> Result<Url, Error> {
        authority_url(host)?;
        let mut url = self.url.clone();
        let path = format!("{}{}", url.path(), RELAY_ATTESTATION_PATH);
        url.set_path(&path);
        let enclave: String = url::form_urlencoded::byte_serialize(host.as_bytes()).collect();
        url.set_query(Some(&format!(
            "nonce={}&enclave={enclave}",
            fetch::lower_hex(nonce)
        )));
        Ok(url)
    }
}

/// The attestation path under a relay URL, whose path ends in `/`.
const RELAY_ATTESTATION_PATH: &str = ".well-known/tinfoil-attestation";

impl AttestationFetcher for AttestationRelay {
    fn fetch_attestation(&self, host: String, nonce: [u8; NONCE_SIZE]) -> FetchFuture<Vec<u8>> {
        let target = self.document_url(&host, &nonce);
        Box::pin(async move { Ok(fetch::relayed(target?).await?) })
    }
}

impl fmt::Debug for AttestationRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationRelay")
            .field("url", &self.url.as_str())
            .finish()
    }
}

/// A [`RouterListFetcher`] that fetches the router list through a relay,
/// such as an endpoint on the application's own origin that forwards the
/// request to `https://atc.tinfoil.sh/routers`.
///
/// It sends `GET <url>/routers`, with the query parameters that a direct
/// fetch sends, of which this client sends none, and parses the response
/// as a direct fetch's: a JSON array of host strings of at most 32 MiB,
/// fetched with no redirect to a URL that is not HTTPS.
#[derive(Clone)]
pub struct RouterListRelay {
    url: Url,
}

impl RouterListRelay {
    /// A relay at `url`, under the rules of [`AttestationRelay::new`].
    ///
    /// # Errors
    ///
    /// As [`AttestationRelay::new`].
    pub fn new(url: impl AsRef<str>) -> Result<Self, Error> {
        Ok(Self {
            url: base_url::validate_as(url.as_ref(), "router list relay URL")?,
        })
    }

    /// The URL that the relay was built from, with its path ending in `/`.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Where the list is fetched.
    pub(crate) fn list_url(&self) -> Url {
        let mut url = self.url.clone();
        let path = format!("{}routers", url.path());
        url.set_path(&path);
        url
    }
}

impl RouterListFetcher for RouterListRelay {
    fn fetch_router_list(&self) -> FetchFuture<Vec<String>> {
        let target = self.list_url();
        Box::pin(async move { Ok(router::relayed_list(target).await?) })
    }
}

impl fmt::Debug for RouterListRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouterListRelay")
            .field("url", &self.url.as_str())
            .finish()
    }
}

/// The document fetch of a client: the caller's fetcher within the bound of
/// a direct fetch, with its errors in the client's categories, or the
/// direct fetch.
pub(crate) fn attestation_fetch(fetcher: Option<Arc<dyn AttestationFetcher>>) -> Fetch {
    let Some(fetcher) = fetcher else {
        return crate::internal::enclave::network_fetch();
    };
    Arc::new(move |host, nonce| {
        let fetched = fetcher.fetch_attestation(host, nonce);
        Box::pin(async move {
            match tokio::time::timeout(fetch::FETCH_TIMEOUT, fetched).await {
                Ok(result) => result.map_err(from_fetcher),
                Err(_) => Err(Error::network(format!(
                    "fetching the attestation document took longer than {} seconds",
                    fetch::FETCH_TIMEOUT.as_secs()
                ))
                .timed_out()),
            }
        })
    })
}

/// The hosts that `fetcher` proposes; any failure is an empty list.
pub(crate) async fn router_list(fetcher: Arc<dyn RouterListFetcher>) -> Vec<String> {
    fetcher.fetch_router_list().await.unwrap_or_default()
}

/// A fetcher's error in the client's categories: this crate's error keeps
/// its kind, and any other is a network error that has it as its source.
pub(crate) fn from_fetcher(error: BoxError) -> Error {
    Error::wrap(ErrorKind::Network, error)
}

#[cfg(test)]
#[path = "fetchers_tests.rs"]
mod tests;
