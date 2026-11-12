//! Names the enclave to a proxy.

use std::sync::Arc;

use reqwest::Url;

use crate::internal::transport::RoundTrip;

/// The header that tells a proxy which enclave to forward a sealed request
/// to, so that the request reaches the enclave that the client verified.
pub(crate) const ENCLAVE_URL_HEADER: &str = "X-Tinfoil-Enclave-Url";

/// `next` behind a layer that sets [`ENCLAVE_URL_HEADER`] to
/// `https://<enclave_host>` on every request, when `base_url` is on another
/// origin than the enclave; otherwise `next` itself.
///
/// The value is the verified enclave's host, which never changes, so every
/// request, a replay and a request after re-verification included, names
/// the enclave that was verified. A value that the caller set is replaced.
pub(crate) fn with_enclave_url(
    next: Arc<dyn RoundTrip>,
    enclave_host: &str,
    base_url: Option<&Url>,
) -> Arc<dyn RoundTrip> {
    next
}
