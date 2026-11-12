//! Keeps a client's requests on its own origin.

use std::sync::Arc;

use reqwest::Url;

use crate::error::Error;
use crate::internal::transport::RoundTrip;

/// `next` behind a guard that refuses a request to any origin other than
/// the enclave's (`https://<enclave_host>`) and the base URL's. Either may
/// be absent; the gateway passes only its base URL.
///
/// The guard is the outermost layer: a refused request is a configuration
/// error, reaches no other layer, and starts no verification. It protects
/// the headers of a request, such as an API key, from being sent to
/// another host.
///
/// An enclave host that is not a host with an optional port is a
/// configuration error here, before any I/O.
pub(crate) fn with_origin_restriction(
    next: Arc<dyn RoundTrip>,
    enclave_host: Option<&str>,
    base_url: Option<&Url>,
) -> Result<Arc<dyn RoundTrip>, Error> {
    Err(Error::not_implemented("the origin restriction"))
}
