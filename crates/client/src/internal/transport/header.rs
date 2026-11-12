//! Names the enclave to a proxy.

use std::sync::Arc;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Request, Response, Url};

use crate::internal::BoxFuture;
use crate::internal::transport::base_url::{enclave_origin, origin_of};
use crate::internal::transport::{Failure, RoundTrip};

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
/// Without a proxy the header is not touched.
pub(crate) fn with_enclave_url(
    next: Arc<dyn RoundTrip>,
    enclave_host: &str,
    base_url: Option<&Url>,
) -> Arc<dyn RoundTrip> {
    match enclave_url_value(enclave_host, base_url) {
        Some(value) => Arc::new(EnclaveUrl { value, next }),
        None => next,
    }
}

/// The header's value, when `base_url` is a proxy: it is set, and it is on
/// another origin than the enclave. The value is `https://` and the host
/// as the client was given it.
fn enclave_url_value(enclave_host: &str, base_url: Option<&Url>) -> Option<HeaderValue> {
    let proxy = origin_of(base_url?).ok()?;
    let enclave = enclave_origin(enclave_host).ok()?;
    if proxy == enclave {
        return None;
    }
    HeaderValue::from_str(&format!("https://{enclave_host}")).ok()
}

/// The layer of [`with_enclave_url`].
struct EnclaveUrl {
    value: HeaderValue,
    next: Arc<dyn RoundTrip>,
}

impl RoundTrip for EnclaveUrl {
    fn round_trip(&self, mut request: Request) -> BoxFuture<Result<Response, Failure>> {
        request.headers_mut().insert(
            HeaderName::from_static("x-tinfoil-enclave-url"),
            self.value.clone(),
        );
        self.next.round_trip(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_constant_and_the_name_that_is_set_are_the_same_header() {
        assert_eq!(
            HeaderName::from_bytes(ENCLAVE_URL_HEADER.as_bytes()).unwrap(),
            HeaderName::from_static("x-tinfoil-enclave-url")
        );
    }

    #[test]
    fn only_a_base_url_on_another_origin_is_a_proxy() {
        let url = |text: &str| Url::parse(text).unwrap();
        let value = |host: &str, base: Option<&str>| {
            enclave_url_value(host, base.map(url).as_ref())
                .map(|value| value.to_str().unwrap().to_owned())
        };
        assert_eq!(value("enclave.example.com", None), None);
        assert_eq!(
            value(
                "enclave.example.com",
                Some("https://enclave.example.com/v1/")
            ),
            None
        );
        // The default port and the letter case do not make another origin.
        assert_eq!(
            value(
                "Enclave.Example.com:443",
                Some("https://enclave.example.com/")
            ),
            None
        );
        assert_eq!(
            value("enclave.example.com", Some("https://proxy.example.com/")).as_deref(),
            Some("https://enclave.example.com")
        );
        // Another port, and another scheme, are other origins. The value is
        // the host as it was given.
        assert_eq!(
            value(
                "Enclave.example.com:8443",
                Some("https://enclave.example.com/")
            )
            .as_deref(),
            Some("https://Enclave.example.com:8443")
        );
        assert_eq!(
            value("localhost", Some("http://localhost/")).as_deref(),
            Some("https://localhost")
        );
    }
}
