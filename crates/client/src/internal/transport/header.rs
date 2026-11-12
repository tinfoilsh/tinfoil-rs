//! Names the enclave to a proxy.

use std::sync::Arc;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Request, Response, Url};

use crate::error::Error;
use crate::internal::BoxFuture;
use crate::internal::transport::base_url::{enclave_origin, origin_of};
use crate::internal::transport::{Failure, RoundTrip};

/// The header that tells a proxy which enclave to forward a sealed request
/// to, so that the request reaches the enclave that the client verified.
pub(crate) const ENCLAVE_URL_HEADER: &str = "X-Tinfoil-Enclave-Url";

/// `next` behind a layer that sets [`ENCLAVE_URL_HEADER`] to the enclave's
/// origin on every request, when `base_url` is on another origin than the
/// enclave; otherwise `next` itself.
///
/// The value is the origin of the verified enclave's host, which never
/// changes, so every request, a replay and a request after re-verification
/// included, names the enclave that was verified. A value that the caller
/// set is replaced. Without a proxy the header is not touched.
///
/// An enclave host that yields no origin, or an origin that cannot be a
/// header value, is a configuration error here, before any request: the
/// header is never left out of a request that needs it.
pub(crate) fn with_enclave_url(
    next: Arc<dyn RoundTrip>,
    enclave_host: &str,
    base_url: Option<&Url>,
) -> Result<Arc<dyn RoundTrip>, Error> {
    Ok(match enclave_url_value(enclave_host, base_url)? {
        Some(value) => Arc::new(EnclaveUrl { value, next }),
        None => next,
    })
}

/// The header's value, when `base_url` is a proxy: it is set, and it is on
/// another origin than the enclave.
///
/// The value is the enclave's origin in its normalized form, which is
/// ASCII: `https://`, the host in lowercase, an internationalized name in
/// its ASCII form, and the port unless it is 443.
fn enclave_url_value(
    enclave_host: &str,
    base_url: Option<&Url>,
) -> Result<Option<HeaderValue>, Error> {
    let Some(base_url) = base_url else {
        return Ok(None);
    };
    let proxy = origin_of(base_url)?;
    let enclave = enclave_origin(enclave_host)?;
    if proxy == enclave {
        return Ok(None);
    }
    HeaderValue::from_str(&enclave)
        .map(Some)
        .map_err(|_| Error::configuration("the enclave's origin cannot be sent in a header"))
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
                .unwrap()
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
        // Another port, and another scheme, are other origins.
        assert_eq!(
            value(
                "enclave.example.com:8443",
                Some("https://enclave.example.com/")
            )
            .as_deref(),
            Some("https://enclave.example.com:8443")
        );
        assert_eq!(
            value("localhost", Some("http://localhost/")).as_deref(),
            Some("https://localhost")
        );
    }

    #[test]
    fn the_value_is_the_enclaves_origin_in_ascii_however_the_host_is_written() {
        let proxy = Url::parse("https://proxy.example.com/").unwrap();
        let value = |host: &str| {
            enclave_url_value(host, Some(&proxy))
                .unwrap()
                .expect("a proxy")
                .to_str()
                .expect("ASCII")
                .to_owned()
        };
        assert_eq!(
            value("b\u{fc}cher.example"),
            "https://xn--bcher-kva.example"
        );
        assert_eq!(
            value("B\u{dc}CHER.example:8443"),
            "https://xn--bcher-kva.example:8443"
        );
        assert_eq!(
            value("Enclave.Example.COM:443"),
            "https://enclave.example.com"
        );
        assert_eq!(value("[::1]:8443"), "https://[::1]:8443");
    }

    #[test]
    fn a_host_that_yields_no_origin_is_refused_when_the_layer_is_built() {
        struct Unused;
        impl RoundTrip for Unused {
            fn round_trip(&self, _: Request) -> BoxFuture<Result<Response, Failure>> {
                unreachable!("nothing is sent")
            }
        }
        let proxy = Url::parse("https://proxy.example.com/").unwrap();
        for host in ["", "enclave.example.com/path", "user@enclave.example.com"] {
            let error = with_enclave_url(Arc::new(Unused), host, Some(&proxy))
                .err()
                .expect(host);
            assert_eq!(error.kind(), crate::ErrorKind::Configuration, "{host}");
        }
        // Without a proxy the host is not looked at.
        assert!(with_enclave_url(Arc::new(Unused), "", None).is_ok());
    }
}
