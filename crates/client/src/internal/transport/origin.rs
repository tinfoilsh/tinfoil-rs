//! Keeps a client's requests on its own origin.

use std::sync::Arc;

use reqwest::{Request, Response, Url};

use crate::error::Error;
use crate::internal::BoxFuture;
use crate::internal::transport::base_url::{enclave_origin, origin_of};
use crate::internal::transport::{Failure, RoundTrip};

/// `next` behind a guard that refuses a request to any origin other than
/// the enclave's (`https://<enclave_host>`) and the base URL's. Either may
/// be absent; the gateway passes only its base URL.
///
/// The guard is the outermost layer: a refused request is a configuration
/// error, reaches no other layer, and starts no verification. It protects
/// the headers of a request, such as an API key, from being sent to
/// another host.
///
/// Origins are compared whole and exactly: the scheme, the host in
/// lowercase and the port, where a scheme's default port and no port are
/// the same. So `http://` to the enclave's host, another port, and a
/// subdomain are all other origins. The path plays no part: a request to
/// an allowed origin passes whatever its path, also outside the path of
/// the base URL. A URL that is not `http` or `https` has no origin and is
/// refused.
///
/// An enclave host that is not a host with an optional port is a
/// configuration error here, before any I/O.
pub(crate) fn with_origin_restriction(
    next: Arc<dyn RoundTrip>,
    enclave_host: Option<&str>,
    base_url: Option<&Url>,
) -> Result<Arc<dyn RoundTrip>, Error> {
    Ok(allowed_origins(enclave_host, base_url)?.guard(next))
}

/// The origins that a client's requests may go to: everything of
/// [`with_origin_restriction`] that can fail, so that a caller can do it
/// before the steps that must not happen for a client that cannot be
/// made.
pub(crate) fn allowed_origins(
    enclave_host: Option<&str>,
    base_url: Option<&Url>,
) -> Result<AllowedOrigins, Error> {
    let mut allowed = Vec::with_capacity(2);
    if let Some(host) = enclave_host {
        allowed.push(enclave_origin(host)?);
    }
    if let Some(base_url) = base_url {
        allowed.push(origin_of(base_url)?);
    }
    Ok(AllowedOrigins {
        allowed,
        enclave: enclave_host.unwrap_or_default().to_owned(),
    })
}

/// The origins of [`allowed_origins`].
pub(crate) struct AllowedOrigins {
    allowed: Vec<String>,
    enclave: String,
}

impl AllowedOrigins {
    /// `next` behind the guard for these origins.
    pub(crate) fn guard(self, next: Arc<dyn RoundTrip>) -> Arc<dyn RoundTrip> {
        Arc::new(OriginGuard {
            allowed: self.allowed,
            enclave: self.enclave,
            next,
        })
    }
}

/// The guard of [`with_origin_restriction`].
struct OriginGuard {
    allowed: Vec<String>,
    /// The enclave's host, for the refusal's message.
    enclave: String,
    next: Arc<dyn RoundTrip>,
}

impl OriginGuard {
    /// A configuration error unless `url` is on an allowed origin. The
    /// message names the origin that was refused, which holds no path, no
    /// query and no credential.
    fn check(&self, url: &Url) -> Result<(), Error> {
        let Ok(origin) = origin_of(url) else {
            return Err(Error::configuration(format!(
                "refusing to send a request that is neither http nor https: the client is \
                 bound to the enclave {:?}",
                self.enclave
            )));
        };
        if self.allowed.contains(&origin) {
            return Ok(());
        }
        Err(Error::configuration(format!(
            "refusing to send a request to {origin:?}: the client is bound to the enclave {:?}",
            self.enclave
        )))
    }
}

impl RoundTrip for OriginGuard {
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        match self.check(request.url()) {
            Ok(()) => self.next.round_trip(request),
            Err(error) => Box::pin(std::future::ready(Err(Failure::from(error)))),
        }
    }
}
