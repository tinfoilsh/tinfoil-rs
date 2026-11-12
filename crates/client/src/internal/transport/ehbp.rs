//! The EHBP mode: bodies are sealed to the attested HPKE key.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use reqwest::header::{CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING, UPGRADE};
use reqwest::{Method, Request, Response};
use tinfoil_ehbp::{Code, ServerIdentity};

use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::enclave::Evidence;
use crate::internal::transport::base_url::is_loopback;
use crate::internal::transport::{Failure, Mode, RoundTrip};

#[cfg(test)]
#[path = "ehbp_tests.rs"]
mod tests;

/// The prefix of the header names that belong to the protocol.
const PROTOCOL_HEADER_PREFIX: &str = "ehbp-";

/// Seals request bodies to the HPKE key of the current verification and
/// opens the response bodies, over an ordinary HTTPS connection to the
/// enclave or to a proxy.
///
/// - **Requests.** [`check_request`] lists the requests that are refused
///   before any I/O.
/// - **Binding.** [`bind`](Mode::bind) parses the HPKE key of the evidence
///   into the protocol's server identity. Evidence without an HPKE key, or
///   with one that does not parse, is an attestation error.
/// - **Bodies.** A request body is sealed with a fresh HPKE context for
///   each attempt, frame by frame as it is produced, and the response is
///   opened frame by frame as it is read: a frame's plaintext is released
///   once that frame has authenticated, without waiting for the end of the
///   body. A request without a body, or with an empty one, is sent as it
///   is, and its response is returned as it is: neither is sealed nor
///   authenticated. The method, URL and headers are never sealed.
/// - **Responses.** A response to a sealed request carries the protocol's
///   response nonce, and is opened whatever its status. Without the nonce,
///   a response with a status outside `2xx` passes through as an ordinary
///   response, because a proxy may refuse a request before it reaches the
///   enclave; its status, headers and body are not authenticated. A `2xx`
///   response without the nonce, and any response with an invalid or
///   repeated one, is an attestation error: its body is never returned.
/// - **Body failures.** A frame that does not authenticate, or a body that
///   ends inside a frame, fails the read of the response body with a
///   `reqwest` error whose source is the protocol's error. The frames
///   before it were authentic and have been delivered; nothing of the
///   failing frame or after it is.
/// - **Rejection.** The enclave answers a body sealed to a key that it
///   does not hold with status `422`, the media type
///   `application/problem+json` and the protocol's key-configuration
///   problem type, before its application sees the request. That is
///   reported as an attestation error marked
///   [`Failure::peer_lacks_key`]. Any other `422` is an ordinary response.
/// - **Redirects** are not followed; a `3xx` is returned to the caller.
/// - **Network.** Each binding has a carrier `reqwest::Client` of its own,
///   with the standard certificate checks against the compiled-in roots on
///   the `ring` provider; it is not pinned, since the sealing is the
///   binding. Connections are pooled within a binding and closed with it,
///   so the first request after a new verification opens a new connection:
///   behind a proxy, the old one may lead to the instance whose key was
///   rejected. A forward proxy from the environment is used as `reqwest`
///   uses it by default. A failure of the carrier is a network error.
pub(crate) struct EhbpMode {
    /// The TLS configuration of every carrier client.
    tls: rustls::ClientConfig,
    /// Whether the carrier clients read the environment's proxy settings.
    environment_proxy: bool,
}

impl EhbpMode {
    /// The mode, with the TLS configuration of its carrier clients.
    pub(crate) fn new() -> Result<Self, Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls,
            environment_proxy: true,
        })
    }

    /// The carrier client of one binding.
    fn carrier(&self) -> Result<reqwest::Client, Error> {
        let mut builder = reqwest::Client::builder()
            .tls_backend_preconfigured(self.tls.clone())
            .redirect(reqwest::redirect::Policy::none());
        if !self.environment_proxy {
            builder = builder.no_proxy();
        }
        builder
            .build()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))
    }
}

impl<V: Evidence> Mode<V> for EhbpMode {
    fn validate_request(&self, request: &Request) -> Result<(), Error> {
        check_request(request)
    }

    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error> {
        let Some(key) = evidence.hpke_public_key() else {
            return Err(Error::attestation(
                "the attestation document endorses no HPKE key, so the EHBP transport mode \
                 cannot be used; use the TLS transport mode",
            ));
        };
        let identity = ServerIdentity::from_public_key_hex(key).map_err(|source| {
            Error::wrap(
                ErrorKind::Attestation,
                Context {
                    what: "failed to parse the attested HPKE public key",
                    source,
                },
            )
        })?;
        Ok(Arc::new(Sealing {
            identity,
            carrier: self.carrier()?,
        }))
    }
}

/// The request checks of the EHBP mode. The gateway runs them before it
/// reads its catalog or verifies a replica. Each refusal is a configuration
/// error, and none repeats the URL, which may hold a credential.
///
/// 1. A request with the `CONNECT` method or an `Upgrade` header: its
///    traffic would continue outside the bodies that are sealed.
/// 2. A URL with a user name or a password.
/// 3. A URL that is neither `https://` nor `http://` to a loopback host:
///    the method, URL and headers are not sealed, so only the connection
///    protects them.
/// 4. A request that sets `Host`, `Content-Length`, `Transfer-Encoding` or
///    a header whose name begins with `Ehbp-`: the transport sets these.
pub(crate) fn check_request(request: &Request) -> Result<(), Error> {
    if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
        return Err(Error::configuration(
            "the EHBP transport mode seals only request and response bodies, so it cannot \
             protect a protocol upgrade, such as a WebSocket, or a CONNECT tunnel; use the \
             TLS transport mode on a direct connection",
        ));
    }
    let url = request.url();
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::configuration(
            "the request URL must not include credentials",
        ));
    }
    let protected = match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(is_loopback),
        _ => false,
    };
    if !protected {
        return Err(Error::configuration(
            "the EHBP transport mode sends requests over https, or over http to a loopback \
             host only",
        ));
    }
    if let Some(name) = request.headers().keys().find(|name| is_reserved(name)) {
        return Err(Error::configuration(format!(
            "the `{name}` header is set by the EHBP transport mode and cannot be set on a request"
        )));
    }
    Ok(())
}

/// Whether the transport owns the header `name`. Header names are held in
/// lowercase, so the comparison ignores the caller's spelling.
fn is_reserved(name: &HeaderName) -> bool {
    name == HOST
        || name == CONTENT_LENGTH
        || name == TRANSFER_ENCODING
        || name.as_str().starts_with(PROTOCOL_HEADER_PREFIX)
}

/// The transport bound to one attested HPKE key.
struct Sealing {
    identity: ServerIdentity,
    carrier: reqwest::Client,
}

impl RoundTrip for Sealing {
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        // The protocol's client is scoped to one origin and refuses any
        // other. The origin of a request is checked by the layer in front
        // of the transport, so each request gets a client for its own
        // origin; the client is a handle on the shared carrier and holds
        // nothing else that outlives the request.
        let sealing = tinfoil_ehbp::Client::with_identity_and_http_client(
            request.url().clone(),
            self.identity.clone(),
            self.carrier.clone(),
        );
        Box::pin(async move {
            let sealing = sealing.map_err(failure)?;
            sealing.execute(request).await.map_err(failure)
        })
    }
}

/// The failure for an error of the protocol's client.
fn failure(error: tinfoil_ehbp::Error) -> Failure {
    match error {
        tinfoil_ehbp::Error::Coded(Code::KeyConfigMismatch, _) => {
            Failure::peer_lacks_key(Error::wrap(
                ErrorKind::Attestation,
                Context {
                    what: "the enclave does not hold the HPKE key that the request body was \
                           sealed to",
                    source: error,
                },
            ))
        }
        // The request never left: the caller built one that cannot be sent.
        tinfoil_ehbp::Error::Coded(Code::InvalidInput, _)
        | tinfoil_ehbp::Error::Url(_)
        | tinfoil_ehbp::Error::HeaderValue(_) => Error::wrap(
            ErrorKind::Configuration,
            Context {
                what: "the EHBP transport mode cannot send the request",
                source: error,
            },
        )
        .into(),
        tinfoil_ehbp::Error::Http(error) => {
            let timeout = error.is_timeout();
            // The URL may hold a credential in its query.
            let error = Error::wrap(ErrorKind::Network, error.without_url());
            if timeout { error.timed_out() } else { error }.into()
        }
        // Everything else is a body that could not be sealed or a response
        // that could not be opened: nothing of it is trusted.
        other => Error::wrap(
            ErrorKind::Attestation,
            Context {
                what: "the EHBP exchange failed",
                source: other,
            },
        )
        .into(),
    }
}

/// An error of the protocol's client, with what it means here.
#[derive(Debug)]
struct Context {
    what: &'static str,
    source: tinfoil_ehbp::Error,
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.what, self.source)
    }
}

impl StdError for Context {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}
