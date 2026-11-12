//! The EHBP mode: bodies are sealed to the attested HPKE key.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt;
use http_body_util::BodyExt;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, TRANSFER_ENCODING, UPGRADE};
use reqwest::{Method, Request, Response, ResponseBuilderExt, StatusCode};
use tinfoil_ehbp::{Code, ServerIdentity};

use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::enclave::Evidence;
use crate::internal::fetch::{never_proxied, route, tls_builder, tls_builder_with};
use crate::internal::transport::base_url::is_loopback;
use crate::internal::transport::{Failure, Mode, RoundTrip};

#[cfg(test)]
#[path = "ehbp_tests.rs"]
pub(crate) mod tests;

/// The prefix of the header names that belong to the protocol.
const PROTOCOL_HEADER_PREFIX: &str = "ehbp-";

/// The longest key-configuration problem that is read.
const MAX_PROBLEM_BYTES: usize = 64 * 1024;

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
///   body. A request without a body, or with a body in memory that is
///   empty, is sent as it is, and its response is returned as it is:
///   neither is sealed nor authenticated. The method, URL and headers are
///   never sealed.
/// - **Empty streams.** A streamed body counts as a body even if it turns
///   out to produce no data. Such a request has nothing to seal and goes
///   out without a body and without the protocol's header, so no response
///   to it can be opened; the rules for a sealed request are applied to
///   the response all the same. A `2xx` response, or one that carries a
///   response nonce, is an attestation error. So is the key-configuration
///   problem, but it is no rejection: nothing was sealed to a key, so the
///   verification stays. Any other response passes through.
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
/// - **Network.** Each binding has carrier `reqwest::Client`s of its own,
///   with the standard certificate checks against the compiled-in roots on
///   the `ring` provider; they are not pinned, since the sealing is the
///   binding. Connections are pooled within a binding and closed with it,
///   so the first request after a new verification opens a new connection:
///   behind a proxy, the old one may lead to the instance whose key was
///   rejected. A failure of a carrier is a network error.
/// - **Proxies.** A forward proxy from the environment is used as `reqwest`
///   uses it by default, except for a request to `localhost` or a loopback
///   address ([`never_proxied`]), which always connects directly: such a
///   request may travel over plain `http`, and a proxy would read its URL
///   and headers. A binding therefore has two carriers, and each request
///   takes the one for its host. The carrier for the other hosts sends
///   over HTTPS only.
pub(crate) struct EhbpMode {
    /// A proxy in place of the environment's proxy settings. Only tests
    /// set one.
    proxy: Option<reqwest::Proxy>,
    /// Root certificates in place of the compiled-in ones. Only tests set
    /// them.
    roots: Option<rustls::RootCertStore>,
}

impl EhbpMode {
    /// The mode.
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            proxy: None,
            roots: None,
        })
    }

    /// A carrier client of one binding: `direct` for the hosts that are
    /// never proxied, and otherwise for all others.
    ///
    /// The carrier for all others sends over HTTPS only. The request
    /// checks already refuse plain `http` to such a host; the carrier
    /// refuses it again by itself, so that a request that reached a
    /// binding without those checks still cannot put its URL and headers
    /// on the network, or before a proxy, in the clear. Plain `http` is
    /// for loopback hosts, which take the direct carrier.
    fn carrier(&self, direct: bool) -> Result<reqwest::Client, Error> {
        let builder = match &self.roots {
            Some(roots) => tls_builder_with(roots.clone())?,
            None => tls_builder()?,
        }
        .https_only(!direct)
        .redirect(reqwest::redirect::Policy::none());
        route(builder, direct, self.proxy.clone())
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
            proxied: self.carrier(false)?,
            direct: self.carrier(true)?,
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
    /// The carrier for the hosts that the environment's proxy applies to.
    proxied: reqwest::Client,
    /// The carrier for the hosts that are never proxied.
    direct: reqwest::Client,
}

impl RoundTrip for Sealing {
    fn round_trip(&self, mut request: Request) -> BoxFuture<Result<Response, Failure>> {
        // The protocol's client is scoped to one origin and refuses any
        // other. The origin of a request is checked by the layer in front
        // of the transport, so each request gets a client for its own
        // origin; the client is a handle on the shared carrier and holds
        // nothing else that outlives the request.
        let carrier = if never_proxied(request.url()) {
            &self.direct
        } else {
            &self.proxied
        };
        let sealing = tinfoil_ehbp::Client::with_identity_and_http_client(
            request.url().clone(),
            self.identity.clone(),
            carrier.clone(),
        );
        // A body in memory is known to be empty or not, and the protocol's
        // client treats it accordingly. A stream is a body whatever it
        // produces, so what it produces is observed.
        let produced = watch_stream(&mut request);
        Box::pin(async move {
            let sealing = sealing.map_err(failure)?;
            let response = sealing.execute(request).await.map_err(failure)?;
            // The client reads a stream up to its first data, or to its
            // end, before it sends anything. A stream that has produced
            // none by now was empty, and the request went out unsealed.
            if produced.is_some_and(|produced| !produced.load(Ordering::SeqCst)) {
                return unsealed(response).await;
            }
            Ok(response)
        })
    }
}

/// Puts a watch on the body of `request` if it is a stream: the flag is
/// set once the stream has produced data. `None` for a request without a
/// body or with a body in memory.
fn watch_stream(request: &mut Request) -> Option<Arc<AtomicBool>> {
    if request.body()?.as_bytes().is_some() {
        return None;
    }
    let body = request.body_mut().take()?;
    let produced = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&produced);
    let watched = body.map_frame(move |frame| {
        if frame.data_ref().is_some_and(|data| !data.is_empty()) {
            flag.store(true, Ordering::SeqCst);
        }
        frame
    });
    *request.body_mut() = Some(reqwest::Body::wrap(watched));
    Some(produced)
}

/// Applies the rules for the response to a sealed request to `response`,
/// the answer to a request whose streamed body was empty and which was
/// therefore sent unsealed.
async fn unsealed(response: Response) -> Result<Response, Failure> {
    if response.status().is_success()
        || response
            .headers()
            .contains_key(tinfoil_ehbp::RESPONSE_NONCE_HEADER)
    {
        return Err(Error::attestation(
            "the request body was a stream that produced no data, so nothing was sealed and \
             the response cannot be authenticated; send such a request without a body",
        )
        .into());
    }
    if response.status() == StatusCode::UNPROCESSABLE_ENTITY && is_problem(&response) {
        return key_configuration_problem(response).await;
    }
    Ok(response)
}

/// Whether the media type of `response` is that of a problem document.
fn is_problem(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| {
            media_type
                .trim()
                .eq_ignore_ascii_case(tinfoil_ehbp::PROBLEM_JSON_MEDIA_TYPE)
        })
}

/// Reads the body of a `422` problem response to an unsealed request, up
/// to [`MAX_PROBLEM_BYTES`]. The key-configuration problem is an error, as
/// it is for a request with a body, but it says nothing about the keys:
/// the request carried nothing that was sealed to one, so the verification
/// stays. Anything else is returned as a response with the same body.
async fn key_configuration_problem(mut response: Response) -> Result<Response, Failure> {
    let mut read = Vec::new();
    let mut size = 0usize;
    let mut ended = false;
    while size <= MAX_PROBLEM_BYTES {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                size = size.saturating_add(chunk.len());
                read.push(chunk);
            }
            Ok(None) => {
                ended = true;
                break;
            }
            Err(error) => return Err(failure(tinfoil_ehbp::Error::Http(error))),
        }
    }
    if ended && size <= MAX_PROBLEM_BYTES {
        let problem = serde_json::from_slice::<serde_json::Value>(&read.concat()).ok();
        let problem_type = problem
            .as_ref()
            .and_then(|problem| problem.get("type"))
            .and_then(serde_json::Value::as_str);
        if problem_type == Some(tinfoil_ehbp::KEY_CONFIG_PROBLEM_TYPE) {
            return Err(Error::attestation(
                "the server reported a key configuration mismatch for a request whose \
                 streamed body produced no data and was sent unsealed",
            )
            .into());
        }
    }

    // The same response, with what was read in front of the rest.
    let url = response.url().clone();
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());
    if let Some(headers) = builder.headers_mut() {
        *headers = response.headers().clone();
    }
    if let Some(extensions) = builder.extensions_mut() {
        *extensions = std::mem::take(response.extensions_mut());
    }
    // After the extensions, which the URL is kept among.
    let builder = builder.url(url);
    let read = futures_util::stream::iter(read.into_iter().map(Ok::<_, reqwest::Error>));
    let body = reqwest::Body::wrap_stream(read.chain(response.bytes_stream()));
    builder
        .body(body)
        .map(Response::from)
        .map_err(|error| Error::wrap(ErrorKind::Attestation, error).into())
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
