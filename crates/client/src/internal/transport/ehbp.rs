//! The EHBP mode: bodies are sealed to the attested HPKE key.

use std::sync::Arc;

use crate::error::Error;
use crate::internal::enclave::Evidence;
use crate::internal::transport::{Mode, RoundTrip};

/// Seals request bodies to the HPKE key of the current verification and
/// opens the response bodies, over an ordinary HTTPS connection to the
/// enclave or to a proxy.
///
/// - **Requests.** A request with an `Upgrade` header or the `CONNECT`
///   method is a configuration error before any I/O: its traffic would
///   continue outside the bodies that are sealed. So is a request that sets
///   `Host`, `Content-Length`, `Transfer-Encoding` or one of the protocol's
///   own headers (`Ehbp-Encapsulated-Key`, `Ehbp-Response-Nonce`).
/// - **Binding.** [`bind`](Mode::bind) parses the HPKE key of the evidence
///   into the protocol's server identity. Evidence without an HPKE key, or
///   with one that does not parse, is an attestation error.
/// - **Bodies.** A request body is sealed with a fresh HPKE context for
///   each attempt, and the response is opened chunk by chunk as it is
///   read. A request without a body is sent as it is, and its response is
///   returned as it is: neither is sealed. The method, URL and headers are
///   never sealed.
/// - **Responses.** A response with an error status and no response nonce
///   passes through as an ordinary response, because a proxy may refuse a
///   request before it reaches the enclave; its status and body are not
///   authenticated. A success response without the nonce, or with an
///   invalid one, is an attestation error.
/// - **Rejection.** The enclave answers a body sealed to a key that it no
///   longer holds with the protocol's key-configuration problem. That is
///   reported as an attestation error marked
///   [`PeerLacksKey`](crate::internal::transport::PeerLacksKey).
/// - **Redirects** are not followed; a `3xx` is returned to the caller.
/// - **Network.** The carrier is one shared `reqwest::Client` with the
///   standard certificate checks; it is not pinned, since the sealing is
///   the binding. A failure of it is a network error.
pub(crate) struct EhbpMode;

impl EhbpMode {
    /// The mode, with its carrier client.
    pub(crate) fn new() -> Result<Self, Error> {
        Err(Error::not_implemented("the EHBP transport mode"))
    }
}

impl<V: Evidence> Mode<V> for EhbpMode {
    fn validate_request(&self, request: &reqwest::Request) -> Result<(), Error> {
        check_request(request)
    }

    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error> {
        Err(Error::not_implemented("the EHBP transport mode"))
    }
}

/// The request checks of the EHBP mode, as [`EhbpMode`] lists them. The
/// gateway runs them before it reads its catalog or verifies a replica.
pub(crate) fn check_request(request: &reqwest::Request) -> Result<(), Error> {
    Err(Error::not_implemented("the EHBP request checks"))
}
