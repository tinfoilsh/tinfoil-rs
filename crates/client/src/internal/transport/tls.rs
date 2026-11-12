//! The TLS mode: every connection is pinned to the attested TLS key.

use std::sync::Arc;

use crate::error::Error;
use crate::internal::enclave::Evidence;
use crate::internal::transport::{Mode, RoundTrip};

/// Pins connections to the TLS key of the current verification.
///
/// - **Requests.** Only `https://` requests are accepted; a plaintext
///   request is a configuration error before any I/O. A `Host` header set
///   by the caller is refused the same way.
/// - **Binding.** [`bind`](Mode::bind) builds one `reqwest::Client` for the
///   fingerprint, with a TLS configuration of its own on the `ring`
///   provider (TLS 1.2 and later), handed to `reqwest` as a preconfigured
///   TLS stack so that connection pooling works as usual. Evidence without
///   a TLS key is an attestation error. The client follows no redirects.
///   A forward proxy from the environment is used as `reqwest` uses it by
///   default; the handshake inside its tunnel is pinned like any other.
/// - **The check.** The configuration's certificate verifier is
///   [`PinnedServerVerifier`]. It runs on every handshake, so a pooled
///   connection was checked when it was opened and a new connection is
///   checked again.
/// - **Rejection.** A handshake that fails a certificate check, the pin
///   included, never reached the enclave's application. It is reported as
///   an attestation error marked
///   [`Failure::peer_lacks_key`](crate::internal::transport::Failure::peer_lacks_key), which
///   makes the transport verify again.
/// - **Retirement.** A new binding is a new `reqwest::Client`. The old one
///   is dropped by the transport; requests in flight on it finish, and its
///   idle connections close with it.
pub(crate) struct TlsMode;

impl<V: Evidence> Mode<V> for TlsMode {
    fn validate_request(&self, request: &reqwest::Request) -> Result<(), Error> {
        Err(Error::not_implemented("the TLS transport mode"))
    }

    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error> {
        Err(Error::not_implemented("the TLS transport mode"))
    }
}

/// A `rustls` server-certificate verifier that accepts a server only if it
/// passes the standard checks and holds the attested key.
///
/// 1. The standard WebPKI verification runs first, unchanged: the chain to
///    a bundled root, validity, and the server name. The pin adds to these
///    checks and never replaces them.
/// 2. The SHA-256 of the leaf certificate's subject public key info, in
///    lowercase hexadecimal, is compared with the attested fingerprint. The
///    key is taken from the leaf as the WebPKI parser read it, so no second
///    certificate parser can disagree with the first.
///
/// A mismatch fails the handshake with an error that the mode recognizes as
/// a pin failure. Signature checks of the handshake are delegated to the
/// `ring` provider's algorithms.
#[derive(Debug)]
pub(crate) struct PinnedServerVerifier {
    /// The attested fingerprint.
    fingerprint: String,
}

impl PinnedServerVerifier {
    /// A verifier for `fingerprint`, the attested TLS key fingerprint. An
    /// empty fingerprint is a configuration error.
    pub(crate) fn new(fingerprint: &str) -> Result<Self, Error> {
        Err(Error::not_implemented("the pinned certificate verifier"))
    }
}

/// The SHA-256 of `spki_der`, a subject public key info, in lowercase
/// hexadecimal: the form of an attested TLS key fingerprint.
pub(crate) fn spki_fingerprint(spki_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    crate::internal::fetch::lower_hex(&Sha256::digest(spki_der))
}
