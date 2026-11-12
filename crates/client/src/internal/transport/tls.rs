//! The TLS mode: every connection is pinned to the attested TLS key.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use reqwest::header::HOST;
use reqwest::{Client, Request, Response};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, OtherError, RootCertStore,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::enclave::Evidence;
use crate::internal::fetch::lower_hex;
use crate::internal::transport::{Failure, Mode, RoundTrip};

/// Pins connections to the TLS key of the current verification.
///
/// - **Requests.** Only `https://` requests are accepted; a plaintext
///   request is a configuration error before any I/O. A `Host` header set
///   by the caller is refused the same way.
/// - **Binding.** [`bind`](Mode::bind) builds one `reqwest::Client` for the
///   fingerprint, with a TLS configuration of its own on the `ring`
///   provider (TLS 1.2 and 1.3), handed to `reqwest` as a preconfigured
///   TLS stack so that connections are pooled as usual. Evidence without a
///   TLS key is an attestation error, and an empty fingerprint is a
///   configuration error. The client follows no redirect: a `3xx` is
///   returned to the caller. A forward proxy named by `HTTPS_PROXY`,
///   `ALL_PROXY` and `NO_PROXY` is used as `reqwest` uses it by default:
///   the client asks it for a tunnel, and the handshake inside the tunnel
///   is with the enclave and is pinned like any other.
/// - **The check.** The configuration's certificate verifier is
///   [`PinnedServerVerifier`]. Every connection makes a full handshake,
///   which the verifier checks: session resumption is off, because a
///   resumed session presents no certificate to check.
/// - **Rejection.** A handshake that fails a certificate check (the chain,
///   the validity, the name or the pin) never reached the enclave's
///   application. It is reported as an attestation error marked
///   [`Failure::peer_lacks_key`], which makes the transport verify again.
///   Every other failure is a network error.
/// - **Retirement.** A binding owns its `reqwest::Client` and with it its
///   connection pool. The transport drops the binding when a newer
///   verification replaces it; requests in flight on it finish, and its
///   idle connections close with it. No connection is shared between two
///   bindings.
pub(crate) struct TlsMode {
    roots: Arc<RootCertStore>,
    /// Whether a proxy named in the environment is used. Always, outside
    /// the tests, which must reach their local server directly.
    environment_proxy: bool,
}

impl TlsMode {
    /// The mode, with the root certificates that are compiled in.
    pub(crate) fn new() -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            roots: Arc::new(roots),
            environment_proxy: true,
        }
    }

    /// The mode with `roots` in place of the compiled-in root
    /// certificates and without a proxy, for tests against a local server.
    #[cfg(test)]
    pub(crate) fn with_roots(roots: RootCertStore) -> Self {
        Self {
            roots: Arc::new(roots),
            environment_proxy: false,
        }
    }
}

impl<V: Evidence> Mode<V> for TlsMode {
    fn validate_request(&self, request: &Request) -> Result<(), Error> {
        if request.url().scheme() != "https" {
            return Err(Error::configuration(
                "the TLS transport mode requires an HTTPS request",
            ));
        }
        if request.headers().contains_key(HOST) {
            return Err(Error::configuration(
                "the Host header is set by the client and cannot be set on a request",
            ));
        }
        Ok(())
    }

    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error> {
        let fingerprint = evidence
            .tls_public_key_fp()
            .ok_or_else(|| Error::attestation("document endorses no \"tls\" key"))?;
        let verifier = PinnedServerVerifier::new(fingerprint, Arc::clone(&self.roots))?;
        let mut tls = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        // A resumed session skips the certificate, and with it the
        // verifier. Without resumption every connection is checked.
        tls.resumption = rustls::client::Resumption::disabled();
        let mut builder = Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none());
        if !self.environment_proxy {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?;
        Ok(Arc::new(TlsBound { client }))
    }
}

/// The `ring` provider, the only one that the crate is built with.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client whose every connection is pinned to one attested key.
struct TlsBound {
    client: Client,
}

impl RoundTrip for TlsBound {
    /// Sends `request` over a pinned connection. The request's own timeout,
    /// if it has one, is applied by the client.
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        // A plaintext request is refused by the mode before it gets here,
        // and by the client itself, which is HTTPS-only.
        let sent = self.client.execute(request);
        Box::pin(async move { sent.await.map_err(failure) })
    }
}

/// A failed request as the transport reports it: a failed certificate
/// check is an attestation error that says that the peer does not hold the
/// attested key; anything else is a network error.
fn failure(error: reqwest::Error) -> Failure {
    if let Some(reason) = certificate_failure(&error) {
        return Failure::peer_lacks_key(Error::wrap(
            ErrorKind::Attestation,
            CertificateRefused {
                reason,
                source: error,
            },
        ));
    }
    let timeout = error.is_timeout();
    let error = Error::wrap(ErrorKind::Network, error);
    Failure::from(if timeout { error.timed_out() } else { error })
}

/// Why the handshake refused the server's certificate, if that is why
/// `error` happened.
fn certificate_failure(error: &(dyn StdError + 'static)) -> Option<String> {
    let mut next = Some(error);
    while let Some(error) = next {
        if let Some(rustls::Error::InvalidCertificate(reason)) = tls_error(error) {
            return Some(match reason {
                CertificateError::Other(other) => other.0.to_string(),
                reason => format!("{reason:?}"),
            });
        }
        next = error.source();
    }
    None
}

/// The TLS error that `error` is, or that it wraps as an I/O error does.
///
/// A TLS failure reaches the caller inside I/O errors, one within another,
/// and an I/O error's `source` skips the error that it wraps. So an I/O
/// error is opened, as often as it takes.
fn tls_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a rustls::Error> {
    let mut error = error;
    loop {
        if let Some(tls) = error.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        error = error.downcast_ref::<std::io::Error>()?.get_ref()?;
    }
}

/// The error for a server whose certificate the handshake refused.
#[derive(Debug)]
struct CertificateRefused {
    reason: String,
    source: reqwest::Error,
}

impl fmt::Display for CertificateRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the enclave's TLS certificate was refused: {}",
            self.reason
        )
    }
}

impl StdError for CertificateRefused {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}

/// The reason that the verifier gives when a certificate passes the
/// standard checks and carries another key than the attested one.
#[derive(Debug)]
struct KeyMismatch;

impl fmt::Display for KeyMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the certificate does not carry the attested key")
    }
}

impl StdError for KeyMismatch {}

/// A `rustls` server-certificate verifier that accepts a server only if it
/// passes the standard checks and holds the attested key.
///
/// 1. The standard WebPKI verification runs first, unchanged: the chain to
///    a root certificate, the validity period and the server name. The pin
///    adds to these checks and never replaces them.
/// 2. The SHA-256 of the leaf certificate's subject public key info, as
///    the certificate encodes it, in lowercase hexadecimal, is compared
///    with the attested fingerprint as text. Only the leaf is compared: a
///    certificate authority that holds the key does not pass. A
///    fingerprint that is not such a digest matches nothing.
///
/// A mismatch fails the handshake. The signatures of the handshake are
/// checked by the standard verifier with the `ring` provider's algorithms.
#[derive(Debug)]
pub(crate) struct PinnedServerVerifier {
    /// The attested fingerprint.
    fingerprint: String,
    /// The standard verifier.
    webpki: Arc<WebPkiServerVerifier>,
}

impl PinnedServerVerifier {
    /// A verifier for `fingerprint`, the attested TLS key fingerprint, that
    /// trusts `roots`. An empty fingerprint is a configuration error.
    pub(crate) fn new(fingerprint: &str, roots: Arc<RootCertStore>) -> Result<Self, Error> {
        if fingerprint.is_empty() {
            return Err(Error::configuration(
                "the TLS transport mode requires a verified certificate fingerprint",
            ));
        }
        let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider())
            .build()
            .map_err(|error| Error::wrap(ErrorKind::Configuration, error))?;
        Ok(Self {
            fingerprint: fingerprint.to_owned(),
            webpki,
        })
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if leaf_fingerprint(end_entity)? != self.fingerprint {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(KeyMismatch)),
            )));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// The fingerprint of the key of `certificate`: the SHA-256 of its subject
/// public key info, read by the parser that the standard verification
/// uses, so that no second parser can disagree with the first.
pub(crate) fn leaf_fingerprint(certificate: &CertificateDer<'_>) -> Result<String, rustls::Error> {
    let parsed = webpki::EndEntityCert::try_from(certificate)
        .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
    Ok(spki_fingerprint(&parsed.subject_public_key_info()))
}

/// The SHA-256 of `spki_der`, a subject public key info, in lowercase
/// hexadecimal: the form of an attested TLS key fingerprint.
pub(crate) fn spki_fingerprint(spki_der: &[u8]) -> String {
    lower_hex(&Sha256::digest(spki_der))
}

#[cfg(test)]
#[path = "tls_tests.rs"]
mod tests;
