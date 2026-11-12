//! Fetches raw attestation documents. It parses nothing: verification
//! belongs to the verifier.

use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::verifier::NONCE_SIZE;

/// The path of an enclave's attestation endpoint.
pub(crate) const ATTESTATION_PATH: &str = "/.well-known/tinfoil-attestation";

/// The bound on one document fetch, from the request to the last byte of
/// the body.
pub(crate) const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest attestation document that is read. A document of exactly
/// this size is accepted; one byte more is refused.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 32 << 20;

/// The number of redirects that a fetch of attestation material follows.
pub(crate) const MAX_REDIRECTS: usize = 10;

/// Where the attestation document of `host` is fetched with `nonce`:
/// `https://<host>/.well-known/tinfoil-attestation?nonce=<lowercase hex>`,
/// or, through a relay,
/// `https://<relay>/.well-known/tinfoil-attestation?nonce=<hex>&enclave=<host, query-escaped>`.
///
/// `host` and `relay` are each a host with an optional port, not a URL: a
/// value that carries a scheme, a path, a query or user information is
/// refused, and so is an empty `host`. The error is a configuration error,
/// and nothing has been sent.
pub(crate) fn document_url(
    host: &str,
    relay: Option<&str>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Url, Error> {
    Err(Error::not_implemented("the attestation document URL"))
}

/// Fetches the attestation document of `host` for `nonce` and returns the
/// response body as received.
///
/// - The request carries the `Tinfoil-SDK` and `Tinfoil-SDK-Version`
///   headers and nothing else of the caller's: no credential, no cookie.
/// - It goes out on a connection of its own, never a pooled one, so that a
///   fetch after a rollout cannot land on a replica that is draining.
/// - Redirects are followed up to [`MAX_REDIRECTS`] times and only to
///   `https://` URLs. The document proves itself, so a redirect cannot make
///   an untrusted document pass; it can only fail the fetch.
/// - The fetch ends after [`FETCH_TIMEOUT`], whatever the caller's own
///   deadline is.
/// - The body is read as a stream and the read stops at
///   [`MAX_DOCUMENT_BYTES`] plus one byte.
///
/// Every failure is a network error (a connection failure, a timeout, a
/// status above 299, an oversized body), except an invalid `host` or
/// `relay`, which is a configuration error raised before anything is sent.
///
/// Dropping the future closes the connection and leaves nothing behind.
pub(crate) async fn document(
    host: &str,
    relay: Option<&str>,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented("the attestation document fetch"))
}

/// A `reqwest` client for material that is not attested yet (documents,
/// the router list, the gateway catalog): the standard certificate checks
/// against the bundled roots on the `ring` provider, HTTPS only, the
/// redirect rule of [`document`], no connection reuse, and `timeout` as
/// the bound on each request.
pub(crate) fn plain_client(timeout: Duration) -> Result<reqwest::Client, Error> {
    Err(Error::not_implemented("the client for unattested fetches"))
}

/// Reads the body of `response`, stopping with a network error once it
/// exceeds `limit` bytes. `what` names the body in that error.
pub(crate) async fn read_bounded(
    response: reqwest::Response,
    limit: usize,
    what: &'static str,
) -> Result<Vec<u8>, Error> {
    Err(Error::not_implemented("the bounded body read"))
}

/// `bytes` as lowercase hexadecimal, the form of the nonce in a fetch URL.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            if let Some(digit) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(*digit));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(lower_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(lower_hex(&[]), "");
    }
}
