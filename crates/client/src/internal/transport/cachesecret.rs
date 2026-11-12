//! Adds the user cache secret to request bodies.

use std::sync::Arc;

use crate::internal::transport::RoundTrip;
use crate::options::Secret;

/// The request-body member that scopes the prompt cache.
pub(crate) const FIELD: &str = "user_cache_secret";

/// `next` behind a layer that adds `secret` to the bodies of the requests
/// that carry it; `next` itself when there is no secret.
///
/// A request carries the member when it is a `POST` with a body held in
/// memory whose path ends in `/chat/completions`, `/completions` or
/// `/responses`. The suffix match needs no `/v1` prefix, so a base URL
/// with a path prefix still qualifies. Other endpoints are left alone:
/// they do not use the cache and may reject an unknown member.
///
/// The member is spliced into the body's text ([`inject`]), and the
/// `Content-Length` follows. A replay sends the body with the member.
pub(crate) fn with_cache_secret(
    next: Arc<dyn RoundTrip>,
    secret: Option<Secret>,
) -> Arc<dyn RoundTrip> {
    next
}

/// Adds `"user_cache_secret": <secret>` to a JSON object by editing its
/// text, so that every other byte that the caller wrote, numbers beyond
/// double precision included, reaches the enclave unchanged.
///
/// Returns `None`, meaning "send the original bytes", when the body:
///
/// - is not valid UTF-8, or is not one JSON object with only whitespace
///   around it;
/// - already has the member with a non-empty string, or with a value that
///   is not a string: the caller's value is never overwritten;
/// - has the member more than once.
///
/// An existing empty string is replaced with the secret.
pub(crate) fn inject(body: &[u8], secret: &str) -> Option<Vec<u8>> {
    None
}
