//! Reads the model from a request to the gateway and scopes its prompt
//! cache.

use reqwest::Request;

use crate::error::Error;
use crate::options::Secret;

/// The request-body member that carries the derived cache salt.
pub(crate) const CACHE_SALT_FIELD: &str = "cache_salt";

/// The largest multipart upload that is read to find its model.
pub(crate) const MAX_MULTIPART_BYTES: usize = 64 << 20;

/// Prepares a request for routing. Only a `POST` with a body is touched.
///
/// **JSON** (`application/json`): the body is read into memory, so it can
/// be sent again.
///
/// - If the request has no `X-Tinfoil-Model` header, a non-empty `model`
///   string in the body sets it.
/// - On a path that carries the cache secret, the secret is the body's
///   non-empty `user_cache_secret` string, or else `secret`. From it and
///   the bearer credential of the `Authorization` header the client
///   derives a salt (HKDF-SHA-256) and replaces the `user_cache_secret`
///   member with a `cache_salt` member, so the secret itself never leaves
///   the client. Any `X-Tinfoil-Cache-Prefix` header from the caller is
///   removed, and a new one is set to an HMAC of the prompt's first
///   element (the `instructions` string, or the first item of `messages`,
///   `input` or `prompt`) under a second derived key, when there is one.
/// - The members are edited in the body's text, so the other bytes are
///   unchanged.
/// - A body that has `model`, `user_cache_secret` or `cache_salt` more
///   than once is a configuration error: a parser that keeps the first
///   member and one that keeps the last would otherwise disagree about the
///   pinned model or leak the secret.
/// - A body that is not a JSON object is forwarded as it is.
///
/// **Multipart** (`multipart/form-data`): with an `X-Tinfoil-Model` header
/// the upload is left to stream. Without one the body is read, up to
/// [`MAX_MULTIPART_BYTES`], and must hold exactly one non-empty `model`
/// field that is not a file; that sets the header. A missing boundary, an
/// unreadable form or another count of `model` fields is a configuration
/// error.
///
/// Any other content type is left alone.
pub(crate) async fn prepare(request: Request, secret: Option<&Secret>) -> Result<Request, Error> {
    Err(Error::not_implemented("gateway request preparation"))
}

/// The credential of a `Bearer` authorization, whose scheme is matched
/// without regard to case; empty for any other scheme.
pub(crate) fn bearer_credential(authorization: &str) -> &str {
    match authorization.trim().split_once(' ') {
        Some((scheme, credential)) if scheme.eq_ignore_ascii_case("Bearer") => credential.trim(),
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_bearer_authorization_has_a_credential() {
        assert_eq!(bearer_credential("Bearer abc"), "abc");
        assert_eq!(bearer_credential("  bearer   abc  "), "abc");
        assert_eq!(bearer_credential("Basic abc"), "");
        assert_eq!(bearer_credential("abc"), "");
    }
}
