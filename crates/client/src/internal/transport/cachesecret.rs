//! Adds the user cache secret to request bodies.

use std::fmt;
use std::sync::Arc;

use http_body_util::BodyExt;
use reqwest::header::{CONTENT_LENGTH, HeaderValue};
use reqwest::{Method, Request, Response};
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::transport::{Failure, RoundTrip};
use crate::options::Secret;

/// The request-body member that scopes the prompt cache.
pub(crate) const FIELD: &str = "user_cache_secret";

/// The endings of the paths whose bodies carry the member.
const PATHS: [&str; 3] = ["/chat/completions", "/completions", "/responses"];

/// `next` behind a layer that adds `secret` to the bodies of the requests
/// that carry it; `next` itself when there is no secret, or an empty one.
///
/// A request carries the member when it is a `POST` with a body whose
/// path ends in `/chat/completions`, `/completions` or `/responses`. The
/// suffix match needs no `/v1` prefix, so a base URL with a path prefix
/// still qualifies. Other endpoints are left alone: they do not use the
/// cache and may reject an unknown member.
///
/// The member is spliced into the body's text ([`inject`]), and a
/// `Content-Length` header that the request carries follows. A replay
/// sends the body with the member.
///
/// A body that is a stream is read to its end first, into memory, so that
/// it gets the member like any other. With the member it is sent from
/// memory, and can be sent again after a key rejection. Without a change
/// it stays a stream, of the bytes that were read: it cannot be sent
/// again, and a stream that produced no data is still a body to the
/// transport mode, which matters where bodies are sealed. A stream that
/// fails is a network error, and nothing is sent.
pub(crate) fn with_cache_secret(
    next: Arc<dyn RoundTrip>,
    secret: Option<Secret>,
) -> Arc<dyn RoundTrip> {
    match secret {
        Some(secret) if !secret.expose().is_empty() => Arc::new(CacheSecret { secret, next }),
        _ => next,
    }
}

/// The layer of [`with_cache_secret`].
struct CacheSecret {
    secret: Secret,
    next: Arc<dyn RoundTrip>,
}

/// Whether `request` is one whose body carries the member.
fn eligible(request: &Request) -> bool {
    request.method() == Method::POST
        && request.body().is_some()
        && PATHS
            .iter()
            .any(|path| request.url().path().ends_with(path))
}

impl RoundTrip for CacheSecret {
    fn round_trip(&self, mut request: Request) -> BoxFuture<Result<Response, Failure>> {
        if !eligible(&request) {
            return self.next.round_trip(request);
        }
        let injected = match request.body().and_then(reqwest::Body::as_bytes) {
            Some(body) => inject(body, self.secret.expose()),
            None => {
                // A stream. Reading it needs an await.
                let (secret, next) = (self.secret.clone(), Arc::clone(&self.next));
                return Box::pin(async move {
                    let Some(stream) = request.body_mut().take() else {
                        return next.round_trip(request).await;
                    };
                    let read = stream.collect().await.map_err(|error| {
                        Error::wrap(ErrorKind::Network, Unread(error.without_url()))
                    })?;
                    let read = read.to_bytes();
                    match inject(&read, secret.expose()) {
                        Some(body) => set_body(&mut request, body),
                        // Still a stream, of what was read: the layers
                        // below treat it as they would have treated the
                        // caller's stream.
                        None => {
                            let again = futures_util::stream::once(async move {
                                Ok::<_, std::convert::Infallible>(read)
                            });
                            *request.body_mut() = Some(reqwest::Body::wrap_stream(again));
                        }
                    }
                    next.round_trip(request).await
                });
            }
        };
        if let Some(body) = injected {
            set_body(&mut request, body);
        }
        self.next.round_trip(request)
    }
}

/// Makes `body` the body of `request`. A `Content-Length` header that the
/// request carries is set to the new length; none is added, since the
/// transport writes the length of a body in memory by itself.
fn set_body(request: &mut Request, body: Vec<u8>) {
    if request.headers().contains_key(CONTENT_LENGTH) {
        request
            .headers_mut()
            .insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
    *request.body_mut() = Some(reqwest::Body::from(body));
}

/// A request body that could not be read to its end.
#[derive(Debug)]
struct Unread(reqwest::Error);

impl fmt::Display for Unread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the request body could not be read")
    }
}

impl std::error::Error for Unread {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// The members of a JSON object in the order of its text, repeated names
/// included: each name decoded, each value as it is written.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de: 'a, 'a> Deserialize<'de> for Members<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Collect<'a>(std::marker::PhantomData<&'a ()>);

        impl<'de: 'a, 'a> Visitor<'de> for Collect<'a> {
            type Value = Members<'a>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry::<String, &'a RawValue>()? {
                    members.push(member);
                }
                Ok(Members(members))
            }
        }

        deserializer.deserialize_map(Collect(std::marker::PhantomData))
    }
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
/// A member's name is compared after its escapes are decoded, so the
/// member is found however its name is written. An existing empty string
/// is replaced with the secret. Otherwise the member is added as the
/// object's last.
pub(crate) fn inject(body: &[u8], secret: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let Members(members) = serde_json::from_str(text).ok()?;
    let member = format!(
        "{}:{}",
        serde_json::to_string(FIELD).ok()?,
        serde_json::to_string(secret).ok()?
    );
    let mut present = members
        .iter()
        .filter(|(name, _)| name == FIELD)
        .map(|(_, value)| *value);
    let (at, replaced, insert) = match (present.next(), present.next()) {
        (None, _) => {
            // The object's closing brace is the last brace of the text.
            let close = text.rfind('}')?;
            let separator = if members.is_empty() { "" } else { "," };
            (close, 0, format!("{separator}{member}"))
        }
        (Some(value), None) if value.get() == "\"\"" => {
            // The value is a part of `text`; its address says where.
            let at = value
                .get()
                .as_ptr()
                .addr()
                .checked_sub(text.as_ptr().addr())?;
            let end = at.checked_add(value.get().len())?;
            if text.get(at..end) != Some(value.get()) {
                return None;
            }
            (at, value.get().len(), serde_json::to_string(secret).ok()?)
        }
        _ => return None,
    };
    let mut out = Vec::with_capacity(body.len().saturating_add(insert.len()));
    out.extend_from_slice(body.get(..at)?);
    out.extend_from_slice(insert.as_bytes());
    out.extend_from_slice(body.get(at.checked_add(replaced)?..)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn injected(body: &str) -> Option<String> {
        inject(body.as_bytes(), "s3cret").map(|out| String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_body_that_is_not_one_json_object_is_left_alone() {
        for body in [
            "",
            " ",
            "[]",
            "[{}]",
            "null",
            "\"text\"",
            "42",
            "{",
            "{}}",
            "{} {}",
            "{} x",
            "{\"a\":1,}",
            "{\"a\" 1}",
            "{a:1}",
            "{\"a\":1}\u{0}",
            "\u{feff}{}",
            "not json",
        ] {
            assert_eq!(injected(body), None, "{body:?}");
        }
        assert_eq!(inject(b"{\"a\":\"\xff\"}", "s3cret"), None);
    }

    #[test]
    fn a_value_that_the_caller_set_is_never_overwritten() {
        for body in [
            r#"{"user_cache_secret":"theirs"}"#,
            r#"{"user_cache_secret":" "}"#,
            r#"{"user_cache_secret":null}"#,
            r#"{"user_cache_secret":0}"#,
            r#"{"user_cache_secret":false}"#,
            r#"{"user_cache_secret":{}}"#,
            r#"{"user_cache_secret":[""]}"#,
            // Written with an escape, it is the same member.
            r#"{"user_cache_\u0073ecret":"theirs"}"#,
            r#"{"model":"m","user_cache_secret":"theirs","n":1}"#,
        ] {
            assert_eq!(injected(body), None, "{body}");
        }
    }

    #[test]
    fn a_repeated_member_is_left_alone_whatever_its_values() {
        for body in [
            r#"{"user_cache_secret":"","user_cache_secret":""}"#,
            r#"{"user_cache_secret":"","user_cache_secret":"theirs"}"#,
            r#"{"user_cache_secret":"theirs","user_cache_secret":""}"#,
            r#"{"user_cache_secret":"","user_cache_\u0073ecret":""}"#,
        ] {
            assert_eq!(injected(body), None, "{body}");
        }
    }

    #[test]
    fn the_member_is_added_last_and_every_other_byte_is_kept() {
        assert_eq!(
            injected("{}").as_deref(),
            Some(r#"{"user_cache_secret":"s3cret"}"#)
        );
        assert_eq!(
            injected(" {\n} \n").as_deref(),
            Some(" {\n\"user_cache_secret\":\"s3cret\"} \n")
        );
        // Key order, spacing, a number beyond double precision, a repeated
        // name and a brace inside a string all stay as written.
        let body =
            r#"{ "seed": 12345678901234567890123, "b": {"x": "}"}, "a": 1.0e0, "a": [ 2 ] }"#;
        assert_eq!(
            injected(body).as_deref(),
            Some(
                r#"{ "seed": 12345678901234567890123, "b": {"x": "}"}, "a": 1.0e0, "a": [ 2 ] ,"user_cache_secret":"s3cret"}"#
            )
        );
        // A member of a nested object is not the object's own.
        assert_eq!(
            injected(r#"{"metadata":{"user_cache_secret":"inner"}}"#).as_deref(),
            Some(r#"{"metadata":{"user_cache_secret":"inner"},"user_cache_secret":"s3cret"}"#)
        );
        // Names differ by case.
        assert_eq!(
            injected(r#"{"User_Cache_Secret":"x"}"#).as_deref(),
            Some(r#"{"User_Cache_Secret":"x","user_cache_secret":"s3cret"}"#)
        );
    }

    #[test]
    fn an_empty_string_is_replaced_where_it_stands() {
        assert_eq!(
            injected(r#"{"user_cache_secret":""}"#).as_deref(),
            Some(r#"{"user_cache_secret":"s3cret"}"#)
        );
        assert_eq!(
            injected(r#"{"a":"","user_cache_secret" : "" ,"b":""}"#).as_deref(),
            Some(r#"{"a":"","user_cache_secret" : "s3cret" ,"b":""}"#)
        );
        assert_eq!(
            injected(r#"{"user_cache_\u0073ecret":""}"#).as_deref(),
            Some(r#"{"user_cache_\u0073ecret":"s3cret"}"#)
        );
    }

    #[test]
    fn the_secret_is_written_as_a_json_string() {
        let out = inject(b"{}", "quote\" slash\\ line\n \u{e9}").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value[FIELD], "quote\" slash\\ line\n \u{e9}");
    }

    #[test]
    fn only_a_post_with_a_body_to_a_cached_endpoint_carries_the_member() {
        let request = |method: Method, url: &str, body: Option<&'static str>| {
            let mut request = Request::new(method, url.parse().unwrap());
            *request.body_mut() = body.map(reqwest::Body::from);
            request
        };
        let host = "https://enclave.example.com";
        for path in [
            "/v1/chat/completions",
            "/chat/completions",
            "/v1/completions",
            "/v1/responses",
            "/prefix/api/v1/responses",
            "/responses",
        ] {
            let url = format!("{host}{path}");
            assert!(eligible(&request(Method::POST, &url, Some("{}"))), "{path}");
            // The query is no part of the path.
            let url = format!("{host}{path}?stream=true");
            assert!(eligible(&request(Method::POST, &url, Some("{}"))), "{path}");
            let url = format!("{host}{path}");
            assert!(!eligible(&request(Method::POST, &url, None)), "{path}");
            assert!(!eligible(&request(Method::PUT, &url, Some("{}"))), "{path}");
            assert!(!eligible(&request(Method::GET, &url, Some("{}"))), "{path}");
        }
        for path in [
            "/v1/embeddings",
            "/v1/audio/transcriptions",
            "/v1/responses/",
            "/v1/responses/resp_1",
            "/v1/chat/completions/x",
            "/",
        ] {
            let url = format!("{host}{path}");
            assert!(
                !eligible(&request(Method::POST, &url, Some("{}"))),
                "{path}"
            );
        }
        // The path, not the query, decides.
        let url = format!("{host}/v1/embeddings?next=/responses");
        assert!(!eligible(&request(Method::POST, &url, Some("{}"))));
    }
}
