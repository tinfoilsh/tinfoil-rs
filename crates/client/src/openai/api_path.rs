//! The API path of an OpenAI client and the API base that it makes.
//!
//! No error from this module repeats the path: it comes from the caller's
//! configuration, as a URL with a credential might.

use reqwest::Url;

use crate::error::Error;

/// The API path of [`OpenAIOptions`](crate::OpenAIOptions) without one.
pub(crate) const DEFAULT_API_PATH: &str = "/v1/";

/// The API base: `api_path`, or [`DEFAULT_API_PATH`] when it is `None`,
/// joined under `root` (the HTTP client's base URL, whose path ends in
/// `/`), ending in `/`, so that request paths join under it.
///
/// A configuration error for an API path that [`validate`] refuses, and for
/// one that parsing would rewrite, so that the API base is the path as the
/// caller wrote it.
pub(crate) fn join(root: &Url, api_path: Option<&str>) -> Result<Url, Error> {
    let api_path = api_path.unwrap_or(DEFAULT_API_PATH);
    validate(api_path)?;
    let mut path = format!("{}{api_path}", root.path().trim_end_matches('/'));
    if !path.ends_with('/') {
        path.push('/');
    }
    let mut joined = root.clone();
    joined.set_path(&path);
    if joined.path() != path {
        return Err(invalid("it is not a URL path as written"));
    }
    Ok(joined)
}

/// Requires an absolute path that can only name a path under its root, in
/// this order, each a configuration error:
///
/// 1. it does not start with `/`, or it starts with `//`;
/// 2. it contains `?` or `#`: a query or a fragment;
/// 3. it contains whitespace, a control character or a backslash, which a
///    URL parser would drop or rewrite;
/// 4. a segment has a `%` that does not start an escape of two hex digits;
/// 5. a segment is `.` or `..`, or contains `/`, once percent-decoded.
pub(crate) fn validate(api_path: &str) -> Result<(), Error> {
    if !api_path.starts_with('/') || api_path.starts_with("//") {
        return Err(invalid("it must be an absolute path, such as /v1/"));
    }
    if api_path.contains(['?', '#']) {
        return Err(invalid("it must not carry a query or a fragment"));
    }
    if api_path
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(invalid(
            "it contains whitespace, a control character or a backslash",
        ));
    }
    for segment in api_path.split('/') {
        let decoded = percent_decode(segment)
            .ok_or_else(|| invalid("it has a % that does not start an escape"))?;
        if decoded == b"." || decoded == b".." || decoded.contains(&b'/') {
            return Err(invalid(
                "it must not contain a \".\" or \"..\" segment or an encoded slash",
            ));
        }
    }
    Ok(())
}

/// The bytes of `segment` with its percent escapes decoded; `None` when a
/// `%` is not followed by two hex digits.
fn percent_decode(segment: &str) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(segment.len());
    let mut bytes = segment.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            decoded.push(byte);
            continue;
        }
        let pair = [bytes.next()?, bytes.next()?];
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let text = std::str::from_utf8(&pair).ok()?;
        decoded.push(u8::from_str_radix(text, 16).ok()?);
    }
    Some(decoded)
}

fn invalid(reason: &str) -> Error {
    Error::configuration(format!("invalid API path: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn url(text: &str) -> Url {
        Url::parse(text).unwrap()
    }

    #[test]
    fn the_api_path_joins_under_the_root_whether_or_not_it_ends_with_a_slash() {
        let cases = [
            (
                "https://enclave.example.com/",
                None,
                "https://enclave.example.com/v1/",
            ),
            (
                "https://proxy.example/relay/",
                None,
                "https://proxy.example/relay/v1/",
            ),
            (
                "https://proxy.example/relay",
                None,
                "https://proxy.example/relay/v1/",
            ),
            (
                "https://enclave.example.com/",
                Some("/"),
                "https://enclave.example.com/",
            ),
            (
                "https://enclave.example.com/",
                Some("/api"),
                "https://enclave.example.com/api/",
            ),
            (
                "https://proxy.example/relay/",
                Some("/openai/v1"),
                "https://proxy.example/relay/openai/v1/",
            ),
            (
                "http://localhost:8080/",
                Some("/v1/"),
                "http://localhost:8080/v1/",
            ),
            (
                "https://enclave.example.com/",
                Some("/v%31/"),
                "https://enclave.example.com/v%31/",
            ),
        ];
        for (root, api_path, want) in cases {
            let joined = join(&url(root), api_path).unwrap();
            assert_eq!(joined.as_str(), want, "{root} {api_path:?}");
        }
    }

    #[test]
    fn an_api_path_that_could_leave_its_root_is_refused() {
        let refused = [
            ("", "absolute path"),
            ("v1/", "absolute path"),
            ("//evil.example/v1/", "absolute path"),
            ("https://evil.example/v1/", "absolute path"),
            ("/v1/?", "query or a fragment"),
            ("/v1?key=1", "query or a fragment"),
            ("/v1/#", "query or a fragment"),
            ("/v1 /", "whitespace"),
            ("/v1/\t", "whitespace"),
            ("/v1\\..\\x", "backslash"),
            ("/v1/\u{0}", "control"),
            ("/v1/%", "escape"),
            ("/v1/%2", "escape"),
            ("/v1/%zz/", "escape"),
            ("/.", "segment"),
            ("/..", "segment"),
            ("/v1/../admin/", "segment"),
            ("/v1/./", "segment"),
            ("/%2e%2e/admin/", "segment"),
            ("/%2E/", "segment"),
            ("/.%2e/", "segment"),
            ("/v1%2fadmin/", "encoded slash"),
            ("/v1%2Fadmin/", "encoded slash"),
            ("/v1/é/", "as written"),
            ("/v1/\"/", "as written"),
        ];
        for (api_path, reason) in refused {
            let error =
                join(&url("https://enclave.example.com/"), Some(api_path)).expect_err(api_path);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{api_path:?}");
            let message = error.to_string();
            assert!(message.contains("invalid API path"), "{message}");
            assert!(message.contains(reason), "{api_path:?}: {message}");
        }
    }
}
