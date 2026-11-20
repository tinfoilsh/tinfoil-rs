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
    // One separator only: a root that ends in `//` keeps its empty segment.
    let root_path = root.path().strip_suffix('/').unwrap_or(root.path());
    let mut path = format!("{root_path}{api_path}");
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

/// Requires an RFC 3986 `path-absolute` that can only name a path under its
/// root and that every URL parser reads as it is written, in this order,
/// each a configuration error:
///
/// 1. it does not start with `/`, or it starts with `//`;
/// 2. it contains `?` or `#`: a query or a fragment;
/// 3. it contains a byte that is not a path character ([`is_path_char`]):
///    an unreserved character, a sub-delimiter, `:`, `@`, `%` or `/`;
/// 4. a segment has a `%` that does not start an escape of two hex digits;
/// 5. a segment is `.` or `..`, or contains `/` or `\`, once
///    percent-decoded.
///
/// Any other well-formed escape is accepted, also one of a byte that is not
/// UTF-8, such as `%ff`.
pub(crate) fn validate(api_path: &str) -> Result<(), Error> {
    if !api_path.starts_with('/') || api_path.starts_with("//") {
        return Err(invalid("it must be an absolute path, such as /v1/"));
    }
    if api_path.contains(['?', '#']) {
        return Err(invalid("it must not carry a query or a fragment"));
    }
    if !api_path.bytes().all(is_path_char) {
        return Err(invalid("it must consist only of RFC 3986 path characters"));
    }
    for segment in api_path.split('/') {
        let decoded = percent_decode(segment)
            .ok_or_else(|| invalid("it has a % that does not start an escape"))?;
        if decoded == b"." || decoded == b".." || decoded.iter().any(|b| matches!(b, b'/' | b'\\'))
        {
            return Err(invalid(
                "it must not contain a \".\" or \"..\" segment or an encoded slash or backslash",
            ));
        }
    }
    Ok(())
}

/// Whether `byte` may appear in an API path as written: an RFC 3986
/// `pchar` (unreserved `A-Z a-z 0-9 - . _ ~`, a sub-delimiter
/// `! $ & ' ( ) * + , ; =`, `:` or `@`), the `%` of an escape, or the `/`
/// between segments.
fn is_path_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@%/".contains(&byte)
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
                "https://proxy.example/relay//",
                None,
                "https://proxy.example/relay//v1/",
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
    fn an_api_path_outside_the_rules_is_refused() {
        let refused = [
            ("", "absolute path"),
            ("v1", "absolute path"),
            ("v1/", "absolute path"),
            ("//evil.example/v1/", "absolute path"),
            ("https://evil.example/v1/", "absolute path"),
            ("/v1/?q=1", "query or a fragment"),
            ("/v1/#f", "query or a fragment"),
            ("/v1?", "query or a fragment"),
            ("/v1/../admin", "segment"),
            ("/..", "segment"),
            ("/.", "segment"),
            ("/./v1", "segment"),
            ("/%2e%2e/admin", "segment"),
            ("/v1/%2E/", "segment"),
            ("/.%2e/", "segment"),
            ("/a%2fb/", "encoded slash"),
            ("/a%2Fb/", "encoded slash"),
            ("/a%5cb/", "backslash"),
            ("/a%5C..%5Cb/", "backslash"),
            ("/%zz/", "escape"),
            ("/v1/%", "escape"),
            ("/v1/%2", "escape"),
            ("/v1\\..\\admin/", "RFC 3986"),
            ("/v1 /", "RFC 3986"),
            ("/v1\n/", "RFC 3986"),
            ("/v\t1/", "RFC 3986"),
            ("/v1\r/", "RFC 3986"),
            ("/v1\u{0}/", "RFC 3986"),
            ("/v1\u{7f}/", "RFC 3986"),
            ("/v1/\u{a0}/", "RFC 3986"),
            ("/v1/\u{2028}/", "RFC 3986"),
            ("/v1/\u{e9}/", "RFC 3986"),
            ("/v1/\"/", "RFC 3986"),
            ("/v1/</", "RFC 3986"),
            ("/v1/>/", "RFC 3986"),
            ("/v1/[/", "RFC 3986"),
            ("/v1/]/", "RFC 3986"),
            ("/v1/^/", "RFC 3986"),
            ("/v1/`/", "RFC 3986"),
            ("/v1/{/", "RFC 3986"),
            ("/v1/|/", "RFC 3986"),
            ("/v1/}/", "RFC 3986"),
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

    #[test]
    fn every_rfc_3986_path_character_and_every_other_escape_is_accepted() {
        for api_path in [
            "/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/0123456789/",
            "/-._~/",
            "/!$&'()*+,;=/",
            "/:@/",
            "/v%31/",
            "/a%20b/",
            "/%c3%a9/",
            "/%ff/",
            "/%2e%2e%2e/",
            "/.well-known/",
            "/.../",
        ] {
            let joined = join(&url("https://enclave.example.com/"), Some(api_path))
                .unwrap_or_else(|error| panic!("{api_path:?}: {error}"));
            assert_eq!(
                joined.as_str(),
                format!("https://enclave.example.com{api_path}"),
                "{api_path:?}"
            );
        }
    }

    /// The characters that an API path may hold as written, `%` aside.
    const PATH_CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/";

    #[test]
    fn every_byte_is_accepted_exactly_when_it_is_a_path_character() {
        let root = url("https://enclave.example.com/");
        for byte in 0..=u8::MAX {
            let api_path = [b"/a".as_slice(), &[byte], b"b/"].concat();
            let accepted = PATH_CHARS.contains(&byte);
            // A byte that is not ASCII alone is no `str`, and no path.
            let Ok(api_path) = std::str::from_utf8(&api_path) else {
                assert!(!accepted, "{byte:#04x}");
                continue;
            };
            let result = join(&root, Some(api_path));
            assert_eq!(result.is_ok(), accepted, "{byte:#04x}: {result:?}");
            if let Ok(joined) = result {
                assert_eq!(joined.path(), api_path, "{byte:#04x}");
            }
        }
        // And every character outside ASCII.
        for c in [
            '\u{80}',
            '\u{a0}',
            '\u{e9}',
            '\u{2028}',
            '\u{fffd}',
            '\u{1f600}',
        ] {
            let api_path = format!("/a{c}b/");
            assert!(join(&root, Some(&api_path)).is_err(), "{c:?}");
        }
    }

    #[test]
    fn every_escape_is_accepted_except_a_slash_or_a_backslash() {
        let root = url("https://enclave.example.com/");
        for byte in 0..=u8::MAX {
            for escape in [format!("%{byte:02x}"), format!("%{byte:02X}")] {
                let api_path = format!("/a{escape}b/");
                let accepted = !matches!(byte, b'/' | b'\\');
                let result = join(&root, Some(&api_path));
                assert_eq!(result.is_ok(), accepted, "{api_path}: {result:?}");
                if let Ok(joined) = result {
                    assert_eq!(joined.path(), api_path);
                }
                // An escape that is a whole segment: only `.` is refused,
                // since `.` alone is the dot segment.
                let api_path = format!("/{escape}/");
                let accepted = !matches!(byte, b'/' | b'\\' | b'.');
                assert_eq!(join(&root, Some(&api_path)).is_ok(), accepted, "{api_path}");
            }
        }
    }
}
