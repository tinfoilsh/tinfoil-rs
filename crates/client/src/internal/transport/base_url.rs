//! The rules for a client's base URL (where requests go instead of the
//! enclave's own origin: a path on that origin, or a proxy on another) and
//! for the origins that requests are compared by.
//!
//! No error from this module repeats the URL or the host that it refuses:
//! either may hold a credential.

use reqwest::Url;

use crate::error::Error;

/// Checks a `base_url` option and returns it parsed, with its path made to
/// end in `/` so that a relative path joins under it.
///
/// The text must be an absolute `http://` or `https://` URL as a caller
/// would write one deliberately: the scheme, `://`, then a host. Each
/// failure is a configuration error, checked in this order:
///
/// 1. it is empty;
/// 2. it contains whitespace, a control character or a backslash, which a
///    URL parser would silently drop or rewrite;
/// 3. it does not start with `http://` or `https://` (in any case), or no
///    host follows;
/// 4. its authority contains `@` (a user name or a password, even an empty
///    one) or `%`;
/// 5. it contains `?` or `#`: a query string or a fragment, even an empty
///    one, which joining a path would drop;
/// 6. it does not parse as a URL with a host;
/// 7. it is `http://` to a host other than `localhost` or a loopback IP
///    address, as written. Other names are not resolved, so DNS cannot make
///    a remote host pass. Headers are not sealed in any transport mode, so
///    plaintext is accepted only where the traffic never leaves the machine.
///
/// The parsed URL is normalized as URLs are everywhere else in the client:
/// the scheme and host in lowercase, an internationalized host in its
/// ASCII form, a default port removed, and dot segments of the path
/// resolved.
pub(crate) fn validate(base_url: &str) -> Result<Url, Error> {
    if base_url.is_empty() {
        return Err(invalid("it is empty"));
    }
    if base_url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(invalid(
            "it contains whitespace, a control character or a backslash",
        ));
    }
    let rest = strip_prefix_ignore_case(base_url, "https://")
        .or_else(|| strip_prefix_ignore_case(base_url, "http://"))
        .ok_or_else(|| {
            invalid("it must be an absolute URL that starts with https:// or http://")
        })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(invalid("it has no host"));
    }
    if authority.contains('@') {
        return Err(invalid("it must not carry a user name or a password"));
    }
    if authority.contains('%') {
        return Err(invalid("its host must not be percent-encoded"));
    }
    if base_url.contains(['?', '#']) {
        return Err(invalid("it must not carry a query string or a fragment"));
    }
    let mut url = Url::parse(base_url).map_err(|_| invalid("it is not a valid URL"))?;
    let Some(host) = url.host() else {
        return Err(invalid("it has no host"));
    };
    if url.scheme() == "http" && !is_loopback_host(&host) {
        return Err(invalid(
            "HTTP is allowed only for localhost or a loopback IP address; use HTTPS to protect request headers",
        ));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// Requires a base URL in the TLS mode to be on the enclave's own origin: a
/// pinned connection cannot pass through a proxy. Each failure is a
/// configuration error: an enclave host that yields no origin, or a base
/// URL on another origin.
pub(crate) fn validate_for_tls(base_url: &Url, enclave_host: &str) -> Result<(), Error> {
    if origin_of(base_url)? == enclave_origin(enclave_host)? {
        return Ok(());
    }
    Err(Error::configuration(
        "a base URL off the verified enclave's origin is a proxy, which requires TransportMode::Ehbp",
    ))
}

/// The normalized origin of an `http` or `https` URL: the scheme and the
/// host in lowercase, the port unless it is the scheme's default, and
/// brackets around an IPv6 address, as in `https://example.com:8443`. A
/// URL of another scheme, or without a host, is a configuration error.
pub(crate) fn origin_of(url: &Url) -> Result<String, Error> {
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(Error::configuration(
            "a URL must use http or https and name a host",
        ));
    }
    Ok(url.origin().ascii_serialization())
}

/// The origin, `https://<host>`, of an enclave given as a host with an
/// optional port. See [`authority_url`] for what is refused.
pub(crate) fn enclave_origin(host: &str) -> Result<String, Error> {
    origin_of(&authority_url(host)?)
}

/// `https://<authority>/` for a host with an optional port.
///
/// A value that is not exactly that is a configuration error: an empty
/// value; one with whitespace or a control character; one that carries a
/// scheme, a path, a query, a fragment, user information, a backslash or a
/// percent sign; and one that does not parse as the authority of a URL.
pub(crate) fn authority_url(authority: &str) -> Result<Url, Error> {
    let refused = || Error::configuration("an enclave host must be a host with an optional port");
    if authority.is_empty()
        || authority.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '/' | '?' | '#' | '@' | '\\' | '%')
        })
    {
        return Err(refused());
    }
    let url = Url::parse(&format!("https://{authority}/")).map_err(|_| refused())?;
    if url.host().is_none() || url.path() != "/" {
        return Err(refused());
    }
    Ok(url)
}

/// Whether `host`, as written, is `localhost` or a loopback IP address.
pub(crate) fn is_loopback(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_loopback_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(address) => address.is_loopback(),
        url::Host::Ipv6(address) => address.is_loopback(),
    }
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}

fn invalid(reason: &str) -> Error {
    Error::configuration(format!("invalid base URL: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn a_base_url_that_is_not_a_plain_absolute_http_url_is_refused() {
        let refused = [
            // Empty, or not a URL at all.
            ("", "empty"),
            ("proxy.example.com", "starts with"),
            ("/v1/", "starts with"),
            ("//proxy.example.com/", "starts with"),
            // Another scheme.
            ("ftp://proxy.example.com/", "starts with"),
            ("wss://proxy.example.com/", "starts with"),
            ("file:///etc/passwd", "starts with"),
            // A scheme without the two slashes.
            ("https:proxy.example.com", "starts with"),
            ("https:/proxy.example.com", "starts with"),
            // No host.
            ("https://", "no host"),
            ("https:///v1/", "no host"),
            ("http://?x", "no host"),
            // Text that a parser would rewrite without saying so.
            (" https://proxy.example.com/", "whitespace"),
            ("https://proxy.example.com/ ", "whitespace"),
            ("https://proxy.exa\tmple.com/", "whitespace"),
            ("https://proxy.example.com/\n", "whitespace"),
            ("https://proxy.example.com/a b", "whitespace"),
            ("https:\\\\proxy.example.com\\v1", "backslash"),
            ("https://proxy.example.com\\@evil.example/", "backslash"),
            ("https://proxy.example.com/\u{0}", "control"),
            // Credentials, even empty ones.
            ("https://user@proxy.example.com/", "user name"),
            ("https://user:hunter2@proxy.example.com/", "user name"),
            ("https://:hunter2@proxy.example.com/", "user name"),
            ("https://@proxy.example.com/", "user name"),
            // A percent-encoded host.
            ("https://proxy%2eexample.com/", "percent-encoded"),
            // A query string or a fragment, even an empty one.
            ("https://proxy.example.com/?", "query"),
            ("https://proxy.example.com/v1?key=1", "query"),
            ("https://proxy.example.com/#", "query"),
            ("https://proxy.example.com/v1#top", "query"),
            ("https://proxy.example.com?x=1", "query"),
            // Hosts that do not parse.
            ("https://exa mple.com/", "whitespace"),
            ("https://[::1/", "not a valid URL"),
            ("https://::1/", "not a valid URL"),
            ("https://proxy.example.com:99999/", "not a valid URL"),
            ("https://proxy.example.com:port/", "not a valid URL"),
            ("https://xn--/", "not a valid URL"),
            // Plaintext to a host that is not this machine.
            ("http://proxy.example.com/", "HTTP is allowed only"),
            ("http://localhost.example.com/", "HTTP is allowed only"),
            ("http://localhost./", "HTTP is allowed only"),
            ("http://10.0.0.1/", "HTTP is allowed only"),
            ("http://0.0.0.0/", "HTTP is allowed only"),
            ("http://[::2]/", "HTTP is allowed only"),
            ("http://[::ffff:127.0.0.1]/", "HTTP is allowed only"),
            ("http://128.0.0.1/", "HTTP is allowed only"),
        ];
        for (input, reason) in refused {
            let error = validate(input).expect_err(input);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{input:?}");
            let message = error.to_string();
            assert!(message.contains(reason), "{input:?}: {message}");
        }
    }

    #[test]
    fn no_refusal_repeats_the_url() {
        for input in [
            "https://user:hunter2@proxy.example.com/",
            "ftp://user:hunter2@proxy.example.com/",
            "user:hunter2@proxy.example.com",
            "https://user:hunter2@proxy.example.com/?token=hunter2",
            "https://user:hunter2@[::1/",
            "http://user:hunter2@proxy.example.com/",
            " https://user:hunter2@proxy.example.com/",
        ] {
            let message = validate(input).expect_err(input).to_string();
            assert!(!message.contains("hunter2"), "{message}");
            assert!(!message.contains("proxy.example"), "{message}");
        }
    }

    #[test]
    fn an_accepted_base_url_is_normalized_and_ends_in_a_slash() {
        let accepted = [
            // The trailing slash rule.
            ("https://proxy.example.com", "https://proxy.example.com/"),
            ("https://proxy.example.com/", "https://proxy.example.com/"),
            (
                "https://proxy.example.com/v1",
                "https://proxy.example.com/v1/",
            ),
            (
                "https://proxy.example.com/v1/",
                "https://proxy.example.com/v1/",
            ),
            (
                "https://proxy.example.com/a/b/c",
                "https://proxy.example.com/a/b/c/",
            ),
            // Case, and the default port.
            (
                "HTTPS://Proxy.Example.COM/V1",
                "https://proxy.example.com/V1/",
            ),
            (
                "https://proxy.example.com:443/",
                "https://proxy.example.com/",
            ),
            (
                "https://proxy.example.com:8443/",
                "https://proxy.example.com:8443/",
            ),
            ("https://proxy.example.com:/", "https://proxy.example.com/"),
            ("http://localhost:80/", "http://localhost/"),
            // A trailing dot is part of the host.
            ("https://proxy.example.com./", "https://proxy.example.com./"),
            // An internationalized host, in either form.
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
            (
                "https://xn--bcher-kva.example/",
                "https://xn--bcher-kva.example/",
            ),
            // IP literals.
            ("https://192.0.2.7/", "https://192.0.2.7/"),
            ("https://[2001:db8::1]/", "https://[2001:db8::1]/"),
            (
                "https://[2001:DB8:0:0:0:0:0:1]:8443/x",
                "https://[2001:db8::1]:8443/x/",
            ),
            // Dot segments are resolved.
            (
                "https://proxy.example.com/a/../b",
                "https://proxy.example.com/b/",
            ),
            (
                "https://proxy.example.com/a/./b/",
                "https://proxy.example.com/a/b/",
            ),
            // Plaintext to this machine.
            ("http://localhost/", "http://localhost/"),
            ("http://LOCALHOST:8080/v1", "http://localhost:8080/v1/"),
            ("http://127.0.0.1:8080", "http://127.0.0.1:8080/"),
            ("http://127.8.9.10/", "http://127.8.9.10/"),
            ("http://[::1]:8080/", "http://[::1]:8080/"),
            // Other spellings of an IPv4 loopback address parse to it.
            ("http://127.1/", "http://127.0.0.1/"),
            ("http://2130706433/", "http://127.0.0.1/"),
        ];
        for (input, expected) in accepted {
            let url = validate(input).unwrap_or_else(|error| panic!("{input:?}: {error}"));
            assert_eq!(url.as_str(), expected, "{input:?}");
            assert!(url.username().is_empty() && url.password().is_none());
            assert!(url.query().is_none() && url.fragment().is_none());
        }
    }

    #[test]
    fn a_relative_path_joins_under_an_accepted_base_url() {
        let base = validate("https://proxy.example.com/tinfoil").expect("valid");
        let joined = base.join("v1/chat/completions").expect("joins");
        assert_eq!(
            joined.as_str(),
            "https://proxy.example.com/tinfoil/v1/chat/completions"
        );
    }

    #[test]
    fn origins_compare_equal_whatever_the_spelling() {
        let same = [
            ("https://example.com/", "https://EXAMPLE.com:443/path"),
            ("http://localhost/", "http://localhost:80/x"),
            (
                "https://[2001:db8::1]/",
                "https://[2001:DB8:0:0:0:0:0:1]:443/",
            ),
            ("https://bücher.example/", "https://xn--bcher-kva.example/"),
        ];
        for (a, b) in same {
            let a = origin_of(&Url::parse(a).expect("url")).expect("origin");
            let b = origin_of(&Url::parse(b).expect("url")).expect("origin");
            assert_eq!(a, b);
        }
        let different = [
            ("https://example.com/", "http://example.com/"),
            ("https://example.com/", "https://example.com:8443/"),
            ("https://example.com/", "https://example.com./"),
            ("https://example.com/", "https://www.example.com/"),
            ("https://[::1]/", "https://127.0.0.1/"),
        ];
        for (a, b) in different {
            let a = origin_of(&Url::parse(a).expect("url")).expect("origin");
            let b = origin_of(&Url::parse(b).expect("url")).expect("origin");
            assert_ne!(a, b);
        }
        assert_eq!(
            origin_of(&Url::parse("https://example.com:8443/x").expect("url")).expect("origin"),
            "https://example.com:8443"
        );
        assert_eq!(
            origin_of(&Url::parse("https://[2001:db8::1]/").expect("url")).expect("origin"),
            "https://[2001:db8::1]"
        );
    }

    #[test]
    fn a_url_of_another_scheme_has_no_origin() {
        for input in ["ftp://example.com/", "data:text/plain,x", "file:///tmp/x"] {
            let url = Url::parse(input).expect("url");
            assert_eq!(
                origin_of(&url).expect_err(input).kind(),
                ErrorKind::Configuration
            );
        }
    }

    #[test]
    fn an_enclave_host_is_a_host_with_an_optional_port_and_nothing_else() {
        let accepted = [
            ("enclave.example.com", "https://enclave.example.com"),
            ("Enclave.Example.COM", "https://enclave.example.com"),
            ("enclave.example.com:443", "https://enclave.example.com"),
            (
                "enclave.example.com:8443",
                "https://enclave.example.com:8443",
            ),
            ("192.0.2.7:8443", "https://192.0.2.7:8443"),
            ("[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
            ("localhost", "https://localhost"),
        ];
        for (host, origin) in accepted {
            assert_eq!(enclave_origin(host).expect(host), origin, "{host:?}");
        }
        for host in [
            "",
            " enclave.example.com",
            "enclave.example.com ",
            "https://enclave.example.com",
            "enclave.example.com/",
            "enclave.example.com/v1",
            "enclave.example.com?x=1",
            "enclave.example.com#x",
            "user@enclave.example.com",
            "user:hunter2@enclave.example.com",
            "enclave.example.com\\x",
            "enclave%2eexample.com",
            "::1",
            "[::1",
            "enclave.example.com:99999",
            "enclave.example.com:port",
            "enclave.example.com\n",
        ] {
            let error = enclave_origin(host).expect_err(host);
            assert_eq!(error.kind(), ErrorKind::Configuration, "{host:?}");
            assert!(!error.to_string().contains("hunter2"));
        }
    }

    #[test]
    fn a_tls_base_url_must_be_on_the_enclaves_origin() {
        let on_origin = [
            ("https://enclave.example.com/", "enclave.example.com"),
            ("https://enclave.example.com/api/v1/", "enclave.example.com"),
            (
                "https://ENCLAVE.example.com:443/api/",
                "enclave.example.com",
            ),
            (
                "https://enclave.example.com:8443/",
                "enclave.example.com:8443",
            ),
        ];
        for (base, host) in on_origin {
            let base = validate(base).expect("valid");
            assert!(validate_for_tls(&base, host).is_ok(), "{base} on {host}");
        }
        let off_origin = [
            ("https://proxy.example.com/", "enclave.example.com"),
            ("https://enclave.example.com:8443/", "enclave.example.com"),
            ("https://enclave.example.com/", "enclave.example.com:8443"),
            ("http://localhost/", "localhost"),
            ("https://enclave.example.com./", "enclave.example.com"),
        ];
        for (base, host) in off_origin {
            let base = validate(base).expect("valid");
            let error = validate_for_tls(&base, host).expect_err("off the origin");
            assert_eq!(error.kind(), ErrorKind::Configuration);
            assert!(error.to_string().contains("TransportMode::Ehbp"));
        }
        let base = validate("https://enclave.example.com/").expect("valid");
        assert!(validate_for_tls(&base, "enclave.example.com/x").is_err());
    }

    #[test]
    fn loopback_is_judged_from_the_host_as_written() {
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "[::1]",
        ] {
            assert!(is_loopback(host), "{host}");
        }
        for host in [
            "example.com",
            "localhost.example.com",
            "10.0.0.1",
            "0.0.0.0",
            "::2",
        ] {
            assert!(!is_loopback(host), "{host}");
        }
    }
}
