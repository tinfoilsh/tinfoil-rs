//! The rules for a client's base URL: where requests go instead of the
//! enclave's own origin, which is a path on that origin or a proxy on
//! another.

use reqwest::Url;

use crate::error::Error;

/// Checks a `base_url` option and returns it parsed, with its path made to
/// end in `/` so that a relative path joins under it. Each failure is a
/// configuration error, in this order:
///
/// 1. it is not an absolute `http` or `https` URL;
/// 2. it carries a user name or a password. This error does not repeat the
///    URL, and it comes before every error that does;
/// 3. it carries a query string or a fragment, which joining a path would
///    drop;
/// 4. it is `http://` to a host other than `localhost` or a loopback IP
///    address, as written. Other names are not resolved, so DNS cannot make
///    a remote host pass. Headers are not sealed in any mode, so plaintext
///    is accepted only where the traffic never leaves the machine.
pub(crate) fn validate(base_url: &str) -> Result<Url, Error> {
    Err(Error::not_implemented("base URL validation"))
}

/// Requires a base URL in the TLS mode to be on the enclave's own origin: a
/// pinned connection cannot pass through a proxy. A configuration error
/// that names the enclave's origin and the mode to use instead.
pub(crate) fn validate_for_tls(base_url: &Url, enclave_host: &str) -> Result<(), Error> {
    Err(Error::not_implemented("base URL validation"))
}

/// The normalized origin of an absolute `http` or `https` URL: lowercase
/// scheme and host, no default port, brackets around an IPv6 address.
pub(crate) fn origin_of(url: &Url) -> Result<String, Error> {
    Err(Error::not_implemented("origin normalization"))
}

/// The origin of an enclave given as a host with an optional port. A value
/// that is not exactly that (it carries a scheme, a path, a query, a
/// fragment or user information) is a configuration error.
pub(crate) fn enclave_origin(host: &str) -> Result<String, Error> {
    Err(Error::not_implemented("origin normalization"))
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

#[cfg(test)]
mod tests {
    use super::*;

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
