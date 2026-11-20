//! The options that the client builders share.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::internal::transport::base_url;
use crate::verifier::{BoxError, Policy, Verification};

/// How a client protects its traffic to an enclave.
///
/// The default is [`Tls`](Transport::Tls), the stronger transport. A proxy
/// exists only inside [`Ehbp`](Transport::Ehbp), so that it cannot be
/// combined with a pinned connection.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transport {
    /// Pins every connection to the attested TLS key: the standard
    /// certificate checks run first, then the server's public key is
    /// compared with the attested fingerprint, on every handshake. It
    /// protects the whole request and response, and needs a direct
    /// connection to the enclave, so it takes no URL: requests go to the
    /// enclave's own HTTPS origin.
    #[default]
    Tls,
    /// Seals request and response bodies to the attested HPKE key, so that
    /// they stay private through a proxy. The method, URL and headers are
    /// not sealed, and neither is a request without a body or the response
    /// to it. Protocol upgrades, such as WebSockets, and `CONNECT` are
    /// refused, because nothing after the handshake would be sealed.
    Ehbp {
        /// A proxy that forwards requests to the enclave, which requests
        /// are then sent to; `None` sends them directly to the enclave.
        ///
        /// Requests to the proxy carry the `X-Tinfoil-Enclave-Url` header,
        /// set to `https://<enclave>`, so that the proxy can forward them.
        /// The proxy sees the method, the URL and the headers of every
        /// request, an API key among them.
        ///
        /// The URL must be absolute and use HTTPS; `http://` is accepted
        /// only for `localhost` or a loopback IP address, for a local
        /// development proxy or a sidecar. It must not carry a user name, a
        /// password, a query string or a fragment, even an empty one. Its
        /// path, if any, is where the proxy is mounted, and is made to end
        /// in `/`. An enclave client also refuses a proxy on the enclave's
        /// own origin, which is no proxy. Each mistake, an empty string
        /// among them, is a configuration error.
        proxy_url: Option<String>,
    },
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tls => f.write_str("Tls"),
            // The proxy URL has not been checked for credentials yet: only
            // whether it is set is printed.
            Transport::Ehbp { proxy_url } => f
                .debug_struct("Ehbp")
                .field("proxy_url", &proxy_url.as_ref().map(|_| "[set]"))
                .finish(),
        }
    }
}

/// The transport without its proxy: what the client's internals switch on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum TransportMode {
    /// [`Transport::Tls`].
    #[default]
    Tls,
    /// [`Transport::Ehbp`].
    Ehbp,
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportMode::Tls => "tls",
            TransportMode::Ehbp => "ehbp",
        })
    }
}

/// A veto over evidence of type `V` that passed the verifier.
pub(crate) type Check<V> = Arc<dyn Fn(&V) -> Result<(), BoxError> + Send + Sync + 'static>;

/// A caller's veto over a verification that passed the verifier.
pub(crate) type VerificationCheck = Check<Verification>;

/// A string that must not be printed: the user cache secret.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The secret itself, for the one place that sends it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The options that every route takes. A field is `None` until its setter
/// is called.
#[derive(Clone, Default)]
pub(crate) struct CommonOptions {
    pub(crate) policy: Policy,
    pub(crate) verification_check: Option<VerificationCheck>,
    pub(crate) user_cache_secret: Option<Secret>,
    pub(crate) timeout: Option<Duration>,
}

impl CommonOptions {
    /// A configuration error for a `user_cache_secret` that is empty or a
    /// `timeout` of zero: an option is either unset or has a value.
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self
            .user_cache_secret
            .as_ref()
            .is_some_and(|secret| secret.expose().is_empty())
        {
            return Err(Error::configuration(
                "the user cache secret is empty; leave the option unset instead",
            ));
        }
        if self.timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(Error::configuration(
                "the timeout is zero; leave the option unset for no deadline",
            ));
        }
        Ok(())
    }
}

impl RouteOptions {
    /// The mode of the `transport` option.
    pub(crate) fn mode(&self) -> TransportMode {
        match self.transport {
            Transport::Tls => TransportMode::Tls,
            Transport::Ehbp { .. } => TransportMode::Ehbp,
        }
    }

    /// The proxy URL of the `transport` option, checked and parsed; `None`
    /// when there is none.
    pub(crate) fn checked_proxy_url(&self) -> Result<Option<Url>, Error> {
        match &self.transport {
            Transport::Ehbp {
                proxy_url: Some(proxy_url),
            } => base_url::validate(proxy_url).map(Some),
            _ => Ok(None),
        }
    }
}

impl fmt::Debug for CommonOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonOptions")
            .field("policy", &self.policy)
            .field("verification_check", &self.verification_check.is_some())
            .field("user_cache_secret", &self.user_cache_secret)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// The options of the enclave and router routes.
#[derive(Clone, Default)]
pub(crate) struct RouteOptions {
    pub(crate) common: CommonOptions,
    pub(crate) transport: Transport,
}

impl fmt::Debug for RouteOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteOptions")
            .field("common", &self.common)
            .field("transport", &self.transport)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_the_cache_secret_or_an_unchecked_proxy_url() {
        let options = RouteOptions {
            common: CommonOptions {
                user_cache_secret: Some(Secret::new("s3cret-value")),
                ..CommonOptions::default()
            },
            transport: Transport::Ehbp {
                proxy_url: Some("https://user:hunter2@proxy.example/".into()),
            },
        };
        let printed = format!("{options:?}");
        assert!(!printed.contains("s3cret-value"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    #[test]
    fn the_default_transport_is_tls() {
        assert_eq!(Transport::default(), Transport::Tls);
        assert_eq!(RouteOptions::default().mode(), TransportMode::Tls);
        assert_eq!(TransportMode::Ehbp.to_string(), "ehbp");
    }
}
