//! The options that the client builders share.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;

use crate::error::Error;
use crate::internal::transport::base_url;
use crate::verifier::{BoxError, Verification, Verifier};

/// How a client protects its traffic to an enclave.
///
/// The default is [`Tls`](TransportMode::Tls), the stronger mode. A proxy
/// `base_url` requires [`Ehbp`](TransportMode::Ehbp).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportMode {
    /// Pins every connection to the attested TLS key: the standard
    /// certificate checks run first, then the server's public key is
    /// compared with the attested fingerprint, on every handshake. It
    /// protects the whole request and response, and needs a direct
    /// connection to the enclave.
    #[default]
    Tls,
    /// Seals request and response bodies to the attested HPKE key, so they
    /// stay private through a proxy. The method, URL and headers are not
    /// sealed, and neither is a request without a body or the response to
    /// it. Protocol upgrades, such as WebSockets, and `CONNECT` are refused,
    /// because nothing after the handshake would be sealed.
    Ehbp,
}

impl TransportMode {
    /// The mode's name: `tls` or `ehbp`.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportMode::Tls => "tls",
            TransportMode::Ehbp => "ehbp",
        }
    }
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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
    pub(crate) verifier: Option<Arc<Verifier>>,
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
    /// The transport mode: the option, or [`TransportMode::Tls`].
    pub(crate) fn mode(&self) -> TransportMode {
        self.transport_mode.unwrap_or_default()
    }

    /// The `base_url` option, checked and parsed; `None` when it is unset.
    pub(crate) fn checked_base_url(&self) -> Result<Option<Url>, Error> {
        self.base_url.as_deref().map(base_url::validate).transpose()
    }
}

impl fmt::Debug for CommonOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonOptions")
            .field("verifier", &self.verifier)
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
    pub(crate) transport_mode: Option<TransportMode>,
    pub(crate) base_url: Option<String>,
}

impl fmt::Debug for RouteOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The base URL has not been checked yet, so it may hold credentials:
        // only whether it was set is printed.
        f.debug_struct("RouteOptions")
            .field("common", &self.common)
            .field("transport_mode", &self.transport_mode)
            .field("base_url", &self.base_url.as_ref().map(|_| "[set]"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_shows_the_cache_secret_or_an_unchecked_base_url() {
        let options = RouteOptions {
            common: CommonOptions {
                user_cache_secret: Some(Secret::new("s3cret-value")),
                ..CommonOptions::default()
            },
            transport_mode: Some(TransportMode::Ehbp),
            base_url: Some("https://user:hunter2@proxy.example/".into()),
        };
        let printed = format!("{options:?}");
        assert!(!printed.contains("s3cret-value"), "{printed}");
        assert!(!printed.contains("hunter2"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    #[test]
    fn the_default_mode_is_tls() {
        assert_eq!(TransportMode::default(), TransportMode::Tls);
        assert_eq!(TransportMode::Ehbp.to_string(), "ehbp");
    }
}
