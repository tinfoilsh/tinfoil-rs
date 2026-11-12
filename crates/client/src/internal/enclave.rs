//! One enclave and the policy that its attestation is verified against.
//!
//! An [`Enclave`] keeps no state between verifications. The
//! [`Transport`](super::transport::Transport) caches what it verifies and
//! binds traffic to the keys that the verification endorses.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::error::Error;
use crate::internal::{BoxFuture, Clock};
use crate::options::{Check, VerificationCheck};
use crate::verifier::{Verification, Verifier};

/// The pause before the one retry of a failed verification.
pub(crate) const RETRY_DELAY: Duration = Duration::from_secs(1);

/// What the transports read from a verification: the keys to bind traffic
/// to and the time until which it authorizes requests.
///
/// The clients use [`Verification`]. The trait exists so that the tests of
/// this crate's state handling can run on a record of their own, since
/// only the verifier can build a `Verification`.
pub(crate) trait Evidence: Send + Sync + 'static {
    /// The endorsed TLS key fingerprint.
    fn tls_public_key_fp(&self) -> Option<&str>;
    /// The endorsed HPKE public key.
    fn hpke_public_key(&self) -> Option<&str>;
    /// When the evidence stops authorizing requests. `None` is evidence
    /// without a deadline, which a client does not accept: it is treated as
    /// expired.
    fn freshness_expires_at(&self) -> Option<SystemTime>;
}

impl Evidence for Verification {
    fn tls_public_key_fp(&self) -> Option<&str> {
        Verification::tls_public_key_fp(self)
    }

    fn hpke_public_key(&self) -> Option<&str> {
        Verification::hpke_public_key(self)
    }

    fn freshness_expires_at(&self) -> Option<SystemTime> {
        Verification::freshness_expires_at(self)
    }
}

/// Whether `evidence` authorizes a request at `now`: it has a deadline, and
/// `now` is before it.
pub(crate) fn fresh_at(evidence: &impl Evidence, now: SystemTime) -> bool {
    evidence
        .freshness_expires_at()
        .is_some_and(|deadline| now < deadline)
}

/// One attempt to obtain evidence: fetch a document and verify it.
pub(crate) type Source<V> = Arc<dyn Fn() -> BoxFuture<Result<V, Error>> + Send + Sync + 'static>;

/// What describes an [`Enclave`].
pub(crate) struct Config {
    /// The enclave: a host with an optional port.
    pub(crate) host: String,
    /// A host that fetches the attestation document on the client's behalf.
    pub(crate) relay: Option<String>,
    /// The repository pin, `org/project[@revision][@sha256:digest]`, or
    /// empty to accept a config that the verifier authorizes.
    pub(crate) repo: String,
    /// The policy; `None` selects the default verifier.
    pub(crate) verifier: Option<Arc<Verifier>>,
    /// The caller's veto.
    pub(crate) verification_check: Option<VerificationCheck>,
}

/// One enclave and the policy that its attestation is verified against.
pub(crate) struct Enclave<V = Verification> {
    host: String,
    repo: String,
    verifier: Option<Arc<Verifier>>,
    source: Source<V>,
    check: Option<Check<V>>,
    clock: Clock,
}

impl Enclave<Verification> {
    /// Checks `config.repo` against the verifier's rules for a repository
    /// pin (`Verifier::check_repo_verifiability`) and does no I/O. A usage
    /// error from the verifier is a configuration error.
    pub(crate) fn new(config: Config) -> Result<Self, Error> {
        Err(Error::not_implemented("the enclave"))
    }

    /// The verification policy, which several enclaves can share.
    pub(crate) fn verifier(&self) -> Option<&Arc<Verifier>> {
        self.verifier.as_ref()
    }
}

impl<V: Evidence> Enclave<V> {
    /// The enclave's host.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// The repository pin, with any tag or digest; empty without one.
    pub(crate) fn repo(&self) -> &str {
        &self.repo
    }

    /// Fetches and verifies the enclave's attestation, and tries once more
    /// after [`RETRY_DELAY`] when the first attempt fails with a network or
    /// attestation error.
    ///
    /// One attempt, in order:
    ///
    /// 1. a fresh random nonce;
    /// 2. the document fetch ([`fetch::document`](super::fetch::document)),
    ///    under no caller's deadline, since one verification serves every
    ///    request that waits for it;
    /// 3. `Verifier::verify_v3` with the nonce and the repository pin: a
    ///    usage error is a configuration error, any other rejection is an
    ///    attestation error with the verifier's error as its source;
    /// 4. the key checks of [`validate_transport_keys`];
    /// 5. the freshness deadline against the clock (evidence with no
    ///    deadline counts as expired);
    /// 6. the caller's veto, given the verification; a rejection is an
    ///    attestation error that names the host and wraps the caller's
    ///    error;
    /// 7. the freshness deadline again, since the veto may have run past
    ///    it.
    ///
    /// A configuration error and a veto are never retried. When the retry
    /// fails too, its error is returned with the first attempt's error
    /// attached ([`Error::earlier_attempt`]).
    ///
    /// Dropping the future abandons the attempt; nothing is kept.
    pub(crate) async fn verify(&self) -> Result<V, Error> {
        Err(Error::not_implemented("enclave verification"))
    }

    /// As [`verify`](Self::verify) without the retry, so that a caller that
    /// tries several enclaves moves on quickly.
    pub(crate) async fn verify_once(&self) -> Result<V, Error> {
        Err(Error::not_implemented("enclave verification"))
    }
}

/// Requires the keys that a transport binds traffic to. An attestation
/// error when:
///
/// - the document endorses a `tls` item in a format other than the SPKI
///   SHA-256 fingerprint;
/// - it endorses no TLS key at all, which is required in every transport
///   mode;
/// - it endorses an `hpke` item in a format other than X25519 HPKE.
///
/// A document without an HPKE key passes here; the sealed-body transport
/// refuses it when it is asked to bind to one.
pub(crate) fn validate_transport_keys(verification: &Verification) -> Result<(), Error> {
    Err(Error::not_implemented("the transport key checks"))
}

/// A verifier error in the client's categories, by its outermost type: a
/// usage error is the caller's configuration error, and any rejection is an
/// attestation error. The verifier's error stays the source.
pub(crate) fn from_verifier(error: crate::verifier::Error) -> Error {
    use crate::error::ErrorKind;
    match error {
        crate::verifier::Error::Usage(_) => Error::wrap(ErrorKind::Configuration, error),
        _ => Error::wrap(ErrorKind::Attestation, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn a_usage_error_is_a_configuration_error_and_keeps_its_source() {
        let usage = Verifier::new()
            .check_repo_verifiability("not a reference")
            .expect_err("an invalid reference is refused");
        let error = from_verifier(usage);
        assert_eq!(error.kind(), ErrorKind::Configuration);
        let source = std::error::Error::source(&error).expect("the verifier's error");
        assert!(source.is::<crate::verifier::Error>());
    }

    struct Record(Option<SystemTime>);

    impl Evidence for Record {
        fn tls_public_key_fp(&self) -> Option<&str> {
            None
        }
        fn hpke_public_key(&self) -> Option<&str> {
            None
        }
        fn freshness_expires_at(&self) -> Option<SystemTime> {
            self.0
        }
    }

    #[test]
    fn evidence_is_fresh_strictly_before_its_deadline_and_never_without_one() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert!(fresh_at(&Record(Some(now + Duration::from_secs(1))), now));
        assert!(!fresh_at(&Record(Some(now)), now));
        assert!(!fresh_at(&Record(None), now));
    }
}
