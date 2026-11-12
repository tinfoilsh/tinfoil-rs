//! One enclave and the policy that its attestation is verified against.
//!
//! An [`Enclave`] keeps no state between verifications. The
//! [`Transport`](super::transport::Transport) caches what it verifies and
//! binds traffic to the keys that the verification endorses.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::error::{Error, ErrorKind};
use crate::internal::transport::base_url::authority_url;
use crate::internal::{BoxFuture, Clock, fetch, system_clock};
use crate::options::{Check, VerificationCheck};
use crate::verifier::{
    BoxError, CRYPTO_MATERIAL_ID_HPKE, CRYPTO_MATERIAL_ID_TLS, CryptoMaterialItem,
    KEY_SPKI_FP_SHA256_V1_FORMAT, KEY_X25519_HPKE_V1_FORMAT, NONCE_SIZE, Verification, Verifier,
    random_nonce,
};

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

/// Fetches the attestation document of a host, through a relay if one is
/// given, for a nonce. The clients use [`fetch::document`].
pub(crate) type Fetch = Arc<
    dyn Fn(String, Option<String>, [u8; NONCE_SIZE]) -> BoxFuture<Result<Vec<u8>, Error>>
        + Send
        + Sync
        + 'static,
>;

/// What describes an [`Enclave`].
pub(crate) struct Config {
    /// The enclave: a host with an optional port.
    pub(crate) host: String,
    /// A host that fetches the attestation document on the client's behalf.
    pub(crate) relay: Option<String>,
    /// The repository pin, `org/project[@revision][@sha256:digest]`, or
    /// `None` to accept a config that the verifier authorizes.
    pub(crate) repo: Option<String>,
    /// The policy; `None` selects the default verifier.
    pub(crate) verifier: Option<Arc<Verifier>>,
    /// The caller's veto.
    pub(crate) verification_check: Option<VerificationCheck>,
}

/// One enclave and the policy that its attestation is verified against.
pub(crate) struct Enclave<V = Verification> {
    host: String,
    repo: Option<String>,
    verifier: Option<Arc<Verifier>>,
    source: Source<V>,
    check: Option<Check<V>>,
    clock: Clock,
}

/// A [`Config`] that passed its checks, with the verifier that it selects.
pub(crate) struct Checked {
    host: String,
    relay: Option<String>,
    repo: Option<String>,
    verifier: Arc<Verifier>,
    verification_check: Option<VerificationCheck>,
}

impl Checked {
    /// The enclave's host.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// The verification policy: the configured one, or the default
    /// verifier, which was built for the checks and is the one that the
    /// enclave then verifies with.
    pub(crate) fn verifier(&self) -> &Arc<Verifier> {
        &self.verifier
    }
}

impl Config {
    /// The checks of an enclave's description. They do no I/O, and they are
    /// the only such checks: a client builder and [`Enclave::with_fetch`]
    /// both go through here. Each failure is a configuration error, in this
    /// order:
    ///
    /// 1. the host, or the relay, is not a host with an optional port;
    /// 2. the repository pin is `Some("")` ([`check_pin`]);
    /// 3. the verifier cannot verify against the pin
    ///    (`Verifier::check_repo_verifiability`): the pin is not a
    ///    repository reference, or the verifier's own configuration rules
    ///    it out. The verifier's usage error is the source.
    pub(crate) fn check(self) -> Result<Checked, Error> {
        authority_url(&self.host)?;
        if let Some(relay) = &self.relay {
            authority_url(relay)?;
        }
        check_pin(self.repo.as_deref())?;
        let verifier = self.verifier.unwrap_or_else(|| Arc::new(Verifier::new()));
        verifier
            .check_repo_verifiability(self.repo.as_deref())
            .map_err(from_verifier)?;
        Ok(Checked {
            host: self.host,
            relay: self.relay,
            repo: self.repo,
            verifier,
            verification_check: self.verification_check,
        })
    }
}

/// Fetches attestation documents over the network ([`fetch::document`]).
pub(crate) fn network_fetch() -> Fetch {
    Arc::new(|host, relay, nonce| {
        Box::pin(async move { fetch::document(&host, relay.as_deref(), &nonce).await })
    })
}

impl Enclave<Verification> {
    /// An enclave that is verified by fetching its attestation document
    /// and judged by the system clock. See [`Config::check`] for the
    /// checks.
    pub(crate) fn new(config: Config) -> Result<Self, Error> {
        Self::with_fetch(config, system_clock(), network_fetch())
    }

    /// An enclave whose documents come from `fetch`. It does no I/O; the
    /// failures are those of [`Config::check`].
    pub(crate) fn with_fetch(config: Config, clock: Clock, fetch: Fetch) -> Result<Self, Error> {
        Ok(Self::from_checked(config.check()?, clock, fetch))
    }

    /// The enclave of a description that was checked already.
    ///
    /// One attempt to obtain a verification is, in order: a fresh random
    /// nonce; `fetch` for the host, the relay and the nonce;
    /// `Verifier::verify_v3` on the document with the nonce and the pin
    /// (a usage error is a configuration error, any other rejection is an
    /// attestation error, and the verifier's error is the source either
    /// way); and [`validate_transport_keys`].
    pub(crate) fn from_checked(checked: Checked, clock: Clock, fetch: Fetch) -> Self {
        let verifier = checked.verifier;
        let source: Source<Verification> = {
            let (host, relay, repo) = (checked.host.clone(), checked.relay, checked.repo.clone());
            let verifier = Arc::clone(&verifier);
            Arc::new(move || {
                let (host, relay, repo) = (host.clone(), relay.clone(), repo.clone());
                let (verifier, fetch) = (Arc::clone(&verifier), Arc::clone(&fetch));
                Box::pin(async move {
                    let nonce =
                        random_nonce().map_err(|error| Error::wrap(ErrorKind::Network, error))?;
                    let document = fetch(host, relay, nonce).await?;
                    let verification = verifier
                        .verify_v3(&document, &nonce, repo.as_deref())
                        .map_err(from_verifier)?;
                    validate_transport_keys(&verification)?;
                    Ok(verification)
                })
            })
        };
        Self {
            host: checked.host,
            repo: checked.repo,
            verifier: Some(verifier),
            source,
            check: checked.verification_check,
            clock,
        }
    }

    /// The verification policy, which several enclaves can share.
    pub(crate) fn verifier(&self) -> Option<&Arc<Verifier>> {
        self.verifier.as_ref()
    }
}

impl<V: Evidence> Enclave<V> {
    /// An enclave whose evidence comes from `source`, for the tests of the
    /// code that is built on an enclave. Nothing is checked.
    #[cfg(test)]
    pub(crate) fn from_source(
        host: &str,
        source: Source<V>,
        check: Option<Check<V>>,
        clock: Clock,
    ) -> Self {
        Self {
            host: host.to_owned(),
            repo: None,
            verifier: None,
            source,
            check,
            clock,
        }
    }

    /// The enclave's host.
    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    /// The repository pin, with any tag or digest; `None` without one.
    pub(crate) fn repo(&self) -> Option<&str> {
        self.repo.as_deref()
    }

    /// The clock that the enclave judges freshness by.
    pub(crate) fn clock(&self) -> &Clock {
        &self.clock
    }

    /// Obtains evidence and checks it, and tries once more after
    /// [`RETRY_DELAY`] when the first attempt fails with a network or
    /// attestation error.
    ///
    /// One attempt, in order:
    ///
    /// 1. the source: for a client, a fresh nonce, the document fetch and
    ///    the verifier, under no caller's deadline, since one verification
    ///    serves every request that waits for it;
    /// 2. the freshness deadline against the clock. Evidence with no
    ///    deadline counts as expired: a client accepts no verification
    ///    that nothing limits in time;
    /// 3. the caller's veto, given the evidence; a rejection is an
    ///    attestation error that names the host and has the caller's error
    ///    in its source chain;
    /// 4. the freshness deadline again, since the veto may have run past
    ///    it.
    ///
    /// A configuration error and a veto are never retried. When the retry
    /// fails too, its error is returned with the first attempt's error
    /// attached ([`Error::earlier_attempt`]).
    ///
    /// Dropping the future abandons the attempt; nothing is kept.
    pub(crate) async fn verify(&self) -> Result<V, Error> {
        let first = match self.attempt().await {
            Ok(evidence) => return Ok(evidence),
            Err(error) => error,
        };
        if !retryable(&first) {
            return Err(first);
        }
        tokio::time::sleep(RETRY_DELAY).await;
        self.attempt().await.map_err(|error| error.after(first))
    }

    /// As [`verify`](Self::verify) without the retry, so that a caller that
    /// tries several enclaves moves on quickly.
    pub(crate) async fn verify_once(&self) -> Result<V, Error> {
        self.attempt().await
    }

    async fn attempt(&self) -> Result<V, Error> {
        let evidence = (self.source)().await?;
        self.check_freshness(&evidence)?;
        if let Some(check) = &self.check {
            check(&evidence).map_err(|source| {
                Error::wrap(
                    ErrorKind::Attestation,
                    Rejected {
                        host: self.host.clone(),
                        source,
                    },
                )
            })?;
        }
        self.check_freshness(&evidence)?;
        Ok(evidence)
    }

    fn check_freshness(&self, evidence: &V) -> Result<(), Error> {
        if fresh_at(evidence, (self.clock)()) {
            Ok(())
        } else {
            Err(freshness_expired())
        }
    }
}

/// The error for evidence whose freshness deadline has passed, or that has
/// none.
pub(crate) fn freshness_expired() -> Error {
    Error::attestation(
        "attestation freshness witnesses have expired; retry verification with fresh evidence",
    )
}

/// A rejection by the caller's veto. It is a decision about the evidence,
/// so it is not retried.
#[derive(Debug)]
struct Rejected {
    host: String,
    source: BoxError,
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verification check rejected {}: {}",
            self.host, self.source
        )
    }
}

impl StdError for Rejected {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Whether a failed attempt is worth one more: a network or attestation
/// error that is not the caller's veto.
fn retryable(error: &Error) -> bool {
    let vetoed = error.source().is_some_and(|source| source.is::<Rejected>());
    !vetoed && matches!(error.kind(), ErrorKind::Network | ErrorKind::Attestation)
}

/// Refuses an empty repository pin. "No pin" is `None`; `Some("")` is a
/// configuration error, so that an empty string from a caller's own
/// configuration never silently removes the pin.
pub(crate) fn check_pin(repo: Option<&str>) -> Result<(), Error> {
    match repo {
        Some("") => Err(Error::configuration(
            "the repository pin is empty; pass `None` to verify without a repository pin",
        )),
        _ => Ok(()),
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
    check_transport_keys(
        verification.crypto_material(),
        verification.tls_public_key_fp().is_some(),
    )
}

/// The checks of [`validate_transport_keys`], on the endorsed items and on
/// whether the verification reports a TLS key.
fn check_transport_keys(items: &[CryptoMaterialItem], has_tls_key: bool) -> Result<(), Error> {
    check_key_format(items, CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT)?;
    if !has_tls_key {
        return Err(Error::attestation(format!(
            "document endorses no {CRYPTO_MATERIAL_ID_TLS:?} key"
        )));
    }
    check_key_format(items, CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT)
}

/// An attestation error for an endorsed `id` item whose format is not
/// `format`.
fn check_key_format(items: &[CryptoMaterialItem], id: &str, format: &str) -> Result<(), Error> {
    match items
        .iter()
        .find(|item| item.id == id && item.format != format)
    {
        Some(item) => Err(Error::attestation(format!(
            "crypto_material item {id:?} has format {:?}, want {format:?}",
            item.format
        ))),
        None => Ok(()),
    }
}

/// A verifier error in the client's categories, by its outermost type: a
/// usage error is the caller's configuration error, and any rejection is an
/// attestation error. The verifier's error stays the source.
pub(crate) fn from_verifier(error: crate::verifier::Error) -> Error {
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
            .check_repo_verifiability(Some("not a reference"))
            .expect_err("an invalid reference is refused");
        let error = from_verifier(usage);
        assert_eq!(error.kind(), ErrorKind::Configuration);
        let source = std::error::Error::source(&error).expect("the verifier's error");
        assert!(source.is::<crate::verifier::Error>());
    }

    #[test]
    fn an_empty_pin_is_refused_and_an_absent_one_is_not() {
        let error = check_pin(Some("")).expect_err("an empty pin is refused");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert!(error.to_string().contains("repository pin is empty"));
        assert!(check_pin(None).is_ok());
        assert!(check_pin(Some("owner/name")).is_ok());
    }

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::internal::testing::{Record, Script, Step, record, tokio_clock};

    const HOUR: Duration = Duration::from_secs(3600);

    fn enclave(
        script: &Arc<Script>,
        clock: &Clock,
        check: Option<Check<Record>>,
    ) -> Enclave<Record> {
        Enclave::from_source(
            "enclave.example.com",
            script.source(),
            check,
            Arc::clone(clock),
        )
    }

    #[test]
    fn evidence_is_fresh_strictly_before_its_deadline_and_never_without_one() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let with = |expires| Record {
            name: "r",
            tls: None,
            hpke: None,
            expires,
        };
        assert!(fresh_at(&with(Some(now + Duration::from_micros(1))), now));
        assert!(!fresh_at(&with(Some(now)), now));
        assert!(!fresh_at(&with(Some(now - Duration::from_secs(1))), now));
        assert!(!fresh_at(&with(None), now));
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_attempt_that_succeeds_is_the_only_attempt() {
        let clock = tokio_clock();
        let evidence = record("a", &clock, HOUR);
        let script = Script::new([Step::Ready(Ok(evidence.clone()))]);
        let started = tokio::time::Instant::now();
        assert_eq!(
            enclave(&script, &clock, None)
                .verify()
                .await
                .expect("verified"),
            evidence
        );
        assert_eq!(script.calls(), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_network_failure_is_tried_once_more_after_one_second() {
        let clock = tokio_clock();
        let evidence = record("a", &clock, HOUR);
        let script = Script::new([
            Step::Ready(Err(Error::network("connection reset"))),
            Step::Ready(Ok(evidence.clone())),
        ]);
        let started = tokio::time::Instant::now();
        assert_eq!(
            enclave(&script, &clock, None)
                .verify()
                .await
                .expect("verified"),
            evidence
        );
        assert_eq!(script.calls(), 2);
        assert_eq!(started.elapsed(), RETRY_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_failure_is_returned_with_the_first_attached_and_there_is_no_third_attempt() {
        let clock = tokio_clock();
        let script = Script::new([
            Step::Ready(Err(Error::network("first"))),
            Step::Ready(Err(Error::attestation("second"))),
            Step::Ready(Ok(record("never", &clock, HOUR))),
        ]);
        let error = enclave(&script, &clock, None)
            .verify()
            .await
            .expect_err("fails twice");
        assert_eq!(error.to_string(), "attestation error: second");
        assert_eq!(
            error.earlier_attempt().map(Error::to_string).as_deref(),
            Some("network error: first")
        );
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_configuration_error_is_not_tried_again() {
        let clock = tokio_clock();
        let script = Script::new([
            Step::Ready(Err(Error::configuration("bad pin"))),
            Step::Ready(Ok(record("never", &clock, HOUR))),
        ]);
        let started = tokio::time::Instant::now();
        let error = enclave(&script, &clock, None)
            .verify()
            .await
            .expect_err("fails");
        assert_eq!(error.kind(), ErrorKind::Configuration);
        assert!(error.earlier_attempt().is_none());
        assert_eq!(script.calls(), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_single_attempt_is_never_tried_again() {
        let clock = tokio_clock();
        let script = Script::new([
            Step::Ready(Err(Error::network("down"))),
            Step::Ready(Ok(record("never", &clock, HOUR))),
        ]);
        let error = enclave(&script, &clock, None)
            .verify_once()
            .await
            .expect_err("fails");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert_eq!(script.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_veto_is_an_attestation_error_that_names_the_host_and_is_not_tried_again() {
        let clock = tokio_clock();
        let script = Script::new([
            Step::Ready(Ok(record("a", &clock, HOUR))),
            Step::Ready(Ok(record("b", &clock, HOUR))),
        ]);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let check: Check<Record> = {
            let seen = Arc::clone(&seen);
            Arc::new(move |evidence: &Record| {
                seen.lock().unwrap().push(evidence.name);
                Err(std::io::Error::other("unknown measurement").into())
            })
        };
        let started = tokio::time::Instant::now();
        let error = enclave(&script, &clock, Some(check))
            .verify()
            .await
            .expect_err("vetoed");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert_eq!(
            error.to_string(),
            "attestation error: verification check rejected enclave.example.com: unknown measurement"
        );
        let caller = error
            .source()
            .and_then(StdError::source)
            .expect("the caller's error");
        assert!(caller.is::<std::io::Error>());
        assert!(error.earlier_attempt().is_none());
        assert_eq!(*seen.lock().unwrap(), ["a"]);
        assert_eq!(script.calls(), 1);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_veto_that_accepts_sees_each_verification_once() {
        let clock = tokio_clock();
        let evidence = record("a", &clock, HOUR);
        let script = Script::new([Step::Ready(Ok(evidence.clone()))]);
        let calls = Arc::new(AtomicUsize::new(0));
        let check: Check<Record> = {
            let calls = Arc::clone(&calls);
            Arc::new(move |_: &Record| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        };
        assert_eq!(
            enclave(&script, &clock, Some(check))
                .verify()
                .await
                .expect("verified"),
            evidence
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_evidence_never_reaches_the_veto_and_is_tried_again() {
        let clock = tokio_clock();
        let fresh = record("fresh", &clock, HOUR);
        let script = Script::new([
            Step::Ready(Ok(record("stale", &clock, Duration::ZERO))),
            Step::Ready(Ok(fresh.clone())),
        ]);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let check: Check<Record> = {
            let seen = Arc::clone(&seen);
            Arc::new(move |evidence: &Record| {
                seen.lock().unwrap().push(evidence.name);
                Ok(())
            })
        };
        assert_eq!(
            enclave(&script, &clock, Some(check))
                .verify()
                .await
                .expect("verified"),
            fresh
        );
        assert_eq!(*seen.lock().unwrap(), ["fresh"]);
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn evidence_without_a_deadline_is_refused_as_expired() {
        let clock = tokio_clock();
        let mut unlimited = record("unlimited", &clock, HOUR);
        unlimited.expires = None;
        let script = Script::new([
            Step::Ready(Ok(unlimited.clone())),
            Step::Ready(Ok(unlimited)),
        ]);
        let error = enclave(&script, &clock, None)
            .verify()
            .await
            .expect_err("no deadline");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(
            error
                .to_string()
                .contains("freshness witnesses have expired"),
            "{error}"
        );
        assert!(error.earlier_attempt().is_some());
        assert_eq!(script.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn evidence_that_expires_while_the_veto_runs_is_refused() {
        // The veto is synchronous, so the test moves the clock from inside
        // it: an offset that the clock adds to Tokio's time.
        let offset = Arc::new(Mutex::new(Duration::ZERO));
        let base = tokio_clock();
        let clock: Clock = {
            let offset = Arc::clone(&offset);
            Arc::new(move || base() + *offset.lock().unwrap())
        };
        let script = Script::new([Step::Ready(Ok(record("a", &clock, HOUR)))]);
        let check: Check<Record> = Arc::new(move |_: &Record| {
            *offset.lock().unwrap() = HOUR;
            Ok(())
        });
        let error = enclave(&script, &clock, Some(check))
            .verify_once()
            .await
            .expect_err("expired");
        assert!(
            error
                .to_string()
                .contains("freshness witnesses have expired"),
            "{error}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_verification_keeps_nothing_and_the_next_one_starts_over() {
        let clock = tokio_clock();
        let evidence = record("b", &clock, HOUR);
        let script = Script::new([
            Step::Ready(Err(Error::network("down"))),
            Step::Ready(Ok(evidence.clone())),
        ]);
        let enclave = enclave(&script, &clock, None);
        // Dropped in the pause before the retry.
        let abandoned = tokio::time::timeout(Duration::from_millis(500), enclave.verify()).await;
        assert!(abandoned.is_err());
        assert_eq!(script.calls(), 1);
        assert_eq!(enclave.verify().await.expect("verified"), evidence);
        assert_eq!(script.calls(), 2);
    }

    fn config(host: &str, relay: Option<&str>, repo: Option<&str>) -> Config {
        Config {
            host: host.to_owned(),
            relay: relay.map(str::to_owned),
            repo: repo.map(str::to_owned),
            verifier: None,
            verification_check: None,
        }
    }

    type Fetched = Arc<Mutex<Vec<(String, Option<String>, [u8; NONCE_SIZE])>>>;

    /// A fetch that records its arguments and returns `result`.
    fn recording_fetch(result: Result<Vec<u8>, Error>) -> (Fetch, Fetched) {
        let fetched: Fetched = Arc::default();
        let fetch: Fetch = {
            let fetched = Arc::clone(&fetched);
            Arc::new(move |host, relay, nonce| {
                fetched.lock().unwrap().push((host, relay, nonce));
                let result = result.clone();
                Box::pin(async move { result })
            })
        };
        (fetch, fetched)
    }

    #[tokio::test(start_paused = true)]
    async fn an_enclave_that_cannot_be_verified_is_refused_before_any_fetch() {
        for (config, reason) in [
            (config("", None, Some("owner/name")), "enclave host"),
            (
                config("https://enclave.example.com", None, Some("owner/name")),
                "enclave host",
            ),
            (
                config("enclave.example.com/x", None, Some("owner/name")),
                "enclave host",
            ),
            (
                config("enclave.example.com", Some("gateway.example.com/x"), None),
                "enclave host",
            ),
            (
                config("enclave.example.com", None, Some("")),
                "repository pin is empty",
            ),
            (
                config("enclave.example.com", None, Some("not a reference")),
                "",
            ),
        ] {
            let (fetch, fetched) = recording_fetch(Ok(Vec::new()));
            let error = Enclave::with_fetch(config, tokio_clock(), fetch)
                .err()
                .expect("refused");
            assert_eq!(error.kind(), ErrorKind::Configuration, "{error}");
            assert!(error.to_string().contains(reason), "{error}");
            assert!(fetched.lock().unwrap().is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_pin_that_the_verifier_refuses_keeps_the_verifiers_error_as_its_source() {
        let (fetch, _) = recording_fetch(Ok(Vec::new()));
        let error = Enclave::with_fetch(
            config("enclave.example.com", None, Some("not a reference")),
            tokio_clock(),
            fetch,
        )
        .err()
        .expect("refused");
        assert!(
            error
                .source()
                .is_some_and(|s| s.is::<crate::verifier::Error>())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn each_attempt_fetches_with_a_fresh_nonce_and_a_rejected_document_is_tried_once_more() {
        let (fetch, fetched) = recording_fetch(Ok(b"not a document".to_vec()));
        let enclave = Enclave::with_fetch(
            config(
                "enclave.example.com:8443",
                Some("gateway.example.com"),
                Some("owner/name"),
            ),
            tokio_clock(),
            fetch,
        )
        .expect("an enclave");
        assert_eq!(enclave.host(), "enclave.example.com:8443");
        assert_eq!(enclave.repo(), Some("owner/name"));

        let error = enclave
            .verify()
            .await
            .expect_err("the document is rejected");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(
            error
                .source()
                .is_some_and(|s| s.is::<crate::verifier::Error>())
        );
        let earlier = error.earlier_attempt().expect("the first attempt");
        assert_eq!(earlier.kind(), ErrorKind::Attestation);

        let fetched = fetched.lock().unwrap();
        assert_eq!(fetched.len(), 2);
        for (host, relay, _) in fetched.iter() {
            assert_eq!(host, "enclave.example.com:8443");
            assert_eq!(relay.as_deref(), Some("gateway.example.com"));
        }
        assert_ne!(fetched[0].2, fetched[1].2);
        assert_ne!(fetched[0].2, [0u8; NONCE_SIZE]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_fetch_is_reported_as_it_is_and_tried_once_more() {
        let (fetch, fetched) = recording_fetch(Err(Error::network("HTTP 503")));
        let enclave = Enclave::with_fetch(
            config("enclave.example.com", None, None),
            tokio_clock(),
            fetch,
        )
        .expect("an enclave");
        let error = enclave.verify().await.expect_err("the fetch fails");
        assert_eq!(error.to_string(), "network error: HTTP 503");
        assert_eq!(fetched.lock().unwrap().len(), 2);
        let error = enclave.verify_once().await.expect_err("the fetch fails");
        assert!(error.earlier_attempt().is_none());
        assert_eq!(fetched.lock().unwrap().len(), 3);
    }

    fn item(id: &str, format: &str) -> CryptoMaterialItem {
        CryptoMaterialItem {
            id: id.to_owned(),
            format: format.to_owned(),
            data: "00".to_owned(),
        }
    }

    #[test]
    fn the_transport_keys_must_be_in_the_formats_that_the_transports_bind_to() {
        let tls = item(CRYPTO_MATERIAL_ID_TLS, KEY_SPKI_FP_SHA256_V1_FORMAT);
        let hpke = item(CRYPTO_MATERIAL_ID_HPKE, KEY_X25519_HPKE_V1_FORMAT);
        let other = item("other", "https://example.com/format");

        assert!(check_transport_keys(&[tls.clone(), hpke.clone(), other.clone()], true).is_ok());
        // A document without an HPKE key passes.
        assert!(check_transport_keys(&[tls.clone(), other], true).is_ok());

        let refused = [
            // No TLS key at all.
            (vec![hpke.clone()], false, "endorses no \"tls\" key"),
            (vec![], false, "endorses no \"tls\" key"),
            // A TLS item in another format.
            (
                vec![
                    item(CRYPTO_MATERIAL_ID_TLS, crate::verifier::KEY_SPKI_V1_FORMAT),
                    hpke.clone(),
                ],
                false,
                "item \"tls\" has format",
            ),
            // A second TLS item in another format, next to a good one.
            (
                vec![tls.clone(), item(CRYPTO_MATERIAL_ID_TLS, "x")],
                true,
                "item \"tls\" has format \"x\"",
            ),
            // An HPKE item in another format.
            (
                vec![tls.clone(), item(CRYPTO_MATERIAL_ID_HPKE, "y")],
                true,
                "item \"hpke\" has format \"y\"",
            ),
        ];
        for (items, has_tls_key, reason) in refused {
            let error = check_transport_keys(&items, has_tls_key).expect_err(reason);
            assert_eq!(error.kind(), ErrorKind::Attestation);
            assert!(error.to_string().contains(reason), "{error}");
        }
    }
}
