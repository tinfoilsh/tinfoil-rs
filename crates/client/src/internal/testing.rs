//! What the tests of the internal modules share: evidence that a test can
//! build, a clock that follows Tokio's paused time, and a scripted source
//! of evidence.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::Notify;

use crate::error::Error;
use crate::internal::Clock;
use crate::internal::enclave::{Evidence, Source};

/// Evidence with the three facts that the transports read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) name: &'static str,
    pub(crate) tls: Option<String>,
    pub(crate) hpke: Option<String>,
    pub(crate) expires: Option<SystemTime>,
}

impl Evidence for Record {
    type Facts = Record;
    fn facts(&self) -> Option<&Record> {
        Some(self)
    }
    fn tls_public_key_fp(&self) -> Option<&str> {
        self.tls.as_deref()
    }
    fn hpke_public_key(&self) -> Option<&str> {
        self.hpke.as_deref()
    }
    fn freshness_expires_at(&self) -> Option<SystemTime> {
        self.expires
    }
}

/// The instant that [`tokio_clock`] reports when a test starts.
pub(crate) const EPOCH: Duration = Duration::from_secs(1_800_000_000);

/// A wall clock that starts at [`EPOCH`] and advances with Tokio's time,
/// so that a test with paused time controls it.
pub(crate) fn tokio_clock() -> Clock {
    let started = tokio::time::Instant::now();
    Arc::new(move || SystemTime::UNIX_EPOCH + EPOCH + started.elapsed())
}

/// Evidence named `name` that expires `valid_for` after the clock's
/// present.
pub(crate) fn record(name: &'static str, clock: &Clock, valid_for: Duration) -> Record {
    Record {
        name,
        tls: Some(format!("{name}-tls")),
        hpke: Some(format!("{name}-hpke")),
        expires: Some(clock() + valid_for),
    }
}

/// One step of a [`Script`].
pub(crate) enum Step {
    /// Return this result at once.
    Ready(Result<Record, Error>),
    /// Return this result once the notify is signalled.
    Gated(Arc<Notify>, Result<Record, Error>),
    /// Return this result after this much of Tokio's time.
    After(Duration, Result<Record, Error>),
}

/// A source of evidence that plays its steps in order and counts its
/// calls. A call beyond the last step fails with a network error.
pub(crate) struct Script {
    steps: Mutex<VecDeque<Step>>,
    calls: AtomicUsize,
}

impl Script {
    pub(crate) fn new(steps: impl IntoIterator<Item = Step>) -> Arc<Self> {
        Arc::new(Self {
            steps: Mutex::new(steps.into_iter().collect()),
            calls: AtomicUsize::new(0),
        })
    }

    /// How many attempts have started.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub(crate) fn source(self: &Arc<Self>) -> Source<Record> {
        let script = Arc::clone(self);
        Arc::new(move || {
            script.calls.fetch_add(1, Ordering::SeqCst);
            let step = script.steps.lock().unwrap().pop_front();
            Box::pin(async move {
                match step {
                    Some(Step::Ready(result)) => result,
                    Some(Step::Gated(gate, result)) => {
                        gate.notified().await;
                        result
                    }
                    Some(Step::After(delay, result)) => {
                        tokio::time::sleep(delay).await;
                        result
                    }
                    None => Err(Error::network("the script has no step left")),
                }
            })
        })
    }
}

/// One attempt as an observer was told it: the host, and the name of the
/// evidence or the error's message.
pub(crate) type Told = (String, Result<&'static str, String>);

/// An observer of attempts that records what it is told, and the records.
pub(crate) fn observer() -> (crate::options::Notify<Record>, Arc<Mutex<Vec<Told>>>) {
    let told = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&told);
    let notify: crate::options::Notify<Record> = Arc::new(move |host, outcome| {
        let outcome = outcome
            .map(|record| record.name)
            .map_err(ToString::to_string);
        log.lock().unwrap().push((host.to_owned(), outcome));
    });
    (notify, told)
}

/// The report that a verifier's rejection carries, found from a client
/// error through its sources.
pub(crate) fn rejected_report(error: &Error) -> Option<&crate::verifier::VerificationReport> {
    let source = std::error::Error::source(error)?;
    match source.downcast_ref::<crate::verifier::Error>()? {
        crate::verifier::Error::Verification(rejected) => Some(rejected.report()),
        _ => None,
    }
}

/// A client error for a document that the verifier rejected: an empty
/// document, which the envelope step rejects, with its report.
pub(crate) fn rejected_by_verifier() -> Error {
    let nonce = crate::verifier::random_nonce().unwrap();
    let rejection = crate::verifier::Verifier::default()
        .verify_v3(b"{}", &nonce, &crate::verifier::Pin::repo("owner/name"))
        .expect_err("an empty document is rejected");
    crate::internal::enclave::from_verifier(rejection)
}
