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
