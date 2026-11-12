//! The transport's state machine, on scripted evidence, a mode that
//! records what it binds and sends, and Tokio's paused time.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::{Method, Request, Response, Url};
use tokio::sync::Notify;

use super::{Failure, KeyFailure, Mode, RoundTrip, Transport};
use crate::error::{Error, ErrorKind};
use crate::internal::enclave::{Enclave, RETRY_DELAY};
use crate::internal::testing::{Record, Script, Step, record, tokio_clock};
use crate::internal::{BoxFuture, Clock};

const HOUR: Duration = Duration::from_secs(3600);

/// What a bound transport answers to one request.
enum Reply {
    /// A response whose body is the binding's name.
    Respond,
    /// The peer does not hold the binding's keys.
    PeerLacksKey,
    /// Another failure, with what it claims about the keys.
    Fail(Error, KeyFailure),
    /// Wait for the notify, then answer with the reply.
    Gated(Arc<Notify>, Box<Reply>),
}

/// What the mode and its bindings record. A binding is named after its
/// evidence.
#[derive(Default)]
struct Log {
    bound: Vec<&'static str>,
    sent: Vec<&'static str>,
    retired: Vec<&'static str>,
    replies: HashMap<&'static str, VecDeque<Reply>>,
}

#[derive(Default)]
struct FakeMode {
    log: Arc<Mutex<Log>>,
    /// Runs inside `bind`, before the binding is returned.
    on_bind: Option<Box<dyn Fn() + Send + Sync>>,
}

impl FakeMode {
    fn bound(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().bound.clone()
    }
    fn sent(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().sent.clone()
    }
    fn retired(&self) -> Vec<&'static str> {
        self.log.lock().unwrap().retired.clone()
    }
    /// Queues `reply` as the next answer of the binding named `name`.
    fn reply(&self, name: &'static str, reply: Reply) {
        self.log
            .lock()
            .unwrap()
            .replies
            .entry(name)
            .or_default()
            .push_back(reply);
    }
}

impl Mode<Record> for FakeMode {
    fn validate_request(&self, request: &Request) -> Result<(), Error> {
        if request.method() == Method::CONNECT {
            return Err(Error::configuration("the mode cannot protect CONNECT"));
        }
        Ok(())
    }

    fn bind(&self, evidence: &Record) -> Result<Arc<dyn RoundTrip>, Error> {
        if evidence.tls.is_none() {
            return Err(Error::attestation("the evidence endorses no key"));
        }
        if let Some(hook) = &self.on_bind {
            hook();
        }
        self.log.lock().unwrap().bound.push(evidence.name);
        Ok(Arc::new(FakeBound {
            name: evidence.name,
            log: Arc::clone(&self.log),
        }))
    }
}

struct FakeBound {
    name: &'static str,
    log: Arc<Mutex<Log>>,
}

impl Drop for FakeBound {
    fn drop(&mut self) {
        self.log.lock().unwrap().retired.push(self.name);
    }
}

impl RoundTrip for FakeBound {
    fn round_trip(&self, _request: Request) -> BoxFuture<Result<Response, Failure>> {
        let name = self.name;
        let mut reply = {
            let mut log = self.log.lock().unwrap();
            log.sent.push(name);
            log.replies
                .get_mut(name)
                .and_then(VecDeque::pop_front)
                .unwrap_or(Reply::Respond)
        };
        Box::pin(async move {
            loop {
                match reply {
                    Reply::Respond => {
                        return Ok(Response::from(http::Response::new(name.to_owned())));
                    }
                    Reply::PeerLacksKey => {
                        return Err(Failure::peer_lacks_key(Error::attestation(
                            "certificate does not match the attested key",
                        )));
                    }
                    Reply::Fail(error, key) => return Err(Failure { error, key }),
                    Reply::Gated(gate, then) => {
                        gate.notified().await;
                        reply = *then;
                    }
                }
            }
        })
    }
}

fn request() -> Request {
    Request::new(
        Method::GET,
        Url::parse("https://enclave.example.com/").unwrap(),
    )
}

/// Lets every spawned task run until it waits.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// The name of the binding that served `transport`'s next request.
async fn served_by(transport: &Transport<Record>) -> String {
    let response = transport.round_trip(request()).await.expect("a response");
    response.text().await.expect("a body")
}

struct Fixture {
    clock: Clock,
    script: Arc<Script>,
    mode: Arc<FakeMode>,
    transport: Transport<Record>,
}

/// A transport connected on evidence `a`, valid for an hour, followed by
/// `steps` for the verifications after it.
async fn connected(steps: impl FnOnce(&Clock) -> Vec<Step>) -> Fixture {
    connected_with(FakeMode::default(), steps).await
}

async fn connected_with(mode: FakeMode, steps: impl FnOnce(&Clock) -> Vec<Step>) -> Fixture {
    let clock = tokio_clock();
    let mut all = vec![Step::Ready(Ok(record("a", &clock, HOUR)))];
    all.extend(steps(&clock));
    let script = Script::new(all);
    let mode = Arc::new(mode);
    let enclave = Enclave::from_source(
        "enclave.example.com",
        script.source(),
        None,
        Arc::clone(&clock),
    );
    let transport = Transport::connect(enclave, mode.clone(), true)
        .await
        .expect("connected");
    Fixture {
        clock,
        script,
        mode,
        transport,
    }
}

fn ok(name: &'static str, clock: &Clock, valid_for: Duration) -> Step {
    Step::Ready(Ok(record(name, clock, valid_for)))
}

// Connecting.

#[tokio::test(start_paused = true)]
async fn connecting_verifies_once_and_binds_to_that_verification() {
    let f = connected(|_| vec![]).await;
    assert_eq!(f.script.calls(), 1);
    assert_eq!(f.mode.bound(), ["a"]);
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(served_by(&f.transport).await, "a");
    assert_eq!(f.script.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn connecting_fails_when_the_enclave_does_not_verify_and_retries_only_when_asked() {
    for (retry, attempts) in [(true, 2), (false, 1)] {
        let clock = tokio_clock();
        let script = Script::new([
            Step::Ready(Err(Error::network("down"))),
            Step::Ready(Err(Error::attestation("rejected"))),
        ]);
        let mode = Arc::new(FakeMode::default());
        let enclave = Enclave::from_source("enclave.example.com", script.source(), None, clock);
        let error = Transport::connect(enclave, mode.clone(), retry)
            .await
            .expect_err("no transport");
        assert_eq!(script.calls(), attempts);
        assert_eq!(error.earlier_attempt().is_some(), retry);
        assert!(mode.bound().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn connecting_fails_when_the_mode_cannot_bind_to_the_evidence() {
    let clock = tokio_clock();
    let mut keyless = record("keyless", &clock, HOUR);
    keyless.tls = None;
    let script = Script::new([Step::Ready(Ok(keyless))]);
    let enclave = Enclave::from_source("enclave.example.com", script.source(), None, clock);
    let error = Transport::connect(enclave, Arc::new(FakeMode::default()), true)
        .await
        .expect_err("no transport");
    assert_eq!(
        error.to_string(),
        "attestation error: the evidence endorses no key"
    );
    assert_eq!(script.calls(), 1);
}

// Validity and expiry.

#[tokio::test(start_paused = true)]
async fn a_valid_verification_is_returned_without_verifying() {
    let f = connected(|_| vec![]).await;
    tokio::time::advance(HOUR - Duration::from_nanos(1)).await;
    assert_eq!(
        f.transport.ensure_verified().await.expect("valid").name,
        "a"
    );
    assert_eq!(served_by(&f.transport).await, "a");
    assert_eq!(f.script.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_verification_is_expired_at_its_deadline_and_the_enclave_is_verified_again() {
    let f = connected(|clock| vec![ok("b", clock, 3 * HOUR)]).await;
    tokio::time::advance(HOUR).await;
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(
        f.transport.ensure_verified().await.expect("verified").name,
        "b"
    );
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.mode.bound(), ["a", "b"]);
    assert_eq!(f.transport.current().name, "b");
    assert_eq!(served_by(&f.transport).await, "b");
}

#[tokio::test(start_paused = true)]
async fn a_request_after_expiry_verifies_first_and_goes_out_under_the_new_keys() {
    let f = connected(|clock| vec![ok("b", clock, 3 * HOUR)]).await;
    tokio::time::advance(2 * HOUR).await;
    assert_eq!(served_by(&f.transport).await, "b");
    assert_eq!(f.mode.sent(), ["b"]);
}

#[tokio::test(start_paused = true)]
async fn a_request_is_not_sent_when_the_verification_it_needs_fails() {
    let f = connected(|_| {
        vec![
            Step::Ready(Err(Error::network("down"))),
            Step::Ready(Err(Error::attestation("rejected"))),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;
    let failure = f.transport.round_trip(request()).await.expect_err("fails");
    assert_eq!(failure.error.to_string(), "attestation error: rejected");
    assert_eq!(
        failure.error.earlier_attempt().map(Error::kind),
        Some(ErrorKind::Network)
    );
    assert_eq!(failure.key, KeyFailure::None);
    assert!(f.mode.sent().is_empty());
    assert_eq!(f.transport.current().name, "a");
}

#[tokio::test(start_paused = true)]
async fn a_failed_verification_is_not_remembered() {
    let f = connected(|clock| {
        vec![
            Step::Ready(Err(Error::configuration("refused"))),
            ok("b", clock, 3 * HOUR),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;
    assert!(f.transport.ensure_verified().await.is_err());
    assert_eq!(
        f.transport.ensure_verified().await.expect("verified").name,
        "b"
    );
    assert_eq!(f.script.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn evidence_that_expires_while_the_mode_binds_is_not_published() {
    // Binding is synchronous, so the mode moves the clock itself: an
    // offset on top of Tokio's time, set by the second bind.
    let offset = Arc::new(Mutex::new(Duration::ZERO));
    let binds = Arc::new(Mutex::new(0));
    let mode = FakeMode {
        on_bind: Some(Box::new({
            let (offset, binds) = (Arc::clone(&offset), Arc::clone(&binds));
            move || {
                let mut binds = binds.lock().unwrap();
                *binds += 1;
                if *binds == 2 {
                    *offset.lock().unwrap() = 2 * HOUR;
                }
            }
        })),
        ..FakeMode::default()
    };
    let base = tokio_clock();
    let clock: Clock = {
        let offset = Arc::clone(&offset);
        Arc::new(move || base() + *offset.lock().unwrap())
    };
    let script = Script::new([
        Step::Ready(Ok(record("a", &clock, HOUR))),
        Step::Ready(Ok(record("b", &clock, HOUR))),
    ]);
    let mode = Arc::new(mode);
    let enclave = Enclave::from_source(
        "enclave.example.com",
        script.source(),
        None,
        Arc::clone(&clock),
    );
    let transport = Transport::connect(enclave, mode.clone(), true)
        .await
        .expect("connected");

    let error = transport
        .reverify()
        .await
        .expect_err("expired while binding");
    assert_eq!(error.kind(), ErrorKind::Attestation);
    assert!(
        error
            .to_string()
            .contains("freshness witnesses have expired"),
        "{error}"
    );
    assert_eq!(transport.current().name, "a");
    // The binding that was never published is retired.
    assert_eq!(mode.retired(), ["b"]);
}

// Verifying again on request.

#[tokio::test(start_paused = true)]
async fn reverify_verifies_even_when_the_current_verification_is_valid() {
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    assert_eq!(f.transport.reverify().await.expect("verified").name, "b");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.transport.current().name, "b");
    assert_eq!(served_by(&f.transport).await, "b");
}

#[tokio::test(start_paused = true)]
async fn a_failed_reverify_keeps_the_previous_binding_in_use() {
    let f = connected(|_| {
        vec![
            Step::Ready(Err(Error::network("down"))),
            Step::Ready(Err(Error::network("still down"))),
        ]
    })
    .await;
    let error = f.transport.reverify().await.expect_err("fails");
    assert_eq!(error.to_string(), "network error: still down");
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(
        f.transport
            .ensure_verified()
            .await
            .expect("still valid")
            .name,
        "a"
    );
    assert_eq!(served_by(&f.transport).await, "a");
    assert_eq!(f.script.calls(), 3);
    assert!(f.mode.retired().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_failed_bind_keeps_the_previous_binding_in_use() {
    let f = connected(|clock| {
        let mut keyless = record("keyless", clock, HOUR);
        keyless.tls = None;
        vec![Step::Ready(Ok(keyless))]
    })
    .await;
    let error = f.transport.reverify().await.expect_err("cannot bind");
    assert_eq!(
        error.to_string(),
        "attestation error: the evidence endorses no key"
    );
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(served_by(&f.transport).await, "a");
}

// One verification at a time.

#[tokio::test(start_paused = true)]
async fn callers_that_need_a_verification_at_once_share_one() {
    let gate = Arc::new(Notify::new());
    let f = connected(|clock| {
        vec![Step::Gated(
            Arc::clone(&gate),
            Ok(record("b", clock, 3 * HOUR)),
        )]
    })
    .await;
    tokio::time::advance(HOUR).await;

    let mut waiters = Vec::new();
    for i in 0..8 {
        let transport = f.transport.clone();
        waiters.push(tokio::spawn(async move {
            match i % 3 {
                0 => transport.ensure_verified().await.map(|v| v.name.to_owned()),
                1 => transport.reverify().await.map(|v| v.name.to_owned()),
                _ => Ok(served_by(&transport).await),
            }
        }));
    }
    settle().await;
    assert_eq!(f.script.calls(), 2);
    gate.notify_one();
    for waiter in waiters {
        assert_eq!(waiter.await.expect("joined").expect("verified"), "b");
    }
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.mode.bound(), ["a", "b"]);
}

#[tokio::test(start_paused = true)]
async fn every_waiter_receives_the_failure_of_the_shared_verification() {
    let gate = Arc::new(Notify::new());
    let f = connected(|_| {
        vec![
            Step::Gated(Arc::clone(&gate), Err(Error::network("down"))),
            Step::Ready(Err(Error::attestation("rejected"))),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;

    let waiters: Vec<_> = (0..5)
        .map(|_| {
            let transport = f.transport.clone();
            tokio::spawn(async move { transport.ensure_verified().await })
        })
        .collect();
    settle().await;
    gate.notify_one();
    for waiter in waiters {
        let error = waiter.await.expect("joined").expect_err("fails");
        assert_eq!(error.to_string(), "attestation error: rejected");
        assert_eq!(
            error.earlier_attempt().map(Error::to_string).as_deref(),
            Some("network error: down")
        );
    }
    // One verification: its first attempt and its one retry.
    assert_eq!(f.script.calls(), 3);
    assert_eq!(f.transport.current().name, "a");
}

#[tokio::test(start_paused = true)]
async fn a_check_that_panics_fails_the_shared_verification_for_every_waiter_and_nothing_else() {
    let clock = tokio_clock();
    let gate = Arc::new(Notify::new());
    let script = Script::new([
        Step::Ready(Ok(record("a", &clock, HOUR))),
        Step::Gated(Arc::clone(&gate), Ok(record("b", &clock, 3 * HOUR))),
        Step::Ready(Ok(record("c", &clock, 3 * HOUR))),
    ]);
    let check: crate::options::Check<Record> = Arc::new(|evidence: &Record| {
        if evidence.name == "b" {
            panic!("the check went wrong");
        }
        Ok(())
    });
    let enclave = Enclave::from_source(
        "enclave.example.com",
        script.source(),
        Some(check),
        Arc::clone(&clock),
    );
    let mode = Arc::new(FakeMode::default());
    let transport = Transport::connect(enclave, mode.clone(), true)
        .await
        .expect("connected");
    tokio::time::advance(HOUR).await;

    // Two callers wait for one verification, whose check panics.
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let transport = transport.clone();
            tokio::spawn(async move { transport.ensure_verified().await })
        })
        .collect();
    settle().await;
    assert_eq!(script.calls(), 2);
    gate.notify_one();
    for waiter in waiters {
        // Neither task panicked: each got the verification's error.
        let error = waiter.await.expect("no panic").expect_err("rejected");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(error.to_string().contains("the check panicked"), "{error}");
    }
    // A rejection is not tried again, and nothing was bound to it.
    assert_eq!(script.calls(), 2);
    assert_eq!(transport.current().name, "a");
    assert_eq!(mode.bound(), ["a"]);

    // The transport is as usable as after any failed verification.
    assert_eq!(
        transport.ensure_verified().await.expect("verified").name,
        "c"
    );
    assert_eq!(served_by(&transport).await, "c");
    assert_eq!(script.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_verification_that_finished_is_not_handed_to_a_later_caller() {
    let f = connected(|clock| vec![ok("b", clock, HOUR), ok("c", clock, HOUR)]).await;
    assert_eq!(f.transport.reverify().await.expect("verified").name, "b");
    assert_eq!(f.transport.reverify().await.expect("verified").name, "c");
    assert_eq!(f.script.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_finished_verification_that_a_slow_waiter_still_holds_is_not_joined() {
    use futures_util::FutureExt;

    let gate = Arc::new(Notify::new());
    let f = connected(|clock| {
        vec![
            Step::Gated(Arc::clone(&gate), Ok(record("b", clock, HOUR))),
            ok("c", clock, HOUR),
        ]
    })
    .await;

    // Two callers wait for one verification. The first is a task; the
    // second is polled by hand, so that it can be left behind.
    let first = {
        let transport = f.transport.clone();
        tokio::spawn(async move { transport.reverify().await })
    };
    settle().await;
    let mut slow = Box::pin(f.transport.reverify());
    assert!((&mut slow).now_or_never().is_none());

    gate.notify_one();
    assert_eq!(first.await.expect("joined").expect("verified").name, "b");
    assert_eq!(f.script.calls(), 2);

    // The verification is finished, and the slow waiter has not looked
    // yet. A caller that asks for a new verification now gets a new one.
    assert_eq!(f.transport.reverify().await.expect("verified").name, "c");
    assert_eq!(f.script.calls(), 3);
    assert!(slow.await.is_ok());
    assert_eq!(f.script.calls(), 3);
}

// Dropped callers.

#[tokio::test(start_paused = true)]
async fn dropping_one_waiter_leaves_the_verification_to_the_others() {
    for dropped in [0, 1, 2] {
        let gate = Arc::new(Notify::new());
        let f = connected(|clock| {
            vec![Step::Gated(
                Arc::clone(&gate),
                Ok(record("b", clock, 3 * HOUR)),
            )]
        })
        .await;
        tokio::time::advance(HOUR).await;

        let mut waiters: Vec<_> = (0..3)
            .map(|_| {
                let transport = f.transport.clone();
                tokio::spawn(async move { transport.ensure_verified().await })
            })
            .collect();
        settle().await;
        // The first waiter started the verification; the others joined it.
        let abandoned = waiters.remove(dropped);
        abandoned.abort();
        assert!(abandoned.await.expect_err("aborted").is_cancelled());
        settle().await;

        gate.notify_one();
        for waiter in waiters {
            assert_eq!(waiter.await.expect("joined").expect("verified").name, "b");
        }
        assert_eq!(f.script.calls(), 2, "waiter {dropped} dropped");
        assert_eq!(f.transport.current().name, "b");
    }
}

#[tokio::test(start_paused = true)]
async fn dropping_every_waiter_abandons_the_verification_and_the_next_caller_starts_a_new_one() {
    let gate = Arc::new(Notify::new());
    let f = connected(|clock| {
        vec![
            Step::Gated(Arc::clone(&gate), Ok(record("abandoned", clock, 3 * HOUR))),
            ok("b", clock, 3 * HOUR),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;

    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let transport = f.transport.clone();
            tokio::spawn(async move { transport.ensure_verified().await })
        })
        .collect();
    settle().await;
    assert_eq!(f.script.calls(), 2);
    for waiter in waiters {
        waiter.abort();
        assert!(waiter.await.expect_err("aborted").is_cancelled());
    }

    // Nothing was published, and the transport is not waiting on anything.
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(
        f.transport.ensure_verified().await.expect("verified").name,
        "b"
    );
    assert_eq!(f.script.calls(), 3);
    // The abandoned attempt is gone: releasing it publishes nothing.
    gate.notify_one();
    settle().await;
    assert_eq!(f.transport.current().name, "b");
    assert_eq!(f.mode.bound(), ["a", "b"]);
}

#[tokio::test(start_paused = true)]
async fn a_caller_dropped_in_the_pause_before_the_retry_leaves_the_transport_usable() {
    let f = connected(|clock| {
        vec![
            Step::Ready(Err(Error::network("down"))),
            // The retry of the abandoned verification is never asked for.
            ok("b", clock, 3 * HOUR),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;
    let abandoned = tokio::time::timeout(RETRY_DELAY / 2, f.transport.ensure_verified()).await;
    assert!(abandoned.is_err());
    assert_eq!(f.script.calls(), 2);
    assert_eq!(
        f.transport.ensure_verified().await.expect("verified").name,
        "b"
    );
    assert_eq!(f.script.calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn a_dropped_reverify_leaves_the_previous_binding_in_place() {
    let gate = Arc::new(Notify::new());
    let f =
        connected(|clock| vec![Step::Gated(Arc::clone(&gate), Ok(record("b", clock, HOUR)))]).await;
    let abandoned = tokio::time::timeout(Duration::from_secs(5), f.transport.reverify()).await;
    assert!(abandoned.is_err());
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(
        f.transport
            .ensure_verified()
            .await
            .expect("still valid")
            .name,
        "a"
    );
    assert_eq!(served_by(&f.transport).await, "a");
    assert_eq!(f.script.calls(), 2);
    assert!(f.mode.retired().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_dropped_request_that_waited_for_a_verification_sends_nothing() {
    let gate = Arc::new(Notify::new());
    let f = connected(|clock| {
        vec![
            Step::Gated(Arc::clone(&gate), Ok(record("abandoned", clock, 3 * HOUR))),
            ok("b", clock, 3 * HOUR),
        ]
    })
    .await;
    tokio::time::advance(HOUR).await;
    let abandoned =
        tokio::time::timeout(Duration::from_secs(5), f.transport.round_trip(request())).await;
    assert!(abandoned.is_err());
    assert!(f.mode.sent().is_empty());
    assert_eq!(served_by(&f.transport).await, "b");
}

// Requests.

#[tokio::test(start_paused = true)]
async fn a_request_that_the_mode_cannot_protect_never_starts_a_verification() {
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    tokio::time::advance(HOUR).await;
    let connect = Request::new(
        Method::CONNECT,
        Url::parse("https://enclave.example.com/").unwrap(),
    );
    let failure = f.transport.round_trip(connect).await.expect_err("refused");
    assert_eq!(failure.error.kind(), ErrorKind::Configuration);
    assert_eq!(failure.key, KeyFailure::None);
    assert_eq!(f.script.calls(), 1);
    assert!(f.mode.sent().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_key_rejection_invalidates_the_verification_and_the_next_request_verifies_again() {
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    f.mode.reply("a", Reply::PeerLacksKey);

    let failure = f
        .transport
        .round_trip(request())
        .await
        .expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::Rejected);
    assert_eq!(failure.error.kind(), ErrorKind::Attestation);
    // The last successful verification is still reported, and nothing has
    // been verified yet.
    assert_eq!(f.transport.current().name, "a");
    assert_eq!(f.script.calls(), 1);

    assert_eq!(served_by(&f.transport).await, "b");
    assert_eq!(f.script.calls(), 2);
    assert_eq!(f.mode.sent(), ["a", "b"]);
    assert_eq!(f.transport.current().name, "b");
}

#[tokio::test(start_paused = true)]
async fn ensure_verified_verifies_again_after_a_key_rejection() {
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    f.mode.reply("a", Reply::PeerLacksKey);
    assert!(f.transport.round_trip(request()).await.is_err());
    assert_eq!(
        f.transport.ensure_verified().await.expect("verified").name,
        "b"
    );
}

#[tokio::test(start_paused = true)]
async fn a_late_rejection_of_a_replaced_verification_does_not_retire_the_new_one() {
    let gate = Arc::new(Notify::new());
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    f.mode.reply(
        "a",
        Reply::Gated(Arc::clone(&gate), Box::new(Reply::PeerLacksKey)),
    );

    let in_flight = {
        let transport = f.transport.clone();
        tokio::spawn(async move { transport.round_trip(request()).await })
    };
    settle().await;
    assert_eq!(f.mode.sent(), ["a"]);

    assert_eq!(f.transport.reverify().await.expect("verified").name, "b");
    gate.notify_one();
    let failure = in_flight.await.expect("joined").expect_err("rejected");
    assert_eq!(failure.key, KeyFailure::Rejected);

    // The rejection was of the old keys: the new verification stands.
    assert_eq!(served_by(&f.transport).await, "b");
    assert_eq!(f.script.calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_request_in_flight_finishes_on_the_binding_it_started_on_which_is_retired_afterwards() {
    let gate = Arc::new(Notify::new());
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    f.mode.reply(
        "a",
        Reply::Gated(Arc::clone(&gate), Box::new(Reply::Respond)),
    );

    let in_flight = {
        let transport = f.transport.clone();
        tokio::spawn(async move { served_by(&transport).await })
    };
    settle().await;

    assert_eq!(f.transport.reverify().await.expect("verified").name, "b");
    // The old binding is still serving its request.
    assert!(f.mode.retired().is_empty());
    assert_eq!(served_by(&f.transport).await, "b");

    gate.notify_one();
    assert_eq!(in_flight.await.expect("joined"), "a");
    assert_eq!(f.mode.retired(), ["a"]);
}

#[tokio::test(start_paused = true)]
async fn a_replaced_binding_with_no_request_in_flight_is_retired_at_once() {
    let f = connected(|clock| vec![ok("b", clock, HOUR)]).await;
    f.transport.reverify().await.expect("verified");
    assert_eq!(f.mode.retired(), ["a"]);
}

#[tokio::test(start_paused = true)]
async fn another_failure_passes_through_and_invalidates_nothing() {
    let f = connected(|_| vec![]).await;
    f.mode.reply(
        "a",
        Reply::Fail(Error::network("connection reset"), KeyFailure::None),
    );
    // A binding has no say over invalidation: only the transport vouches
    // for it.
    f.mode.reply(
        "a",
        Reply::Fail(Error::network("claims a rejection"), KeyFailure::Rejected),
    );

    for message in ["connection reset", "claims a rejection"] {
        let failure = f.transport.round_trip(request()).await.expect_err("fails");
        assert_eq!(
            failure.error.to_string(),
            format!("network error: {message}")
        );
        assert_eq!(failure.key, KeyFailure::None);
    }
    assert_eq!(served_by(&f.transport).await, "a");
    assert_eq!(f.script.calls(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_clock_of_the_fixture_follows_paused_time() {
    let f = connected(|_| vec![]).await;
    let before = (f.clock)();
    tokio::time::advance(HOUR).await;
    assert_eq!((f.clock)().duration_since(before).expect("later"), HOUR);
}
