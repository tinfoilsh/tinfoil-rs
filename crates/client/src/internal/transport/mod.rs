//! The request chain between a client and its enclave.
//!
//! A [`Transport`] verifies an enclave and sends each request under the
//! keys of its current verification. The other modules each add one layer
//! in front of it, and a route chooses which to stack. From the caller
//! inward, an enclave or router client sends through:
//!
//! 1. [`origin`]: refuses a request to any origin other than the enclave's
//!    or the proxy URL's;
//! 2. [`cachesecret`]: adds the user cache secret to the bodies that carry
//!    it, above the sealing layer, so that the field is sealed with the
//!    rest of the body or sent over the pinned connection;
//! 3. [`replay`]: sends a request once more after a key rejection;
//! 4. [`header`]: names the enclave to a proxy;
//! 5. the [`Transport`], whose mode is [`tls`] or [`ehbp`].

use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::FutureExt;
use futures_util::future::{Shared, WeakShared};
use reqwest::{Request, Response};

use crate::error::{Error, ErrorKind};
use crate::internal::BoxFuture;
use crate::internal::enclave::{Enclave, Evidence, fresh_at, freshness_expired};
use crate::verifier::VerificationReport;

pub(crate) mod base_url;
pub(crate) mod cachesecret;
pub(crate) mod ehbp;
pub(crate) mod header;
pub(crate) mod origin;
pub(crate) mod replay;
pub(crate) mod tls;

#[cfg(test)]
mod tests;

/// What a failed request says about the keys that it was sent under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyFailure {
    /// Nothing: the failure has another cause.
    None,
    /// The peer does not hold the keys that the transport was bound to, as
    /// a bound transport detected before the enclave's application saw the
    /// request. Only a bound transport reports this.
    PeerLacksKey,
    /// The same, after the [`Transport`] has invalidated the verification
    /// that the request was sent under: a replay will go out under a fresh
    /// one. Only the [`Transport`] reports this, and only this may make a
    /// caller replay.
    Rejected,
}

/// The failure of a request in the chain: the error for the caller, and
/// what it says about the keys.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) error: Error,
    pub(crate) key: KeyFailure,
}

impl Failure {
    /// The failure of a bound transport whose peer does not hold its keys.
    /// `error` is the attestation error for the caller.
    pub(crate) fn peer_lacks_key(error: Error) -> Self {
        Self {
            error,
            key: KeyFailure::PeerLacksKey,
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self {
            error,
            key: KeyFailure::None,
        }
    }
}

/// One layer of the request chain.
pub(crate) trait RoundTrip: Send + Sync + 'static {
    /// Sends `request` and returns the response, whatever its status.
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>>;
}

/// A way to protect requests with the keys of one verification.
pub(crate) trait Mode<V>: Send + Sync + 'static {
    /// A configuration error for a request that the mode cannot protect.
    /// It runs before any I/O, so such a request never starts a
    /// verification.
    fn validate_request(&self, request: &Request) -> Result<(), Error>;

    /// A transport bound to the keys of `evidence`. Evidence without the
    /// key that the mode needs is an attestation error. The bound
    /// transport reports a peer that does not hold the keys with
    /// [`Failure::peer_lacks_key`].
    ///
    /// Dropping the returned transport retires it: the [`Transport`] drops
    /// its reference when a newer verification replaces this one, and each
    /// request in flight holds one until it finishes.
    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error>;
}

/// One successful verification and the transport bound to its keys. They
/// are published together, so that a request is never sent under keys
/// other than those of the verification that it checked.
pub(crate) struct State<V> {
    pub(crate) evidence: Arc<V>,
    /// The transport bound to the keys of `evidence`, until something
    /// invalidates the state: a key rejection, or a re-verification that
    /// fails with an attestation error. Invalidation drops it, so that a
    /// binding's idle connections close at once, and no new request can
    /// reach them. A request in flight holds a reference of its own.
    bound: Mutex<Option<Arc<dyn RoundTrip>>>,
}

impl<V> State<V> {
    /// The bound transport, or `None` once the state has been invalidated.
    /// The lock is never held across an await, and every write leaves it
    /// consistent, so a lock that a panicking holder poisoned is still
    /// usable.
    fn bound(&self) -> MutexGuard<'_, Option<Arc<dyn RoundTrip>>> {
        match self.bound.lock() {
            Ok(bound) => bound,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Invalidates the state for good and drops its binding.
    fn invalidate(&self) {
        let retired = self.bound().take();
        // The binding is dropped outside the lock.
        drop(retired);
    }
}

/// The verification in progress, shared by every caller that waits for it.
type Refresh = Shared<BoxFuture<Result<(), Error>>>;

/// A reference to a [`Refresh`] that does not keep it alive.
type WeakRefresh = WeakShared<BoxFuture<Result<(), Error>>>;

/// Verifies its enclave, and again when the verification expires or is
/// rejected, and sends each request over the transport bound to the keys
/// of the current verification.
///
/// - **One verification at a time.** Callers that need a verification while
///   one is running wait for that one and share its result, a failure
///   included; a caller that asks for a new verification while one is
///   running joins it too. The shared future is driven by its waiters: a
///   caller that is dropped leaves it to the others, and when the last
///   waiter is dropped the attempt is dropped with it and the next caller
///   starts a new one. There is no background task.
/// - **Publication.** A new state is published only after the mode has
///   bound a transport to it and the evidence is still fresh at that
///   moment; evidence that expired meanwhile is an attestation error and
///   publishes nothing. A failed verification is not remembered: the next
///   caller verifies again.
/// - **Failure.** A verification that fails with an attestation error
///   invalidates the state that it was replacing, so that no request that
///   starts afterwards is sent under it, even while it is fresh: the next
///   request verifies first. A network or a configuration error, or a
///   verification that every caller dropped, keeps the previous state,
///   which stays usable until it expires or is invalidated.
/// - **Retirement.** Publishing or invalidating drops the bound transport
///   of the previous state. Requests in flight finish on it, and it is
///   gone once the last of them is done.
/// - **Rejection.** A key rejection invalidates the state that the request
///   was sent under, not the current one, so a late rejection cannot retire
///   a newer verification. A failed verification likewise invalidates only
///   the state that it was replacing.
/// - **Attempts.** Every attempt to verify the enclave, the first attempt
///   of a verification that is retried included, becomes the last
///   verification as soon as its outcome is decided, and is then told to
///   the enclave's observer, outside every lock. The outcome of an attempt
///   that binding or freshness refused afterwards is that error. An
///   abandoned attempt has no outcome, and is neither kept nor told.
///
/// The transport is a handle: a clone shares the same state.
pub(crate) struct Transport<V: Evidence = VerificationReport> {
    inner: Arc<Inner<V>>,
}

impl<V: Evidence> Clone for Transport<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V: Evidence> std::fmt::Debug for Transport<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").finish_non_exhaustive()
    }
}

struct Inner<V: Evidence> {
    enclave: Enclave<V>,
    mode: Arc<dyn Mode<V>>,
    slot: Mutex<Slot<V>>,
}

struct Slot<V> {
    /// The last successful verification.
    state: Arc<State<V>>,
    /// The outcome of the last attempt to verify the enclave, which may be
    /// a failure after `state` was published.
    last: Result<Arc<V>, Error>,
    /// The verification that callers are waiting for, with its number. The
    /// reference is weak: the waiters own the future, so that it is dropped
    /// with the last of them.
    refresh: Option<(u64, WeakRefresh)>,
    /// The number of the next verification.
    next_refresh: u64,
}

impl<V: Evidence> Inner<V> {
    /// The slot. It is never held across an await, and every write leaves
    /// it consistent, so a lock that a panicking holder poisoned is still
    /// usable.
    fn slot(&self) -> MutexGuard<'_, Slot<V>> {
        match self.slot.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The transport bound to `state` if the state authorizes a request
    /// now: nothing has invalidated it, and its evidence is before its
    /// deadline.
    fn valid(&self, state: &State<V>) -> Option<Arc<dyn RoundTrip>> {
        if !fresh_at(state.evidence.as_ref(), (self.enclave.clock())()) {
            return None;
        }
        state.bound().clone()
    }

    /// Verifies the enclave, binds the mode to the result and makes sure
    /// that the evidence is fresh. A first attempt that fails and is
    /// retried is recorded and told at once ([`retried`](Self::retried)).
    async fn fresh_state(&self) -> Result<Arc<State<V>>, Error> {
        let evidence = self.enclave.verify(|error| self.retried(error)).await?;
        new_state(self.mode.as_ref(), self.enclave.clock(), evidence)
    }

    /// Records the failure of an attempt that is about to be retried as
    /// the last verification, and tells the enclave's observer after the
    /// slot's lock is released.
    fn retried(&self, error: &Error) {
        self.slot().last = Err(error.clone());
        self.enclave.notify(Err(error));
    }

    /// One shared verification, numbered `id`, of an enclave whose last
    /// successful verification is `replacing`: verifies, binds, and
    /// publishes the new state if it is still fresh. Whatever the outcome,
    /// it removes itself from the slot before it completes, so that no
    /// later caller is handed a finished verification.
    ///
    /// An attestation error invalidates `replacing`: a request that starts
    /// afterwards is not sent under it, but waits for a verification of
    /// its own. Any other error, a network or a configuration error,
    /// leaves `replacing` as valid as it was. A dropped verification
    /// touches nothing. Only `replacing` is invalidated, never a state
    /// that was published after it.
    ///
    /// The outcome becomes the last verification under the slot's lock, and
    /// is told to the enclave's observer once the lock is released and the
    /// refresh has left the slot, so that an observer that starts a
    /// verification starts one of its own.
    async fn refresh(self: Arc<Self>, id: u64, replacing: Arc<State<V>>) -> Result<(), Error> {
        let result = self.fresh_state().await;
        let mut slot = self.slot();
        if slot
            .refresh
            .as_ref()
            .is_some_and(|(current, _)| *current == id)
        {
            slot.refresh = None;
        }
        // Binding, or waiting for the slot, can outlast the deadline.
        let result = result.and_then(|state| match self.valid(&state) {
            Some(_) => Ok(state),
            None => Err(freshness_expired()),
        });
        match result {
            Ok(state) => {
                let evidence = Arc::clone(&state.evidence);
                slot.last = Ok(Arc::clone(&evidence));
                slot.state = state;
                drop(slot);
                self.enclave.notify(Ok(&evidence));
                Ok(())
            }
            Err(error) => {
                slot.last = Err(error.clone());
                // Under the slot's lock, so that no caller can take the
                // state as valid after the verification has failed.
                let retired = if error.kind() == ErrorKind::Attestation {
                    replacing.bound().take()
                } else {
                    None
                };
                drop(slot);
                drop(retired);
                self.enclave.notify(Err(&error));
                Err(error)
            }
        }
    }
}

/// Binds `mode` to `evidence` and requires the evidence to be fresh
/// afterwards.
fn new_state<V: Evidence>(
    mode: &dyn Mode<V>,
    clock: &crate::internal::Clock,
    evidence: V,
) -> Result<Arc<State<V>>, Error> {
    let bound = mode.bind(&evidence)?;
    if !fresh_at(&evidence, clock()) {
        return Err(freshness_expired());
    }
    Ok(Arc::new(State {
        evidence: Arc::new(evidence),
        bound: Mutex::new(Some(bound)),
    }))
}

impl<V: Evidence> Transport<V> {
    /// Verifies `enclave` and returns a transport that holds the result.
    /// `retry` gives the verification its one retry; without it a caller
    /// that tries several enclaves moves on quickly. No transport exists
    /// without a successful verification.
    ///
    /// Each attempt is told to the enclave's observer once its outcome is
    /// decided: a first attempt that is retried before the pause, and the
    /// last one after binding, a failure included. The successful one is
    /// the transport's last verification.
    ///
    /// Dropping the future abandons the verification and keeps nothing.
    pub(crate) async fn connect(
        enclave: Enclave<V>,
        mode: Arc<dyn Mode<V>>,
        retry: bool,
    ) -> Result<Self, Error> {
        let evidence = if retry {
            enclave.verify(|error| enclave.notify(Err(error))).await
        } else {
            enclave.verify_once().await
        };
        let state = match evidence
            .and_then(|evidence| new_state(mode.as_ref(), enclave.clock(), evidence))
        {
            Ok(state) => state,
            Err(error) => {
                enclave.notify(Err(&error));
                return Err(error);
            }
        };
        enclave.notify(Ok(&state.evidence));
        let last = Ok(Arc::clone(&state.evidence));
        Ok(Self {
            inner: Arc::new(Inner {
                enclave,
                mode,
                slot: Mutex::new(Slot {
                    state,
                    last,
                    refresh: None,
                    next_refresh: 0,
                }),
            }),
        })
    }

    /// The enclave that the transport verifies.
    pub(crate) fn enclave(&self) -> &Enclave<V> {
        &self.inner.enclave
    }

    /// The last successful verification, unchecked: it may have expired or
    /// been invalidated. For the tests of the state that the transport
    /// keeps; the clients report [`last_verification`](Self::last_verification).
    #[cfg(test)]
    pub(crate) fn current(&self) -> Arc<V> {
        Arc::clone(&self.inner.slot().state.evidence)
    }

    /// The outcome of the last attempt to verify the enclave, without I/O
    /// and unchecked: a success may have expired or been invalidated since.
    /// A failure is the error that the attempt was reported with.
    pub(crate) fn last_verification(&self) -> Result<Arc<V>, Error> {
        self.inner.slot().last.clone()
    }

    /// A verification that is valid now, verifying first only if the
    /// current one has expired or was invalidated. `Ok` means that requests
    /// can be sent under it.
    ///
    /// Dropping the future leaves the current state as it is; see the type
    /// for what happens to a verification in progress.
    pub(crate) async fn ensure_verified(&self) -> Result<Arc<V>, Error> {
        let (state, _) = self.verified(false).await?;
        Ok(Arc::clone(&state.evidence))
    }

    /// Verifies again even if the current verification is still valid, and
    /// returns a verification that is valid now.
    ///
    /// A failure with an attestation error invalidates the current state,
    /// and drops its binding: the next request verifies again, and is not
    /// sent if that fails too. Any other failure keeps the current state,
    /// which stays usable until it expires or is invalidated.
    pub(crate) async fn reverify(&self) -> Result<Arc<V>, Error> {
        let (state, _) = self.verified(true).await?;
        Ok(Arc::clone(&state.evidence))
    }

    /// A valid state and the transport bound to it. With `force`, or when
    /// the current state is not valid, the caller first waits for a
    /// verification: the one in progress, or a new one.
    async fn verified(
        &self,
        mut force: bool,
    ) -> Result<(Arc<State<V>>, Arc<dyn RoundTrip>), Error> {
        loop {
            let refresh: Refresh = {
                let mut slot = self.inner.slot();
                if !force && let Some(bound) = self.inner.valid(&slot.state) {
                    return Ok((Arc::clone(&slot.state), bound));
                }
                let running = slot.refresh.as_ref().and_then(|(_, weak)| weak.upgrade());
                match running {
                    Some(refresh) => refresh,
                    None => {
                        let id = slot.next_refresh;
                        slot.next_refresh = id.wrapping_add(1);
                        let replacing = Arc::clone(&slot.state);
                        let future: BoxFuture<Result<(), Error>> =
                            Box::pin(Arc::clone(&self.inner).refresh(id, replacing));
                        let refresh = future.shared();
                        slot.refresh = refresh.downgrade().map(|weak| (id, weak));
                        refresh
                    }
                }
            };
            refresh.await?;
            // A request can invalidate the new state before this caller
            // wakes, so the slot is read again instead of trusting the
            // result.
            force = false;
        }
    }
}

impl<V: Evidence> RoundTrip for Transport<V> {
    /// Validates the request against the mode, which never starts a
    /// verification; obtains a valid state as
    /// [`ensure_verified`](Transport::ensure_verified) does, and fails
    /// without sending if there is none; and sends the request over the
    /// transport bound to that state. A failure that reports
    /// [`KeyFailure::PeerLacksKey`] invalidates that state and is returned
    /// as [`KeyFailure::Rejected`]. Every other failure and every response
    /// pass through.
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        let transport = self.clone();
        Box::pin(async move {
            transport.inner.mode.validate_request(&request)?;
            let (state, bound) = transport.verified(false).await?;
            match bound.round_trip(request).await {
                Ok(response) => Ok(response),
                Err(failure) => {
                    let key = match failure.key {
                        KeyFailure::PeerLacksKey => {
                            // The state that the request was sent under,
                            // which may no longer be the current one.
                            state.invalidate();
                            KeyFailure::Rejected
                        }
                        // Only this transport vouches for an invalidation.
                        KeyFailure::Rejected | KeyFailure::None => KeyFailure::None,
                    };
                    Err(Failure {
                        error: failure.error,
                        key,
                    })
                }
            }
        })
    }
}
