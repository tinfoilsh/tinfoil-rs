//! The request chain between a client and its enclave.
//!
//! A [`Transport`] verifies an enclave and sends each request under the
//! keys of its current verification. The other modules each add one layer
//! in front of it, and a route chooses which to stack. From the caller
//! inward, an enclave or router client sends through:
//!
//! 1. [`origin`]: refuses a request to any origin other than the enclave's
//!    or the configured base URL's;
//! 2. [`cachesecret`]: adds the user cache secret to the bodies that carry
//!    it, above the sealing layer, so that the field is sealed with the
//!    rest of the body or sent over the pinned connection;
//! 3. [`replay`]: sends a request once more after a key rejection;
//! 4. [`header`]: names the enclave to a proxy;
//! 5. the [`Transport`], whose mode is [`tls`] or [`ehbp`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::FutureExt;
use futures_util::future::{Shared, WeakShared};
use reqwest::{Request, Response};

use crate::error::Error;
use crate::internal::BoxFuture;
use crate::internal::enclave::{Enclave, Evidence, fresh_at, freshness_expired};
use crate::verifier::Verification;

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
    pub(crate) bound: Arc<dyn RoundTrip>,
    /// Whether a key rejection invalidated this state.
    rejected: AtomicBool,
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
///   publishes nothing. A failed verification keeps the previous state,
///   and is not remembered: the next caller verifies again.
/// - **Retirement.** Publishing replaces the bound transport. Requests in
///   flight finish on the old one, which is dropped when the last of them
///   is done.
/// - **Rejection.** A key rejection invalidates the state that the request
///   was sent under, not the current one, so a late rejection cannot retire
///   a newer verification.
///
/// The transport is a handle: a clone shares the same state.
pub(crate) struct Transport<V = Verification> {
    inner: Arc<Inner<V>>,
}

impl<V> Clone for Transport<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V> std::fmt::Debug for Transport<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transport").finish_non_exhaustive()
    }
}

struct Inner<V> {
    enclave: Enclave<V>,
    mode: Arc<dyn Mode<V>>,
    slot: Mutex<Slot<V>>,
}

struct Slot<V> {
    /// The last successful verification.
    state: Arc<State<V>>,
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

    /// Whether `state` authorizes a request now: no key rejection has
    /// invalidated it, and its evidence is before its deadline.
    fn valid(&self, state: &State<V>) -> bool {
        !state.rejected.load(Ordering::SeqCst)
            && fresh_at(state.evidence.as_ref(), (self.enclave.clock())())
    }

    /// Verifies the enclave, binds the mode to the result and makes sure
    /// that the evidence is fresh.
    async fn fresh_state(&self, retry: bool) -> Result<Arc<State<V>>, Error> {
        let evidence = if retry {
            self.enclave.verify().await?
        } else {
            self.enclave.verify_once().await?
        };
        new_state(self.mode.as_ref(), self.enclave.clock(), evidence)
    }

    /// One shared verification, numbered `id`: verifies, binds, and
    /// publishes the new state if it is still fresh. Whatever the outcome,
    /// it removes itself from the slot before it completes, so that no
    /// later caller is handed a finished verification.
    async fn refresh(self: Arc<Self>, id: u64) -> Result<(), Error> {
        let result = self.fresh_state(true).await;
        let mut slot = self.slot();
        if slot
            .refresh
            .as_ref()
            .is_some_and(|(current, _)| *current == id)
        {
            slot.refresh = None;
        }
        let state = result?;
        // Binding, or waiting for the slot, can outlast the deadline.
        if !self.valid(&state) {
            return Err(freshness_expired());
        }
        slot.state = state;
        Ok(())
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
        bound,
        rejected: AtomicBool::new(false),
    }))
}

impl<V: Evidence> Transport<V> {
    /// Verifies `enclave` and returns a transport that holds the result.
    /// `retry` gives the verification its one retry; without it a caller
    /// that tries several enclaves moves on quickly. No transport exists
    /// without a successful verification.
    ///
    /// Dropping the future abandons the verification and keeps nothing.
    pub(crate) async fn connect(
        enclave: Enclave<V>,
        mode: Arc<dyn Mode<V>>,
        retry: bool,
    ) -> Result<Self, Error> {
        let evidence = if retry {
            enclave.verify().await?
        } else {
            enclave.verify_once().await?
        };
        let state = new_state(mode.as_ref(), enclave.clock(), evidence)?;
        Ok(Self {
            inner: Arc::new(Inner {
                enclave,
                mode,
                slot: Mutex::new(Slot {
                    state,
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
    /// been rejected.
    pub(crate) fn current(&self) -> Arc<V> {
        Arc::clone(&self.inner.slot().state.evidence)
    }

    /// A verification that is valid now, verifying first only if the
    /// current one has expired or was rejected. `Ok` means that requests
    /// can be sent under it.
    ///
    /// Dropping the future leaves the current state as it is; see the type
    /// for what happens to a verification in progress.
    pub(crate) async fn ensure_verified(&self) -> Result<Arc<V>, Error> {
        let state = self.verified(false).await?;
        Ok(Arc::clone(&state.evidence))
    }

    /// Verifies again even if the current verification is still valid, and
    /// returns a verification that is valid now. A failure keeps the
    /// current state, which stays usable until it expires or is rejected.
    pub(crate) async fn reverify(&self) -> Result<Arc<V>, Error> {
        let state = self.verified(true).await?;
        Ok(Arc::clone(&state.evidence))
    }

    /// A valid state. With `force`, or when the current state is not
    /// valid, the caller first waits for a verification: the one in
    /// progress, or a new one.
    async fn verified(&self, mut force: bool) -> Result<Arc<State<V>>, Error> {
        loop {
            let refresh: Refresh = {
                let mut slot = self.inner.slot();
                if !force && self.inner.valid(&slot.state) {
                    return Ok(Arc::clone(&slot.state));
                }
                let running = slot.refresh.as_ref().and_then(|(_, weak)| weak.upgrade());
                match running {
                    Some(refresh) => refresh,
                    None => {
                        let id = slot.next_refresh;
                        slot.next_refresh = id.wrapping_add(1);
                        let future: BoxFuture<Result<(), Error>> =
                            Box::pin(Arc::clone(&self.inner).refresh(id));
                        let refresh = future.shared();
                        slot.refresh = refresh.downgrade().map(|weak| (id, weak));
                        refresh
                    }
                }
            };
            refresh.await?;
            // A request can reject the new state before this caller wakes,
            // so the slot is read again instead of trusting the result.
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
            let state = transport.verified(false).await?;
            match state.bound.round_trip(request).await {
                Ok(response) => Ok(response),
                Err(failure) => {
                    let key = match failure.key {
                        KeyFailure::PeerLacksKey => {
                            // The state that the request was sent under,
                            // which may no longer be the current one.
                            state.rejected.store(true, Ordering::SeqCst);
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
