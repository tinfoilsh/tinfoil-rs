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

use std::sync::{Arc, RwLock};

use futures_util::future::Shared;
use reqwest::{Request, Response};

use crate::error::Error;
use crate::internal::enclave::{Enclave, Evidence};
use crate::internal::{BoxFuture, Clock};
use crate::verifier::Verification;

pub(crate) mod base_url;
pub(crate) mod cachesecret;
pub(crate) mod ehbp;
pub(crate) mod header;
pub(crate) mod origin;
pub(crate) mod replay;
pub(crate) mod tls;

/// One layer of the request chain.
pub(crate) trait RoundTrip: Send + Sync + 'static {
    /// Sends `request` and returns the response, whatever its status.
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Error>>;
}

/// A way to protect requests with the keys of one verification.
pub(crate) trait Mode<V>: Send + Sync + 'static {
    /// A configuration error for a request that the mode cannot protect.
    /// It runs before any I/O, so such a request never starts a
    /// verification.
    fn validate_request(&self, request: &Request) -> Result<(), Error>;

    /// A transport bound to the keys of `evidence`. Its errors that mean
    /// "the peer does not hold these keys", detected before the enclave's
    /// application saw the request, are marked with [`PeerLacksKey`].
    fn bind(&self, evidence: &V) -> Result<Arc<dyn RoundTrip>, Error>;
}

/// The error of a bound transport whose peer does not hold the keys that it
/// was bound to. The [`Transport`] turns it into a [`KeyRejection`] once it
/// has invalidated the state that the request was sent under; only that
/// error may make a caller replay.
#[derive(Debug)]
pub(crate) struct PeerLacksKey(pub(crate) Error);

/// A key rejection whose verification has already been invalidated, so a
/// replay goes out under a fresh one. It wraps the attestation error of the
/// rejection.
#[derive(Debug)]
pub(crate) struct KeyRejection(pub(crate) Error);

/// One successful verification and the transport bound to its keys. They
/// are published together, so that a request is never sent under keys
/// other than those of the verification that it checked.
pub(crate) struct State<V> {
    pub(crate) evidence: Arc<V>,
    pub(crate) bound: Arc<dyn RoundTrip>,
}

/// The verification in progress, shared by every caller that waits for it.
type Refresh<V> = Shared<BoxFuture<Result<Arc<State<V>>, Error>>>;

/// Verifies its enclave, and again when the verification expires or is
/// rejected, and sends each request over the transport bound to the keys
/// of the current verification.
///
/// - **One verification at a time.** Callers that need a verification while
///   one is running wait for that one and share its result, a failure
///   included. The shared future is driven by its waiters: a caller that is
///   dropped leaves it to the others, and when the last waiter is dropped
///   the attempt is abandoned and the next caller starts a new one. There
///   is no background task.
/// - **Publication.** A new state is published only after the mode has
///   bound a transport to it and the evidence is still fresh at that
///   moment; evidence that expired meanwhile is an attestation error and
///   publishes nothing. A failed verification keeps the previous state.
/// - **Retirement.** Publishing replaces the bound transport. Requests in
///   flight finish on the old one, whose idle connections are closed when
///   the last of them is done.
/// - **Rejection.** A key rejection invalidates the state that the request
///   was sent under, not the current one, so a late rejection cannot retire
///   a newer verification.
pub(crate) struct Transport<V = Verification> {
    enclave: Enclave<V>,
    mode: Arc<dyn Mode<V>>,
    clock: Clock,
    current: RwLock<Slot<V>>,
}

struct Slot<V> {
    /// The last successful verification.
    state: Arc<State<V>>,
    /// Whether a key rejection invalidated `state`.
    rejected: bool,
    /// The verification that callers are waiting for, if one is running.
    refresh: Option<Refresh<V>>,
}

impl<V: Evidence> Transport<V> {
    /// Verifies `enclave` and returns a transport that holds the result.
    /// `retry` selects [`Enclave::verify`] over [`Enclave::verify_once`].
    /// No transport exists without a successful verification.
    pub(crate) async fn connect(
        enclave: Enclave<V>,
        mode: Arc<dyn Mode<V>>,
        clock: Clock,
        retry: bool,
    ) -> Result<Self, Error> {
        Err(Error::not_implemented("the verified transport"))
    }

    /// The enclave that the transport verifies.
    pub(crate) fn enclave(&self) -> &Enclave<V> {
        &self.enclave
    }

    /// The last successful verification, unchecked: it may have expired or
    /// been rejected.
    pub(crate) fn current(&self) -> Arc<V> {
        let slot = match self.current.read() {
            Ok(slot) => slot,
            // A slot is replaced as a whole, so one that a panicking writer
            // left behind is still consistent.
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(&slot.state.evidence)
    }

    /// A verification that is valid now, verifying first only if the
    /// current one has expired or was rejected. `Ok` means that requests
    /// can be sent under it.
    pub(crate) async fn ensure_verified(&self) -> Result<Arc<V>, Error> {
        Err(Error::not_implemented("ensure_verified"))
    }

    /// Verifies again even if the current verification is still valid.
    pub(crate) async fn reverify(&self) -> Result<Arc<V>, Error> {
        Err(Error::not_implemented("reverify"))
    }
}

impl<V: Evidence> RoundTrip for Transport<V> {
    /// Validates the request against the mode, obtains a valid state as
    /// [`ensure_verified`](Transport::ensure_verified) does, and sends the
    /// request over its bound transport. A [`PeerLacksKey`] error
    /// invalidates that state and is returned as a [`KeyRejection`].
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Error>> {
        Box::pin(async { Err(Error::not_implemented("the verified transport")) })
    }
}
