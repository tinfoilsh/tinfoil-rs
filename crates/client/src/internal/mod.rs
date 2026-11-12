//! The machinery behind the clients. Nothing here is public.
//!
//! | module | what it does |
//! |---|---|
//! | [`sdkinfo`] | the SDK's name and version, as sent with attestation fetches |
//! | [`fetch`] | fetches a raw attestation document, directly or through a relay |
//! | [`enclave`] | one enclave and its policy: fetch, verify, key checks, the caller's veto, the retry |
//! | [`transport`] | the current verification and the transport bound to its keys, and the layers of the request chain |
//! | [`router`] | discovers Tinfoil's router |
//! | [`cachesecret`] | resolves and stores the user cache secret |
//! | [`attested`] | what the enclave and router clients share |
//! | [`body`] | the guard on a response body: its deadline and its errors |
//! | `gateway` | the gateway route (feature `unstable-gateway`) |
//!
//! Internal functions return [`Error`](crate::Error) values that are
//! already classified where the category is known at the point of failure,
//! and plain causes otherwise; `Error::wrap` at the seams gives a category
//! only to a cause that has none yet.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

pub(crate) mod attested;
pub(crate) mod body;
pub(crate) mod cachesecret;
pub(crate) mod enclave;
pub(crate) mod fetch;
#[cfg(feature = "unstable-gateway")]
pub(crate) mod gateway;
pub(crate) mod router;
pub(crate) mod sdkinfo;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod transport;

/// A boxed future that can move between threads.
pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// The wall clock that expiry is judged by. Tests supply their own.
pub(crate) type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync + 'static>;

/// The system clock.
pub(crate) fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}
