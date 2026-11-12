//! Sends a request once more after a key rejection.

use std::sync::Arc;

use reqwest::{Request, Response};

use crate::error::Error;
use crate::internal::BoxFuture;
use crate::internal::transport::{Failure, KeyFailure, RoundTrip};

/// `next` behind a layer that sends a request a second time when the first
/// attempt fails with a
/// [`KeyFailure::Rejected`](crate::internal::transport::KeyFailure::Rejected). The
/// rejection has already invalidated the verification, so the second
/// attempt verifies the same enclave host again and goes out under the new
/// keys.
///
/// - Only a request whose body can be produced again is replayed: no body,
///   or a body held in memory. For a streaming body the error is an
///   attestation error that says that the body could not be sent again,
///   with the rejection attached ([`Error::earlier_attempt`]).
/// - There is one replay. If it fails, its error is returned with the first
///   rejection attached, and it makes no layer replay again.
/// - Any other error, and every response, passes through untouched. A
///   failure that only claims a missing key
///   ([`KeyFailure::PeerLacksKey`]) is not replayed: nothing has
///   invalidated the verification that it was sent under.
pub(crate) fn with_replay(next: Arc<dyn RoundTrip>) -> Arc<dyn RoundTrip> {
    Arc::new(Replay { next })
}

/// The layer of [`with_replay`].
struct Replay {
    next: Arc<dyn RoundTrip>,
}

impl RoundTrip for Replay {
    fn round_trip(&self, request: Request) -> BoxFuture<Result<Response, Failure>> {
        let next = Arc::clone(&self.next);
        Box::pin(async move {
            // `None` for a body that is a stream.
            let again = request.try_clone();
            let rejection = match next.round_trip(request).await {
                Err(failure) if failure.key == KeyFailure::Rejected => failure.error,
                other => return other,
            };
            let Some(again) = again else {
                return Err(Error::attestation(
                    "cannot send the request again after the enclave's key changed: its body \
                     is a stream, which cannot be replayed",
                )
                .after(rejection)
                .unsent_after_rejection()
                .into());
            };
            match next.round_trip(again).await {
                Ok(response) => Ok(response),
                Err(failure) => Err(failure.error.after_all(rejection).into()),
            }
        })
    }
}
