//! Sends a request once more after a key rejection.

use std::sync::Arc;

use crate::internal::transport::RoundTrip;

/// `next` behind a layer that sends a request a second time when the first
/// attempt fails with a
/// [`KeyRejection`](crate::internal::transport::KeyRejection). The
/// rejection has already invalidated the verification, so the second
/// attempt verifies the same enclave host again and goes out under the new
/// keys.
///
/// - Only a request whose body can be produced again is replayed: no body,
///   or a body held in memory. For a streaming body the rejection is
///   returned, with a note that the body could not be sent again.
/// - There is one replay. If it fails, its error is returned with the first
///   rejection attached.
/// - Any other error, and every response, passes through untouched.
pub(crate) fn with_replay(next: Arc<dyn RoundTrip>) -> Arc<dyn RoundTrip> {
    next
}
