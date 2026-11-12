//! The body of a response from an attested client.
//!
//! A response is `reqwest`'s, and so is the error of reading its body. The
//! clients put every response body behind a [`guard`], so that a failed
//! read carries a classified [`Error`] that `Error::from_reqwest` finds,
//! and so that the request's deadline also ends a body that is still
//! being read.

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body::{Body, Frame, SizeHint};
use reqwest::Response;
use tokio::time::{Instant, Sleep};

use crate::error::{Error, ErrorKind};

/// The message of the error for a deadline that passed.
pub(crate) const DEADLINE_PASSED: &str = "the operation did not finish before its timeout";

/// `response` with its body guarded:
///
/// - A read that fails, fails with a `reqwest` error whose source is the
///   client's error for it ([`classify`]).
/// - With a `deadline`, a read that has not finished by then fails with a
///   network error that is marked as a timeout, whether or not data is
///   still arriving. Nothing is read after that.
///
/// The status, the headers, the URL and the body's declared length stay as
/// they are.
pub(crate) fn guard(response: Response, deadline: Option<Instant>) -> Response {
    let (parts, body) = http::Response::<reqwest::Body>::from(response).into_parts();
    let guarded = Guarded {
        inner: body,
        deadline: deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline))),
        failed: false,
    };
    Response::from(http::Response::from_parts(
        parts,
        reqwest::Body::wrap(guarded),
    ))
}

/// A response body, its deadline, and whether it has failed.
struct Guarded {
    inner: reqwest::Body,
    deadline: Option<Pin<Box<Sleep>>>,
    failed: bool,
}

impl Body for Guarded {
    type Data = <reqwest::Body as Body>::Data;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(None);
        }
        // The deadline first: data that arrives after it is not delivered.
        if let Some(deadline) = &mut this.deadline
            && deadline.as_mut().poll(cx).is_ready()
        {
            this.failed = true;
            return Poll::Ready(Some(Err(Error::deadline(DEADLINE_PASSED))));
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Err(error))) => {
                this.failed = true;
                Poll::Ready(Some(Err(classify(error))))
            }
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The client's error for a failed read of a response body.
///
/// - An error that already carries a client error keeps it.
/// - A failure of the sealed-body protocol other than its carrier's (a
///   frame that does not authenticate, a body that ends inside a frame, a
///   frame over the size limit) is an attestation error: what follows in
///   the body cannot be trusted. Its message names the protocol's error.
/// - Anything else is a network error, marked when it is a timeout.
///
/// The `reqwest` error is the source, without its URL, which may hold a
/// credential.
pub(crate) fn classify(error: reqwest::Error) -> Error {
    let error = error.without_url();
    if let Some(classified) = Error::find_in(&error) {
        return classified.clone();
    }
    let timeout = error.is_timeout();
    match protocol_failure(&error) {
        Some(detail) => Error::wrap(
            ErrorKind::Attestation,
            Unauthenticated {
                detail,
                source: error,
            },
        ),
        None => {
            let error = Error::wrap(ErrorKind::Network, error);
            if timeout { error.timed_out() } else { error }
        }
    }
}

/// The text of the sealed-body protocol's error among the sources of
/// `error`, unless it is a failure of the connection underneath.
fn protocol_failure(error: &(dyn StdError + 'static)) -> Option<String> {
    let mut next = Some(error);
    while let Some(error) = next {
        match error.downcast_ref::<tinfoil_ehbp::Error>() {
            Some(tinfoil_ehbp::Error::Http(_)) => return None,
            Some(protocol) => return Some(protocol.to_string()),
            None => next = error.source(),
        }
    }
    None
}

/// A sealed response body that stopped authenticating.
#[derive(Debug)]
struct Unauthenticated {
    detail: String,
    source: reqwest::Error,
}

impl fmt::Display for Unauthenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the sealed response body could not be opened: {}",
            self.detail
        )
    }
}

impl StdError for Unauthenticated {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}
