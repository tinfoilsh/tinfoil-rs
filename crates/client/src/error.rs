//! The error that the clients return.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use crate::verifier::BoxError;

/// What a caller does about an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid arguments or client configuration, or a request that the
    /// client cannot protect. Fix the caller; retrying will not help.
    Configuration,
    /// The client could not reach what it needed: a network failure, a
    /// timeout, or an HTTP error status while it fetched attestation
    /// material, a failed connection to the enclave, or a gateway that keeps
    /// routing a request away from the enclave that it was sealed to. Retry
    /// later with the same client.
    Network,
    /// Rejected evidence, policy or channel binding: the enclave could not
    /// be trusted, and nothing was sent to it. The client verifies again by
    /// itself on the next request; a failure that persists deserves an
    /// investigation.
    Attestation,
}

impl ErrorKind {
    /// The kind as one lowercase word: `configuration`, `network` or
    /// `attestation`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::Configuration => "configuration",
            ErrorKind::Network => "network",
            ErrorKind::Attestation => "attestation",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error from a Tinfoil client.
///
/// Every error has one [`ErrorKind`], which says what to do about it. The
/// message is the kind, `" error: "`, then the cause, as in
/// `attestation error: <cause>`. [`source`](StdError::source) returns the
/// underlying error when there is one. For a rejected attestation document
/// that is the verifier's [`Error`](crate::verifier::Error), which carries
/// the layer that rejected it; it is a diagnostic, and neither its presence
/// nor its type is promised.
///
/// Errors from the OpenAI API are not of this type: they keep
/// `async_openai`'s own.
///
/// The error is cheap to clone: one failed verification is reported to
/// every request that waited for it.
#[derive(Clone)]
pub struct Error {
    inner: Arc<Inner>,
}

struct Inner {
    kind: ErrorKind,
    timeout: bool,
    cause: Cause,
    earlier_attempt: Option<Error>,
}

enum Cause {
    Message(String),
    Source(BoxError),
}

impl Error {
    /// The category of the error.
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    /// Whether a deadline ended the operation: the client's `timeout`
    /// option, a request's own timeout, or one of the client's fixed bounds
    /// on fetching attestation material.
    pub fn is_timeout(&self) -> bool {
        self.inner.timeout
    }

    /// The failure of the first attempt, when this error is the failure of
    /// the one retry that a verification gets.
    pub fn earlier_attempt(&self) -> Option<&Error> {
        self.inner.earlier_attempt.as_ref()
    }

    /// The client error behind a failed OpenAI call, if there is one.
    ///
    /// A typed `async_openai` call returns `OpenAIError`. When the attested
    /// HTTP client under it fails, for example because the enclave no longer
    /// passes verification, its error travels inside that `OpenAIError`;
    /// this returns it. `None` means that the failure came from the API or
    /// from `async_openai` itself.
    #[cfg(feature = "openai")]
    pub fn from_openai(error: &async_openai::error::OpenAIError) -> Option<&Error> {
        use async_openai::error::OpenAIError;
        let mut next: Option<&(dyn StdError + 'static)> = match error {
            OpenAIError::Boxed(boxed) => Some(boxed.as_ref()),
            OpenAIError::Reqwest(error) => Some(error),
            _ => None,
        };
        while let Some(error) = next {
            if let Some(found) = error.downcast_ref::<Error>() {
                return Some(found);
            }
            next = error.source();
        }
        None
    }

    fn new(kind: ErrorKind, cause: Cause) -> Self {
        Self {
            inner: Arc::new(Inner {
                kind,
                timeout: false,
                cause,
                earlier_attempt: None,
            }),
        }
    }

    /// A configuration error with `message` as its cause.
    pub(crate) fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Configuration, Cause::Message(message.into()))
    }

    /// A network error with `message` as its cause.
    pub(crate) fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, Cause::Message(message.into()))
    }

    /// An attestation error with `message` as its cause.
    pub(crate) fn attestation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Attestation, Cause::Message(message.into()))
    }

    /// An error of `kind` that wraps `source`, unless `source` is already a
    /// client error, which is returned as it is: an error keeps the category
    /// that it was first given.
    pub(crate) fn wrap(kind: ErrorKind, source: impl Into<BoxError>) -> Self {
        match source.into().downcast::<Error>() {
            Ok(classified) => *classified,
            Err(source) => Self::new(kind, Cause::Source(source)),
        }
    }

    /// The same error, marked as the expiry of a deadline.
    pub(crate) fn timed_out(self) -> Self {
        self.rebuild(|inner| inner.timeout = true)
    }

    /// The same error, with the failure of the attempt before it attached.
    pub(crate) fn after(self, earlier: Error) -> Self {
        self.rebuild(|inner| inner.earlier_attempt = Some(earlier))
    }

    /// The error of a function whose body is not written yet.
    pub(crate) fn not_implemented(what: &'static str) -> Self {
        Self::configuration(format!("{what} is not implemented"))
    }

    fn rebuild(self, change: impl FnOnce(&mut Inner)) -> Self {
        let mut inner = match Arc::try_unwrap(self.inner) {
            Ok(inner) => inner,
            Err(shared) => Inner {
                kind: shared.kind,
                timeout: shared.timeout,
                cause: Cause::Source(Box::new(Error { inner: shared })),
                earlier_attempt: None,
            },
        };
        change(&mut inner);
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner.cause {
            Cause::Message(message) => write!(f, "{} error: {message}", self.inner.kind),
            // A shared error that was rebuilt wraps itself; its message
            // already carries the prefix.
            Cause::Source(source) if source.is::<Error>() => source.fmt(f),
            Cause::Source(source) => write!(f, "{} error: {source}", self.inner.kind),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Error");
        debug.field("kind", &self.inner.kind);
        if self.inner.timeout {
            debug.field("timeout", &true);
        }
        match &self.inner.cause {
            Cause::Message(message) => debug.field("message", message),
            Cause::Source(source) => debug.field("source", source),
        };
        if let Some(earlier) = &self.inner.earlier_attempt {
            debug.field("earlier_attempt", earlier);
        }
        debug.finish()
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.inner.cause {
            Cause::Message(_) => None,
            Cause::Source(source) => Some(source.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_is_the_kind_then_the_cause() {
        assert_eq!(
            Error::configuration("enclave host is required").to_string(),
            "configuration error: enclave host is required"
        );
        assert_eq!(
            Error::network("503 Service Unavailable").to_string(),
            "network error: 503 Service Unavailable"
        );
        let io = std::io::Error::other("no HPKE key");
        let error = Error::wrap(ErrorKind::Attestation, io);
        assert_eq!(error.to_string(), "attestation error: no HPKE key");
        assert_eq!(error.kind(), ErrorKind::Attestation);
        assert!(error.source().is_some_and(|s| s.is::<std::io::Error>()));
    }

    #[test]
    fn wrapping_keeps_the_first_category() {
        let inner = Error::configuration("bad option");
        let outer = Error::wrap(ErrorKind::Attestation, inner);
        assert_eq!(outer.kind(), ErrorKind::Configuration);
        assert_eq!(outer.to_string(), "configuration error: bad option");
    }

    #[test]
    fn a_shared_error_can_be_marked_without_changing_its_message() {
        let first = Error::network("connection reset");
        let kept = first.clone();
        let marked = first.timed_out();
        assert!(marked.is_timeout());
        assert!(!kept.is_timeout());
        assert_eq!(marked.to_string(), "network error: connection reset");

        let retry = Error::attestation("document rejected").after(kept);
        assert_eq!(
            retry.earlier_attempt().map(Error::kind),
            Some(ErrorKind::Network)
        );
    }

    #[test]
    fn a_placeholder_reports_what_is_missing() {
        let error = Error::not_implemented("router discovery");
        assert_eq!(
            error.to_string(),
            "configuration error: router discovery is not implemented"
        );
    }

    #[cfg(feature = "openai")]
    #[test]
    fn a_client_error_is_found_inside_an_openai_error() {
        use async_openai::error::OpenAIError;
        let boxed: BoxError = Box::new(Error::attestation("certificate does not match"));
        let wrapped = OpenAIError::from(boxed);
        let found = Error::from_openai(&wrapped).map(Error::kind);
        assert_eq!(found, Some(ErrorKind::Attestation));
        assert!(Error::from_openai(&OpenAIError::InvalidArgument("x".into())).is_none());
    }
}
