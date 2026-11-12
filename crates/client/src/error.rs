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
    /// material, or a failed connection to the enclave. Retry later with
    /// the same client.
    Network,
    /// Rejected evidence, policy or channel binding: the enclave could not
    /// be trusted, or what it answered could not be authenticated. The
    /// client verifies again by itself on the next request; a failure that
    /// persists deserves an investigation.
    ///
    /// Whether the request was delivered depends on where the error arose:
    ///
    /// - **Not delivered.** A verification failed (in `connect`,
    ///   `ensure_verified`, `reverify`, or before a request that needed
    ///   one): the evidence or the policy was rejected, the
    ///   `verification_check` refused it, or the document endorses no key
    ///   for the transport mode. No connection for the request was
    ///   opened, and nothing was sent. In
    ///   [`TransportMode::Tls`](crate::TransportMode::Tls) the one other
    ///   attestation error is the pin: the server's certificate fails the
    ///   standard checks or does not carry the attested key. That fails
    ///   the handshake, before the request is written. So in that mode no
    ///   attestation error leaves a request delivered.
    /// - **Possibly delivered.** In
    ///   [`TransportMode::Ehbp`](crate::TransportMode::Ehbp) the body is
    ///   sealed to the attested key, so nobody else can read it, but the
    ///   error can arise after the sealed request has left: the answer
    ///   says that the enclave does not hold the key, a success response
    ///   carries no valid proof that the enclave sent it, or a part of
    ///   the response body does not authenticate while it is read (found
    ///   with [`Error::from_reqwest`]). None of these says whether the
    ///   enclave received the request and acted on it.
    ///
    /// So, in the EHBP mode, do not conclude from an attestation error on
    /// a request that the request had no effect. Send a request that must
    /// not take effect twice with an idempotency key, or find out what
    /// became of it before sending it again. The client itself sends a
    /// request a second time in one case only, after a key rejection and
    /// a new verification; in the EHBP mode that rejection is an answer
    /// that is not authenticated.
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

#[derive(Clone)]
struct Inner {
    kind: ErrorKind,
    timeout: bool,
    /// Whether a key rejection left the request unsent because its body
    /// could not be produced again.
    unsent_after_rejection: bool,
    cause: Cause,
    earlier_attempt: Option<Error>,
}

#[derive(Clone)]
enum Cause {
    Message(String),
    // Shared, so that a copy of the error keeps the same source.
    Source(Arc<dyn StdError + Send + Sync + 'static>),
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

    /// The failure of the attempt before the one that this error reports:
    /// the first attempt of a verification, when this error is the failure
    /// of the one retry that a verification gets; or the key rejection of
    /// a request, when this error is the failure of the one replay that
    /// the request gets, or says that its body could not be sent again.
    /// The earlier failure can have an earlier attempt of its own.
    pub fn earlier_attempt(&self) -> Option<&Error> {
        self.inner.earlier_attempt.as_ref()
    }

    /// The client error behind a failed OpenAI call, if there is one.
    ///
    /// A typed `async_openai` call returns `OpenAIError`. When the attested
    /// HTTP client under it fails, for example because the enclave no longer
    /// passes verification, its error travels inside that `OpenAIError`;
    /// this returns it. It is found in the error of:
    ///
    /// - every call, streaming or not, that fails before its response
    ///   arrives: a refused verification, a refused request, a failed
    ///   connection, a deadline;
    /// - a call whose response `async_openai` reads whole, when that read
    ///   fails;
    /// - `chat_relaxed()` calls and the streams of
    ///   [`RelaxedChat::create_stream`](crate::RelaxedChat::create_stream)
    ///   and [`parse_event_stream`](crate::sse::parse_event_stream), at
    ///   any point.
    ///
    /// It is **not** found in an item of a stream that a typed call
    /// returned (`chat().create_stream(..)`, `responses().create_stream(..)`
    /// and the like). When the body of such a stream fails while it is
    /// read (in [`TransportMode::Ehbp`](crate::TransportMode::Ehbp) a
    /// part that does not authenticate; a broken connection; a deadline),
    /// the stream still ends with an error and delivers nothing after it,
    /// but `async_openai` keeps only a message in
    /// `OpenAIError::StreamError`, and the message need not name the
    /// cause. A caller that must tell these failures apart reads the
    /// stream with `chat_relaxed()` or through an HTTP client.
    ///
    /// Otherwise `None` means that the failure came from the API or from
    /// `async_openai` itself.
    #[cfg(feature = "openai")]
    pub fn from_openai(error: &async_openai::error::OpenAIError) -> Option<&Error> {
        use async_openai::error::OpenAIError;
        let source: &(dyn StdError + 'static) = match error {
            OpenAIError::Boxed(boxed) => boxed.as_ref(),
            OpenAIError::Reqwest(error) => error,
            _ => return None,
        };
        Self::find_in(source)
    }

    /// The client error behind a failed read of a response body, if there
    /// is one.
    ///
    /// The body of a response is read with `reqwest`'s methods
    /// (`chunk`, `bytes`, `text`, `json`, `bytes_stream`), which return a
    /// `reqwest::Error`. When the read of a response from one of this
    /// crate's clients fails, the client's error travels inside that
    /// `reqwest::Error`, and this returns it, with its [`kind`](Self::kind):
    ///
    /// - An attestation error: in
    ///   [`TransportMode::Ehbp`](crate::TransportMode::Ehbp), a part of the
    ///   body did not authenticate, or the body ended inside a sealed
    ///   frame. What was read before it was authentic; nothing of the
    ///   failing frame or after it was delivered.
    /// - A network error: the connection failed while the body was read,
    ///   or the request's deadline passed, in which case
    ///   [`is_timeout`](Self::is_timeout) is `true` (and so is
    ///   `reqwest::Error::is_timeout`).
    ///
    /// `None` means that the error did not come from reading such a body:
    /// for example, a body that is not the JSON that the caller asked for.
    pub fn from_reqwest(error: &reqwest::Error) -> Option<&Error> {
        Self::find_in(error)
    }

    /// The first client error among `error` and its sources.
    pub(crate) fn find_in<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a Error> {
        let mut next = Some(error);
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
                unsent_after_rejection: false,
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
            Err(source) => Self::new(kind, Cause::Source(Arc::from(source))),
        }
    }

    /// The same error, marked as the expiry of a deadline.
    pub(crate) fn timed_out(self) -> Self {
        self.rebuild(|inner| inner.timeout = true)
    }

    /// The same error, marked as the one for a request that was not sent
    /// again after a key rejection because its body is a stream. A caller
    /// that can build the request anew may send it once more.
    pub(crate) fn unsent_after_rejection(self) -> Self {
        self.rebuild(|inner| inner.unsent_after_rejection = true)
    }

    /// Whether the error carries the mark of
    /// [`unsent_after_rejection`](Self::unsent_after_rejection).
    #[cfg(feature = "openai")]
    pub(crate) fn is_unsent_after_rejection(&self) -> bool {
        self.inner.unsent_after_rejection
    }

    /// The same error, with the failure of the attempt before it attached.
    pub(crate) fn after(self, earlier: Error) -> Self {
        self.rebuild(|inner| inner.earlier_attempt = Some(earlier))
    }

    /// The same error, with `earliest` attached behind the attempts that it
    /// already carries: an error that is itself the failure of a retry
    /// keeps its first attempt, and `earliest` becomes the attempt before
    /// that one.
    pub(crate) fn after_all(self, earliest: Error) -> Self {
        let earlier = match self.inner.earlier_attempt.clone() {
            Some(earlier) => earlier.after_all(earliest),
            None => earliest,
        };
        self.after(earlier)
    }

    /// A network error for a deadline that passed, marked as a timeout.
    /// Its source is an I/O error of the kind `TimedOut`, which is what
    /// `reqwest` recognizes as a timeout when the error travels inside one
    /// of its own.
    pub(crate) fn deadline(message: &'static str) -> Self {
        Self::wrap(
            ErrorKind::Network,
            std::io::Error::new(std::io::ErrorKind::TimedOut, message),
        )
        .timed_out()
    }

    /// The same error with `change` applied. An error that other holders
    /// share is copied first, with its cause, its source chain and its
    /// earlier attempt as they are.
    fn rebuild(self, change: impl FnOnce(&mut Inner)) -> Self {
        let mut inner = Arc::try_unwrap(self.inner).unwrap_or_else(|shared| (*shared).clone());
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
            Cause::Source(source) => Some(source.as_ref() as &(dyn StdError + 'static)),
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
    fn marking_a_shared_error_keeps_its_source_chain_and_its_earlier_attempt() {
        let source = std::io::Error::other("connection reset");
        let retry = Error::wrap(ErrorKind::Network, source).after(Error::attestation("first"));
        let kept = retry.clone();
        let marked = retry.timed_out();

        assert!(marked.is_timeout());
        assert!(!kept.is_timeout());
        assert_eq!(marked.to_string(), "network error: connection reset");
        // The source is still the I/O error itself, not a copy of the
        // client error in front of it.
        let source = marked.source().expect("the I/O error");
        assert!(source.is::<std::io::Error>());
        assert!(source.source().is_none());
        assert_eq!(
            marked.earlier_attempt().map(Error::to_string).as_deref(),
            Some("attestation error: first")
        );

        let shared = marked.clone();
        let later = marked.after(Error::network("second"));
        assert!(later.is_timeout());
        assert!(later.source().is_some_and(|s| s.is::<std::io::Error>()));
        assert_eq!(
            shared.earlier_attempt().map(Error::to_string).as_deref(),
            Some("attestation error: first")
        );
    }

    #[test]
    fn an_attempt_is_attached_behind_the_attempts_that_an_error_already_has() {
        let replay = Error::network("second fetch").after(Error::network("first fetch"));
        let joined = replay.after_all(Error::attestation("key rejected"));
        let chain: Vec<String> = std::iter::successors(Some(&joined), |e| e.earlier_attempt())
            .map(Error::to_string)
            .collect();
        assert_eq!(
            chain,
            [
                "network error: second fetch",
                "network error: first fetch",
                "attestation error: key rejected"
            ]
        );
        let single = Error::network("replay").after_all(Error::attestation("key rejected"));
        assert_eq!(
            single.earlier_attempt().map(Error::kind),
            Some(ErrorKind::Attestation)
        );
        assert!(
            single
                .earlier_attempt()
                .unwrap()
                .earlier_attempt()
                .is_none()
        );
    }

    #[test]
    fn a_passed_deadline_is_a_network_timeout_that_reqwest_would_recognize() {
        let error = Error::deadline("too slow");
        assert_eq!(error.kind(), ErrorKind::Network);
        assert!(error.is_timeout());
        assert_eq!(error.to_string(), "network error: too slow");
        let io = error
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .expect("an I/O error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
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
