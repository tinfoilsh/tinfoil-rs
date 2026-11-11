//! The errors that the verifier returns.

use std::error::Error as StdError;
use std::fmt;

/// The underlying cause carried by an error of this crate.
type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// An error returned by the verifier: either the caller's mistake or a
/// document that must not be trusted.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The verifier was built or called with invalid inputs.
    Usage(UsageError),
    /// The document was rejected.
    Verification(VerificationError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(error) => error.fmt(f),
            Error::Verification(error) => error.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Usage(error) => error.source(),
            Error::Verification(error) => error.source(),
        }
    }
}

impl From<UsageError> for Error {
    fn from(error: UsageError) -> Self {
        Error::Usage(error)
    }
}

impl From<VerificationError> for Error {
    fn from(error: VerificationError) -> Self {
        Error::Verification(error)
    }
}

/// A verifier built or called with invalid inputs. Fix the caller; retrying
/// will not help.
#[derive(Debug)]
pub struct UsageError {
    source: BoxError,
}

impl UsageError {
    pub(crate) fn new(source: impl Into<BoxError>) -> Self {
        Self {
            source: source.into(),
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "usage error: {}", self.source)
    }
}

impl StdError for UsageError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

/// The verification layer that rejected a document.
///
/// More layers may be added, so a caller must tolerate values that it does
/// not recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Layer {
    /// The document cannot be parsed, is not bound to the caller's nonce, or
    /// contradicts itself.
    Envelope,
    /// The reference values fail to authenticate or do not match the
    /// requested workload.
    Provenance,
    /// The hardware evidence is not authentic.
    Quote,
    /// Authentic evidence does not satisfy the policy.
    Policy,
}

impl Layer {
    /// The layer's name: `envelope`, `provenance`, `quote` or `policy`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Layer::Envelope => "envelope",
            Layer::Provenance => "provenance",
            Layer::Quote => "quote",
            Layer::Policy => "policy",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A document that must not be trusted, and the layer that rejected it.
#[derive(Debug)]
pub struct VerificationError {
    layer: Layer,
    source: BoxError,
}

impl VerificationError {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the verifier that classifies rejections is not in the crate yet"
        )
    )]
    pub(crate) fn new(layer: Layer, source: impl Into<BoxError>) -> Self {
        Self {
            layer,
            source: source.into(),
        }
    }

    /// The layer that rejected the document.
    pub fn layer(&self) -> Layer {
        self.layer
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "verification error: {}: {}", self.layer, self.source)
    }
}

impl StdError for VerificationError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verification_error_names_its_layer() {
        let error = VerificationError::new(Layer::Quote, "report signature is invalid");
        assert_eq!(
            error.to_string(),
            "verification error: quote: report signature is invalid"
        );
        assert_eq!(error.layer(), Layer::Quote);
        assert_eq!(
            error.source().unwrap().to_string(),
            "report signature is invalid"
        );
    }

    #[test]
    fn a_usage_error_carries_its_cause() {
        let error = UsageError::new("nonce must be 32 bytes");
        assert_eq!(error.to_string(), "usage error: nonce must be 32 bytes");
        assert_eq!(
            error.source().unwrap().to_string(),
            "nonce must be 32 bytes"
        );
    }

    #[test]
    fn the_enum_displays_and_unwraps_as_its_variant() {
        let usage: Error = UsageError::new("bad option").into();
        assert!(matches!(usage, Error::Usage(_)));
        assert_eq!(usage.to_string(), "usage error: bad option");
        assert_eq!(usage.source().unwrap().to_string(), "bad option");

        let cause = std::io::Error::other("truncated");
        let rejected: Error = VerificationError::new(Layer::Envelope, cause).into();
        assert_eq!(
            rejected.to_string(),
            "verification error: envelope: truncated"
        );
        let source = rejected.source().unwrap();
        assert!(source.downcast_ref::<std::io::Error>().is_some());
        match rejected {
            Error::Verification(error) => assert_eq!(error.layer(), Layer::Envelope),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn layers_have_stable_names() {
        let names: Vec<&str> = [
            Layer::Envelope,
            Layer::Provenance,
            Layer::Quote,
            Layer::Policy,
        ]
        .iter()
        .map(Layer::as_str)
        .collect();
        assert_eq!(names, ["envelope", "provenance", "quote", "policy"]);
        assert_eq!(Layer::Policy.to_string(), "policy");
    }

    #[test]
    fn errors_cross_threads() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
        assert_send_sync::<UsageError>();
        assert_send_sync::<VerificationError>();
    }
}
