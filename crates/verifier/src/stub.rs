//! Support for functions whose contract is fixed before their body exists,
//! and the message-carrying error type that the internal modules share.

use std::fmt;

/// The error of a function that is specified but not built yet. Every
/// module error converts from it, so such a function fails like any other
/// rejection instead of panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotImplemented(pub(crate) &'static str);

impl fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not implemented", self.0)
    }
}

/// The result of a function that is specified but not built yet.
pub(crate) fn pending<T, E: From<NotImplemented>>(function: &'static str) -> Result<T, E> {
    Err(NotImplemented(function).into())
}

/// Defines a module error that carries a message. Layer classification
/// happens only where the public verifier maps module errors to its own.
macro_rules! message_error {
    ($(#[$meta:meta])* $vis:vis struct $name:ident;) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        $vis struct $name {
            message: String,
        }

        impl $name {
            /// An error with the given message.
            pub(crate) fn new(message: impl Into<String>) -> Self {
                Self {
                    message: message.into(),
                }
            }

            /// The same error with `context` in front of its message.
            pub(crate) fn within(self, context: impl std::fmt::Display) -> Self {
                Self::new(format!("{context}: {}", self.message))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.message)
            }
        }

        impl std::error::Error for $name {}

        impl From<$crate::stub::NotImplemented> for $name {
            fn from(error: $crate::stub::NotImplemented) -> Self {
                Self::new(error.to_string())
            }
        }
    };
}

pub(crate) use message_error;

#[cfg(test)]
mod tests {
    use super::*;

    message_error! {
        /// An error for the tests below.
        struct ExampleError;
    }

    fn unbuilt() -> Result<u8, ExampleError> {
        pending("example::unbuilt")
    }

    #[test]
    fn an_unbuilt_function_returns_an_error_that_names_it() {
        let error = unbuilt().unwrap_err();
        assert_eq!(error.to_string(), "example::unbuilt is not implemented");
    }

    #[test]
    fn context_goes_in_front_of_the_message() {
        let error = ExampleError::new("bad length").within("report");
        assert_eq!(error.to_string(), "report: bad length");
    }
}
