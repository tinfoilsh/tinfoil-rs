//! The message-carrying error type that the internal modules share.

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
                Self {
                    message: format!("{context}: {}", self.message),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.message)
            }
        }

        impl std::error::Error for $name {}
    };
}

pub(crate) use message_error;

#[cfg(test)]
mod tests {
    message_error! {
        /// An error for the test below.
        struct ExampleError;
    }

    #[test]
    fn context_goes_in_front_of_the_message() {
        let error = ExampleError::new("bad length").within("report");
        assert_eq!(error.to_string(), "report: bad length");
        assert_eq!(error, ExampleError::new("report: bad length"));
    }
}
