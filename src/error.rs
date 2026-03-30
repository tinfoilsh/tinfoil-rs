//! Error types for the Tinfoil SDK.
//!
//! Users should match on three categories:
//!
//! ```text
//! Error
//! ├── Configuration  — Client misconfigured (fix your code, retrying won't help)
//! ├── Attestation    — Verification failed (may be transient, can retry)
//! └── Api            — OpenAI API error (passthrough from async-openai)
//! ```
//!
//! Use [`is_configuration()`](Error::is_configuration),
//! [`is_attestation()`](Error::is_attestation),
//! [`is_retryable()`](Error::is_retryable), and
//! [`is_api()`](Error::is_api) to classify errors.

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    // =====================================================================
    // Public categories (user-facing)
    // =====================================================================
    /// Client misconfigured — fix your code, retrying will not help.
    #[error("{0}")]
    Configuration(String),

    /// OpenAI API error. These pass through unchanged from `async-openai`.
    #[error("API error: {0}")]
    Api(#[from] async_openai::error::OpenAIError),

    // =====================================================================
    // Attestation errors (internal variants, all classified as attestation)
    //
    // These mirror the error types used in sigstore-rs and the attestation
    // modules so the internal code stays consistent with upstream.
    // Users should match with is_attestation() rather than these variants.
    // =====================================================================
    /// Attestation document fetch failed.
    #[error("{0}")]
    AttestationFetch(String),

    /// Hardware attestation verification failed.
    #[error("{0}")]
    AttestationVerification(String),

    /// TLS certificate fingerprint mismatch.
    #[error("TLS certificate fingerprint mismatch")]
    CertificateMismatch,

    /// Sigstore verification failed.
    /// Uses the same variant name as our sigstore module internals,
    /// matching the sigstore-rs error patterns.
    #[error("{0}")]
    SigstoreVerification(String),

    /// GitHub API error during attestation bundle fetch.
    #[error("{0}")]
    GitHub(String),

    /// Measurement mismatch between code and enclave.
    #[error("Measurement mismatch: expected {expected}, got {actual}")]
    MeasurementMismatch { expected: String, actual: String },

    /// TLS-related error during verification.
    #[error("{0}")]
    Tls(String),

    /// Network error during attestation fetch.
    #[error("{0}")]
    Network(String),

    /// Unsupported attestation format.
    #[error("{0}")]
    UnsupportedFormat(String),

    /// HTTP error (from reqwest).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Base64 decoding error.
    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Returns true if this is a configuration error (fix your code).
    pub fn is_configuration(&self) -> bool {
        matches!(self, Error::Configuration(_))
    }

    /// Returns true if this is an attestation/verification error.
    ///
    /// This includes all non-configuration, non-API errors. Use
    /// [`is_retryable()`](Error::is_retryable) to check if the error
    /// is likely transient and worth retrying.
    pub fn is_attestation(&self) -> bool {
        matches!(
            self,
            Error::AttestationFetch(_)
                | Error::AttestationVerification(_)
                | Error::CertificateMismatch
                | Error::SigstoreVerification(_)
                | Error::GitHub(_)
                | Error::MeasurementMismatch { .. }
                | Error::Tls(_)
                | Error::Network(_)
                | Error::UnsupportedFormat(_)
                | Error::Http(_)
                | Error::Json(_)
                | Error::Base64(_)
                | Error::Io(_)
        )
    }

    /// Returns true if this error is likely transient and the operation
    /// may succeed on retry.
    ///
    /// Network-related errors (fetch failures, HTTP errors, TLS handshake
    /// failures) are retryable. Parse errors, verification failures, and
    /// mismatches are permanent.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::AttestationFetch(_)
                | Error::Network(_)
                | Error::Http(_)
                | Error::Tls(_)
        )
    }

    /// Returns true if this is an OpenAI API error.
    pub fn is_api(&self) -> bool {
        matches!(self, Error::Api(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
