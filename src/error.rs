//! Error types for the Tinfoil SDK.
//!
//! Users should match on four categories — the same set surfaced by the
//! JavaScript and Swift SDKs so the docs apply uniformly:
//!
//! ```text
//! Error
//! ├── Configuration  — Client misconfigured (fix your code, retrying won't help)
//! ├── Fetch          — Couldn't fetch attestation materials (retry, transient)
//! ├── Attestation    — Verification failed (security issue, do not retry)
//! └── Api            — OpenAI API error (passthrough from async-openai)
//! ```
//!
//! Use [`is_configuration()`](Error::is_configuration),
//! [`is_fetch()`](Error::is_fetch),
//! [`is_attestation()`](Error::is_attestation),
//! [`is_api()`](Error::is_api), and
//! [`is_retryable()`](Error::is_retryable) to classify errors.

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

    /// Encrypted HTTP Body Protocol (EHBP) failure. Fail-closed: an
    /// encrypted exchange never falls back to plaintext.
    #[error("EHBP error: {0}")]
    Ehbp(String),

    /// The enclave rejected an EHBP request because its HPKE key rotated.
    /// Re-verify the enclave before retrying the request.
    #[error("EHBP key configuration mismatch: {0}")]
    EhbpKeyMismatch(String),

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
    /// Returns true if this is a configuration error.
    ///
    /// The client was misconfigured (missing API key, invalid URL, etc).
    /// Fix your code — retrying will not help.
    pub fn is_configuration(&self) -> bool {
        matches!(self, Error::Configuration(_))
    }

    /// Returns true if this is a fetch error.
    ///
    /// Network or HTTP failure while fetching attestation materials,
    /// Sigstore bundles, or GitHub API responses. Transient — retry,
    /// possibly with backoff. Mirrors `FetchError` in the JavaScript SDK.
    pub fn is_fetch(&self) -> bool {
        matches!(
            self,
            Error::AttestationFetch(_)
                | Error::Network(_)
                | Error::Http(_)
                | Error::GitHub(_)
                | Error::Io(_)
        )
    }

    /// Returns true if this is an attestation/verification error.
    ///
    /// The materials were fetched successfully, but verification failed —
    /// signatures, certificate chains, measurements, or the structure of
    /// the attestation document itself. **Security-relevant.** Do not
    /// retry blindly. Mirrors `AttestationError` in the JavaScript SDK.
    pub fn is_attestation(&self) -> bool {
        matches!(
            self,
            Error::AttestationVerification(_)
                | Error::CertificateMismatch
                | Error::SigstoreVerification(_)
                | Error::MeasurementMismatch { .. }
                | Error::Tls(_)
                | Error::Ehbp(_)
                | Error::EhbpKeyMismatch(_)
                | Error::UnsupportedFormat(_)
                | Error::Json(_)
                | Error::Base64(_)
        )
    }

    /// Returns true if this is an OpenAI API error.
    ///
    /// The error came from the upstream API after the secure connection
    /// was established (authentication failure, rate limit, malformed
    /// request, etc). Pass through unchanged from `async-openai`.
    pub fn is_api(&self) -> bool {
        matches!(self, Error::Api(_))
    }

    /// Returns true when the enclave rejected an EHBP request because
    /// its HPKE key configuration rotated.
    pub fn is_ehbp_key_mismatch(&self) -> bool {
        matches!(self, Error::EhbpKeyMismatch(_))
    }

    /// Returns true if this error is likely transient and the operation
    /// may succeed on retry.
    ///
    /// In practice this means [`is_fetch()`](Error::is_fetch) errors plus
    /// the retryable subset of API errors. Configuration and attestation
    /// errors are never retryable.
    pub fn is_retryable(&self) -> bool {
        if self.is_fetch() {
            return true;
        }
        if let Error::Api(api) = self {
            return is_retryable_openai_error(api);
        }
        false
    }
}

fn is_retryable_openai_error(err: &async_openai::error::OpenAIError) -> bool {
    use async_openai::error::OpenAIError;
    match err {
        // Transport-level reqwest errors are always retryable.
        OpenAIError::Reqwest(_) => true,
        // API errors carry an OpenAI-style `code` ("server_error",
        // "rate_limit_exceeded", ...). Only the transient codes retry.
        OpenAIError::ApiError(api) => matches!(
            api.api_error.code.as_deref(),
            Some("server_error") | Some("rate_limit_exceeded")
        ),
        // Everything else (deserialization, invalid argument,
        // feature-gated stream / file errors) is not retryable.
        _ => false,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn ehbp_key_mismatch_is_an_attestation_error() {
        let error = Error::EhbpKeyMismatch("rotated".into());

        assert!(error.is_attestation());
        assert!(error.is_ehbp_key_mismatch());
        assert!(!error.is_retryable());
    }
}
