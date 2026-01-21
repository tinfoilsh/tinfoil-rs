//! Error types for the Tinfoil client

use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Attestation fetch failed: {0}")]
    AttestationFetch(String),

    #[error("Attestation verification failed: {0}")]
    AttestationVerification(String),

    #[error("Sigstore verification failed: {0}")]
    SigstoreVerification(String),

    #[error("GitHub API error: {0}")]
    GitHub(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Unsupported attestation format: {0}")]
    UnsupportedFormat(String),

    #[error("Measurement mismatch: expected {expected}, got {actual}")]
    MeasurementMismatch { expected: String, actual: String },

    #[error("TLS certificate fingerprint mismatch")]
    CertificateMismatch,

    #[error("Client not verified - call verify() first")]
    NotVerified,

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("API error: HTTP {status}: {message}")]
    Api { status: u16, message: String },

    #[error("No embedding in response")]
    NoEmbedding,
}

pub type Result<T> = std::result::Result<T, Error>;
