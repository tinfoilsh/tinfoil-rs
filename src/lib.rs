//! # Tinfoil Rust Client
//!
//! Secure client for Tinfoil TEE inference with hardware attestation verification.
//!
//! ## Three-Step Verification
//!
//! This SDK implements Tinfoil's full verification process:
//!
//! ### Step 1: Hardware Attestation (AMD SEV-SNP)
//! - Fetches attestation document from enclave
//! - Verifies ECDSA P-384 signature on SNP report
//! - Validates certificate chain: VCEK → ASK → ARK (AMD root of trust)
//! - Extracts enclave measurement from verified report
//!
//! ### Step 2: Sigstore Verification (Code Provenance)
//! - Fetches latest release from GitHub
//! - Retrieves Sigstore attestation bundle
//! - **Cryptographically verifies** DSSE signature using certificate's P-256 key
//! - Validates certificate is from GitHub Actions for the correct repo
//! - Extracts source measurement from signed in-toto statement
//!
//! ### Step 3: Measurement Comparison
//! - Compares enclave measurement (from hardware) with source measurement (from Sigstore)
//! - If they match, the enclave is running the exact published open-source code
//!
//! ## TLS Certificate Pinning
//! 
//! The attestation document contains the enclave's TLS public key. The SDK:
//! - Computes SPKI fingerprint from the attestation
//! - Pins TLS connections to only accept that exact certificate
//! - Rejects MITM attacks even with compromised CAs
//!
//! ## Example
//!
//! ```rust,ignore
//! use tinfoil::Client;
//! use tinfoil::chat::{ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Attestation + TLS pinning happens automatically in the constructor.
//!     let client = Client::new(
//!         "inference.tinfoil.sh",
//!         "tinfoilsh/confidential-model-router",
//!         "api-key",
//!     ).await?;
//!
//!     // All async-openai methods are available directly via Deref.
//!     let request = CreateChatCompletionRequestArgs::default()
//!         .model("gpt-oss-120b")
//!         .messages(vec![ChatCompletionRequestUserMessageArgs::default()
//!             .content("Hello!")
//!             .build()?
//!             .into()])
//!         .build()?;
//!
//!     // Non-streaming
//!     let response = client.chat().create(request.clone()).await?;
//!
//!     // Streaming
//!     let stream = client.chat().create_stream(request).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod constants;
mod ehbp;
mod ehbp_transport;
pub mod error;
pub mod multimodal;
pub mod relaxed;
pub mod sse;
pub mod verifier;

// Internal: per-user prompt-cache scoping (`user_cache_secret`). The public
// surface is `Client::with_user_cache_secret` and the automatic injection.
mod user_cache_secret;

// Unit-test helpers shared across in-crate test modules.
#[cfg(test)]
mod test_support;

// Reachable for in-tree integration tests; hidden from rustdoc so it isn't
// advertised as part of the public API contract.
#[doc(hidden)]
pub mod discovery;

/// Install `ring` as the process-wide rustls crypto provider.
///
/// `Once`-guarded so callers can invoke this from every public entry
/// point cheaply — only the first call actually installs; subsequent
/// calls are a single atomic load.
///
/// Why we need this: rustls 0.23 used to auto-install a crypto provider
/// when its default `aws_lc_rs` feature was active. Tinfoil now compiles
/// rustls with `default-features = false, features = ["ring"]` (so the
/// crate links cleanly on Windows MSVC), which removes that auto-install.
/// Without an explicit install, anything that builds a `reqwest::Client`
/// or accepts an inbound TLS connection panics with `No process-level
/// CryptoProvider available — call CryptoProvider::install_default()`.
///
/// Every public entry point in this crate calls this helper before
/// touching anything that ends up at the rustls runtime — that way
/// callers don't have to know or care about the crypto provider.
pub(crate) fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // Returns Err if a provider was already installed (e.g. by a
        // host application that calls install_default() itself before
        // any tinfoil entry point runs). That's fine — we just don't
        // overwrite. The Once still completes so future calls no-op.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub use async_openai;
pub use client::{Client, SecureClient};
pub use error::Error;
pub use relaxed::{
    RelaxedChat, RelaxedChatRequestBuilder, RelaxedResponse, RelaxedStream, RelaxedStreamChunk,
    RelaxedToolCall,
};
pub use verifier::{GroundTruth, Measurement, PredicateType};

/// Re-export of `async_openai::types::chat`.
pub use async_openai::types::chat;

/// Re-export of `async_openai::types::audio`.
pub use async_openai::types::audio;

/// Re-export of `async_openai::types::embeddings`.
pub use async_openai::types::embeddings;
