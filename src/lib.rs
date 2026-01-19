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
//! use tinfoil::{SecureClient, attestation, sigstore};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Step 1: Hardware attestation
//!     let doc = attestation::fetch("inference.tinfoil.sh").await?;
//!     let enclave = attestation::verify_full(&doc).await?;
//!     
//!     // Step 2: Sigstore verification (full cryptographic verification)
//!     let source = sigstore::verify_repo("tinfoilsh/confidential-model").await?;
//!     
//!     // Step 3: Compare measurements
//!     enclave.measurement.equals(&source)?;
//!     
//!     // Create TLS-pinned client using verified fingerprint
//!     let client = SecureClient::with_fingerprint(
//!         "inference.tinfoil.sh",
//!         "api-key",
//!         &enclave.tls_public_key_fp
//!     ).await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod attestation;
pub mod client;
pub mod embedded;
pub mod error;
pub mod github;
pub mod tls;
pub mod api;
pub mod sigstore;

pub use client::SecureClient;
pub use error::Error;
pub use api::{ChatMessage, ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse};
