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
//! use tinfoil::SecureClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client with enclave host and GitHub repo for code provenance
//!     let mut client = SecureClient::new(
//!         "inference.tinfoil.sh",
//!         "tinfoilsh/confidential-model-router",
//!         "api-key",
//!     );
//!     
//!     // verify() performs all three steps automatically:
//!     // 1. Sigstore verification (code provenance from GitHub Actions)
//!     // 2. Hardware attestation (AMD SEV-SNP certificate chain)
//!     // 3. Measurement comparison (code matches enclave)
//!     // Then pins TLS to the attested certificate for all future requests.
//!     client.verify().await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod api;
pub mod client;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod verifier;

pub use client::SecureClient;
pub use error::Error;
pub use api::{ChatMessage, ChatRequest, ChatResponse, EmbeddingRequest, EmbeddingResponse};
pub use verifier::{GroundTruth, Measurement, PredicateType};
