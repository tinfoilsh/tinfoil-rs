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
//!     let mut client = SecureClient::new(
//!         "inference.tinfoil.sh",
//!         "tinfoilsh/confidential-model-router",
//!         "api-key",
//!     );
//!     
//!     // verify() attests the enclave and pins TLS to the attested certificate.
//!     client.verify().await?;
//!     
//!     // Use the pinned HTTP client for requests to the enclave.
//!     let http = client.http_client()?;
//!     let resp = http.post(format!("{}/v1/chat/completions", client.base_url()))
//!         .bearer_auth(client.api_key())
//!         .json(&serde_json::json!({
//!             "model": "model-name",
//!             "messages": [{"role": "user", "content": "Hello!"}]
//!         }))
//!         .send()
//!         .await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod constants;
pub mod discovery;
pub mod error;
pub mod verifier;

pub use client::SecureClient;
pub use error::Error;
pub use verifier::{GroundTruth, Measurement, PredicateType};
