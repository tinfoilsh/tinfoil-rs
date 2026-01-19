//! Attestation verification module
//!
//! Implements the three-step Tinfoil verification process:
//!
//! ## Step 1: Enclave Runtime Verification (Hardware Attestation)
//! Verifies the enclave is running in genuine secure hardware:
//! - Fetch attestation document from `/.well-known/tinfoil-attestation`
//! - Parse SEV-SNP report
//! - Verify AMD certificate chain to hardware root
//! - Extract measurement and TLS fingerprint
//! 
//! ## Step 2: Code Integrity Verification (Sigstore)
//! Verifies the source code was built correctly:
//! - Fetch Sigstore bundle from GitHub
//! - Verify GitHub Actions signatures
//! - Extract expected measurements
//! 
//! ## Step 3: Consistency Verification
//! Compares source measurement (Sigstore) with enclave measurement (hardware):
//! - If they match, the enclave runs the exact open-source code
//! 
//! ## TLS Binding
//! Verifies TLS connection terminates inside the verified enclave:
//! - Compare server TLS cert SPKI hash with attested fingerprint

pub mod types;
pub mod sev;

// Re-export public types
pub use types::{AttestationDocument, PredicateType, Verification, Measurement, GroundTruth, MeasurementError};

use crate::error::{Error, Result};
use super::sigstore;

/// Fetch attestation document from an enclave
pub async fn fetch(host: &str) -> Result<AttestationDocument> {
    let url = format!("https://{}/.well-known/tinfoil-attestation", host);
    
    let response = reqwest::get(&url)
        .await
        .map_err(|e| Error::AttestationFetch(format!("HTTP request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::AttestationFetch(format!(
            "HTTP {}: {}",
            response.status(),
            response.status().canonical_reason().unwrap_or("Unknown error")
        )));
    }
    
    let doc: AttestationDocument = response.json().await
        .map_err(|e| Error::AttestationFetch(format!("JSON parse failed: {}", e)))?;
    
    Ok(doc)
}

/// Parse attestation document and extract fields without cryptographic verification.
/// For full security, use `verify_full()` which validates the certificate chain and signature.
pub fn parse_report(doc: &AttestationDocument) -> Result<Verification> {
    match doc.format {
        PredicateType::SevGuestV2 => sev::parse_report(&doc.body),
        PredicateType::TdxGuestV2 => Err(Error::UnsupportedFormat(
            "Intel TDX attestation not yet implemented".into()
        )),
        PredicateType::SnpTdxMultiPlatformV1 => {
            // Multi-platform format - use SEV-SNP verification
            sev::parse_report(&doc.body)
        }
        PredicateType::Unknown => Err(Error::AttestationVerification(
            "Unknown attestation format".into()
        )),
    }
}

/// Full verification with AMD certificate chain (Step 1 complete)
/// 
/// This performs complete hardware attestation verification:
/// - Fetches VCEK from AMD KDS
/// - Validates VCEK → ASK → ARK certificate chain
/// - Verifies report signature against VCEK
pub async fn verify_full(doc: &AttestationDocument) -> Result<Verification> {
    match doc.format {
        PredicateType::SevGuestV2 => sev::verify_full(&doc.body).await,
        PredicateType::TdxGuestV2 => Err(Error::UnsupportedFormat(
            "Intel TDX attestation not yet implemented".into()
        )),
        PredicateType::SnpTdxMultiPlatformV1 => {
            sev::verify_full(&doc.body).await
        }
        PredicateType::Unknown => Err(Error::AttestationVerification(
            "Unknown attestation format".into()
        )),
    }
}

/// Full end-to-end verification (Steps 1, 2, and 3)
/// 
/// This performs the complete Tinfoil verification process:
/// 1. Hardware attestation (enclave is genuine)
/// 2. Sigstore verification (code provenance)
/// 3. Measurement comparison (code matches)
/// 
/// Returns `GroundTruth` containing:
/// - TLS fingerprint for certificate pinning
/// - HPKE public key for EHBP encryption
/// - Verified measurements from both source and enclave
pub async fn verify_complete(host: &str, repo: &str) -> Result<GroundTruth> {
    // Step 1: Hardware attestation
    let doc = fetch(host).await?;
    let enclave_verification = verify_full(&doc).await?;
    
    // Step 2: Sigstore verification
    let code_measurement = sigstore::verify_repo(repo).await?;
    
    // Step 3: Measurement comparison
    enclave_verification.measurement.equals(&code_measurement)
        .map_err(|e| Error::AttestationVerification(format!("Measurement mismatch: {}", e)))?;
    
    // Compute fingerprints
    let target_type = &enclave_verification.measurement.type_;
    let code_fingerprint = code_measurement.fingerprint_for_target(target_type);
    let enclave_fingerprint = enclave_verification.measurement.fingerprint();

    Ok(GroundTruth {
        tls_public_key: Some(enclave_verification.tls_public_key_fp),
        hpke_public_key: enclave_verification.hpke_public_key,
        code_measurement,
        enclave_measurement: enclave_verification.measurement,
        code_fingerprint,
        enclave_fingerprint,
    })
}
