//! SEV-SNP report signature verification.
//!
//! This module handles:
//! - Parsing ECDSA P-384 signature components from the report
//! - Verifying the report signature against the VCEK public key

use crate::error::{Error, Result};
use crate::verifier::attestation::constants::*;

/// Parse R and S from the signature bytes.
///
/// AMD SEV-SNP stores ECDSA P-384 signatures as:
/// - R: 72 bytes (48 bytes value in little-endian + 24 bytes padding)
/// - S: 72 bytes (48 bytes value in little-endian + 24 bytes padding)
/// - Reserved: 368 bytes
fn parse_signature_components(sig_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if sig_bytes.len() < SIG_COMPONENT_SIZE * 2 {
        return Err(Error::AttestationVerification("Signature too short".into()));
    }

    // Extract R (first 48 bytes of first 72-byte component) and convert from LE to BE
    let r_le = &sig_bytes[0..SIG_VALUE_SIZE];
    let r_be: Vec<u8> = r_le.iter().copied().rev().collect();

    // Extract S (first 48 bytes of second 72-byte component) and convert from LE to BE
    let s_le = &sig_bytes[SIG_COMPONENT_SIZE..SIG_COMPONENT_SIZE + SIG_VALUE_SIZE];
    let s_be: Vec<u8> = s_le.iter().copied().rev().collect();

    Ok((r_be, s_be))
}

/// Verify report signature against VCEK public key.
///
/// Note: Uses deprecated GenericArray from p384 crate's dependency.
/// This is safe and will be fixed when upstream crates update.
#[allow(deprecated)]
pub(super) fn verify_report_signature(report: &[u8], vcek: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    use p384::elliptic_curve::generic_array::GenericArray;

    // Parse VCEK certificate
    let vcek_cert = Certificate::from_der(vcek)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;

    // Extract public key from VCEK
    let pubkey_bytes = vcek_cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    // The report signature is ECDSA P-384 over SHA-384 hash of report body
    // Report body is bytes 0-672 (before signature)
    let report_body = &report[0..SIGNATURE_OFFSET];

    // Extract and convert signature components (little-endian to big-endian)
    let sig_bytes = &report[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE];
    let (r_be, s_be) = parse_signature_components(sig_bytes)?;

    // Construct signature from scalars
    let signature = Signature::from_scalars(
        GenericArray::clone_from_slice(&r_be),
        GenericArray::clone_from_slice(&s_be),
    ).map_err(|e| Error::AttestationVerification(format!("Invalid signature format: {}", e)))?;

    // Parse verifying key from VCEK public key
    // The public key is an uncompressed EC point (04 || x || y)
    let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
        .map_err(|e| Error::AttestationVerification(format!("Invalid VCEK public key: {}", e)))?;

    // Verify (internally hashes with SHA-384)
    verifying_key.verify(report_body, &signature)
        .map_err(|e| Error::AttestationVerification(format!("Signature verification failed: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_parsing() {
        // Create a mock signature with known values
        let mut sig = vec![0u8; 512];

        // R component: little-endian 48 bytes (then 24 padding)
        for i in 0..48 {
            sig[i] = (48 - i) as u8; // 48, 47, 46, ..., 1
        }

        // S component: starts at offset 72
        for i in 0..48 {
            sig[72 + i] = (i + 1) as u8; // 1, 2, 3, ..., 48
        }

        let (r_be, s_be) = parse_signature_components(&sig).unwrap();

        // R should be reversed: 1, 2, 3, ..., 48
        assert_eq!(r_be[0], 1);
        assert_eq!(r_be[47], 48);

        // S should be reversed: 48, 47, ..., 1
        assert_eq!(s_be[0], 48);
        assert_eq!(s_be[47], 1);
    }
}
