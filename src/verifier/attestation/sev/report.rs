//! SEV-SNP report decoding and structure validation.
//!
//! This module handles:
//! - Base64/gzip decoding of report data
//! - Report structure validation (size, version)
//! - MBZ (Must Be Zero) field validation
//! - Signer info field validation

use flate2::read::GzDecoder;
use std::io::Read;

use crate::error::{Error, Result};
use crate::verifier::attestation::constants::*;
use crate::verifier::util::decode_b64;

/// Decode and decompress a base64+gzip encoded attestation report.
pub(super) fn decode_report(body: &str) -> Result<Vec<u8>> {
    let compressed = decode_b64(body)
        .map_err(|e| Error::AttestationVerification(format!("Base64 decode failed: {}", e)))?;

    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut report_bytes = Vec::new();
    decoder.read_to_end(&mut report_bytes)
        .map_err(|e| Error::AttestationVerification(format!("Gzip decompress failed: {}", e)))?;

    Ok(report_bytes)
}

/// Validate basic report structure (size and version).
pub(super) fn validate_report_structure(report: &[u8]) -> Result<()> {
    if report.len() != REPORT_SIZE {
        return Err(Error::AttestationVerification(format!(
            "Invalid report size: expected {}, got {}",
            REPORT_SIZE, report.len()
        )));
    }

    let version = u32::from_le_bytes([report[0], report[1], report[2], report[3]]);
    if version < 2 || (version > 3 && version != 5) {
        return Err(Error::AttestationVerification(format!(
            "Unsupported report version: {} (supported: 2, 3, 5)", version
        )));
    }

    Ok(())
}

/// Validate that a byte range is all zeros (Must Be Zero).
pub(super) fn validate_mbz_bytes(report: &[u8], start: usize, end: usize, field_name: &str) -> Result<()> {
    if report[start..end].iter().any(|&b| b != 0) {
        return Err(Error::AttestationVerification(format!(
            "MBZ field {} at [0x{:x}:0x{:x}] contains non-zero bytes",
            field_name, start, end
        )));
    }
    Ok(())
}

/// Validate that reserved bits 47-16 in a TCB field are zero.
fn validate_tcb_mbz(tcb: u64, field_name: &str) -> Result<()> {
    // Bits 47-16 (32 bits) must be zero
    let reserved_bits = (tcb >> 16) & 0xFFFF_FFFF;
    if reserved_bits != 0 {
        return Err(Error::AttestationVerification(format!(
            "{} has non-zero reserved bits 47-16: 0x{:x}",
            field_name, tcb
        )));
    }
    Ok(())
}

/// Validate all MBZ (Must Be Zero) fields in the report per AMD SEV-SNP spec.
pub(super) fn validate_mbz_fields(report: &[u8]) -> Result<()> {
    let version = u32::from_le_bytes([report[0], report[1], report[2], report[3]]);

    // Reserved after signer_info: 0x4C-0x50 (4 bytes)
    validate_mbz_bytes(report, 0x4C, 0x50, "reserved_after_signer_info")?;

    // Reserved area depends on version
    // Version 3+: family/model/stepping at 0x188-0x18B, so MBZ is 0x18B-0x1A0
    // Version 2: MBZ is 0x188-0x1A0
    if version >= 3 {
        validate_mbz_bytes(report, 0x18B, 0x1A0, "reserved_v3")?;
    } else {
        validate_mbz_bytes(report, 0x188, 0x1A0, "reserved_v2")?;
    }

    // Reserved after current version fields: 0x1EB-0x1EC (1 byte)
    validate_mbz_bytes(report, 0x1EB, 0x1EC, "reserved_after_current_version")?;

    // Reserved after committed version fields: 0x1EF-0x1F0 (1 byte)
    validate_mbz_bytes(report, 0x1EF, 0x1F0, "reserved_after_committed_version")?;

    // Reserved before signature: 0x1F8-0x2A0 (168 bytes)
    validate_mbz_bytes(report, 0x1F8, 0x2A0, "reserved_before_signature")?;

    // Validate TCB fields have reserved bits 47-16 as zero
    let current_tcb = u64::from_le_bytes(
        report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8].try_into().unwrap()
    );
    validate_tcb_mbz(current_tcb, "current_tcb")?;

    let reported_tcb = u64::from_le_bytes(
        report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8].try_into().unwrap()
    );
    validate_tcb_mbz(reported_tcb, "reported_tcb")?;

    let committed_tcb = u64::from_le_bytes(
        report[COMMITTED_TCB_OFFSET..COMMITTED_TCB_OFFSET + 8].try_into().unwrap()
    );
    validate_tcb_mbz(committed_tcb, "committed_tcb")?;

    let launch_tcb = u64::from_le_bytes(
        report[LAUNCH_TCB_OFFSET..LAUNCH_TCB_OFFSET + 8].try_into().unwrap()
    );
    validate_tcb_mbz(launch_tcb, "launch_tcb")?;

    Ok(())
}

/// Validate signer info field and return maskChipKey flag.
///
/// Signer info field (32-bit at offset 0x48):
/// - Bits 31-5: Must be zero
/// - Bits 2-4: Signing key (must be 0 for VCEK)
/// - Bit 1: maskChipKey flag
/// - Bit 0: authorKeyEn flag
pub(super) fn validate_signer_info(report: &[u8]) -> Result<bool> {
    let signer_info = u32::from_le_bytes(
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].try_into().unwrap()
    );

    // Bits 31-5 must be zero
    if signer_info >> 5 != 0 {
        return Err(Error::AttestationVerification(format!(
            "Signer info bits 31-5 must be zero, got 0x{:x}",
            signer_info >> 5
        )));
    }

    // Signing key (bits 2-4) must be 0 (VCEK)
    let signing_key = (signer_info >> 2) & 0x7;
    if signing_key != 0 {
        return Err(Error::AttestationVerification(format!(
            "Only VCEK-signed reports are supported, got signing key {}",
            signing_key
        )));
    }

    // Extract maskChipKey flag (bit 1)
    let mask_chip_key = (signer_info & 0x2) != 0;

    Ok(mask_chip_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid report for testing.
    /// Sets version to 2 and all other bytes to zero.
    fn create_test_report(version: u32) -> Vec<u8> {
        let mut report = vec![0u8; REPORT_SIZE];
        // Set version (little-endian u32 at offset 0)
        report[0..4].copy_from_slice(&version.to_le_bytes());
        report
    }

    // =========================================================================
    // validate_report_structure tests
    // =========================================================================

    #[test]
    fn test_validate_report_structure_valid_version_2() {
        let report = create_test_report(2);
        assert!(validate_report_structure(&report).is_ok());
    }

    #[test]
    fn test_validate_report_structure_valid_version_3() {
        let report = create_test_report(3);
        assert!(validate_report_structure(&report).is_ok());
    }

    #[test]
    fn test_validate_report_structure_valid_version_5() {
        let report = create_test_report(5);
        assert!(validate_report_structure(&report).is_ok());
    }

    #[test]
    fn test_validate_report_structure_invalid_version_0() {
        let report = create_test_report(0);
        let result = validate_report_structure(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported report version"));
    }

    #[test]
    fn test_validate_report_structure_invalid_version_1() {
        let report = create_test_report(1);
        let result = validate_report_structure(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported report version"));
    }

    #[test]
    fn test_validate_report_structure_invalid_version_4() {
        let report = create_test_report(4);
        let result = validate_report_structure(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported report version"));
    }

    #[test]
    fn test_validate_report_structure_wrong_size() {
        let report = vec![0u8; 100]; // Wrong size
        let result = validate_report_structure(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid report size"));
    }

    // =========================================================================
    // validate_mbz_bytes tests
    // =========================================================================

    #[test]
    fn test_validate_mbz_bytes_all_zeros() {
        let data = vec![0u8; 100];
        assert!(validate_mbz_bytes(&data, 10, 50, "test_field").is_ok());
    }

    #[test]
    fn test_validate_mbz_bytes_non_zero() {
        let mut data = vec![0u8; 100];
        data[25] = 1; // Set a non-zero byte in the range
        let result = validate_mbz_bytes(&data, 10, 50, "test_field");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MBZ field test_field"));
    }

    #[test]
    fn test_validate_mbz_bytes_non_zero_outside_range() {
        let mut data = vec![0u8; 100];
        data[5] = 1; // Non-zero outside the checked range
        data[60] = 1; // Non-zero outside the checked range
        // Should pass because the range [10, 50) is all zeros
        assert!(validate_mbz_bytes(&data, 10, 50, "test_field").is_ok());
    }

    // =========================================================================
    // validate_signer_info tests
    // =========================================================================

    #[test]
    fn test_validate_signer_info_vcek_no_mask() {
        let mut report = create_test_report(2);
        // signer_info = 0x00 (VCEK, no mask, no author key)
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        let result = validate_signer_info(&report);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // maskChipKey should be false
    }

    #[test]
    fn test_validate_signer_info_vcek_with_mask() {
        let mut report = create_test_report(2);
        // signer_info = 0x02 (VCEK, maskChipKey=1, authorKeyEn=0)
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        let result = validate_signer_info(&report);
        assert!(result.is_ok());
        assert!(result.unwrap()); // maskChipKey should be true
    }

    #[test]
    fn test_validate_signer_info_vcek_with_author_key() {
        let mut report = create_test_report(2);
        // signer_info = 0x01 (VCEK, maskChipKey=0, authorKeyEn=1)
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        let result = validate_signer_info(&report);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // maskChipKey should be false
    }

    #[test]
    fn test_validate_signer_info_non_vcek_signing_key() {
        let mut report = create_test_report(2);
        // signer_info = 0x04 (signing_key = 1, not VCEK)
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&4u32.to_le_bytes());
        let result = validate_signer_info(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Only VCEK-signed reports"));
    }

    #[test]
    fn test_validate_signer_info_reserved_bits_set() {
        let mut report = create_test_report(2);
        // signer_info = 0x20 (bit 5 set, should fail)
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&0x20u32.to_le_bytes());
        let result = validate_signer_info(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bits 31-5 must be zero"));
    }

    // =========================================================================
    // validate_mbz_fields tests
    // =========================================================================

    #[test]
    fn test_validate_mbz_fields_valid_v2() {
        let report = create_test_report(2);
        // All zeros is valid for MBZ fields
        assert!(validate_mbz_fields(&report).is_ok());
    }

    #[test]
    fn test_validate_mbz_fields_valid_v3() {
        let report = create_test_report(3);
        assert!(validate_mbz_fields(&report).is_ok());
    }

    #[test]
    fn test_validate_mbz_fields_non_zero_reserved_after_signer_info() {
        let mut report = create_test_report(2);
        report[0x4C] = 1; // Non-zero in reserved_after_signer_info
        let result = validate_mbz_fields(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved_after_signer_info"));
    }

    #[test]
    fn test_validate_mbz_fields_non_zero_reserved_before_signature() {
        let mut report = create_test_report(2);
        report[0x200] = 1; // Non-zero in reserved_before_signature
        let result = validate_mbz_fields(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved_before_signature"));
    }

    #[test]
    fn test_validate_mbz_fields_tcb_reserved_bits_set() {
        let mut report = create_test_report(2);
        // Set reserved bits 47-16 in current_tcb
        // TCB format: bits 0-7: bl_spl, 8-15: tee_spl, 16-47: reserved (MBZ), 48-55: snp_spl, 56-63: ucode_spl
        let tcb_with_reserved_bits: u64 = 0x0000_0001_0000_0000; // bit 32 set (in reserved range)
        report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8].copy_from_slice(&tcb_with_reserved_bits.to_le_bytes());
        let result = validate_mbz_fields(&report);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("current_tcb"));
    }
}
