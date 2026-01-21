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
