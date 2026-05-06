//! SEV-SNP report field validation.
//!
//! This module handles validation of:
//! - Guest policy constraints
//! - TCB (Trusted Computing Base) requirements
//! - Platform info requirements
//! - VMPL (Virtual Machine Privilege Level)
//! - Field equality checks (report_data, host_data, etc.)

use crate::error::{Error, Result};
use crate::verifier::attestation::constants::*;
use crate::verifier::attestation::types::{
    SnpPlatformInfo, SnpPolicy, TcbParts, ValidationOptions,
};

use super::cert_chain::validate_vcek_extensions;
use super::report::{validate_mbz_fields, validate_signer_info};

/// Validate committed TCB matches current TCB (reject provisional firmware).
///
/// Provisional firmware has committed_tcb != current_tcb, meaning the firmware
/// has not yet been committed to the hardware. This is a security risk as the
/// firmware could be rolled back.
fn validate_committed_tcb(report: &[u8]) -> Result<()> {
    let committed_tcb = u64::from_le_bytes(
        report[COMMITTED_TCB_OFFSET..COMMITTED_TCB_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let current_tcb = u64::from_le_bytes(
        report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8]
            .try_into()
            .unwrap(),
    );

    if committed_tcb != current_tcb {
        return Err(Error::AttestationVerification(format!(
            "Provisional firmware not allowed: committed_tcb (0x{:x}) != current_tcb (0x{:x})",
            committed_tcb, current_tcb
        )));
    }

    // Validate version fields match
    let committed_build = report[COMMITTED_BUILD_OFFSET];
    let current_build = report[CURRENT_BUILD_OFFSET];
    if committed_build != current_build {
        return Err(Error::AttestationVerification(format!(
            "Provisional firmware: committed_build ({}) != current_build ({})",
            committed_build, current_build
        )));
    }

    let committed_minor = report[COMMITTED_MINOR_OFFSET];
    let current_minor = report[CURRENT_MINOR_OFFSET];
    if committed_minor != current_minor {
        return Err(Error::AttestationVerification(format!(
            "Provisional firmware: committed_minor ({}) != current_minor ({})",
            committed_minor, current_minor
        )));
    }

    let committed_major = report[COMMITTED_MAJOR_OFFSET];
    let current_major = report[CURRENT_MAJOR_OFFSET];
    if committed_major != current_major {
        return Err(Error::AttestationVerification(format!(
            "Provisional firmware: committed_major ({}) != current_major ({})",
            committed_major, current_major
        )));
    }

    Ok(())
}

/// Validate guest policy against required policy constraints.
///
/// This checks:
/// 1. ABI version compatibility (required version must not exceed report version)
/// 2. Unauthorized capabilities (report has them but required doesn't allow)
/// 3. Required restrictions (report lacks what required mandates)
fn validate_policy(report_policy: &SnpPolicy, required: &SnpPolicy) -> Result<()> {
    // ABI version check - required version must not be greater than report version
    let required_version = ((required.abi_major as u16) << 8) | (required.abi_minor as u16);
    let report_version = ((report_policy.abi_major as u16) << 8) | (report_policy.abi_minor as u16);
    if required_version > report_version {
        return Err(Error::AttestationVerification(format!(
            "Required ABI version ({}.{}) is greater than report's ABI version ({}.{})",
            required.abi_major,
            required.abi_minor,
            report_policy.abi_major,
            report_policy.abi_minor
        )));
    }

    // Unauthorized capabilities (report has them, required doesn't allow)
    if !required.migrate_ma && report_policy.migrate_ma {
        return Err(Error::AttestationVerification(
            "Unauthorized migration agent capability".into(),
        ));
    }
    if !required.debug && report_policy.debug {
        return Err(Error::AttestationVerification(
            "Debug mode not allowed".into(),
        ));
    }
    if !required.smt && report_policy.smt {
        return Err(Error::AttestationVerification(
            "Unauthorized SMT capability".into(),
        ));
    }
    if !required.cxl_allowed && report_policy.cxl_allowed {
        return Err(Error::AttestationVerification(
            "Unauthorized CXL capability".into(),
        ));
    }
    if !required.mem_aes256_xts && report_policy.mem_aes256_xts {
        return Err(Error::AttestationVerification(
            "Unauthorized memory encryption mode (AES-256-XTS)".into(),
        ));
    }

    // Required restrictions (report lacks what required mandates)
    if required.mem_aes256_xts && !report_policy.mem_aes256_xts {
        return Err(Error::AttestationVerification(
            "AES-256-XTS memory encryption required but not present".into(),
        ));
    }
    if required.single_socket && !report_policy.single_socket {
        return Err(Error::AttestationVerification(
            "Single socket restriction required but not present".into(),
        ));
    }
    if required.rapl_dis && !report_policy.rapl_dis {
        return Err(Error::AttestationVerification(
            "RAPL disabled required but not present".into(),
        ));
    }
    if required.ciphertext_hiding_dram && !report_policy.ciphertext_hiding_dram {
        return Err(Error::AttestationVerification(
            "Ciphertext hiding in DRAM required but not enforced".into(),
        ));
    }
    if required.page_swap_disabled && !report_policy.page_swap_disabled {
        return Err(Error::AttestationVerification(
            "Page swap disabled required but not present".into(),
        ));
    }

    Ok(())
}

/// Validate platform info against required platform info constraints.
///
/// This checks both unauthorized capabilities (report has them but required doesn't allow)
/// and required features (report lacks what required mandates).
fn validate_platform_info(report_info: &SnpPlatformInfo, required: &SnpPlatformInfo) -> Result<()> {
    // Unauthorized features (report has it enabled, but required doesn't allow it)
    if report_info.smt_enabled && !required.smt_enabled {
        return Err(Error::AttestationVerification(
            "Unauthorized platform feature SMT enabled".into(),
        ));
    }

    // Required capabilities (report must have these if required mandates them)
    if required.tsme_enabled && !report_info.tsme_enabled {
        return Err(Error::AttestationVerification(
            "TSME required but not enabled on platform".into(),
        ));
    }
    if required.ecc_enabled && !report_info.ecc_enabled {
        return Err(Error::AttestationVerification(
            "ECC required but not enabled on platform".into(),
        ));
    }
    if required.rapl_disabled && !report_info.rapl_disabled {
        return Err(Error::AttestationVerification(
            "RAPL disabled required but RAPL is enabled on platform".into(),
        ));
    }
    if required.ciphertext_hiding_dram_enabled && !report_info.ciphertext_hiding_dram_enabled {
        return Err(Error::AttestationVerification(
            "Ciphertext hiding in DRAM required but not enabled on platform".into(),
        ));
    }
    if required.alias_check_complete && !report_info.alias_check_complete {
        return Err(Error::AttestationVerification(
            "Alias check completion required but not complete on platform".into(),
        ));
    }
    if required.tio_enabled && !report_info.tio_enabled {
        return Err(Error::AttestationVerification(
            "TIO required but not enabled on platform".into(),
        ));
    }

    Ok(())
}

/// Validate VMPL (Virtual Machine Privilege Level) from report.
///
/// VMPL is a 4-bit value (0-3) indicating the privilege level:
/// - VMPL 0: Most privileged (typically hypervisor/firmware)
/// - VMPL 3: Least privileged (typically guest application)
///
/// For production workloads, we typically expect VMPL 0.
fn validate_vmpl(report: &[u8], expected_vmpl: Option<u8>) -> Result<()> {
    let vmpl = u32::from_le_bytes(report[VMPL_OFFSET..VMPL_OFFSET + 4].try_into().unwrap());

    // VMPL must be in valid range 0-3
    if vmpl > 3 {
        return Err(Error::AttestationVerification(format!(
            "VMPL {} is not in valid range 0-3",
            vmpl
        )));
    }

    // If specific VMPL is required, verify it matches
    if let Some(expected) = expected_vmpl {
        if vmpl != expected as u32 {
            return Err(Error::AttestationVerification(format!(
                "VMPL mismatch: expected {}, got {}",
                expected, vmpl
            )));
        }
    }

    Ok(())
}

/// Validate report with certificate chain (matches Python's validate_report(report, chain, options)).
///
/// This function combines:
/// 1. Report field validation (policy, version, TCB) using provided options
/// 2. VCEK TCB validation (ensures VCEK cert extensions match report TCB)
///
/// Returns maskChipKey flag for HWID validation.
pub(super) fn validate_report_with_chain(
    report: &[u8],
    vcek: &[u8],
    options: &ValidationOptions,
) -> Result<bool> {
    // Validate report fields using options
    let mask_chip_key = validate_report_fields_with_options(report, options)?;

    // Validate VCEK TCB matches report TCB (like Python's chain.validate_vcek_tcb())
    let reported_tcb = &report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];
    validate_vcek_extensions(vcek, reported_tcb)?;

    Ok(mask_chip_key)
}

/// Validate report fields using configurable ValidationOptions.
/// Returns maskChipKey flag for HWID validation.
fn validate_report_fields_with_options(report: &[u8], options: &ValidationOptions) -> Result<bool> {
    // Validate all MBZ (Must Be Zero) fields first (always required)
    validate_mbz_fields(report)?;

    // Validate signature algorithm (must be 1 = ECDSA P-384 SHA-384) (always required)
    let signature_algo = u32::from_le_bytes(
        report[SIGNATURE_ALGO_OFFSET..SIGNATURE_ALGO_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    if signature_algo != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
        return Err(Error::AttestationVerification(format!(
            "Unsupported signature algorithm: {}, only ECDSA P-384 SHA-384 (1) is supported",
            signature_algo
        )));
    }

    // Validate signer info field (returns maskChipKey for HWID validation)
    let mask_chip_key = validate_signer_info(report)?;

    // Reject permit_provisional_firmware=true (not supported, matches Python reference)
    if options.permit_provisional_firmware {
        return Err(Error::AttestationVerification(
            "permit_provisional_firmware=true is not supported".into(),
        ));
    }

    // Validate committed TCB (always required since permit_provisional_firmware must be false)
    validate_committed_tcb(report)?;

    // Extract and validate guest policy
    let policy_raw =
        u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());

    // Bit 17 must be 1 (reserved per AMD spec) - always required
    if policy_raw & POLICY_RESERVED_BIT_17 == 0 {
        return Err(Error::AttestationVerification(
            "Policy bit 17 must be 1 (reserved)".into(),
        ));
    }

    // Bits 63-26 must be zero - always required
    if policy_raw >> 26 != 0 {
        return Err(Error::AttestationVerification(format!(
            "Policy bits 63-26 must be zero, got 0x{:x}",
            policy_raw >> 26
        )));
    }

    // Validate guest policy if specified
    if let Some(ref required_policy) = options.guest_policy {
        let report_policy = SnpPolicy::from_u64(policy_raw);
        validate_policy(&report_policy, required_policy)?;
    }

    // Validate Guest SVN if specified
    if let Some(min_guest_svn) = options.minimum_guest_svn {
        let guest_svn = u32::from_le_bytes(
            report[GUEST_SVN_OFFSET..GUEST_SVN_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
        if guest_svn < min_guest_svn {
            return Err(Error::AttestationVerification(format!(
                "Guest SVN {} is below minimum {}",
                guest_svn, min_guest_svn
            )));
        }
    }

    // Extract and validate firmware version if specified
    let build = report[CURRENT_BUILD_OFFSET];
    let minor = report[CURRENT_MINOR_OFFSET];
    let major = report[CURRENT_MAJOR_OFFSET];

    if let Some(min_build) = options.minimum_build {
        if build < min_build {
            return Err(Error::AttestationVerification(format!(
                "Current firmware build {} is below minimum {}",
                build, min_build
            )));
        }
        // Also check committed build (matches Python reference)
        let committed_build = report[COMMITTED_BUILD_OFFSET];
        if committed_build < min_build {
            return Err(Error::AttestationVerification(format!(
                "Committed firmware build {} is below minimum {}",
                committed_build, min_build
            )));
        }
    }

    if let Some(min_version) = options.minimum_version {
        let version = (major as u16) << 8 | (minor as u16);
        if version < min_version {
            let min_major = (min_version >> 8) as u8;
            let min_minor = (min_version & 0xFF) as u8;
            return Err(Error::AttestationVerification(format!(
                "Current firmware version {}.{} is below minimum {}.{}",
                major, minor, min_major, min_minor
            )));
        }
        // Also check committed version (matches Python reference)
        let committed_major = report[COMMITTED_MAJOR_OFFSET];
        let committed_minor = report[COMMITTED_MINOR_OFFSET];
        let committed_version = (committed_major as u16) << 8 | (committed_minor as u16);
        if committed_version < min_version {
            let min_major = (min_version >> 8) as u8;
            let min_minor = (min_version & 0xFF) as u8;
            return Err(Error::AttestationVerification(format!(
                "Committed firmware version {}.{} is below minimum {}.{}",
                committed_major, committed_minor, min_major, min_minor
            )));
        }
    }

    // Validate TCB from reported_tcb, current_tcb, committed_tcb, and launch_tcb
    if let Some(ref min_tcb) = options.minimum_tcb {
        // Check reported_tcb
        let reported_tcb = u64::from_le_bytes(
            report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let reported_parts = TcbParts::from_u64(reported_tcb);
        if !reported_parts.meets_minimum(min_tcb) {
            return Err(Error::AttestationVerification(format!(
                "Reported TCB ({:?}) below minimum ({:?})",
                reported_parts, min_tcb
            )));
        }

        // Check current_tcb
        let current_tcb = u64::from_le_bytes(
            report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let current_parts = TcbParts::from_u64(current_tcb);
        if !current_parts.meets_minimum(min_tcb) {
            return Err(Error::AttestationVerification(format!(
                "Current TCB ({:?}) below minimum ({:?})",
                current_parts, min_tcb
            )));
        }

        // Check committed_tcb
        let committed_tcb = u64::from_le_bytes(
            report[COMMITTED_TCB_OFFSET..COMMITTED_TCB_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let committed_parts = TcbParts::from_u64(committed_tcb);
        if !committed_parts.meets_minimum(min_tcb) {
            return Err(Error::AttestationVerification(format!(
                "Committed TCB ({:?}) below minimum ({:?})",
                committed_parts, min_tcb
            )));
        }
    }

    // Validate launch_tcb separately if specified (may have different requirements)
    if let Some(ref min_launch_tcb) = options.minimum_launch_tcb {
        let launch_tcb = u64::from_le_bytes(
            report[LAUNCH_TCB_OFFSET..LAUNCH_TCB_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let launch_parts = TcbParts::from_u64(launch_tcb);
        if !launch_parts.meets_minimum(min_launch_tcb) {
            return Err(Error::AttestationVerification(format!(
                "Launch TCB ({:?}) below minimum ({:?})",
                launch_parts, min_launch_tcb
            )));
        }
    }

    // Validate platform info if specified
    if let Some(ref required_platform_info) = options.platform_info {
        let platform_info_raw = u64::from_le_bytes(
            report[PLATFORM_INFO_OFFSET..PLATFORM_INFO_OFFSET + 8]
                .try_into()
                .unwrap(),
        );

        // Validate platform_info reserved bits must be zero
        // Valid bits per AMD spec: 0 (SMT), 1 (TSME), 2 (ECC), 3 (RAPL_DIS),
        //                         4 (CIPHERTEXT_HIDING), 5 (ALIAS_CHECK), 7 (TIO)
        // Reserved: bit 6, bits 8-63
        const PLATFORM_INFO_VALID_MASK: u64 = 0b10111111; // bits 0-5 and 7
        if platform_info_raw & !PLATFORM_INFO_VALID_MASK != 0 {
            return Err(Error::AttestationVerification(format!(
                "Platform info has non-zero reserved bits: 0x{:x}",
                platform_info_raw
            )));
        }

        let report_platform_info = SnpPlatformInfo::from_u64(platform_info_raw);
        validate_platform_info(&report_platform_info, required_platform_info)?;
    }

    // Validate VMPL if specified
    validate_vmpl(report, options.vmpl)?;

    // Validate optional field equality checks
    if let Some(ref expected) = options.report_data {
        let actual = &report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "report_data mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.host_data {
        let actual = &report[HOST_DATA_OFFSET..HOST_DATA_OFFSET + HOST_DATA_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "host_data mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.image_id {
        let actual = &report[IMAGE_ID_OFFSET..IMAGE_ID_OFFSET + IMAGE_ID_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "image_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.family_id {
        let actual = &report[FAMILY_ID_OFFSET..FAMILY_ID_OFFSET + FAMILY_ID_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "family_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.report_id {
        let actual = &report[REPORT_ID_OFFSET..REPORT_ID_OFFSET + REPORT_ID_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "report_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.report_id_ma {
        let actual = &report[REPORT_ID_MA_OFFSET..REPORT_ID_MA_OFFSET + REPORT_ID_MA_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "report_id_ma mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.measurement {
        let actual = &report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "measurement mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    if let Some(ref expected) = options.chip_id {
        let actual = &report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
        if actual != expected.as_slice() {
            return Err(Error::AttestationVerification(format!(
                "chip_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
    }

    Ok(mask_chip_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal valid report for testing.
    /// Sets version to 2, policy bit 17, and all other bytes to zero.
    fn create_test_report(version: u32) -> Vec<u8> {
        let mut report = vec![0u8; REPORT_SIZE];
        // Set version (little-endian u32 at offset 0)
        report[0..4].copy_from_slice(&version.to_le_bytes());
        // Set policy bit 17 (required per AMD spec)
        let policy: u64 = POLICY_RESERVED_BIT_17;
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());
        // Set signature algorithm to ECDSA P-384 SHA-384 (required)
        report[SIGNATURE_ALGO_OFFSET..SIGNATURE_ALGO_OFFSET + 4]
            .copy_from_slice(&SIGNATURE_ALGO_ECDSA_P384_SHA384.to_le_bytes());
        report
    }

    /// Returns a minimal ValidationOptions for testing.
    /// All optional validations are disabled (None/false).
    fn minimal_options() -> ValidationOptions {
        ValidationOptions {
            guest_policy: None,
            minimum_guest_svn: None,
            minimum_build: None,
            minimum_version: None,
            minimum_tcb: None,
            minimum_launch_tcb: None,
            permit_provisional_firmware: false,
            platform_info: None,
            vmpl: None,
            report_data: None,
            host_data: None,
            image_id: None,
            family_id: None,
            report_id: None,
            report_id_ma: None,
            measurement: None,
            chip_id: None,
        }
    }

    // =========================================================================
    // Signature algorithm validation tests
    // =========================================================================

    #[test]
    fn test_wrong_signature_algorithm_zero() {
        let mut report = create_test_report(2);
        // Set signature algorithm to 0 (invalid)
        report[SIGNATURE_ALGO_OFFSET..SIGNATURE_ALGO_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported signature algorithm"));
    }

    #[test]
    fn test_wrong_signature_algorithm_two() {
        let mut report = create_test_report(2);
        // Set signature algorithm to 2 (hypothetical future algorithm)
        report[SIGNATURE_ALGO_OFFSET..SIGNATURE_ALGO_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported signature algorithm"));
    }

    // =========================================================================
    // Policy validation tests
    // =========================================================================

    #[test]
    fn test_policy_missing_bit_17() {
        let mut report = create_test_report(2);
        // Clear policy bit 17 (required to be set)
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Policy bit 17 must be 1"));
    }

    #[test]
    fn test_policy_high_bits_set() {
        let mut report = create_test_report(2);
        // Set bit 26 (should be zero)
        let policy: u64 = POLICY_RESERVED_BIT_17 | (1u64 << 26);
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());
        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Policy bits 63-26 must be zero"));
    }

    #[test]
    fn test_policy_debug_mode_not_allowed() {
        let report = create_test_report(2);
        // Set debug bit in policy (bit 19)
        let mut policy =
            u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
        policy |= 1u64 << 19; // DEBUG bit

        let mut report = report;
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());

        // Create options that disallow debug mode
        let mut options = minimal_options();
        options.guest_policy = Some(SnpPolicy {
            debug: false,
            ..Default::default()
        });

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Debug mode not allowed"));
    }

    #[test]
    fn test_policy_unauthorized_smt() {
        let report = create_test_report(2);
        // Set SMT bit in policy (bit 16)
        let mut policy =
            u64::from_le_bytes(report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap());
        policy |= 1u64 << 16; // SMT bit

        let mut report = report;
        report[POLICY_OFFSET..POLICY_OFFSET + 8].copy_from_slice(&policy.to_le_bytes());

        // Create options that disallow SMT
        let mut options = minimal_options();
        options.guest_policy = Some(SnpPolicy {
            smt: false,
            ..Default::default()
        });

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unauthorized SMT capability"));
    }

    // =========================================================================
    // TCB validation tests
    // =========================================================================

    #[test]
    fn test_tcb_below_minimum() {
        let report = create_test_report(2);
        // Set minimum TCB requirement that won't be met by all-zeros
        let mut options = minimal_options();
        options.minimum_tcb = Some(TcbParts {
            bl_spl: 1,
            tee_spl: 0,
            snp_spl: 0,
            ucode_spl: 0,
        });

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("TCB") && err.contains("below minimum"));
    }

    // =========================================================================
    // Guest SVN validation tests
    // =========================================================================

    #[test]
    fn test_guest_svn_below_minimum() {
        let report = create_test_report(2);
        // Report has guest_svn = 0, require minimum of 1
        let mut options = minimal_options();
        options.minimum_guest_svn = Some(1);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Guest SVN 0 is below minimum 1"));
    }

    // =========================================================================
    // Firmware version validation tests
    // =========================================================================

    #[test]
    fn test_firmware_build_below_minimum() {
        let report = create_test_report(2);
        // Report has build = 0, require minimum of 1
        let mut options = minimal_options();
        options.minimum_build = Some(1);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("firmware build 0 is below minimum 1"));
    }

    #[test]
    fn test_firmware_version_below_minimum() {
        let report = create_test_report(2);
        // Report has version = 0.0, require minimum of 1.0
        let mut options = minimal_options();
        options.minimum_version = Some(0x0100); // version 1.0

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("firmware version 0.0 is below minimum 1.0"));
    }

    // =========================================================================
    // Platform info validation tests
    // =========================================================================

    #[test]
    fn test_platform_info_unauthorized_smt() {
        let mut report = create_test_report(2);
        // Set SMT enabled in platform info (bit 0)
        let platform_info: u64 = 1; // SMT enabled
        report[PLATFORM_INFO_OFFSET..PLATFORM_INFO_OFFSET + 8]
            .copy_from_slice(&platform_info.to_le_bytes());

        // Create options that disallow SMT
        let mut options = minimal_options();
        options.platform_info = Some(SnpPlatformInfo {
            smt_enabled: false,
            ..Default::default()
        });

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unauthorized platform feature SMT enabled"));
    }

    #[test]
    fn test_platform_info_required_tsme_missing() {
        let report = create_test_report(2);
        // Platform info is all zeros (no TSME)

        // Create options that require TSME
        let mut options = minimal_options();
        options.platform_info = Some(SnpPlatformInfo {
            tsme_enabled: true,
            ..Default::default()
        });

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("TSME required but not enabled"));
    }

    // =========================================================================
    // VMPL validation tests
    // =========================================================================

    #[test]
    fn test_vmpl_out_of_range() {
        let mut report = create_test_report(2);
        // Set VMPL to 4 (out of valid range 0-3)
        report[VMPL_OFFSET..VMPL_OFFSET + 4].copy_from_slice(&4u32.to_le_bytes());

        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VMPL 4 is not in valid range 0-3"));
    }

    #[test]
    fn test_vmpl_mismatch() {
        let mut report = create_test_report(2);
        // Set VMPL to 1
        report[VMPL_OFFSET..VMPL_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());

        // Require VMPL 0
        let mut options = minimal_options();
        options.vmpl = Some(0);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("VMPL mismatch: expected 0, got 1"));
    }

    // =========================================================================
    // Provisional firmware validation tests
    // =========================================================================

    #[test]
    fn test_provisional_firmware_tcb_mismatch() {
        let mut report = create_test_report(2);
        // Set committed_tcb different from current_tcb
        // TCB format: bits 0-7=bl_spl, 8-15=tee_spl, 16-47=reserved(MBZ), 48-55=snp_spl, 56-63=ucode_spl
        let committed_tcb: u64 = 0x480E_0000_0000_0007; // valid TCB with ucode=0x48, snp=0x0E, bl=0x07
        let current_tcb: u64 = 0x480E_0000_0000_0001; // same but different bl_spl
        report[COMMITTED_TCB_OFFSET..COMMITTED_TCB_OFFSET + 8]
            .copy_from_slice(&committed_tcb.to_le_bytes());
        report[CURRENT_TCB_OFFSET..CURRENT_TCB_OFFSET + 8]
            .copy_from_slice(&current_tcb.to_le_bytes());

        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Provisional firmware not allowed"));
    }

    #[test]
    fn test_provisional_firmware_build_mismatch() {
        let mut report = create_test_report(2);
        // Set committed_build different from current_build
        report[COMMITTED_BUILD_OFFSET] = 1;
        report[CURRENT_BUILD_OFFSET] = 2;

        let result = validate_report_fields_with_options(&report, &minimal_options());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("committed_build (1) != current_build (2)"));
    }

    #[test]
    fn test_permit_provisional_firmware_not_supported() {
        let report = create_test_report(2);
        let mut options = minimal_options();
        options.permit_provisional_firmware = true;

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("permit_provisional_firmware=true is not supported"));
    }

    // =========================================================================
    // Field mismatch validation tests
    // =========================================================================

    #[test]
    fn test_report_data_mismatch() {
        let report = create_test_report(2);
        // Report data is all zeros

        // Expect different report_data
        let mut options = minimal_options();
        options.report_data = Some([1u8; 64]);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("report_data mismatch"));
    }

    #[test]
    fn test_measurement_mismatch() {
        let report = create_test_report(2);
        // Measurement is all zeros

        // Expect different measurement
        let mut options = minimal_options();
        options.measurement = Some([0xABu8; 48]);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("measurement mismatch"));
    }

    #[test]
    fn test_host_data_mismatch() {
        let report = create_test_report(2);
        // Host data is all zeros

        // Expect different host_data
        let mut options = minimal_options();
        options.host_data = Some([0xCDu8; 32]);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("host_data mismatch"));
    }

    #[test]
    fn test_chip_id_mismatch() {
        let report = create_test_report(2);
        // Chip ID is all zeros

        // Expect different chip_id
        let mut options = minimal_options();
        options.chip_id = Some([0xEFu8; 64]);

        let result = validate_report_fields_with_options(&report, &options);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chip_id mismatch"));
    }

    // =========================================================================
    // validate_policy unit tests
    // =========================================================================

    #[test]
    fn test_validate_policy_abi_version_too_high() {
        let report_policy = SnpPolicy {
            abi_major: 1,
            abi_minor: 0,
            ..Default::default()
        };
        let required_policy = SnpPolicy {
            abi_major: 2,
            abi_minor: 0,
            ..Default::default()
        };

        let result = validate_policy(&report_policy, &required_policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Required ABI version (2.0) is greater than report's ABI version (1.0)"));
    }

    #[test]
    fn test_validate_policy_unauthorized_migrate_ma() {
        let report_policy = SnpPolicy {
            migrate_ma: true,
            ..Default::default()
        };
        let required_policy = SnpPolicy {
            migrate_ma: false,
            ..Default::default()
        };

        let result = validate_policy(&report_policy, &required_policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unauthorized migration agent capability"));
    }

    #[test]
    fn test_validate_policy_required_single_socket_missing() {
        let report_policy = SnpPolicy {
            single_socket: false,
            ..Default::default()
        };
        let required_policy = SnpPolicy {
            single_socket: true,
            ..Default::default()
        };

        let result = validate_policy(&report_policy, &required_policy);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Single socket restriction required but not present"));
    }

    // =========================================================================
    // validate_platform_info unit tests
    // =========================================================================

    #[test]
    fn test_validate_platform_info_required_ecc_missing() {
        let report_info = SnpPlatformInfo {
            ecc_enabled: false,
            ..Default::default()
        };
        let required_info = SnpPlatformInfo {
            ecc_enabled: true,
            ..Default::default()
        };

        let result = validate_platform_info(&report_info, &required_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("ECC required but not enabled"));
    }

    #[test]
    fn test_validate_platform_info_required_rapl_disabled_missing() {
        let report_info = SnpPlatformInfo {
            rapl_disabled: false,
            ..Default::default()
        };
        let required_info = SnpPlatformInfo {
            rapl_disabled: true,
            ..Default::default()
        };

        let result = validate_platform_info(&report_info, &required_info);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("RAPL disabled required but RAPL is enabled"));
    }

    // =========================================================================
    // validate_vmpl unit tests
    // =========================================================================

    #[test]
    fn test_validate_vmpl_valid_range() {
        let mut report = create_test_report(2);
        // Test all valid VMPL values
        for vmpl in 0u32..=3 {
            report[VMPL_OFFSET..VMPL_OFFSET + 4].copy_from_slice(&vmpl.to_le_bytes());
            assert!(validate_vmpl(&report, None).is_ok());
        }
    }

    #[test]
    fn test_validate_vmpl_exact_match() {
        let mut report = create_test_report(2);
        report[VMPL_OFFSET..VMPL_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        assert!(validate_vmpl(&report, Some(2)).is_ok());
    }

    // =========================================================================
    // validate_committed_tcb unit tests
    // =========================================================================

    #[test]
    fn test_validate_committed_tcb_minor_mismatch() {
        let mut report = create_test_report(2);
        report[COMMITTED_MINOR_OFFSET] = 1;
        report[CURRENT_MINOR_OFFSET] = 2;

        let result = validate_committed_tcb(&report);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("committed_minor (1) != current_minor (2)"));
    }

    #[test]
    fn test_validate_committed_tcb_major_mismatch() {
        let mut report = create_test_report(2);
        report[COMMITTED_MAJOR_OFFSET] = 1;
        report[CURRENT_MAJOR_OFFSET] = 2;

        let result = validate_committed_tcb(&report);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("committed_major (1) != current_major (2)"));
    }
}
