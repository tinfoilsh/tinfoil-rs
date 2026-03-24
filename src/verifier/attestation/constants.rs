//! Constants for AMD SEV-SNP attestation verification.
//!
//! This module contains all the magic numbers, offsets, and OIDs used in
//! SEV-SNP attestation report parsing and certificate chain verification.

// =============================================================================
// Report Structure
// =============================================================================

/// Total size of an SEV-SNP attestation report in bytes.
pub const REPORT_SIZE: usize = 1184;

// =============================================================================
// Report Field Offsets - Core Fields
// =============================================================================

/// Offset of the guest SVN (Security Version Number) field.
pub const GUEST_SVN_OFFSET: usize = 0x04;

/// Offset of the 64-bit guest policy field.
pub const POLICY_OFFSET: usize = 8;

/// Offset of the 16-byte family ID field.
pub const FAMILY_ID_OFFSET: usize = 0x10;

/// Size of the family ID field in bytes.
pub const FAMILY_ID_SIZE: usize = 16;

/// Offset of the 16-byte image ID field.
pub const IMAGE_ID_OFFSET: usize = 0x20;

/// Size of the image ID field in bytes.
pub const IMAGE_ID_SIZE: usize = 16;

/// Offset of the VMPL (Virtual Machine Privilege Level) field.
/// VMPL ranges from 0 (most privileged) to 3 (least privileged).
pub const VMPL_OFFSET: usize = 0x30;

/// Offset of the signature algorithm field.
/// Must be 1 for ECDSA P-384 SHA-384.
pub const SIGNATURE_ALGO_OFFSET: usize = 0x34;

/// Expected value for ECDSA P-384 SHA-384 signature algorithm.
pub const SIGNATURE_ALGO_ECDSA_P384_SHA384: u32 = 1;

/// Offset of the current TCB (Trusted Computing Base) field.
pub const CURRENT_TCB_OFFSET: usize = 0x38;

/// Offset of the 64-bit platform info field.
pub const PLATFORM_INFO_OFFSET: usize = 0x40;

/// Offset of the 32-bit signer info field.
pub const SIGNER_INFO_OFFSET: usize = 0x48;

// =============================================================================
// Report Field Offsets - Report Data and Measurement
// =============================================================================

/// Offset of the 64-byte report data field.
/// Contains TLS public key fingerprint (first 32 bytes) and HPKE key (next 32 bytes).
pub const REPORT_DATA_OFFSET: usize = 80;

/// Size of the report data field in bytes.
pub const REPORT_DATA_SIZE: usize = 64;

/// Offset of the 32-byte host data field.
pub const HOST_DATA_OFFSET: usize = 0xC0;

/// Size of the host data field in bytes.
pub const HOST_DATA_SIZE: usize = 32;

/// Offset of the 48-byte measurement field.
/// Contains the SHA-384 hash of the guest memory at launch.
pub const MEASUREMENT_OFFSET: usize = 144;

/// Size of the measurement field in bytes.
pub const MEASUREMENT_SIZE: usize = 48;

// =============================================================================
// Report Field Offsets - IDs and TCB
// =============================================================================

/// Offset of the 32-byte report ID field.
pub const REPORT_ID_OFFSET: usize = 0x140;

/// Size of the report ID field in bytes.
pub const REPORT_ID_SIZE: usize = 32;

/// Offset of the 32-byte report ID MA (Migration Agent) field.
pub const REPORT_ID_MA_OFFSET: usize = 0x160;

/// Size of the report ID MA field in bytes.
pub const REPORT_ID_MA_SIZE: usize = 32;

/// Offset of the 64-byte reported TCB field (used for VCEK lookup).
pub const REPORTED_TCB_OFFSET: usize = 384;

/// Offset of the 64-byte chip ID field.
pub const CHIP_ID_OFFSET: usize = 416;

/// Size of the chip ID field in bytes.
pub const CHIP_ID_SIZE: usize = 64;

// =============================================================================
// Report Field Offsets - Version Fields
// =============================================================================

/// Offset of the committed TCB field.
pub const COMMITTED_TCB_OFFSET: usize = 0x1E0;

/// Offset of the committed firmware build number.
pub const COMMITTED_BUILD_OFFSET: usize = 0x1EC;

/// Offset of the committed firmware minor version.
pub const COMMITTED_MINOR_OFFSET: usize = 0x1ED;

/// Offset of the committed firmware major version.
pub const COMMITTED_MAJOR_OFFSET: usize = 0x1EE;

/// Offset of the current firmware build number.
pub const CURRENT_BUILD_OFFSET: usize = 488; // 0x1E8

/// Offset of the current firmware minor version.
pub const CURRENT_MINOR_OFFSET: usize = 489; // 0x1E9

/// Offset of the current firmware major version.
pub const CURRENT_MAJOR_OFFSET: usize = 490; // 0x1EA

/// Offset of the launch TCB field.
pub const LAUNCH_TCB_OFFSET: usize = 0x1F0;

// =============================================================================
// Report Field Offsets - Signature
// =============================================================================

/// Offset of the signature field in the report.
pub const SIGNATURE_OFFSET: usize = 672;

/// Total size of the signature field in bytes (includes padding).
pub const SIGNATURE_SIZE: usize = 512;

/// Size of the actual ECDSA P-384 signature (R + S components).
/// Each component is 72 bytes (48 bytes value + 24 bytes padding).
pub const ECDSA_P384_SIGNATURE_SIZE: usize = 144;

// =============================================================================
// Signature Component Sizes
// =============================================================================

/// Size of each signature component (R or S) including padding.
/// Each component is stored as 48 bytes of value + 24 bytes of padding.
pub const SIG_COMPONENT_SIZE: usize = 72;

/// Size of the actual P-384 scalar value (without padding).
pub const SIG_VALUE_SIZE: usize = 48;

// =============================================================================
// Policy Bit Masks
// =============================================================================

/// Bit 17 of the guest policy must be set (reserved per AMD spec).
pub const POLICY_RESERVED_BIT_17: u64 = 1 << 17;

// =============================================================================
// AMD VCEK Certificate OID Extensions
// =============================================================================
// OID arc: 1.3.6.1.4.1.3704.1 (AMD SEV)

/// OID for bootloader SPL (Security Patch Level) in VCEK certificate.
pub const OID_BL_SPL: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1");

/// OID for TEE SPL in VCEK certificate.
pub const OID_TEE_SPL: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2");

/// OID for SNP SPL in VCEK certificate.
pub const OID_SNP_SPL: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3");

/// OID for microcode SPL in VCEK certificate.
pub const OID_UCODE_SPL: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8");

/// OID for hardware ID in VCEK certificate.
pub const OID_HWID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");

/// OID for product name in VCEK certificate (e.g., "Genoa").
pub const OID_PRODUCT_NAME: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.2");

/// OID for Cloud Service Provider ID in VCEK certificate.
/// Presence of this OID indicates a CSP-specific certificate, not chip-specific.
pub const OID_CSP_ID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.5");

// =============================================================================
// AMD Root of Trust
// =============================================================================

/// AMD ARK (AMD Root Key) SPKI fingerprint for Genoa processors.
///
/// This is the SHA-256 hash of the ARK's SubjectPublicKeyInfo (SPKI) in DER format.
/// Pinning this value ensures we only trust certificates signed by AMD's genuine root key.
///
/// To regenerate this value:
/// ```bash
/// curl -s 'https://kds.amd.com/vcek/v1/Genoa/cert_chain' | \
///   openssl x509 -pubkey -noout | \
///   openssl pkey -pubin -outform DER | sha256sum
/// ```
pub const AMD_ARK_GENOA_SPKI_FINGERPRINT: &str =
    "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831";
