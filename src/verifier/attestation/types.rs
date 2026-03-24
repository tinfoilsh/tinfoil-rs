//! Core types for attestation verification

use serde::{Deserialize, Serialize};

/// Predicate types for different attestation formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PredicateType {
    #[serde(rename = "https://tinfoil.sh/predicate/sev-snp-guest/v2")]
    SevGuestV2,

    #[serde(rename = "https://tinfoil.sh/predicate/tdx-guest/v2")]
    TdxGuestV2,

    #[serde(rename = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1")]
    SnpTdxMultiPlatformV1,

    #[serde(other)]
    Unknown,
}

impl PredicateType {
    /// Returns the URL string representation of this predicate type.
    /// Used for fingerprint computation to match Python's algorithm.
    pub fn as_url(&self) -> &'static str {
        match self {
            PredicateType::SevGuestV2 => "https://tinfoil.sh/predicate/sev-snp-guest/v2",
            PredicateType::TdxGuestV2 => "https://tinfoil.sh/predicate/tdx-guest/v2",
            PredicateType::SnpTdxMultiPlatformV1 => {
                "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
            }
            PredicateType::Unknown => "unknown",
        }
    }
}

/// Raw attestation document from the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub format: PredicateType,
    pub body: String, // Base64-encoded, gzipped attestation
}

impl AttestationDocument {
    /// Compute SHA-256 hash of the attestation document.
    ///
    /// Matches the Go and JS implementations: `sha256(format + body)` where
    /// `format` is the predicate type URL and `body` is the base64-encoded payload.
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let data = format!("{}{}", self.format.as_url(), self.body);
        let hash = Sha256::digest(data.as_bytes());
        hex::encode(hash)
    }
}

/// Measurement registers from the enclave
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    #[serde(rename = "type")]
    pub type_: PredicateType,
    pub registers: Vec<String>,
}

impl Measurement {
    /// Compare measurements, handling multi-platform predicates
    pub fn equals(&self, other: &Measurement) -> Result<(), MeasurementError> {
        // Multi-platform to specific platform comparison
        if self.type_ == PredicateType::SnpTdxMultiPlatformV1 {
            return self.compare_multiplatform(other);
        }
        if other.type_ == PredicateType::SnpTdxMultiPlatformV1 {
            return other.compare_multiplatform(self);
        }

        // Direct comparison
        if self.type_ != other.type_ {
            return Err(MeasurementError::FormatMismatch);
        }

        if self.registers != other.registers {
            return Err(MeasurementError::RegisterMismatch);
        }

        Ok(())
    }

    fn compare_multiplatform(&self, other: &Measurement) -> Result<(), MeasurementError> {
        if self.registers.len() < 3 {
            return Err(MeasurementError::TooFewRegisters);
        }

        match other.type_ {
            PredicateType::SnpTdxMultiPlatformV1 => {
                // Direct comparison for multi-platform to multi-platform
                if self.registers != other.registers {
                    return Err(MeasurementError::RegisterMismatch);
                }
            }
            PredicateType::SevGuestV2 => {
                // Multi-platform register[0] is SNP measurement
                let expected_snp = &self.registers[0];
                let actual_snp = other
                    .registers
                    .get(0)
                    .ok_or(MeasurementError::TooFewRegisters)?;

                if expected_snp != actual_snp {
                    return Err(MeasurementError::SnpMismatch);
                }
            }
            PredicateType::TdxGuestV2 => {
                if other.registers.len() < 5 {
                    return Err(MeasurementError::TooFewRegisters);
                }

                // Multi-platform registers[1,2] are RTMR1, RTMR2
                // TDX registers are [MRTD, RTMR0, RTMR1, RTMR2, RTMR3]
                let expected_rtmr1 = &self.registers[1];
                let expected_rtmr2 = &self.registers[2];
                let actual_rtmr1 = &other.registers[2];
                let actual_rtmr2 = &other.registers[3];

                if expected_rtmr1 != actual_rtmr1 {
                    return Err(MeasurementError::Rtmr1Mismatch);
                }
                if expected_rtmr2 != actual_rtmr2 {
                    return Err(MeasurementError::Rtmr2Mismatch);
                }

                // RTMR3 should be zeros
                let rtmr3_zero = "0".repeat(96);
                if other.registers[4] != rtmr3_zero {
                    return Err(MeasurementError::Rtmr3Mismatch);
                }
            }
            _ => return Err(MeasurementError::FormatMismatch),
        }

        Ok(())
    }

    /// Compute fingerprint of measurement for its own type.
    ///
    /// Algorithm matches Python's tinfoil implementation:
    /// - If single register, returns the raw register value (no hashing)
    /// - Otherwise, hashes: type_url + registers.join("")
    pub fn fingerprint(&self) -> String {
        self.fingerprint_for_target(&self.type_)
    }

    /// Compute fingerprint for a specific target platform type.
    ///
    /// For SEV-SNP (SevGuestV2), uses only the first register.
    /// For multi-platform source targeting SNP, extracts the SNP register.
    ///
    /// Algorithm matches Python's tinfoil implementation:
    /// - If single register, returns the raw register value (no hashing)
    /// - Otherwise, hashes: type_url + registers.join("")
    pub fn fingerprint_for_target(&self, target_type: &PredicateType) -> String {
        use sha2::{Digest, Sha256};

        let registers: Vec<&str> = match (&self.type_, target_type) {
            // Multi-platform source targeting SEV-SNP: use first register (SNP measurement)
            (PredicateType::SnpTdxMultiPlatformV1, PredicateType::SevGuestV2) => {
                vec![self.registers.first().map(|s| s.as_str()).unwrap_or("")]
            }
            // SEV-SNP measurement: use first register
            (PredicateType::SevGuestV2, _) => {
                vec![self.registers.first().map(|s| s.as_str()).unwrap_or("")]
            }
            // TDX measurement: all 5 registers
            (PredicateType::TdxGuestV2, _) => self.registers.iter().map(|s| s.as_str()).collect(),
            // Default: use all registers
            _ => self.registers.iter().map(|s| s.as_str()).collect(),
        };

        // Match Python: if single register, return raw value (no hashing)
        if registers.len() == 1 {
            return registers[0].to_string();
        }

        // Match Python: hash type_url + registers.join("") (empty separator)
        let all_data = format!("{}{}", self.type_.as_url(), registers.join(""));
        let hash = Sha256::digest(all_data.as_bytes());
        hex::encode(hash)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum MeasurementError {
    #[error("Attestation format mismatch")]
    FormatMismatch,

    #[error("Register values don't match")]
    RegisterMismatch,

    #[error("Too few registers in measurement")]
    TooFewRegisters,

    #[error("SNP measurement mismatch")]
    SnpMismatch,

    #[error("RTMR1 mismatch")]
    Rtmr1Mismatch,

    #[error("RTMR2 mismatch")]
    Rtmr2Mismatch,

    #[error("RTMR3 mismatch (expected zeros)")]
    Rtmr3Mismatch,
}

/// Result of successful attestation verification
#[derive(Debug, Clone)]
pub struct Verification {
    /// Enclave measurement registers
    pub measurement: Measurement,

    /// TLS public key fingerprint (hex-encoded SHA256)
    pub tls_public_key_fp: String,

    /// HPKE public key for encrypted communication (hex-encoded)
    pub hpke_public_key: Option<String>,
}

/// Decoded SNP policy field from attestation report
#[derive(Debug, Clone, Default)]
pub struct SnpPolicy {
    pub abi_minor: u8,
    pub abi_major: u8,
    pub smt: bool,
    pub migrate_ma: bool,
    pub debug: bool,
    pub single_socket: bool,
    pub cxl_allowed: bool,
    pub mem_aes256_xts: bool,
    pub rapl_dis: bool,
    pub ciphertext_hiding_dram: bool,
    pub page_swap_disabled: bool,
}

impl SnpPolicy {
    pub fn from_u64(value: u64) -> Self {
        Self {
            abi_minor: (value & 0xFF) as u8,
            abi_major: ((value >> 8) & 0xFF) as u8,
            smt: (value & (1 << 16)) != 0,
            migrate_ma: (value & (1 << 18)) != 0,
            debug: (value & (1 << 19)) != 0,
            single_socket: (value & (1 << 20)) != 0,
            cxl_allowed: (value & (1 << 21)) != 0,
            mem_aes256_xts: (value & (1 << 22)) != 0,
            rapl_dis: (value & (1 << 23)) != 0,
            ciphertext_hiding_dram: (value & (1 << 24)) != 0,
            page_swap_disabled: (value & (1 << 25)) != 0,
        }
    }
}

/// Decoded SNP platform info field from attestation report
#[derive(Debug, Clone, Default)]
pub struct SnpPlatformInfo {
    pub smt_enabled: bool,
    pub tsme_enabled: bool,
    pub ecc_enabled: bool,
    pub rapl_disabled: bool,
    pub ciphertext_hiding_dram_enabled: bool,
    pub alias_check_complete: bool,
    pub tio_enabled: bool,
}

impl SnpPlatformInfo {
    pub fn from_u64(value: u64) -> Self {
        Self {
            smt_enabled: (value & (1 << 0)) != 0,
            tsme_enabled: (value & (1 << 1)) != 0,
            ecc_enabled: (value & (1 << 2)) != 0,
            rapl_disabled: (value & (1 << 3)) != 0,
            ciphertext_hiding_dram_enabled: (value & (1 << 4)) != 0,
            alias_check_complete: (value & (1 << 5)) != 0,
            tio_enabled: (value & (1 << 7)) != 0,
        }
    }
}

/// TCB version components
#[derive(Debug, Clone, Default)]
pub struct TcbParts {
    pub bl_spl: u8,
    pub tee_spl: u8,
    pub snp_spl: u8,
    pub ucode_spl: u8,
}

impl TcbParts {
    pub fn from_u64(tcb: u64) -> Self {
        Self {
            bl_spl: (tcb & 0xFF) as u8,
            tee_spl: ((tcb >> 8) & 0xFF) as u8,
            snp_spl: ((tcb >> 48) & 0xFF) as u8,
            ucode_spl: ((tcb >> 56) & 0xFF) as u8,
        }
    }

    pub fn meets_minimum(&self, min: &TcbParts) -> bool {
        self.bl_spl >= min.bl_spl
            && self.tee_spl >= min.tee_spl
            && self.snp_spl >= min.snp_spl
            && self.ucode_spl >= min.ucode_spl
    }
}

/// Validation options for SEV-SNP attestation (mirrors Python's ValidationOptions)
#[derive(Debug, Clone)]
pub struct ValidationOptions {
    /// Policy constraints
    pub guest_policy: Option<SnpPolicy>,
    pub minimum_guest_svn: Option<u32>,
    pub minimum_build: Option<u8>,
    pub minimum_version: Option<u16>, // (major << 8) | minor

    /// TCB requirements
    pub minimum_tcb: Option<TcbParts>,
    pub minimum_launch_tcb: Option<TcbParts>,
    pub permit_provisional_firmware: bool,

    /// Platform info requirements
    pub platform_info: Option<SnpPlatformInfo>,

    /// VMPL requirement
    pub vmpl: Option<u8>,

    /// Optional field equality checks
    /// When set, the corresponding report field must exactly match the provided value
    pub report_data: Option<[u8; 64]>,
    pub host_data: Option<[u8; 32]>,
    pub image_id: Option<[u8; 16]>,
    pub family_id: Option<[u8; 16]>,
    pub report_id: Option<[u8; 32]>,
    pub report_id_ma: Option<[u8; 32]>,
    pub measurement: Option<[u8; 48]>,
    pub chip_id: Option<[u8; 64]>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            guest_policy: Some(SnpPolicy {
                smt: true,
                migrate_ma: false,
                debug: false,
                single_socket: false,
                cxl_allowed: false,
                mem_aes256_xts: false,
                rapl_dis: false,
                ciphertext_hiding_dram: false,
                page_swap_disabled: false,
                ..Default::default()
            }),
            minimum_guest_svn: Some(0),
            minimum_build: Some(21),
            minimum_version: Some((1 << 8) | 55), // 1.55
            minimum_tcb: Some(TcbParts {
                bl_spl: 0x7,
                tee_spl: 0,
                snp_spl: 0xe,
                ucode_spl: 0x48,
            }),
            minimum_launch_tcb: Some(TcbParts {
                bl_spl: 0x7,
                tee_spl: 0,
                snp_spl: 0xe,
                ucode_spl: 0x48,
            }),
            permit_provisional_firmware: false,
            platform_info: Some(SnpPlatformInfo {
                smt_enabled: true,
                tsme_enabled: true,
                ..Default::default()
            }),
            vmpl: Some(0),
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
}

/// Ground truth after full verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    /// SHA-256 hex digest of the release artifact
    pub digest: String,

    /// TLS certificate fingerprint to pin
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_public_key: Option<String>,

    /// HPKE public key for encrypted communication (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hpke_public_key: Option<String>,

    /// Code measurement (from Sigstore or config)
    pub code_measurement: Measurement,

    /// Enclave measurement (from hardware attestation)
    pub enclave_measurement: Measurement,

    /// Fingerprint of code measurement
    pub code_fingerprint: String,

    /// Fingerprint of enclave measurement
    pub enclave_fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTMR3_ZERO: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn test_measurement_equals_multiplatform_to_multiplatform() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        assert!(m1.equals(&m2).is_ok());
    }

    #[test]
    fn test_measurement_equals_multiplatform_mismatch() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp_other".into(), "rtmr1".into(), "rtmr2".into()],
        };
        assert!(m1.equals(&m2).is_err());
    }

    #[test]
    fn test_measurement_equals_multiplatform_to_sevsnp() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["sevsnp".into()],
        };
        assert!(m1.equals(&m2).is_ok());
    }

    #[test]
    fn test_measurement_equals_multiplatform_to_tdx() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "rtmr1".into(),
                "rtmr2".into(),
                RTMR3_ZERO.into(),
            ],
        };
        assert!(m1.equals(&m2).is_ok());
    }

    #[test]
    fn test_measurement_equals_tdx_wrong_rtmr3() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["sevsnp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "rtmr1".into(),
                "rtmr2".into(),
                "nonzero".into(), // Should be zeros
            ],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::Rtmr3Mismatch));
    }

    #[test]
    fn test_ground_truth_json_roundtrip() {
        let gt = GroundTruth {
            digest: "abc123".into(),
            tls_public_key: Some("pubkey".into()),
            hpke_public_key: Some("hpkekey".into()),
            code_measurement: Measurement {
                type_: PredicateType::SnpTdxMultiPlatformV1,
                registers: vec!["a".into(), "b".into()],
            },
            enclave_measurement: Measurement {
                type_: PredicateType::SevGuestV2,
                registers: vec!["a".into()],
            },
            code_fingerprint: "fp1".into(),
            enclave_fingerprint: "fp2".into(),
        };

        let json = serde_json::to_string(&gt).expect("serialize");
        let gt2: GroundTruth = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(gt.tls_public_key, gt2.tls_public_key);
        assert_eq!(gt.hpke_public_key, gt2.hpke_public_key);
        assert_eq!(gt.code_measurement, gt2.code_measurement);
        assert_eq!(gt.enclave_measurement, gt2.enclave_measurement);
    }

    #[test]
    fn test_fingerprint_consistency() {
        // Test that multi-platform source targeting SEV-SNP produces the same
        // fingerprint as the corresponding SEV-SNP enclave measurement
        let snp_measurement = "33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1";

        let router_mp = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec![
                snp_measurement.into(),
                "896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1".into(),
                "fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec".into(),
            ],
        };

        let snp_enclave = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec![snp_measurement.into()],
        };

        // Fingerprints should match when targeting SEV-SNP
        // Both result in single register, so raw value is returned (not hash)
        let source_fp = router_mp.fingerprint_for_target(&PredicateType::SevGuestV2);
        let enclave_fp = snp_enclave.fingerprint();

        assert_eq!(source_fp, enclave_fp);
        assert_eq!(source_fp, snp_measurement); // Raw register, not hash
    }

    // =========================================================================
    // MeasurementError variant tests
    // =========================================================================

    #[test]
    fn test_measurement_error_format_mismatch() {
        let m1 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["snp".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "rtmr1".into(),
                "rtmr2".into(),
                RTMR3_ZERO.into(),
            ],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::FormatMismatch));
    }

    #[test]
    fn test_measurement_error_format_mismatch_unknown() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::Unknown,
            registers: vec!["unknown".into()],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::FormatMismatch));
    }

    #[test]
    fn test_measurement_error_too_few_registers_multiplatform() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "rtmr1".into()], // Only 2, need 3
        };
        let m2 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["snp".into()],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::TooFewRegisters));
    }

    #[test]
    fn test_measurement_error_too_few_registers_tdx() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "rtmr1".into(),
                "rtmr2".into(),
            ], // Only 4, need 5
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::TooFewRegisters));
    }

    #[test]
    fn test_measurement_error_too_few_registers_sevsnp() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec![], // Empty
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::TooFewRegisters));
    }

    #[test]
    fn test_measurement_error_snp_mismatch() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["expected_snp".into(), "rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["actual_snp".into()],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::SnpMismatch));
    }

    #[test]
    fn test_measurement_error_rtmr1_mismatch() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "expected_rtmr1".into(), "rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "actual_rtmr1".into(), // Mismatch with expected_rtmr1
                "rtmr2".into(),
                RTMR3_ZERO.into(),
            ],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::Rtmr1Mismatch));
    }

    #[test]
    fn test_measurement_error_rtmr2_mismatch() {
        let m1 = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec!["snp".into(), "rtmr1".into(), "expected_rtmr2".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec![
                "mrtd".into(),
                "rtmr0".into(),
                "rtmr1".into(),
                "actual_rtmr2".into(), // Mismatch with expected_rtmr2
                RTMR3_ZERO.into(),
            ],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::Rtmr2Mismatch));
    }

    #[test]
    fn test_measurement_error_register_mismatch_direct() {
        // Direct comparison of same type with different registers
        let m1 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["snp1".into()],
        };
        let m2 = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["snp2".into()],
        };
        let err = m1.equals(&m2).unwrap_err();
        assert!(matches!(err, MeasurementError::RegisterMismatch));
    }
}
