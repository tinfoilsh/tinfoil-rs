//! Core types for attestation verification

use serde::{Deserialize, Serialize};

/// Predicate types for different attestation formats
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Raw attestation document from the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub format: PredicateType,
    pub body: String, // Base64-encoded, gzipped attestation
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
                let actual_snp = other.registers.get(0)
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
    pub fn fingerprint(&self) -> String {
        self.fingerprint_for_target(&self.type_)
    }

    /// Compute fingerprint for a specific target platform type.
    ///
    /// For SEV-SNP (SevGuestV2), uses only the first register.
    /// For multi-platform source targeting SNP, extracts the SNP register.
    pub fn fingerprint_for_target(&self, target_type: &PredicateType) -> String {
        use sha2::{Sha256, Digest};

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
            (PredicateType::TdxGuestV2, _) => {
                self.registers.iter().map(|s| s.as_str()).collect()
            }
            // Default: use all registers
            _ => {
                self.registers.iter().map(|s| s.as_str()).collect()
            }
        };

        let joined = registers.join("|");
        let hash = Sha256::digest(joined.as_bytes());
        hex::encode(hash)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
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

/// Ground truth after full verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
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
        let router_mp = Measurement {
            type_: PredicateType::SnpTdxMultiPlatformV1,
            registers: vec![
                "33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1".into(),
                "896d8b9138548e63779a121b8c2b1a087ddaa39901e1fd096319ff0005b9699fe04dd13adb33063a1d65dd4bcdc2f5b1".into(),
                "fbe40d6adb70ef8047dbfbd9be05fcf39d9dd32d5b88c70dd5c06024d3a8d79a5d2e9e9723d3b3cb206bfd887eddcdec".into(),
            ],
        };

        let snp_enclave = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["33162608e171154bae88886365341dad7eb5821ba87785041f7f2f6281511a65b01069894cfebad5370939e05a0a1ca1".into()],
        };

        // Fingerprints should match when targeting SEV-SNP
        let source_fp = router_mp.fingerprint_for_target(&PredicateType::SevGuestV2);
        let enclave_fp = snp_enclave.fingerprint();

        assert_eq!(source_fp, enclave_fp);
        assert_eq!(source_fp, "08ea4d8c2e8da077c682529d3cd1d1500d84e100df6b81781e38733f0589cfa1");
    }
}
