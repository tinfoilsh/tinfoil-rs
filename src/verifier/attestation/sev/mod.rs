//! AMD SEV-SNP attestation verification
//!
//! This module verifies SEV-SNP attestation reports using the AMD certificate chain.
//! The verification flow:
//! 1. Parse the raw attestation report
//! 2. Fetch VCEK certificate from AMD KDS (via Tinfoil's proxy)
//! 3. Verify ARK public key matches pinned value (root of trust)
//! 4. Verify ARK is self-signed (RSA-PSS SHA-384)
//! 5. Verify ASK is signed by ARK (RSA-PSS SHA-384)
//! 6. Verify VCEK is signed by ASK (RSA-PSS SHA-384)
//! 7. Verify report signature against VCEK (ECDSA P-384)
//! 8. Extract measurement and TLS keys

mod cert_chain;
mod report;
mod signature;
mod validation;

use crate::error::Result;
use super::constants::*;
use super::types::{Measurement, PredicateType, ValidationOptions, Verification};

/// Full async verification including VCEK fetch and chain validation.
///
/// If `options` is `None`, uses `ValidationOptions::default()` which enforces
/// production-grade security requirements.
pub async fn verify_full(body: &str) -> Result<Verification> {
    verify_full_with_options(body, &ValidationOptions::default()).await
}

/// Sync verification with caller-supplied collateral.
///
/// Mirrors [`verify_full_with_options`] but skips the AMD KDS fetch — VCEK
/// DER + ASK||ARK PEM chain come in as arguments. Used by:
///   - cross-SDK conformance binary's `verify-attestation-sev` stage, which
///     mandates hermetic verification (no AMD KDS network call).
///   - integrators that pre-fetch and cache the chain.
///
/// `trusted_ark_spki_fingerprint`: `None` enforces the embedded pinned
/// AMD-Genoa ARK fingerprint (production). `Some(_)` substitutes a different
/// fingerprint — only the conformance suite's Phase 4B-SEV synthetic-chain
/// fixtures should ever set this; production code paths MUST pass `None`.
pub fn verify_with_inline_collateral(
    body: &str,
    vcek_der: &[u8],
    cert_chain_pem: &[u8],
    options: &ValidationOptions,
    trusted_ark_spki_fingerprint: Option<&str>,
) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = report::decode_report(body)?;

    // 2. Basic structure validation
    report::validate_report_structure(&report_bytes)?;

    // 3. Extract chip_id for VCEK HWID cross-check (reported_tcb is unused
    //    on this path — caller supplied the VCEK already, no lookup needed).
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];

    // 4. Verify the supplied certificate chain end-to-end.
    cert_chain::verify_cert_chain_crypto_with_override(
        vcek_der,
        cert_chain_pem,
        trusted_ark_spki_fingerprint,
    )?;

    // 5. Validate report fields against chain + options.
    let mask_chip_key =
        validation::validate_report_with_chain(&report_bytes, vcek_der, options)?;

    // 6. Validate VCEK HWID matches the report's chip_id.
    cert_chain::validate_vcek_hwid(vcek_der, chip_id, mask_chip_key)?;

    // 7. Verify report signature with VCEK pubkey.
    signature::verify_report_signature(&report_bytes, vcek_der)?;

    // 8. Build the Verification result.
    let measurement_bytes =
        &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    let tls_fp = hex::encode(&report_data[..32]);
    let hpke_key = hex::encode(&report_data[32..]);

    let measurement = Measurement {
        type_: PredicateType::SevGuestV2,
        registers: vec![hex::encode(measurement_bytes)],
    };

    Ok(Verification {
        measurement,
        tls_public_key_fp: tls_fp,
        hpke_public_key: Some(hpke_key),
    })
}

/// Full async verification with custom validation options.
///
/// Allows customizing policy, TCB, and platform requirements.
pub async fn verify_full_with_options(body: &str, options: &ValidationOptions) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = report::decode_report(body)?;

    // 2. Basic structure validation
    report::validate_report_structure(&report_bytes)?;

    // 3. Extract chip_id and TCB for VCEK lookup
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
    let reported_tcb = &report_bytes[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];

    // 4. Fetch and verify certificate chain
    let vcek = cert_chain::fetch_vcek(chip_id, reported_tcb).await?;
    let cert_chain_pem = cert_chain::fetch_cert_chain().await?;

    // 5. Verify certificate chain with full cryptographic verification
    cert_chain::verify_cert_chain_crypto(&vcek, &cert_chain_pem)?;

    // 6. Validate report with chain (matches Python's validate_report(report, chain, options))
    // This combines report field validation with VCEK TCB validation
    let mask_chip_key = validation::validate_report_with_chain(&report_bytes, &vcek, options)?;

    // 7. Validate VCEK HWID matches chip_id
    cert_chain::validate_vcek_hwid(&vcek, chip_id, mask_chip_key)?;

    // 8. Verify report signature against VCEK
    signature::verify_report_signature(&report_bytes, &vcek)?;

    // 9. Extract measurements and keys
    let measurement_bytes = &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    let tls_fp = hex::encode(&report_data[..32]);
    let hpke_key = hex::encode(&report_data[32..]);

    let measurement = Measurement {
        type_: PredicateType::SevGuestV2,
        registers: vec![hex::encode(measurement_bytes)],
    };

    Ok(Verification {
        measurement,
        tls_public_key_fp: tls_fp,
        hpke_public_key: Some(hpke_key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_fingerprint() {
        // Single register: returns raw value (matches Python algorithm)
        let m_single = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["abc123".to_string()],
        };
        let fp_single = m_single.fingerprint();
        assert_eq!(fp_single, "abc123"); // Raw value, not hash

        // Multiple registers: returns hash of type_url + registers.join("")
        let m_multi = Measurement {
            type_: PredicateType::TdxGuestV2,
            registers: vec!["reg1".to_string(), "reg2".to_string()],
        };
        let fp_multi = m_multi.fingerprint();
        assert_eq!(fp_multi.len(), 64); // SHA-256 hex is 64 chars
    }

    #[test]
    fn test_ark_fingerprint_constant() {
        // Ensure the fingerprint is a valid 64-character hex string
        assert_eq!(AMD_ARK_GENOA_SPKI_FINGERPRINT.len(), 64);
        assert!(AMD_ARK_GENOA_SPKI_FINGERPRINT.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
