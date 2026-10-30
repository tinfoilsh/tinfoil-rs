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

/// Sync verification with caller-supplied collateral (VCEK DER + ASK||ARK PEM),
/// skipping the AMD KDS fetch. The embedded pinned AMD ARK is enforced.
pub fn verify_with_inline_collateral(
    body: &str,
    vcek_der: &[u8],
    cert_chain_pem: &[u8],
    options: &ValidationOptions,
) -> Result<Verification> {
    verify_inline(body, vcek_der, cert_chain_pem, options, None)
}

/// Conformance-only: trust `ark_spki_fingerprint` instead of the pinned AMD ARK,
/// so synthetic chains can be verified. Not part of the production API.
#[cfg(feature = "conformance")]
pub fn verify_with_inline_collateral_untrusted_ark(
    body: &str,
    vcek_der: &[u8],
    cert_chain_pem: &[u8],
    options: &ValidationOptions,
    ark_spki_fingerprint: &str,
) -> Result<Verification> {
    verify_inline(body, vcek_der, cert_chain_pem, options, Some(ark_spki_fingerprint))
}

fn verify_inline(
    body: &str,
    vcek_der: &[u8],
    cert_chain_pem: &[u8],
    options: &ValidationOptions,
    ark_spki_fingerprint: Option<&str>,
) -> Result<Verification> {
    let report_bytes = report::decode_report(body)?;
    report::validate_report_structure(&report_bytes)?;
    cert_chain::verify_cert_chain_crypto_with_override(
        vcek_der,
        cert_chain_pem,
        ark_spki_fingerprint,
    )?;
    verify_report_with_vcek(&report_bytes, vcek_der, options)
}

/// Report checks shared by the inline and KDS paths once the VCEK chain is
/// trusted: field validation, VCEK HWID binding, report signature, result.
fn verify_report_with_vcek(
    report_bytes: &[u8],
    vcek_der: &[u8],
    options: &ValidationOptions,
) -> Result<Verification> {
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
    let mask_chip_key = validation::validate_report_with_chain(report_bytes, vcek_der, options)?;
    cert_chain::validate_vcek_hwid(vcek_der, chip_id, mask_chip_key)?;
    signature::verify_report_signature(report_bytes, vcek_der)?;

    let measurement_bytes =
        &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    Ok(Verification {
        measurement: Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec![hex::encode(measurement_bytes)],
        },
        tls_public_key_fp: hex::encode(&report_data[..32]),
        hpke_public_key: Some(hex::encode(&report_data[32..])),
    })
}

/// Full async verification with custom validation options.
///
/// Allows customizing policy, TCB, and platform requirements.
pub async fn verify_full_with_options(body: &str, options: &ValidationOptions) -> Result<Verification> {
    let report_bytes = report::decode_report(body)?;
    report::validate_report_structure(&report_bytes)?;

    // Fetch the VCEK for this chip/TCB plus the ASK||ARK chain from AMD KDS.
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
    let reported_tcb = &report_bytes[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];
    let vcek = cert_chain::fetch_vcek(chip_id, reported_tcb).await?;
    let cert_chain_pem = cert_chain::fetch_cert_chain().await?;
    cert_chain::verify_cert_chain_crypto(&vcek, &cert_chain_pem)?;

    verify_report_with_vcek(&report_bytes, &vcek, options)
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
