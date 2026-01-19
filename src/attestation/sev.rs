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

use base64::Engine;
use flate2::read::GzDecoder;
use sha2::{Sha256, Sha384, Digest};
use std::io::Read;

use crate::error::{Error, Result};
use super::types::{Measurement, PredicateType, Verification};

// SEV-SNP report offsets (v3 report structure)
const REPORT_DATA_OFFSET: usize = 80;
const REPORT_DATA_SIZE: usize = 64;
const MEASUREMENT_OFFSET: usize = 144;
const MEASUREMENT_SIZE: usize = 48;
const SIGNATURE_OFFSET: usize = 672;
const SIGNATURE_SIZE: usize = 512;
const REPORT_SIZE: usize = 1184;

// Chip ID and TCB for VCEK lookup
const CHIP_ID_OFFSET: usize = 416;
const CHIP_ID_SIZE: usize = 64;
const REPORTED_TCB_OFFSET: usize = 384;

// Additional report field offsets for validation
const POLICY_OFFSET: usize = 8;
const CURRENT_BUILD_OFFSET: usize = 54;
const CURRENT_MINOR_OFFSET: usize = 55;
const CURRENT_MAJOR_OFFSET: usize = 56;

// Minimum TCB values for production
const MIN_BL_SPL: u8 = 0x07;
const MIN_TEE_SPL: u8 = 0x00;
const MIN_SNP_SPL: u8 = 0x0e;
const MIN_UCODE_SPL: u8 = 0x48;
const MIN_BUILD: u8 = 21;
const MIN_VERSION_MAJOR: u8 = 1;
const MIN_VERSION_MINOR: u8 = 55;

// Guest policy bit masks (64-bit policy field)
const POLICY_DEBUG_BIT: u64 = 1 << 19;
const POLICY_MIGRATE_MA_BIT: u64 = 1 << 18;
const POLICY_SMT_BIT: u64 = 1 << 16;

// Signature component sizes (AMD SEV-SNP ECDSA P-384)
// Each component (R, S) is stored in 72 bytes (48 bytes value + 24 bytes padding)
// Values are in little-endian format
const SIG_COMPONENT_SIZE: usize = 72;
const SIG_VALUE_SIZE: usize = 48;  // P-384 scalar size

/// AMD ARK (AMD Root Key) for Genoa processors
/// This is the SPKI (SubjectPublicKeyInfo) SHA-256 fingerprint of the ARK public key.
/// Pinning this value ensures we only trust certificates signed by AMD's genuine root key.
/// 
/// To regenerate this value:
/// ```bash
/// curl -s 'https://kds.amd.com/vcek/v1/Genoa/cert_chain' | \
///   openssl x509 -pubkey -noout | \
///   openssl pkey -pubin -outform DER | sha256sum
/// ```
const AMD_ARK_GENOA_SPKI_FINGERPRINT: &str = "429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831";

/// Verify AMD SEV-SNP attestation and extract measurements
pub fn verify(body: &str) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = decode_report(body)?;
    
    // 2. Basic structure validation
    validate_report_structure(&report_bytes)?;
    
    // 3. Extract measurement (48 bytes at offset 144)
    let measurement_bytes = &report_bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE];
    
    // 4. Extract report data (64 bytes at offset 80)
    // First 32 bytes: TLS public key fingerprint
    // Next 32 bytes: HPKE public key
    let report_data = &report_bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE];
    let tls_fp = hex::encode(&report_data[..32]);
    let hpke_key = hex::encode(&report_data[32..]);
    
    // 5. Verify report signature
    // This checks that the signature in the report is not trivially invalid
    // Full VCEK chain verification requires async (fetching certs)
    verify_report_signature_basic(&report_bytes)?;
    
    // 6. Build verification result
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

/// Full async verification including VCEK fetch and chain validation
pub async fn verify_full(body: &str) -> Result<Verification> {
    // 1. Decode and decompress
    let report_bytes = decode_report(body)?;

    // 2. Basic structure validation
    validate_report_structure(&report_bytes)?;

    // 3. Validate report fields (policy, version, TCB)
    validate_report_fields(&report_bytes)?;

    // 4. Extract chip_id and TCB for VCEK lookup
    let chip_id = &report_bytes[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE];
    let reported_tcb = &report_bytes[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8];

    // 5. Fetch and verify certificate chain
    let vcek = fetch_vcek(chip_id, reported_tcb).await?;
    let cert_chain = fetch_cert_chain().await?;

    // 6. Verify certificate chain with full cryptographic verification
    verify_cert_chain_crypto(&vcek, &cert_chain)?;

    // 7. Verify report signature against VCEK
    verify_report_signature_full(&report_bytes, &vcek)?;

    // 8. Extract measurements and keys
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

fn decode_report(body: &str) -> Result<Vec<u8>> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|e| Error::AttestationVerification(format!("Base64 decode failed: {}", e)))?;
    
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut report_bytes = Vec::new();
    decoder.read_to_end(&mut report_bytes)
        .map_err(|e| Error::AttestationVerification(format!("Gzip decompress failed: {}", e)))?;
    
    Ok(report_bytes)
}

fn validate_report_structure(report: &[u8]) -> Result<()> {
    if report.len() != REPORT_SIZE {
        return Err(Error::AttestationVerification(format!(
            "Invalid report size: expected {}, got {}",
            REPORT_SIZE, report.len()
        )));
    }

    let version = u32::from_le_bytes([report[0], report[1], report[2], report[3]]);
    if version < 2 || version > 3 {
        return Err(Error::AttestationVerification(format!(
            "Unexpected report version: {}", version
        )));
    }

    Ok(())
}

/// Validate report fields against production requirements
fn validate_report_fields(report: &[u8]) -> Result<()> {
    // Extract and validate guest policy
    let policy = u64::from_le_bytes(
        report[POLICY_OFFSET..POLICY_OFFSET + 8].try_into().unwrap()
    );

    // Debug must be disabled
    if policy & POLICY_DEBUG_BIT != 0 {
        return Err(Error::AttestationVerification(
            "Debug mode is enabled in guest policy".into()
        ));
    }

    // Migrate MA must be disabled
    if policy & POLICY_MIGRATE_MA_BIT != 0 {
        return Err(Error::AttestationVerification(
            "Migration agent is enabled in guest policy".into()
        ));
    }

    // SMT must be enabled (for performance)
    if policy & POLICY_SMT_BIT == 0 {
        return Err(Error::AttestationVerification(
            "SMT is disabled in guest policy".into()
        ));
    }

    // Extract and validate firmware version
    let build = report[CURRENT_BUILD_OFFSET];
    let minor = report[CURRENT_MINOR_OFFSET];
    let major = report[CURRENT_MAJOR_OFFSET];

    if build < MIN_BUILD {
        return Err(Error::AttestationVerification(format!(
            "Firmware build {} is below minimum {}", build, MIN_BUILD
        )));
    }

    // Compare version (major.minor)
    let version = (major as u16) << 8 | (minor as u16);
    let min_version = (MIN_VERSION_MAJOR as u16) << 8 | (MIN_VERSION_MINOR as u16);
    if version < min_version {
        return Err(Error::AttestationVerification(format!(
            "Firmware version {}.{} is below minimum {}.{}",
            major, minor, MIN_VERSION_MAJOR, MIN_VERSION_MINOR
        )));
    }

    // Extract and validate TCB from reported_tcb field
    let tcb = u64::from_le_bytes(
        report[REPORTED_TCB_OFFSET..REPORTED_TCB_OFFSET + 8].try_into().unwrap()
    );

    let bl_spl = (tcb & 0xFF) as u8;
    let tee_spl = ((tcb >> 8) & 0xFF) as u8;
    let snp_spl = ((tcb >> 48) & 0xFF) as u8;
    let ucode_spl = ((tcb >> 56) & 0xFF) as u8;

    if bl_spl < MIN_BL_SPL {
        return Err(Error::AttestationVerification(format!(
            "Boot loader SPL {} is below minimum {}", bl_spl, MIN_BL_SPL
        )));
    }

    if tee_spl < MIN_TEE_SPL {
        return Err(Error::AttestationVerification(format!(
            "TEE SPL {} is below minimum {}", tee_spl, MIN_TEE_SPL
        )));
    }

    if snp_spl < MIN_SNP_SPL {
        return Err(Error::AttestationVerification(format!(
            "SNP SPL {} is below minimum {}", snp_spl, MIN_SNP_SPL
        )));
    }

    if ucode_spl < MIN_UCODE_SPL {
        return Err(Error::AttestationVerification(format!(
            "Microcode SPL {} is below minimum {}", ucode_spl, MIN_UCODE_SPL
        )));
    }

    Ok(())
}

/// Parse R and S from the signature bytes
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

fn verify_report_signature_basic(report: &[u8]) -> Result<()> {
    let sig_bytes = &report[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_SIZE];
    
    // Basic check: signature should not be all zeros
    if sig_bytes.iter().all(|&b| b == 0) {
        return Err(Error::AttestationVerification(
            "Invalid signature: all zeros".into()
        ));
    }
    
    // Parse and validate R and S components
    let (r_be, s_be) = parse_signature_components(sig_bytes)?;
    
    if r_be.iter().all(|&b| b == 0) || s_be.iter().all(|&b| b == 0) {
        return Err(Error::AttestationVerification(
            "Invalid ECDSA signature components".into()
        ));
    }
    
    Ok(())
}

/// Fetch VCEK certificate from AMD KDS via Tinfoil's proxy
async fn fetch_vcek(chip_id: &[u8], tcb: &[u8]) -> Result<Vec<u8>> {
    // Parse TCB components
    let tcb_val = u64::from_le_bytes(tcb.try_into().unwrap());
    let bl_spl = (tcb_val & 0xFF) as u8;
    let tee_spl = ((tcb_val >> 8) & 0xFF) as u8;
    let snp_spl = ((tcb_val >> 48) & 0xFF) as u8;
    let ucode_spl = ((tcb_val >> 56) & 0xFF) as u8;
    
    let chip_id_hex = hex::encode(chip_id);
    
    // AMD KDS URL format (via Tinfoil proxy)
    let url = format!(
        "https://kds-proxy.tinfoil.sh/vcek/v1/Genoa/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        chip_id_hex, bl_spl, tee_spl, snp_spl, ucode_spl
    );
    
    let response = reqwest::get(&url)
        .await
        .map_err(|e| Error::AttestationVerification(format!("Failed to fetch VCEK: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::AttestationVerification(format!(
            "VCEK fetch failed: HTTP {}",
            response.status()
        )));
    }
    
    let vcek_der = response.bytes().await
        .map_err(|e| Error::AttestationVerification(format!("Failed to read VCEK: {}", e)))?;
    
    Ok(vcek_der.to_vec())
}

/// Get AMD certificate chain (ASK + ARK) from embedded assets
async fn fetch_cert_chain() -> Result<Vec<u8>> {
    Ok(crate::embedded::GENOA_CERT_CHAIN.to_vec())
}

/// Parse PEM certificates from the chain
fn parse_pem_chain(chain_pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pems = pem::parse_many(chain_pem)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse PEM chain: {}", e)))?;
    
    Ok(pems.into_iter().map(|p| p.contents().to_vec()).collect())
}

/// Compute SPKI fingerprint of a certificate's public key
fn compute_spki_fingerprint(cert_der: &[u8]) -> Result<String> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    let spki_der = cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode SPKI: {}", e)))?;
    
    let hash = Sha256::digest(&spki_der);
    Ok(hex::encode(hash))
}

/// Extract public key bytes from a certificate
fn extract_pubkey_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    // Return the full SPKI DER-encoded (needed for RSA key parsing)
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode SPKI: {}", e)))
}

/// Extract TBS (To Be Signed) certificate bytes
fn extract_tbs_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    cert.tbs_certificate
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode TBS: {}", e)))
}

/// Extract signature bytes from a certificate
fn extract_signature_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::Decode;
    
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;
    
    Ok(cert.signature.raw_bytes().to_vec())
}

/// Verify the certificate chain with full cryptographic verification
/// 
/// This function:
/// 1. Verifies ARK public key matches pinned fingerprint (root of trust)
/// 2. Verifies ARK is self-signed (RSA-PSS SHA-384)
/// 3. Verifies ASK signature against ARK public key
/// 4. Verifies VCEK signature against ASK public key
fn verify_cert_chain_crypto(vcek_der: &[u8], cert_chain_pem: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;
    
    // Parse certificates
    let vcek_cert = Certificate::from_der(vcek_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;
    
    let chain_certs = parse_pem_chain(cert_chain_pem)?;
    if chain_certs.len() < 2 {
        return Err(Error::AttestationVerification(
            "Certificate chain should contain ASK and ARK".into()
        ));
    }
    
    let ask_der = &chain_certs[0];
    let ark_der = &chain_certs[1];
    
    let ask_cert = Certificate::from_der(ask_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse ASK: {}", e)))?;
    
    let ark_cert = Certificate::from_der(ark_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse ARK: {}", e)))?;
    
    // === STEP 1: Verify ARK public key matches pinned fingerprint ===
    // This is the root of trust - if this matches, we know we have AMD's genuine ARK
    let ark_fingerprint = compute_spki_fingerprint(ark_der)?;
    if ark_fingerprint != AMD_ARK_GENOA_SPKI_FINGERPRINT {
        return Err(Error::AttestationVerification(format!(
            "ARK public key fingerprint mismatch! Expected: {}, Got: {}. \
             This could indicate a MITM attack or AMD has rotated their root key.",
            AMD_ARK_GENOA_SPKI_FINGERPRINT, ark_fingerprint
        )));
    }
    
    // === STEP 2: Verify issuer/subject chain structure ===
    let vcek_issuer = &vcek_cert.tbs_certificate.issuer;
    let ask_subject = &ask_cert.tbs_certificate.subject;
    let ask_issuer = &ask_cert.tbs_certificate.issuer;
    let ark_subject = &ark_cert.tbs_certificate.subject;
    let ark_issuer = &ark_cert.tbs_certificate.issuer;
    
    // VCEK should be issued by ASK
    if vcek_issuer != ask_subject {
        return Err(Error::AttestationVerification(
            "VCEK issuer does not match ASK subject".into()
        ));
    }
    
    // ASK should be issued by ARK
    if ask_issuer != ark_subject {
        return Err(Error::AttestationVerification(
            "ASK issuer does not match ARK subject".into()
        ));
    }
    
    // ARK should be self-signed
    if ark_issuer != ark_subject {
        return Err(Error::AttestationVerification(
            "ARK is not self-signed".into()
        ));
    }
    
    // Verify CN values
    let ark_cn = extract_cn(ark_subject)?;
    if ark_cn != "ARK-Genoa" {
        return Err(Error::AttestationVerification(format!(
            "Unexpected ARK CN: {}, expected ARK-Genoa", ark_cn
        )));
    }
    
    let ask_cn = extract_cn(ask_subject)?;
    if ask_cn != "SEV-Genoa" {
        return Err(Error::AttestationVerification(format!(
            "Unexpected ASK CN: {}, expected SEV-Genoa", ask_cn
        )));
    }
    
    // === STEP 3: Verify ARK self-signature (RSA-PSS SHA-384) ===
    let ark_pubkey = extract_pubkey_from_cert(ark_der)?;
    let ark_tbs = extract_tbs_from_cert(ark_der)?;
    let ark_sig = extract_signature_from_cert(ark_der)?;
    verify_rsa_pss_signature(&ark_tbs, &ark_sig, &ark_pubkey, "ARK self-signature")?;
    
    // === STEP 4: Verify ASK signature against ARK ===
    let ask_tbs = extract_tbs_from_cert(ask_der)?;
    let ask_sig = extract_signature_from_cert(ask_der)?;
    verify_rsa_pss_signature(&ask_tbs, &ask_sig, &ark_pubkey, "ASK signature")?;
    
    // === STEP 5: Verify VCEK signature against ASK ===
    let ask_pubkey = extract_pubkey_from_cert(ask_der)?;
    let vcek_tbs = extract_tbs_from_cert(vcek_der)?;
    let vcek_sig = extract_signature_from_cert(vcek_der)?;
    verify_rsa_pss_signature(&vcek_tbs, &vcek_sig, &ask_pubkey, "VCEK signature")?;
    
    Ok(())
}

/// Verify an RSA-PSS SHA-384 signature
fn verify_rsa_pss_signature(
    tbs_der: &[u8],
    signature: &[u8],
    signer_spki_der: &[u8],
    context: &str,
) -> Result<()> {
    use rsa::RsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::pkcs8::DecodePublicKey;
    
    // Parse RSA public key from SPKI DER
    let rsa_pubkey = RsaPublicKey::from_public_key_der(signer_spki_der)
        .map_err(|e| Error::AttestationVerification(format!("Invalid RSA public key for {}: {}", context, e)))?;
    
    // Create PSS verifier with SHA-384
    let verifying_key: VerifyingKey<Sha384> = VerifyingKey::new(rsa_pubkey);
    
    // Parse signature
    let sig = Signature::try_from(signature)
        .map_err(|e| Error::AttestationVerification(format!("Invalid signature format for {}: {}", context, e)))?;
    
    // Verify
    verifying_key.verify(tbs_der, &sig)
        .map_err(|e| Error::AttestationVerification(format!("{} verification failed: {}", context, e)))?;
    
    Ok(())
}

/// Extract Common Name from X.509 Name
fn extract_cn(name: &x509_cert::name::Name) -> Result<String> {
    use x509_cert::der::oid::db::rfc4519::CN;
    use der::asn1::Utf8StringRef;
    use der::{Decode, Encode};
    
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == CN {
                let value_bytes = atv.value.value();
                
                // Try to decode as UTF8String first
                if let Ok(s) = Utf8StringRef::from_der(atv.value.to_der().unwrap_or_default().as_slice()) {
                    return Ok(s.as_str().to_string());
                }
                
                // Fallback: treat the raw value as UTF-8
                if let Ok(s) = std::str::from_utf8(value_bytes) {
                    return Ok(s.to_string());
                }
                
                return Err(Error::AttestationVerification("CN value is not valid UTF-8".into()));
            }
        }
    }
    
    Err(Error::AttestationVerification("No CN found in certificate".into()))
}

/// Verify report signature against VCEK public key
/// 
/// Note: Uses deprecated GenericArray from p384 crate's dependency.
/// This is safe and will be fixed when upstream crates update.
#[allow(deprecated)]
fn verify_report_signature_full(report: &[u8], vcek: &[u8]) -> Result<()> {
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
    fn test_measurement_fingerprint() {
        let m = Measurement {
            type_: PredicateType::SevGuestV2,
            registers: vec!["abc123".to_string()],
        };
        
        let fp = m.fingerprint();
        assert!(!fp.is_empty());
        assert_eq!(fp.len(), 64);
    }
    
    #[test]
    fn test_signature_parsing() {
        // Create a mock signature with known values
        let mut sig = vec![0u8; 512];
        
        // R component: little-endian 48 bytes (then 24 padding)
        for i in 0..48 {
            sig[i] = (48 - i) as u8;  // 48, 47, 46, ..., 1
        }
        
        // S component: starts at offset 72
        for i in 0..48 {
            sig[72 + i] = (i + 1) as u8;  // 1, 2, 3, ..., 48
        }
        
        let (r_be, s_be) = parse_signature_components(&sig).unwrap();
        
        // R should be reversed: 1, 2, 3, ..., 48
        assert_eq!(r_be[0], 1);
        assert_eq!(r_be[47], 48);
        
        // S should be reversed: 48, 47, ..., 1
        assert_eq!(s_be[0], 48);
        assert_eq!(s_be[47], 1);
    }
    
    #[test]
    fn test_ark_fingerprint_constant() {
        // Ensure the fingerprint is a valid 64-character hex string
        assert_eq!(AMD_ARK_GENOA_SPKI_FINGERPRINT.len(), 64);
        assert!(AMD_ARK_GENOA_SPKI_FINGERPRINT.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
