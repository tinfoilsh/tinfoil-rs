//! AMD certificate chain verification.
//!
//! This module handles:
//! - Fetching VCEK certificates from AMD KDS
//! - Verifying the certificate chain (VCEK → ASK → ARK)
//! - Validating certificate CNs and location fields
//! - RSA-PSS SHA-384 signature verification

use sha2::{Sha256, Sha384, Digest};

use crate::error::{Error, Result};
use crate::verifier::attestation::constants::*;

/// Fetch VCEK certificate from AMD KDS via Tinfoil's proxy.
pub(super) async fn fetch_vcek(chip_id: &[u8], tcb: &[u8]) -> Result<Vec<u8>> {
    use crate::verifier::util::fetch_with_retry;

    // Parse TCB components
    let tcb_val = u64::from_le_bytes(tcb.try_into().unwrap());
    let bl_spl = (tcb_val & 0xFF) as u8;
    let tee_spl = ((tcb_val >> 8) & 0xFF) as u8;
    let snp_spl = ((tcb_val >> 48) & 0xFF) as u8;
    let ucode_spl = ((tcb_val >> 56) & 0xFF) as u8;

    let chip_id_hex = hex::encode(chip_id);

    // AMD KDS URL format (via Tinfoil proxy)
    let url = format!(
        "{}/vcek/v1/Genoa/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        crate::constants::KDS_PROXY, chip_id_hex, bl_spl, tee_spl, snp_spl, ucode_spl
    );

    let response = fetch_with_retry(&url)
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

/// Get AMD certificate chain (ASK + ARK) from embedded assets.
pub(super) async fn fetch_cert_chain() -> Result<Vec<u8>> {
    Ok(crate::verifier::embedded::GENOA_CERT_CHAIN.to_vec())
}

/// Parse PEM certificates from the chain.
fn parse_pem_chain(chain_pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let pems = pem::parse_many(chain_pem)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse PEM chain: {}", e)))?;

    Ok(pems.into_iter().map(|p| p.contents().to_vec()).collect())
}

/// Compute SPKI fingerprint of a certificate's public key.
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

/// Extract public key bytes from a certificate.
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

/// Extract TBS (To Be Signed) certificate bytes.
fn extract_tbs_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::{Decode, Encode};

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;

    cert.tbs_certificate
        .to_der()
        .map_err(|e| Error::AttestationVerification(format!("Failed to encode TBS: {}", e)))
}

/// Extract signature bytes from a certificate.
fn extract_signature_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    use x509_cert::Certificate;
    use der::Decode;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse cert: {}", e)))?;

    Ok(cert.signature.raw_bytes().to_vec())
}

/// Check if an OID matches the expected value.
fn oid_matches(oid: &der::oid::ObjectIdentifier, expected: &[u64]) -> bool {
    let oid_str = oid.to_string();
    let expected_str = expected.iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".");
    oid_str == expected_str
}

/// Decode a DER-encoded INTEGER to u8.
fn decode_der_integer(data: &[u8]) -> Result<u8> {
    use der::Decode;
    let uint = der::asn1::UintRef::from_der(data).map_err(|e| {
        Error::AttestationVerification(format!("Invalid DER INTEGER: {}", e))
    })?;
    let bytes = uint.as_bytes();
    match bytes.len() {
        0 => Ok(0),
        1 => Ok(bytes[0]),
        _ => Err(Error::AttestationVerification(format!(
            "DER INTEGER value {} does not fit in u8",
            hex::encode(bytes)
        ))),
    }
}

/// Extract extension value by OID from VCEK certificate.
fn get_vcek_extension(vcek_der: &[u8], target_oid: &[u64]) -> Result<Option<Vec<u8>>> {
    use x509_cert::Certificate;
    use der::Decode;

    let cert = Certificate::from_der(vcek_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if oid_matches(&ext.extn_id, target_oid) {
                return Ok(Some(ext.extn_value.as_bytes().to_vec()));
            }
        }
    }
    Ok(None)
}

/// Validate VCEK HWID matches report chip_id.
///
/// If maskChipKey is set in the report, chip_id must be all zeros.
/// Otherwise, HWID from VCEK must match chip_id from report.
pub(super) fn validate_vcek_hwid(vcek_der: &[u8], chip_id: &[u8], mask_chip_key: bool) -> Result<()> {
    if mask_chip_key {
        // If maskChipKey is set, chip_id must be all zeros
        if chip_id.iter().any(|&b| b != 0) {
            return Err(Error::AttestationVerification(
                "maskChipKey is set but CHIP_ID is not zeroed".into()
            ));
        }
        return Ok(());
    }

    // Extract HWID from VCEK OID extension
    let hwid = get_vcek_extension(vcek_der, OID_HWID)?
        .ok_or_else(|| Error::AttestationVerification("Missing HWID in VCEK".into()))?;

    // HWID must be exactly 64 bytes
    if hwid.len() != 64 {
        return Err(Error::AttestationVerification(format!(
            "VCEK HWID length is {}, expected 64 bytes", hwid.len()
        )));
    }

    // HWID must match chip_id from the report
    if hwid != chip_id {
        return Err(Error::AttestationVerification(format!(
            "VCEK HWID does not match report CHIP_ID: expected {}, got {}",
            hex::encode(chip_id), hex::encode(&hwid)
        )));
    }

    Ok(())
}

/// Validate VCEK certificate extensions against report TCB values.
pub(super) fn validate_vcek_extensions(vcek_der: &[u8], reported_tcb: &[u8]) -> Result<()> {
    let tcb_val = u64::from_le_bytes(reported_tcb.try_into().unwrap());
    let bl_spl = (tcb_val & 0xFF) as u8;
    let tee_spl = ((tcb_val >> 8) & 0xFF) as u8;
    let snp_spl = ((tcb_val >> 48) & 0xFF) as u8;
    let ucode_spl = ((tcb_val >> 56) & 0xFF) as u8;

    // Validate BL_SPL
    let vcek_bl = get_vcek_extension(vcek_der, OID_BL_SPL)?
        .ok_or_else(|| Error::AttestationVerification("Missing BL_SPL in VCEK".into()))?;
    let vcek_bl_val = decode_der_integer(&vcek_bl)?;
    if vcek_bl_val != bl_spl {
        return Err(Error::AttestationVerification(format!(
            "VCEK BL_SPL ({}) does not match report ({})", vcek_bl_val, bl_spl
        )));
    }

    // Validate TEE_SPL
    let vcek_tee = get_vcek_extension(vcek_der, OID_TEE_SPL)?
        .ok_or_else(|| Error::AttestationVerification("Missing TEE_SPL in VCEK".into()))?;
    let vcek_tee_val = decode_der_integer(&vcek_tee)?;
    if vcek_tee_val != tee_spl {
        return Err(Error::AttestationVerification(format!(
            "VCEK TEE_SPL ({}) does not match report ({})", vcek_tee_val, tee_spl
        )));
    }

    // Validate SNP_SPL
    let vcek_snp = get_vcek_extension(vcek_der, OID_SNP_SPL)?
        .ok_or_else(|| Error::AttestationVerification("Missing SNP_SPL in VCEK".into()))?;
    let vcek_snp_val = decode_der_integer(&vcek_snp)?;
    if vcek_snp_val != snp_spl {
        return Err(Error::AttestationVerification(format!(
            "VCEK SNP_SPL ({}) does not match report ({})", vcek_snp_val, snp_spl
        )));
    }

    // Validate UCODE_SPL
    let vcek_ucode = get_vcek_extension(vcek_der, OID_UCODE_SPL)?
        .ok_or_else(|| Error::AttestationVerification("Missing UCODE_SPL in VCEK".into()))?;
    let vcek_ucode_val = decode_der_integer(&vcek_ucode)?;
    if vcek_ucode_val != ucode_spl {
        return Err(Error::AttestationVerification(format!(
            "VCEK UCODE_SPL ({}) does not match report ({})", vcek_ucode_val, ucode_spl
        )));
    }

    // Validate PRODUCT_NAME is "Genoa" (ASN.1 IA5String: 0x16 0x05 "Genoa")
    let vcek_product = get_vcek_extension(vcek_der, OID_PRODUCT_NAME)?
        .ok_or_else(|| Error::AttestationVerification("Missing PRODUCT_NAME in VCEK".into()))?;
    // Expected: IA5String tag (0x16), length (0x05), "Genoa"
    let expected_product = b"\x16\x05Genoa";
    if vcek_product != expected_product {
        return Err(Error::AttestationVerification(format!(
            "VCEK PRODUCT_NAME is not Genoa: {:?}", vcek_product
        )));
    }

    // Reject if CSP_ID is present (indicates cloud service provider cert, not chip-specific)
    if get_vcek_extension(vcek_der, OID_CSP_ID)?.is_some() {
        return Err(Error::AttestationVerification(
            "VCEK contains unexpected CSP_ID extension".into()
        ));
    }

    Ok(())
}

/// Validate that a certificate is currently valid (not expired, not before valid date).
fn validate_certificate_validity(cert: &x509_cert::Certificate, cert_name: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::AttestationVerification("System time before Unix epoch".into()))?
        .as_secs();

    // Extract notBefore and notAfter from certificate validity
    let validity = &cert.tbs_certificate.validity;

    // Convert x509_cert Time to Unix timestamp
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();

    if now < not_before {
        return Err(Error::AttestationVerification(format!(
            "{} certificate is not yet valid (current time {} < notBefore {})",
            cert_name, now, not_before
        )));
    }

    if now > not_after {
        return Err(Error::AttestationVerification(format!(
            "{} certificate has expired (current time {} > notAfter {})",
            cert_name, now, not_after
        )));
    }

    Ok(())
}

/// Validate BasicConstraints extension on a certificate.
/// CA certificates (ARK, ASK) must have CA:true. Leaf certificates (VCEK) must not.
fn validate_basic_constraints(
    cert: &x509_cert::Certificate,
    cert_name: &str,
    expect_ca: bool,
) -> Result<()> {
    use x509_cert::ext::pkix::BasicConstraints;

    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_critical, bc))) => {
            if expect_ca && !bc.ca {
                return Err(Error::AttestationVerification(format!(
                    "{} certificate missing CA:true in BasicConstraints",
                    cert_name
                )));
            }
            if !expect_ca && bc.ca {
                return Err(Error::AttestationVerification(format!(
                    "{} leaf certificate has CA:true (expected leaf)",
                    cert_name
                )));
            }
            Ok(())
        }
        Ok(None) if expect_ca => Err(Error::AttestationVerification(format!(
            "{} certificate missing BasicConstraints extension",
            cert_name
        ))),
        Ok(None) => Ok(()), // Leaf cert without BasicConstraints is acceptable
        Err(e) => Err(Error::AttestationVerification(format!(
            "Failed to parse {} BasicConstraints: {}",
            cert_name, e
        ))),
    }
}

/// Verify the certificate chain with full cryptographic verification.
///
/// This function:
/// 1. Verifies ARK public key matches pinned fingerprint (root of trust)
/// 2. Verifies ARK is self-signed (RSA-PSS SHA-384)
/// 3. Verifies ASK signature against ARK public key
/// 4. Verifies VCEK signature against ASK public key
/// 5. Validates all certificates are within their validity period
/// 6. Validates BasicConstraints (ARK/ASK must be CAs, VCEK must not)
pub(super) fn verify_cert_chain_crypto(vcek_der: &[u8], cert_chain_pem: &[u8]) -> Result<()> {
    use x509_cert::Certificate;
    use der::Decode;

    // Parse certificates
    let vcek_cert = Certificate::from_der(vcek_der)
        .map_err(|e| Error::AttestationVerification(format!("Failed to parse VCEK: {}", e)))?;

    // Validate VCEK certificate format
    // Version must be v3
    if vcek_cert.tbs_certificate.version != x509_cert::certificate::Version::V3 {
        return Err(Error::AttestationVerification(
            "VCEK certificate version is not v3".into()
        ));
    }

    // Public key must be EC with P-384 curve
    // OID for ecPublicKey: 1.2.840.10045.2.1
    // OID for secp384r1: 1.3.132.0.34
    let vcek_spki = &vcek_cert.tbs_certificate.subject_public_key_info;
    const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    const OID_SECP384R1: &[u64] = &[1, 3, 132, 0, 34];

    if !oid_matches(&vcek_spki.algorithm.oid, OID_EC_PUBLIC_KEY) {
        return Err(Error::AttestationVerification(format!(
            "VCEK public key is not EC: {}", vcek_spki.algorithm.oid
        )));
    }

    // Verify curve is P-384 (secp384r1)
    if let Some(params) = &vcek_spki.algorithm.parameters {
        use der::{Decode, Encode};
        let params_der = params.to_der()
            .map_err(|_| Error::AttestationVerification("Failed to encode VCEK curve parameters".into()))?;
        let curve_oid = der::oid::ObjectIdentifier::from_der(params_der.as_slice())
            .map_err(|_| Error::AttestationVerification("Failed to parse VCEK curve OID".into()))?;
        if !oid_matches(&curve_oid, OID_SECP384R1) {
            return Err(Error::AttestationVerification(format!(
                "VCEK public key curve is not P-384: {}", curve_oid
            )));
        }
    } else {
        return Err(Error::AttestationVerification(
            "VCEK public key missing curve parameters".into()
        ));
    }

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

    // Validate ARK certificate version (must be v3)
    if ark_cert.tbs_certificate.version != x509_cert::certificate::Version::V3 {
        return Err(Error::AttestationVerification(
            "ARK certificate version is not v3".into()
        ));
    }

    // Validate ASK certificate version (must be v3)
    if ask_cert.tbs_certificate.version != x509_cert::certificate::Version::V3 {
        return Err(Error::AttestationVerification(
            "ASK certificate version is not v3".into()
        ));
    }

    // Validate all certificates are within their validity period
    validate_certificate_validity(&vcek_cert, "VCEK")?;
    validate_certificate_validity(&ask_cert, "ASK")?;
    validate_certificate_validity(&ark_cert, "ARK")?;

    // Validate BasicConstraints: ARK and ASK must be CAs, VCEK must not
    validate_basic_constraints(&ark_cert, "ARK", true)?;
    validate_basic_constraints(&ask_cert, "ASK", true)?;
    validate_basic_constraints(&vcek_cert, "VCEK", false)?;

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

    let vcek_subject = &vcek_cert.tbs_certificate.subject;
    let vcek_cn = extract_cn(vcek_subject)?;
    if vcek_cn != "SEV-VCEK" {
        return Err(Error::AttestationVerification(format!(
            "Unexpected VCEK CN: {}, expected SEV-VCEK", vcek_cn
        )));
    }

    // Verify AMD location fields for all certificates
    validate_amd_location(ark_subject, "ARK")?;
    validate_amd_location(ask_subject, "ASK")?;
    validate_amd_location(vcek_subject, "VCEK")?;

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

/// Verify an RSA-PSS SHA-384 signature.
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

/// Validate that a certificate's subject/issuer has AMD's expected location fields.
///
/// AMD certificates should have:
/// - Country: US
/// - State: CA
/// - Locality: Santa Clara
/// - Organization: Advanced Micro Devices
/// - Organizational Unit: Engineering
fn validate_amd_location(name: &x509_cert::name::Name, cert_name: &str) -> Result<()> {
    use x509_cert::der::oid::db::rfc4519::{C, ST, L, O, OU};
    use der::asn1::Utf8StringRef;
    use der::{Decode, Encode};

    fn extract_attr(name: &x509_cert::name::Name, oid: &der::oid::ObjectIdentifier) -> Option<String> {
        for rdn in name.0.iter() {
            for atv in rdn.0.iter() {
                if &atv.oid == oid {
                    let value_bytes = atv.value.value();
                    if let Ok(s) = Utf8StringRef::from_der(atv.value.to_der().unwrap_or_default().as_slice()) {
                        return Some(s.as_str().to_string());
                    }
                    if let Ok(s) = std::str::from_utf8(value_bytes) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    }

    let country = extract_attr(name, &C);
    let state = extract_attr(name, &ST);
    let locality = extract_attr(name, &L);
    let org = extract_attr(name, &O);
    let org_unit = extract_attr(name, &OU);

    if country.as_deref() != Some("US") {
        return Err(Error::AttestationVerification(format!(
            "{} certificate country is not US: {:?}", cert_name, country
        )));
    }
    if state.as_deref() != Some("CA") {
        return Err(Error::AttestationVerification(format!(
            "{} certificate state is not CA: {:?}", cert_name, state
        )));
    }
    if locality.as_deref() != Some("Santa Clara") {
        return Err(Error::AttestationVerification(format!(
            "{} certificate locality is not Santa Clara: {:?}", cert_name, locality
        )));
    }
    if org.as_deref() != Some("Advanced Micro Devices") {
        return Err(Error::AttestationVerification(format!(
            "{} certificate organization is not Advanced Micro Devices: {:?}", cert_name, org
        )));
    }
    if org_unit.as_deref() != Some("Engineering") {
        return Err(Error::AttestationVerification(format!(
            "{} certificate organizational unit is not Engineering: {:?}", cert_name, org_unit
        )));
    }

    Ok(())
}

/// Extract Common Name from X.509 Name.
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
