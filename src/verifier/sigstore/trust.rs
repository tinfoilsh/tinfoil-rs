//! Trust root management for Sigstore verification.
//!
//! This module handles loading and parsing the embedded Sigstore trusted root,
//! which contains Fulcio CA certificates, Rekor transparency log keys, and
//! Certificate Transparency log keys.

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;
use super::keyring::Keyring;

/// Embedded Sigstore trusted root (Fulcio certs, Rekor keys, CTFE keys)
/// This avoids TUF network calls and provides offline verification capability.
const TRUSTED_ROOT_JSON: &str = include_str!("../../../assets/trusted_root.json");

/// Parsed trusted root for Rekor public keys, Fulcio CAs, and CT logs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TrustedRoot {
    tlogs: Vec<Tlog>,
    certificate_authorities: Vec<CertificateAuthority>,
    ctlogs: Vec<CtLog>,
}

/// Certificate Transparency log entry
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CtLog {
    public_key: PublicKeyInfo,
    #[allow(dead_code)]
    log_id: LogId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateAuthority {
    cert_chain: CertChain,
    valid_for: ValidityPeriod,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertChain {
    certificates: Vec<CertificateEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateEntry {
    raw_bytes: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidityPeriod {
    start: String,
    end: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Tlog {
    public_key: PublicKeyInfo,
    log_id: LogId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyInfo {
    raw_bytes: String,
    key_details: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LogId {
    key_id: String,
}

/// Represents a Fulcio CA with its certificate chain and validity period
pub struct FulcioCa {
    /// Certificate chain: first is intermediate (issuer), last is root
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Validity start as Unix timestamp
    pub valid_from: u64,
    /// Validity end as Unix timestamp (None = no end)
    pub valid_until: Option<u64>,
}

/// Load Rekor public keys from embedded trust root.
///
/// Returns a list of (key_id, key_der, key_type) tuples.
pub fn load_rekor_keys() -> Result<Vec<(String, Vec<u8>, String)>> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut keys = Vec::new();
    for tlog in root.tlogs {
        let key_der = decode_b64(&tlog.public_key.raw_bytes)
            .map_err(|e| Error::SigstoreVerification(format!("Failed to decode Rekor key: {}", e)))?;
        keys.push((tlog.log_id.key_id, key_der, tlog.public_key.key_details));
    }
    Ok(keys)
}

/// Load Certificate Transparency log keyring from embedded trust root.
///
/// This creates a Keyring containing all CT log public keys, which can be used
/// for SCT verification using the sigstore-rs adapted transparency module.
pub fn load_ctlog_keyring() -> Result<Keyring> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut key_ders: Vec<Vec<u8>> = Vec::new();
    for ctlog in root.ctlogs {
        // Only include P-256 keys (the keyring only supports EC P-256)
        if ctlog.public_key.key_details != "PKIX_ECDSA_P256_SHA_256" {
            continue;
        }
        let public_key_der = decode_b64(&ctlog.public_key.raw_bytes)
            .map_err(|e| Error::SigstoreVerification(format!("Failed to decode CT log key: {}", e)))?;
        key_ders.push(public_key_der);
    }

    Keyring::new(key_ders.iter().map(|k| k.as_slice()))
        .map_err(|e| Error::SigstoreVerification(format!("Failed to create CT log keyring: {}", e)))
}

/// Load Fulcio Certificate Authorities from embedded trust root.
pub fn load_fulcio_cas() -> Result<Vec<FulcioCa>> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut cas = Vec::new();
    for ca in root.certificate_authorities {
        let mut cert_chain_der = Vec::new();
        for cert in &ca.cert_chain.certificates {
            let der = decode_b64(&cert.raw_bytes)
                .map_err(|e| Error::SigstoreVerification(format!("Failed to decode Fulcio cert: {}", e)))?;
            cert_chain_der.push(der);
        }

        let valid_from = parse_rfc3339_to_unix(&ca.valid_for.start)?;
        let valid_until = ca.valid_for.end.as_ref().map(|e| parse_rfc3339_to_unix(e)).transpose()?;

        cas.push(FulcioCa {
            cert_chain_der,
            valid_from,
            valid_until,
        });
    }
    Ok(cas)
}

/// Parse RFC3339 timestamp to Unix timestamp.
pub fn parse_rfc3339_to_unix(s: &str) -> Result<u64> {
    // Parse ISO 8601 / RFC 3339 format manually
    // Format: "2022-04-13T20:06:15Z" or "2022-12-31T23:59:59.999Z"
    let s = s.trim_end_matches('Z');
    let (date_part, time_part) = s.split_once('T')
        .ok_or_else(|| Error::SigstoreVerification(format!("Invalid timestamp format: {}", s)))?;

    let date_parts: Vec<&str> = date_part.split('-').collect();
    if date_parts.len() != 3 {
        return Err(Error::SigstoreVerification(format!("Invalid date format: {}", date_part)));
    }

    let year: i32 = date_parts[0].parse().map_err(|_| Error::SigstoreVerification("Invalid year".into()))?;
    let month: u32 = date_parts[1].parse().map_err(|_| Error::SigstoreVerification("Invalid month".into()))?;
    let day: u32 = date_parts[2].parse().map_err(|_| Error::SigstoreVerification("Invalid day".into()))?;

    // Handle time with optional fractional seconds
    let time_base = time_part.split('.').next().unwrap_or(time_part);
    let time_parts: Vec<&str> = time_base.split(':').collect();
    if time_parts.len() != 3 {
        return Err(Error::SigstoreVerification(format!("Invalid time format: {}", time_part)));
    }

    let hour: u32 = time_parts[0].parse().map_err(|_| Error::SigstoreVerification("Invalid hour".into()))?;
    let minute: u32 = time_parts[1].parse().map_err(|_| Error::SigstoreVerification("Invalid minute".into()))?;
    let second: u32 = time_parts[2].parse().map_err(|_| Error::SigstoreVerification("Invalid second".into()))?;

    // Calculate days since Unix epoch (1970-01-01)
    let days = days_since_epoch(year, month, day);
    let secs = (days as u64) * 86400 + (hour as u64) * 3600 + (minute as u64) * 60 + (second as u64);

    Ok(secs)
}

/// Calculate days since Unix epoch for a given date.
fn days_since_epoch(year: i32, month: u32, day: u32) -> i64 {
    // Days in each month (non-leap year)
    const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    fn is_leap_year(y: i32) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    let mut days: i64 = 0;

    // Add days for years since 1970
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for months in current year
    for m in 1..month {
        days += DAYS_IN_MONTH[(m - 1) as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add days in current month
    days += (day - 1) as i64;

    days
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc3339() {
        let ts = parse_rfc3339_to_unix("2022-04-13T20:06:15Z").unwrap();
        // 2022-04-13 20:06:15 UTC
        assert!(ts > 0);
    }

    #[test]
    fn test_load_rekor_keys() {
        let keys = load_rekor_keys().unwrap();
        assert!(!keys.is_empty());
    }

    #[test]
    fn test_load_ctlog_keyring() {
        let keyring = load_ctlog_keyring().unwrap();
        // Just verify it loads without error
        let _ = keyring;
    }

    #[test]
    fn test_load_fulcio_cas() {
        let cas = load_fulcio_cas().unwrap();
        assert!(!cas.is_empty());
    }
}
