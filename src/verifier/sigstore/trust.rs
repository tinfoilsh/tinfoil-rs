//! Trust root management for Sigstore verification.
//!
//! This module handles loading and parsing the embedded Sigstore trusted root,
//! which contains Fulcio CA certificates, Rekor transparency log keys, and
//! Certificate Transparency log keys.

use serde::Deserialize;

use super::keyring::Keyring;
use crate::error::{Error, Result};
use crate::verifier::util::decode_b64;

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
    #[serde(default)]
    timestamp_authorities: Vec<TimestampAuthorityEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimestampAuthorityEntry {
    cert_chain: CertChain,
    #[serde(default)]
    valid_for: Option<ValidityPeriod>,
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
    #[serde(default)]
    base_url: String,
    public_key: PublicKeyInfo,
    log_id: LogId,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyInfo {
    raw_bytes: String,
    key_details: String,
    #[serde(default)]
    valid_for: Option<ValidityPeriod>,
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

/// Represents a loaded Rekor transparency log key with its metadata.
pub struct RekorKey {
    pub key_id: String,
    /// Hostname of the log's baseUrl. Checkpoint signatures must carry this
    /// name (sigstore-go derives the note verifier name the same way).
    pub host: String,
    pub key_der: Vec<u8>,
    pub key_type: String,
    /// Validity start as Unix timestamp (None = no lower bound)
    pub valid_from: Option<u64>,
    /// Validity end as Unix timestamp (None = no upper bound)
    pub valid_until: Option<u64>,
}

/// An RFC 3161 timestamp authority trusted for observer timestamps.
pub struct TimestampAuthority {
    /// Certificate chain: first is the TSA signing (leaf) cert, last is the root.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Validity start as Unix timestamp (None = no lower bound)
    pub valid_from: Option<u64>,
    /// Validity end as Unix timestamp (None = no upper bound)
    pub valid_until: Option<u64>,
}

fn parse_validity(vf: &Option<ValidityPeriod>) -> Result<(Option<u64>, Option<u64>)> {
    match vf {
        Some(vf) => {
            let from = parse_rfc3339_to_unix(&vf.start)?;
            let until = vf
                .end
                .as_ref()
                .map(|e| parse_rfc3339_to_unix(e))
                .transpose()?;
            Ok((Some(from), until))
        }
        None => Ok((None, None)),
    }
}

/// Load timestamp authorities from embedded trust root.
pub fn load_timestamp_authorities() -> Result<Vec<TimestampAuthority>> {
    load_timestamp_authorities_from_json(TRUSTED_ROOT_JSON)
}

/// Load timestamp authorities from a trusted root JSON string.
pub fn load_timestamp_authorities_from_json(json: &str) -> Result<Vec<TimestampAuthority>> {
    let root: TrustedRoot = serde_json::from_str(json)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut tsas = Vec::new();
    for tsa in root.timestamp_authorities {
        let cert_chain_der = tsa
            .cert_chain
            .certificates
            .iter()
            .map(|c| {
                decode_b64(&c.raw_bytes).map_err(|e| {
                    Error::SigstoreVerification(format!("Failed to decode TSA cert: {}", e))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let (valid_from, valid_until) = parse_validity(&tsa.valid_for)?;
        tsas.push(TimestampAuthority {
            cert_chain_der,
            valid_from,
            valid_until,
        });
    }
    Ok(tsas)
}

/// Load Rekor public keys from embedded trust root.
pub fn load_rekor_keys() -> Result<Vec<RekorKey>> {
    load_rekor_keys_from_json(TRUSTED_ROOT_JSON)
}

/// Load Rekor public keys from a trusted root JSON string.
pub fn load_rekor_keys_from_json(json: &str) -> Result<Vec<RekorKey>> {
    let root: TrustedRoot = serde_json::from_str(json)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut keys = Vec::new();
    for tlog in root.tlogs {
        let key_der = decode_b64(&tlog.public_key.raw_bytes).map_err(|e| {
            Error::SigstoreVerification(format!("Failed to decode Rekor key: {}", e))
        })?;

        let (valid_from, valid_until) = parse_validity(&tlog.public_key.valid_for)?;
        let host = tlog
            .base_url
            .split("://")
            .last()
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("")
            .to_string();

        keys.push(RekorKey {
            key_id: tlog.log_id.key_id,
            host,
            key_der,
            key_type: tlog.public_key.key_details,
            valid_from,
            valid_until,
        });
    }
    Ok(keys)
}

/// Load Certificate Transparency log keyring from embedded trust root.
///
/// This creates a Keyring containing all CT log public keys with their validity
/// periods, which can be used for SCT verification using the sigstore-rs adapted
/// transparency module. Keys are only accepted if the SCT timestamp falls within
/// the key's validity window.
pub fn load_ctlog_keyring() -> Result<Keyring> {
    let root: TrustedRoot = serde_json::from_str(TRUSTED_ROOT_JSON)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut keys_with_validity: Vec<(Vec<u8>, Option<u64>, Option<u64>)> = Vec::new();
    for ctlog in root.ctlogs {
        // Only include P-256 keys (the keyring only supports EC P-256)
        if ctlog.public_key.key_details != "PKIX_ECDSA_P256_SHA_256" {
            continue;
        }
        let public_key_der = decode_b64(&ctlog.public_key.raw_bytes).map_err(|e| {
            Error::SigstoreVerification(format!("Failed to decode CT log key: {}", e))
        })?;

        let (valid_from, valid_until) = parse_validity(&ctlog.public_key.valid_for)?;

        keys_with_validity.push((public_key_der, valid_from, valid_until));
    }

    Keyring::new_with_validity(
        keys_with_validity
            .iter()
            .map(|(der, from, until)| (der.as_slice(), *from, *until)),
    )
    .map_err(|e| Error::SigstoreVerification(format!("Failed to create CT log keyring: {}", e)))
}

/// Load Certificate Transparency log keyring from a trusted root JSON string.
pub fn load_ctlog_keyring_from_json(json: &str) -> Result<Keyring> {
    let root: TrustedRoot = serde_json::from_str(json)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut keys_with_validity: Vec<(Vec<u8>, Option<u64>, Option<u64>)> = Vec::new();
    for ctlog in root.ctlogs {
        if ctlog.public_key.key_details != "PKIX_ECDSA_P256_SHA_256" {
            continue;
        }
        let public_key_der = decode_b64(&ctlog.public_key.raw_bytes).map_err(|e| {
            Error::SigstoreVerification(format!("Failed to decode CT log key: {}", e))
        })?;

        let (valid_from, valid_until) = parse_validity(&ctlog.public_key.valid_for)?;

        keys_with_validity.push((public_key_der, valid_from, valid_until));
    }

    Keyring::new_with_validity(
        keys_with_validity
            .iter()
            .map(|(der, from, until)| (der.as_slice(), *from, *until)),
    )
    .map_err(|e| Error::SigstoreVerification(format!("Failed to create CT log keyring: {}", e)))
}

/// Load Fulcio Certificate Authorities from embedded trust root.
pub fn load_fulcio_cas() -> Result<Vec<FulcioCa>> {
    load_fulcio_cas_from_json(TRUSTED_ROOT_JSON)
}

/// Load Fulcio Certificate Authorities from a trusted root JSON string.
pub fn load_fulcio_cas_from_json(json: &str) -> Result<Vec<FulcioCa>> {
    let root: TrustedRoot = serde_json::from_str(json)
        .map_err(|e| Error::SigstoreVerification(format!("Failed to parse trusted root: {}", e)))?;

    let mut cas = Vec::new();
    for ca in root.certificate_authorities {
        let mut cert_chain_der = Vec::new();
        for cert in &ca.cert_chain.certificates {
            let der = decode_b64(&cert.raw_bytes).map_err(|e| {
                Error::SigstoreVerification(format!("Failed to decode Fulcio cert: {}", e))
            })?;
            cert_chain_der.push(der);
        }

        let valid_from = parse_rfc3339_to_unix(&ca.valid_for.start)?;
        let valid_until = ca
            .valid_for
            .end
            .as_ref()
            .map(|e| parse_rfc3339_to_unix(e))
            .transpose()?;

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
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(|e| {
        Error::SigstoreVerification(format!("Invalid RFC3339 timestamp '{}': {}", s, e))
    })?;

    let ts = dt.unix_timestamp();
    if ts < 0 {
        return Err(Error::SigstoreVerification(format!(
            "Timestamp before Unix epoch: '{}'",
            s
        )));
    }
    Ok(ts as u64)
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
    fn test_load_timestamp_authorities() {
        let tsas = load_timestamp_authorities().unwrap();
        assert!(!tsas.is_empty());
        assert!(tsas[0].cert_chain_der.len() >= 2);
        assert_eq!(load_rekor_keys().unwrap()[0].host, "rekor.sigstore.dev");
    }

    #[test]
    fn test_load_fulcio_cas() {
        let cas = load_fulcio_cas().unwrap();
        assert!(!cas.is_empty());
    }
}
