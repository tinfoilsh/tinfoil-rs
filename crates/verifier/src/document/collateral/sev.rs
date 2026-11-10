//! AMD SEV-SNP endorsement collateral.

use super::{CheckedEntry, CollateralError};
use crate::canonical;
use crate::json::decode;

/// Decoded amd-vcek collateral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdVcek {
    /// The chip certificate, DER.
    pub vcek_der: Vec<u8>,
    /// The intermediate certificate, then the root certificate, PEM.
    pub cert_chain_pem: String,
}

/// Decoded amd-crl collateral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmdCrl {
    /// The certificate revocation list, DER.
    pub crl_der: Vec<u8>,
}

pub(super) fn decode_vcek(entry: CheckedEntry) -> Result<AmdVcek, CollateralError> {
    let id = entry.id;
    let mut vcek_der_base64 = String::new();
    let mut cert_chain_pem = String::new();
    for (name, value) in entry.data.into_members() {
        let decoded = match name.as_str() {
            "vcek_der_base64" => decode::string(value, &name).map(|v| vcek_der_base64 = v),
            "cert_chain_pem" => decode::string(value, &name).map(|v| cert_chain_pem = v),
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing("amd-vcek", &id, &error))?;
    }
    let vcek_der =
        canonical::decode_base64("vcek_der_base64", &vcek_der_base64).map_err(|error| {
            CollateralError::invalid(format!("amd-vcek collateral entry {id:?}: {error}"))
        })?;
    Ok(AmdVcek {
        vcek_der,
        cert_chain_pem,
    })
}

pub(super) fn decode_crl(entry: CheckedEntry) -> Result<AmdCrl, CollateralError> {
    let id = entry.id;
    let mut crl_der_base64 = String::new();
    for (name, value) in entry.data.into_members() {
        let decoded = match name.as_str() {
            "crl_der_base64" => decode::string(value, &name).map(|v| crl_der_base64 = v),
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing("amd-crl", &id, &error))?;
    }
    let crl_der = canonical::decode_base64("crl_der_base64", &crl_der_base64).map_err(|error| {
        CollateralError::invalid(format!("amd-crl collateral entry {id:?}: {error}"))
    })?;
    Ok(AmdCrl { crl_der })
}
