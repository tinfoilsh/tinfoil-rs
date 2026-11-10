//! Config collateral: the workload's config bytes, or a signed reference to
//! them.

use super::{
    CONFIG_ENDORSEMENT_V2_FORMAT, CONFIG_V1_FORMAT, CheckedEntry, CollateralError, object_bundle,
};
use crate::canonical;
use crate::json::Value;
use crate::json::decode;

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// Untrusted config material decoded from a document.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigEndorsement {
    /// Exact config bytes without an endorsement. The caller's policy must
    /// authorize them.
    Plain {
        /// The config bytes; never empty.
        config: Vec<u8>,
    },
    /// A signed reference to a config. The reference must match the
    /// endorsement once that has been verified independently.
    Signed {
        /// `sha256:` followed by the lowercase hex digest of the endorsed
        /// reference.
        reference: String,
        /// The registry approval bundle, a JSON object.
        bundle: Value,
        /// The config bytes, when the document carries them; never empty.
        config: Option<Vec<u8>>,
        /// The issuer certificate, DER, when the document carries one.
        issuer: Option<Vec<u8>>,
    },
}

impl ConfigEndorsement {
    /// The signed reference, or `None` for plain config.
    pub fn reference(&self) -> Option<&str> {
        match self {
            ConfigEndorsement::Plain { .. } => None,
            ConfigEndorsement::Signed { reference, .. } => Some(reference),
        }
    }

    /// The approval bundle, or `None` for plain config.
    pub fn bundle(&self) -> Option<&Value> {
        match self {
            ConfigEndorsement::Plain { .. } => None,
            ConfigEndorsement::Signed { bundle, .. } => Some(bundle),
        }
    }

    /// The config bytes, when the document carries them.
    pub fn config(&self) -> Option<&[u8]> {
        match self {
            ConfigEndorsement::Plain { config } => Some(config),
            ConfigEndorsement::Signed { config, .. } => config.as_deref(),
        }
    }

    /// The issuer certificate, when the document carries one.
    pub fn issuer(&self) -> Option<&[u8]> {
        match self {
            ConfigEndorsement::Plain { .. } => None,
            ConfigEndorsement::Signed { issuer, .. } => issuer.as_deref(),
        }
    }
}

pub(super) fn decode(entry: CheckedEntry) -> Result<ConfigEndorsement, CollateralError> {
    let CheckedEntry {
        id, format, data, ..
    } = entry;
    let (mut reference, mut config, mut issuer) = (String::new(), String::new(), String::new());
    let mut bundle = None;
    for (name, value) in data.into_members() {
        let decoded = match name.as_str() {
            "endorsement_ref" => decode::string(value, &name).map(|v| reference = v),
            "config_base64" => decode::string(value, &name).map(|v| config = v),
            "sigstore_bundle" => {
                bundle = Some(value);
                Ok(())
            }
            "issuer_certificate_der" => decode::string(value, &name).map(|v| issuer = v),
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing(&format, &id, &error))?;
    }

    let is_v2 = format == CONFIG_ENDORSEMENT_V2_FORMAT;
    if !issuer.is_empty() && !is_v2 {
        return Err(CollateralError::invalid(
            "issuer certificates require v2 config collateral",
        ));
    }
    if format == CONFIG_V1_FORMAT {
        // A `null` bundle counts as present here.
        if !reference.is_empty() || bundle.is_some() {
            return Err(CollateralError::invalid(
                "plain config collateral cannot contain an endorsement",
            ));
        }
        return Ok(ConfigEndorsement::Plain {
            config: decode_config(&config)?,
        });
    }

    let Some(digest) = reference.strip_prefix("sha256:") else {
        return Err(CollateralError::invalid(
            "endorsement_ref must be a SHA-256 reference",
        ));
    };
    canonical::decode_lower_hex("endorsement_ref", digest, SHA256_SIZE)?;
    let Some(bundle) = object_bundle(bundle) else {
        return Err(CollateralError::invalid(
            "sigstore_bundle must be an object",
        ));
    };
    let issuer = if issuer.is_empty() {
        None
    } else {
        Some(canonical::decode_base64("issuer_certificate_der", &issuer)?)
    };
    let config = if is_v2 && config.is_empty() {
        None
    } else {
        Some(decode_config(&config)?)
    };
    Ok(ConfigEndorsement::Signed {
        reference,
        bundle,
        config,
        issuer,
    })
}

fn decode_config(encoded: &str) -> Result<Vec<u8>, CollateralError> {
    let config = canonical::decode_base64("config_base64", encoded)?;
    if config.is_empty() {
        return Err(CollateralError::invalid("config_base64 must not be empty"));
    }
    Ok(config)
}
