//! Container provenance collateral: the build attestation of one container
//! image.

use super::sigstore::missing_bundle;
use super::{CheckedEntry, CollateralError, present};
use crate::canonical;
use crate::json::Value;
use crate::json::decode;

/// Entry format carrying the build attestation of one container image
/// `{digest, sigstore_bundle}`.
pub const CONTAINER_PROVENANCE_V1_FORMAT: &str =
    "https://tinfoil.sh/collateral/container-provenance/v1";

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// Decodes a build attestation and returns it with the SHA-256 of its
/// image, lowercase hex. The bundle is never `null`.
pub(super) fn decode(entry: CheckedEntry) -> Result<(String, Value), CollateralError> {
    let CheckedEntry {
        id, format, data, ..
    } = entry;
    let mut digest = String::new();
    let mut bundle = None;
    for (name, value) in data.into_members() {
        let decoded = match name.as_str() {
            "digest" => decode::string(value, &name).map(|v| digest = v),
            "sigstore_bundle" => {
                bundle = Some(value);
                Ok(())
            }
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing(&format, &id, &error))?;
    }
    canonical::decode_lower_hex("container digest", &digest, SHA256_SIZE)?;
    let bundle = present(bundle).ok_or_else(|| missing_bundle(&format, &id))?;
    Ok((digest, bundle))
}
