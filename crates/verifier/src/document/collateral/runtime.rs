//! Runtime collateral: the runtime manifest and the bundle that signs it.

use super::{CheckedEntry, CollateralError, object_bundle};
use crate::json::Value;
use crate::json::decode;
use crate::{canonical, semver};

/// The repository that publishes the runtime.
pub const RUNTIME_REPO: &str = "tinfoilsh/cvmimage";
/// Entry id of the runtime entry.
pub const RUNTIME_ID: &str = "runtime";
/// Entry format of the runtime entry.
pub const RUNTIME_V1_FORMAT: &str = "https://tinfoil.sh/collateral/igvm-runtime/v1";
/// Entry id of the platform reference that config verification uses.
pub const PLATFORM_ID: &str = "platform";

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// An immutable pin of one runtime release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeReference {
    /// The repository; always [`RUNTIME_REPO`] in a valid reference.
    pub repo: String,
    /// The release tag: a full semantic version with a leading `v`.
    pub tag: String,
    /// The SHA-256 of the runtime manifest, lowercase hex.
    pub digest: String,
}

impl RuntimeReference {
    /// Checks the repository, the tag and the digest, in that order.
    pub fn validate(&self) -> Result<(), CollateralError> {
        if self.repo != RUNTIME_REPO {
            return Err(CollateralError::invalid(format!(
                "runtime repository must be {RUNTIME_REPO}"
            )));
        }
        if !semver::is_full(&self.tag) {
            return Err(CollateralError::invalid(
                "runtime tag must be a full semantic version",
            ));
        }
        canonical::decode_lower_hex("runtime digest", &self.digest, SHA256_SIZE)?;
        Ok(())
    }
}

/// Untrusted runtime material decoded from a document.
#[derive(Debug, PartialEq, Eq)]
pub struct Runtime {
    /// The release that the entry names.
    pub reference: RuntimeReference,
    /// The runtime manifest bytes.
    pub manifest: Vec<u8>,
    /// The bundle that signs the manifest, a JSON object.
    pub bundle: Value,
}

pub(super) fn decode(entry: CheckedEntry) -> Result<Runtime, CollateralError> {
    let CheckedEntry {
        id, format, data, ..
    } = entry;
    let mut reference = RuntimeReference::default();
    let mut manifest = String::new();
    let mut bundle = None;
    for (name, value) in data.into_members() {
        let decoded = match name.as_str() {
            "repo" => decode::string(value, &name).map(|v| reference.repo = v),
            "tag" => decode::string(value, &name).map(|v| reference.tag = v),
            "digest" => decode::string(value, &name).map(|v| reference.digest = v),
            "manifest_base64" => decode::string(value, &name).map(|v| manifest = v),
            "sigstore_bundle" => {
                bundle = Some(value);
                Ok(())
            }
            _ => Err(decode::unknown_member("data", &name)),
        };
        decoded.map_err(|error| CollateralError::parsing(&format, &id, &error))?;
    }
    reference.validate()?;
    let manifest = canonical::decode_base64("manifest_base64", &manifest)?;
    let Some(bundle) = object_bundle(bundle) else {
        return Err(CollateralError::invalid(
            "sigstore_bundle must be an object",
        ));
    };
    Ok(Runtime {
        reference,
        manifest,
        bundle,
    })
}
