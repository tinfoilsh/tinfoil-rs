//! Reference values that the caller supplies in place of endorsements.

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::endorsement::approval::parse_name;
use crate::policy::{self, ARTIFACT_FORMAT_V2, Artifact};
use crate::runtime::{
    MAX_CONFIG_SIZE, RuntimeReference, decode_manifest, parse_manifest, runtime_from_config,
};

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// Reference values that the caller trusts by itself, for documents with
/// `attestation-collaterals/v3` collateral.
///
/// A supplied component replaces the endorsement and the renewal check of
/// that component only, and no endorsement is consulted for it even if the
/// document carries one. A component left as `None` keeps its normal
/// checks. Hardware authentication, the bindings between the components
/// and register pins stay mandatory. These values must come from trusted
/// client configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmbeddedReferences {
    /// The config that the enclave must run.
    pub config: Option<EmbeddedConfig>,
    /// The exact runtime manifest that the config pins.
    pub runtime: Option<Vec<u8>>,
    /// A platform policy artifact in the `platform-endorsements/v2` format.
    pub platform: Option<Vec<u8>>,
}

/// A config that the caller authorizes without a registry endorsement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedConfig {
    /// The exact config bytes. Their digest and the runtime that they pin
    /// are derived from them.
    Bytes {
        /// The config, 1 byte to 1 MiB.
        bytes: Vec<u8>,
        /// The `/org/project/revision` identity that the caller associates
        /// with the config. Without one, the config matches no repository
        /// pin.
        name: Option<String>,
    },
    /// A config known by its digest, with the runtime that it pins.
    Reference {
        /// The SHA-256 of the config, 64 lowercase hex digits.
        digest: String,
        /// The runtime release that the config pins.
        runtime: RuntimeReference,
        /// The `/org/project/revision` identity that the caller associates
        /// with the config. Without one, the config matches no repository
        /// pin.
        name: Option<String>,
    },
}

/// A caller-authorized config, reduced to what verification needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigReference {
    /// The versioned config name, when the caller gave one.
    pub(crate) name: Option<String>,
    /// The SHA-256 of the config, lowercase hex.
    pub(crate) digest: String,
    /// The runtime that the config pins.
    pub(crate) runtime: RuntimeReference,
}

/// A caller-supplied platform policy artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Platform {
    /// The decoded artifact.
    pub(crate) artifact: Artifact,
    /// The SHA-256 of the supplied bytes, lowercase hex.
    pub(crate) digest: String,
}

/// Checked embedded references, owned by a verifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Embedded {
    /// The caller-authorized config.
    pub(crate) config: Option<ConfigReference>,
    /// The runtime manifest bytes.
    pub(crate) runtime: Option<Vec<u8>>,
    /// The platform policy artifact.
    pub(crate) platform: Option<Platform>,
}

impl Embedded {
    /// Checks caller-supplied references and copies them.
    ///
    /// In order: at least one component is present; config bytes have 1 to
    /// [`MAX_CONFIG_SIZE`] bytes and pin a runtime; a config name is a
    /// versioned config name; the config digest is a SHA-256; the runtime
    /// pin is valid; a supplied manifest is the one that the config pins; a
    /// supplied manifest decodes; a supplied platform artifact decodes and
    /// has the v2 format. The error is a message for the caller.
    pub(crate) fn check(references: EmbeddedReferences) -> Result<Self, String> {
        let EmbeddedReferences {
            config,
            runtime,
            platform,
        } = references;
        if config.is_none() && runtime.is_none() && platform.is_none() {
            return Err("embedded references must contain at least one component".to_owned());
        }
        let config = match config {
            None => None,
            Some(EmbeddedConfig::Reference {
                digest,
                runtime,
                name,
            }) => Some(ConfigReference {
                name,
                digest,
                runtime,
            }),
            Some(EmbeddedConfig::Bytes { bytes, name }) => {
                if bytes.is_empty() || bytes.len() > MAX_CONFIG_SIZE {
                    return Err("embedded config size is outside allowed bounds".to_owned());
                }
                let runtime = runtime_from_config(&bytes).map_err(|cause| cause.to_string())?;
                Some(ConfigReference {
                    name,
                    digest: canonical::encode_lower_hex(&Sha256::digest(&bytes)),
                    runtime,
                })
            }
        };
        if let Some(reference) = &config {
            if let Some(name) = &reference.name {
                parse_name(name).map_err(|cause| cause.to_string())?;
            }
            canonical::decode_lower_hex("config digest", &reference.digest, SHA256_SIZE)
                .map_err(|cause| cause.to_string())?;
            reference
                .runtime
                .validate()
                .map_err(|cause| cause.to_string())?;
            // Both come from the caller, so a manifest that the config does
            // not pin is refused here and not at verification.
            if let Some(manifest) = &runtime {
                parse_manifest(manifest, &reference.runtime).map_err(|cause| cause.to_string())?;
            }
        }
        if let Some(manifest) = &runtime {
            decode_manifest(manifest).map_err(|cause| cause.to_string())?;
        }
        let platform = match platform {
            None => None,
            Some(bytes) => {
                let artifact = policy::parse(&bytes).map_err(|cause| cause.to_string())?;
                if artifact.format != ARTIFACT_FORMAT_V2 {
                    return Err("embedded platform requires platform-endorsements/v2".to_owned());
                }
                Some(Platform {
                    artifact,
                    digest: canonical::encode_lower_hex(&Sha256::digest(&bytes)),
                })
            }
        };
        Ok(Self {
            config,
            runtime,
            platform,
        })
    }
}
