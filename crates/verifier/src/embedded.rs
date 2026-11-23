//! Reference values that the caller supplies in place of endorsements.

use sha2::{Digest, Sha256};

use crate::canonical;
use crate::endorsement::approval::parse_name;
use crate::policy::{self, ARTIFACT_FORMAT_V2, Artifact};
use crate::runtime::{
    self, MAX_CONFIG_SIZE, container_provenance_from_config, decode_manifest, parse_manifest,
    runtime_from_config,
};

/// The size of a SHA-256 digest in bytes.
const SHA256_SIZE: usize = 32;

/// An immutable pin of one runtime release: what a config's `cvm-version`
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReference {
    /// The repository of the runtime, `tinfoilsh/cvmimage`.
    pub repo: String,
    /// The release tag: a full semantic version with a leading `v`, such as
    /// `v0.15.0`.
    pub tag: String,
    /// The SHA-256 of the runtime manifest, 64 lowercase hex digits.
    pub digest: String,
}

/// A config that the caller supplies itself, in place of a registry
/// endorsement: [`ConfigTrust::Embedded`](crate::ConfigTrust::Embedded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedConfig {
    /// The exact config bytes. Their digest and the runtime that they pin
    /// are derived from them. The document must still prove every
    /// container build that the config requires.
    Bytes {
        /// The config, 1 byte to 1 MiB.
        bytes: Vec<u8>,
        /// The `/org/project/revision` identity that the caller associates
        /// with the config. Without one, the config matches no repository
        /// pin.
        name: Option<String>,
    },
    /// A config known by its digest, with the runtime that it pins. The
    /// container builds that the config requires are checked only when the
    /// document carries the config bytes.
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
    pub(crate) runtime: runtime::RuntimeReference,
    /// The bytes of a config that the caller embedded in full. A config
    /// embedded by reference has none.
    pub(crate) bytes: Option<Vec<u8>>,
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
    /// In order: a supplied manifest decodes; a supplied platform artifact
    /// decodes and has the v2 format; config bytes have 1 to
    /// [`MAX_CONFIG_SIZE`] bytes, pin a runtime and state container build
    /// requirements that can be read; a config name is a versioned config
    /// name; the config digest is a SHA-256; the runtime pin is valid; a
    /// supplied manifest is the one that the config pins. The error is a
    /// message for the caller.
    pub(crate) fn check(
        config: Option<EmbeddedConfig>,
        runtime: Option<Vec<u8>>,
        platform: Option<Vec<u8>>,
    ) -> Result<Self, String> {
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
        let config = match config {
            None => None,
            Some(EmbeddedConfig::Reference {
                digest,
                runtime,
                name,
            }) => Some(ConfigReference {
                name,
                digest,
                runtime: runtime::RuntimeReference {
                    repo: runtime.repo,
                    tag: runtime.tag,
                    digest: runtime.digest,
                },
                bytes: None,
            }),
            Some(EmbeddedConfig::Bytes { bytes, name }) => {
                if bytes.is_empty() || bytes.len() > MAX_CONFIG_SIZE {
                    return Err("embedded config size is outside allowed bounds".to_owned());
                }
                let runtime = runtime_from_config(&bytes).map_err(|cause| cause.to_string())?;
                container_provenance_from_config(&bytes).map_err(|cause| cause.to_string())?;
                Some(ConfigReference {
                    name,
                    digest: canonical::encode_lower_hex(&Sha256::digest(&bytes)),
                    runtime,
                    bytes: Some(bytes),
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
        Ok(Self {
            config,
            runtime,
            platform,
        })
    }
}
