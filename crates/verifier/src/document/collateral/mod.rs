//! The collateral entries that an attestation document carries, and their
//! strict decoding.
//!
//! Collateral is unendorsed transport: every entry is authenticated by its
//! own signature chain during verification, so a decoded entry is not trusted
//! and a tampered one can only cause a rejection.

mod config;
mod runtime;
mod sev;
mod sigstore;
mod tdx;

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use crate::canonical::CanonicalError;
use crate::json::decode::{self, DecodeError};
use crate::json::{Object, Value};

pub use config::ConfigEndorsement;
pub use runtime::{
    PLATFORM_ID, RUNTIME_ID, RUNTIME_REPO, RUNTIME_V1_FORMAT, Runtime, RuntimeReference,
};
pub use sev::{AmdCrl, AmdVcek};
pub use sigstore::{Freshness, SigstoreRef};
pub use tdx::{IntelPcs, PcsResponse};

/// Collateral format of the workload-release collateral: code and platform
/// bundles with their freshness witnesses.
pub const FORMAT_V2: &str = "https://tinfoil.sh/predicate/attestation-collaterals/v2";
/// Collateral format of the config, runtime and platform collateral.
pub const FORMAT_V3: &str = "https://tinfoil.sh/predicate/attestation-collaterals/v3";

/// Entry format carrying `{vcek_der_base64, cert_chain_pem}`.
pub const AMD_VCEK_V1_FORMAT: &str = "https://tinfoil.sh/collateral/amd-vcek/v1";
/// Entry format carrying `{crl_der_base64}`: the AMD certificate revocation
/// list for the product line.
pub const AMD_CRL_V1_FORMAT: &str = "https://tinfoil.sh/collateral/amd-crl/v1";
/// Entry format carrying captured Intel PCS responses.
pub const INTEL_PCS_V1_FORMAT: &str = "https://tinfoil.sh/collateral/intel-pcs/v1";
/// Entry format carrying NVIDIA certificate chains and reference material.
pub const NVIDIA_GPU_V1_FORMAT: &str = "https://tinfoil.sh/collateral/nvidia-gpu/v1";
/// Entry format carrying the code-provenance bundle
/// `{repo, tag, digest, sigstore_bundle}`.
pub const SIGSTORE_CODE_V1_FORMAT: &str = "https://tinfoil.sh/collateral/sigstore-code/v1";
/// Entry format carrying the platform-endorsements bundle
/// `{repo, tag, digest, sigstore_bundle}`.
pub const SIGSTORE_PLATFORM_V1_FORMAT: &str = "https://tinfoil.sh/collateral/sigstore-platform/v1";
/// Entry format carrying a freshness witness for a Sigstore reference-values
/// artifact.
pub const SIGSTORE_FRESHNESS_V1_FORMAT: &str =
    "https://tinfoil.sh/collateral/sigstore-freshness/v1";
/// Entry format carrying a signed release approval.
pub const ARTIFACT_FRESHNESS_V1_FORMAT: &str =
    "https://tinfoil.sh/collateral/artifact-freshness/v1";
/// Entry format carrying an exact config and its timestamped registry
/// approval bundle.
pub const CONFIG_ENDORSEMENT_V1_FORMAT: &str =
    "https://tinfoil.sh/collateral/config-endorsement/v1";
/// Entry format carrying a registry approval bundle, optionally with the
/// config bytes and the issuer certificate.
pub const CONFIG_ENDORSEMENT_V2_FORMAT: &str =
    "https://tinfoil.sh/collateral/config-endorsement/v2";
/// Entry format carrying exact config bytes that the caller's policy must
/// authorize.
pub const CONFIG_V1_FORMAT: &str = "https://tinfoil.sh/collateral/config/v1";

/// Role of hardware-vendor material used to verify evidence
/// cryptographically.
pub const ROLE_ENDORSEMENT: &str = "endorsement";
/// Role of signed expectations used to appraise verified evidence.
pub const ROLE_REFERENCE_VALUES: &str = "reference-values";

/// The reserved collateral subject of the CPU quote.
pub const SUBJECT_CPU: &str = "cpu";
/// Entry id of the freshness witness for the code bundle.
pub const FRESHNESS_ID_CODE: &str = "code-freshness";
/// Entry id of the freshness witness for the platform bundle.
pub const FRESHNESS_ID_PLATFORM: &str = "platform-freshness";
/// Entry id of the freshness witness for the runtime bundle.
pub const FRESHNESS_ID_RUNTIME: &str = "runtime-freshness";
/// Entry id of the config entry.
pub const CONFIG_ID: &str = "tinfoil-config";

/// Why collateral could not be decoded or returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollateralError {
    /// The document carries no entry for the requested purpose. Malformed
    /// collateral never reaches the accessors, because decoding rejects it.
    NotFound(String),
    /// The collateral is malformed or contradicts itself.
    Invalid(String),
}

impl CollateralError {
    /// Whether the error reports a missing entry, as opposed to a bad one.
    pub fn is_not_found(&self) -> bool {
        matches!(self, CollateralError::NotFound(_))
    }

    fn invalid(message: impl Into<String>) -> Self {
        CollateralError::Invalid(message.into())
    }

    /// A known entry whose data does not decode.
    fn parsing(label: &str, id: &str, error: &DecodeError) -> Self {
        Self::invalid(format!("parsing {label} collateral entry {id:?}: {error}"))
    }
}

impl fmt::Display for CollateralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CollateralError::NotFound(what) => write!(f, "collateral entry not found: {what}"),
            CollateralError::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CollateralError {}

impl From<CanonicalError> for CollateralError {
    fn from(error: CanonicalError) -> Self {
        Self::invalid(error.to_string())
    }
}

/// One self-describing collateral record, as it appears in a document.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Entry {
    /// The entry's id, unique within a document.
    pub id: String,
    /// [`ROLE_ENDORSEMENT`] or [`ROLE_REFERENCE_VALUES`].
    pub role: String,
    /// The format that determines how `data` is read.
    pub format: String,
    /// What the entry is about, such as [`SUBJECT_CPU`].
    pub subjects: Vec<String>,
    /// The payload. An entry needs one, and it must be a JSON object:
    /// `None` records that the document leaves it out, and such an entry
    /// is rejected when the document's collateral is checked.
    pub data: Option<Value>,
}

impl Entry {
    /// Decodes one element of a document's `collateral` array. `null` is an
    /// entry with every field empty.
    pub fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut entry = Entry::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(entry);
        };
        for (name, value) in object.into_members() {
            match name.as_str() {
                "id" => entry.id = decode::string(value, "id")?,
                "role" => entry.role = decode::string(value, "role")?,
                "format" => entry.format = decode::string(value, "format")?,
                "subjects" => {
                    entry.subjects = decode::strings(value, "subjects")?.unwrap_or_default();
                }
                "data" => entry.data = Some(value),
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(entry)
    }
}

/// An entry that passed the shape checks: its data is an object.
struct CheckedEntry {
    id: String,
    role: String,
    format: String,
    subjects: Vec<String>,
    data: Object,
}

/// The vendor collateral that chains CPU evidence to its vendor root. `None`
/// means that there is no such collateral; which fields are required depends
/// on the evidence format, and authenticating the evidence rejects a missing
/// one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CpuEndorsements {
    /// The AMD chip certificate and its chain.
    pub amd_vcek: Option<AmdVcek>,
    /// The AMD certificate revocation list.
    pub amd_crl: Option<AmdCrl>,
    /// The captured Intel PCS responses.
    pub intel_pcs: Option<IntelPcs>,
}

/// Decoded collateral: for each purpose that the verifier knows, the first
/// entry serving it. `None` means that no entry serves that purpose.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Set {
    /// The endorsement collateral for [`SUBJECT_CPU`], of every platform.
    pub cpu: CpuEndorsements,
    /// The code-provenance reference.
    pub sigstore_code: Option<SigstoreRef>,
    /// The platform-endorsements reference.
    pub sigstore_platform: Option<SigstoreRef>,
    /// The config entry.
    pub config: Option<ConfigEndorsement>,
    /// The runtime entry.
    pub runtime: Option<Runtime>,
    /// The freshness witnesses by entry id.
    pub freshness: BTreeMap<String, Freshness>,
    /// How many entries claim the platform id or the platform format.
    platform_count: usize,
    /// Whether a platform reference carries the reserved platform id.
    has_config_platform: bool,
}

impl Set {
    /// The platform reference for config verification, which must be the
    /// only platform entry and carry the reserved id.
    pub fn config_platform(&self) -> Result<&SigstoreRef, CollateralError> {
        if self.platform_count == 0 {
            return Err(CollateralError::NotFound(
                "no platform reference-values entry".to_owned(),
            ));
        }
        // With exactly one platform entry, the reference under the reserved
        // id is also the first one.
        match &self.sigstore_platform {
            Some(platform) if self.platform_count == 1 && self.has_config_platform => Ok(platform),
            _ => Err(CollateralError::invalid(
                "conflicting platform collateral for config verification",
            )),
        }
    }
}

/// Checks the shape of the entries and decodes every entry of a known role
/// and format, so that a malformed entry fails whether or not verification
/// would read it.
///
/// An entry whose role and format have no decoder (an unknown format, or a
/// known format under another role) is checked for shape only and not kept.
/// Config and runtime entries require their reserved ids, formats and roles.
/// An endorsement entry serves the CPU only when its subjects include
/// [`SUBJECT_CPU`].
pub fn decode(entries: Vec<Entry>) -> Result<Set, CollateralError> {
    let mut set = Set::default();
    for entry in validate(entries)? {
        let cpu = entry.subjects.iter().any(|subject| subject == SUBJECT_CPU);
        let (id, role, format) = (
            entry.id.as_str(),
            entry.role.as_str(),
            entry.format.as_str(),
        );
        if id == PLATFORM_ID || format == SIGSTORE_PLATFORM_V1_FORMAT {
            set.platform_count = set.platform_count.saturating_add(1);
        }
        let is_config_format = format == CONFIG_ENDORSEMENT_V1_FORMAT
            || format == CONFIG_ENDORSEMENT_V2_FORMAT
            || format == CONFIG_V1_FORMAT;

        if id == CONFIG_ID || is_config_format {
            if id != CONFIG_ID || !is_config_format || role != ROLE_REFERENCE_VALUES {
                return Err(CollateralError::invalid(format!(
                    "conflicting collateral entry for {CONFIG_ID:?}"
                )));
            }
            set.config = Some(config::decode(entry)?);
        } else if id == RUNTIME_ID || format == RUNTIME_V1_FORMAT {
            if id != RUNTIME_ID || format != RUNTIME_V1_FORMAT || role != ROLE_REFERENCE_VALUES {
                return Err(CollateralError::invalid(format!(
                    "conflicting collateral entry for {RUNTIME_ID:?}"
                )));
            }
            set.runtime = Some(runtime::decode(entry)?);
        } else if format == ARTIFACT_FRESHNESS_V1_FORMAT || id == FRESHNESS_ID_RUNTIME {
            if (id != FRESHNESS_ID_PLATFORM && id != FRESHNESS_ID_RUNTIME)
                || format != ARTIFACT_FRESHNESS_V1_FORMAT
                || role != ROLE_REFERENCE_VALUES
            {
                return Err(CollateralError::invalid(format!(
                    "conflicting artifact freshness collateral {id:?}"
                )));
            }
            let (id, witness) = sigstore::decode_freshness(entry)?;
            set.freshness.insert(id, witness);
        } else if role == ROLE_ENDORSEMENT && format == AMD_VCEK_V1_FORMAT {
            let vcek = sev::decode_vcek(entry)?;
            if cpu && set.cpu.amd_vcek.is_none() {
                set.cpu.amd_vcek = Some(vcek);
            }
        } else if role == ROLE_ENDORSEMENT && format == AMD_CRL_V1_FORMAT {
            let crl = sev::decode_crl(entry)?;
            if cpu && set.cpu.amd_crl.is_none() {
                set.cpu.amd_crl = Some(crl);
            }
        } else if role == ROLE_ENDORSEMENT && format == INTEL_PCS_V1_FORMAT {
            let pcs = tdx::decode(entry)?;
            if cpu && set.cpu.intel_pcs.is_none() {
                set.cpu.intel_pcs = Some(pcs);
            }
        } else if role == ROLE_REFERENCE_VALUES && format == SIGSTORE_CODE_V1_FORMAT {
            let reference = sigstore::decode_ref(entry)?;
            if set.sigstore_code.is_none() {
                set.sigstore_code = Some(reference);
            }
        } else if role == ROLE_REFERENCE_VALUES && format == SIGSTORE_PLATFORM_V1_FORMAT {
            if id == PLATFORM_ID {
                set.has_config_platform = true;
            }
            let reference = sigstore::decode_ref(entry)?;
            if set.sigstore_platform.is_none() {
                set.sigstore_platform = Some(reference);
            }
        } else if role == ROLE_REFERENCE_VALUES && format == SIGSTORE_FRESHNESS_V1_FORMAT {
            // Entry ids are unique, so no witness is replaced.
            let (id, witness) = sigstore::decode_freshness(entry)?;
            set.freshness.insert(id, witness);
        }
    }
    Ok(set)
}

/// Checks every entry's shape, in order: an id and a format, a unique id, a
/// known role, and data that is a JSON object.
fn validate(entries: Vec<Entry>) -> Result<Vec<CheckedEntry>, CollateralError> {
    let mut seen = HashSet::with_capacity(entries.len());
    let mut checked = Vec::with_capacity(entries.len());
    for (index, entry) in entries.into_iter().enumerate() {
        let Entry {
            id,
            role,
            format,
            subjects,
            data,
        } = entry;
        if id.is_empty() || format.is_empty() {
            return Err(CollateralError::invalid(format!(
                "collateral entry {index} is incomplete"
            )));
        }
        if !seen.insert(id.clone()) {
            return Err(CollateralError::invalid(format!(
                "duplicate collateral entry id {id:?}"
            )));
        }
        if role != ROLE_ENDORSEMENT && role != ROLE_REFERENCE_VALUES {
            return Err(CollateralError::invalid(format!(
                "collateral entry {id:?} has unknown role {role:?}"
            )));
        }
        // Only known formats are decoded, so the data of every entry is
        // checked here.
        let data = match data.map(|data| decode::object(data, "data")) {
            Some(Ok(Some(data))) => data,
            _ => {
                return Err(CollateralError::invalid(format!(
                    "collateral entry {id:?} data is not a valid JSON object"
                )));
            }
        };
        checked.push(CheckedEntry {
            id,
            role,
            format,
            subjects,
            data,
        });
    }
    Ok(checked)
}

/// Whether a bundle member holds something to verify: it is present and not
/// `null`. Whether a present bundle verifies is for provenance to judge.
fn present(bundle: Option<Value>) -> Option<Value> {
    bundle.filter(|bundle| !bundle.is_null())
}

/// Whether a bundle member is a JSON object.
fn object_bundle(bundle: Option<Value>) -> Option<Value> {
    bundle.filter(|bundle| bundle.as_object().is_some())
}

#[cfg(test)]
pub(crate) mod tests;
