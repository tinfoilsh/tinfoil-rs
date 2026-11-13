//! The policy artifact document and the lookups on it.

use std::collections::BTreeMap;

use super::{
    ARTIFACT_FORMAT, ARTIFACT_FORMAT_V2, PLATFORM_SEV_SNP, PLATFORM_TDX, PolicyError, SevSnpPolicy,
    Shape, Stack, TdxPolicy, map, satisfies, truncated, validate_policy_hex,
};
use crate::canonical;
use crate::json::decode::{self, DecodeError};
use crate::json::{self, Value};

/// Hex digits in an SEV-SNP machine identifier, the 64-byte CHIP_ID.
const SEV_IDENTIFIER_HEX_LEN: usize = 128;
/// Hex digits in a TDX machine identifier, the 16-byte PPID.
const TDX_IDENTIFIER_HEX_LEN: usize = 32;
/// The size of an MRTD or RTMR register in bytes.
const REGISTER_SIZE: usize = 48;

/// A parsed policy artifact: named platform measurements, named policies,
/// and the machines that key both by hardware identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Artifact {
    /// [`ARTIFACT_FORMAT`] or [`ARTIFACT_FORMAT_V2`].
    pub format: String,
    /// TDX platform measurements by name. Empty in a v2 artifact.
    pub measurements: BTreeMap<String, PlatformMeasurement>,
    /// The policy name of each endorsed machine, by hardware identifier:
    /// the CHIP_ID of an SEV-SNP machine (128 lowercase hex digits) or the
    /// PPID of a TDX machine (32 lowercase hex digits).
    pub machines: BTreeMap<String, String>,
    /// Appraisal policies by name.
    pub policies: BTreeMap<String, Policy>,
}

/// The expected registers of one TDX platform configuration, with the VM
/// shape that it was measured for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlatformMeasurement {
    /// The expected MRTD: 48 bytes, lowercase hex.
    pub mrtd: String,
    /// The expected RTMR0: 48 bytes, lowercase hex.
    pub rtmr0: String,
    /// The VM shape. Always present in a parsed artifact.
    pub shape: Option<Shape>,
    /// The host stack that produced the measurement. Informational; never
    /// checked.
    pub stack: Option<Stack>,
}

/// A named appraisal policy for one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// A policy for AMD SEV-SNP machines.
    SevSnp(SevSnpPolicy),
    /// A policy for Intel TDX machines.
    Tdx(TdxPolicy),
}

impl Policy {
    /// [`PLATFORM_SEV_SNP`] or [`PLATFORM_TDX`].
    pub fn platform(&self) -> &'static str {
        match self {
            Policy::SevSnp(_) => PLATFORM_SEV_SNP,
            Policy::Tdx(_) => PLATFORM_TDX,
        }
    }

    /// The SEV-SNP block, if the policy is for that platform.
    pub fn as_sev_snp(&self) -> Option<&SevSnpPolicy> {
        match self {
            Policy::SevSnp(policy) => Some(policy),
            Policy::Tdx(_) => None,
        }
    }

    /// The TDX block, if the policy is for that platform.
    pub fn as_tdx(&self) -> Option<&TdxPolicy> {
        match self {
            Policy::Tdx(policy) => Some(policy),
            Policy::SevSnp(_) => None,
        }
    }
}

/// A policy as the document spells it: a platform label and up to two
/// platform blocks. Validation requires exactly the block that the label
/// names.
#[derive(Default)]
struct DecodedPolicy {
    platform: String,
    sev_snp: Option<SevSnpPolicy>,
    tdx: Option<TdxPolicy>,
}

impl DecodedPolicy {
    /// Decodes one policy; `null` is a policy with nothing set.
    fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut policy = DecodedPolicy::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(policy);
        };
        for (name, value) in object.into_members() {
            match name.as_str() {
                "platform" => policy.platform = decode::string(value, &name)?,
                "sev_snp" => policy.sev_snp = SevSnpPolicy::from_value(value, &name)?,
                "tdx" => policy.tdx = TdxPolicy::from_value(value, &name)?,
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(policy)
    }

    /// Selects the block that the platform label names. The other block
    /// must be absent.
    fn into_policy(self, name: &str) -> Result<Policy, PolicyError> {
        match (self.platform.as_str(), self.sev_snp, self.tdx) {
            (PLATFORM_SEV_SNP, Some(policy), None) => Ok(Policy::SevSnp(policy)),
            (PLATFORM_SEV_SNP, _, _) => Err(PolicyError::new(format!(
                "policy {name:?}: platform sev-snp requires exactly the sev_snp block"
            ))),
            (PLATFORM_TDX, None, Some(policy)) => Ok(Policy::Tdx(policy)),
            (PLATFORM_TDX, _, _) => Err(PolicyError::new(format!(
                "policy {name:?}: platform tdx requires exactly the tdx block"
            ))),
            (platform, _, _) => Err(PolicyError::new(format!(
                "policy {name:?}: unsupported platform {platform:?}"
            ))),
        }
    }
}

impl PlatformMeasurement {
    /// Decodes one measurement; `null` is a measurement with nothing set.
    fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut measurement = PlatformMeasurement::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(measurement);
        };
        for (name, value) in object.into_members() {
            match name.as_str() {
                "mrtd" => measurement.mrtd = decode::string(value, &name)?,
                "rtmr0" => measurement.rtmr0 = decode::string(value, &name)?,
                "shape" => measurement.shape = Shape::from_value(value, &name)?,
                "stack" => measurement.stack = Stack::from_value(value, &name)?,
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(measurement)
    }

    /// Checks the shape and both registers of the measurement called `name`.
    fn validate(&self, name: &str) -> Result<(), PolicyError> {
        let context = || format!("measurement {name:?}");
        let Some(shape) = &self.shape else {
            return Err(PolicyError::new("shape is required").within(context()));
        };
        if shape.cpus <= 0 || shape.memory_mb <= 0 || shape.disks <= 0 {
            return Err(
                PolicyError::new("cpus, memory_mb, and disks must be positive").within(context()),
            );
        }
        if shape.gpus.is_some_and(|gpus| gpus < 0) {
            return Err(PolicyError::new("gpus must be non-negative").within(context()));
        }
        validate_policy_hex("mrtd", &self.mrtd, REGISTER_SIZE)
            .map_err(|error| error.within(context()))?;
        validate_policy_hex("rtmr0", &self.rtmr0, REGISTER_SIZE)
            .map_err(|error| error.within(context()))
    }
}

/// Strictly decodes and validates a policy artifact.
///
/// An unknown member anywhere in the document is rejected, with names
/// compared exactly, and so is a repeated member name. A `null` member is
/// read as an absent one.
pub fn parse(data: &[u8]) -> Result<Artifact, PolicyError> {
    parse_value(json::parse(data)?)
}

/// Decodes and validates a policy artifact from parsed JSON, by the rules of
/// [`parse`].
///
/// A parsed value keeps every number as its literal, so this reads exactly
/// what [`parse`] would read from the text that the value came from. It is
/// how an artifact is read out of a signed statement's predicate.
pub fn parse_value(value: Value) -> Result<Artifact, PolicyError> {
    let mut format = String::new();
    let mut measurements = BTreeMap::new();
    let mut machines = BTreeMap::new();
    let mut decoded_policies = BTreeMap::new();
    let document = decode::object(value, "policy artifact")?;
    for (name, value) in document.map(json::Object::into_members).unwrap_or_default() {
        match name.as_str() {
            "format" => format = decode::string(value, &name)?,
            "measurements" => {
                measurements = map(value, &name, PlatformMeasurement::from_value)?;
            }
            "machines" => machines = map(value, &name, decode::string)?,
            "policies" => decoded_policies = map(value, &name, DecodedPolicy::from_value)?,
            _ => return Err(decode::unknown_member("policy artifact", &name).into()),
        }
    }
    if format != ARTIFACT_FORMAT && format != ARTIFACT_FORMAT_V2 {
        return Err(PolicyError::new(format!(
            "unsupported artifact format {format:?}"
        )));
    }
    let with_measurements = format == ARTIFACT_FORMAT;
    if !with_measurements && !measurements.is_empty() {
        return Err(PolicyError::new(
            "platform endorsement v2 excludes workload measurements",
        ));
    }

    let mut policies = BTreeMap::new();
    for (name, decoded) in decoded_policies {
        let policy = decoded.into_policy(&name)?;
        validate_policy(&policy, with_measurements, &measurements)
            .map_err(|error| error.within(format_args!("policy {name:?}")))?;
        policies.insert(name, policy);
    }
    for (name, measurement) in &measurements {
        measurement.validate(name)?;
    }
    for (identifier, policy_name) in &machines {
        validate_machine(identifier, policy_name, &policies)
            .map_err(|error| error.within(format_args!("machine {}...", truncated(identifier))))?;
    }
    Ok(Artifact {
        format,
        measurements,
        machines,
        policies,
    })
}

/// Checks one policy against the artifact format: the workload-specific
/// members are required when the format carries measurements and excluded
/// when it does not.
fn validate_policy(
    policy: &Policy,
    with_measurements: bool,
    measurements: &BTreeMap<String, PlatformMeasurement>,
) -> Result<(), PolicyError> {
    match policy {
        Policy::SevSnp(sev_snp) => {
            if with_measurements == sev_snp.host_data.is_empty() {
                return Err(PolicyError::new(
                    "host_data is required in v1 and excluded in v2",
                ));
            }
            sev_snp.validate()
        }
        Policy::Tdx(tdx) => {
            if with_measurements == tdx.platform_measurements.is_empty() {
                return Err(PolicyError::new(
                    "platform_measurements are required in v1 and excluded in v2",
                ));
            }
            tdx.validate()?;
            match tdx
                .platform_measurements
                .iter()
                .find(|reference| !measurements.contains_key(*reference))
            {
                Some(reference) => Err(PolicyError::new(format!(
                    "platform_measurements ref {reference:?} not in measurements"
                ))),
                None => Ok(()),
            }
        }
    }
}

/// Checks one machine: its policy exists, and its identifier is lowercase
/// hex of the length that the policy's platform uses.
fn validate_machine(
    identifier: &str,
    policy_name: &str,
    policies: &BTreeMap<String, Policy>,
) -> Result<(), PolicyError> {
    let Some(policy) = policies.get(policy_name) else {
        return Err(PolicyError::new(format!("unknown policy {policy_name:?}")));
    };
    if identifier.is_empty() || !canonical::is_lower_hex(identifier) {
        return Err(PolicyError::new("identifier is not lowercase hex"));
    }
    let (label, want) = match policy {
        Policy::SevSnp(_) => (PLATFORM_SEV_SNP, SEV_IDENTIFIER_HEX_LEN),
        Policy::Tdx(_) => (PLATFORM_TDX, TDX_IDENTIFIER_HEX_LEN),
    };
    if identifier.len() != want {
        return Err(PolicyError::new(format!(
            "{label} identifier must be {want} hex chars, got {}",
            identifier.len()
        )));
    }
    Ok(())
}

impl Artifact {
    /// Looks up the appraisal policy of a machine and returns it with its
    /// name.
    ///
    /// `identifier_hex` is the platform identifier, in lowercase hex, taken
    /// from authenticated evidence, and `platform` is the platform of that
    /// evidence, which the policy must be for. An identifier that the
    /// artifact does not list is an error: the machine is not endorsed.
    pub fn policy_for(
        &self,
        identifier_hex: &str,
        platform: &str,
    ) -> Result<(&str, &Policy), PolicyError> {
        let Some(name) = self.machines.get(identifier_hex) else {
            return Err(PolicyError::new(format!(
                "platform identifier {}... is not endorsed",
                truncated(identifier_hex)
            )));
        };
        let policy = self.policies.get(name);
        let policy_platform = policy.map_or("", Policy::platform);
        match policy {
            Some(policy) if policy_platform == platform => Ok((name, policy)),
            _ => Err(PolicyError::new(format!(
                "policy {name:?} is for platform {policy_platform:?}, evidence is {platform:?}"
            ))),
        }
    }

    /// Selects the one measurement entry that `policy` allows whose MRTD and
    /// RTMR0 equal the given values, and returns it with its name.
    ///
    /// Only entries measured for the `required` VM shape are candidates, so
    /// a quote from an endorsed machine that runs a VM of another shape
    /// resolves nothing. `mrtd_hex` and `rtmr0_hex` must come from a
    /// verified quote.
    pub fn resolve_platform_measurement(
        &self,
        policy: &TdxPolicy,
        required: Option<&Shape>,
        mrtd_hex: &str,
        rtmr0_hex: &str,
    ) -> Result<(&str, &PlatformMeasurement), PolicyError> {
        let Some(required) = required else {
            return Err(PolicyError::new("required VM shape is missing"));
        };
        let mut any_shape_match = false;
        for reference in &policy.platform_measurements {
            let Some((name, measurement)) = self.measurements.get_key_value(reference) else {
                continue;
            };
            if !satisfies(measurement.shape.as_ref(), Some(required)) {
                continue;
            }
            any_shape_match = true;
            if measurement.mrtd == mrtd_hex && measurement.rtmr0 == rtmr0_hex {
                return Ok((name, measurement));
            }
        }
        if !any_shape_match {
            return Err(PolicyError::new(format!(
                "no endorsed platform measurement matches the required VM shape {required}"
            )));
        }
        Err(PolicyError::new(format!(
            "platform measurements (mrtd {}...) do not match any allowed configuration",
            truncated(mrtd_hex)
        )))
    }
}
