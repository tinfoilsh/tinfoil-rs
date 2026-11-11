//! What reference values resolve for a quote, and how caller pins and
//! release measurements combine.

use super::{AssemblyError, Authenticated};
use crate::measurement::{Expected, Measurement, Register};
use crate::policy::{Artifact, PLATFORM_SEV_SNP, PLATFORM_TDX, Policy};

/// The size of the TDX MR_CONFIG_ID field in bytes.
pub const MR_CONFIG_ID_SIZE: usize = 48;

/// Everything that reference values resolve for one quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValues<'a> {
    /// The policy that the machine must satisfy.
    pub policy: &'a Policy,
    /// The name of that policy in the artifact.
    pub policy_name: String,
    /// The name of the resolved TDX platform measurement, when one was
    /// resolved.
    pub platform_measurement_name: Option<String>,
    /// The registers that the release fixes.
    pub code: Expected,
    /// The registers that the quote must show: the release's, with the
    /// caller's pins and, for the repository-release contract on TDX, the
    /// platform registers.
    pub expected: Expected,
    /// The SEV-SNP HOST_DATA that the quote must show, as lowercase hex;
    /// empty when the contract leaves it to the policy and the policy has
    /// none.
    pub host_data: String,
    /// The TDX MR_CONFIG_ID that the quote must show.
    pub config_id: [u8; MR_CONFIG_ID_SIZE],
}

/// Looks up the policy of the quote's machine in a policy artifact
/// ([`Artifact::policy_for`]) by the quote's identity and platform. A
/// machine that the artifact does not endorse is an error.
pub fn resolve_policy<'a>(
    endorsements: &'a Artifact,
    quote: &Authenticated,
) -> Result<(&'a str, &'a Policy), AssemblyError> {
    Ok(endorsements.policy_for(quote.identity(), quote.platform())?)
}

/// The platform label of a set of expected registers.
fn platform_of(expected: &Expected) -> &'static str {
    match expected {
        Expected::SevSnp { .. } => PLATFORM_SEV_SNP,
        Expected::Tdx { .. } => PLATFORM_TDX,
    }
}

/// One register of the merged expectation: the pin where the code leaves
/// the register open, the code's value otherwise. A pin that differs from
/// a value that the code fixes is recorded in `conflict`, which keeps the
/// first register that disagreed.
fn fill(
    name: &'static str,
    fixed: Option<Register>,
    pin: Option<Register>,
    conflict: &mut Option<&'static str>,
) -> Option<Register> {
    match (fixed, pin) {
        (fixed, None) => fixed,
        (None, pin) => pin,
        (Some(fixed), Some(pin)) => {
            if fixed != pin && conflict.is_none() {
                *conflict = Some(name);
            }
            Some(fixed)
        }
    }
}

/// Combines the registers that the release fixes with the caller's pins.
///
/// Without pins, the result is `code`. With pins: the pins are for the
/// same platform as `code`, or it is an error; a register that the code
/// leaves open takes the pin; a register that both fix must be equal in
/// both, or it is an error that names the register.
pub fn apply_pins(code: &Expected, pins: Option<&Expected>) -> Result<Expected, AssemblyError> {
    let Some(pins) = pins else {
        return Ok(code.clone());
    };
    let mut conflict = None;
    let merged = match (pins, code) {
        (Expected::SevSnp { launch: pin }, Expected::SevSnp { launch }) => Expected::SevSnp {
            launch: fill("launch measurement", *launch, *pin, &mut conflict),
        },
        (
            Expected::Tdx {
                mrtd: pin_mrtd,
                rtmr0: pin_rtmr0,
                rtmr1: pin_rtmr1,
                rtmr2: pin_rtmr2,
                rtmr3: pin_rtmr3,
            },
            Expected::Tdx {
                mrtd,
                rtmr0,
                rtmr1,
                rtmr2,
                rtmr3,
            },
        ) => Expected::Tdx {
            mrtd: fill("MRTD", *mrtd, *pin_mrtd, &mut conflict),
            rtmr0: fill("RTMR0", *rtmr0, *pin_rtmr0, &mut conflict),
            rtmr1: fill("RTMR1", *rtmr1, *pin_rtmr1, &mut conflict),
            rtmr2: fill("RTMR2", *rtmr2, *pin_rtmr2, &mut conflict),
            rtmr3: fill("RTMR3", *rtmr3, *pin_rtmr3, &mut conflict),
        },
        (pins, code) => {
            return Err(AssemblyError::new(format!(
                "pinned registers are for {}, but the enclave is {}",
                platform_of(pins),
                platform_of(code)
            )));
        }
    };
    match conflict {
        Some(name) => Err(AssemblyError::new(format!(
            "pinned {name} does not match the signed release measurement"
        ))),
        None => Ok(merged),
    }
}

/// The measurement that `expected` requires. An error that names every
/// register that is still open: assembly never leaves a register unchecked.
pub fn complete(expected: &Expected) -> Result<Measurement, AssemblyError> {
    let mut missing: Vec<&str> = Vec::new();
    let mut get = |name: &'static str, register: &Option<Register>| {
        register.unwrap_or_else(|| {
            missing.push(name);
            Register::new([0; crate::measurement::REGISTER_SIZE])
        })
    };
    let measurement = match expected {
        Expected::SevSnp { launch } => Measurement::SevSnp {
            launch: get("launch measurement", launch),
        },
        Expected::Tdx {
            mrtd,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
        } => Measurement::Tdx {
            mrtd: get("MRTD", mrtd),
            rtmr0: get("RTMR0", rtmr0),
            rtmr1: get("RTMR1", rtmr1),
            rtmr2: get("RTMR2", rtmr2),
            rtmr3: get("RTMR3", rtmr3),
        },
    };
    if missing.is_empty() {
        Ok(measurement)
    } else {
        Err(AssemblyError::new(format!(
            "nothing fixes the expected {}",
            missing.join(", ")
        )))
    }
}

/// Parses a register of authenticated reference values, with `label` in
/// front of the error.
pub(super) fn register(
    label: impl std::fmt::Display,
    value: &str,
) -> Result<Register, AssemblyError> {
    crate::measurement::parse_register(value)
        .map_err(|message| AssemblyError::new(format!("{label}: {message}")))
}
