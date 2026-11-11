//! What reference values resolve for a quote, and how caller pins and
//! release measurements combine.

use super::{AssemblyError, Authenticated};
use crate::measurement::{Expected, Measurement};
use crate::policy::{Artifact, Policy};
use crate::stub::pending;

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
    pending("quote::resolve::resolve_policy")
}

/// Combines the registers that the release fixes with the caller's pins.
///
/// Without pins, the result is `code`. With pins: the pins are for the
/// same platform as `code`, or it is an error; a register that the code
/// leaves open takes the pin; a register that both fix must be equal in
/// both, or it is an error that names the register.
pub fn apply_pins(code: &Expected, pins: Option<&Expected>) -> Result<Expected, AssemblyError> {
    pending("quote::resolve::apply_pins")
}

/// The measurement that `expected` requires. An error that names every
/// register that is still open: assembly never leaves a register unchecked.
pub fn complete(expected: &Expected) -> Result<Measurement, AssemblyError> {
    pending("quote::resolve::complete")
}
