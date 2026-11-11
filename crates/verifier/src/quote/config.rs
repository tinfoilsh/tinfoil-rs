//! Reference values of the endorsed-config contract.

use super::resolve::ResolvedValues;
use super::{AssemblyError, Authenticated};
use crate::measurement::Expected;
use crate::policy::Artifact;
use crate::runtime::Measurements;
use crate::stub::pending;

/// Reference values of the endorsed-config contract: a platform policy
/// artifact, the measurements of the runtime that the config pins, and the
/// hash that binds the config into the quote.
#[derive(Debug, Clone)]
pub struct ConfigReferenceValues<'a> {
    /// The platform policy artifact.
    pub endorsements: &'a Artifact,
    /// The launch measurements of the runtime.
    pub runtime: &'a Measurements,
    /// The SHA-256 of the config.
    pub hash: [u8; 32],
}

impl<'a> ConfigReferenceValues<'a> {
    /// Resolves the policy and the expected registers for a quote.
    ///
    /// In order: the machine's policy is looked up
    /// ([`resolve_policy`](super::resolve::resolve_policy)). Then by
    /// platform:
    ///
    /// - SEV-SNP: the policy must set no host data of its own; the
    ///   expected HOST_DATA is the config hash, and the code measurement is
    ///   the runtime's SEV-SNP launch measurement;
    /// - TDX: the policy must list no platform measurements; the expected
    ///   MR_CONFIG_ID is the config hash followed by zeros, and the code
    ///   measurement is the runtime's MRTD and four RTMRs.
    ///
    /// The caller's pins are then applied
    /// ([`apply_pins`](super::resolve::apply_pins)).
    pub fn resolve(
        &self,
        quote: &Authenticated,
        pins: Option<&Expected>,
    ) -> Result<ResolvedValues<'a>, AssemblyError> {
        pending("quote::config::ConfigReferenceValues::resolve")
    }
}
