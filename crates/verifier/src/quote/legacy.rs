//! Reference values of the repository-release contract.

use super::resolve::ResolvedValues;
use super::{AssemblyError, Authenticated};
use crate::measurement::{Expected, Register};
use crate::policy::{Artifact, Shape};
use crate::stub::pending;

/// Reference values of the repository-release contract: a platform policy
/// artifact and the registers and VM shape of a code release.
#[derive(Debug, Clone)]
pub struct LegacyReferenceValues<'a> {
    /// The platform policy artifact.
    pub endorsements: &'a Artifact,
    /// The SEV-SNP launch measurement that the release fixes.
    pub sev_snp_launch: Register,
    /// The TDX RTMR1 that the release fixes.
    pub tdx_rtmr1: Register,
    /// The TDX RTMR2 that the release fixes.
    pub tdx_rtmr2: Register,
    /// The VM shape that the release declares.
    pub shape: &'a Shape,
}

impl<'a> LegacyReferenceValues<'a> {
    /// Resolves the policy and the expected registers for a quote.
    ///
    /// In order: the machine's policy is looked up
    /// ([`resolve_policy`](super::resolve::resolve_policy)); the code
    /// measurement is the release's registers for the quote's platform;
    /// the caller's pins are applied
    /// ([`apply_pins`](super::resolve::apply_pins)). Then by platform:
    ///
    /// - SEV-SNP: the expected HOST_DATA is the policy's;
    /// - TDX: the release fixes only RTMR1 and RTMR2. The platform
    ///   measurement is resolved from the artifact by the quote's own MRTD
    ///   and RTMR0 and the release's shape
    ///   ([`Artifact::resolve_platform_measurement`]); its MRTD and RTMR0
    ///   fill those registers where no pin has, and an unpinned RTMR3 must
    ///   be zero.
    pub fn resolve(
        &self,
        quote: &Authenticated,
        pins: Option<&Expected>,
    ) -> Result<ResolvedValues<'a>, AssemblyError> {
        pending("quote::legacy::LegacyReferenceValues::resolve")
    }
}
