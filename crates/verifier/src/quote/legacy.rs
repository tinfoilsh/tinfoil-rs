//! Reference values of the repository-release contract.

use super::resolve::{MR_CONFIG_ID_SIZE, ResolvedValues, apply_pins, register, resolve_policy};
use super::{AssemblyError, Authenticated};
use crate::measurement::{Expected, REGISTER_SIZE, Register};
use crate::policy::{Artifact, Shape};

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
        let (policy_name, policy) = resolve_policy(self.endorsements, quote)?;
        let code = match quote {
            Authenticated::SevSnp(_) => Expected::SevSnp {
                launch: Some(self.sev_snp_launch),
            },
            Authenticated::Tdx(_) => Expected::Tdx {
                mrtd: None,
                rtmr0: None,
                rtmr1: Some(self.tdx_rtmr1),
                rtmr2: Some(self.tdx_rtmr2),
                rtmr3: None,
            },
        };
        let mut expected = apply_pins(&code, pins)?;
        let mut host_data = String::new();
        let mut platform_measurement_name = None;
        match quote {
            Authenticated::SevSnp(_) => {
                let sev_snp = policy.as_sev_snp().ok_or_else(|| {
                    AssemblyError::new(format!("policy {policy_name:?} is not for sev-snp"))
                })?;
                host_data.clone_from(&sev_snp.host_data);
            }
            Authenticated::Tdx(tdx_quote) => {
                let tdx = policy.as_tdx().ok_or_else(|| {
                    AssemblyError::new(format!("policy {policy_name:?} is not for tdx"))
                })?;
                let (quote_mrtd, quote_rtmr0) = tdx_quote.platform_measurements();
                let (name, measurement) = self.endorsements.resolve_platform_measurement(
                    tdx,
                    Some(self.shape),
                    &quote_mrtd,
                    &quote_rtmr0,
                )?;
                let platform_mrtd = register(
                    format_args!("platform measurement {name:?} MRTD"),
                    &measurement.mrtd,
                )?;
                let platform_rtmr0 = register(
                    format_args!("platform measurement {name:?} RTMR0"),
                    &measurement.rtmr0,
                )?;
                platform_measurement_name = Some(name.to_owned());
                let Expected::Tdx {
                    mrtd,
                    rtmr0,
                    rtmr3,
                    ..
                } = &mut expected
                else {
                    return Err(AssemblyError::new(
                        "expected a TDX measurement for a tdx quote",
                    ));
                };
                mrtd.get_or_insert(platform_mrtd);
                rtmr0.get_or_insert(platform_rtmr0);
                rtmr3.get_or_insert(Register::new([0; REGISTER_SIZE]));
            }
        }
        Ok(ResolvedValues {
            policy,
            policy_name: policy_name.to_owned(),
            platform_measurement_name,
            code,
            expected,
            host_data,
            config_id: [0; MR_CONFIG_ID_SIZE],
        })
    }
}
