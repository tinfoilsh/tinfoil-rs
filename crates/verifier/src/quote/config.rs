//! Reference values of the endorsed-config contract.

use super::resolve::{MR_CONFIG_ID_SIZE, ResolvedValues, apply_pins, register, resolve_policy};
use super::{AssemblyError, Authenticated};
use crate::canonical;
use crate::measurement::Expected;
use crate::policy::Artifact;
use crate::runtime::Measurements;

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
        let (policy_name, policy) = resolve_policy(self.endorsements, quote)?;
        let mut host_data = String::new();
        let mut config_id = [0; MR_CONFIG_ID_SIZE];
        let code = match quote {
            Authenticated::SevSnp(_) => {
                let sev_snp = policy.as_sev_snp().ok_or_else(|| {
                    AssemblyError::new(format!("policy {policy_name:?} is not for sev-snp"))
                })?;
                if !sev_snp.host_data.is_empty() {
                    return Err(AssemblyError::new(
                        "config runtime cannot be combined with platform host_data",
                    ));
                }
                host_data = canonical::encode_lower_hex(&self.hash);
                Expected::SevSnp {
                    launch: Some(register(
                        "runtime SNP launch measurement",
                        &self.runtime.snp_launch.measurement,
                    )?),
                }
            }
            Authenticated::Tdx(_) => {
                let tdx = policy.as_tdx().ok_or_else(|| {
                    AssemblyError::new(format!("policy {policy_name:?} is not for tdx"))
                })?;
                if !tdx.platform_measurements.is_empty() {
                    return Err(AssemblyError::new(
                        "config runtime cannot be combined with platform_measurements",
                    ));
                }
                for (target, byte) in config_id.iter_mut().zip(self.hash) {
                    *target = byte;
                }
                let [mrtd, rtmr0, rtmr1, rtmr2, rtmr3] = self.runtime.tdx_launch.registers();
                let parse = |index: usize, value: &str| {
                    register(format_args!("runtime TDX register {index}"), value).map(Some)
                };
                Expected::Tdx {
                    mrtd: parse(0, mrtd)?,
                    rtmr0: parse(1, rtmr0)?,
                    rtmr1: parse(2, rtmr1)?,
                    rtmr2: parse(3, rtmr2)?,
                    rtmr3: parse(4, rtmr3)?,
                }
            }
        };
        let expected = apply_pins(&code, pins)?;
        Ok(ResolvedValues {
            policy,
            policy_name: policy_name.to_owned(),
            platform_measurement_name: None,
            code,
            expected,
            host_data,
            config_id,
        })
    }
}
