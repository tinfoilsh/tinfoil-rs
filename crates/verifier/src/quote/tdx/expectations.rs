//! The expected state of a TDX quote.

use super::authenticate::Quote;
use super::lib::validate::Options;
use crate::document::REPORT_DATA_SIZE;
use crate::measurement::Measurement;
use crate::measurement::REGISTER_SIZE;
use crate::policy::TdxPolicy;
use crate::quote::AssemblyError;
use crate::quote::resolve::MR_CONFIG_ID_SIZE;

/// The fully translated expected state of a TDX quote, resolved at assembly
/// so that validation performs no translation and no lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations {
    /// The exact values and floors that the quote is validated against.
    options: Options,
    /// The lowest acceptable `tcbEvaluationDataNumber` of the Intel
    /// collateral. It is separate because it is not a field of the quote.
    /// Every minimum that a policy can state is kept exactly.
    minimum_tcb_evaluation_data_number: u64,
}

/// Translates an endorsed policy into the expected state of a quote.
///
/// `measurement` is the complete TDX measurement that the quote must show;
/// any other measurement is an error. In order:
///
/// 1. the policy is valid ([`TdxPolicy::validate`]);
/// 2. the QE vendor identifier (16 bytes), the minimum TEE TCB SVN (16
///    bytes), MRSEAM (48 bytes), the TD attributes (8 bytes) and XFAM (8
///    bytes) decode from hex;
/// 3. MR_OWNER and MR_OWNER_CONFIG are expected to be zero, MR_CONFIG_ID to
///    be `config_id`, MRTD and the RTMRs to be those of `measurement`, and
///    the report data to be `report_data`;
/// 4. the minimum `tcbEvaluationDataNumber` is the policy's, converted
///    without loss: a valid policy states one that is not negative, and
///    every such value fits the 64 unsigned bits it is kept in. It is never
///    narrowed, so a minimum that no collateral reaches rejects every quote
///    instead of wrapping to a small one.
///
/// The QE and PCE security versions are not policy: quote verification
/// already holds them to Intel's signed collateral.
pub fn assemble(
    policy: &TdxPolicy,
    measurement: &Measurement,
    report_data: &[u8; REPORT_DATA_SIZE],
    config_id: &[u8; MR_CONFIG_ID_SIZE],
) -> Result<Expectations, AssemblyError> {
    policy.validate()?;
    let qe_vendor_id = fixed("qe_vendor_id", &policy.qe_vendor_id)?;
    let minimum_tee_tcb_svn = fixed("minimum_tee_tcb_svn", &policy.minimum_tee_tcb_svn)?;
    let mr_seam = fixed("mr_seam", &policy.mr_seam)?;
    let td_attributes = fixed("td_attributes", &policy.td_attributes)?;
    let xfam = fixed("xfam", &policy.xfam)?;
    let Measurement::Tdx {
        mrtd,
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
    } = measurement
    else {
        return Err(AssemblyError::new(
            "a TDX quote needs a TDX measurement to be compared with",
        ));
    };
    let minimum_tcb_evaluation_data_number = policy
        .minimum_tcb_evaluation_data_number
        .and_then(|minimum| u64::try_from(minimum).ok())
        .ok_or_else(|| {
            AssemblyError::new("minimum_tcb_evaluation_data_number is required and not negative")
        })?;
    Ok(Expectations {
        options: Options {
            qe_vendor_id,
            minimum_tee_tcb_svn,
            mr_seam,
            td_attributes,
            xfam,
            mr_td: *mrtd.as_bytes(),
            mr_config_id: *config_id,
            mr_owner: [0; REGISTER_SIZE],
            mr_owner_config: [0; REGISTER_SIZE],
            rtmrs: [
                *rtmr0.as_bytes(),
                *rtmr1.as_bytes(),
                *rtmr2.as_bytes(),
                *rtmr3.as_bytes(),
            ],
            report_data: *report_data,
        },
        minimum_tcb_evaluation_data_number,
    })
}

/// Decodes the hex policy value `name` into exactly `N` bytes.
fn fixed<const N: usize>(name: &str, value: &str) -> Result<[u8; N], AssemblyError> {
    let bytes = crate::policy::decode_hex(name, value, N)?;
    bytes
        .try_into()
        .map_err(|_| AssemblyError::new(format!("{name} must be {N} bytes")))
}

impl Expectations {
    /// Compares a quote against the expected state. This is the only TDX
    /// enforcement entry point, so no subset of the policy can be applied.
    ///
    /// In order: the quote satisfies the options
    /// ([`validate`](super::lib::validate::validate)); the quote's
    /// `tcbEvaluationDataNumber` is at least the minimum. A negative
    /// number is below every minimum.
    pub fn validate(&self, quote: &Quote) -> Result<(), AssemblyError> {
        super::lib::validate::validate(quote.quote(), &self.options)?;
        let number = quote.tcb_evaluation_data_number();
        let reached = u64::try_from(number)
            .is_ok_and(|number| number >= self.minimum_tcb_evaluation_data_number);
        if !reached {
            return Err(AssemblyError::new(format!(
                "tcbEvaluationDataNumber {number} is below the policy minimum {}",
                self.minimum_tcb_evaluation_data_number
            )));
        }
        Ok(())
    }
}
