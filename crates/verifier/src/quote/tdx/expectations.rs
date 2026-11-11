//! The expected state of a TDX quote.

use super::authenticate::Quote;
use super::lib::validate::Options;
use crate::document::REPORT_DATA_SIZE;
use crate::measurement::Measurement;
use crate::policy::TdxPolicy;
use crate::quote::AssemblyError;
use crate::quote::resolve::MR_CONFIG_ID_SIZE;
use crate::stub::pending;

/// The fully translated expected state of a TDX quote, resolved at assembly
/// so that validation performs no translation and no lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations {
    /// The exact values and floors that the quote is validated against.
    options: Options,
    /// The lowest acceptable `tcbEvaluationDataNumber` of the Intel
    /// collateral. It is separate because it is not a field of the quote.
    minimum_tcb_evaluation_data_number: u32,
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
///    the report data to be `report_data`.
///
/// The QE and PCE security versions are not policy: quote verification
/// already holds them to Intel's signed collateral.
pub fn assemble(
    policy: &TdxPolicy,
    measurement: &Measurement,
    report_data: &[u8; REPORT_DATA_SIZE],
    config_id: &[u8; MR_CONFIG_ID_SIZE],
) -> Result<Expectations, AssemblyError> {
    pending("quote::tdx::assemble")
}

impl Expectations {
    /// Compares a quote against the expected state. This is the only TDX
    /// enforcement entry point, so no subset of the policy can be applied.
    ///
    /// In order: the quote satisfies the options
    /// ([`validate`](super::lib::validate::validate)); the quote's
    /// `tcbEvaluationDataNumber` is at least the minimum.
    pub fn validate(&self, quote: &Quote) -> Result<(), AssemblyError> {
        pending("quote::tdx::Expectations::validate")
    }
}
