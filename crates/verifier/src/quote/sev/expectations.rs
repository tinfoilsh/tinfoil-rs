//! The expected state of an SEV-SNP report.

use super::authenticate::Quote;
use super::lib::abi::{GuestPolicy, PlatformInfo};
use super::lib::validate::Options;
use crate::document::REPORT_DATA_SIZE;
use crate::measurement::Register;
use crate::policy::SevSnpPolicy;
use crate::quote::AssemblyError;
use crate::stub::pending;

/// The fully translated expected state of an SEV-SNP report, resolved at
/// assembly so that validation performs no translation and no lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectations {
    /// The bounds and exact values that the report is validated against.
    options: Options,
    /// The guest policy that the report must show exactly, apart from the
    /// ABI version, which is a floor.
    guest_policy: GuestPolicy,
    /// The platform info that the report must show exactly.
    platform_info: PlatformInfo,
}

/// Translates an endorsed policy into the expected state of a quote.
///
/// `policy` carries the host data that the report must show (the caller
/// has put the resolved value in place). In order:
///
/// 1. the policy is valid ([`SevSnpPolicy::validate`]);
/// 2. the policy fits the quote's product line. Genoa: no FMC level in
///    either TCB, and `iommu_write_safe` not set. Turin: an FMC level in
///    both TCBs, and `iommu_write_safe` set;
/// 3. the firmware API version and the guest ABI version parse as
///    `major.minor` ([`parse_policy_version`](crate::policy::parse_policy_version));
/// 4. both TCB floors are valid for the product line's TCB layout
///    ([`TcbParts::for_product_line`](super::lib::kds::TcbParts::for_product_line));
/// 5. host data (32 bytes), image identifier and family identifier (16
///    bytes each) decode from hex; an empty value leaves the field
///    unchecked;
/// 6. the expected measurement is `launch`, the expected report data is
///    `report_data`, and the expected CHIP_ID is the quote's own identity.
pub fn assemble(
    policy: &SevSnpPolicy,
    quote: &Quote,
    launch: Register,
    report_data: &[u8; REPORT_DATA_SIZE],
) -> Result<Expectations, AssemblyError> {
    pending("quote::sev::assemble")
}

impl Expectations {
    /// Compares a quote against the expected state. This is the only
    /// SEV-SNP enforcement entry point, so no subset of the policy can be
    /// applied.
    ///
    /// In order:
    ///
    /// 1. the report satisfies the options
    ///    ([`validate`](super::lib::validate::validate));
    /// 2. the report's guest policy equals the expected one in every flag;
    ///    the ABI version was already checked as a floor;
    /// 3. the report's platform info equals the expected one in every
    ///    flag;
    /// 4. the report was launched without an identity block: CHIP_ID is not
    ///    masked, no author key is enabled, and the identity key digest and
    ///    author key digest are all zero.
    pub fn validate(&self, quote: &Quote) -> Result<(), AssemblyError> {
        pending("quote::sev::Expectations::validate")
    }
}
