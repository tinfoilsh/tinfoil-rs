//! Validation of an authenticated SEV-SNP report's fields against bounds
//! and exact values.

use super::abi::{
    CHIP_ID_SIZE, GuestPolicy, HOST_DATA_SIZE, ID_SIZE, MEASUREMENT_SIZE, PlatformInfo,
    REPORT_DATA_SIZE, Report,
};
use super::kds::{Extensions, TcbParts};
use crate::quote::AssemblyError;
use crate::stub::pending;

/// What a report must show.
///
/// The guest policy and platform info here are bounds: a flag that widens
/// what the guest or host may do is allowed only if it is set here, and a
/// flag that restricts is required if it is set here. Exact equality of
/// both is the caller's additional check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The guest policy bound; its ABI version is the lowest that the
    /// report's guest policy may state.
    pub guest_policy: GuestPolicy,
    /// The lowest acceptable guest SVN.
    pub minimum_guest_svn: u32,
    /// The lowest acceptable firmware build number.
    pub minimum_build: u8,
    /// The lowest acceptable firmware API version, major in the high byte.
    pub minimum_version: u16,
    /// The floor of the reported TCB.
    pub minimum_tcb: TcbParts,
    /// The floor of the launch TCB.
    pub minimum_launch_tcb: TcbParts,
    /// Whether the committed firmware may be older than the current one.
    pub permit_provisional_firmware: bool,
    /// The platform info bound.
    pub platform_info: PlatformInfo,
    /// The exact VMPL.
    pub vmpl: u32,
    /// The exact REPORT_DATA.
    pub report_data: [u8; REPORT_DATA_SIZE],
    /// The exact MEASUREMENT.
    pub measurement: [u8; MEASUREMENT_SIZE],
    /// The exact CHIP_ID.
    pub chip_id: [u8; CHIP_ID_SIZE],
    /// The exact HOST_DATA, when the policy fixes it.
    pub host_data: Option<[u8; HOST_DATA_SIZE]>,
    /// The exact IMAGE_ID, when the policy fixes it.
    pub image_id: Option<[u8; ID_SIZE]>,
    /// The exact FAMILY_ID, when the policy fixes it.
    pub family_id: Option<[u8; ID_SIZE]>,
    /// The bits that the launch mitigation vector must have set.
    pub minimum_launch_mitigation_vector: u64,
    /// The bits that the current mitigation vector must have set.
    pub minimum_current_mitigation_vector: u64,
}

/// Validates an authenticated report against options.
///
/// `extensions` are those of the VCEK that signed the report. The checks,
/// all of which must hold:
///
/// 1. the guest SVN is at least the minimum;
/// 2. guest policy: the report's ABI version is at least the bound's;
///    migration agent, debug, SMT and CXL are set only if the bound sets
///    them; single socket, AES-256 XTS, RAPL disable, ciphertext hiding and
///    page swap disable are set if the bound sets them;
/// 3. REPORT_DATA, MEASUREMENT and CHIP_ID equal the options'; HOST_DATA,
///    IMAGE_ID and FAMILY_ID equal the options' where given;
/// 4. TCB, with every version split by the layout of the report's product
///    line ([`TcbParts::decompose`]): the committed TCB equals the current
///    one, or with provisional firmware permitted is at most it; the
///    launch TCB is at least its floor; the reported TCB equals the
///    certificate's; the certificate's TCB is at most the current one; the
///    reported TCB is at least its floor. "At most" is
///    [`TcbParts::all_at_most`];
/// 5. firmware: the current build and API version are at least the
///    minimums; the committed build and API version equal the current
///    ones, or with provisional firmware permitted are at most them;
/// 6. platform info: SMT, TSME and SEV-TIO are enabled only if the bound
///    has them; ECC, RAPL disabled, ciphertext hiding, alias check complete
///    and IOMMU write-safe are present if the bound has them;
/// 7. each mitigation vector has every bit of its minimum set;
/// 8. the VMPL equals the options';
/// 9. the CHIP_ID is the certificate's hardware identifier: the whole
///    field for a 64-byte identifier, its first 8 bytes for an 8-byte one.
///    An all-zero CHIP_ID skips this comparison.
pub fn validate(
    report: &Report,
    extensions: &Extensions,
    options: &Options,
) -> Result<(), AssemblyError> {
    pending("quote::sev::lib::validate::validate")
}
