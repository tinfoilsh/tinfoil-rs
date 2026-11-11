//! Validation of an authenticated TDX quote's fields against exact values
//! and floors.

use super::abi::{
    ATTRIBUTES_SIZE, QE_VENDOR_ID_SIZE, QuoteV4, REGISTER_SIZE, REPORT_DATA_SIZE, TEE_TCB_SVN_SIZE,
};
use crate::quote::AssemblyError;
use crate::stub::pending;

/// What a quote must show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// The exact QE vendor identifier.
    pub qe_vendor_id: [u8; QE_VENDOR_ID_SIZE],
    /// The floor of TEE_TCB_SVN, byte by byte.
    pub minimum_tee_tcb_svn: [u8; TEE_TCB_SVN_SIZE],
    /// The exact MRSEAM.
    pub mr_seam: [u8; REGISTER_SIZE],
    /// The exact TDATTRIBUTES.
    pub td_attributes: [u8; ATTRIBUTES_SIZE],
    /// The exact XFAM.
    pub xfam: [u8; ATTRIBUTES_SIZE],
    /// The exact MRTD.
    pub mr_td: [u8; REGISTER_SIZE],
    /// The exact MRCONFIGID.
    pub mr_config_id: [u8; REGISTER_SIZE],
    /// The exact MROWNER.
    pub mr_owner: [u8; REGISTER_SIZE],
    /// The exact MROWNERCONFIG.
    pub mr_owner_config: [u8; REGISTER_SIZE],
    /// The exact RTMR0 to RTMR3.
    pub rtmrs: [[u8; REGISTER_SIZE]; 4],
    /// The exact REPORTDATA.
    pub report_data: [u8; REPORT_DATA_SIZE],
}

/// Validates an authenticated quote against options.
///
/// In order:
///
/// 1. the quote has the version 4 form ([`QuoteV4::parse`] holds);
/// 2. exact values: the QE vendor identifier, MRSEAM, TDATTRIBUTES, XFAM,
///    MRTD, MRCONFIGID, MROWNER, MROWNERCONFIG, the four RTMRs and
///    REPORTDATA equal the options';
/// 3. every byte of TEE_TCB_SVN is at least the same byte of the floor;
/// 4. XFAM has every bit set that the architecture fixes to one and no bit
///    that it fixes to zero; TDATTRIBUTES likewise. These bounds are fixed,
///    not policy.
pub fn validate(quote: &QuoteV4, options: &Options) -> Result<(), AssemblyError> {
    pending("quote::tdx::lib::validate::validate")
}
