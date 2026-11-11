//! Validation of an authenticated TDX quote's fields against exact values
//! and floors.

use super::abi::{
    ATTRIBUTES_SIZE, QE_VENDOR_ID_SIZE, QuoteV4, REGISTER_SIZE, REPORT_DATA_SIZE, TEE_TCB_SVN_SIZE,
};
use crate::canonical::encode_lower_hex;
use crate::quote::AssemblyError;

/// The XFAM bits that the architecture fixes to one.
pub const XFAM_FIXED_1: u64 = 0x0000_0003;
/// The XFAM bits that may be set; every other bit is fixed to zero.
pub const XFAM_FIXED_0: u64 = 0x0006_DBE7;
/// The TDATTRIBUTES bits that the architecture fixes to one.
pub const TD_ATTRIBUTES_FIXED_1: u64 = 0;
/// The TDATTRIBUTES bits that may be set: DEBUG (0), SEPT_VE_DISABLE (28),
/// PKS (30) and PERFMON (63). Every other bit is fixed to zero.
pub const TD_ATTRIBUTES_FIXED_0: u64 = 1 | (1 << 28) | (1 << 30) | (1 << 63);

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

fn exact(field: &str, given: &[u8], required: &[u8]) -> Result<(), AssemblyError> {
    if given == required {
        return Ok(());
    }
    Err(AssemblyError::new(format!(
        "quote field {field} is {}. Expect {}",
        encode_lower_hex(given),
        encode_lower_hex(required)
    )))
}

/// Checks a 64-bit little-endian field against the bits that the
/// architecture fixes.
fn fixed_bits(
    field: &str,
    value: [u8; 8],
    fixed_1: u64,
    fixed_0: u64,
) -> Result<(), AssemblyError> {
    let value = u64::from_le_bytes(value);
    if value & fixed_1 != fixed_1 {
        return Err(AssemblyError::new(format!(
            "unauthorized {field} {value:#x}: bits fixed to one ({fixed_1:#x}) are unset"
        )));
    }
    if value & !fixed_0 != 0 {
        return Err(AssemblyError::new(format!(
            "unauthorized {field} {value:#x}: bits outside {fixed_0:#x} are set"
        )));
    }
    Ok(())
}

/// Validates an authenticated quote against options.
///
/// In order:
///
/// 1. exact values: MRSEAM, TDATTRIBUTES, XFAM, MRTD, MRCONFIGID, MROWNER,
///    MROWNERCONFIG, the four RTMRs, REPORTDATA and the QE vendor
///    identifier equal the options';
/// 2. every byte of TEE_TCB_SVN is at least the same byte of the floor;
/// 3. XFAM has every bit set that the architecture fixes to one
///    ([`XFAM_FIXED_1`]) and no bit that it fixes to zero
///    ([`XFAM_FIXED_0`]); TDATTRIBUTES likewise
///    ([`TD_ATTRIBUTES_FIXED_1`], [`TD_ATTRIBUTES_FIXED_0`]). These bounds
///    are fixed, not policy.
///
/// The form of the quote needs no check here: a [`QuoteV4`] exists only in
/// the version 4 form.
pub fn validate(quote: &QuoteV4, options: &Options) -> Result<(), AssemblyError> {
    let body = &quote.body;
    exact("MR_SEAM", &body.mr_seam, &options.mr_seam)?;
    exact("TD_ATTRIBUTES", &body.td_attributes, &options.td_attributes)?;
    exact("XFAM", &body.xfam, &options.xfam)?;
    exact("MR_TD", &body.mr_td, &options.mr_td)?;
    exact("MR_CONFIG_ID", &body.mr_config_id, &options.mr_config_id)?;
    exact("MR_OWNER", &body.mr_owner, &options.mr_owner)?;
    exact(
        "MR_OWNER_CONFIG",
        &body.mr_owner_config,
        &options.mr_owner_config,
    )?;
    for (index, (given, required)) in body.rtmrs.iter().zip(&options.rtmrs).enumerate() {
        exact(&format!("RTMR[{index}]"), given, required)?;
    }
    exact("REPORT_DATA", &body.report_data, &options.report_data)?;
    exact(
        "QE_VENDOR_ID",
        &quote.header.qe_vendor_id,
        &options.qe_vendor_id,
    )?;

    let below_floor = body
        .tee_tcb_svn
        .iter()
        .zip(&options.minimum_tee_tcb_svn)
        .any(|(given, minimum)| given < minimum);
    if below_floor {
        return Err(AssemblyError::new(format!(
            "TEE TCB security-version number {} is less than the required minimum {}",
            encode_lower_hex(&body.tee_tcb_svn),
            encode_lower_hex(&options.minimum_tee_tcb_svn)
        )));
    }

    fixed_bits("xfam", body.xfam, XFAM_FIXED_1, XFAM_FIXED_0)?;
    fixed_bits(
        "tdAttributes",
        body.td_attributes,
        TD_ATTRIBUTES_FIXED_1,
        TD_ATTRIBUTES_FIXED_0,
    )
}
