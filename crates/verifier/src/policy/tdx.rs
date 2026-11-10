//! The Intel TDX policy block.

use super::{PolicyError, optional, validate_policy_hex};
use crate::json::Value;
use crate::json::decode::{self, DecodeError};

/// The Intel TDX policy of a machine.
///
/// `platform_measurements` names the measurement entries that the machine is
/// endorsed to run; the quote's own MRTD and RTMR0 select exactly one of
/// them. Runtime endorsements supply these measurements instead when a
/// config is verified. The integer is optional so that an absent member is
/// told apart from a meaningful zero; [`TdxPolicy::validate`] rejects an
/// absent one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TdxPolicy {
    /// The quoting enclave vendor id: 16 bytes, lowercase hex.
    pub qe_vendor_id: String,
    /// The lowest acceptable TEE TCB SVN: 16 bytes, lowercase hex.
    pub minimum_tee_tcb_svn: String,
    /// The expected MRSEAM: 48 bytes, lowercase hex.
    pub mr_seam: String,
    /// The expected TD attributes: 8 bytes, lowercase hex.
    pub td_attributes: String,
    /// The expected XFAM: 8 bytes, lowercase hex.
    pub xfam: String,
    /// The lowest acceptable TCB evaluation data number of the collateral.
    pub minimum_tcb_evaluation_data_number: Option<i64>,
    /// Names of the measurement entries that the machine may run.
    pub platform_measurements: Vec<String>,
}

impl TdxPolicy {
    /// Rejects a block with an absent or malformed required member.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let required = |name: &str| PolicyError::new(format!("{name} is required"));
        if self.qe_vendor_id.is_empty() {
            return Err(required("qe_vendor_id"));
        }
        if self.minimum_tee_tcb_svn.is_empty() {
            return Err(required("minimum_tee_tcb_svn"));
        }
        if self.mr_seam.is_empty() {
            return Err(required("mr_seam"));
        }
        if self.td_attributes.is_empty() {
            return Err(required("td_attributes"));
        }
        if self.xfam.is_empty() {
            return Err(required("xfam"));
        }
        match self.minimum_tcb_evaluation_data_number {
            None => return Err(required("minimum_tcb_evaluation_data_number")),
            // A negative minimum would pass for any collateral and so
            // disable the freshness floor without saying so.
            Some(minimum) if minimum < 0 => {
                return Err(PolicyError::new(
                    "minimum_tcb_evaluation_data_number must not be negative",
                ));
            }
            Some(_) => {}
        }
        for (name, value, byte_len) in [
            ("qe_vendor_id", &self.qe_vendor_id, 16),
            ("minimum_tee_tcb_svn", &self.minimum_tee_tcb_svn, 16),
            ("mr_seam", &self.mr_seam, 48),
            ("td_attributes", &self.td_attributes, 8),
            ("xfam", &self.xfam, 8),
        ] {
            validate_policy_hex(name, value, byte_len)?;
        }
        Ok(())
    }

    /// Decodes a `tdx` member; `null` is no block.
    pub(super) fn from_value(value: Value, path: &str) -> Result<Option<Self>, DecodeError> {
        let Some(object) = decode::object(value, path)? else {
            return Ok(None);
        };
        let mut policy = TdxPolicy::default();
        for (name, value) in object.into_members() {
            match name.as_str() {
                "qe_vendor_id" => policy.qe_vendor_id = decode::string(value, &name)?,
                "minimum_tee_tcb_svn" => {
                    policy.minimum_tee_tcb_svn = decode::string(value, &name)?;
                }
                "mr_seam" => policy.mr_seam = decode::string(value, &name)?,
                "td_attributes" => policy.td_attributes = decode::string(value, &name)?,
                "xfam" => policy.xfam = decode::string(value, &name)?,
                "minimum_tcb_evaluation_data_number" => {
                    policy.minimum_tcb_evaluation_data_number =
                        optional(&value, &name, decode::i64)?;
                }
                "platform_measurements" => {
                    policy.platform_measurements =
                        decode::strings(value, &name)?.unwrap_or_default();
                }
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(Some(policy))
    }
}
