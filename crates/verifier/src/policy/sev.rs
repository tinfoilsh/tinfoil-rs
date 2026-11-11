//! The AMD SEV-SNP policy block.

use super::{PolicyError, optional, validate_policy_hex};
use crate::json::Value;
use crate::json::decode::{self, DecodeError};

/// The AMD SEV-SNP policy of a machine.
///
/// `host_data` is supplied by the artifact for workload releases, or derived
/// from the endorsed config. Integers are optional so that an absent member
/// is told apart from a meaningful zero; [`SevSnpPolicy::validate`] rejects
/// an absent one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SevSnpPolicy {
    /// The lowest acceptable firmware build.
    pub minimum_build: Option<u8>,
    /// The lowest acceptable firmware version, as `major.minor`.
    pub minimum_api_version: String,
    /// The lowest acceptable ABI version of the guest policy, as
    /// `major.minor`.
    pub minimum_abi_version: String,
    /// The lowest acceptable guest SVN.
    pub minimum_guest_svn: Option<u32>,
    /// The lowest acceptable current TCB.
    pub minimum_tcb: Tcb,
    /// The lowest acceptable TCB at launch.
    pub minimum_launch_tcb: Tcb,
    /// The guest policy bits that the report must carry.
    pub guest_policy: GuestPolicy,
    /// The platform information that the report must carry.
    pub platform_info: SnpPlatform,
    /// Whether firmware that is installed but not yet committed is allowed.
    pub permit_provisional_firmware: bool,
    /// The privilege level that the report must come from, 0 to 3.
    pub vmpl: Option<i64>,
    /// The expected host data: 32 bytes, lowercase hex. Empty when the
    /// artifact leaves it to the config.
    pub host_data: String,
    /// The expected image id: 16 bytes, lowercase hex.
    pub image_id: String,
    /// The expected family id: 16 bytes, lowercase hex.
    pub family_id: String,
    /// Unsupported: no trusted author key is modeled.
    pub require_author_key: bool,
    /// Unsupported: no trusted id key is modeled.
    pub require_id_block: bool,
    /// The mitigation bits that must have been set at launch.
    pub minimum_launch_mitigation_vector: Option<u64>,
    /// The mitigation bits that must be set now.
    pub minimum_current_mitigation_vector: Option<u64>,
}

impl SevSnpPolicy {
    /// Rejects a block with an absent required member or an unsupported
    /// setting.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let required = |name: &str| PolicyError::new(format!("{name} is required"));
        if self.minimum_build.is_none() {
            return Err(required("minimum_build"));
        }
        if self.minimum_api_version.is_empty() {
            return Err(required("minimum_api_version"));
        }
        if self.minimum_abi_version.is_empty() {
            return Err(required("minimum_abi_version"));
        }
        if self.minimum_guest_svn.is_none() {
            return Err(required("minimum_guest_svn"));
        }
        match self.vmpl {
            None => return Err(required("vmpl")),
            Some(vmpl) if !(0..=3).contains(&vmpl) => {
                return Err(PolicyError::new("vmpl must be between 0 and 3"));
            }
            Some(_) => {}
        }
        if self.image_id.is_empty() {
            return Err(required("image_id"));
        }
        if self.family_id.is_empty() {
            return Err(required("family_id"));
        }
        if self.minimum_launch_mitigation_vector.is_none() {
            return Err(required("minimum_launch_mitigation_vector"));
        }
        if self.minimum_current_mitigation_vector.is_none() {
            return Err(required("minimum_current_mitigation_vector"));
        }
        if self.require_author_key || self.require_id_block {
            return Err(PolicyError::new(
                "require_author_key and require_id_block are not supported (no trusted key material is modeled)",
            ));
        }
        self.minimum_tcb
            .validate()
            .map_err(|error| error.within("minimum_tcb"))?;
        self.minimum_launch_tcb
            .validate()
            .map_err(|error| error.within("minimum_launch_tcb"))?;
        parse_policy_version("minimum_api_version", &self.minimum_api_version)?;
        parse_policy_version("minimum_abi_version", &self.minimum_abi_version)?;
        if !self.host_data.is_empty() {
            validate_policy_hex("host_data", &self.host_data, 32)?;
        }
        validate_policy_hex("image_id", &self.image_id, 16)?;
        validate_policy_hex("family_id", &self.family_id, 16)?;
        Ok(())
    }

    /// Decodes a `sev_snp` member; `null` is no block.
    pub(super) fn from_value(value: Value, path: &str) -> Result<Option<Self>, DecodeError> {
        let Some(object) = decode::object(value, path)? else {
            return Ok(None);
        };
        let mut policy = SevSnpPolicy::default();
        for (name, value) in object.into_members() {
            match name.as_str() {
                "minimum_build" => policy.minimum_build = optional(&value, &name, decode::u8)?,
                "minimum_api_version" => {
                    policy.minimum_api_version = decode::string(value, &name)?;
                }
                "minimum_abi_version" => {
                    policy.minimum_abi_version = decode::string(value, &name)?;
                }
                "minimum_guest_svn" => {
                    policy.minimum_guest_svn = optional(&value, &name, decode::u32)?;
                }
                "minimum_tcb" => policy.minimum_tcb = Tcb::from_value(value, &name)?,
                "minimum_launch_tcb" => {
                    policy.minimum_launch_tcb = Tcb::from_value(value, &name)?;
                }
                "guest_policy" => policy.guest_policy = GuestPolicy::from_value(value, &name)?,
                "platform_info" => {
                    policy.platform_info = SnpPlatform::from_value(value, &name)?;
                }
                "permit_provisional_firmware" => {
                    policy.permit_provisional_firmware = decode::bool(&value, &name)?;
                }
                "vmpl" => policy.vmpl = optional(&value, &name, decode::i64)?,
                "host_data" => policy.host_data = decode::string(value, &name)?,
                "image_id" => policy.image_id = decode::string(value, &name)?,
                "family_id" => policy.family_id = decode::string(value, &name)?,
                "require_author_key" => {
                    policy.require_author_key = decode::bool(&value, &name)?;
                }
                "require_id_block" => policy.require_id_block = decode::bool(&value, &name)?,
                "minimum_launch_mitigation_vector" => {
                    policy.minimum_launch_mitigation_vector = optional(&value, &name, decode::u64)?;
                }
                "minimum_current_mitigation_vector" => {
                    policy.minimum_current_mitigation_vector =
                        optional(&value, &name, decode::u64)?;
                }
                _ => return Err(decode::unknown_member(path, &name)),
            }
        }
        Ok(Some(policy))
    }
}

/// Parses the policy version `name`, written as `major.minor` with each
/// part a decimal number that fits one byte.
pub fn parse_policy_version(name: &str, version: &str) -> Result<(u8, u8), PolicyError> {
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let Some((major, minor)) = version
        .split_once('.')
        .filter(|(major, minor)| digits(major) && digits(minor))
    else {
        return Err(PolicyError::new(format!(
            "{name} {version:?} is not maj.min"
        )));
    };
    let part = |label: &str, text: &str| {
        text.parse::<u8>()
            .map_err(|_| PolicyError::new(format!("{name} {label}: {text:?} is out of range")))
    };
    Ok((part("major", major)?, part("minor", minor)?))
}

/// AMD security patch levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tcb {
    /// The FMC level. Applies to family 1Ah (Turin) parts only.
    pub fmc_spl: Option<u8>,
    /// The boot loader level.
    pub bl_spl: Option<u8>,
    /// The TEE level.
    pub tee_spl: Option<u8>,
    /// The SNP firmware level.
    pub snp_spl: Option<u8>,
    /// The microcode level.
    pub ucode_spl: Option<u8>,
}

impl Tcb {
    /// Rejects a TCB that leaves out a level other than the FMC level.
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (name, level) in [
            ("bl_spl", self.bl_spl),
            ("tee_spl", self.tee_spl),
            ("snp_spl", self.snp_spl),
            ("ucode_spl", self.ucode_spl),
        ] {
            if level.is_none() {
                return Err(PolicyError::new(format!("{name} is required")));
            }
        }
        Ok(())
    }

    /// Decodes a TCB member; `null` is a TCB with no levels.
    fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut tcb = Tcb::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(tcb);
        };
        for (name, value) in object.into_members() {
            let level = match name.as_str() {
                "fmc_spl" => &mut tcb.fmc_spl,
                "bl_spl" => &mut tcb.bl_spl,
                "tee_spl" => &mut tcb.tee_spl,
                "snp_spl" => &mut tcb.snp_spl,
                "ucode_spl" => &mut tcb.ucode_spl,
                _ => return Err(decode::unknown_member(path, &name)),
            };
            *level = optional(&value, &name, decode::u8)?;
        }
        Ok(tcb)
    }
}

/// The SNP guest policy bits enforced at verification. Every bit is
/// compared: a bit that the artifact leaves out is `false`, and the report
/// must have it clear.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuestPolicy {
    /// Debugging of the guest is allowed.
    pub debug: bool,
    /// Simultaneous multithreading is allowed.
    pub smt: bool,
    /// Association with a migration agent is allowed.
    pub migrate_ma: bool,
    /// The guest may run on a single socket only.
    pub single_socket: bool,
    /// CXL devices may be populated.
    pub cxl_allowed: bool,
    /// Memory encryption must use AES-256-XTS.
    pub mem_aes256_xts: bool,
    /// Running average power limit must be disabled.
    pub rapl_dis: bool,
    /// Ciphertext hiding must be enabled for DRAM.
    pub ciphertext_hiding_dram: bool,
    /// Guest access to page swap must be disabled.
    pub page_swap_disable: bool,
}

impl GuestPolicy {
    /// Decodes a `guest_policy` member; `null` is every bit clear.
    fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut policy = GuestPolicy::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(policy);
        };
        for (name, value) in object.into_members() {
            let bit = match name.as_str() {
                "debug" => &mut policy.debug,
                "smt" => &mut policy.smt,
                "migrate_ma" => &mut policy.migrate_ma,
                "single_socket" => &mut policy.single_socket,
                "cxl_allowed" => &mut policy.cxl_allowed,
                "mem_aes256_xts" => &mut policy.mem_aes256_xts,
                "rapl_dis" => &mut policy.rapl_dis,
                "ciphertext_hiding_dram" => &mut policy.ciphertext_hiding_dram,
                "page_swap_disable" => &mut policy.page_swap_disable,
                _ => return Err(decode::unknown_member(path, &name)),
            };
            *bit = decode::bool(&value, &name)?;
        }
        Ok(policy)
    }
}

/// The SNP platform information that a report must carry. Every field is
/// compared for equality, so machines with different host configurations
/// need distinct policies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnpPlatform {
    /// Simultaneous multithreading is enabled.
    pub smt_enabled: bool,
    /// Transparent memory encryption is enabled.
    pub tsme_enabled: bool,
    /// Error-correcting memory is in use.
    pub ecc_enabled: bool,
    /// Running average power limit is disabled.
    pub rapl_disabled: bool,
    /// Ciphertext hiding is enabled for DRAM.
    pub ciphertext_hiding_dram: bool,
    /// The memory alias check has completed.
    pub alias_check_complete: bool,
    /// The IOMMU is write-safe.
    pub iommu_write_safe: bool,
    /// Trusted I/O is enabled.
    pub tio_enabled: bool,
}

impl SnpPlatform {
    /// Decodes a `platform_info` member; `null` is every field `false`.
    fn from_value(value: Value, path: &str) -> Result<Self, DecodeError> {
        let mut platform = SnpPlatform::default();
        let Some(object) = decode::object(value, path)? else {
            return Ok(platform);
        };
        for (name, value) in object.into_members() {
            let field = match name.as_str() {
                "smt_enabled" => &mut platform.smt_enabled,
                "tsme_enabled" => &mut platform.tsme_enabled,
                "ecc_enabled" => &mut platform.ecc_enabled,
                "rapl_disabled" => &mut platform.rapl_disabled,
                "ciphertext_hiding_dram" => &mut platform.ciphertext_hiding_dram,
                "alias_check_complete" => &mut platform.alias_check_complete,
                "iommu_write_safe" => &mut platform.iommu_write_safe,
                "tio_enabled" => &mut platform.tio_enabled,
                _ => return Err(decode::unknown_member(path, &name)),
            };
            *field = decode::bool(&value, &name)?;
        }
        Ok(platform)
    }
}
