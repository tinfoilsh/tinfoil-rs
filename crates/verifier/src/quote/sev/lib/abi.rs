//! The SEV-SNP attestation report (`ATTESTATION_REPORT` of the SEV-SNP
//! firmware ABI) and its bit fields.

use crate::quote::QuoteError;
use crate::x509::{EcdsaHash, PublicKey, SignatureScheme};

/// The size of an attestation report in bytes.
pub const REPORT_SIZE: usize = 0x4A0;
/// The offset of the signature: the report is signed up to here.
pub const SIGNATURE_OFFSET: usize = 0x2A0;
/// The size of the FAMILY_ID and IMAGE_ID fields.
pub const ID_SIZE: usize = 16;
/// The size of the REPORT_DATA field.
pub const REPORT_DATA_SIZE: usize = 64;
/// The size of the MEASUREMENT field.
pub const MEASUREMENT_SIZE: usize = 48;
/// The size of the HOST_DATA field.
pub const HOST_DATA_SIZE: usize = 32;
/// The size of the ID_KEY_DIGEST and AUTHOR_KEY_DIGEST fields.
pub const KEY_DIGEST_SIZE: usize = 48;
/// The size of the REPORT_ID and REPORT_ID_MA fields.
pub const REPORT_ID_SIZE: usize = 32;
/// The size of the CHIP_ID field.
pub const CHIP_ID_SIZE: usize = 64;

/// The SIGNATURE_ALGO value of ECDSA P-384 with SHA-384.
pub const SIGNATURE_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// The size of each of `r` and `s` in the signature field: little-endian,
/// padded with zeros.
const SIGNATURE_COMPONENT_SIZE: usize = 72;
/// The size of a P-384 scalar.
const SCALAR_SIZE: usize = 48;

/// The oldest report version that is accepted.
pub const MIN_REPORT_VERSION: u32 = 2;
/// The newest report version that is accepted.
pub const MAX_REPORT_VERSION: u32 = 5;
/// The first report version that carries the CPUID family, model and
/// stepping.
pub const REPORT_VERSION_WITH_CPUID: u32 = 3;
/// The bits of the CPUID stepping byte that hold the stepping; the other
/// four are reserved.
const CPUID_STEPPING_MASK: u8 = 0x0F;

/// Bit 17 of the guest policy is reserved and always set.
const POLICY_RESERVED_ONE_BIT: u32 = 17;
/// The highest defined bit of the guest policy.
const POLICY_HIGHEST_BIT: u32 = 25;
/// The highest defined bit of PLATFORM_INFO.
const PLATFORM_INFO_HIGHEST_BIT: u32 = 7;

fn error(message: impl Into<String>) -> QuoteError {
    QuoteError::new(message)
}

/// A decoded attestation report. Decoding establishes its form only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// VERSION.
    pub version: u32,
    /// GUEST_SVN.
    pub guest_svn: u32,
    /// POLICY: the guest policy.
    pub policy: u64,
    /// FAMILY_ID.
    pub family_id: [u8; ID_SIZE],
    /// IMAGE_ID.
    pub image_id: [u8; ID_SIZE],
    /// VMPL.
    pub vmpl: u32,
    /// SIGNATURE_ALGO.
    pub signature_algo: u32,
    /// CURRENT_TCB.
    pub current_tcb: u64,
    /// PLATFORM_INFO.
    pub platform_info: u64,
    /// The signing key and flags of the 32-bit field after PLATFORM_INFO.
    pub signer_info: SignerInfo,
    /// REPORT_DATA.
    pub report_data: [u8; REPORT_DATA_SIZE],
    /// MEASUREMENT: the launch digest.
    pub measurement: [u8; MEASUREMENT_SIZE],
    /// HOST_DATA.
    pub host_data: [u8; HOST_DATA_SIZE],
    /// ID_KEY_DIGEST.
    pub id_key_digest: [u8; KEY_DIGEST_SIZE],
    /// AUTHOR_KEY_DIGEST.
    pub author_key_digest: [u8; KEY_DIGEST_SIZE],
    /// REPORT_ID.
    pub report_id: [u8; REPORT_ID_SIZE],
    /// REPORT_ID_MA.
    pub report_id_ma: [u8; REPORT_ID_SIZE],
    /// REPORTED_TCB.
    pub reported_tcb: u64,
    /// The CPUID family, model and stepping; `None` before version 3, and
    /// when all three are zero. The high four bits of the stepping byte are
    /// reserved, and a report that sets any of them does not decode.
    pub cpuid: Option<Cpuid>,
    /// CHIP_ID.
    pub chip_id: [u8; CHIP_ID_SIZE],
    /// COMMITTED_TCB.
    pub committed_tcb: u64,
    /// CURRENT_BUILD.
    pub current_build: u8,
    /// CURRENT_MINOR.
    pub current_minor: u8,
    /// CURRENT_MAJOR.
    pub current_major: u8,
    /// COMMITTED_BUILD.
    pub committed_build: u8,
    /// COMMITTED_MINOR.
    pub committed_minor: u8,
    /// COMMITTED_MAJOR.
    pub committed_major: u8,
    /// LAUNCH_TCB.
    pub launch_tcb: u64,
    /// LAUNCH_MIT_VECTOR; meaningful from version 5.
    pub launch_mitigation_vector: u64,
    /// CURRENT_MIT_VECTOR; meaningful from version 5.
    pub current_mitigation_vector: u64,
}

/// The CPUID family, model and stepping of the reporting chip, with the
/// extended parts folded in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cpuid {
    /// The family.
    pub family: u8,
    /// The model.
    pub model: u8,
    /// The stepping, 0 to 15.
    pub stepping: u8,
}

/// The product line of a chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductLine {
    /// Fourth-generation EPYC.
    Genoa,
    /// Fifth-generation EPYC.
    Turin,
}

impl ProductLine {
    /// The product line's name in AMD's key distribution service.
    pub fn name(self) -> &'static str {
        match self {
            ProductLine::Genoa => "Genoa",
            ProductLine::Turin => "Turin",
        }
    }

    /// The product line that a report's CPUID field names: family 19h
    /// model 11h is Genoa, and family 1Ah model 02h is Turin. A report
    /// without the field, and any other chip, is an error.
    pub fn from_report(report: &Report) -> Result<Self, QuoteError> {
        let cpuid = report.cpuid.ok_or_else(|| {
            error(format!(
                "report carries no CPUID product identity (report version {}, want 3+)",
                report.version
            ))
        })?;
        match (cpuid.family, cpuid.model) {
            (0x19, 0x11) => Ok(ProductLine::Genoa),
            (0x1A, 0x02) => Ok(ProductLine::Turin),
            (family, model) => Err(error(format!(
                "unsupported SEV product in report CPUID: family {family:#x}, model {model:#x}"
            ))),
        }
    }
}

/// Which key signed a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKey {
    /// The versioned chip endorsement key.
    Vcek,
    /// The versioned loaded endorsement key.
    Vlek,
    /// No key: the report is not signed.
    None,
}

/// The signing circumstances of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerInfo {
    /// The kind of key that signed the report.
    pub signing_key: SigningKey,
    /// MASK_CHIP_KEY: whether the host has turned off signing with the
    /// chip key. This is not the masking of CHIP_ID, a separate host
    /// setting that leaves this flag clear and makes CHIP_ID read as zeros.
    pub mask_chip_key: bool,
    /// Whether the guest was launched with an identity block that carries
    /// an author key.
    pub author_key_enabled: bool,
}

impl SignerInfo {
    /// Decodes the 32-bit signer field: bit 0 is the author key flag, bit 1
    /// MASK_CHIP_KEY, bits 2 to 4 the signing key, and bits 5 to 31 must be
    /// zero. Signing key values 2 to 6 are reserved and an error.
    pub fn parse(value: u32) -> Result<Self, QuoteError> {
        if value >> 5 != 0 {
            return Err(error(format!(
                "report signer info has reserved bits set: {value:#x}"
            )));
        }
        let signing_key = match (value >> 2) & 7 {
            0 => SigningKey::Vcek,
            1 => SigningKey::Vlek,
            7 => SigningKey::None,
            reserved => {
                return Err(error(format!(
                    "report signing key value {reserved} is reserved"
                )));
            }
        };
        Ok(Self {
            signing_key,
            mask_chip_key: value & 2 != 0,
            author_key_enabled: value & 1 != 0,
        })
    }
}

/// The guest policy of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestPolicy {
    /// The minimum ABI minor version that the guest requires.
    pub abi_minor: u8,
    /// The minimum ABI major version that the guest requires.
    pub abi_major: u8,
    /// Bit 16: simultaneous multithreading is allowed.
    pub smt: bool,
    /// Bit 18: association with a migration agent is allowed.
    pub migrate_ma: bool,
    /// Bit 19: debugging is allowed.
    pub debug: bool,
    /// Bit 20: the guest can be activated on one socket only.
    pub single_socket: bool,
    /// Bit 21: CXL devices and memory are allowed.
    pub cxl_allowed: bool,
    /// Bit 22: memory encryption must use AES-256 XTS.
    pub mem_aes256_xts: bool,
    /// Bit 23: running average power limit must be disabled.
    pub rapl_dis: bool,
    /// Bit 24: ciphertext hiding must be enabled for DRAM.
    pub ciphertext_hiding_dram: bool,
    /// Bit 25: guest access to page swap must be disabled.
    pub page_swap_disable: bool,
}

impl GuestPolicy {
    /// Decodes a guest policy. Bit 17 is reserved and must be set; bits 26
    /// to 63 must be zero.
    pub fn parse(policy: u64) -> Result<Self, QuoteError> {
        let bit = |index: u32| policy & (1u64 << index) != 0;
        if !bit(POLICY_RESERVED_ONE_BIT) {
            return Err(error("guest policy bit 17 is reserved and must be 1"));
        }
        if policy >> (POLICY_HIGHEST_BIT + 1) != 0 {
            return Err(error(format!(
                "guest policy has reserved bits set: {policy:#x}"
            )));
        }
        let [abi_minor, abi_major, ..] = policy.to_le_bytes();
        Ok(Self {
            abi_minor,
            abi_major,
            smt: bit(16),
            migrate_ma: bit(18),
            debug: bit(19),
            single_socket: bit(20),
            cxl_allowed: bit(21),
            mem_aes256_xts: bit(22),
            rapl_dis: bit(23),
            ciphertext_hiding_dram: bit(24),
            page_swap_disable: bit(25),
        })
    }
}

/// The PLATFORM_INFO of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlatformInfo {
    /// Bit 0: simultaneous multithreading is enabled.
    pub smt_enabled: bool,
    /// Bit 1: transparent memory encryption is enabled.
    pub tsme_enabled: bool,
    /// Bit 2: the platform uses error-correcting memory.
    pub ecc_enabled: bool,
    /// Bit 3: running average power limit is disabled.
    pub rapl_disabled: bool,
    /// Bit 4: ciphertext hiding is enabled for DRAM.
    pub ciphertext_hiding_dram: bool,
    /// Bit 5: the memory alias check has completed.
    pub alias_check_complete: bool,
    /// Bit 6: the IOMMU write-safe mitigation is present.
    pub iommu_write_safe: bool,
    /// Bit 7: SEV-TIO is enabled.
    pub tio_enabled: bool,
}

impl PlatformInfo {
    /// Decodes a PLATFORM_INFO value. Bits 8 to 63 must be zero.
    pub fn parse(platform_info: u64) -> Result<Self, QuoteError> {
        if platform_info >> (PLATFORM_INFO_HIGHEST_BIT + 1) != 0 {
            return Err(error(format!(
                "unrecognized platform info bits: {platform_info:#x}"
            )));
        }
        let bit = |index: u32| platform_info & (1u64 << index) != 0;
        Ok(Self {
            smt_enabled: bit(0),
            tsme_enabled: bit(1),
            ecc_enabled: bit(2),
            rapl_disabled: bit(3),
            ciphertext_hiding_dram: bit(4),
            alias_check_complete: bit(5),
            iommu_write_safe: bit(6),
            tio_enabled: bit(7),
        })
    }
}

/// Reads fixed-width fields from the front of a report.
struct Fields<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Fields<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], QuoteError> {
        let (head, rest) = self
            .bytes
            .split_first_chunk::<N>()
            .ok_or_else(|| error("report is truncated"))?;
        self.bytes = rest;
        self.offset = self.offset.saturating_add(N);
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, QuoteError> {
        self.array::<1>().map(|[byte]| byte)
    }

    fn u32(&mut self) -> Result<u32, QuoteError> {
        self.array().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, QuoteError> {
        self.array().map(u64::from_le_bytes)
    }

    /// Skips reserved bytes up to the offset `end`, which must all be zero.
    fn must_be_zero_until(&mut self, end: usize) -> Result<(), QuoteError> {
        let start = self.offset;
        let count = end
            .checked_sub(start)
            .ok_or_else(|| error("report field offsets are inconsistent"))?;
        let (reserved, rest) = self
            .bytes
            .split_at_checked(count)
            .ok_or_else(|| error("report is truncated"))?;
        if reserved.iter().any(|byte| *byte != 0) {
            return Err(error(format!(
                "report reserved range [{start:#x}:{end:#x}] is not all zero"
            )));
        }
        self.bytes = rest;
        self.offset = end;
        Ok(())
    }
}

impl Report {
    /// Decodes an attestation report of exactly [`REPORT_SIZE`] bytes.
    ///
    /// Rules, each an error when broken:
    ///
    /// - the guest policy decodes ([`GuestPolicy::parse`]) and the signer
    ///   field decodes ([`SignerInfo::parse`]);
    /// - the reserved ranges are zero: `[0x4C, 0x50)`; `[0x188, 0x1A0)`
    ///   before version 3 and `[0x18B, 0x1A0)` from version 3; `0x1EB`;
    ///   `0x1EF`; `[0x208, 0x2A0)`; and, for an ECDSA P-384 signature, the
    ///   signature field after its two 72-byte components.
    ///
    /// The version is not judged here; [`verify_report_signature`] accepts
    /// versions [`MIN_REPORT_VERSION`] to [`MAX_REPORT_VERSION`].
    pub fn parse(data: &[u8]) -> Result<Self, QuoteError> {
        if data.len() != REPORT_SIZE {
            return Err(error(format!(
                "SEV-SNP report must be exactly {REPORT_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let mut fields = Fields {
            bytes: data,
            offset: 0,
        };
        let version = fields.u32()?;
        let guest_svn = fields.u32()?;
        let policy = fields.u64()?;
        GuestPolicy::parse(policy).map_err(|cause| cause.within("malformed guest policy"))?;
        let family_id = fields.array()?;
        let image_id = fields.array()?;
        let vmpl = fields.u32()?;
        let signature_algo = fields.u32()?;
        let current_tcb = fields.u64()?;
        let platform_info = fields.u64()?;
        let signer_info = SignerInfo::parse(fields.u32()?)?;
        fields.must_be_zero_until(0x50)?;
        let report_data = fields.array()?;
        let measurement = fields.array()?;
        let host_data = fields.array()?;
        let id_key_digest = fields.array()?;
        let author_key_digest = fields.array()?;
        let report_id = fields.array()?;
        let report_id_ma = fields.array()?;
        let reported_tcb = fields.u64()?;
        let mut cpuid = None;
        if version >= REPORT_VERSION_WITH_CPUID {
            let [family, model, stepping] = fields.array()?;
            if stepping & !CPUID_STEPPING_MASK != 0 {
                return Err(error(format!(
                    "CPUID stepping byte {stepping:#04x} sets reserved bits"
                )));
            }
            if (family, model, stepping) != (0, 0, 0) {
                cpuid = Some(Cpuid {
                    family,
                    model,
                    stepping,
                });
            }
        }
        fields.must_be_zero_until(0x1A0)?;
        let chip_id = fields.array()?;
        let committed_tcb = fields.u64()?;
        let current_build = fields.u8()?;
        let current_minor = fields.u8()?;
        let current_major = fields.u8()?;
        fields.must_be_zero_until(0x1EC)?;
        let committed_build = fields.u8()?;
        let committed_minor = fields.u8()?;
        let committed_major = fields.u8()?;
        fields.must_be_zero_until(0x1F0)?;
        let launch_tcb = fields.u64()?;
        let launch_mitigation_vector = fields.u64()?;
        let current_mitigation_vector = fields.u64()?;
        fields.must_be_zero_until(SIGNATURE_OFFSET)?;
        if signature_algo == SIGNATURE_ALGO_ECDSA_P384_SHA384 {
            let _components: [u8; 2 * SIGNATURE_COMPONENT_SIZE] = fields.array()?;
            fields.must_be_zero_until(REPORT_SIZE)?;
        }
        Ok(Self {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            signature_algo,
            current_tcb,
            platform_info,
            signer_info,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            cpuid,
            chip_id,
            committed_tcb,
            current_build,
            current_minor,
            current_major,
            committed_build,
            committed_minor,
            committed_major,
            launch_tcb,
            launch_mitigation_vector,
            current_mitigation_vector,
        })
    }
}

/// The report's signature as `r` then `s`, each 48 bytes big-endian.
///
/// The report stores each as 72 bytes, little-endian. All 72 bytes count:
/// a component with a non-zero byte above the 48th does not fit a P-384
/// scalar and is an error.
fn signature_components(report: &[u8]) -> Result<[u8; 2 * SCALAR_SIZE], QuoteError> {
    let malformed = || error("report signature is malformed");
    let signature = report.get(SIGNATURE_OFFSET..).ok_or_else(malformed)?;
    let (r, rest) = signature
        .split_first_chunk::<SIGNATURE_COMPONENT_SIZE>()
        .ok_or_else(malformed)?;
    let (s, _) = rest
        .split_first_chunk::<SIGNATURE_COMPONENT_SIZE>()
        .ok_or_else(malformed)?;
    let mut raw = [0u8; 2 * SCALAR_SIZE];
    let (raw_r, raw_s) = raw.split_at_mut(SCALAR_SIZE);
    for (component, out) in [(r, raw_r), (s, raw_s)] {
        let (scalar, padding) = component.split_at(SCALAR_SIZE);
        if padding.iter().any(|byte| *byte != 0) {
            return Err(error("report signature component is out of range"));
        }
        for (target, source) in out.iter_mut().zip(scalar.iter().rev()) {
            *target = *source;
        }
    }
    Ok(raw)
}

/// Verifies a report's signature under the key of its VCEK certificate.
///
/// The report is [`REPORT_SIZE`] bytes; its version is
/// [`MIN_REPORT_VERSION`] to [`MAX_REPORT_VERSION`]; its guest policy
/// decodes; its signature algorithm is ECDSA P-384 with SHA-384; and the
/// signature verifies over the bytes before [`SIGNATURE_OFFSET`].
/// Every one of those bytes is covered: no bit of the report can change
/// without the signature failing.
pub fn verify_report_signature(report: &[u8], vcek_key: &PublicKey) -> Result<(), QuoteError> {
    let parsed = Report::parse(report)?;
    if !(MIN_REPORT_VERSION..=MAX_REPORT_VERSION).contains(&parsed.version) {
        return Err(error(format!(
            "report version is {}, expected {MIN_REPORT_VERSION} to {MAX_REPORT_VERSION}",
            parsed.version
        )));
    }
    if parsed.signature_algo != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
        return Err(error(format!(
            "unknown report signature algorithm {}",
            parsed.signature_algo
        )));
    }
    let signature = signature_components(report)?;
    let signed = report
        .get(..SIGNATURE_OFFSET)
        .ok_or_else(|| error("report is truncated"))?;
    vcek_key
        .verify(
            SignatureScheme::EcdsaRaw(EcdsaHash::Sha384),
            signed,
            &signature,
        )
        .map_err(|cause| error(format!("report signature: {cause}")))
}

#[cfg(test)]
pub(crate) mod testdata {
    /// A version 5 attestation report captured from Turin hardware.
    pub const TURIN_REPORT: &[u8] = include_bytes!("../../../../tests/data/sev/turin_report.bin");
    /// The VCEK certificate that signed [`TURIN_REPORT`], DER.
    pub const TURIN_VCEK_DER: &[u8] = include_bytes!("../../../../tests/data/sev/turin_vcek.der");
    /// The revocation list that AMD published for Turin on 27 October 2026,
    /// valid until 9 December 2026, DER.
    pub const TURIN_CRL_DER: &[u8] = include_bytes!("../../../../tests/data/sev/turin_crl.der");
    /// An instant inside the validity of [`TURIN_CRL_DER`] and of
    /// [`TURIN_VCEK_DER`]: 1 November 2026.
    pub const TURIN_NOW_UNIX: i64 = 1_793_491_200;
    /// The CHIP_ID of [`TURIN_REPORT`] in hex.
    pub const TURIN_CHIP_ID: &str = "6bb1229b7692b7100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    /// A report of the given version that is zero wherever a field may be,
    /// with the reserved guest policy bit set.
    pub fn blank_report(version: u32) -> Vec<u8> {
        let mut report = vec![0u8; super::REPORT_SIZE];
        report[0..4].copy_from_slice(&version.to_le_bytes());
        report[0x08..0x10].copy_from_slice(&(1u64 << 17).to_le_bytes());
        report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        report
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;
    use crate::canonical::encode_lower_hex;
    use crate::x509::Certificate;

    const SIGNER_INFO_OFFSET: usize = 0x48;

    fn with_signer_info(value: u32) -> Vec<u8> {
        let mut report = blank_report(2);
        report[SIGNER_INFO_OFFSET..SIGNER_INFO_OFFSET + 4].copy_from_slice(&value.to_le_bytes());
        report
    }

    fn vcek_key() -> PublicKey {
        Certificate::from_der(TURIN_VCEK_DER)
            .unwrap()
            .public_key()
            .unwrap()
    }

    #[test]
    fn a_captured_report_decodes() {
        let report = Report::parse(TURIN_REPORT).unwrap();
        assert_eq!(report.version, 5);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.policy, 0x3_0000);
        assert_eq!(report.platform_info, 0x64);
        assert_eq!(report.signature_algo, SIGNATURE_ALGO_ECDSA_P384_SHA384);
        assert_eq!(
            report.cpuid,
            Some(Cpuid {
                family: 0x1A,
                model: 0x02,
                stepping: 0x01
            })
        );
        assert_eq!(
            ProductLine::from_report(&report).unwrap(),
            ProductLine::Turin
        );
        assert_eq!(report.current_tcb, 0x5200_0000_0401_0101);
        assert_eq!(report.reported_tcb, report.current_tcb);
        assert_eq!(report.committed_tcb, report.current_tcb);
        assert_eq!(report.launch_tcb, report.current_tcb);
        assert_eq!(
            (
                report.current_major,
                report.current_minor,
                report.current_build
            ),
            (1, 58, 0)
        );
        assert_eq!(
            (
                report.committed_major,
                report.committed_minor,
                report.committed_build
            ),
            (1, 58, 0)
        );
        assert_eq!(report.launch_mitigation_vector, 0x3f);
        assert_eq!(report.current_mitigation_vector, 0x3f);
        assert!(encode_lower_hex(&report.chip_id).starts_with("6bb1229b7692b710"));
        assert!(report.chip_id[8..].iter().all(|byte| *byte == 0));
        assert!(encode_lower_hex(&report.measurement).starts_with("7821546665c10e96"));
        assert_eq!(
            report.signer_info,
            SignerInfo {
                signing_key: SigningKey::Vcek,
                mask_chip_key: false,
                author_key_enabled: false
            }
        );
        let policy = GuestPolicy::parse(report.policy).unwrap();
        assert_eq!(
            policy,
            GuestPolicy {
                smt: true,
                ..GuestPolicy::default()
            }
        );
        let platform = PlatformInfo::parse(report.platform_info).unwrap();
        assert_eq!(
            platform,
            PlatformInfo {
                ecc_enabled: true,
                alias_check_complete: true,
                iommu_write_safe: true,
                ..PlatformInfo::default()
            }
        );
    }

    #[test]
    fn a_captured_report_verifies_under_its_vcek() {
        verify_report_signature(TURIN_REPORT, &vcek_key()).unwrap();
    }

    #[test]
    fn a_changed_report_does_not_verify() {
        let key = vcek_key();
        // One byte in each signed field class, and one in the signature.
        for offset in [0x04, 0x50, 0x90, 0x1A0, 0x1F8, 0x2A0, 0x2A0 + 72] {
            let mut report = TURIN_REPORT.to_vec();
            report[offset] ^= 1;
            assert!(
                verify_report_signature(&report, &key).is_err(),
                "offset {offset:#x}"
            );
        }
    }

    #[test]
    fn a_stepping_byte_with_reserved_bits_set_is_refused() {
        let key = vcek_key();
        let mut report = TURIN_REPORT.to_vec();
        assert_eq!(report[0x18A], 0x01);
        for high in [0x10, 0x30, 0x80, 0xF0] {
            report[0x18A] = 0x01 | high;
            let message = Report::parse(&report).unwrap_err().to_string();
            assert!(message.contains("reserved bits"), "{message}");
            assert!(verify_report_signature(&report, &key).is_err());
        }
        // The low bits are signed.
        report[0x18A] = 0x02;
        Report::parse(&report).unwrap();
        assert!(verify_report_signature(&report, &key).is_err());
    }

    #[test]
    fn every_bit_before_the_signature_is_signed() {
        let key = vcek_key();
        verify_report_signature(TURIN_REPORT, &key).unwrap();
        for bit in 0..SIGNATURE_OFFSET * 8 {
            let mut report = TURIN_REPORT.to_vec();
            report[bit / 8] ^= 1 << (bit % 8);
            assert!(verify_report_signature(&report, &key).is_err(), "bit {bit}");
        }
    }

    #[test]
    fn every_byte_of_a_signature_component_counts() {
        let key = vcek_key();
        for offset in [0x2A0 + 48, 0x2A0 + 71, 0x2A0 + 72 + 48, 0x2A0 + 143] {
            let mut report = TURIN_REPORT.to_vec();
            report[offset] = 1;
            let error = verify_report_signature(&report, &key).unwrap_err();
            assert!(error.to_string().contains("out of range"), "{error}");
        }
    }

    #[test]
    fn signature_components_are_reversed_into_big_endian() {
        let mut report = blank_report(2);
        for index in 0..48u8 {
            report[SIGNATURE_OFFSET + usize::from(index)] = 48 - index;
            report[SIGNATURE_OFFSET + 72 + usize::from(index)] = index + 1;
        }
        let raw = signature_components(&report).unwrap();
        assert_eq!((raw[0], raw[47]), (1, 48));
        assert_eq!((raw[48], raw[95]), (48, 1));
    }

    #[test]
    fn a_report_of_another_size_is_rejected() {
        let error = Report::parse(&[0u8; 100]).unwrap_err();
        assert!(error.to_string().contains("exactly 1184 bytes"), "{error}");
        let mut longer = blank_report(2);
        longer.extend_from_slice(&[0u8; 64]);
        assert!(Report::parse(&longer).is_err());
        assert!(Report::parse(&[]).is_err());
    }

    #[test]
    fn the_version_is_judged_with_the_signature() {
        let key = vcek_key();
        for version in [0, 1, 6, 7, u32::MAX] {
            let report = blank_report(version);
            assert!(Report::parse(&report).is_ok(), "version {version}");
            let error = verify_report_signature(&report, &key).unwrap_err();
            assert!(error.to_string().contains("report version"), "{error}");
        }
        for version in [2, 3, 4, 5] {
            let error = verify_report_signature(&blank_report(version), &key).unwrap_err();
            assert!(!error.to_string().contains("report version"), "{error}");
        }
    }

    #[test]
    fn an_unknown_signature_algorithm_is_rejected() {
        let mut report = blank_report(2);
        report[0x34..0x38].copy_from_slice(&2u32.to_le_bytes());
        let error = verify_report_signature(&report, &vcek_key()).unwrap_err();
        assert!(error.to_string().contains("signature algorithm"), "{error}");
    }

    #[test]
    fn reserved_ranges_must_be_zero() {
        let cases: [(u32, usize, bool); 16] = [
            (2, 0x4C, false),
            (2, 0x4F, false),
            (2, 0x188, false),
            (2, 0x18A, false),
            (3, 0x18B, false),
            (2, 0x19F, false),
            (2, 0x1EB, false),
            (2, 0x1EF, false),
            // The mitigation vectors are fields in every version.
            (2, 0x1F8, true),
            (2, 0x200, true),
            (5, 0x207, true),
            (2, 0x208, false),
            (5, 0x208, false),
            (5, 0x29F, false),
            (2, 0x2A0 + 144, false),
            (2, REPORT_SIZE - 1, false),
        ];
        for (version, offset, accepted) in cases {
            let mut report = blank_report(version);
            report[offset] = 1;
            assert_eq!(
                Report::parse(&report).is_ok(),
                accepted,
                "version {version}, offset {offset:#x}"
            );
        }
        assert!(Report::parse(&blank_report(2)).is_ok());
        assert!(Report::parse(&blank_report(3)).is_ok());
    }

    #[test]
    fn the_cpuid_field_exists_from_version_3() {
        let mut report = blank_report(3);
        report[0x188..0x18B].copy_from_slice(&[0x19, 0x11, 0x02]);
        let parsed = Report::parse(&report).unwrap();
        assert_eq!(
            ProductLine::from_report(&parsed).unwrap(),
            ProductLine::Genoa
        );
        assert_eq!(ProductLine::Genoa.name(), "Genoa");
        assert_eq!(ProductLine::Turin.name(), "Turin");

        report[0x18A] = 0x0F;
        assert_eq!(
            Report::parse(&report).unwrap().cpuid.unwrap().stepping,
            0x0F
        );
        report[0x18A] = 0x12;
        assert!(Report::parse(&report).is_err());

        let blank = Report::parse(&blank_report(3)).unwrap();
        assert_eq!(blank.cpuid, None);
        let error = ProductLine::from_report(&blank).unwrap_err();
        assert!(
            error.to_string().contains("no CPUID product identity"),
            "{error}"
        );

        for (family, model) in [(0x19, 0x01), (0x19, 0x10), (0x1A, 0x11), (0x17, 0x31)] {
            let mut report = blank_report(5);
            report[0x188..0x18A].copy_from_slice(&[family, model]);
            let parsed = Report::parse(&report).unwrap();
            assert!(ProductLine::from_report(&parsed).is_err());
        }
    }

    #[test]
    fn signer_info_decodes_its_key_and_flags() {
        let cases = [
            (0u32, SigningKey::Vcek, false, false),
            (1, SigningKey::Vcek, false, true),
            (2, SigningKey::Vcek, true, false),
            (4, SigningKey::Vlek, false, false),
            (0x1C, SigningKey::None, false, false),
        ];
        for (value, signing_key, mask_chip_key, author_key_enabled) in cases {
            let report = Report::parse(&with_signer_info(value)).unwrap();
            assert_eq!(
                report.signer_info,
                SignerInfo {
                    signing_key,
                    mask_chip_key,
                    author_key_enabled
                },
                "{value:#x}"
            );
        }
    }

    #[test]
    fn signer_info_with_reserved_values_is_rejected() {
        for value in [0x20u32, 0x8000_0000, 0x08, 0x0C, 0x10, 0x14, 0x18] {
            assert!(
                Report::parse(&with_signer_info(value)).is_err(),
                "{value:#x}"
            );
        }
    }

    #[test]
    fn the_guest_policy_has_one_reserved_bit_that_is_set() {
        assert!(GuestPolicy::parse(0).is_err());
        assert!(GuestPolicy::parse(1 << 17).is_ok());
        assert!(GuestPolicy::parse((1 << 17) | (1 << 26)).is_err());
        assert!(GuestPolicy::parse((1 << 17) | (1 << 63)).is_err());
        let all = GuestPolicy::parse(0x03FF_0000 | 0x0102).unwrap();
        assert_eq!(
            all,
            GuestPolicy {
                abi_minor: 2,
                abi_major: 1,
                smt: true,
                migrate_ma: true,
                debug: true,
                single_socket: true,
                cxl_allowed: true,
                mem_aes256_xts: true,
                rapl_dis: true,
                ciphertext_hiding_dram: true,
                page_swap_disable: true,
            }
        );
        let mut report = blank_report(2);
        report[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());
        let error = Report::parse(&report).unwrap_err();
        assert!(
            error.to_string().contains("malformed guest policy"),
            "{error}"
        );
    }

    #[test]
    fn platform_info_has_eight_defined_bits() {
        assert_eq!(PlatformInfo::parse(0).unwrap(), PlatformInfo::default());
        let all = PlatformInfo::parse(0xFF).unwrap();
        assert!(all.smt_enabled && all.tsme_enabled && all.ecc_enabled && all.rapl_disabled);
        assert!(
            all.ciphertext_hiding_dram
                && all.alias_check_complete
                && all.iommu_write_safe
                && all.tio_enabled
        );
        assert!(PlatformInfo::parse(0x100).is_err());
        assert!(PlatformInfo::parse(1 << 63).is_err());
    }
}
