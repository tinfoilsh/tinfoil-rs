//! The expected state of an SEV-SNP report.

use super::authenticate::Quote;
use super::lib::abi::{GuestPolicy, PlatformInfo, ProductLine};
use super::lib::kds::TcbParts;
use super::lib::validate::{Options, validate};
use crate::document::REPORT_DATA_SIZE;
use crate::measurement::Register;
use crate::policy::{SevSnpPolicy, Tcb, decode_hex, parse_policy_version};
use crate::quote::{AssemblyError, QuoteError};

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

fn quote_error(field: &str, error: QuoteError) -> AssemblyError {
    AssemblyError::new(format!("{field}: {error}"))
}

/// The guest policy flags that a policy states, with a zero ABI version.
fn expected_guest_policy(policy: &SevSnpPolicy) -> GuestPolicy {
    let flags = &policy.guest_policy;
    GuestPolicy {
        abi_minor: 0,
        abi_major: 0,
        smt: flags.smt,
        migrate_ma: flags.migrate_ma,
        debug: flags.debug,
        single_socket: flags.single_socket,
        cxl_allowed: flags.cxl_allowed,
        mem_aes256_xts: flags.mem_aes256_xts,
        rapl_dis: flags.rapl_dis,
        ciphertext_hiding_dram: flags.ciphertext_hiding_dram,
        page_swap_disable: flags.page_swap_disable,
    }
}

/// The platform info that a policy states.
fn expected_platform_info(policy: &SevSnpPolicy) -> PlatformInfo {
    let info = &policy.platform_info;
    PlatformInfo {
        smt_enabled: info.smt_enabled,
        tsme_enabled: info.tsme_enabled,
        ecc_enabled: info.ecc_enabled,
        rapl_disabled: info.rapl_disabled,
        ciphertext_hiding_dram: info.ciphertext_hiding_dram,
        alias_check_complete: info.alias_check_complete,
        iommu_write_safe: info.iommu_write_safe,
        tio_enabled: info.tio_enabled,
    }
}

/// The levels of a policy TCB floor for a product line.
fn tcb_floor(field: &str, product_line: ProductLine, tcb: &Tcb) -> Result<TcbParts, AssemblyError> {
    let level = |value: Option<u8>, name: &str| {
        value.ok_or_else(|| AssemblyError::new(format!("{field}: {name} is required")))
    };
    TcbParts::for_product_line(
        product_line,
        tcb.fmc_spl,
        level(tcb.bl_spl, "bl_spl")?,
        level(tcb.tee_spl, "tee_spl")?,
        level(tcb.snp_spl, "snp_spl")?,
        level(tcb.ucode_spl, "ucode_spl")?,
    )
    .map_err(|cause| quote_error(field, cause))
}

/// Decodes a hex policy value of exactly `N` bytes.
fn fixed_hex<const N: usize>(name: &str, value: &str) -> Result<[u8; N], AssemblyError> {
    let bytes = decode_hex(name, value, N)?;
    <[u8; N]>::try_from(bytes.as_slice())
        .map_err(|_| AssemblyError::new(format!("{name} must be {N} bytes")))
}

/// Translates an endorsed policy into the expected state of a quote.
///
/// `policy` carries the host data that the report must show: the caller
/// has put the resolved value in place, and an empty one is an error. In
/// order:
///
/// 1. the policy is valid ([`SevSnpPolicy::validate`]);
/// 2. the policy fits the quote's product line. Genoa: no FMC level in
///    either TCB, and `iommu_write_safe` not set. Turin: an FMC level in
///    both TCBs, and `iommu_write_safe` set;
/// 3. the firmware API version and the guest ABI version parse as
///    `major.minor` ([`parse_policy_version`]);
/// 4. both TCB floors are valid for the product line's TCB layout
///    ([`TcbParts::for_product_line`]);
/// 5. host data (32 bytes), image identifier and family identifier (16
///    bytes each) decode from hex;
/// 6. the expected measurement is `launch`, the expected report data is
///    `report_data`, and the expected CHIP_ID is the quote's own identity.
///
/// What the result holds the report to
/// ([`Expectations::validate`]): the firmware build and API version, the
/// guest SVN, both TCBs and both mitigation vectors are floors, as is the
/// ABI version of the guest policy; every flag of the guest policy and of
/// the platform info, the VMPL, the host data, the image and family
/// identifiers, the report data and the measurement are exact.
pub fn assemble(
    policy: &SevSnpPolicy,
    quote: &Quote,
    launch: Register,
    report_data: &[u8; REPORT_DATA_SIZE],
) -> Result<Expectations, AssemblyError> {
    policy.validate()?;
    let product_line = quote.product_line();
    let fmc_levels = (
        policy.minimum_tcb.fmc_spl.is_some(),
        policy.minimum_launch_tcb.fmc_spl.is_some(),
    );
    match product_line {
        ProductLine::Genoa => {
            if fmc_levels != (false, false) {
                return Err(AssemblyError::new(
                    "fmc_spl is not valid for product line Genoa",
                ));
            }
            if policy.platform_info.iommu_write_safe {
                return Err(AssemblyError::new(
                    "iommu_write_safe is not valid for product line Genoa",
                ));
            }
        }
        ProductLine::Turin => {
            if fmc_levels != (true, true) {
                return Err(AssemblyError::new(
                    "fmc_spl is required for product line Turin",
                ));
            }
            if !policy.platform_info.iommu_write_safe {
                return Err(AssemblyError::new(
                    "iommu_write_safe is required for product line Turin",
                ));
            }
        }
    }
    let (api_major, api_minor) =
        parse_policy_version("minimum_api_version", &policy.minimum_api_version)?;
    let (abi_major, abi_minor) =
        parse_policy_version("minimum_abi_version", &policy.minimum_abi_version)?;
    let minimum_tcb = tcb_floor("minimum_tcb", product_line, &policy.minimum_tcb)?;
    let minimum_launch_tcb = tcb_floor(
        "minimum_launch_tcb",
        product_line,
        &policy.minimum_launch_tcb,
    )?;
    let required = |name: &str| AssemblyError::new(format!("{name} is required"));
    let vmpl = policy
        .vmpl
        .and_then(|vmpl| u32::try_from(vmpl).ok())
        .ok_or_else(|| required("vmpl"))?;
    let host_data = fixed_hex("host_data", &policy.host_data)?;
    let image_id = fixed_hex("image_id", &policy.image_id)?;
    let family_id = fixed_hex("family_id", &policy.family_id)?;

    let guest_policy = expected_guest_policy(policy);
    let platform_info = expected_platform_info(policy);
    let chip_id = quote.report().chip_id;
    let options = Options {
        guest_policy: GuestPolicy {
            abi_major,
            abi_minor,
            ..guest_policy
        },
        minimum_guest_svn: policy
            .minimum_guest_svn
            .ok_or_else(|| required("minimum_guest_svn"))?,
        minimum_build: policy
            .minimum_build
            .ok_or_else(|| required("minimum_build"))?,
        minimum_version: u16::from_be_bytes([api_major, api_minor]),
        minimum_tcb,
        minimum_launch_tcb,
        permit_provisional_firmware: policy.permit_provisional_firmware,
        platform_info,
        vmpl,
        report_data: *report_data,
        measurement: *launch.as_bytes(),
        chip_id,
        host_data: Some(host_data),
        image_id: Some(image_id),
        family_id: Some(family_id),
        minimum_launch_mitigation_vector: policy
            .minimum_launch_mitigation_vector
            .ok_or_else(|| required("minimum_launch_mitigation_vector"))?,
        minimum_current_mitigation_vector: policy
            .minimum_current_mitigation_vector
            .ok_or_else(|| required("minimum_current_mitigation_vector"))?,
    };
    Ok(Expectations {
        options,
        guest_policy,
        platform_info,
    })
}

impl Expectations {
    /// Compares a quote against the expected state. This is the only
    /// SEV-SNP enforcement entry point, so no subset of the policy can be
    /// applied.
    ///
    /// In order:
    ///
    /// 1. the report satisfies the options
    ///    ([`validate`]), which also binds
    ///    the report's reported TCB and CHIP_ID to the VCEK certificate;
    /// 2. the report's guest policy equals the expected one in every flag;
    ///    the ABI version was already checked as a floor;
    /// 3. the report's platform info equals the expected one in every
    ///    flag;
    /// 4. the report was launched without an identity block: CHIP_ID is not
    ///    masked, no author key is enabled, and the identity key digest and
    ///    author key digest are all zero.
    pub fn validate(&self, quote: &Quote) -> Result<(), AssemblyError> {
        let report = quote.report();
        validate(report, quote.vcek_extensions(), &self.options)?;

        let policy = GuestPolicy::parse(report.policy)
            .map_err(|cause| quote_error("parsing report guest policy", cause))?;
        let expected = GuestPolicy {
            abi_major: policy.abi_major,
            abi_minor: policy.abi_minor,
            ..self.guest_policy
        };
        if policy != expected {
            return Err(AssemblyError::new(
                "SEV report guest policy does not match the endorsed policy",
            ));
        }
        let info = PlatformInfo::parse(report.platform_info)
            .map_err(|cause| quote_error("parsing report PLATFORM_INFO", cause))?;
        if info != self.platform_info {
            return Err(AssemblyError::new(
                "SEV report PLATFORM_INFO does not match the endorsed policy",
            ));
        }

        let signer = &report.signer_info;
        if signer.mask_chip_key {
            return Err(AssemblyError::new(
                "report masks CHIP_ID; masked platform identities are unsupported",
            ));
        }
        if signer.author_key_enabled {
            return Err(AssemblyError::new(
                "report carries an author key; ID-block launches are unsupported",
            ));
        }
        if report.id_key_digest.iter().any(|byte| *byte != 0) {
            return Err(AssemblyError::new(
                "report carries an ID block; ID-block launches are unsupported",
            ));
        }
        if report.author_key_digest.iter().any(|byte| *byte != 0) {
            return Err(AssemblyError::new(
                "report carries an author key digest; ID-block launches are unsupported",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instant::Instant;
    use crate::json::{self, Value};
    use crate::policy::PLATFORM_SEV_SNP;
    use crate::quote::sev::authenticate::{Evidence, authenticate, embedded_cert_chain_pem};
    use crate::quote::sev::differential_tests::{authentication_cases, named, policy_from_object};
    use crate::quote::sev::lib::abi::testdata::{
        TURIN_CHIP_ID, TURIN_CRL_DER, TURIN_NOW_UNIX, TURIN_REPORT, TURIN_VCEK_DER,
    };
    use crate::quote::sev::lib::kds::TcbLayout;
    use crate::sigstore::testutil::b64;

    const ARTIFACT: &[u8] = include_bytes!("../../../tests/data/platform_endorsements.json");
    /// Snapshots of two production Turin machines: the report, its VCEK
    /// and the policy that the machine was held to.
    const SNAPSHOTS: [&[u8]; 2] = [
        include_bytes!("../../../tests/data/sev/turin_inf17.json"),
        include_bytes!("../../../tests/data/sev/turin_inf18.json"),
    ];
    /// The identifier of a Genoa machine in the artifact.
    const GENOA_CHIP_ID: &str = "cfdce31f5c40fc4e6eef803f6b5ed77e88b22603a91337bacab58446ab05fb8ef7bb5221611dced98dfa01d1eac114ca9a7952c262705977a36d81b0a53f856e";

    fn artifact_policy(identity: &str) -> SevSnpPolicy {
        let artifact = crate::policy::parse(ARTIFACT).unwrap();
        let (_, policy) = artifact.policy_for(identity, PLATFORM_SEV_SNP).unwrap();
        policy.as_sev_snp().unwrap().clone()
    }

    fn turin_quote() -> Quote {
        Quote::unauthenticated(TURIN_REPORT, TURIN_VCEK_DER)
    }

    /// A Genoa quote: evidence captured from production hardware.
    fn genoa_quote() -> Quote {
        named(&authentication_cases(), "real-genoa/unchanged")
            .authenticate()
            .unwrap()
    }

    fn turin_inputs() -> (Register, [u8; REPORT_DATA_SIZE]) {
        let report = turin_quote().report().clone();
        (Register::new(report.measurement), report.report_data)
    }

    fn with_report(change: impl FnOnce(&mut Vec<u8>)) -> Quote {
        let mut report = TURIN_REPORT.to_vec();
        change(&mut report);
        Quote::unauthenticated(&report, TURIN_VCEK_DER)
    }

    /// A policy with every member present and nothing demanded.
    fn pinned_policy() -> SevSnpPolicy {
        let tcb = Tcb {
            fmc_spl: None,
            bl_spl: Some(0),
            tee_spl: Some(0),
            snp_spl: Some(0),
            ucode_spl: Some(0),
        };
        SevSnpPolicy {
            minimum_build: Some(21),
            minimum_api_version: "1.55".to_owned(),
            minimum_abi_version: "0.31".to_owned(),
            minimum_guest_svn: Some(0),
            minimum_tcb: tcb,
            minimum_launch_tcb: tcb,
            vmpl: Some(0),
            host_data: "ab".repeat(32),
            image_id: "cd".repeat(16),
            family_id: "ef".repeat(16),
            guest_policy: crate::policy::GuestPolicy {
                smt: true,
                page_swap_disable: true,
                ..Default::default()
            },
            minimum_launch_mitigation_vector: Some(3),
            minimum_current_mitigation_vector: Some(1),
            ..SevSnpPolicy::default()
        }
    }

    fn assembly_error(policy: &SevSnpPolicy, quote: &Quote) -> String {
        assemble(policy, quote, Register::new([0; 48]), &[0; 64])
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn a_genoa_policy_translates_into_options() {
        let mut policy = artifact_policy(GENOA_CHIP_ID);
        policy.host_data = "00".repeat(32);
        let quote = genoa_quote();
        assert_eq!(quote.product_line(), ProductLine::Genoa);
        let expectations = assemble(&policy, &quote, Register::new([7; 48]), &[9; 64]).unwrap();
        let options = &expectations.options;
        assert_eq!(options.minimum_build, 21);
        assert_eq!(options.minimum_version, (1 << 8) | 55);
        assert_eq!(options.minimum_tcb.layout, TcbLayout::V0);
        assert_eq!(options.minimum_tcb.bl_spl, 7);
        assert_eq!(options.minimum_tcb.snp_spl, 14);
        assert_eq!(options.minimum_tcb.ucode_spl, 72);
        assert_eq!(options.minimum_tcb.fmc_spl, 0);
        assert!(options.guest_policy.smt);
        assert!(!options.guest_policy.debug);
        assert!(options.platform_info.tsme_enabled);
        assert_eq!(options.measurement, [7; 48]);
        assert_eq!(options.report_data, [9; 64]);
        assert_eq!(options.chip_id, quote.report().chip_id);
        assert_eq!(options.host_data, Some([0; 32]));
    }

    #[test]
    fn a_turin_policy_translates_into_options() {
        let mut policy = artifact_policy(TURIN_CHIP_ID);
        policy.host_data = "00".repeat(32);
        let expectations =
            assemble(&policy, &turin_quote(), Register::new([0; 48]), &[0; 64]).unwrap();
        let options = &expectations.options;
        assert_eq!(options.minimum_build, 0);
        assert_eq!(options.minimum_version, (1 << 8) | 58);
        assert_eq!(options.minimum_tcb.layout, TcbLayout::V1);
        assert_eq!(options.minimum_tcb.fmc_spl, 1);
        assert_eq!(options.minimum_tcb.bl_spl, 1);
        assert_eq!(options.minimum_tcb.tee_spl, 1);
        assert_eq!(options.minimum_tcb.snp_spl, 4);
        assert_eq!(options.minimum_tcb.ucode_spl, 82);
        assert_eq!(
            options.minimum_tcb.compose().unwrap(),
            0x5200_0000_0401_0101
        );
        assert!(options.platform_info.iommu_write_safe);
        // The ABI floor rides in the guest policy bound; the exact
        // companion carries no version.
        assert_eq!(expectations.guest_policy.abi_major, 0);
        assert_eq!(expectations.guest_policy.abi_minor, 0);
    }

    #[test]
    fn pinned_fields_are_translated_and_required() {
        let quote = genoa_quote();
        let mut policy = pinned_policy();
        let expectations = assemble(&policy, &quote, Register::new([0; 48]), &[0; 64]).unwrap();
        let options = &expectations.options;
        assert_eq!(options.host_data, Some([0xab; 32]));
        assert_eq!(options.image_id, Some([0xcd; 16]));
        assert_eq!(options.family_id, Some([0xef; 16]));
        assert!(options.guest_policy.page_swap_disable);
        assert_eq!(
            (
                options.guest_policy.abi_major,
                options.guest_policy.abi_minor
            ),
            (0, 31)
        );
        assert_eq!(options.minimum_launch_mitigation_vector, 3);
        assert_eq!(options.minimum_current_mitigation_vector, 1);

        // Absent or malformed values are errors: the host data is never
        // left unchecked.
        policy.host_data = "abcd".to_owned();
        assert!(assembly_error(&policy, &quote).contains("host_data"));
        policy.host_data = String::new();
        assert!(assembly_error(&policy, &quote).contains("host_data"));

        // No identity block trust material is modeled.
        policy.host_data = "ab".repeat(32);
        policy.require_id_block = true;
        assert!(assembly_error(&policy, &quote).contains("not supported"));
        policy.require_id_block = false;
        policy.require_author_key = true;
        assert!(assembly_error(&policy, &quote).contains("not supported"));
    }

    #[test]
    fn a_policy_must_fit_the_product_line() {
        let turin = {
            let mut policy = artifact_policy(TURIN_CHIP_ID);
            policy.host_data = "00".repeat(32);
            policy
        };
        let quote = turin_quote();
        assemble(&turin, &quote, Register::new([0; 48]), &[0; 64]).unwrap();
        let mut missing_fmc = turin.clone();
        missing_fmc.minimum_tcb.fmc_spl = None;
        assert!(assembly_error(&missing_fmc, &quote).contains("fmc_spl is required"));
        let mut missing_launch_fmc = turin.clone();
        missing_launch_fmc.minimum_launch_tcb.fmc_spl = None;
        assert!(assembly_error(&missing_launch_fmc, &quote).contains("fmc_spl is required"));
        let mut not_write_safe = turin.clone();
        not_write_safe.platform_info.iommu_write_safe = false;
        assert!(assembly_error(&not_write_safe, &quote).contains("iommu_write_safe is required"));

        let genoa = {
            let mut policy = artifact_policy(GENOA_CHIP_ID);
            policy.host_data = "00".repeat(32);
            policy
        };
        let quote = genoa_quote();
        assemble(&genoa, &quote, Register::new([0; 48]), &[0; 64]).unwrap();
        let mut with_fmc = genoa.clone();
        with_fmc.minimum_tcb.fmc_spl = Some(1);
        assert!(assembly_error(&with_fmc, &quote).contains("fmc_spl is not valid"));
        let mut with_zero_fmc = genoa.clone();
        with_zero_fmc.minimum_launch_tcb.fmc_spl = Some(0);
        assert!(assembly_error(&with_zero_fmc, &quote).contains("fmc_spl is not valid"));
        let mut write_safe = genoa.clone();
        write_safe.platform_info.iommu_write_safe = true;
        assert!(assembly_error(&write_safe, &quote).contains("iommu_write_safe is not valid"));
        // A policy for the other product line.
        assert!(assembly_error(&turin, &quote).contains("not valid for product line Genoa"));
    }

    #[test]
    fn a_captured_turin_report_satisfies_its_policy() {
        let quote = authenticate(
            Evidence {
                report: TURIN_REPORT,
                vcek_der: TURIN_VCEK_DER,
                cert_chain_pem: std::str::from_utf8(embedded_cert_chain_pem(ProductLine::Turin))
                    .unwrap(),
                crl_der: TURIN_CRL_DER,
            },
            Instant::from_unix(TURIN_NOW_UNIX, 0).unwrap(),
            None,
        )
        .unwrap();
        let mut policy = artifact_policy(quote.identity());
        policy.host_data = crate::canonical::encode_lower_hex(&quote.report().host_data);
        let (launch, report_data) = turin_inputs();
        let expectations = assemble(&policy, &quote, launch, &report_data).unwrap();
        expectations.validate(&quote).unwrap();
        // The expectations hold their own copy of the policy.
        policy.guest_policy.debug = true;
        expectations.validate(&quote).unwrap();
        assert!(!expectations.guest_policy.debug);
    }

    #[test]
    fn every_expectation_is_enforced_after_authentication() {
        let config_hash = [0x5c; 32];
        let guest_policy: u64 = 0x3_0133;
        let base = |report: &mut Vec<u8>| {
            report[0xC0..0xE0].copy_from_slice(&config_hash);
            report[0x08..0x10].copy_from_slice(&guest_policy.to_le_bytes());
        };
        let quote = with_report(base);
        let mut policy = artifact_policy(TURIN_CHIP_ID);
        policy.minimum_abi_version = "1.51".to_owned();
        policy.host_data = String::new();
        let (launch, report_data) = turin_inputs();
        let error = assemble(&policy, &quote, launch, &report_data).unwrap_err();
        assert!(error.to_string().contains("host_data"), "{error}");
        policy.host_data = crate::canonical::encode_lower_hex(&config_hash);
        let expectations = assemble(&policy, &quote, launch, &report_data).unwrap();
        expectations.validate(&quote).unwrap();

        type Change = fn(&mut Vec<u8>);
        let changes: [(&str, Change); 15] = [
            ("config hash", |report| report[0xC0] ^= 1),
            ("launch measurement", |report| report[0x90] ^= 1),
            ("ABI below the floor", |report| report[0x08] -= 1),
            ("guest debug", |report| report[0x0A] |= 1 << 3),
            ("platform state", |report| report[0x40] ^= 1),
            ("family identifier", |report| report[0x10] ^= 1),
            ("image identifier", |report| report[0x20] ^= 1),
            ("identity block", |report| report[0xE0] = 1),
            ("identity block with a guest SVN", |report| {
                report[0x04] = 1;
                report[0xE0] = 1;
            }),
            ("author key digest", |report| report[0x110 + 47] = 1),
            ("author key enabled", |report| report[0x48] = 1),
            ("masked CHIP_ID", |report| report[0x48] = 2),
            ("report data", |report| report[0x50] ^= 1),
            ("VMPL", |report| report[0x30] = 1),
            ("CHIP_ID", |report| report[0x1A0] ^= 1),
        ];
        for (name, change) in changes {
            let changed = with_report(|report| {
                base(report);
                change(report);
            });
            assert!(expectations.validate(&changed).is_err(), "{name}");
        }
        // The ABI version is a floor, not an exact value.
        let newer_abi = with_report(|report| {
            base(report);
            report[0x08] += 1;
        });
        expectations.validate(&newer_abi).unwrap();

        // The guest SVN is a floor.
        let mut floor_policy = policy.clone();
        floor_policy.minimum_guest_svn = Some(1);
        let floor = assemble(&floor_policy, &quote, launch, &report_data).unwrap();
        for (svn, accepted) in [(0, false), (1, true), (2, true)] {
            let quote = with_report(|report| {
                base(report);
                report[0x04] = svn;
            });
            assert_eq!(floor.validate(&quote).is_ok(), accepted, "{svn}");
        }
    }

    #[test]
    fn guest_policy_and_platform_info_are_exact() {
        let (launch, report_data) = turin_inputs();
        let quote = turin_quote();
        let mut policy = artifact_policy(TURIN_CHIP_ID);
        policy.host_data = "00".repeat(32);
        // The bound alone would accept a report without a restriction that
        // the policy does not ask for, and with a protection that it does
        // not ask for; the exact comparison does not.
        let restricted = with_report(|report| report[0x0A] |= 1 << 4);
        let protected = with_report(|report| report[0x40] |= 1 << 3);
        let expectations = assemble(&policy, &quote, launch, &report_data).unwrap();
        expectations.validate(&quote).unwrap();
        for (name, changed) in [
            ("single socket", &restricted),
            ("RAPL disabled", &protected),
        ] {
            super::validate(
                changed.report(),
                changed.vcek_extensions(),
                &expectations.options,
            )
            .unwrap_or_else(|error| panic!("{name}: {error}"));
            let error = expectations.validate(changed).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("does not match the endorsed policy"),
                "{error}"
            );
        }
        // The platform info of a policy is not a permission either.
        policy.platform_info.ecc_enabled = false;
        let without_ecc = assemble(&policy, &quote, launch, &report_data).unwrap();
        let error = without_ecc.validate(&quote).unwrap_err();
        assert!(error.to_string().contains("PLATFORM_INFO"), "{error}");
    }

    #[test]
    fn production_snapshots_satisfy_the_policy_they_were_held_to() {
        for snapshot in SNAPSHOTS {
            let snapshot = json::parse(snapshot).unwrap();
            let snapshot = snapshot.as_object().unwrap();
            let field = |name: &str| b64(snapshot.get(name).and_then(Value::as_str).unwrap());
            let (report, vcek) = (field("report_base64"), field("vcek_der_base64"));
            let quote = authenticate(
                Evidence {
                    report: &report,
                    vcek_der: &vcek,
                    cert_chain_pem: std::str::from_utf8(embedded_cert_chain_pem(
                        ProductLine::Turin,
                    ))
                    .unwrap(),
                    crl_der: TURIN_CRL_DER,
                },
                Instant::from_unix(TURIN_NOW_UNIX, 0).unwrap(),
                None,
            )
            .unwrap();
            assert_eq!(quote.product_line(), ProductLine::Turin);
            assert_eq!(quote.report().version, 5);
            assert_eq!(quote.report().platform_info, 0x64);

            let block = snapshot.get("policy").and_then(Value::as_object).unwrap();
            assert_eq!(
                block.get("platform").and_then(Value::as_str),
                Some(PLATFORM_SEV_SNP)
            );
            let policy =
                policy_from_object(block.get("sev_snp").and_then(Value::as_object).unwrap());
            assert_eq!(
                expected_platform_info(&policy),
                PlatformInfo {
                    ecc_enabled: true,
                    alias_check_complete: true,
                    iommu_write_safe: true,
                    ..PlatformInfo::default()
                }
            );
            let launch = Register::new(quote.report().measurement);
            let report_data = quote.report().report_data;
            let expectations = assemble(&policy, &quote, launch, &report_data).unwrap();
            expectations.validate(&quote).unwrap();

            // The platform info is exact: a policy without ECC does not
            // accept a machine that has it.
            let mut wrong = policy.clone();
            wrong.platform_info.ecc_enabled = false;
            let expectations = assemble(&wrong, &quote, launch, &report_data).unwrap();
            assert!(expectations.validate(&quote).is_err());
        }
    }
}
