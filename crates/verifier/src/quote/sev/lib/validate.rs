//! Validation of an authenticated SEV-SNP report's fields against bounds
//! and exact values.

use super::abi::{
    CHIP_ID_SIZE, GuestPolicy, HOST_DATA_SIZE, ID_SIZE, MEASUREMENT_SIZE, PlatformInfo,
    REPORT_DATA_SIZE, REPORT_VERSION_WITH_CPUID, Report, SigningKey,
};
use super::kds::{Extensions, HWID_SIZE_V0, HWID_SIZE_V1, TcbLayout, TcbParts};
use crate::quote::AssemblyError;

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

/// The TCB layout that a report's own fields are read with: that of the
/// chip family and model in its CPUID field from version 3 (family 19h is
/// [`TcbLayout::V0`]; family 1Ah with extended model 0 or 1 is
/// [`TcbLayout::V1`]), and [`TcbLayout::V0`] before. The certificate's
/// layout must be the same.
fn report_layout(report: &Report, certificate: TcbLayout) -> Result<TcbLayout, AssemblyError> {
    let layout = if report.version >= REPORT_VERSION_WITH_CPUID {
        let cpuid = report.cpuid.ok_or_else(|| {
            AssemblyError::new("could not determine the report's TCB layout: no CPUID")
        })?;
        match (cpuid.family, cpuid.model >> 4) {
            (0x19, 0x0 | 0x1 | 0xA) => TcbLayout::V0,
            (0x1A, 0x0 | 0x1) => TcbLayout::V1,
            (family, _) => {
                return Err(AssemblyError::new(format!(
                    "could not determine the report's TCB layout: family {family:#x}, model {:#x}",
                    cpuid.model
                )));
            }
        }
    } else {
        TcbLayout::V0
    };
    if layout != certificate {
        return Err(AssemblyError::new(
            "the report and the VCEK certificate use different TCB layouts",
        ));
    }
    Ok(layout)
}

/// `lower` must be at most `higher` in every level.
fn at_most(lower: (&TcbParts, &str), higher: (&TcbParts, &str), problems: &mut Vec<String>) {
    if !lower.0.all_at_most(higher.0) {
        problems.push(format!(
            "the {} is lower than the {} in at least one component",
            higher.1, lower.1
        ));
    }
}

/// Both must pack to the same TCB version, which requires that both are
/// valid ([`TcbParts::compose`]).
fn equal(left: (&TcbParts, &str), right: (&TcbParts, &str), problems: &mut Vec<String>) {
    match (left.0.compose(), right.0.compose()) {
        (Ok(a), Ok(b)) if a == b && left.0.layout == right.0.layout => {}
        (Ok(_), Ok(_)) => problems.push(format!("the {} does not match the {}", left.1, right.1)),
        (Err(cause), _) | (_, Err(cause)) => {
            problems.push(format!("could not compare TCB values: {cause}"));
        }
    }
}

fn check_guest_policy(report: u64, bound: &GuestPolicy, problems: &mut Vec<String>) {
    let policy = match GuestPolicy::parse(report) {
        Ok(policy) => policy,
        Err(cause) => {
            problems.push(format!("could not parse the guest policy: {cause}"));
            return;
        }
    };
    if (bound.abi_major, bound.abi_minor) > (policy.abi_major, policy.abi_minor) {
        problems.push(format!(
            "required guest policy ABI version ({}.{}) is greater than the report's ({}.{})",
            bound.abi_major, bound.abi_minor, policy.abi_major, policy.abi_minor
        ));
        return;
    }
    let unauthorized = [
        (policy.migrate_ma && !bound.migrate_ma, "migration agent"),
        (policy.debug && !bound.debug, "debug"),
        (policy.smt && !bound.smt, "simultaneous multithreading"),
        (policy.cxl_allowed && !bound.cxl_allowed, "CXL"),
    ];
    let missing = [
        (
            bound.single_socket && !policy.single_socket,
            "single socket",
        ),
        (
            bound.mem_aes256_xts && !policy.mem_aes256_xts,
            "AES-256 XTS",
        ),
        (bound.rapl_dis && !policy.rapl_dis, "RAPL disable"),
        (
            bound.ciphertext_hiding_dram && !policy.ciphertext_hiding_dram,
            "ciphertext hiding",
        ),
        (
            bound.page_swap_disable && !policy.page_swap_disable,
            "page swap disable",
        ),
    ];
    for (found, name) in unauthorized {
        if found {
            problems.push(format!("guest policy allows {name}, which is unauthorized"));
        }
    }
    for (absent, name) in missing {
        if absent {
            problems.push(format!(
                "guest policy lacks the required {name} restriction"
            ));
        }
    }
}

fn check_platform_info(report: u64, bound: &PlatformInfo, problems: &mut Vec<String>) {
    let info = match PlatformInfo::parse(report) {
        Ok(info) => info,
        Err(cause) => {
            problems.push(format!("could not parse the platform info: {cause}"));
            return;
        }
    };
    let unauthorized = [
        (info.smt_enabled && !bound.smt_enabled, "SMT"),
        (info.tsme_enabled && !bound.tsme_enabled, "TSME"),
        (info.tio_enabled && !bound.tio_enabled, "SEV-TIO"),
    ];
    let missing = [
        (bound.ecc_enabled && !info.ecc_enabled, "ECC memory"),
        (bound.rapl_disabled && !info.rapl_disabled, "RAPL disabled"),
        (
            bound.ciphertext_hiding_dram && !info.ciphertext_hiding_dram,
            "ciphertext hiding",
        ),
        (
            bound.alias_check_complete && !info.alias_check_complete,
            "completed memory alias check",
        ),
        (
            bound.iommu_write_safe && !info.iommu_write_safe,
            "IOMMU write-safe mitigation",
        ),
    ];
    for (found, name) in unauthorized {
        if found {
            problems.push(format!("unauthorized platform feature {name} is enabled"));
        }
    }
    for (absent, name) in missing {
        if absent {
            problems.push(format!("required platform feature {name} is not present"));
        }
    }
}

fn check_exact(field: &str, given: &[u8], required: Option<&[u8]>, problems: &mut Vec<String>) {
    if required.is_some_and(|required| required != given) {
        problems.push(format!("report field {field} is not the expected value"));
    }
}

fn check_tcb(
    report: &Report,
    certificate: &TcbParts,
    options: &Options,
    problems: &mut Vec<String>,
) {
    let layout = match report_layout(report, certificate.layout) {
        Ok(layout) => layout,
        Err(cause) => {
            problems.push(cause.to_string());
            return;
        }
    };
    let split = |tcb: u64| TcbParts::decompose(layout, tcb);
    let parts = (
        split(report.reported_tcb),
        split(report.current_tcb),
        split(report.committed_tcb),
        split(report.launch_tcb),
    );
    let (reported, current, committed, launch) = match parts {
        (Ok(reported), Ok(current), Ok(committed), Ok(launch)) => {
            (reported, current, committed, launch)
        }
        (reported, current, committed, launch) => {
            for cause in [reported, current, committed, launch]
                .into_iter()
                .filter_map(Result::err)
            {
                problems.push(cause.to_string());
            }
            return;
        }
    };
    let committed = (&committed, "report's COMMITTED_TCB");
    let current = (&current, "report's CURRENT_TCB");
    let reported = (&reported, "report's REPORTED_TCB");
    let launch = (&launch, "report's LAUNCH_TCB");
    let certificate = (certificate, "TCB of the VCEK certificate");
    if options.permit_provisional_firmware {
        at_most(committed, current, problems);
    } else {
        equal(committed, current, problems);
    }
    at_most(
        (&options.minimum_launch_tcb, "policy minimum launch TCB"),
        launch,
        problems,
    );
    equal(reported, certificate, problems);
    at_most(certificate, current, problems);
    at_most(
        (&options.minimum_tcb, "policy minimum TCB"),
        reported,
        problems,
    );
}

fn check_firmware(report: &Report, options: &Options, problems: &mut Vec<String>) {
    if options.minimum_build > report.current_build {
        problems.push(format!(
            "firmware build number {} is less than the required minimum {}",
            report.current_build, options.minimum_build
        ));
        return;
    }
    let current = u16::from_be_bytes([report.current_major, report.current_minor]);
    let committed = u16::from_be_bytes([report.committed_major, report.committed_minor]);
    if options.minimum_version > current {
        problems.push(format!(
            "firmware API version ({}.{}) is less than the required minimum ({}.{})",
            report.current_major,
            report.current_minor,
            options.minimum_version >> 8,
            options.minimum_version & 0xff
        ));
        return;
    }
    let (build_ok, version_ok) = if options.permit_provisional_firmware {
        (
            report.committed_build <= report.current_build,
            committed <= current,
        )
    } else {
        (
            report.committed_build == report.current_build,
            committed == current,
        )
    };
    if !build_ok {
        problems.push(format!(
            "committed build number {} is not consistent with the current build number {}",
            report.committed_build, report.current_build
        ));
    } else if !version_ok {
        problems.push(format!(
            "committed API version ({}.{}) is not consistent with the current API version ({}.{})",
            report.committed_major,
            report.committed_minor,
            report.current_major,
            report.current_minor
        ));
    }
}

/// The CHIP_ID must be the certificate's hardware identifier: the whole
/// field for a 64-byte identifier, its first 8 bytes for an 8-byte one. An
/// all-zero CHIP_ID is not compared.
fn check_chip_id(chip_id: &[u8; CHIP_ID_SIZE], hwid: &[u8]) -> Result<(), AssemblyError> {
    if chip_id.iter().all(|byte| *byte == 0) {
        return Ok(());
    }
    let compared: &[u8] = match hwid.len() {
        HWID_SIZE_V0 => chip_id,
        HWID_SIZE_V1 => chip_id.get(..HWID_SIZE_V1).unwrap_or_default(),
        other => {
            return Err(AssemblyError::new(format!(
                "VCEK certificate hardware identifier has unsupported size {other}"
            )));
        }
    };
    if compared != hwid {
        return Err(AssemblyError::new(
            "report field CHIP_ID is not the VCEK certificate's hardware identifier",
        ));
    }
    Ok(())
}

/// Validates an authenticated report against options.
///
/// `extensions` are those of the VCEK that signed the report; a report
/// that names another signing key is an error. In order:
///
/// 1. the guest SVN is at least the minimum;
/// 2. all of the following hold:
///    - guest policy: the report's ABI version is at least the bound's;
///      migration agent, debug, SMT and CXL are set only if the bound sets
///      them; single socket, AES-256 XTS, RAPL disable, ciphertext hiding
///      and page swap disable are set if the bound sets them;
///    - REPORT_DATA, MEASUREMENT and CHIP_ID equal the options';
///      HOST_DATA, IMAGE_ID and FAMILY_ID equal the options' where given;
///    - TCB, with every version of the report split by the layout of its
///      chip, which must be the certificate's layout
///      ([`TcbParts::decompose`]): the committed TCB equals the current
///      one, or with provisional firmware permitted is at most it; the
///      launch TCB is at least its floor; the reported TCB equals the
///      certificate's; the certificate's TCB is at most the current one;
///      the reported TCB is at least its floor. "At most" is
///      [`TcbParts::all_at_most`]; "equals" also requires that both sides
///      are valid TCB versions ([`TcbParts::compose`]);
///    - firmware: the current build and API version are at least the
///      minimums; the committed build and API version equal the current
///      ones, or with provisional firmware permitted are at most them;
///    - platform info: SMT, TSME and SEV-TIO are enabled only if the
///      bound has them; ECC, RAPL disabled, ciphertext hiding, alias check
///      complete and IOMMU write-safe are present if the bound has them;
///    - each mitigation vector has every bit of its minimum set;
/// 3. the VMPL equals the options';
/// 4. the CHIP_ID is the certificate's hardware identifier: the whole
///    field for a 64-byte identifier, its first 8 bytes for an 8-byte one.
///    An all-zero CHIP_ID skips this comparison.
pub fn validate(
    report: &Report,
    extensions: &Extensions,
    options: &Options,
) -> Result<(), AssemblyError> {
    if report.signer_info.signing_key != SigningKey::Vcek {
        return Err(AssemblyError::new(
            "report is not signed by a VCEK; no other signing key is supported",
        ));
    }
    if report.guest_svn < options.minimum_guest_svn {
        return Err(AssemblyError::new(format!(
            "report's GUEST_SVN {} is less than the required minimum {}",
            report.guest_svn, options.minimum_guest_svn
        )));
    }

    let mut problems = Vec::new();
    check_guest_policy(report.policy, &options.guest_policy, &mut problems);
    check_exact(
        "REPORT_DATA",
        &report.report_data,
        Some(&options.report_data),
        &mut problems,
    );
    check_exact(
        "HOST_DATA",
        &report.host_data,
        options
            .host_data
            .as_ref()
            .map(<[u8; HOST_DATA_SIZE]>::as_slice),
        &mut problems,
    );
    check_exact(
        "FAMILY_ID",
        &report.family_id,
        options.family_id.as_ref().map(<[u8; ID_SIZE]>::as_slice),
        &mut problems,
    );
    check_exact(
        "IMAGE_ID",
        &report.image_id,
        options.image_id.as_ref().map(<[u8; ID_SIZE]>::as_slice),
        &mut problems,
    );
    check_exact(
        "MEASUREMENT",
        &report.measurement,
        Some(&options.measurement),
        &mut problems,
    );
    check_exact(
        "CHIP_ID",
        &report.chip_id,
        Some(&options.chip_id),
        &mut problems,
    );
    check_tcb(report, &extensions.tcb, options, &mut problems);
    check_firmware(report, options, &mut problems);
    check_platform_info(report.platform_info, &options.platform_info, &mut problems);
    for (name, vector, minimum) in [
        (
            "launch",
            report.launch_mitigation_vector,
            options.minimum_launch_mitigation_vector,
        ),
        (
            "current",
            report.current_mitigation_vector,
            options.minimum_current_mitigation_vector,
        ),
    ] {
        if vector & minimum != minimum {
            problems.push(format!(
                "{name} mitigation vector ({vector:#x}) is missing required bits; expected at least ({minimum:#x})"
            ));
        }
    }
    if !problems.is_empty() {
        return Err(AssemblyError::new(problems.join("; ")));
    }

    if options.vmpl != report.vmpl {
        return Err(AssemblyError::new(format!(
            "report VMPL {} is not {}",
            report.vmpl, options.vmpl
        )));
    }
    check_chip_id(&report.chip_id, &extensions.hwid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::sev::lib::abi::testdata::blank_report;
    use crate::quote::sev::lib::kds::HWID_SIZE_V0;

    /// A change to a value in place.
    type Change<T> = fn(&mut T);

    const GOOD_TCB: u64 = 0x9270_0000_0000_7f1f;
    const TURIN_TCB: u64 = 0x5200_0000_0401_0101;
    const TURIN_HWID: [u8; 8] = [0x6b, 0xb1, 0x22, 0x9b, 0x76, 0x92, 0xb7, 0x10];

    /// A version 3 Genoa report with SMT and debug allowed, SMT enabled,
    /// firmware 1.49 build 2, and every TCB the same.
    fn report(change: impl FnOnce(&mut Vec<u8>)) -> Report {
        let mut bytes = blank_report(3);
        bytes[0x08..0x10].copy_from_slice(&0x000b_0000u64.to_le_bytes());
        bytes[0x40] = 1;
        bytes[0x188..0x18B].copy_from_slice(&[0x19, 0x11, 0x00]);
        for offset in [0x38, 0x180, 0x1E0, 0x1F0] {
            bytes[offset..offset + 8].copy_from_slice(&GOOD_TCB.to_le_bytes());
        }
        bytes[0x1E8..0x1EB].copy_from_slice(&[2, 49, 1]);
        bytes[0x1EC..0x1EF].copy_from_slice(&[2, 49, 1]);
        bytes[0x50] = 0x12;
        bytes[0x90] = 0x34;
        bytes[0xC0] = 0x56;
        bytes[0x10] = 0x78;
        bytes[0x20] = 0x9a;
        bytes[0x1A0..0x1E0].copy_from_slice(&[0x5a; 64]);
        change(&mut bytes);
        Report::parse(&bytes).unwrap()
    }

    fn turin_report(change: impl FnOnce(&mut Vec<u8>)) -> Report {
        report(|bytes| {
            bytes[0x188..0x18B].copy_from_slice(&[0x1A, 0x02, 0x00]);
            for offset in [0x38, 0x180, 0x1E0, 0x1F0] {
                bytes[offset..offset + 8].copy_from_slice(&TURIN_TCB.to_le_bytes());
            }
            bytes[0x1A0..0x1E0].fill(0);
            bytes[0x1A0..0x1A8].copy_from_slice(&TURIN_HWID);
            change(bytes);
        })
    }

    fn extensions(layout: TcbLayout, tcb: u64, hwid: &[u8]) -> Extensions {
        Extensions {
            product_name: String::new(),
            hwid: hwid.to_vec(),
            tcb: TcbParts::decompose(layout, tcb).unwrap(),
        }
    }

    fn genoa_extensions() -> Extensions {
        extensions(TcbLayout::V0, GOOD_TCB, &[0x5a; HWID_SIZE_V0])
    }

    fn turin_extensions() -> Extensions {
        extensions(TcbLayout::V1, TURIN_TCB, &TURIN_HWID)
    }

    /// Options that the base report satisfies with nothing to spare.
    fn options(report: &Report, layout: TcbLayout) -> Options {
        let floor = TcbParts::decompose(layout, 0).unwrap();
        Options {
            guest_policy: GuestPolicy {
                smt: true,
                debug: true,
                ..GuestPolicy::default()
            },
            minimum_guest_svn: 0,
            minimum_build: 0,
            minimum_version: 0,
            minimum_tcb: floor,
            minimum_launch_tcb: floor,
            permit_provisional_firmware: false,
            platform_info: PlatformInfo {
                smt_enabled: true,
                ..PlatformInfo::default()
            },
            vmpl: 0,
            report_data: report.report_data,
            measurement: report.measurement,
            chip_id: report.chip_id,
            host_data: None,
            image_id: None,
            family_id: None,
            minimum_launch_mitigation_vector: 0,
            minimum_current_mitigation_vector: 0,
        }
    }

    fn check(
        report: &Report,
        extensions: &Extensions,
        change: impl FnOnce(&mut Options),
    ) -> Result<(), String> {
        let mut options = options(report, extensions.tcb.layout);
        change(&mut options);
        validate(report, extensions, &options).map_err(|error| error.to_string())
    }

    fn rejected(result: Result<(), String>, want: &str) {
        let error = result.unwrap_err();
        assert!(error.contains(want), "{error}");
    }

    #[test]
    fn a_report_that_meets_every_option_validates() {
        let base = report(|_| {});
        check(&base, &genoa_extensions(), |_| {}).unwrap();
        check(&base, &genoa_extensions(), |options| {
            options.minimum_build = 2;
            options.minimum_version = (1 << 8) | 49;
            options.minimum_tcb = TcbParts::decompose(TcbLayout::V0, GOOD_TCB).unwrap();
            options.minimum_launch_tcb = options.minimum_tcb;
            options.host_data = Some(base.host_data);
            options.image_id = Some(base.image_id);
            options.family_id = Some(base.family_id);
        })
        .unwrap();
        let turin = turin_report(|_| {});
        check(&turin, &turin_extensions(), |_| {}).unwrap();
    }

    #[test]
    fn the_guest_svn_is_a_floor() {
        let base = report(|bytes| bytes[0x04] = 5);
        for (minimum, accepted) in [(4, true), (5, true), (6, false)] {
            let result = check(&base, &genoa_extensions(), |options| {
                options.minimum_guest_svn = minimum;
            });
            assert_eq!(result.is_ok(), accepted, "{minimum}");
        }
    }

    #[test]
    fn the_firmware_build_and_version_are_floors() {
        let base = report(|_| {});
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_build = 3
            }),
            "firmware build number 2 is less than the required minimum 3",
        );
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_version = 0xff00;
            }),
            "firmware API version (1.49) is less than the required minimum (255.0)",
        );
        for (version, accepted) in [
            (0x0131, true),
            (0x0132, false),
            (0x00ff, true),
            (0x0200, false),
        ] {
            let result = check(&base, &genoa_extensions(), |options| {
                options.minimum_version = version;
            });
            assert_eq!(result.is_ok(), accepted, "{version:#x}");
        }
    }

    #[test]
    fn the_tcb_floors_compare_level_by_level() {
        let base = report(|_| {});
        let floor = |change: fn(&mut TcbParts)| {
            let mut floor = TcbParts::decompose(TcbLayout::V0, GOOD_TCB).unwrap();
            change(&mut floor);
            floor
        };
        check(&base, &genoa_extensions(), |options| {
            options.minimum_tcb = floor(|floor| floor.ucode_spl = 0x44);
        })
        .unwrap();
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_tcb = floor(|floor| floor.ucode_spl = 0xff);
            }),
            "report's REPORTED_TCB is lower than the policy minimum TCB",
        );
        // One level above, another below: still not at least the floor.
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_tcb = floor(|floor| {
                    floor.ucode_spl = 0;
                    floor.snp_spl = 0x71;
                });
            }),
            "REPORTED_TCB",
        );
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_launch_tcb = floor(|floor| floor.snp_spl = 0x71);
            }),
            "report's LAUNCH_TCB is lower than the policy minimum launch TCB",
        );
        // A floor of another layout is never met.
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.minimum_tcb = TcbParts::decompose(TcbLayout::V1, 0).unwrap();
            }),
            "REPORTED_TCB",
        );
    }

    #[test]
    fn committed_firmware_older_than_current_needs_permission() {
        let cases: [(Change<Vec<u8>>, &str); 3] = [
            (|bytes| bytes[0x1EC] = 1, "committed build number 1"),
            (
                |bytes| bytes[0x1E9] = 51,
                "committed API version (1.49) is not consistent with the current API version (1.51)",
            ),
            (
                |bytes| {
                    // Committed and launch TCB with a lower bootloader level.
                    bytes[0x1E0] = 0;
                    bytes[0x1F0] = 0;
                },
                "report's COMMITTED_TCB does not match the report's CURRENT_TCB",
            ),
        ];
        for (change, want) in cases {
            let provisional = report(change);
            rejected(check(&provisional, &genoa_extensions(), |_| {}), want);
            check(&provisional, &genoa_extensions(), |options| {
                options.permit_provisional_firmware = true;
            })
            .unwrap();
        }
        // Committed firmware newer than current is never accepted.
        let cases: [Change<Vec<u8>>; 3] = [
            |bytes| bytes[0x1EC] = 3,
            |bytes| bytes[0x1ED] = 50,
            |bytes| bytes[0x1E7] = 0x93,
        ];
        for change in cases {
            let newer = report(change);
            for permitted in [false, true] {
                let result = check(&newer, &genoa_extensions(), |options| {
                    options.permit_provisional_firmware = permitted;
                });
                assert!(result.is_err(), "{permitted}");
            }
        }
    }

    #[test]
    fn the_reported_tcb_is_the_certificates() {
        let base = report(|_| {});
        let other = extensions(TcbLayout::V0, GOOD_TCB - 1, &[0x5a; HWID_SIZE_V0]);
        rejected(
            check(&base, &other, |_| {}),
            "report's REPORTED_TCB does not match the TCB of the VCEK certificate",
        );
        // Reported and certified below current is consistent.
        let lower = report(|bytes| bytes[0x180] -= 1);
        check(&lower, &other, |_| {}).unwrap();
        // Certified above current is not.
        let behind = report(|bytes| {
            bytes[0x38] -= 1;
            bytes[0x1E0] -= 1;
        });
        rejected(
            check(&behind, &genoa_extensions(), |_| {}),
            "report's CURRENT_TCB is lower than the TCB of the VCEK certificate",
        );
    }

    #[test]
    fn equal_tcbs_must_also_be_valid_ones() {
        // A level above 127 in the committed and current TCB.
        let high = report(|bytes| {
            bytes[0x38] = 0x80;
            bytes[0x1E0] = 0x80;
        });
        rejected(
            check(&high, &genoa_extensions(), |_| {}),
            "could not compare TCB values",
        );
        check(&high, &genoa_extensions(), |options| {
            options.permit_provisional_firmware = true;
        })
        .unwrap();
    }

    #[test]
    fn the_report_is_read_with_the_layout_of_its_chip() {
        let cpuid = |family: u8, model: u8| {
            report(move |bytes| {
                bytes[0x188] = family;
                bytes[0x189] = model;
                for offset in [0x38, 0x180, 0x1E0, 0x1F0] {
                    bytes[offset..offset + 8].fill(0);
                }
            })
        };
        let older = extensions(TcbLayout::V0, 0, &[0x5a; HWID_SIZE_V0]);
        let newer = extensions(TcbLayout::V1, 0, &[0x5a; 8]);
        // Family 19h, any of its three product lines.
        for model in [0x01, 0x11, 0xA0] {
            check(&cpuid(0x19, model), &older, |_| {}).unwrap();
            rejected(
                check(&cpuid(0x19, model), &newer, |_| {}),
                "different TCB layouts",
            );
        }
        // Family 1Ah, extended model 0 or 1.
        for model in [0x02, 0x10] {
            check(&cpuid(0x1A, model), &newer, |_| {}).unwrap();
            rejected(
                check(&cpuid(0x1A, model), &older, |_| {}),
                "different TCB layouts",
            );
        }
        for (family, model) in [(0x18, 0x00), (0x19, 0x20), (0x1A, 0x20), (0x1B, 0x02)] {
            rejected(
                check(&cpuid(family, model), &older, |_| {}),
                "could not determine the report's TCB layout",
            );
        }
        // A report without the CPUID field has the older layout.
        let version_2 = report(|bytes| {
            bytes[0] = 2;
            bytes[0x188..0x18B].fill(0);
        });
        check(&version_2, &genoa_extensions(), |_| {}).unwrap();
        let newer_certificate = extensions(TcbLayout::V1, 0, &[0x5a; 8]);
        rejected(
            check(&version_2, &newer_certificate, |_| {}),
            "different TCB layouts",
        );
        let version_3_without = report(|bytes| bytes[0x188..0x18B].fill(0));
        rejected(
            check(&version_3_without, &genoa_extensions(), |_| {}),
            "no CPUID",
        );
    }

    #[test]
    fn reserved_tcb_bits_of_the_newer_layout_are_rejected() {
        for offset in [0x38, 0x180, 0x1E0, 0x1F0] {
            let reserved = turin_report(|bytes| bytes[offset + 4] = 1);
            rejected(
                check(&reserved, &turin_extensions(), |_| {}),
                "reserved bits",
            );
        }
    }

    #[test]
    fn the_guest_policy_is_a_bound() {
        let bit = |index: u32| {
            report(move |bytes| {
                let policy = 0x000b_0000u64 | (1 << index);
                bytes[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
            })
        };
        // Flags that widen what is allowed need the bound's permission.
        let widening: [(u32, Change<GuestPolicy>); 2] = [
            (18, |bound| bound.migrate_ma = true),
            (21, |bound| bound.cxl_allowed = true),
        ];
        for (index, allow) in widening {
            rejected(
                check(&bit(index), &genoa_extensions(), |_| {}),
                "unauthorized",
            );
            check(&bit(index), &genoa_extensions(), |options| {
                allow(&mut options.guest_policy)
            })
            .unwrap();
        }
        let base = report(|_| {});
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.guest_policy.debug = false
            }),
            "allows debug",
        );
        rejected(
            check(&base, &genoa_extensions(), |options| {
                options.guest_policy.smt = false
            }),
            "allows simultaneous multithreading",
        );
        // Flags that restrict are required when the bound has them.
        let restricting: [(u32, Change<GuestPolicy>); 5] = [
            (20, |bound| bound.single_socket = true),
            (22, |bound| bound.mem_aes256_xts = true),
            (23, |bound| bound.rapl_dis = true),
            (24, |bound| bound.ciphertext_hiding_dram = true),
            (25, |bound| bound.page_swap_disable = true),
        ];
        for (index, require) in restricting {
            check(&bit(index), &genoa_extensions(), |_| {}).unwrap();
            check(&bit(index), &genoa_extensions(), |options| {
                require(&mut options.guest_policy);
            })
            .unwrap();
            rejected(
                check(&base, &genoa_extensions(), |options| {
                    require(&mut options.guest_policy);
                }),
                "lacks the required",
            );
        }
    }

    #[test]
    fn the_guest_abi_version_is_a_floor() {
        let abi = report(|bytes| bytes[0x08..0x0A].copy_from_slice(&[31, 1]));
        for ((major, minor), accepted) in [
            ((1, 30), true),
            ((1, 31), true),
            ((1, 32), false),
            ((0, 255), true),
            ((2, 0), false),
        ] {
            let result = check(&abi, &genoa_extensions(), |options| {
                options.guest_policy.abi_major = major;
                options.guest_policy.abi_minor = minor;
            });
            assert_eq!(result.is_ok(), accepted, "{major}.{minor}");
        }
    }

    #[test]
    fn the_platform_info_is_a_bound() {
        let info = |value: u8| report(move |bytes| bytes[0x40] = value);
        rejected(
            check(&info(1), &genoa_extensions(), |options| {
                options.platform_info = PlatformInfo::default();
            }),
            "unauthorized platform feature SMT",
        );
        let enabling: [(u8, Change<PlatformInfo>); 2] = [
            (1 << 1, |bound| bound.tsme_enabled = true),
            (1 << 7, |bound| bound.tio_enabled = true),
        ];
        for (bit, allow) in enabling {
            rejected(
                check(&info(1 | bit), &genoa_extensions(), |_| {}),
                "unauthorized",
            );
            check(&info(1 | bit), &genoa_extensions(), |options| {
                allow(&mut options.platform_info);
            })
            .unwrap();
        }
        let protecting: [(u8, Change<PlatformInfo>); 5] = [
            (1 << 2, |bound| bound.ecc_enabled = true),
            (1 << 3, |bound| bound.rapl_disabled = true),
            (1 << 4, |bound| bound.ciphertext_hiding_dram = true),
            (1 << 5, |bound| bound.alias_check_complete = true),
            (1 << 6, |bound| bound.iommu_write_safe = true),
        ];
        for (bit, require) in protecting {
            check(&info(1 | bit), &genoa_extensions(), |_| {}).unwrap();
            check(&info(1 | bit), &genoa_extensions(), |options| {
                require(&mut options.platform_info);
            })
            .unwrap();
            rejected(
                check(&info(1), &genoa_extensions(), |options| {
                    require(&mut options.platform_info);
                }),
                "required platform feature",
            );
        }
        let reserved = report(|bytes| bytes[0x41] = 1);
        rejected(
            check(&reserved, &genoa_extensions(), |_| {}),
            "unrecognized platform info bits",
        );
    }

    #[test]
    fn exact_fields_must_match() {
        let base = report(|_| {});
        let changes: [(&str, Change<Options>); 6] = [
            ("REPORT_DATA", |options| options.report_data = [0; 64]),
            ("HOST_DATA", |options| options.host_data = Some([0; 32])),
            ("FAMILY_ID", |options| options.family_id = Some([0; 16])),
            ("IMAGE_ID", |options| options.image_id = Some([0; 16])),
            ("MEASUREMENT", |options| options.measurement = [0; 48]),
            ("CHIP_ID", |options| options.chip_id = [0; 64]),
        ];
        for (field, change) in changes {
            rejected(
                check(&base, &genoa_extensions(), change),
                &format!("report field {field}"),
            );
        }
    }

    #[test]
    fn the_vmpl_is_exact() {
        let base = report(|bytes| bytes[0x30] = 2);
        for (vmpl, accepted) in [(0, false), (1, false), (2, true), (3, false)] {
            let result = check(&base, &genoa_extensions(), |options| options.vmpl = vmpl);
            assert_eq!(result.is_ok(), accepted, "{vmpl}");
        }
    }

    #[test]
    fn mitigation_vectors_must_have_every_required_bit() {
        let vectors = |launch: u8, current: u8| {
            report(move |bytes| {
                bytes[0x1F8] = launch;
                bytes[0x200] = current;
            })
        };
        let cases = [
            ((0x0, 0x0), (0x0, 0x0), None),
            ((0x3, 0x1), (0x3, 0x1), None),
            ((0x7, 0xF), (0x3, 0x1), None),
            ((0x1, 0x3), (0x3, 0x0), Some("launch mitigation vector")),
            ((0x3, 0x4), (0x0, 0x5), Some("current mitigation vector")),
        ];
        for ((launch, current), (minimum_launch, minimum_current), want) in cases {
            let result = check(&vectors(launch, current), &genoa_extensions(), |options| {
                options.minimum_launch_mitigation_vector = minimum_launch;
                options.minimum_current_mitigation_vector = minimum_current;
            });
            match want {
                None => result.unwrap(),
                Some(want) => rejected(result, want),
            }
        }
    }

    #[test]
    fn the_chip_id_is_the_certificates_hardware_identifier() {
        let mut turin = [0u8; CHIP_ID_SIZE];
        turin[..8].copy_from_slice(&TURIN_HWID);
        let legacy = [0x5a; CHIP_ID_SIZE];
        check_chip_id(&turin, &TURIN_HWID).unwrap();
        check_chip_id(&legacy, &legacy).unwrap();
        // An all-zero CHIP_ID is not compared.
        check_chip_id(&[0; CHIP_ID_SIZE], &TURIN_HWID).unwrap();
        let error = check_chip_id(&turin, &[0xff; 8]).unwrap_err();
        assert!(error.to_string().contains("is not the VCEK"), "{error}");
        let error = check_chip_id(&turin, &[0; 7]).unwrap_err();
        assert!(error.to_string().contains("unsupported size 7"), "{error}");
        // Only the first 8 bytes are compared with an 8-byte identifier.
        let mut tail = turin;
        tail[8] = 1;
        tail[63] = 1;
        check_chip_id(&tail, &TURIN_HWID).unwrap();
        let mut head = turin;
        head[7] ^= 1;
        assert!(check_chip_id(&head, &TURIN_HWID).is_err());
        let mut other = legacy;
        other[63] ^= 1;
        assert!(check_chip_id(&other, &legacy).is_err());

        let report = turin_report(|bytes| bytes[0x1A0] ^= 1);
        rejected(
            check(&report, &turin_extensions(), |_| {}),
            "is not the VCEK",
        );
    }

    #[test]
    fn a_report_signed_by_another_key_is_unsupported() {
        for signer_info in [1u8 << 2, 7 << 2] {
            let report = report(|bytes| bytes[0x48] = signer_info);
            rejected(
                check(&report, &genoa_extensions(), |_| {}),
                "not signed by a VCEK",
            );
        }
    }
}
