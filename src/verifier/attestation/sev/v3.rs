//! Offline V3 CPU evidence appraisal matching Tinfoil Go's SEV verifier.
//!
//! The caller authenticates the platform endorsement and selects the machine
//! policy using CHIP_ID from this same report. This module authenticates that
//! report under pinned AMD roots, checks fresh revocation collateral, and
//! enforces the complete endorsed SEV policy. It never fetches collateral.
use super::{
    cert_chain,
    product::{Product, Tcb},
    report, signature,
};
use crate::error::{Error, Result};
use crate::verifier::attestation::{
    constants::*,
    types::{Measurement, PredicateType},
};
use serde::Deserialize;
use serde_json::Value;

/// Untrusted document-carried AMD evidence. None of its fields is a trust anchor.
#[derive(Debug, Clone, Copy)]
pub struct Evidence<'a> {
    pub report: &'a [u8],
    pub vcek_der: &'a [u8],
    pub cert_chain_pem: &'a [u8],
    pub crl_der: &'a [u8],
}

/// Authenticate and appraise CPU evidence. `policy` must be the selected
/// SEV-SNP block from an independently verified Tinfoil platform endorsement.
/// `expected_report_data` is the standard V3 SHA-256 envelope binding followed
/// by 32 zero bytes, computed by the envelope verifier from the domain, nonce,
/// attested crypto material, and device-evidence digests.
pub fn verify_evidence(
    ev: Evidence<'_>,
    expected_report_data: &[u8; 64],
    policy: &Value,
) -> Result<Measurement> {
    if ev.report.len() != REPORT_SIZE {
        return Err(err("SEV report must be exactly 1184 bytes"));
    }
    report::validate_report_structure(ev.report)?;
    let product = Product::from_report(ev.report, true)?;
    validate_format(ev.report, product)?;
    cert_chain::verify_cert_chain_crypto_for_product(ev.vcek_der, ev.cert_chain_pem, product)?;
    // Go appraises revocation against the repository-pinned intermediate,
    // never a serial number chosen by the untrusted document.
    cert_chain::verify_crl(ev.crl_der, product.chain())?;
    let cert_tcb = cert_chain::vcek_tcb_for_product(ev.vcek_der, product)?;
    cert_chain::validate_vcek_hwid_for_product(
        ev.vcek_der,
        &ev.report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE],
        product,
    )?;
    signature::verify_report_signature(ev.report, ev.vcek_der)?;
    let policy = parse_policy(policy)?;
    validate_fields(ev.report, expected_report_data, &policy, product, cert_tcb)?;
    Ok(Measurement {
        type_: PredicateType::SevGuestV2,
        registers: vec![hex::encode(
            &ev.report[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_SIZE],
        )],
    })
}

/// Validate every SEV policy in a signed platform artifact, including entries
/// that do not correspond to the current machine. Product-specific checks are
/// applied during evidence appraisal after CPUID is authenticated.
pub(crate) fn validate_policy(policy: &Value) -> Result<()> {
    parse_policy(policy).map(|_| ())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    minimum_build: u8,
    minimum_api_version: String,
    minimum_abi_version: String,
    minimum_guest_svn: u32,
    minimum_tcb: PolicyTcb,
    minimum_launch_tcb: PolicyTcb,
    guest_policy: GuestPolicy,
    platform_info: PlatformInfo,
    #[serde(default)]
    permit_provisional_firmware: bool,
    vmpl: u8,
    #[serde(default)]
    host_data: String,
    image_id: String,
    family_id: String,
    #[serde(default)]
    require_author_key: bool,
    #[serde(default)]
    require_id_block: bool,
    minimum_launch_mitigation_vector: u64,
    minimum_current_mitigation_vector: u64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTcb {
    #[serde(default)]
    fmc_spl: Option<u8>,
    bl_spl: u8,
    tee_spl: u8,
    snp_spl: u8,
    ucode_spl: u8,
}
impl PolicyTcb {
    fn parts(&self, product: Product) -> Result<Tcb> {
        if self.fmc_spl.is_some() != (product == Product::Turin) {
            return Err(err(
                "Policy FMC SPL layout does not match signed CPU product",
            ));
        }
        self.validate()?;
        Ok(Tcb {
            fmc: self.fmc_spl,
            bl: self.bl_spl,
            tee: self.tee_spl,
            snp: self.snp_spl,
            ucode: self.ucode_spl,
        })
    }
    fn validate(&self) -> Result<()> {
        if [
            self.fmc_spl.unwrap_or(0),
            self.bl_spl,
            self.tee_spl,
            self.snp_spl,
        ]
        .iter()
        .any(|n| *n > 127)
        {
            return Err(err("Policy SPL exceeds AMD 7-bit range"));
        }
        Ok(())
    }
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GuestPolicy {
    debug: bool,
    smt: bool,
    migrate_ma: bool,
    single_socket: bool,
    cxl_allowed: bool,
    mem_aes256_xts: bool,
    rapl_dis: bool,
    ciphertext_hiding_dram: bool,
    page_swap_disable: bool,
}
impl GuestPolicy {
    fn bits(&self) -> u64 {
        (1 << 17)
            | ((self.smt as u64) << 16)
            | ((self.migrate_ma as u64) << 18)
            | ((self.debug as u64) << 19)
            | ((self.single_socket as u64) << 20)
            | ((self.cxl_allowed as u64) << 21)
            | ((self.mem_aes256_xts as u64) << 22)
            | ((self.rapl_dis as u64) << 23)
            | ((self.ciphertext_hiding_dram as u64) << 24)
            | ((self.page_swap_disable as u64) << 25)
    }
}
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PlatformInfo {
    smt_enabled: bool,
    tsme_enabled: bool,
    ecc_enabled: bool,
    rapl_disabled: bool,
    ciphertext_hiding_dram: bool,
    alias_check_complete: bool,
    iommu_write_safe: bool,
    tio_enabled: bool,
}
impl PlatformInfo {
    fn bits(&self) -> u64 {
        self.smt_enabled as u64
            | ((self.tsme_enabled as u64) << 1)
            | ((self.ecc_enabled as u64) << 2)
            | ((self.rapl_disabled as u64) << 3)
            | ((self.ciphertext_hiding_dram as u64) << 4)
            | ((self.alias_check_complete as u64) << 5)
            | ((self.iommu_write_safe as u64) << 6)
            | ((self.tio_enabled as u64) << 7)
    }
}
fn parse_policy(value: &Value) -> Result<Policy> {
    let p: Policy = serde_json::from_value(value.clone())
        .map_err(|e| Error::AttestationVerification(format!("Invalid endorsed SEV policy: {e}")))?;
    if p.vmpl > 3 || p.require_author_key || p.require_id_block {
        return Err(err("Unsupported SEV VMPL/ID-block/author-key policy"));
    }
    version(&p.minimum_api_version)?;
    version(&p.minimum_abi_version)?;
    p.minimum_tcb.validate()?;
    p.minimum_launch_tcb.validate()?;
    if !p.host_data.is_empty() {
        decode_hex(&p.host_data, 32)?;
    }
    decode_hex(&p.image_id, 16)?;
    decode_hex(&p.family_id, 16)?;
    Ok(p)
}
fn version(value: &str) -> Result<u16> {
    let (major, minor) = value
        .split_once('.')
        .ok_or_else(|| err("SEV version must be maj.min"))?;
    if [major, minor]
        .iter()
        .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(err("SEV version must contain decimal maj.min"));
    }
    let major: u8 = major
        .parse()
        .map_err(|_| err("SEV version major exceeds u8"))?;
    let minor: u8 = minor
        .parse()
        .map_err(|_| err("SEV version minor exceeds u8"))?;
    Ok((major as u16) << 8 | minor as u16)
}
fn decode_hex(value: &str, size: usize) -> Result<Vec<u8>> {
    if value.len() != size * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(err("SEV policy hex must be lowercase and exact length"));
    }
    hex::decode(value).map_err(|_| err("Invalid SEV policy hex"))
}
fn u64at(report: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(report[offset..offset + 8].try_into().unwrap())
}
fn u32at(report: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(report[offset..offset + 4].try_into().unwrap())
}
fn err(message: &str) -> Error {
    Error::AttestationVerification(message.into())
}

fn validate_format(r: &[u8], product: Product) -> Result<()> {
    // Only VCEK, no masked chip identity or author-key/ID-block launch.
    if u32at(r, SIGNER_INFO_OFFSET) != 0 {
        return Err(err("SEV signer must be unmasked VCEK with no author key"));
    }
    if u32at(r, SIGNATURE_ALGO_OFFSET) != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
        return Err(err("SEV signature algorithm must be ECDSA P-384 SHA-384"));
    }
    let policy = u64at(r, POLICY_OFFSET);
    if policy & POLICY_RESERVED_BIT_17 == 0 || policy >> 26 != 0 {
        return Err(err("Malformed SEV guest policy reserved bits"));
    }
    for (start, end) in [
        (0x4c, 0x50),
        (0xe0, 0x140),
        (0x18b, 0x1a0),
        (0x1eb, 0x1ec),
        (0x1ef, 0x1f0),
        (if u32at(r, 0) >= 5 { 0x208 } else { 0x1f8 }, 0x2a0),
        (SIGNATURE_OFFSET + ECDSA_P384_SIGNATURE_SIZE, REPORT_SIZE),
    ] {
        report::validate_mbz_bytes(r, start, end, "V3 reserved/ID-block field")?;
    }
    for offset in [
        CURRENT_TCB_OFFSET,
        REPORTED_TCB_OFFSET,
        COMMITTED_TCB_OFFSET,
        LAUNCH_TCB_OFFSET,
    ] {
        product.tcb(u64at(r, offset))?;
    }
    Ok(())
}
fn validate_fields(
    r: &[u8],
    expected: &[u8; 64],
    p: &Policy,
    product: Product,
    certificate: Tcb,
) -> Result<()> {
    if p.platform_info.iommu_write_safe != (product == Product::Turin) {
        return Err(err(
            "Policy IOMMU_WRITE_SAFE setting does not match CPU product",
        ));
    }
    let min_tcb = p.minimum_tcb.parts(product)?;
    let min_launch = p.minimum_launch_tcb.parts(product)?;
    let reported = product.tcb(u64at(r, REPORTED_TCB_OFFSET))?;
    let current = product.tcb(u64at(r, CURRENT_TCB_OFFSET))?;
    let committed = product.tcb(u64at(r, COMMITTED_TCB_OFFSET))?;
    let launch = product.tcb(u64at(r, LAUNCH_TCB_OFFSET))?;
    if reported != certificate
        || !certificate.le(current)
        || !min_tcb.le(reported)
        || !min_launch.le(launch)
    {
        return Err(err(
            "SEV TCB certificate/report/endorsed minimum relationship failed",
        ));
    }
    if if p.permit_provisional_firmware {
        !committed.le(current)
    } else {
        committed != current
    } {
        return Err(err("SEV committed/current TCB relationship failed"));
    }
    let current_version = (r[CURRENT_MAJOR_OFFSET] as u16) << 8 | r[CURRENT_MINOR_OFFSET] as u16;
    let committed_version =
        (r[COMMITTED_MAJOR_OFFSET] as u16) << 8 | r[COMMITTED_MINOR_OFFSET] as u16;
    let minimum_version = version(&p.minimum_api_version)?;
    if current_version < minimum_version || r[CURRENT_BUILD_OFFSET] < p.minimum_build {
        return Err(err("SEV firmware API/build is below endorsed minimum"));
    }
    if if p.permit_provisional_firmware {
        committed_version > current_version || r[COMMITTED_BUILD_OFFSET] > r[CURRENT_BUILD_OFFSET]
    } else {
        committed_version != current_version || r[COMMITTED_BUILD_OFFSET] != r[CURRENT_BUILD_OFFSET]
    } {
        return Err(err(
            "SEV committed/current firmware version relationship failed",
        ));
    }
    let guest = u64at(r, POLICY_OFFSET);
    if (guest as u16) < version(&p.minimum_abi_version)? || guest & !0xffff != p.guest_policy.bits()
    {
        return Err(err("SEV guest policy does not match endorsed policy"));
    }
    if u64at(r, PLATFORM_INFO_OFFSET) != p.platform_info.bits() {
        return Err(err("SEV PLATFORM_INFO does not match endorsed policy"));
    }
    if u32at(r, GUEST_SVN_OFFSET) < p.minimum_guest_svn || u32at(r, VMPL_OFFSET) != p.vmpl as u32 {
        return Err(err("SEV guest SVN/VMPL violates endorsed policy"));
    }
    for (offset, size, value) in [
        (HOST_DATA_OFFSET, HOST_DATA_SIZE, p.host_data.as_str()),
        (IMAGE_ID_OFFSET, IMAGE_ID_SIZE, p.image_id.as_str()),
        (FAMILY_ID_OFFSET, FAMILY_ID_SIZE, p.family_id.as_str()),
    ] {
        if r[offset..offset + size] != decode_hex(value, size)? {
            return Err(err(
                "SEV host_data/image_id/family_id differs from endorsed policy",
            ));
        }
    }
    if r[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + REPORT_DATA_SIZE] != expected[..] {
        return Err(err("SEV REPORT_DATA does not match V3 envelope binding"));
    }
    for (offset, required) in [
        (0x1f8, p.minimum_launch_mitigation_vector),
        (0x200, p.minimum_current_mitigation_vector),
    ] {
        if u64at(r, offset) & required != required {
            return Err(err("SEV mitigation vector lacks endorsed required bits"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    fn fixture() -> (Vec<u8>, Vec<u8>, Value) {
        let f: Value = serde_json::from_str(include_str!("testdata/turin-public.json")).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        (
            b64.decode(f["report_base64"].as_str().unwrap()).unwrap(),
            b64.decode(f["vcek_der_base64"].as_str().unwrap()).unwrap(),
            f["policy"]["sev_snp"].clone(),
        )
    }
    fn verify_components(
        report: &[u8],
        vcek: &[u8],
        policy: &Value,
        expected: &[u8; 64],
    ) -> Result<()> {
        let product = Product::from_report(report, true)?;
        validate_format(report, product)?;
        cert_chain::verify_cert_chain_crypto_for_product(vcek, product.chain(), product)?;
        let tcb = cert_chain::vcek_tcb_for_product(vcek, product)?;
        cert_chain::validate_vcek_hwid_for_product(
            vcek,
            &report[CHIP_ID_OFFSET..CHIP_ID_OFFSET + CHIP_ID_SIZE],
            product,
        )?;
        signature::verify_report_signature(report, vcek)?;
        validate_fields(report, expected, &parse_policy(policy)?, product, tcb)
    }
    #[test]
    fn public_turin_signature_and_policy_positive_with_negative_mutations() {
        let (report, vcek, policy) = fixture();
        let expected: [u8; 64] = report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64]
            .try_into()
            .unwrap();
        verify_components(&report, &vcek, &policy, &expected).unwrap();
        // Envelope binding, exact platform bits, and all five TCB components
        // each independently fail when changed, without weakening root checks.
        let mut bad = expected;
        bad[31] ^= 1;
        assert!(verify_components(&report, &vcek, &policy, &bad).is_err());
        for (field, value) in [
            ("ecc_enabled", false),
            ("tsme_enabled", true),
            ("iommu_write_safe", false),
        ] {
            let mut p = policy.clone();
            p["platform_info"][field] = Value::Bool(value);
            assert!(
                verify_components(&report, &vcek, &p, &expected).is_err(),
                "{field}"
            );
        }
        for field in ["fmc_spl", "bl_spl", "tee_spl", "snp_spl", "ucode_spl"] {
            let mut p = policy.clone();
            p["minimum_tcb"][field] = Value::from(126);
            assert!(
                verify_components(&report, &vcek, &p, &expected).is_err(),
                "{field}"
            );
        }
        for offset in [
            REPORT_DATA_OFFSET,
            CHIP_ID_OFFSET,
            MEASUREMENT_OFFSET,
            CURRENT_TCB_OFFSET,
            SIGNATURE_OFFSET,
        ] {
            let mut r = report.clone();
            r[offset] ^= 1;
            assert!(
                verify_components(&r, &vcek, &policy, &expected).is_err(),
                "offset {offset}"
            );
        }
        // The same report cannot be reinterpreted under Genoa roots/layout.
        assert!(cert_chain::verify_cert_chain_crypto_for_product(
            &vcek,
            Product::Genoa.chain(),
            Product::Genoa
        )
        .is_err());
        let mut bad = vcek.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(verify_components(&report, &bad, &policy, &expected).is_err());
    }
    #[test]
    fn mitigation_vector_bytes_are_reserved_before_report_v5() {
        let (mut r, _, _) = fixture();
        r[0x1f8] = 1;
        assert!(validate_format(&r, Product::Turin).is_ok());
        r[..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(validate_format(&r, Product::Turin).is_err());
        r[0x1f8] = 0;
        r[0x200..0x208].fill(0);
        assert!(validate_format(&r, Product::Turin).is_ok());
    }

    #[test]
    fn v3_requires_crl_and_exact_report_size() {
        let (report, vcek, policy) = fixture();
        let expected = report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64]
            .try_into()
            .unwrap();
        let ev = Evidence {
            report: &report,
            vcek_der: &vcek,
            cert_chain_pem: Product::Turin.chain(),
            crl_der: &[],
        };
        assert!(verify_evidence(ev, &expected, &policy)
            .unwrap_err()
            .to_string()
            .contains("CRL"));
        let mut longer = report.clone();
        longer.push(0);
        assert!(verify_evidence(
            Evidence {
                report: &longer,
                ..ev
            },
            &expected,
            &policy
        )
        .is_err());
        assert!(verify_evidence(Evidence { report: &[], ..ev }, &expected, &policy).is_err());
    }
    #[test]
    fn incomplete_or_unsupported_endorsed_policy_rejected() {
        let (_, _, policy) = fixture();
        validate_policy(&policy).unwrap();
        for field in [
            "minimum_build",
            "minimum_api_version",
            "minimum_abi_version",
            "minimum_guest_svn",
            "minimum_tcb",
            "vmpl",
            "minimum_current_mitigation_vector",
        ] {
            let mut p = policy.clone();
            p.as_object_mut().unwrap().remove(field);
            assert!(validate_policy(&p).is_err(), "missing {field}");
        }
        for field in ["require_author_key", "require_id_block"] {
            let mut p = policy.clone();
            p[field] = Value::Bool(true);
            assert!(validate_policy(&p).is_err());
        }
        let mut p = policy.clone();
        p["minimum_tcb"]["bl_spl"] = Value::from(128);
        assert!(validate_policy(&p).is_err());
        for bad in ["1.256", "1.-1", "+1.58", "1.58.0", "1."] {
            let mut p = policy.clone();
            p["minimum_api_version"] = Value::from(bad);
            assert!(validate_policy(&p).is_err(), "{bad}");
        }
    }
}
