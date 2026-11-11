//! TCB versions, product lines and certificate extensions, as AMD's Key
//! Distribution Service defines them.

use ::der::Decode;
use ::der::asn1::{Ia5StringRef, ObjectIdentifier, OctetStringRef, UintRef};

use super::abi::ProductLine;
use crate::quote::QuoteError;
use crate::x509::Certificate;

/// The VCEK extension for the layout version of the TCB and hardware
/// identifier.
pub const OID_STRUCT_VERSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.1");
/// The VCEK extension for the product name.
pub const OID_PRODUCT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.2");
/// The VCEK extension for the bootloader security patch level.
pub const OID_BL_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.1");
/// The VCEK extension for the TEE security patch level.
pub const OID_TEE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.2");
/// The VCEK extension for the SNP firmware security patch level.
pub const OID_SNP_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.3");
/// The VCEK extension for reserved security patch level 4.
pub const OID_SPL_4: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.4");
/// The VCEK extension for reserved security patch level 5.
pub const OID_SPL_5: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.5");
/// The VCEK extension for reserved security patch level 6.
pub const OID_SPL_6: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.6");
/// The VCEK extension for reserved security patch level 7.
pub const OID_SPL_7: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.7");
/// The VCEK extension for the microcode security patch level.
pub const OID_UCODE_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.8");
/// The VCEK extension for the FMC security patch level.
pub const OID_FMC_SPL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.3.9");
/// The VCEK extension for the hardware identifier.
pub const OID_HWID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.4");
/// The extension for a cloud service provider identifier. It marks a
/// certificate that is not specific to one chip.
pub const OID_CSP_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.3704.1.5");

/// The size of the hardware identifier in certificates of
/// [`TcbLayout::V0`].
pub const HWID_SIZE_V0: usize = 64;
/// The size of the hardware identifier in certificates of
/// [`TcbLayout::V1`].
pub const HWID_SIZE_V1: usize = 8;

fn error(message: impl Into<String>) -> QuoteError {
    QuoteError::new(message)
}

/// How a product line packs its security patch levels into a 64-bit TCB
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbLayout {
    /// Genoa: bootloader in byte 0, TEE in byte 1, reserved levels 4 to 7
    /// in bytes 2 to 5, SNP in byte 6, microcode in byte 7. No FMC level.
    V0,
    /// Turin: FMC in byte 0, bootloader in byte 1, TEE in byte 2, SNP in
    /// byte 3, bytes 4 to 6 reserved and zero, microcode in byte 7.
    V1,
}

impl TcbLayout {
    /// The layout that a product line uses.
    pub fn of(product_line: ProductLine) -> Self {
        match product_line {
            ProductLine::Genoa => TcbLayout::V0,
            ProductLine::Turin => TcbLayout::V1,
        }
    }
}

/// The security patch levels of a TCB version, by component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcbParts {
    /// The layout that the levels belong to.
    pub layout: TcbLayout,
    /// The bootloader level.
    pub bl_spl: u8,
    /// The TEE level.
    pub tee_spl: u8,
    /// Reserved level 4; zero under [`TcbLayout::V1`].
    pub spl_4: u8,
    /// Reserved level 5; zero under [`TcbLayout::V1`].
    pub spl_5: u8,
    /// Reserved level 6; zero under [`TcbLayout::V1`].
    pub spl_6: u8,
    /// Reserved level 7; zero under [`TcbLayout::V1`].
    pub spl_7: u8,
    /// The SNP firmware level.
    pub snp_spl: u8,
    /// The microcode level.
    pub ucode_spl: u8,
    /// The FMC level; zero under [`TcbLayout::V0`].
    pub fmc_spl: u8,
}

/// The highest value of every level other than the microcode level.
const MAX_SPL: u8 = 127;

/// The bits of a [`TcbLayout::V1`] TCB version that are reserved: bytes 4
/// to 6.
const V1_RESERVED_BITS: u64 = 0x00ff_ffff_0000_0000;

impl TcbParts {
    /// The levels of a policy floor for a product line. An absent FMC level
    /// counts as zero; whether a product line requires or forbids one is
    /// the caller's rule. The reserved levels are zero, and the levels must
    /// form a valid TCB version in the product line's layout
    /// ([`TcbParts::compose`]).
    pub fn for_product_line(
        product_line: ProductLine,
        fmc_spl: Option<u8>,
        bl_spl: u8,
        tee_spl: u8,
        snp_spl: u8,
        ucode_spl: u8,
    ) -> Result<Self, QuoteError> {
        let parts = Self {
            layout: TcbLayout::of(product_line),
            bl_spl,
            tee_spl,
            spl_4: 0,
            spl_5: 0,
            spl_6: 0,
            spl_7: 0,
            snp_spl,
            ucode_spl,
            fmc_spl: fmc_spl.unwrap_or(0),
        };
        parts.compose()?;
        Ok(parts)
    }

    /// Splits a 64-bit TCB version by a layout. Under [`TcbLayout::V1`]
    /// the reserved bytes 4 to 6 must be zero. No level is range-checked
    /// here; [`TcbParts::compose`] does that.
    pub fn decompose(layout: TcbLayout, tcb: u64) -> Result<Self, QuoteError> {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = tcb.to_le_bytes();
        match layout {
            TcbLayout::V0 => Ok(Self {
                layout,
                bl_spl: b0,
                tee_spl: b1,
                spl_4: b2,
                spl_5: b3,
                spl_6: b4,
                spl_7: b5,
                snp_spl: b6,
                ucode_spl: b7,
                fmc_spl: 0,
            }),
            TcbLayout::V1 => {
                let reserved = tcb & V1_RESERVED_BITS;
                if reserved != 0 {
                    return Err(error(format!(
                        "non-zero reserved bits in TCB version: {reserved:#x}"
                    )));
                }
                Ok(Self {
                    layout,
                    bl_spl: b1,
                    tee_spl: b2,
                    spl_4: 0,
                    spl_5: 0,
                    spl_6: 0,
                    spl_7: 0,
                    snp_spl: b3,
                    ucode_spl: b7,
                    fmc_spl: b0,
                })
            }
        }
    }

    /// Packs the levels into a 64-bit TCB version. Every level other than
    /// the microcode level must be at most 127; under [`TcbLayout::V0`] the
    /// FMC level must be zero, and under [`TcbLayout::V1`] the reserved
    /// levels must be zero.
    pub fn compose(&self) -> Result<u64, QuoteError> {
        for (name, value) in [
            ("SNP", self.snp_spl),
            ("reserved 7", self.spl_7),
            ("reserved 6", self.spl_6),
            ("reserved 5", self.spl_5),
            ("reserved 4", self.spl_4),
            ("TEE", self.tee_spl),
            ("bootloader", self.bl_spl),
            ("FMC", self.fmc_spl),
        ] {
            if value > MAX_SPL {
                return Err(error(format!(
                    "{name} security patch level is {value}, want 0 to {MAX_SPL}"
                )));
            }
        }
        match self.layout {
            TcbLayout::V0 => {
                if self.fmc_spl != 0 {
                    return Err(error(
                        "the FMC security patch level is not defined for this TCB layout",
                    ));
                }
                Ok(u64::from_le_bytes([
                    self.bl_spl,
                    self.tee_spl,
                    self.spl_4,
                    self.spl_5,
                    self.spl_6,
                    self.spl_7,
                    self.snp_spl,
                    self.ucode_spl,
                ]))
            }
            TcbLayout::V1 => {
                if self.spl_4 != 0 || self.spl_5 != 0 || self.spl_6 != 0 || self.spl_7 != 0 {
                    return Err(error(
                        "reserved security patch levels must be zero in this TCB layout",
                    ));
                }
                Ok(u64::from_le_bytes([
                    self.fmc_spl,
                    self.bl_spl,
                    self.tee_spl,
                    self.snp_spl,
                    0,
                    0,
                    0,
                    self.ucode_spl,
                ]))
            }
        }
    }

    /// Whether every level of `self` is at most the same level of `other`,
    /// and both have the same layout.
    pub fn all_at_most(&self, other: &TcbParts) -> bool {
        self.layout == other.layout
            && self.ucode_spl <= other.ucode_spl
            && self.snp_spl <= other.snp_spl
            && self.spl_7 <= other.spl_7
            && self.spl_6 <= other.spl_6
            && self.spl_5 <= other.spl_5
            && self.spl_4 <= other.spl_4
            && self.tee_spl <= other.tee_spl
            && self.bl_spl <= other.bl_spl
            && self.fmc_spl <= other.fmc_spl
    }
}

/// The AMD extensions of a VCEK certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extensions {
    /// The product name, such as `Genoa` or `Turin-B1`. It is recorded and
    /// not interpreted: the product line comes from the report.
    pub product_name: String,
    /// The hardware identifier of the chip: [`HWID_SIZE_V0`] or
    /// [`HWID_SIZE_V1`] bytes, by layout.
    pub hwid: Vec<u8>,
    /// The TCB version that the certificate is issued for.
    pub tcb: TcbParts,
}

impl Extensions {
    /// The TCB version that the certificate is issued for, packed.
    pub fn tcb_version(&self) -> Result<u64, QuoteError> {
        self.tcb.compose()
    }
}

/// `id-ce-authorityKeyIdentifier`, the one extension of a VCEK certificate
/// that is not AMD's own.
const OID_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");

/// Reads the AMD extensions of a VCEK certificate.
///
/// Every extension of the certificate other than the authority key
/// identifier must be one of the AMD extensions above. Rules, each an
/// error when broken:
///
/// - the struct version is an INTEGER, 0 ([`TcbLayout::V0`]) or 1
///   ([`TcbLayout::V1`]);
/// - the product name is an IA5String;
/// - the hardware identifier is present and has the size of the layout:
///   either the bare bytes or an OCTET STRING of them;
/// - there is no cloud service provider identifier;
/// - the bootloader, TEE, SNP, microcode and reserved 5 to 7 levels are
///   present; under `V0` reserved level 4 is present and the FMC level is
///   absent, and under `V1` the reverse; each is an INTEGER from 0 to 255;
/// - the levels form a valid TCB version ([`TcbParts::compose`]).
pub fn vcek_extensions(vcek: &Certificate) -> Result<Extensions, QuoteError> {
    const KNOWN: [ObjectIdentifier; 13] = [
        OID_STRUCT_VERSION,
        OID_PRODUCT_NAME,
        OID_BL_SPL,
        OID_TEE_SPL,
        OID_SNP_SPL,
        OID_SPL_4,
        OID_SPL_5,
        OID_SPL_6,
        OID_SPL_7,
        OID_UCODE_SPL,
        OID_FMC_SPL,
        OID_HWID,
        OID_CSP_ID,
    ];
    for (oid, _) in vcek.extensions() {
        if oid != OID_AUTHORITY_KEY_IDENTIFIER && !KNOWN.contains(&oid) {
            return Err(error(format!(
                "certificate has an extension that is not an AMD extension: {oid}"
            )));
        }
    }
    let layout = match extension_u8(vcek, OID_STRUCT_VERSION, "struct version")? {
        0 => TcbLayout::V0,
        1 => TcbLayout::V1,
        other => {
            return Err(error(format!(
                "unsupported certificate struct version {other}"
            )));
        }
    };
    let product_name = extension_ia5_string(vcek, OID_PRODUCT_NAME, "product name")?;
    if vcek.extension(OID_CSP_ID).is_some() {
        return Err(error(
            "certificate carries a cloud service provider identifier",
        ));
    }
    let hwid_size = match layout {
        TcbLayout::V0 => HWID_SIZE_V0,
        TcbLayout::V1 => HWID_SIZE_V1,
    };
    let hwid = extension_octets(vcek, OID_HWID, "hardware identifier", hwid_size)?;
    let bl_spl = extension_u8(vcek, OID_BL_SPL, "bootloader level")?;
    let tee_spl = extension_u8(vcek, OID_TEE_SPL, "TEE level")?;
    let snp_spl = extension_u8(vcek, OID_SNP_SPL, "SNP level")?;
    let spl_5 = extension_u8(vcek, OID_SPL_5, "reserved level 5")?;
    let spl_6 = extension_u8(vcek, OID_SPL_6, "reserved level 6")?;
    let spl_7 = extension_u8(vcek, OID_SPL_7, "reserved level 7")?;
    let ucode_spl = extension_u8(vcek, OID_UCODE_SPL, "microcode level")?;
    let (spl_4, fmc_spl) = match layout {
        TcbLayout::V0 => {
            if vcek.extension(OID_FMC_SPL).is_some() {
                return Err(error(
                    "certificate carries an FMC level, which its struct version does not define",
                ));
            }
            (extension_u8(vcek, OID_SPL_4, "reserved level 4")?, 0)
        }
        TcbLayout::V1 => {
            if vcek.extension(OID_SPL_4).is_some() {
                return Err(error(
                    "certificate carries reserved level 4, which its struct version does not define",
                ));
            }
            (0, extension_u8(vcek, OID_FMC_SPL, "FMC level")?)
        }
    };
    let tcb = TcbParts {
        layout,
        bl_spl,
        tee_spl,
        spl_4,
        spl_5,
        spl_6,
        spl_7,
        snp_spl,
        ucode_spl,
        fmc_spl,
    };
    tcb.compose()?;
    Ok(Extensions {
        product_name,
        hwid,
        tcb,
    })
}

/// The value of an extension that holds a DER INTEGER from 0 to 255 with
/// nothing after it. A missing extension is an error.
pub fn extension_u8(
    certificate: &Certificate,
    oid: ObjectIdentifier,
    field: &str,
) -> Result<u8, QuoteError> {
    let extension = certificate
        .extension(oid)
        .ok_or_else(|| error(format!("certificate has no {field} extension")))?;
    let integer = UintRef::from_der(extension.value)
        .map_err(|cause| error(format!("{field} extension is not an INTEGER: {cause}")))?;
    match integer.as_bytes() {
        [] => Ok(0),
        [value] => Ok(*value),
        _ => Err(error(format!("{field} extension does not fit in a byte"))),
    }
}

/// The value of an extension that holds a DER IA5String with nothing after
/// it. A missing extension is an error.
pub fn extension_ia5_string(
    certificate: &Certificate,
    oid: ObjectIdentifier,
    field: &str,
) -> Result<String, QuoteError> {
    let extension = certificate
        .extension(oid)
        .ok_or_else(|| error(format!("certificate has no {field} extension")))?;
    Ia5StringRef::from_der(extension.value)
        .map(|text| text.as_str().to_string())
        .map_err(|cause| error(format!("{field} extension is not an IA5String: {cause}")))
}

/// The value of an extension that holds `size` bytes, either bare or as a
/// DER OCTET STRING with nothing after it. A missing extension is an error.
pub fn extension_octets(
    certificate: &Certificate,
    oid: ObjectIdentifier,
    field: &str,
    size: usize,
) -> Result<Vec<u8>, QuoteError> {
    let extension = certificate
        .extension(oid)
        .ok_or_else(|| error(format!("certificate has no {field} extension")))?;
    if extension.value.len() == size {
        return Ok(extension.value.to_vec());
    }
    let octets = OctetStringRef::from_der(extension.value)
        .map_err(|cause| error(format!("{field} extension is not an OCTET STRING: {cause}")))?;
    if octets.as_bytes().len() != size {
        return Err(error(format!(
            "{field} extension has {} bytes, want {size}",
            octets.as_bytes().len()
        )));
    }
    Ok(octets.as_bytes().to_vec())
}

/// The last line of every certificate block.
const PEM_CERTIFICATE_END: &[u8] = b"-----END CERTIFICATE-----";

/// Splits an AMD certificate chain (the `cert_chain` of the key
/// distribution service) into the ASK and the ARK certificate, DER.
///
/// The text is exactly two `CERTIFICATE` blocks, the ASK and then the ARK
/// ([`pem_certificates`](crate::x509::der::pem_certificates)). Nothing
/// follows the second block but the end of its last line: a further line,
/// even an empty one, is an error.
pub fn parse_product_cert_chain(pem: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    let mut certificates = crate::x509::der::pem_certificates(pem)?;
    let (ask, ark) = match (certificates.pop(), certificates.pop(), certificates.pop()) {
        (Some(ark), Some(ask), None) => (ask, ark),
        _ => {
            return Err(error(
                "certificate chain must carry exactly the ASK and ARK certificates",
            ));
        }
    };
    let tail = pem
        .windows(PEM_CERTIFICATE_END.len())
        .rposition(|window| window == PEM_CERTIFICATE_END)
        .and_then(|start| start.checked_add(PEM_CERTIFICATE_END.len()))
        .and_then(|end| pem.get(end..))
        .unwrap_or_default();
    let line_rest = tail.strip_suffix(b"\n").unwrap_or(tail);
    if line_rest.iter().any(|byte| !b" \t\r".contains(byte)) {
        return Err(error("certificate chain carries trailing data"));
    }
    Ok((ask, ark))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::sev::lib::abi::testdata::TURIN_VCEK_DER;

    fn vcek() -> Certificate {
        Certificate::from_der(TURIN_VCEK_DER).unwrap()
    }

    #[test]
    fn integer_extensions_of_a_captured_vcek_read_as_bytes() {
        let vcek = vcek();
        assert_eq!(
            extension_u8(&vcek, OID_STRUCT_VERSION, "struct version").unwrap(),
            1
        );
        assert_eq!(extension_u8(&vcek, OID_FMC_SPL, "FMC").unwrap(), 1);
        assert_eq!(extension_u8(&vcek, OID_BL_SPL, "bootloader").unwrap(), 1);
        assert_eq!(extension_u8(&vcek, OID_TEE_SPL, "TEE").unwrap(), 1);
        assert_eq!(extension_u8(&vcek, OID_SNP_SPL, "SNP").unwrap(), 4);
        assert_eq!(
            extension_u8(&vcek, OID_UCODE_SPL, "microcode").unwrap(),
            0x52
        );
        let missing = extension_u8(&vcek, OID_SPL_4, "SPL4").unwrap_err();
        assert!(
            missing.to_string().contains("no SPL4 extension"),
            "{missing}"
        );
        assert!(extension_u8(&vcek, OID_PRODUCT_NAME, "product").is_err());
    }

    #[test]
    fn the_product_name_of_a_captured_vcek_is_an_ia5_string() {
        let vcek = vcek();
        assert_eq!(
            extension_ia5_string(&vcek, OID_PRODUCT_NAME, "product name").unwrap(),
            "Turin"
        );
        assert!(extension_ia5_string(&vcek, OID_BL_SPL, "bootloader").is_err());
        assert!(vcek.extension(OID_CSP_ID).is_none());
    }

    #[test]
    fn the_hardware_identifier_of_a_captured_vcek_has_the_newer_size() {
        let vcek = vcek();
        let hwid = extension_octets(&vcek, OID_HWID, "HWID", HWID_SIZE_V1).unwrap();
        assert_eq!(
            crate::canonical::encode_lower_hex(&hwid),
            "6bb1229b7692b710"
        );
        assert!(extension_octets(&vcek, OID_HWID, "HWID", HWID_SIZE_V0).is_err());
    }

    #[test]
    fn levels_compare_component_by_component() {
        let base = TcbParts {
            layout: TcbLayout::V1,
            bl_spl: 1,
            tee_spl: 1,
            spl_4: 0,
            spl_5: 0,
            spl_6: 0,
            spl_7: 0,
            snp_spl: 4,
            ucode_spl: 0x52,
            fmc_spl: 1,
        };
        assert!(base.all_at_most(&base));
        let higher = TcbParts { snp_spl: 5, ..base };
        assert!(base.all_at_most(&higher));
        assert!(!higher.all_at_most(&base));
        let mixed = TcbParts {
            snp_spl: 5,
            ucode_spl: 0x51,
            ..base
        };
        assert!(!base.all_at_most(&mixed));
        assert!(!mixed.all_at_most(&base));
        let other_layout = TcbParts {
            layout: TcbLayout::V0,
            ..base
        };
        assert!(!base.all_at_most(&other_layout));
    }

    const TURIN_TCB: u64 = 0x5200_0000_0401_0101;

    fn parts(layout: TcbLayout) -> TcbParts {
        TcbParts {
            layout,
            bl_spl: 0,
            tee_spl: 0,
            spl_4: 0,
            spl_5: 0,
            spl_6: 0,
            spl_7: 0,
            snp_spl: 0,
            ucode_spl: 0,
            fmc_spl: 0,
        }
    }

    #[test]
    fn the_newer_layout_splits_and_packs() {
        let split = TcbParts::decompose(TcbLayout::V1, TURIN_TCB).unwrap();
        assert_eq!(
            split,
            TcbParts {
                fmc_spl: 1,
                bl_spl: 1,
                tee_spl: 1,
                snp_spl: 4,
                ucode_spl: 82,
                ..parts(TcbLayout::V1)
            }
        );
        assert_eq!(split.compose().unwrap(), TURIN_TCB);
    }

    #[test]
    fn the_older_layout_splits_and_packs() {
        let tcb = 0x9270_0504_0302_7f1f;
        let split = TcbParts::decompose(TcbLayout::V0, tcb).unwrap();
        assert_eq!(
            split,
            TcbParts {
                bl_spl: 0x1f,
                tee_spl: 0x7f,
                spl_4: 2,
                spl_5: 3,
                spl_6: 4,
                spl_7: 5,
                snp_spl: 0x70,
                ucode_spl: 0x92,
                ..parts(TcbLayout::V0)
            }
        );
        assert_eq!(split.compose().unwrap(), tcb);
        // The same bits under the other layout are another TCB.
        assert!(TcbParts::decompose(TcbLayout::V1, tcb).is_err());
    }

    #[test]
    fn reserved_bits_of_the_newer_layout_must_be_zero() {
        for bit in 32..56 {
            let error = TcbParts::decompose(TcbLayout::V1, 1 << bit).unwrap_err();
            assert!(error.to_string().contains("reserved bits"), "{error}");
        }
        for bit in (0..32).chain(56..64) {
            TcbParts::decompose(TcbLayout::V1, 1 << bit).unwrap();
        }
        for bit in 0..64 {
            TcbParts::decompose(TcbLayout::V0, 1 << bit).unwrap();
        }
    }

    #[test]
    fn splitting_does_not_judge_levels_and_packing_does() {
        // Every byte of a version splits, whatever its value.
        let split = TcbParts::decompose(TcbLayout::V0, u64::MAX).unwrap();
        assert_eq!(split.bl_spl, 0xff);
        assert!(split.compose().is_err());

        let fields: [fn(&mut TcbParts) -> &mut u8; 7] = [
            |parts| &mut parts.bl_spl,
            |parts| &mut parts.tee_spl,
            |parts| &mut parts.spl_4,
            |parts| &mut parts.spl_5,
            |parts| &mut parts.spl_6,
            |parts| &mut parts.spl_7,
            |parts| &mut parts.snp_spl,
        ];
        for field in fields {
            let mut at_limit = parts(TcbLayout::V0);
            *field(&mut at_limit) = 127;
            at_limit.compose().unwrap();
            let mut over = parts(TcbLayout::V0);
            *field(&mut over) = 128;
            let error = over.compose().unwrap_err();
            assert!(error.to_string().contains("want 0 to 127"), "{error}");
        }
        let microcode = TcbParts {
            ucode_spl: 255,
            ..parts(TcbLayout::V0)
        };
        assert_eq!(microcode.compose().unwrap(), 0xff << 56);
        let fmc = TcbParts {
            fmc_spl: 128,
            ..parts(TcbLayout::V1)
        };
        assert!(fmc.compose().is_err());
    }

    #[test]
    fn a_layout_has_only_its_own_levels() {
        let fmc_in_older = TcbParts {
            fmc_spl: 1,
            ..parts(TcbLayout::V0)
        };
        assert!(fmc_in_older.compose().is_err());
        for reserved in [
            TcbParts {
                spl_4: 1,
                ..parts(TcbLayout::V1)
            },
            TcbParts {
                spl_5: 1,
                ..parts(TcbLayout::V1)
            },
            TcbParts {
                spl_6: 1,
                ..parts(TcbLayout::V1)
            },
            TcbParts {
                spl_7: 1,
                ..parts(TcbLayout::V1)
            },
        ] {
            assert!(reserved.compose().is_err());
        }
    }

    #[test]
    fn a_policy_floor_takes_the_layout_of_its_product_line() {
        let turin = TcbParts::for_product_line(ProductLine::Turin, Some(1), 1, 1, 4, 82).unwrap();
        assert_eq!(turin.layout, TcbLayout::V1);
        assert_eq!(turin.compose().unwrap(), TURIN_TCB);
        let genoa = TcbParts::for_product_line(ProductLine::Genoa, None, 7, 0, 14, 72).unwrap();
        assert_eq!(genoa.layout, TcbLayout::V0);
        assert_eq!(genoa.compose().unwrap(), 0x480e_0000_0000_0007);

        // An absent FMC level counts as zero in either layout.
        let without = TcbParts::for_product_line(ProductLine::Turin, None, 1, 1, 4, 82).unwrap();
        assert_eq!(without.fmc_spl, 0);
        TcbParts::for_product_line(ProductLine::Genoa, Some(0), 7, 0, 14, 72).unwrap();
        assert!(TcbParts::for_product_line(ProductLine::Genoa, Some(1), 7, 0, 14, 72).is_err());
        assert!(TcbParts::for_product_line(ProductLine::Genoa, None, 128, 0, 0, 0).is_err());
        assert!(TcbParts::for_product_line(ProductLine::Turin, Some(128), 0, 0, 0, 0).is_err());
        TcbParts::for_product_line(ProductLine::Turin, Some(127), 127, 127, 127, 255).unwrap();
    }

    #[test]
    fn floors_of_different_layouts_do_not_compare() {
        let older = TcbParts::for_product_line(ProductLine::Genoa, None, 0, 0, 0, 0).unwrap();
        let newer = TcbParts::for_product_line(ProductLine::Turin, None, 0, 0, 0, 0).unwrap();
        assert!(!older.all_at_most(&newer));
        assert!(!newer.all_at_most(&older));
        assert!(older.all_at_most(&older));
    }

    #[test]
    fn the_extensions_of_a_captured_vcek_are_read() {
        let extensions = vcek_extensions(&vcek()).unwrap();
        assert_eq!(extensions.product_name, "Turin");
        assert_eq!(extensions.hwid.len(), HWID_SIZE_V1);
        assert_eq!(
            crate::canonical::encode_lower_hex(&extensions.hwid),
            "6bb1229b7692b710"
        );
        assert_eq!(extensions.tcb.layout, TcbLayout::V1);
        assert_eq!(extensions.tcb_version().unwrap(), TURIN_TCB);
    }

    #[test]
    fn a_certificate_without_amd_extensions_has_none_to_read() {
        let other = crate::x509::certificate::testdata::certificate(
            crate::x509::certificate::testdata::FULCIO_INTERMEDIATE_PEM,
        );
        let error = vcek_extensions(&other).unwrap_err();
        assert!(
            error.to_string().contains("not an AMD extension"),
            "{error}"
        );
    }

    #[test]
    fn a_chain_ends_with_the_last_line_of_its_second_block() {
        let block = |byte: u8| {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                crate::sigstore::testutil::to_b64(&[byte; 3])
            )
        };
        let chain = |tail: &str| format!("{}\n{}{tail}", block(1), block(2));
        for tail in ["", "\n", "\r\n"] {
            parse_product_cert_chain(chain(tail).as_bytes()).unwrap();
        }
        for tail in ["\n\n", "\n \n", "\r\n\r\n", "\nx", "\n\t"] {
            assert!(
                parse_product_cert_chain(chain(tail).as_bytes()).is_err(),
                "{tail:?}"
            );
        }
        // Blank lines before and between the blocks are not trailing data.
        let spaced = format!("\n{}\n\n{}\n", block(1), block(2));
        parse_product_cert_chain(spaced.as_bytes()).unwrap();
        for product_line in [ProductLine::Genoa, ProductLine::Turin] {
            let embedded = crate::quote::sev::authenticate::embedded_cert_chain_pem(product_line);
            parse_product_cert_chain(embedded).unwrap();
        }
    }

    #[test]
    fn a_chain_is_exactly_the_ask_and_the_ark() {
        let block = |byte: u8| {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                crate::sigstore::testutil::to_b64(&[byte; 3])
            )
        };
        let (ask, ark) =
            parse_product_cert_chain(format!("{}{}", block(1), block(2)).as_bytes()).unwrap();
        assert_eq!((ask, ark), (vec![1; 3], vec![2; 3]));
        assert!(parse_product_cert_chain(block(1).as_bytes()).is_err());
        let three = format!("{}{}{}", block(1), block(2), block(3));
        assert!(parse_product_cert_chain(three.as_bytes()).is_err());
        assert!(parse_product_cert_chain(b"").is_err());
        let trailing = format!("{}{}trailing", block(1), block(2));
        assert!(parse_product_cert_chain(trailing.as_bytes()).is_err());
    }
}
