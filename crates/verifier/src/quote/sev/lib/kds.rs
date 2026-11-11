//! TCB versions, product lines and certificate extensions, as AMD's Key
//! Distribution Service defines them.

use ::der::Decode;
use ::der::asn1::{Ia5StringRef, ObjectIdentifier, OctetStringRef, UintRef};

use super::abi::ProductLine;
use crate::quote::QuoteError;
use crate::stub::pending;
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

impl TcbParts {
    /// The levels of a policy floor for a product line: `fmc_spl` is given
    /// exactly for product lines whose layout has it. Every level other
    /// than the microcode level is at most 127, the reserved levels are
    /// zero, and the levels fit the layout ([`TcbParts::compose`]).
    pub fn for_product_line(
        product_line: ProductLine,
        fmc_spl: Option<u8>,
        bl_spl: u8,
        tee_spl: u8,
        snp_spl: u8,
        ucode_spl: u8,
    ) -> Result<Self, QuoteError> {
        pending("quote::sev::lib::kds::TcbParts::for_product_line")
    }

    /// Splits a 64-bit TCB version by a layout. Under [`TcbLayout::V1`]
    /// the reserved bytes 4 to 6 must be zero.
    pub fn decompose(layout: TcbLayout, tcb: u64) -> Result<Self, QuoteError> {
        pending("quote::sev::lib::kds::TcbParts::decompose")
    }

    /// Packs the levels into a 64-bit TCB version. Every level other than
    /// the microcode level must be at most 127; under [`TcbLayout::V0`] the
    /// FMC level must be zero, and under [`TcbLayout::V1`] the reserved
    /// levels must be zero.
    pub fn compose(&self) -> Result<u64, QuoteError> {
        pending("quote::sev::lib::kds::TcbParts::compose")
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
    /// The product name, such as `Genoa` or `Turin-B1`.
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

/// Reads the AMD extensions of a VCEK certificate.
///
/// Every extension of the certificate other than the authority key
/// identifier must be one of the AMD extensions above, each at most once.
/// Rules, each an error when broken:
///
/// - the struct version is 0 ([`TcbLayout::V0`]) or 1 ([`TcbLayout::V1`]);
/// - the product name is an IA5String;
/// - the hardware identifier is present and has the size of the layout:
///   either the bare bytes or an OCTET STRING of them;
/// - there is no cloud service provider identifier;
/// - the bootloader, TEE, SNP, microcode and reserved 5 to 7 levels are
///   present; under `V0` reserved level 4 is present and the FMC level is
///   absent, and under `V1` the reverse; each is an INTEGER from 0 to 255;
/// - the levels form a valid TCB version ([`TcbParts::compose`]).
pub fn vcek_extensions(vcek: &Certificate) -> Result<Extensions, QuoteError> {
    pending("quote::sev::lib::kds::vcek_extensions")
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

/// Splits an AMD certificate chain (the `cert_chain` of the key
/// distribution service) into the ASK and the ARK certificate, DER.
///
/// The text is exactly two `CERTIFICATE` blocks, the ASK and then the ARK,
/// with nothing after the second
/// ([`pem_certificates`](crate::x509::der::pem_certificates)).
pub fn parse_product_cert_chain(pem: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QuoteError> {
    let mut certificates = crate::x509::der::pem_certificates(pem)?;
    match (certificates.pop(), certificates.pop(), certificates.pop()) {
        (Some(ark), Some(ask), None) => Ok((ask, ark)),
        _ => Err(error(
            "certificate chain must carry exactly the ASK and ARK certificates",
        )),
    }
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
