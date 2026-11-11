//! The TDX quote, version 4, with ECDSA P-256 attestation key and PCK
//! certificate chain.

use crate::quote::QuoteError;
use crate::stub::pending;

/// The smallest quote: the header, the body, the length of the signed
/// data, and signed data whose QE authentication data and PCK certificate
/// chain are both empty.
pub const QUOTE_MIN_SIZE: usize = HEADER_SIZE
    + TD_QUOTE_BODY_SIZE
    + SIGNED_DATA_LENGTH_SIZE
    + 2 * P256_PAIR_SIZE
    + CERTIFICATION_HEADER_SIZE
    + QE_REPORT_SIZE
    + P256_PAIR_SIZE
    + QE_AUTH_DATA_LENGTH_SIZE
    + CERTIFICATION_HEADER_SIZE;
/// The size of the field that states the length of the signed data.
const SIGNED_DATA_LENGTH_SIZE: usize = 4;
/// The size of a certification data header: a two-byte type and a
/// four-byte length.
const CERTIFICATION_HEADER_SIZE: usize = 6;
/// The size of the field that states the length of the QE authentication
/// data.
const QE_AUTH_DATA_LENGTH_SIZE: usize = 2;
/// The quote version that is read.
pub const QUOTE_VERSION: u16 = 4;
/// The attestation key type of ECDSA with P-256.
pub const ATTESTATION_KEY_TYPE_ECDSA_P256: u16 = 2;
/// The TEE type of TDX.
pub const TEE_TYPE_TDX: u32 = 0x81;
/// The certification data type of a QE report with nested certification
/// data.
pub const CERTIFICATION_TYPE_QE_REPORT: u16 = 6;
/// The certification data type of a PCK certificate chain.
pub const CERTIFICATION_TYPE_PCK_CHAIN: u16 = 5;

/// The size of the quote header.
pub const HEADER_SIZE: usize = 0x30;
/// The size of the TD quote body.
pub const TD_QUOTE_BODY_SIZE: usize = 0x248;
/// The size of a QE report.
pub const QE_REPORT_SIZE: usize = 0x180;
/// The size of the QE vendor identifier.
pub const QE_VENDOR_ID_SIZE: usize = 16;
/// The size of TEE_TCB_SVN.
pub const TEE_TCB_SVN_SIZE: usize = 16;
/// The size of a measurement register: MRSEAM, MRSIGNERSEAM, MRTD,
/// MRCONFIGID, MROWNER, MROWNERCONFIG and each RTMR.
pub const REGISTER_SIZE: usize = 48;
/// The size of SEAMATTRIBUTES, TDATTRIBUTES and XFAM.
pub const ATTRIBUTES_SIZE: usize = 8;
/// The size of REPORTDATA.
pub const REPORT_DATA_SIZE: usize = 64;
/// The size of a P-256 signature and of a P-256 public key, each as two
/// 32-byte big-endian values.
pub const P256_PAIR_SIZE: usize = 64;

/// A decoded version 4 quote. Decoding establishes its form only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteV4 {
    /// The header.
    pub header: Header,
    /// The TD quote body.
    pub body: TdQuoteBody,
    /// The quote's own signature, attestation key and certification data.
    pub signed_data: SignedData,
    /// Bytes after the signed data.
    pub extra_bytes: Vec<u8>,
    /// The header and body as encoded: what the attestation key signed.
    pub signed_bytes: Vec<u8>,
}

/// The quote header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The quote version.
    pub version: u16,
    /// The attestation key type.
    pub attestation_key_type: u16,
    /// The TEE type.
    pub tee_type: u32,
    /// Header bytes 8 and 9. Reserved in version 4.
    pub pce_svn: [u8; 2],
    /// Header bytes 10 and 11. Reserved in version 4.
    pub qe_svn: [u8; 2],
    /// The QE vendor identifier.
    pub qe_vendor_id: [u8; QE_VENDOR_ID_SIZE],
    /// The user data.
    pub user_data: [u8; 20],
}

/// The TD quote body: what the TDX module reports about the trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdQuoteBody {
    /// TEE_TCB_SVN.
    pub tee_tcb_svn: [u8; TEE_TCB_SVN_SIZE],
    /// MRSEAM: the measurement of the TDX module.
    pub mr_seam: [u8; REGISTER_SIZE],
    /// MRSIGNERSEAM.
    pub mr_signer_seam: [u8; REGISTER_SIZE],
    /// SEAMATTRIBUTES.
    pub seam_attributes: [u8; ATTRIBUTES_SIZE],
    /// TDATTRIBUTES.
    pub td_attributes: [u8; ATTRIBUTES_SIZE],
    /// XFAM.
    pub xfam: [u8; ATTRIBUTES_SIZE],
    /// MRTD: the build-time measurement of the trust domain.
    pub mr_td: [u8; REGISTER_SIZE],
    /// MRCONFIGID.
    pub mr_config_id: [u8; REGISTER_SIZE],
    /// MROWNER.
    pub mr_owner: [u8; REGISTER_SIZE],
    /// MROWNERCONFIG.
    pub mr_owner_config: [u8; REGISTER_SIZE],
    /// RTMR0 to RTMR3.
    pub rtmrs: [[u8; REGISTER_SIZE]; 4],
    /// REPORTDATA.
    pub report_data: [u8; REPORT_DATA_SIZE],
}

/// The signature over the quote and the data that certifies its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData {
    /// The signature of the attestation key over the header and body.
    pub signature: [u8; P256_PAIR_SIZE],
    /// The attestation key.
    pub attestation_key: [u8; P256_PAIR_SIZE],
    /// The QE report as encoded: what the PCK key signed.
    pub qe_report_bytes: [u8; QE_REPORT_SIZE],
    /// The decoded QE report.
    pub qe_report: EnclaveReport,
    /// The signature of the PCK key over the QE report.
    pub qe_report_signature: [u8; P256_PAIR_SIZE],
    /// The QE authentication data.
    pub qe_auth_data: Vec<u8>,
    /// The PCK certificate chain: leaf, intermediate and root, PEM.
    pub pck_cert_chain: Vec<u8>,
}

/// The report of the quoting enclave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveReport {
    /// CPUSVN.
    pub cpu_svn: [u8; 16],
    /// MISCSELECT.
    pub misc_select: u32,
    /// ATTRIBUTES.
    pub attributes: [u8; 16],
    /// MRENCLAVE.
    pub mr_enclave: [u8; 32],
    /// MRSIGNER.
    pub mr_signer: [u8; 32],
    /// ISVPRODID.
    pub isv_prod_id: u16,
    /// ISVSVN.
    pub isv_svn: u16,
    /// REPORTDATA.
    pub report_data: [u8; REPORT_DATA_SIZE],
}

impl QuoteV4 {
    /// Decodes a version 4 quote.
    ///
    /// Rules, each an error when broken:
    ///
    /// - at least [`QUOTE_MIN_SIZE`] bytes, and every fixed-size field is
    ///   read only after its bytes are known to be there: a quote too short
    ///   for a field is an error;
    /// - the header's version is [`QUOTE_VERSION`], its attestation key
    ///   type [`ATTESTATION_KEY_TYPE_ECDSA_P256`] and its TEE type
    ///   [`TEE_TYPE_TDX`];
    /// - the signed data length fits the quote; what follows the signed
    ///   data is kept as extra bytes;
    /// - the certification data is of type
    ///   [`CERTIFICATION_TYPE_QE_REPORT`] and its stated size is exactly
    ///   what remains of the signed data;
    /// - the QE authentication data length fits;
    /// - the nested certification data is of type
    ///   [`CERTIFICATION_TYPE_PCK_CHAIN`], and its stated size is exactly
    ///   what remains.
    ///
    /// Multi-byte integers are little-endian. Reserved bytes are not
    /// judged here.
    pub fn parse(quote: &[u8]) -> Result<Self, QuoteError> {
        pending("quote::tdx::lib::abi::QuoteV4::parse")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smallest_quote_holds_every_mandatory_field() {
        // Header, body and length; then signature, key, certification
        // header, QE report, QE report signature, authentication data
        // length, and the nested certification header.
        assert_eq!(0x30 + 0x248 + 4, 636);
        assert_eq!(64 + 64 + 6 + 384 + 64 + 2 + 6, 590);
        assert_eq!(QUOTE_MIN_SIZE, 636 + 590);
        assert_eq!(QUOTE_MIN_SIZE, 0x4CA);
    }
}
