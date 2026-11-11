//! The TDX quote, version 4, with ECDSA P-256 attestation key and PCK
//! certificate chain.

use crate::quote::QuoteError;

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
    /// - the first two bytes state [`QUOTE_VERSION`];
    /// - at least [`QUOTE_MIN_SIZE`] bytes, and every fixed-size field is
    ///   read only after its bytes are known to be there: a quote too short
    ///   for a field is an error;
    /// - the header's attestation key type is
    ///   [`ATTESTATION_KEY_TYPE_ECDSA_P256`] and its TEE type
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
        let mut input = Fields::new(quote);
        let version = Fields::new(quote)
            .u16()
            .ok_or_else(|| QuoteError::new("TDX quote is too short to state its version"))?;
        if version != QUOTE_VERSION {
            return Err(QuoteError::new(format!(
                "TDX quote version {version} is not supported, want {QUOTE_VERSION}"
            )));
        }
        if quote.len() < QUOTE_MIN_SIZE {
            return Err(QuoteError::new(format!(
                "TDX quote is {} bytes, shorter than the smallest quote of {QUOTE_MIN_SIZE}",
                quote.len()
            )));
        }
        let short = || QuoteError::new("TDX quote is too short for its fields");

        let signed_bytes = quote
            .get(..HEADER_SIZE.saturating_add(TD_QUOTE_BODY_SIZE))
            .ok_or_else(short)?
            .to_vec();
        let header = Header::read(&mut input).ok_or_else(short)?;
        if header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA_P256 {
            return Err(QuoteError::new(format!(
                "TDX quote attestation key type {} is not supported",
                header.attestation_key_type
            )));
        }
        if header.tee_type != TEE_TYPE_TDX {
            return Err(QuoteError::new(format!(
                "quote TEE type {:#x} is not TDX",
                header.tee_type
            )));
        }
        let body = TdQuoteBody::read(&mut input).ok_or_else(short)?;

        let signed_data_size = input.length_u32().ok_or_else(short)?;
        let signed = input.take(signed_data_size).ok_or_else(|| {
            QuoteError::new(format!(
                "TDX quote states {signed_data_size} bytes of signed data, more than it holds"
            ))
        })?;
        let extra_bytes = input.rest().to_vec();
        let signed_data = SignedData::read(signed)?;

        Ok(QuoteV4 {
            header,
            body,
            signed_data,
            extra_bytes,
            signed_bytes,
        })
    }
}

/// Reads fixed-size fields from the front of a byte string. Every read is
/// checked: a field that is not wholly there is `None`.
struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (field, rest) = self.rest.split_at_checked(count)?;
        self.rest = rest;
        Some(field)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// A 32-bit length, as a count of bytes.
    fn length_u32(&mut self) -> Option<usize> {
        usize::try_from(self.u32()?).ok()
    }

    fn rest(&self) -> &'a [u8] {
        self.rest
    }
}

impl Header {
    fn read(input: &mut Fields<'_>) -> Option<Self> {
        Some(Header {
            version: input.u16()?,
            attestation_key_type: input.u16()?,
            tee_type: input.u32()?,
            pce_svn: input.array()?,
            qe_svn: input.array()?,
            qe_vendor_id: input.array()?,
            user_data: input.array()?,
        })
    }
}

impl TdQuoteBody {
    fn read(input: &mut Fields<'_>) -> Option<Self> {
        Some(TdQuoteBody {
            tee_tcb_svn: input.array()?,
            mr_seam: input.array()?,
            mr_signer_seam: input.array()?,
            seam_attributes: input.array()?,
            td_attributes: input.array()?,
            xfam: input.array()?,
            mr_td: input.array()?,
            mr_config_id: input.array()?,
            mr_owner: input.array()?,
            mr_owner_config: input.array()?,
            rtmrs: [
                input.array()?,
                input.array()?,
                input.array()?,
                input.array()?,
            ],
            report_data: input.array()?,
        })
    }
}

impl SignedData {
    /// Decodes the signed data, which must be accounted for to its last
    /// byte by the lengths that it states.
    fn read(signed: &[u8]) -> Result<Self, QuoteError> {
        let short = || QuoteError::new("TDX quote signed data is too short for its fields");
        let mut input = Fields::new(signed);
        let signature = input.array().ok_or_else(short)?;
        let attestation_key = input.array().ok_or_else(short)?;

        let certification_type = input.u16().ok_or_else(short)?;
        let certification_size = input.length_u32().ok_or_else(short)?;
        if input.rest().len() != certification_size {
            return Err(QuoteError::new(format!(
                "TDX quote certification data is {} bytes, but states {certification_size}",
                input.rest().len()
            )));
        }
        if certification_type != CERTIFICATION_TYPE_QE_REPORT {
            return Err(QuoteError::new(format!(
                "TDX quote certification data type is {certification_type}, want {CERTIFICATION_TYPE_QE_REPORT}"
            )));
        }

        let qe_report_bytes: [u8; QE_REPORT_SIZE] = input.array().ok_or_else(short)?;
        let qe_report = EnclaveReport::read(&qe_report_bytes).ok_or_else(short)?;
        let qe_report_signature = input.array().ok_or_else(short)?;

        let qe_auth_data_size = usize::from(input.u16().ok_or_else(short)?);
        let qe_auth_data = input
            .take(qe_auth_data_size)
            .ok_or_else(|| {
                QuoteError::new(format!(
                    "TDX quote states {qe_auth_data_size} bytes of QE authentication data, more than it holds"
                ))
            })?
            .to_vec();

        let chain_type = input.u16().ok_or_else(short)?;
        let chain_size = input.length_u32().ok_or_else(short)?;
        if chain_type != CERTIFICATION_TYPE_PCK_CHAIN {
            return Err(QuoteError::new(format!(
                "TDX quote PCK certificate chain data type is {chain_type}, want {CERTIFICATION_TYPE_PCK_CHAIN}"
            )));
        }
        if input.rest().len() != chain_size {
            return Err(QuoteError::new(format!(
                "TDX quote PCK certificate chain is {} bytes, but states {chain_size}",
                input.rest().len()
            )));
        }
        let pck_cert_chain = input.rest().to_vec();

        Ok(SignedData {
            signature,
            attestation_key,
            qe_report_bytes,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            pck_cert_chain,
        })
    }
}

/// The sizes of the reserved areas of a QE report, in order.
const QE_RESERVED_1_SIZE: usize = 28;
const QE_RESERVED_2_SIZE: usize = 32;
const QE_RESERVED_3_SIZE: usize = 96;
const QE_RESERVED_4_SIZE: usize = 60;

impl EnclaveReport {
    fn read(report: &[u8; QE_REPORT_SIZE]) -> Option<Self> {
        let mut input = Fields::new(report);
        let cpu_svn = input.array()?;
        let misc_select = input.u32()?;
        input.take(QE_RESERVED_1_SIZE)?;
        let attributes = input.array()?;
        let mr_enclave = input.array()?;
        input.take(QE_RESERVED_2_SIZE)?;
        let mr_signer = input.array()?;
        input.take(QE_RESERVED_3_SIZE)?;
        let isv_prod_id = input.u16()?;
        let isv_svn = input.u16()?;
        input.take(QE_RESERVED_4_SIZE)?;
        let report_data = input.array()?;
        if !input.rest().is_empty() {
            return None;
        }
        Some(EnclaveReport {
            cpu_svn,
            misc_select,
            attributes,
            mr_enclave,
            mr_signer,
            isv_prod_id,
            isv_svn,
            report_data,
        })
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
