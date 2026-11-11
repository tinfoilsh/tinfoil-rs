//! The collateral of Intel's Provisioning Certification Service, and the
//! SGX extensions of a PCK certificate.

use ::der::asn1::ObjectIdentifier;

use crate::instant::Instant;
use crate::quote::QuoteError;
use crate::stub::pending;
use crate::x509::Certificate;

/// The base URL of the TDX collateral endpoints.
pub const PCS_TDX_BASE_URL: &str = "https://api.trustedservices.intel.com/tdx/certification/v4";
/// The base URL of the SGX collateral endpoints, which serve the PCK
/// revocation lists.
pub const PCS_SGX_BASE_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4";

/// The SGX extension of a PCK certificate.
pub const OID_SGX_EXTENSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
/// The PPID inside the SGX extension.
pub const OID_SGX_PPID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.1");
/// The TCB inside the SGX extension.
pub const OID_SGX_TCB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
/// The PCE identifier inside the SGX extension.
pub const OID_SGX_PCE_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.3");
/// The FMSPC inside the SGX extension.
pub const OID_SGX_FMSPC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

/// The number of component SVNs in a TCB.
pub const TCB_COMPONENTS: usize = 16;

/// The URL of the PCK revocation list of a certificate authority
/// (`platform` or `processor`), in DER.
pub fn pck_crl_url(ca: &str) -> String {
    format!("{PCS_SGX_BASE_URL}/pckcrl?ca={ca}&encoding=der")
}

/// The URL of the TDX TCB info for an FMSPC.
pub fn tcb_info_url(fmspc: &str) -> String {
    format!("{PCS_TDX_BASE_URL}/tcb?fmspc={fmspc}")
}

/// The URL of the TDX QE identity.
pub fn qe_identity_url() -> String {
    format!("{PCS_TDX_BASE_URL}/qe/identity")
}

/// A collateral document together with the bytes that Intel signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed<T> {
    /// The decoded document.
    pub value: T,
    /// The document exactly as it appears in the response body, from the
    /// first to the last byte of the member's value: what the signature
    /// covers.
    pub signed_bytes: Vec<u8>,
    /// The signature: `r` then `s`, 32 bytes each.
    pub signature: [u8; 64],
}

/// The status of a TCB level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcbStatus {
    /// `UpToDate`.
    UpToDate,
    /// `SWHardeningNeeded`.
    SwHardeningNeeded,
    /// `ConfigurationNeeded`.
    ConfigurationNeeded,
    /// `ConfigurationAndSWHardeningNeeded`.
    ConfigurationAndSwHardeningNeeded,
    /// `OutOfDate`.
    OutOfDate,
    /// `OutOfDateConfigurationNeeded`.
    OutOfDateConfigurationNeeded,
    /// `Revoked`.
    Revoked,
}

/// One component of a TCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbComponent {
    /// The component's security version number.
    pub svn: u8,
}

/// The security versions of a TCB level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcb {
    /// The SGX component SVNs; [`TCB_COMPONENTS`] of them in TCB info,
    /// none in a QE identity.
    pub sgx_tcb_components: Vec<TcbComponent>,
    /// The PCE SVN; zero when the level does not state one.
    pub pce_svn: u16,
    /// The TDX component SVNs; [`TCB_COMPONENTS`] of them in TCB info,
    /// none in a QE identity.
    pub tdx_tcb_components: Vec<TcbComponent>,
    /// The ISV SVN of a QE identity or TDX module level; zero when the
    /// level does not state one.
    pub isv_svn: u32,
}

/// One TCB level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbLevel {
    /// The security versions that reach this level.
    pub tcb: Tcb,
    /// The status of the level.
    pub status: TcbStatus,
}

/// What TCB info says about the TDX module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModule {
    /// The expected MRSIGNERSEAM.
    pub mr_signer: Vec<u8>,
    /// The expected SEAMATTRIBUTES under the mask.
    pub attributes: Vec<u8>,
    /// The mask applied to SEAMATTRIBUTES.
    pub attributes_mask: Vec<u8>,
}

/// One TDX module identity of TCB info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxModuleIdentity {
    /// The identity's name, such as `TDX_03`.
    pub id: String,
    /// The TCB levels of this module version.
    pub tcb_levels: Vec<TcbLevel>,
}

/// TDX TCB info for one platform family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcbInfo {
    /// When the document was issued.
    pub issue_date: Instant,
    /// When the document expires.
    pub next_update: Instant,
    /// The FMSPC that the document is for, as written.
    pub fmspc: String,
    /// The PCE identifier that the document is for, as written.
    pub pce_id: String,
    /// The edition of the TCB evaluation that the document reflects.
    pub tcb_evaluation_data_number: u32,
    /// The TDX module's expected signer and attributes.
    pub tdx_module: TdxModule,
    /// The TDX module identities.
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
    /// The TCB levels, in document order.
    pub tcb_levels: Vec<TcbLevel>,
}

/// The identity of the TDX quoting enclave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeIdentity {
    /// When the document was issued.
    pub issue_date: Instant,
    /// When the document expires.
    pub next_update: Instant,
    /// The edition of the TCB evaluation that the document reflects.
    pub tcb_evaluation_data_number: u32,
    /// The expected MISCSELECT under the mask: 4 bytes.
    pub misc_select: Vec<u8>,
    /// The mask applied to MISCSELECT: 4 bytes.
    pub misc_select_mask: Vec<u8>,
    /// The expected ATTRIBUTES under the mask.
    pub attributes: Vec<u8>,
    /// The mask applied to ATTRIBUTES.
    pub attributes_mask: Vec<u8>,
    /// The expected MRSIGNER.
    pub mr_signer: Vec<u8>,
    /// The expected ISVPRODID.
    pub isv_prod_id: u16,
    /// The TCB levels, in document order.
    pub tcb_levels: Vec<TcbLevel>,
}

/// Decodes a TCB info response body: `{"tcbInfo": {...}, "signature":
/// "..."}`.
///
/// The body is strict JSON: valid UTF-8, no repeated member name at any
/// depth, nothing after the value. The signed bytes are the value of the
/// top-level `tcbInfo` member exactly as it appears in the body; no nested
/// member of the same name and no re-encoding can take its place. The
/// signature is 128 hex digits.
///
/// Every member that verification reads is required and has its type:
/// `issueDate`, `nextUpdate` (RFC 3339), `fmspc`, `pceId`,
/// `tcbEvaluationDataNumber`, `tdxModule` (hex `mrsigner`, `attributes`,
/// `attributesMask`), `tdxModuleIdentities` (each with `id` and
/// `tcbLevels`), and `tcbLevels`. A TCB level has `tcb` and a `tcbStatus`
/// that is one of the known statuses; a missing status is an error, never
/// a default. In `tcbLevels` a `tcb` has exactly [`TCB_COMPONENTS`]
/// `sgxtcbcomponents`, exactly as many `tdxtcbcomponents`, and `pcesvn`;
/// in a module identity it has `isvsvn`. SVNs are JSON integers in range,
/// without sign, fraction or exponent. Members that verification does not
/// read are ignored.
pub fn parse_tcb_info(body: &[u8]) -> Result<Signed<TcbInfo>, QuoteError> {
    pending("quote::tdx::lib::pcs::parse_tcb_info")
}

/// Decodes a QE identity response body: `{"enclaveIdentity": {...},
/// "signature": "..."}`, by the rules of [`parse_tcb_info`].
///
/// Required: `issueDate`, `nextUpdate`, `tcbEvaluationDataNumber`, hex
/// `miscselect`, `miscselectMask`, `attributes`, `attributesMask` and
/// `mrsigner`, `isvprodid`, and `tcbLevels`, each with a `tcb` that has
/// `isvsvn` and a known `tcbStatus`.
pub fn parse_qe_identity(body: &[u8]) -> Result<Signed<QeIdentity>, QuoteError> {
    pending("quote::tdx::lib::pcs::parse_qe_identity")
}

/// The TCB that a PCK certificate is issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckCertTcb {
    /// The PCE SVN.
    pub pce_svn: u16,
    /// The CPUSVN.
    pub cpu_svn: [u8; TCB_COMPONENTS],
    /// The component SVNs, in order.
    pub cpu_svn_components: [u8; TCB_COMPONENTS],
}

/// The SGX extensions of a PCK certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckExtensions {
    /// The platform provisioning identifier, lowercase hex.
    pub ppid: String,
    /// The TCB that the certificate is issued for.
    pub tcb: PckCertTcb,
    /// The PCE identifier, lowercase hex.
    pub pce_id: String,
    /// The FMSPC, lowercase hex.
    pub fmspc: String,
}

/// Reads the SGX extensions of a PCK certificate.
///
/// The SGX extension is a DER SEQUENCE of `(identifier, value)` pairs with
/// nothing after it. Required, each exactly once: the PPID (16 bytes), the
/// TCB (16 component SVNs, the PCE SVN and the 16-byte CPUSVN), the PCE
/// identifier (2 bytes) and the FMSPC (6 bytes). Every nested value is
/// canonical DER; a missing member is an error, never a zero.
pub fn pck_extensions(certificate: &Certificate) -> Result<PckExtensions, QuoteError> {
    pending("quote::tdx::lib::pcs::pck_extensions")
}
