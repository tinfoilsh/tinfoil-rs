//! Verification of a TDX quote: the PCK certificate chain, Intel's signed
//! collateral, and the quote's own signatures.

use ::der::asn1::ObjectIdentifier;
use sha2::{Digest, Sha256};

use super::abi::{EnclaveReport, QuoteV4, TdQuoteBody};
use super::pcs::{
    PckExtensions, QeIdentity, Signed, TCB_COMPONENTS, TcbInfo, TcbLevel, TcbStatus,
    parse_qe_identity, parse_tcb_info, pck_crl_url, pck_extensions, qe_identity_url, tcb_info_url,
};
use crate::canonical::encode_lower_hex;
use crate::instant::Instant;
use crate::quote::QuoteError;
use crate::quote::tdx::authenticate::{CollateralRecorder, ReplayedResponse};
use crate::x509::{
    Certificate, Crl, EcdsaHash, KeyAlgorithm, KeyPurpose, NameField, PublicKey, SignatureScheme,
    check_signed_by, pem_blocks, verify_chain,
};

/// The common name of the Intel SGX root certificate.
pub const ROOT_CA_COMMON_NAME: &str = "Intel SGX Root CA";
/// The common name of the only PCK certificate authority that is accepted.
pub const PCK_PLATFORM_CA_COMMON_NAME: &str = "Intel SGX PCK Platform CA";
/// The common name of the PCK certificate authority for processors, whose
/// certificates are recognised but never accepted.
pub const PCK_PROCESSOR_CA_COMMON_NAME: &str = "Intel SGX PCK Processor CA";
/// The common name of every PCK certificate.
pub const PCK_CERTIFICATE_COMMON_NAME: &str = "Intel SGX PCK Certificate";
/// The common name of the certificate that signs TCB info and QE
/// identities.
pub const TCB_SIGNING_COMMON_NAME: &str = "Intel SGX TCB Signing";

/// The response header with the issuer chain of the PCK revocation list.
pub const PCK_CRL_ISSUER_CHAIN_HEADER: &str = "Sgx-Pck-Crl-Issuer-Chain";
/// The response header with the issuer chain of the QE identity.
pub const QE_IDENTITY_ISSUER_CHAIN_HEADER: &str = "Sgx-Enclave-Identity-Issuer-Chain";
/// The response header with the issuer chain of TCB info.
pub const TCB_INFO_ISSUER_CHAIN_HEADER: &str = "Tcb-Info-Issuer-Chain";

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const PEM_CERTIFICATE_END: &[u8] = b"-----END CERTIFICATE-----";

/// What a verified quote establishes beyond its own contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    /// The PCK certificate that certifies the quoting enclave.
    pub pck_certificate: Certificate,
    /// The PCK certificate's SGX extensions.
    pub pck_extensions: PckExtensions,
    /// The TCB info that the quote was verified against.
    pub tcb_info: TcbInfo,
    /// The QE identity that the quote was verified against.
    pub qe_identity: QeIdentity,
}

/// The certificate chain of a quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckCertificateChain {
    /// The PCK certificate.
    pub pck: Certificate,
    /// The certificate of the authority that issued the PCK certificate.
    pub intermediate: Certificate,
    /// The root certificate that the quote carries. It is not the trust
    /// anchor.
    pub root: Certificate,
}

/// A signing certificate and the root that a response header states for
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IssuerChain {
    signing: Certificate,
    root: Certificate,
}

/// Decodes PEM text that consists of exactly `count` certificates.
///
/// The rules of [`pem_blocks`] apply, and further: every block is a
/// `CERTIFICATE`; a carriage return appears only directly in front of a
/// line feed; and nothing follows the last `END` line but its own line
/// end. With `nul_terminated`, one NUL byte may follow that line end, and
/// then the line end is required.
fn pem_certificates_exactly(
    text: &[u8],
    count: usize,
    nul_terminated: bool,
) -> Result<Vec<Certificate>, QuoteError> {
    let (text, terminated) = match text.split_last() {
        Some((0, front)) if nul_terminated => (front, true),
        _ => (text, false),
    };
    let stray_carriage_return = text
        .iter()
        .zip(text.iter().skip(1).map(Some).chain(std::iter::once(None)))
        .any(|(byte, next)| *byte == b'\r' && next != Some(&b'\n'));
    if stray_carriage_return {
        return Err(QuoteError::new(
            "PEM carries a carriage return that is not part of a line end",
        ));
    }
    let (body, line_end) = if let Some(body) = text.strip_suffix(b"\r\n") {
        (body, true)
    } else if let Some(body) = text.strip_suffix(b"\n") {
        (body, true)
    } else {
        (text, false)
    };
    if !body.ends_with(PEM_CERTIFICATE_END) || (terminated && !line_end) {
        return Err(QuoteError::new(
            "PEM carries data after its last certificate",
        ));
    }
    let blocks = pem_blocks(text)?;
    if blocks.len() != count {
        return Err(QuoteError::new(format!(
            "PEM carries {} blocks, want {count} certificates",
            blocks.len()
        )));
    }
    blocks
        .iter()
        .map(|block| {
            if block.label != "CERTIFICATE" {
                return Err(QuoteError::new(format!(
                    "PEM carries a {:?} block, want CERTIFICATE",
                    block.label
                )));
            }
            Ok(Certificate::from_der(&block.contents)?)
        })
        .collect()
}

/// Decodes the certificate chain of a quote: exactly three `CERTIFICATE`
/// blocks, the PCK certificate, its issuer and a root, in that order. One
/// NUL byte may follow the line end of the last block; nothing else may
/// follow it, and no text stands between blocks.
pub fn pck_certificate_chain(chain: &[u8]) -> Result<PckCertificateChain, QuoteError> {
    let certificates = pem_certificates_exactly(chain, 3, true)
        .map_err(|error| error.within("PCK certificate chain"))?;
    let [pck, intermediate, root]: [Certificate; 3] = certificates
        .try_into()
        .map_err(|_| QuoteError::new("PCK certificate chain is not three certificates"))?;
    Ok(PckCertificateChain {
        pck,
        intermediate,
        root,
    })
}

/// Decodes a URL query component: `%XX` is the byte `XX`, `+` is a space.
/// A `%` that is not followed by two hex digits is an error.
fn query_unescape(text: &str) -> Result<Vec<u8>, QuoteError> {
    let invalid = || QuoteError::new("invalid URL escape in an issuer chain header");
    let hex = |digit: u8| {
        char::from(digit)
            .to_digit(16)
            .and_then(|n| u8::try_from(n).ok())
    };
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes.next().and_then(hex).ok_or_else(invalid)?;
                let low = bytes.next().and_then(hex).ok_or_else(invalid)?;
                out.push((high << 4) | low);
            }
            b'+' => out.push(b' '),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Reads an issuer chain from a response header: the header is stated
/// once, with one value that is not empty; the value is URL-encoded PEM of
/// exactly two certificates, the signing certificate and then a root, with
/// nothing after the line end of the second.
fn issuer_chain(response: &ReplayedResponse<'_>, header: &str) -> Result<IssuerChain, QuoteError> {
    let values = response
        .headers
        .get(header)
        .ok_or_else(|| QuoteError::new(format!("response has no {header} header")))?;
    let [value] = values.as_slice() else {
        return Err(QuoteError::new(format!(
            "response states {} values of the {header} header, want 1",
            values.len()
        )));
    };
    if value.is_empty() {
        return Err(QuoteError::new(format!("the {header} header is empty")));
    }
    let pem = query_unescape(value)?;
    let certificates =
        pem_certificates_exactly(&pem, 2, false).map_err(|error| error.within(header))?;
    let [signing, root]: [Certificate; 2] = certificates
        .try_into()
        .map_err(|_| QuoteError::new(format!("the {header} header is not two certificates")))?;
    Ok(IssuerChain { signing, root })
}

/// The last common name of a certificate's subject or issuer; empty when
/// the name has none.
fn common_name(certificate: &Certificate, field: NameField) -> Result<String, QuoteError> {
    Ok(certificate
        .name_attribute(field, OID_COMMON_NAME)?
        .pop()
        .unwrap_or_default())
}

/// Checks one certificate of Intel's hierarchy against its parent: X.509
/// version 3; signed with ECDSA and SHA-256; an ECDSA P-256 key; the
/// subject's common name is `name`; the issuer name is the parent's
/// subject name, byte for byte; and the parent may sign certificates and
/// did sign this one ([`check_signed_by`]).
fn check_certificate(
    certificate: &Certificate,
    parent: &Certificate,
    name: &str,
) -> Result<(), QuoteError> {
    if certificate.version() != 3 {
        return Err(QuoteError::new(format!(
            "certificate has version {}, want 3",
            certificate.version()
        )));
    }
    if certificate.signature_algorithm() != OID_ECDSA_WITH_SHA256 {
        return Err(QuoteError::new(format!(
            "certificate is signed with {}, want ECDSA with SHA-256",
            certificate.signature_algorithm()
        )));
    }
    if certificate.public_key()?.algorithm() != KeyAlgorithm::EcdsaP256 {
        return Err(QuoteError::new("certificate key is not ECDSA P-256"));
    }
    let subject = common_name(certificate, NameField::Subject)?;
    if subject != name {
        return Err(QuoteError::new(format!(
            "certificate subject is {subject:?}, want {name:?}"
        )));
    }
    if certificate.issuer_der() != parent.subject_der() {
        return Err(QuoteError::new(
            "certificate issuer is not the subject of its parent",
        ));
    }
    check_signed_by(certificate, parent)?;
    Ok(())
}

/// The collateral that a quote is verified against.
struct Collateral {
    tcb_info: Signed<TcbInfo>,
    tcb_info_issuer: IssuerChain,
    qe_identity: Signed<QeIdentity>,
    qe_identity_issuer: IssuerChain,
    pck_crl: Crl,
    pck_crl_issuer: IssuerChain,
    root_crl: Crl,
}

/// Obtains the collateral for a PCK certificate with the given FMSPC,
/// issued by the certificate authority `ca`: TCB info, the QE identity,
/// the PCK revocation list, and the root revocation list from the first
/// distribution point of the QE identity's stated root that serves one.
fn obtain_collateral(
    fmspc: &str,
    ca: &str,
    collateral: &mut CollateralRecorder<'_>,
) -> Result<Collateral, QuoteError> {
    let response = collateral
        .get(&tcb_info_url(fmspc))
        .map_err(|error| error.within("TCB info"))?;
    let tcb_info_issuer = issuer_chain(&response, TCB_INFO_ISSUER_CHAIN_HEADER)?;
    let tcb_info = parse_tcb_info(response.body)?;

    let response = collateral
        .get(&qe_identity_url())
        .map_err(|error| error.within("QE identity"))?;
    let qe_identity_issuer = issuer_chain(&response, QE_IDENTITY_ISSUER_CHAIN_HEADER)?;
    let qe_identity = parse_qe_identity(response.body)?;

    let response = collateral
        .get(&pck_crl_url(ca))
        .map_err(|error| error.within("PCK revocation list"))?;
    let pck_crl_issuer = issuer_chain(&response, PCK_CRL_ISSUER_CHAIN_HEADER)?;
    let pck_crl = Crl::from_der(response.body)
        .map_err(|error| QuoteError::new(format!("PCK revocation list: {error}")))?;

    let locations = qe_identity_issuer.root.crl_distribution_uris()?;
    if locations.is_empty() {
        return Err(QuoteError::new(
            "the root of the QE identity's issuer chain names no CRL distribution point",
        ));
    }
    let mut root_crl = None;
    let mut failure = None;
    for location in &locations {
        let served = collateral
            .get(location)
            .and_then(|response| Ok(Crl::from_der(response.body)?));
        match served {
            Ok(crl) => {
                root_crl = Some(crl);
                break;
            }
            Err(error) => failure = Some(error),
        }
    }
    let root_crl = root_crl.ok_or_else(|| {
        let reason = failure.map(|error| error.to_string()).unwrap_or_default();
        QuoteError::new(format!("root revocation list: {reason}"))
    })?;

    Ok(Collateral {
        tcb_info,
        tcb_info_issuer,
        qe_identity,
        qe_identity_issuer,
        pck_crl,
        pck_crl_issuer,
        root_crl,
    })
}

fn expired(what: &str) -> QuoteError {
    QuoteError::new(format!("{what} has expired"))
}

/// Verifies the quote's certificate chain: the profile of each
/// certificate, the path to the trusted root, both revocation lists, and
/// expiry.
fn verify_pck_chain(
    chain: &PckCertificateChain,
    collateral: &Collateral,
    trusted_root: &Certificate,
    now: Instant,
) -> Result<(), QuoteError> {
    check_certificate(&chain.root, &chain.root, ROOT_CA_COMMON_NAME)
        .map_err(|error| error.within("root certificate of the PCK chain"))?;
    check_certificate(
        &chain.intermediate,
        &chain.root,
        PCK_PLATFORM_CA_COMMON_NAME,
    )
    .map_err(|error| error.within("intermediate certificate of the PCK chain"))?;
    check_certificate(&chain.pck, &chain.intermediate, PCK_CERTIFICATE_COMMON_NAME)
        .map_err(|error| error.within("PCK certificate"))?;
    verify_chain(
        &chain.pck,
        std::slice::from_ref(&chain.intermediate),
        std::slice::from_ref(trusted_root),
        now,
        KeyPurpose::ServerAuth,
    )
    .map_err(|error| QuoteError::new(format!("verifying PCK certificate: {error}")))?;

    collateral
        .root_crl
        .verify_issued_by(&chain.root)
        .map_err(|error| QuoteError::new(format!("root revocation list: {error}")))?;
    collateral
        .pck_crl
        .verify_issued_by(&chain.intermediate)
        .map_err(|error| QuoteError::new(format!("PCK revocation list: {error}")))?;
    if collateral.pck_crl.issuer_der() != chain.pck.issuer_der() {
        return Err(QuoteError::new(
            "PCK revocation list is not issued by the issuer of the PCK certificate",
        ));
    }
    if collateral.root_crl.is_revoked(chain.intermediate.serial()) {
        return Err(QuoteError::new(
            "intermediate certificate of the PCK chain is revoked",
        ));
    }
    if collateral.pck_crl.is_revoked(chain.pck.serial()) {
        return Err(QuoteError::new("PCK certificate is revoked"));
    }

    if now > chain.root.not_after() {
        return Err(expired("root certificate of the PCK chain"));
    }
    if now > chain.intermediate.not_after() {
        return Err(expired("intermediate certificate of the PCK chain"));
    }
    if now > chain.pck.not_after() {
        return Err(expired("PCK certificate"));
    }
    Ok(())
}

/// Checks that nothing of the collateral has expired at `now`.
fn check_collateral_expiry(collateral: &Collateral, now: Instant) -> Result<(), QuoteError> {
    let checks = [
        (collateral.tcb_info.value.next_update, "TCB info"),
        (collateral.qe_identity.value.next_update, "QE identity"),
        (
            collateral.tcb_info_issuer.signing.not_after(),
            "TCB info signing certificate",
        ),
        (
            collateral.tcb_info_issuer.root.not_after(),
            "TCB info root certificate",
        ),
        (
            collateral.qe_identity_issuer.root.not_after(),
            "QE identity root certificate",
        ),
        (
            collateral.qe_identity_issuer.signing.not_after(),
            "QE identity signing certificate",
        ),
        (collateral.root_crl.next_update(), "root revocation list"),
        (collateral.pck_crl.next_update(), "PCK revocation list"),
        (
            collateral.pck_crl_issuer.signing.not_after(),
            "PCK revocation list signing certificate",
        ),
        (
            collateral.pck_crl_issuer.root.not_after(),
            "PCK revocation list root certificate",
        ),
    ];
    for (end, what) in checks {
        if now > end {
            return Err(expired(what));
        }
    }
    Ok(())
}

/// Verifies a signed collateral document: its stated root has the profile
/// of the Intel root; its signing certificate has the profile of the TCB
/// signing certificate under that root and chains to the trusted root at
/// `now`; the signature is the signing key's over the signed bytes; and
/// the root revocation list is issued by the stated root and does not
/// revoke the signing certificate.
fn verify_response(
    issuer: &IssuerChain,
    signed_bytes: &[u8],
    signature: &[u8; 64],
    root_crl: &Crl,
    trusted_root: &Certificate,
    now: Instant,
) -> Result<(), QuoteError> {
    check_certificate(&issuer.root, &issuer.root, ROOT_CA_COMMON_NAME)
        .map_err(|error| error.within("root certificate of the issuer chain"))?;
    check_certificate(&issuer.signing, &issuer.root, TCB_SIGNING_COMMON_NAME)
        .map_err(|error| error.within("signing certificate of the issuer chain"))?;
    verify_chain(
        &issuer.signing,
        &[],
        std::slice::from_ref(trusted_root),
        now,
        KeyPurpose::ServerAuth,
    )
    .map_err(|error| QuoteError::new(format!("verifying signing certificate: {error}")))?;
    issuer
        .signing
        .public_key()?
        .verify(
            SignatureScheme::EcdsaRaw(EcdsaHash::Sha256),
            signed_bytes,
            signature,
        )
        .map_err(|error| QuoteError::new(format!("response signature: {error}")))?;
    root_crl
        .verify_issued_by(&issuer.root)
        .map_err(|error| QuoteError::new(format!("root revocation list: {error}")))?;
    if root_crl.is_revoked(issuer.signing.serial()) {
        return Err(QuoteError::new("signing certificate is revoked"));
    }
    Ok(())
}

/// The DER prefix of the SubjectPublicKeyInfo of an uncompressed P-256
/// point: everything in front of the two coordinates.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// The attestation key of a quote: a point on P-256 given as its two
/// coordinates.
fn attestation_key(coordinates: &[u8; 64]) -> Result<PublicKey, QuoteError> {
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(coordinates);
    PublicKey::from_spki_der(&spki).map_err(|error| {
        QuoteError::new(format!("attestation key in the quote is invalid: {error}"))
    })
}

/// Whether every SVN of `given` is at least the same component of
/// `required`. Lists of different lengths never compare.
fn components_reach(given: &[u8], required: &[super::pcs::TcbComponent]) -> bool {
    given.len() == required.len()
        && given
            .iter()
            .zip(required)
            .all(|(given, required)| *given >= required.svn)
}

/// Whether TEE_TCB_SVN reaches the TDX components of a TCB level. When
/// the second byte of TEE_TCB_SVN, the TDX module's major version, is not
/// zero, the first two components belong to the module and are judged by
/// its identity instead.
fn tee_tcb_svn_reaches(tee_tcb_svn: &[u8; TCB_COMPONENTS], level: &TcbLevel) -> bool {
    let [_, module_version, ..] = *tee_tcb_svn;
    let skipped = if module_version > 0 { 2 } else { 0 };
    tee_tcb_svn.len() == level.tcb.tdx_tcb_components.len()
        && tee_tcb_svn
            .iter()
            .zip(&level.tcb.tdx_tcb_components)
            .skip(skipped)
            .all(|(given, required)| *given >= required.svn)
}

fn check_status(what: &str, status: TcbStatus) -> Result<(), QuoteError> {
    if status != TcbStatus::UpToDate {
        return Err(QuoteError::new(format!(
            "{what} TCB status is {}, want {}",
            status.name(),
            TcbStatus::UpToDate.name()
        )));
    }
    Ok(())
}

/// Checks the TD quote body against TCB info, as [`verify_quote`]
/// describes.
fn verify_td_quote_body(
    body: &TdQuoteBody,
    tcb_info: &TcbInfo,
    extensions: &PckExtensions,
) -> Result<(), QuoteError> {
    if extensions.fmspc != tcb_info.fmspc {
        return Err(QuoteError::new(format!(
            "FMSPC of the PCK certificate ({:?}) is not that of the TCB info ({:?})",
            extensions.fmspc, tcb_info.fmspc
        )));
    }
    if extensions.pce_id != tcb_info.pce_id {
        return Err(QuoteError::new(format!(
            "PCE identifier of the PCK certificate ({:?}) is not that of the TCB info ({:?})",
            extensions.pce_id, tcb_info.pce_id
        )));
    }
    let module = &tcb_info.tdx_module;
    if module.mr_signer != body.mr_signer_seam {
        return Err(QuoteError::new(format!(
            "MRSIGNERSEAM {} is not the TDX module signer of the TCB info",
            encode_lower_hex(&body.mr_signer_seam)
        )));
    }
    if module.attributes_mask.len() != body.seam_attributes.len() {
        return Err(QuoteError::new(
            "the TDX module attributes mask of the TCB info does not have the size of SEAMATTRIBUTES",
        ));
    }
    let masked: Vec<u8> = module
        .attributes_mask
        .iter()
        .zip(&body.seam_attributes)
        .map(|(mask, attribute)| mask & attribute)
        .collect();
    if module.attributes != masked {
        return Err(QuoteError::new(format!(
            "SEAMATTRIBUTES under the mask ({}) are not the TDX module attributes of the TCB info",
            encode_lower_hex(&masked)
        )));
    }

    let level = tcb_info
        .tcb_levels
        .iter()
        .find(|level| {
            components_reach(
                &extensions.tcb.cpu_svn_components,
                &level.tcb.sgx_tcb_components,
            ) && extensions.tcb.pce_svn >= level.tcb.pce_svn
                && tee_tcb_svn_reaches(&body.tee_tcb_svn, level)
        })
        .ok_or_else(|| QuoteError::new("no TCB level of the TCB info is reached"))?;

    let [module_svn, module_version, ..] = body.tee_tcb_svn;
    if module_version > 0 {
        let id = format!("TDX_{}", encode_lower_hex(&[module_version]));
        let identity = tcb_info
            .tdx_module_identities
            .iter()
            .find(|identity| identity.id == id)
            .ok_or_else(|| {
                QuoteError::new(format!("the TCB info has no TDX module identity {id:?}"))
            })?;
        let module_level = identity
            .tcb_levels
            .iter()
            .find(|level| u32::from(module_svn) >= level.tcb.isv_svn)
            .ok_or_else(|| {
                QuoteError::new(format!(
                    "no TCB level of the TDX module identity {id:?} is reached"
                ))
            })?;
        check_status("TDX module", module_level.status)?;
    }
    check_status("platform", level.status)
}

/// Checks the QE report against the QE identity, as [`verify_quote`]
/// describes.
fn verify_qe_report(report: &EnclaveReport, identity: &QeIdentity) -> Result<(), QuoteError> {
    let four = |bytes: &[u8], name: &str| -> Result<u32, QuoteError> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| QuoteError::new(format!("{name} of the QE identity is not 4 bytes")))?;
        Ok(u32::from_le_bytes(bytes))
    };
    let mask = four(&identity.misc_select_mask, "miscselectMask")?;
    let misc_select = four(&identity.misc_select, "miscselect")?;
    if report.misc_select & mask != misc_select {
        return Err(QuoteError::new(
            "MISCSELECT of the QE report under the mask is not that of the QE identity",
        ));
    }
    if identity.attributes_mask.len() != report.attributes.len() {
        return Err(QuoteError::new(
            "the attributes mask of the QE identity does not have the size of ATTRIBUTES",
        ));
    }
    let masked: Vec<u8> = identity
        .attributes_mask
        .iter()
        .zip(&report.attributes)
        .map(|(mask, attribute)| mask & attribute)
        .collect();
    if identity.attributes != masked {
        return Err(QuoteError::new(
            "ATTRIBUTES of the QE report under the mask are not those of the QE identity",
        ));
    }
    if identity.mr_signer != report.mr_signer {
        return Err(QuoteError::new(
            "MRSIGNER of the QE report is not that of the QE identity",
        ));
    }
    if report.isv_prod_id != identity.isv_prod_id {
        return Err(QuoteError::new(
            "ISVPRODID of the QE report is not that of the QE identity",
        ));
    }
    let level = identity
        .tcb_levels
        .iter()
        .find(|level| level.tcb.isv_svn <= u32::from(report.isv_svn))
        .ok_or_else(|| QuoteError::new("no TCB level of the QE identity is reached"))?;
    check_status("QE", level.status)
}

/// Verifies a decoded quote against one trusted root, with collateral
/// served by `collateral` and revocation checking on.
///
/// Everything is judged at `now`. In order:
///
/// 1. PCK chain. The quote's chain is exactly three `CERTIFICATE` blocks
///    ([`pck_certificate_chain`]). The PCK certificate's SGX extensions
///    decode ([`pck_extensions`]), and the common name of its issuer is
///    that of the platform CA ([`PCK_PLATFORM_CA_COMMON_NAME`]) or of the
///    processor CA; a chain of the processor CA fails below, because only
///    a platform CA intermediate is accepted;
/// 2. collateral, each served by the recorder and required:
///    - the TCB info for the certificate's FMSPC ([`tcb_info_url`]), with
///      its issuer chain from the `Tcb-Info-Issuer-Chain` header
///      ([`parse_tcb_info`]);
///    - the QE identity ([`qe_identity_url`]), with its issuer chain from
///      the `Sgx-Enclave-Identity-Issuer-Chain` header
///      ([`parse_qe_identity`]);
///    - the PCK revocation list for the certificate's CA
///      ([`pck_crl_url`]), with its issuer chain from the
///      `Sgx-Pck-Crl-Issuer-Chain` header;
///    - the root revocation list, from the first CRL distribution point of
///      the root in the QE identity's issuer chain that serves one.
///
///    An issuer chain header is stated once with one value: URL-encoded
///    PEM of exactly two certificates, the signing certificate and a root;
/// 3. the PCK chain: each of its three certificates has Intel's profile
///    under its parent (X.509 version 3, ECDSA P-256 with SHA-256, the
///    expected common name, the parent's name as issuer, the parent's
///    signature), the root under itself; the PCK certificate chains to the
///    trusted root at `now` through the quote's intermediate
///    ([`verify_chain`] for server authentication, the purpose of a path
///    that states none). The root revocation list is issued by the quote's
///    root and the PCK revocation list by the quote's intermediate, the
///    issuer of the PCK certificate ([`Crl::verify_issued_by`]); neither
///    revokes the certificate below its issuer. `now` is not after the
///    validity of any of the three certificates;
/// 4. expiry of the collateral: `now` is not after the `nextUpdate` of the
///    TCB info, the QE identity or either revocation list, nor after the
///    validity of any certificate of the three issuer chains. The issuer
///    chain of the PCK revocation list is held to nothing else;
/// 5. the TCB info and then the QE identity: the root of the issuer chain
///    has the root's profile; the signing certificate has the profile of
///    the TCB signing certificate under it and chains to the trusted root
///    at `now`; the signature is ECDSA P-256 with SHA-256 over the signed
///    bytes ([`Signed`]); the root revocation list is issued by the chain's
///    root and does not revoke the signing certificate;
/// 6. the quote: the attestation key is a point on P-256 and signed the
///    header and body; the PCK key signed the QE report; the QE report
///    data is the SHA-256 of the attestation key and the QE authentication
///    data, followed by zeros;
/// 7. the TD against TCB info: the certificate's FMSPC and PCE identifier
///    are the document's, as text; MRSIGNERSEAM and the masked
///    SEAMATTRIBUTES are those of the document's TDX module; the first TCB
///    level that the certificate's component SVNs and PCE SVN and the
///    quote's TEE TCB SVN all reach has the status `UpToDate`; and, when
///    the quote's TEE TCB SVN names a module version, the module identity
///    `TDX_<version>` exists and the first of its levels that the module's
///    SVN reaches has the status `UpToDate`;
/// 8. the QE report against the QE identity: the masked MISCSELECT and
///    ATTRIBUTES, MRSIGNER and ISVPRODID are the document's, and the first
///    TCB level whose ISV SVN the report reaches has the status
///    `UpToDate`.
pub fn verify_quote(
    quote: &QuoteV4,
    collateral: &mut CollateralRecorder<'_>,
    trusted_root: &Certificate,
    now: Instant,
) -> Result<VerifiedQuote, QuoteError> {
    let signed_data = &quote.signed_data;
    let chain = pck_certificate_chain(&signed_data.pck_cert_chain)?;
    let extensions = pck_extensions(&chain.pck)?;
    let issuer = common_name(&chain.pck, NameField::Issuer)?;
    let ca = match issuer.as_str() {
        PCK_PLATFORM_CA_COMMON_NAME => "platform",
        PCK_PROCESSOR_CA_COMMON_NAME => "processor",
        _ => {
            return Err(QuoteError::new(format!(
                "PCK certificate is issued by {issuer:?}, not by a PCK certificate authority"
            )));
        }
    };
    let collateral = obtain_collateral(&extensions.fmspc, ca, collateral)?;

    verify_pck_chain(&chain, &collateral, trusted_root, now)?;
    check_collateral_expiry(&collateral, now)?;
    verify_response(
        &collateral.tcb_info_issuer,
        &collateral.tcb_info.signed_bytes,
        &collateral.tcb_info.signature,
        &collateral.root_crl,
        trusted_root,
        now,
    )
    .map_err(|error| error.within("TCB info"))?;
    verify_response(
        &collateral.qe_identity_issuer,
        &collateral.qe_identity.signed_bytes,
        &collateral.qe_identity.signature,
        &collateral.root_crl,
        trusted_root,
        now,
    )
    .map_err(|error| error.within("QE identity"))?;

    attestation_key(&signed_data.attestation_key)?
        .verify(
            SignatureScheme::EcdsaRaw(EcdsaHash::Sha256),
            &quote.signed_bytes,
            &signed_data.signature,
        )
        .map_err(|error| QuoteError::new(format!("quote signature: {error}")))?;
    chain
        .pck
        .public_key()?
        .verify(
            SignatureScheme::EcdsaRaw(EcdsaHash::Sha256),
            &signed_data.qe_report_bytes,
            &signed_data.qe_report_signature,
        )
        .map_err(|error| QuoteError::new(format!("QE report signature: {error}")))?;
    let mut hasher = Sha256::new();
    hasher.update(signed_data.attestation_key);
    hasher.update(&signed_data.qe_auth_data);
    let mut expected_report_data = [0u8; 64];
    for (out, byte) in expected_report_data.iter_mut().zip(hasher.finalize()) {
        *out = byte;
    }
    if signed_data.qe_report.report_data != expected_report_data {
        return Err(QuoteError::new(
            "QE report data is not the hash of the attestation key and the QE authentication data",
        ));
    }

    verify_td_quote_body(&quote.body, &collateral.tcb_info.value, &extensions)?;
    verify_qe_report(&signed_data.qe_report, &collateral.qe_identity.value)?;

    Ok(VerifiedQuote {
        pck_certificate: chain.pck,
        pck_extensions: extensions,
        tcb_info: collateral.tcb_info.value,
        qe_identity: collateral.qe_identity.value,
    })
}
