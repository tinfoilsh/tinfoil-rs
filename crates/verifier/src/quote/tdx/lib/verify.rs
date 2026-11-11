//! Verification of a TDX quote: the PCK certificate chain, Intel's signed
//! collateral, and the quote's own signatures.

use super::abi::QuoteV4;
use super::pcs::{PckExtensions, QeIdentity, TcbInfo};
use crate::instant::Instant;
use crate::quote::QuoteError;
use crate::quote::tdx::authenticate::PcsReplay;
use crate::stub::pending;
use crate::x509::Certificate;

/// The common name of the only PCK certificate authority that is accepted.
pub const PCK_PLATFORM_CA_COMMON_NAME: &str = "Intel SGX PCK Platform CA";

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

/// Verifies a decoded quote against one trusted root, with collateral from
/// the replay and revocation checking on.
///
/// Everything is judged at `now`. In order:
///
/// 1. PCK chain. The quote's chain is exactly three `CERTIFICATE` blocks:
///    the PCK certificate, its issuer and a root; a single NUL byte may
///    follow the last block. The PCK certificate's SGX extensions decode
///    ([`pck_extensions`](super::pcs::pck_extensions)), and its issuer is
///    the platform CA ([`PCK_PLATFORM_CA_COMMON_NAME`]);
/// 2. collateral, each served by the replay and required:
///    - the PCK revocation list for the platform CA
///      ([`pck_crl_url`](super::pcs::pck_crl_url)), with its issuer chain
///      from the `Sgx-Pck-Crl-Issuer-Chain` header;
///    - the TCB info for the certificate's FMSPC
///      ([`tcb_info_url`](super::pcs::tcb_info_url)), with its issuer chain
///      from the `Tcb-Info-Issuer-Chain` header;
///    - the QE identity
///      ([`qe_identity_url`](super::pcs::qe_identity_url)), with its issuer
///      chain from the `Sgx-Enclave-Identity-Issuer-Chain` header;
///    - the root revocation list, from the distribution point of the root
///      in the QE identity's issuer chain.
///
///    An issuer chain header is URL-encoded PEM of exactly two
///    certificates, the signing certificate and a root;
/// 3. expiry: `now` is not after the validity of any certificate above nor
///    after the `nextUpdate` of either revocation list, the TCB info or the
///    QE identity;
/// 4. the PCK chain: each certificate has Intel's profile (X.509 version
///    3, ECDSA P-256 with SHA-256, the expected names), the root is the
///    trusted root, and the chain verifies at `now`
///    ([`verify_chain`](crate::x509::verify_chain)). The root revocation
///    list is issued by the root and does not revoke the intermediate; the
///    PCK revocation list is issued by the PCK certificate's own issuing
///    CA, the one that the chain verified, and does not revoke the PCK
///    certificate;
/// 5. the collateral signatures: each signing chain verifies to the
///    trusted root at `now` and is not revoked by the root revocation
///    list; the TCB info and the QE identity are signed by their signing
///    certificate, ECDSA P-256 with SHA-256 over the signed bytes
///    ([`Signed`](super::pcs::Signed));
/// 6. the quote: the attestation key signed the header and body; the PCK
///    key signed the QE report; the QE report data is the SHA-256 of the
///    attestation key and the QE authentication data, followed by zeros;
/// 7. the TD against TCB info: the certificate's FMSPC and PCE identifier
///    are the document's; MRSIGNERSEAM and the masked SEAMATTRIBUTES are
///    those of the document's TDX module; the first TCB level that the
///    certificate's component SVNs and PCE SVN and the quote's TEE TCB SVN
///    all reach has the status `UpToDate`; and, when the quote's TEE TCB
///    SVN names a module version, the matching module identity's first
///    reached level has the status `UpToDate`;
/// 8. the QE report against the QE identity: the masked MISCSELECT and
///    ATTRIBUTES, MRSIGNER and ISVPRODID are the document's, and the first
///    TCB level whose ISV SVN the report reaches has the status
///    `UpToDate`.
pub fn verify_quote(
    quote: &QuoteV4,
    replay: &PcsReplay<'_>,
    trusted_root: &Certificate,
    now: Instant,
) -> Result<VerifiedQuote, QuoteError> {
    pending("quote::tdx::lib::verify::verify_quote")
}
