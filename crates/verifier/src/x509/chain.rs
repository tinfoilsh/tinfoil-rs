//! Certificate path verification against explicit trust anchors at a
//! supplied time.

use super::{Certificate, X509Error};
use crate::instant::Instant;
use crate::stub::pending;

/// What a certificate path is used for, as an extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// No extended key usage is required of the path.
    Any,
    /// `id-kp-codeSigning`: Sigstore signing certificates and registry
    /// signing certificates.
    CodeSigning,
    /// `id-kp-timeStamping`: RFC 3161 timestamp authorities.
    TimeStamping,
}

/// Verifies that `leaf` chains to one of `roots` at the instant `at`, and
/// returns the path from the leaf to the root, both included.
///
/// A path is built from `leaf` through any of `intermediates` to a
/// certificate in `roots`; the first path that satisfies every rule wins.
/// Certificates in `intermediates` that are not needed are ignored. At most
/// eight certificates form a path. For every path candidate, in order:
///
/// 1. each certificate's issuer name equals its issuer's subject name, byte
///    for byte, and its signature verifies under the issuer's key over the
///    encoded `tbsCertificate` as it appears in the certificate;
/// 2. `at` lies within the validity of every certificate on the path, the
///    root included; both ends of a validity period are inside it;
/// 3. every certificate that issues another has basic constraints with
///    `cA` set, satisfies its path length constraint, and permits
///    certificate signing when it carries a key usage extension;
/// 4. no certificate on the path has a critical extension that this module
///    does not process. Processed: basic constraints, key usage, extended
///    key usage, subject alternative name, and the subject and authority
///    key identifiers. Name constraints are not processed, so a critical
///    name constraints extension rejects;
/// 5. with a `purpose` other than [`KeyPurpose::Any`], every certificate on
///    the path, the root included, either carries no extended key usage
///    extension or lists the purpose or `anyExtendedKeyUsage`.
///
/// A root is trusted as given: it need not be self-signed, and its own
/// signature is not checked. The leaf may itself be one of `roots`, in
/// which case the path has one certificate.
///
/// The profile of the leaf (its key type, names, whether it must carry an
/// extended key usage) is the caller's to check. Revocation is not consulted
/// here; see [`Crl`](super::Crl).
pub fn verify_chain<'a>(
    leaf: &'a Certificate,
    intermediates: &'a [Certificate],
    roots: &'a [Certificate],
    at: Instant,
    purpose: KeyPurpose,
) -> Result<Vec<&'a Certificate>, X509Error> {
    pending("x509::chain::verify_chain")
}
